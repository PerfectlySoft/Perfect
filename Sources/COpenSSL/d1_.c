/* ssl/d1_both.c */
/*
 * DTLS implementation written by Nagendra Modadugu
 * (nagendra@cs.stanford.edu) for the OpenSSL project 2005.
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

#include <limits.h>
#include <string.h>
#include <stdio.h>
#include "ssl_locl.h"
#include "buffer.h"
#include "rand.h"
#include "objects.h"
#include "evp.h"
#include "x509.h"

#define RSMBLY_BITMASK_SIZE(msg_len) (((msg_len) + 7) / 8)

#define RSMBLY_BITMASK_MARK(bitmask, start, end) { \
                        if ((end) - (start) <= 8) { \
                                long ii; \
                                for (ii = (start); ii < (end); ii++) bitmask[((ii) >> 3)] |= (1 << ((ii) & 7)); \
                        } else { \
                                long ii; \
                                bitmask[((start) >> 3)] |= bitmask_start_values[((start) & 7)]; \
                                for (ii = (((start) >> 3) + 1); ii < ((((end) - 1)) >> 3); ii++) bitmask[ii] = 0xff; \
                                bitmask[(((end) - 1) >> 3)] |= bitmask_end_values[((end) & 7)]; \
                        } }

#define RSMBLY_BITMASK_IS_COMPLETE(bitmask, msg_len, is_complete) { \
                        long ii; \
                        OPENSSL_assert((msg_len) > 0); \
                        is_complete = 1; \
                        if (bitmask[(((msg_len) - 1) >> 3)] != bitmask_end_values[((msg_len) & 7)]) is_complete = 0; \
                        if (is_complete) for (ii = (((msg_len) - 1) >> 3) - 1; ii >= 0 ; ii--) \
                                if (bitmask[ii] != 0xff) { is_complete = 0; break; } }

#if 0
# define RSMBLY_BITMASK_PRINT(bitmask, msg_len) { \
                        long ii; \
                        printf("bitmask: "); for (ii = 0; ii < (msg_len); ii++) \
                        printf("%d ", (bitmask[ii >> 3] & (1 << (ii & 7))) >> (ii & 7)); \
                        printf("\n"); }
#endif

static unsigned char bitmask_start_values[] =
    { 0xff, 0xfe, 0xfc, 0xf8, 0xf0, 0xe0, 0xc0, 0x80 };
static unsigned char bitmask_end_values[] =
    { 0xff, 0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f };

/* XDTLS:  figure out the right values */
static const unsigned int g_probable_mtu[] = { 1500, 512, 256 };

static void dtls1_fix_message_header(SSL *s, unsigned long frag_off,
                                     unsigned long frag_len);
static unsigned char *dtls1_write_message_header(SSL *s, unsigned char *p);
static void dtls1_set_message_header_int(SSL *s, unsigned char mt,
                                         unsigned long len,
                                         unsigned short seq_num,
                                         unsigned long frag_off,
                                         unsigned long frag_len);
static long dtls1_get_message_fragment(SSL *s, int st1, int stn, long max,
                                       int *ok);

static hm_fragment *dtls1_hm_fragment_new(unsigned long frag_len,
                                          int reassembly)
{
    hm_fragment *frag = NULL;
    unsigned char *buf = NULL;
    unsigned char *bitmask = NULL;

    frag = (hm_fragment *)OPENSSL_malloc(sizeof(hm_fragment));
    if (frag == NULL)
        return NULL;

    if (frag_len) {
        buf = (unsigned char *)OPENSSL_malloc(frag_len);
        if (buf == NULL) {
            OPENSSL_free(frag);
            return NULL;
        }
    }

    /* zero length fragment gets zero frag->fragment */
    frag->fragment = buf;

    /* Initialize reassembly bitmask if necessary */
    if (reassembly) {
        bitmask =
            (unsigned char *)OPENSSL_malloc(RSMBLY_BITMASK_SIZE(frag_len));
        if (bitmask == NULL) {
            if (buf != NULL)
                OPENSSL_free(buf);
            OPENSSL_free(frag);
            return NULL;
        }
        memset(bitmask, 0, RSMBLY_BITMASK_SIZE(frag_len));
    }

    frag->reassembly = bitmask;

    return frag;
}

void dtls1_hm_fragment_free(hm_fragment *frag)
{

    if (frag->msg_header.is_ccs) {
        EVP_CIPHER_CTX_free(frag->msg_header.
                            saved_retransmit_state.enc_write_ctx);
        EVP_MD_CTX_destroy(frag->msg_header.
                           saved_retransmit_state.write_hash);
    }
    if (frag->fragment)
        OPENSSL_free(frag->fragment);
    if (frag->reassembly)
        OPENSSL_free(frag->reassembly);
    OPENSSL_free(frag);
}

static int dtls1_query_mtu(SSL *s)
{
    if (s->d1->link_mtu) {
        s->d1->mtu =
            s->d1->link_mtu - BIO_dgram_get_mtu_overhead(SSL_get_wbio(s));
        s->d1->link_mtu = 0;
    }

    /* AHA!  Figure out the MTU, and stick to the right size */
    if (s->d1->mtu < dtls1_min_mtu(s)) {
        if (!(SSL_get_options(s) & SSL_OP_NO_QUERY_MTU)) {
            s->d1->mtu =
                BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_QUERY_MTU, 0, NULL);

            /*
             * I've seen the kernel return bogus numbers when it doesn't know
             * (initial write), so just make sure we have a reasonable number
             */
            if (s->d1->mtu < dtls1_min_mtu(s)) {
                /* Set to min mtu */
                s->d1->mtu = dtls1_min_mtu(s);
                BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SET_MTU,
                         s->d1->mtu, NULL);
            }
        } else
            return 0;
    }
    return 1;
}

/*
 * send s->init_buf in records of type 'type' (SSL3_RT_HANDSHAKE or
 * SSL3_RT_CHANGE_CIPHER_SPEC)
 */
int dtls1_do_write(SSL *s, int type)
{
    int ret;
    unsigned int curr_mtu;
    int retry = 1;
    unsigned int len, frag_off, mac_size, blocksize, used_len;

    if (!dtls1_query_mtu(s))
        return -1;

    OPENSSL_assert(s->d1->mtu >= dtls1_min_mtu(s)); /* should have something
                                                     * reasonable now */

    if (s->init_off == 0 && type == SSL3_RT_HANDSHAKE)
        OPENSSL_assert(s->init_num ==
                       (int)s->d1->w_msg_hdr.msg_len +
                       DTLS1_HM_HEADER_LENGTH);

    if (s->write_hash) {
        if (s->enc_write_ctx
            && EVP_CIPHER_CTX_mode(s->enc_write_ctx) == EVP_CIPH_GCM_MODE)
            mac_size = 0;
        else
            mac_size = EVP_MD_CTX_size(s->write_hash);
    } else
        mac_size = 0;

    if (s->enc_write_ctx &&
        (EVP_CIPHER_CTX_mode(s->enc_write_ctx) == EVP_CIPH_CBC_MODE))
        blocksize = 2 * EVP_CIPHER_block_size(s->enc_write_ctx->cipher);
    else
        blocksize = 0;

    frag_off = 0;
    s->rwstate = SSL_NOTHING;

    /* s->init_num shouldn't ever be < 0...but just in case */
    while (s->init_num > 0) {
        if (type == SSL3_RT_HANDSHAKE && s->init_off != 0) {
            /* We must be writing a fragment other than the first one */

            if (frag_off > 0) {
                /* This is the first attempt at writing out this fragment */

                if (s->init_off <= DTLS1_HM_HEADER_LENGTH) {
                    /*
                     * Each fragment that was already sent must at least have
                     * contained the message header plus one other byte.
                     * Therefore |init_off| must have progressed by at least
                     * |DTLS1_HM_HEADER_LENGTH + 1| bytes. If not something went
                     * wrong.
                     */
                    return -1;
                }

                /*
                 * Adjust |init_off| and |init_num| to allow room for a new
                 * message header for this fragment.
                 */
                s->init_off -= DTLS1_HM_HEADER_LENGTH;
                s->init_num += DTLS1_HM_HEADER_LENGTH;
            } else {
                /*
                 * We must have been called again after a retry so use the
                 * fragment offset from our last attempt. We do not need
                 * to adjust |init_off| and |init_num| as above, because
                 * that should already have been done before the retry.
                 */
                frag_off = s->d1->w_msg_hdr.frag_off;
            }
        }

        used_len = BIO_wpending(SSL_get_wbio(s)) + DTLS1_RT_HEADER_LENGTH
            + mac_size + blocksize;
        if (s->d1->mtu > used_len)
            curr_mtu = s->d1->mtu - used_len;
        else
            curr_mtu = 0;

        if (curr_mtu <= DTLS1_HM_HEADER_LENGTH) {
            /*
             * grr.. we could get an error if MTU picked was wrong
             */
            ret = BIO_flush(SSL_get_wbio(s));
            if (ret <= 0) {
                s->rwstate = SSL_WRITING;
                return ret;
            }
            used_len = DTLS1_RT_HEADER_LENGTH + mac_size + blocksize;
            if (s->d1->mtu > used_len + DTLS1_HM_HEADER_LENGTH) {
                curr_mtu = s->d1->mtu - used_len;
            } else {
                /* Shouldn't happen */
                return -1;
            }
        }

        /*
         * We just checked that s->init_num > 0 so this cast should be safe
         */
        if (((unsigned int)s->init_num) > curr_mtu)
            len = curr_mtu;
        else
            len = s->init_num;

        /* Shouldn't ever happen */
        if (len > INT_MAX)
            len = INT_MAX;

        /*
         * XDTLS: this function is too long.  split out the CCS part
         */
        if (type == SSL3_RT_HANDSHAKE) {
            if (len < DTLS1_HM_HEADER_LENGTH) {
                /*
                 * len is so small that we really can't do anything sensible
                 * so fail
                 */
                return -1;
            }
            dtls1_fix_message_header(s, frag_off,
                                     len - DTLS1_HM_HEADER_LENGTH);

            dtls1_write_message_header(s,
                                       (unsigned char *)&s->init_buf->
                                       data[s->init_off]);
        }

        ret = dtls1_write_bytes(s, type, &s->init_buf->data[s->init_off],
                                len);
        if (ret < 0) {
            /*
             * might need to update MTU here, but we don't know which
             * previous packet caused the failure -- so can't really
             * retransmit anything.  continue as if everything is fine and
             * wait for an alert to handle the retransmit
             */
            if (retry && BIO_ctrl(SSL_get_wbio(s),
                                  BIO_CTRL_DGRAM_MTU_EXCEEDED, 0, NULL) > 0) {
                if (!(SSL_get_options(s) & SSL_OP_NO_QUERY_MTU)) {
                    if (!dtls1_query_mtu(s))
                        return -1;
                    /* Have one more go */
                    retry = 0;
                } else
                    return -1;
            } else {
                return (-1);
            }
        } else {

            /*
             * bad if this assert fails, only part of the handshake message
             * got sent.  but why would this happen?
             */
            OPENSSL_assert(len == (unsigned int)ret);

            if (type == SSL3_RT_HANDSHAKE && !s->d1->retransmitting) {
                /*
                 * should not be done for 'Hello Request's, but in that case
                 * we'll ignore the result anyway
                 */
                unsigned char *p =
                    (unsigned char *)&s->init_buf->data[s->init_off];
                const struct hm_header_st *msg_hdr = &s->d1->w_msg_hdr;
                int xlen;

                if (frag_off == 0 && s->version != DTLS1_BAD_VER) {
                    /*
                     * reconstruct message header is if it is being sent in
                     * single fragment
                     */
                    *p++ = msg_hdr->type;
                    l2n3(msg_hdr->msg_len, p);
                    s2n(msg_hdr->seq, p);
                    l2n3(0, p);
                    l2n3(msg_hdr->msg_len, p);
                    p -= DTLS1_HM_HEADER_LENGTH;
                    xlen = ret;
                } else {
                    p += DTLS1_HM_HEADER_LENGTH;
                    xlen = ret - DTLS1_HM_HEADER_LENGTH;
                }

                ssl3_finish_mac(s, p, xlen);
            }

            if (ret == s->init_num) {
                if (s->msg_callback)
                    s->msg_callback(1, s->version, type, s->init_buf->data,
                                    (size_t)(s->init_off + s->init_num), s,
                                    s->msg_callback_arg);

                s->init_off = 0; /* done writing this message */
                s->init_num = 0;

                return (1);
            }
            s->init_off += ret;
            s->init_num -= ret;
            ret -= DTLS1_HM_HEADER_LENGTH;
            frag_off += ret;

            /*
             * We save the fragment offset for the next fragment so we have it
             * available in case of an IO retry. We don't know the length of the
             * next fragment yet so just set that to 0 for now. It will be
             * updated again later.
             */
            dtls1_fix_message_header(s, frag_off, 0);
        }
    }
    return (0);
}

/*
 * Obtain handshake message of message type 'mt' (any if mt == -1), maximum
 * acceptable body length 'max'. Read an entire handshake message.  Handshake
 * messages arrive in fragments.
 */
long dtls1_get_message(SSL *s, int st1, int stn, int mt, long max, int *ok)
{
    int i, al;
    struct hm_header_st *msg_hdr;
    unsigned char *p;
    unsigned long msg_len;

    /*
     * s3->tmp is used to store messages that are unexpected, caused by the
     * absence of an optional handshake message
     */
    if (s->s3->tmp.reuse_message) {
        s->s3->tmp.reuse_message = 0;
        if ((mt >= 0) && (s->s3->tmp.message_type != mt)) {
            al = SSL_AD_UNEXPECTED_MESSAGE;
            SSLerr(SSL_F_DTLS1_GET_MESSAGE, SSL_R_UNEXPECTED_MESSAGE);
            goto f_err;
        }
        *ok = 1;
        s->init_msg = s->init_buf->data + DTLS1_HM_HEADER_LENGTH;
        s->init_num = (int)s->s3->tmp.message_size;
        return s->init_num;
    }

    msg_hdr = &s->d1->r_msg_hdr;
    memset(msg_hdr, 0x00, sizeof(struct hm_header_st));

 again:
    i = dtls1_get_message_fragment(s, st1, stn, max, ok);
    if (i == DTLS1_HM_BAD_FRAGMENT || i == DTLS1_HM_FRAGMENT_RETRY) {
        /* bad fragment received */
        goto again;
    } else if (i <= 0 && !*ok) {
        return i;
    }

    /*
     * Don't change the *message* read sequence number while listening. For
     * the *record* write sequence we reflect the ClientHello sequence number
     * when listening.
     */
    if (s->d1->listen)
        memcpy(s->s3->write_sequence, s->s3->read_sequence,
               sizeof(s->s3->write_sequence));
    else
        s->d1->handshake_read_seq++;

    if (mt >= 0 && s->s3->tmp.message_type != mt) {
        al = SSL_AD_UNEXPECTED_MESSAGE;
        SSLerr(SSL_F_DTLS1_GET_MESSAGE, SSL_R_UNEXPECTED_MESSAGE);
        goto f_err;
    }

    p = (unsigned char *)s->init_buf->data;
    msg_len = msg_hdr->msg_len;

    /* reconstruct message header */
    *(p++) = msg_hdr->type;
    l2n3(msg_len, p);
    s2n(msg_hdr->seq, p);
    l2n3(0, p);
    l2n3(msg_len, p);
    if (s->version != DTLS1_BAD_VER) {
        p -= DTLS1_HM_HEADER_LENGTH;
        msg_len += DTLS1_HM_HEADER_LENGTH;
    }

    ssl3_finish_mac(s, p, msg_len);
    if (s->msg_callback)
        s->msg_callback(0, s->version, SSL3_RT_HANDSHAKE,
                        p, msg_len, s, s->msg_callback_arg);

    memset(msg_hdr, 0x00, sizeof(struct hm_header_st));

    s->init_msg = s->init_buf->data + DTLS1_HM_HEADER_LENGTH;
    return s->init_num;

 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
    *ok = 0;
    return -1;
}

static int dtls1_preprocess_fragment(SSL *s, struct hm_header_st *msg_hdr,
                                     int max)
{
    size_t frag_off, frag_len, msg_len;

    msg_len = msg_hdr->msg_len;
    frag_off = msg_hdr->frag_off;
    frag_len = msg_hdr->frag_len;

    /* sanity checking */
    if ((frag_off + frag_len) > msg_len) {
        SSLerr(SSL_F_DTLS1_PREPROCESS_FRAGMENT, SSL_R_EXCESSIVE_MESSAGE_SIZE);
        return SSL_AD_ILLEGAL_PARAMETER;
    }

    if ((frag_off + frag_len) > (unsigned long)max) {
        SSLerr(SSL_F_DTLS1_PREPROCESS_FRAGMENT, SSL_R_EXCESSIVE_MESSAGE_SIZE);
        return SSL_AD_ILLEGAL_PARAMETER;
    }

    if (s->d1->r_msg_hdr.frag_off == 0) { /* first fragment */
        /*
         * msg_len is limited to 2^24, but is effectively checked against max
         * above
         *
         * Make buffer slightly larger than message length as a precaution
         * against small OOB reads e.g. CVE-2016-6306
         */
        if (!BUF_MEM_grow_clean
            (s->init_buf, msg_len + DTLS1_HM_HEADER_LENGTH + 16)) {
            SSLerr(SSL_F_DTLS1_PREPROCESS_FRAGMENT, ERR_R_BUF_LIB);
            return SSL_AD_INTERNAL_ERROR;
        }

        s->s3->tmp.message_size = msg_len;
        s->d1->r_msg_hdr.msg_len = msg_len;
        s->s3->tmp.message_type = msg_hdr->type;
        s->d1->r_msg_hdr.type = msg_hdr->type;
        s->d1->r_msg_hdr.seq = msg_hdr->seq;
    } else if (msg_len != s->d1->r_msg_hdr.msg_len) {
        /*
         * They must be playing with us! BTW, failure to enforce upper limit
         * would open possibility for buffer overrun.
         */
        SSLerr(SSL_F_DTLS1_PREPROCESS_FRAGMENT, SSL_R_EXCESSIVE_MESSAGE_SIZE);
        return SSL_AD_ILLEGAL_PARAMETER;
    }

    return 0;                   /* no error */
}

static int dtls1_retrieve_buffered_fragment(SSL *s, long max, int *ok)
{
    /*-
     * (0) check whether the desired fragment is available
     * if so:
     * (1) copy over the fragment to s->init_buf->data[]
     * (2) update s->init_num
     */
    pitem *item;
    hm_fragment *frag;
    int al;

    *ok = 0;
    do {
        item = pqueue_peek(s->d1->buffered_messages);
        if (item == NULL)
            return 0;

        frag = (hm_fragment *)item->data;

        if (frag->msg_header.seq < s->d1->handshake_read_seq) {
            /* This is a stale message that has been buffered so clear it */
            pqueue_pop(s->d1->buffered_messages);
            dtls1_hm_fragment_free(frag);
            pitem_free(item);
            item = NULL;
            frag = NULL;
        }
    } while (item == NULL);


    /* Don't return if reassembly still in progress */
    if (frag->reassembly != NULL)
        return 0;

    if (s->d1->handshake_read_seq == frag->msg_header.seq) {
        unsigned long frag_len = frag->msg_header.frag_len;
        pqueue_pop(s->d1->buffered_messages);

        al = dtls1_preprocess_fragment(s, &frag->msg_header, max);

        /* al will be 0 if no alert */
        if (al == 0  && frag->msg_header.frag_len > 0) {
            unsigned char *p =
                (unsigned char *)s->init_buf->data + DTLS1_HM_HEADER_LENGTH;
            memcpy(&p[frag->msg_header.frag_off], frag->fragment,
                   frag->msg_header.frag_len);
        }

        dtls1_hm_fragment_free(frag);
        pitem_free(item);

        if (al == 0) {
            *ok = 1;
            return frag_len;
        }

        ssl3_send_alert(s, SSL3_AL_FATAL, al);
        s->init_num = 0;
        *ok = 0;
        return -1;
    } else
        return 0;
}

/*
 * dtls1_max_handshake_message_len returns the maximum number of bytes
 * permitted in a DTLS handshake message for |s|. The minimum is 16KB, but
 * may be greater if the maximum certificate list size requires it.
 */
static unsigned long dtls1_max_handshake_message_len(const SSL *s)
{
    unsigned long max_len =
        DTLS1_HM_HEADER_LENGTH + SSL3_RT_MAX_ENCRYPTED_LENGTH;
    if (max_len < (unsigned long)s->max_cert_list)
        return s->max_cert_list;
    return max_len;
}

static int
dtls1_reassemble_fragment(SSL *s, const struct hm_header_st *msg_hdr, int *ok)
{
    hm_fragment *frag = NULL;
    pitem *item = NULL;
    int i = -1, is_complete;
    unsigned char seq64be[8];
    unsigned long frag_len = msg_hdr->frag_len;

    if ((msg_hdr->frag_off + frag_len) > msg_hdr->msg_len ||
        msg_hdr->msg_len > dtls1_max_handshake_message_len(s))
        goto err;

    if (frag_len == 0)
        return DTLS1_HM_FRAGMENT_RETRY;

    /* Try to find item in queue */
    memset(seq64be, 0, sizeof(seq64be));
    seq64be[6] = (unsigned char)(msg_hdr->seq >> 8);
    seq64be[7] = (unsigned char)msg_hdr->seq;
    item = pqueue_find(s->d1->buffered_messages, seq64be);

    if (item == NULL) {
        frag = dtls1_hm_fragment_new(msg_hdr->msg_len, 1);
        if (frag == NULL)
            goto err;
        memcpy(&(frag->msg_header), msg_hdr, sizeof(*msg_hdr));
        frag->msg_header.frag_len = frag->msg_header.msg_len;
        frag->msg_header.frag_off = 0;
    } else {
        frag = (hm_fragment *)item->data;
        if (frag->msg_header.msg_len != msg_hdr->msg_len) {
            item = NULL;
            frag = NULL;
            goto err;
        }
    }

    /*
     * If message is already reassembled, this must be a retransmit and can
     * be dropped. In this case item != NULL and so frag does not need to be
     * freed.
     */
    if (frag->reassembly == NULL) {
        unsigned char devnull[256];

        while (frag_len) {
            i = s->method->ssl_read_bytes(s, SSL3_RT_HANDSHAKE,
                                          devnull,
                                          frag_len >
                                          sizeof(devnull) ? sizeof(devnull) :
                                          frag_len, 0);
            if (i <= 0)
                goto err;
            frag_len -= i;
        }
        return DTLS1_HM_FRAGMENT_RETRY;
    }

    /* read the body of the fragment (header has already been read */
    i = s->method->ssl_read_bytes(s, SSL3_RT_HANDSHAKE,
                                  frag->fragment + msg_hdr->frag_off,
                                  frag_len, 0);
    if ((unsigned long)i != frag_len)
        i = -1;
    if (i <= 0)
        goto err;

    RSMBLY_BITMASK_MARK(frag->reassembly, (long)msg_hdr->frag_off,
                        (long)(msg_hdr->frag_off + frag_len));

    RSMBLY_BITMASK_IS_COMPLETE(frag->reassembly, (long)msg_hdr->msg_len,
                               is_complete);

    if (is_complete) {
        OPENSSL_free(frag->reassembly);
        frag->reassembly = NULL;
    }

    if (item == NULL) {
        item = pitem_new(seq64be, frag);
        if (item == NULL) {
            i = -1;
            goto err;
        }

        item = pqueue_insert(s->d1->buffered_messages, item);
        /*
         * pqueue_insert fails iff a duplicate item is inserted. However,
         * |item| cannot be a duplicate. If it were, |pqueue_find|, above,
         * would have returned it and control would never have reached this
         * branch.
         */
        OPENSSL_assert(item != NULL);
    }

    return DTLS1_HM_FRAGMENT_RETRY;

 err:
    if (frag != NULL && item == NULL)
        dtls1_hm_fragment_free(frag);
    *ok = 0;
    return i;
}

static int
dtls1_process_out_of_seq_message(SSL *s, const struct hm_header_st *msg_hdr,
                                 int *ok)
{
    int i = -1;
    hm_fragment *frag = NULL;
    pitem *item = NULL;
    unsigned char seq64be[8];
    unsigned long frag_len = msg_hdr->frag_len;

    if ((msg_hdr->frag_off + frag_len) > msg_hdr->msg_len)
        goto err;

    /* Try to find item in queue, to prevent duplicate entries */
    memset(seq64be, 0, sizeof(seq64be));
    seq64be[6] = (unsigned char)(msg_hdr->seq >> 8);
    seq64be[7] = (unsigned char)msg_hdr->seq;
    item = pqueue_find(s->d1->buffered_messages, seq64be);

    /*
     * If we already have an entry and this one is a fragment, don't discard
     * it and rather try to reassemble it.
     */
    if (item != NULL && frag_len != msg_hdr->msg_len)
        item = NULL;

    /*
     * Discard the message if sequence number was already there, is too far
     * in the future, already in the queue or if we received a FINISHED
     * before the SERVER_HELLO, which then must be a stale retransmit.
     */
    if (msg_hdr->seq <= s->d1->handshake_read_seq ||
        msg_hdr->seq > s->d1->handshake_read_seq + 10 || item != NULL ||
        (s->d1->handshake_read_seq == 0 && msg_hdr->type == SSL3_MT_FINISHED))
    {
        unsigned char devnull[256];

        while (frag_len) {
            i = s->method->ssl_read_bytes(s, SSL3_RT_HANDSHAKE,
                                          devnull,
                                          frag_len >
                                          sizeof(devnull) ? sizeof(devnull) :
                                          frag_len, 0);
            if (i <= 0)
                goto err;
            frag_len -= i;
        }
    } else {
        if (frag_len != msg_hdr->msg_len)
            return dtls1_reassemble_fragment(s, msg_hdr, ok);

        if (frag_len > dtls1_max_handshake_message_len(s))
            goto err;

        frag = dtls1_hm_fragment_new(frag_len, 0);
        if (frag == NULL)
            goto err;

        memcpy(&(frag->msg_header), msg_hdr, sizeof(*msg_hdr));

        if (frag_len) {
            /*
             * read the body of the fragment (header has already been read
             */
            i = s->method->ssl_read_bytes(s, SSL3_RT_HANDSHAKE,
                                          frag->fragment, frag_len, 0);
            if ((unsigned long)i != frag_len)
                i = -1;
            if (i <= 0)
                goto err;
        }

        item = pitem_new(seq64be, frag);
        if (item == NULL)
            goto err;

        item = pqueue_insert(s->d1->buffered_messages, item);
        /*
         * pqueue_insert fails iff a duplicate item is inserted. However,
         * |item| cannot be a duplicate. If it were, |pqueue_find|, above,
         * would have returned it. Then, either |frag_len| !=
         * |msg_hdr->msg_len| in which case |item| is set to NULL and it will
         * have been processed with |dtls1_reassemble_fragment|, above, or
         * the record will have been discarded.
         */
        OPENSSL_assert(item != NULL);
    }

    return DTLS1_HM_FRAGMENT_RETRY;

 err:
    if (frag != NULL && item == NULL)
        dtls1_hm_fragment_free(frag);
    *ok = 0;
    return i;
}

static long
dtls1_get_message_fragment(SSL *s, int st1, int stn, long max, int *ok)
{
    unsigned char wire[DTLS1_HM_HEADER_LENGTH];
    unsigned long len, frag_off, frag_len;
    int i, al;
    struct hm_header_st msg_hdr;

 redo:
    /* see if we have the required fragment already */
    if ((frag_len = dtls1_retrieve_buffered_fragment(s, max, ok)) || *ok) {
        if (*ok)
            s->init_num = frag_len;
        return frag_len;
    }

    /* read handshake message header */
    i = s->method->ssl_read_bytes(s, SSL3_RT_HANDSHAKE, wire,
                                  DTLS1_HM_HEADER_LENGTH, 0);
    if (i <= 0) {               /* nbio, or an error */
        s->rwstate = SSL_READING;
        *ok = 0;
        return i;
    }
    /* Handshake fails if message header is incomplete */
    if (i != DTLS1_HM_HEADER_LENGTH) {
        al = SSL_AD_UNEXPECTED_MESSAGE;
        SSLerr(SSL_F_DTLS1_GET_MESSAGE_FRAGMENT, SSL_R_UNEXPECTED_MESSAGE);
        goto f_err;
    }

    /* parse the message fragment header */
    dtls1_get_message_header(wire, &msg_hdr);

    len = msg_hdr.msg_len;
    frag_off = msg_hdr.frag_off;
    frag_len = msg_hdr.frag_len;

    /*
     * We must have at least frag_len bytes left in the record to be read.
     * Fragments must not span records.
     */
    if (frag_len > s->s3->rrec.length) {
        al = SSL3_AD_ILLEGAL_PARAMETER;
        SSLerr(SSL_F_DTLS1_GET_MESSAGE_FRAGMENT, SSL_R_BAD_LENGTH);
        goto f_err;
    }

    /*
     * if this is a future (or stale) message it gets buffered
     * (or dropped)--no further processing at this time
     * While listening, we accept seq 1 (ClientHello with cookie)
     * although we're still expecting seq 0 (ClientHello)
     */
    if (msg_hdr.seq != s->d1->handshake_read_seq
        && !(s->d1->listen && msg_hdr.seq == 1))
        return dtls1_process_out_of_seq_message(s, &msg_hdr, ok);

    if (frag_len && frag_len < len)
        return dtls1_reassemble_fragment(s, &msg_hdr, ok);

    if (!s->server && s->d1->r_msg_hdr.frag_off == 0 &&
        wire[0] == SSL3_MT_HELLO_REQUEST) {
        /*
         * The server may always send 'Hello Request' messages -- we are
         * doing a handshake anyway now, so ignore them if their format is
         * correct. Does not count for 'Finished' MAC.
         */
        if (wire[1] == 0 && wire[2] == 0 && wire[3] == 0) {
            if (s->msg_callback)
                s->msg_callback(0, s->version, SSL3_RT_HANDSHAKE,
                                wire, DTLS1_HM_HEADER_LENGTH, s,
                                s->msg_callback_arg);

            s->init_num = 0;
            goto redo;
        } else {                /* Incorrectly formated Hello request */

            al = SSL_AD_UNEXPECTED_MESSAGE;
            SSLerr(SSL_F_DTLS1_GET_MESSAGE_FRAGMENT,
                   SSL_R_UNEXPECTED_MESSAGE);
            goto f_err;
        }
    }

    if ((al = dtls1_preprocess_fragment(s, &msg_hdr, max)))
        goto f_err;

    if (frag_len > 0) {
        unsigned char *p =
            (unsigned char *)s->init_buf->data + DTLS1_HM_HEADER_LENGTH;

        i = s->method->ssl_read_bytes(s, SSL3_RT_HANDSHAKE,
                                      &p[frag_off], frag_len, 0);

        /*
         * This shouldn't ever fail due to NBIO because we already checked
         * that we have enough data in the record
         */
        if (i <= 0) {
            s->rwstate = SSL_READING;
            *ok = 0;
            return i;
        }
    } else
        i = 0;

    /*
     * XDTLS: an incorrectly formatted fragment should cause the handshake
     * to fail
     */
    if (i != (int)frag_len) {
        al = SSL3_AD_ILLEGAL_PARAMETER;
        SSLerr(SSL_F_DTLS1_GET_MESSAGE_FRAGMENT, SSL3_AD_ILLEGAL_PARAMETER);
        goto f_err;
    }

    *ok = 1;
    s->state = stn;

    /*
     * Note that s->init_num is *not* used as current offset in
     * s->init_buf->data, but as a counter summing up fragments' lengths: as
     * soon as they sum up to handshake packet length, we assume we have got
     * all the fragments.
     */
    s->init_num = frag_len;
    return frag_len;

 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
    s->init_num = 0;

    *ok = 0;
    return (-1);
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
int dtls1_send_change_cipher_spec(SSL *s, int a, int b)
{
    unsigned char *p;

    if (s->state == a) {
        p = (unsigned char *)s->init_buf->data;
        *p++ = SSL3_MT_CCS;
        s->d1->handshake_write_seq = s->d1->next_handshake_write_seq;
        s->init_num = DTLS1_CCS_HEADER_LENGTH;

        if (s->version == DTLS1_BAD_VER) {
            s->d1->next_handshake_write_seq++;
            s2n(s->d1->handshake_write_seq, p);
            s->init_num += 2;
        }

        s->init_off = 0;

        dtls1_set_message_header_int(s, SSL3_MT_CCS, 0,
                                     s->d1->handshake_write_seq, 0, 0);

        /* buffer the message to handle re-xmits */
        dtls1_buffer_message(s, 1);

        s->state = b;
    }

    /* SSL3_ST_CW_CHANGE_B */
    return (dtls1_do_write(s, SSL3_RT_CHANGE_CIPHER_SPEC));
}

int dtls1_read_failed(SSL *s, int code)
{
    if (code > 0) {
#ifdef TLS_DEBUG
        fprintf(stderr, "invalid state reached %s:%d", __FILE__, __LINE__);
#endif
        return 1;
    }

    if (!dtls1_is_timer_expired(s)) {
        /*
         * not a timeout, none of our business, let higher layers handle
         * this.  in fact it's probably an error
         */
        return code;
    }
#ifndef OPENSSL_NO_HEARTBEATS
    /* done, no need to send a retransmit */
    if (!SSL_in_init(s) && !s->tlsext_hb_pending)
#else
    /* done, no need to send a retransmit */
    if (!SSL_in_init(s))
#endif
    {
        BIO_set_flags(SSL_get_rbio(s), BIO_FLAGS_READ);
        return code;
    }
#if 0                           /* for now, each alert contains only one
                                 * record number */
    item = pqueue_peek(state->rcvd_records);
    if (item) {
        /* send an alert immediately for all the missing records */
    } else
#endif

#if 0                           /* no more alert sending, just retransmit the
                                 * last set of messages */
    if (state->timeout.read_timeouts >= DTLS1_TMO_READ_COUNT)
        ssl3_send_alert(s, SSL3_AL_WARNING,
                        DTLS1_AD_MISSING_HANDSHAKE_MESSAGE);
#endif

    return dtls1_handle_timeout(s);
}

int dtls1_get_queue_priority(unsigned short seq, int is_ccs)
{
    /*
     * The index of the retransmission queue actually is the message sequence
     * number, since the queue only contains messages of a single handshake.
     * However, the ChangeCipherSpec has no message sequence number and so
     * using only the sequence will result in the CCS and Finished having the
     * same index. To prevent this, the sequence number is multiplied by 2.
     * In case of a CCS 1 is subtracted. This does not only differ CSS and
     * Finished, it also maintains the order of the index (important for
     * priority queues) and fits in the unsigned short variable.
     */
    return seq * 2 - is_ccs;
}

int dtls1_retransmit_buffered_messages(SSL *s)
{
    pqueue sent = s->d1->sent_messages;
    piterator iter;
    pitem *item;
    hm_fragment *frag;
    int found = 0;

    iter = pqueue_iterator(sent);

    for (item = pqueue_next(&iter); item != NULL; item = pqueue_next(&iter)) {
        frag = (hm_fragment *)item->data;
        if (dtls1_retransmit_message(s, (unsigned short)
                                     dtls1_get_queue_priority
                                     (frag->msg_header.seq,
                                      frag->msg_header.is_ccs), 0,
                                     &found) <= 0 && found) {
#ifdef TLS_DEBUG
            fprintf(stderr, "dtls1_retransmit_message() failed\n");
#endif
            return -1;
        }
    }

    return 1;
}

int dtls1_buffer_message(SSL *s, int is_ccs)
{
    pitem *item;
    hm_fragment *frag;
    unsigned char seq64be[8];

    /*
     * this function is called immediately after a message has been
     * serialized
     */
    OPENSSL_assert(s->init_off == 0);

    frag = dtls1_hm_fragment_new(s->init_num, 0);
    if (!frag)
        return 0;

    memcpy(frag->fragment, s->init_buf->data, s->init_num);

    if (is_ccs) {
        /* For DTLS1_BAD_VER the header length is non-standard */
        OPENSSL_assert(s->d1->w_msg_hdr.msg_len +
                       ((s->version==DTLS1_BAD_VER)?3:DTLS1_CCS_HEADER_LENGTH)
                       == (unsigned int)s->init_num);
    } else {
        OPENSSL_assert(s->d1->w_msg_hdr.msg_len +
                       DTLS1_HM_HEADER_LENGTH == (unsigned int)s->init_num);
    }

    frag->msg_header.msg_len = s->d1->w_msg_hdr.msg_len;
    frag->msg_header.seq = s->d1->w_msg_hdr.seq;
    frag->msg_header.type = s->d1->w_msg_hdr.type;
    frag->msg_header.frag_off = 0;
    frag->msg_header.frag_len = s->d1->w_msg_hdr.msg_len;
    frag->msg_header.is_ccs = is_ccs;

    /* save current state */
    frag->msg_header.saved_retransmit_state.enc_write_ctx = s->enc_write_ctx;
    frag->msg_header.saved_retransmit_state.write_hash = s->write_hash;
    frag->msg_header.saved_retransmit_state.compress = s->compress;
    frag->msg_header.saved_retransmit_state.session = s->session;
    frag->msg_header.saved_retransmit_state.epoch = s->d1->w_epoch;

    memset(seq64be, 0, sizeof(seq64be));
    seq64be[6] =
        (unsigned
         char)(dtls1_get_queue_priority(frag->msg_header.seq,
                                        frag->msg_header.is_ccs) >> 8);
    seq64be[7] =
        (unsigned
         char)(dtls1_get_queue_priority(frag->msg_header.seq,
                                        frag->msg_header.is_ccs));

    item = pitem_new(seq64be, frag);
    if (item == NULL) {
        dtls1_hm_fragment_free(frag);
        return 0;
    }
#if 0
    fprintf(stderr, "buffered messge: \ttype = %xx\n", msg_buf->type);
    fprintf(stderr, "\t\t\t\t\tlen = %d\n", msg_buf->len);
    fprintf(stderr, "\t\t\t\t\tseq_num = %d\n", msg_buf->seq_num);
#endif

    pqueue_insert(s->d1->sent_messages, item);
    return 1;
}

int
dtls1_retransmit_message(SSL *s, unsigned short seq, unsigned long frag_off,
                         int *found)
{
    int ret;
    /* XDTLS: for now assuming that read/writes are blocking */
    pitem *item;
    hm_fragment *frag;
    unsigned long header_length;
    unsigned char seq64be[8];
    struct dtls1_retransmit_state saved_state;
    unsigned char save_write_sequence[8] = {0, 0, 0, 0, 0, 0, 0, 0};

    /*-
      OPENSSL_assert(s->init_num == 0);
      OPENSSL_assert(s->init_off == 0);
     */

    /* XDTLS:  the requested message ought to be found, otherwise error */
    memset(seq64be, 0, sizeof(seq64be));
    seq64be[6] = (unsigned char)(seq >> 8);
    seq64be[7] = (unsigned char)seq;

    item = pqueue_find(s->d1->sent_messages, seq64be);
    if (item == NULL) {
#ifdef TLS_DEBUG
        fprintf(stderr, "retransmit:  message %d non-existant\n", seq);
#endif
        *found = 0;
        return 0;
    }

    *found = 1;
    frag = (hm_fragment *)item->data;

    if (frag->msg_header.is_ccs)
        header_length = DTLS1_CCS_HEADER_LENGTH;
    else
        header_length = DTLS1_HM_HEADER_LENGTH;

    memcpy(s->init_buf->data, frag->fragment,
           frag->msg_header.msg_len + header_length);
    s->init_num = frag->msg_header.msg_len + header_length;

    dtls1_set_message_header_int(s, frag->msg_header.type,
                                 frag->msg_header.msg_len,
                                 frag->msg_header.seq, 0,
                                 frag->msg_header.frag_len);

    /* save current state */
    saved_state.enc_write_ctx = s->enc_write_ctx;
    saved_state.write_hash = s->write_hash;
    saved_state.compress = s->compress;
    saved_state.session = s->session;
    saved_state.epoch = s->d1->w_epoch;
    saved_state.epoch = s->d1->w_epoch;

    s->d1->retransmitting = 1;

    /* restore state in which the message was originally sent */
    s->enc_write_ctx = frag->msg_header.saved_retransmit_state.enc_write_ctx;
    s->write_hash = frag->msg_header.saved_retransmit_state.write_hash;
    s->compress = frag->msg_header.saved_retransmit_state.compress;
    s->session = frag->msg_header.saved_retransmit_state.session;
    s->d1->w_epoch = frag->msg_header.saved_retransmit_state.epoch;

    if (frag->msg_header.saved_retransmit_state.epoch ==
        saved_state.epoch - 1) {
        memcpy(save_write_sequence, s->s3->write_sequence,
               sizeof(s->s3->write_sequence));
        memcpy(s->s3->write_sequence, s->d1->last_write_sequence,
               sizeof(s->s3->write_sequence));
    }

    ret = dtls1_do_write(s, frag->msg_header.is_ccs ?
                         SSL3_RT_CHANGE_CIPHER_SPEC : SSL3_RT_HANDSHAKE);

    /* restore current state */
    s->enc_write_ctx = saved_state.enc_write_ctx;
    s->write_hash = saved_state.write_hash;
    s->compress = saved_state.compress;
    s->session = saved_state.session;
    s->d1->w_epoch = saved_state.epoch;

    if (frag->msg_header.saved_retransmit_state.epoch ==
        saved_state.epoch - 1) {
        memcpy(s->d1->last_write_sequence, s->s3->write_sequence,
               sizeof(s->s3->write_sequence));
        memcpy(s->s3->write_sequence, save_write_sequence,
               sizeof(s->s3->write_sequence));
    }

    s->d1->retransmitting = 0;

    (void)BIO_flush(SSL_get_wbio(s));
    return ret;
}

unsigned char *dtls1_set_message_header(SSL *s, unsigned char *p,
                                        unsigned char mt, unsigned long len,
                                        unsigned long frag_off,
                                        unsigned long frag_len)
{
    /* Don't change sequence numbers while listening */
    if (frag_off == 0 && !s->d1->listen) {
        s->d1->handshake_write_seq = s->d1->next_handshake_write_seq;
        s->d1->next_handshake_write_seq++;
    }

    dtls1_set_message_header_int(s, mt, len, s->d1->handshake_write_seq,
                                 frag_off, frag_len);

    return p += DTLS1_HM_HEADER_LENGTH;
}

/* don't actually do the writing, wait till the MTU has been retrieved */
static void
dtls1_set_message_header_int(SSL *s, unsigned char mt,
                             unsigned long len, unsigned short seq_num,
                             unsigned long frag_off, unsigned long frag_len)
{
    struct hm_header_st *msg_hdr = &s->d1->w_msg_hdr;

    msg_hdr->type = mt;
    msg_hdr->msg_len = len;
    msg_hdr->seq = seq_num;
    msg_hdr->frag_off = frag_off;
    msg_hdr->frag_len = frag_len;
}

static void
dtls1_fix_message_header(SSL *s, unsigned long frag_off,
                         unsigned long frag_len)
{
    struct hm_header_st *msg_hdr = &s->d1->w_msg_hdr;

    msg_hdr->frag_off = frag_off;
    msg_hdr->frag_len = frag_len;
}

static unsigned char *dtls1_write_message_header(SSL *s, unsigned char *p)
{
    struct hm_header_st *msg_hdr = &s->d1->w_msg_hdr;

    *p++ = msg_hdr->type;
    l2n3(msg_hdr->msg_len, p);

    s2n(msg_hdr->seq, p);
    l2n3(msg_hdr->frag_off, p);
    l2n3(msg_hdr->frag_len, p);

    return p;
}

unsigned int dtls1_link_min_mtu(void)
{
    return (g_probable_mtu[(sizeof(g_probable_mtu) /
                            sizeof(g_probable_mtu[0])) - 1]);
}

unsigned int dtls1_min_mtu(SSL *s)
{
    return dtls1_link_min_mtu() - BIO_dgram_get_mtu_overhead(SSL_get_wbio(s));
}

void
dtls1_get_message_header(unsigned char *data, struct hm_header_st *msg_hdr)
{
    memset(msg_hdr, 0x00, sizeof(struct hm_header_st));
    msg_hdr->type = *(data++);
    n2l3(data, msg_hdr->msg_len);

    n2s(data, msg_hdr->seq);
    n2l3(data, msg_hdr->frag_off);
    n2l3(data, msg_hdr->frag_len);
}

void dtls1_get_ccs_header(unsigned char *data, struct ccs_header_st *ccs_hdr)
{
    memset(ccs_hdr, 0x00, sizeof(struct ccs_header_st));

    ccs_hdr->type = *(data++);
}

int dtls1_shutdown(SSL *s)
{
    int ret;
#ifndef OPENSSL_NO_SCTP
    BIO *wbio;

    wbio = SSL_get_wbio(s);
    if (wbio != NULL && BIO_dgram_is_sctp(wbio) &&
        !(s->shutdown & SSL_SENT_SHUTDOWN)) {
        ret = BIO_dgram_sctp_wait_for_dry(wbio);
        if (ret < 0)
            return -1;

        if (ret == 0)
            BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_SAVE_SHUTDOWN, 1,
                     NULL);
    }
#endif
    ret = ssl3_shutdown(s);
#ifndef OPENSSL_NO_SCTP
    BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_SAVE_SHUTDOWN, 0, NULL);
#endif
    return ret;
}

#ifndef OPENSSL_NO_HEARTBEATS
int dtls1_process_heartbeat(SSL *s)
{
    unsigned char *p = &s->s3->rrec.data[0], *pl;
    unsigned short hbtype;
    unsigned int payload;
    unsigned int padding = 16;  /* Use minimum padding */

    if (s->msg_callback)
        s->msg_callback(0, s->version, TLS1_RT_HEARTBEAT,
                        &s->s3->rrec.data[0], s->s3->rrec.length,
                        s, s->msg_callback_arg);

    /* Read type and payload length first */
    if (1 + 2 + 16 > s->s3->rrec.length)
        return 0;               /* silently discard */
    if (s->s3->rrec.length > SSL3_RT_MAX_PLAIN_LENGTH)
        return 0;               /* silently discard per RFC 6520 sec. 4 */

    hbtype = *p++;
    n2s(p, payload);
    if (1 + 2 + payload + 16 > s->s3->rrec.length)
        return 0;               /* silently discard per RFC 6520 sec. 4 */
    pl = p;

    if (hbtype == TLS1_HB_REQUEST) {
        unsigned char *buffer, *bp;
        unsigned int write_length = 1 /* heartbeat type */  +
            2 /* heartbeat length */  +
            payload + padding;
        int r;

        if (write_length > SSL3_RT_MAX_PLAIN_LENGTH)
            return 0;

        /*
         * Allocate memory for the response, size is 1 byte message type,
         * plus 2 bytes payload length, plus payload, plus padding
         */
        buffer = OPENSSL_malloc(write_length);
        if (buffer == NULL)
            return -1;
        bp = buffer;

        /* Enter response type, length and copy payload */
        *bp++ = TLS1_HB_RESPONSE;
        s2n(payload, bp);
        memcpy(bp, pl, payload);
        bp += payload;
        /* Random padding */
        if (RAND_bytes(bp, padding) <= 0) {
            OPENSSL_free(buffer);
            return -1;
        }

        r = dtls1_write_bytes(s, TLS1_RT_HEARTBEAT, buffer, write_length);

        if (r >= 0 && s->msg_callback)
            s->msg_callback(1, s->version, TLS1_RT_HEARTBEAT,
                            buffer, write_length, s, s->msg_callback_arg);

        OPENSSL_free(buffer);

        if (r < 0)
            return r;
    } else if (hbtype == TLS1_HB_RESPONSE) {
        unsigned int seq;

        /*
         * We only send sequence numbers (2 bytes unsigned int), and 16
         * random bytes, so we just try to read the sequence number
         */
        n2s(pl, seq);

        if (payload == 18 && seq == s->tlsext_hb_seq) {
            dtls1_stop_timer(s);
            s->tlsext_hb_seq++;
            s->tlsext_hb_pending = 0;
        }
    }

    return 0;
}

int dtls1_heartbeat(SSL *s)
{
    unsigned char *buf, *p;
    int ret = -1;
    unsigned int payload = 18;  /* Sequence number + random bytes */
    unsigned int padding = 16;  /* Use minimum padding */

    /* Only send if peer supports and accepts HB requests... */
    if (!(s->tlsext_heartbeat & SSL_TLSEXT_HB_ENABLED) ||
        s->tlsext_heartbeat & SSL_TLSEXT_HB_DONT_SEND_REQUESTS) {
        SSLerr(SSL_F_DTLS1_HEARTBEAT, SSL_R_TLS_HEARTBEAT_PEER_DOESNT_ACCEPT);
        return -1;
    }

    /* ...and there is none in flight yet... */
    if (s->tlsext_hb_pending) {
        SSLerr(SSL_F_DTLS1_HEARTBEAT, SSL_R_TLS_HEARTBEAT_PENDING);
        return -1;
    }

    /* ...and no handshake in progress. */
    if (SSL_in_init(s) || s->in_handshake) {
        SSLerr(SSL_F_DTLS1_HEARTBEAT, SSL_R_UNEXPECTED_MESSAGE);
        return -1;
    }

    /*
     * Check if padding is too long, payload and padding must not exceed 2^14
     * - 3 = 16381 bytes in total.
     */
    OPENSSL_assert(payload + padding <= 16381);

    /*-
     * Create HeartBeat message, we just use a sequence number
     * as payload to distuingish different messages and add
     * some random stuff.
     *  - Message Type, 1 byte
     *  - Payload Length, 2 bytes (unsigned int)
     *  - Payload, the sequence number (2 bytes uint)
     *  - Payload, random bytes (16 bytes uint)
     *  - Padding
     */
    buf = OPENSSL_malloc(1 + 2 + payload + padding);
    if (buf == NULL)
        goto err;
    p = buf;
    /* Message Type */
    *p++ = TLS1_HB_REQUEST;
    /* Payload length (18 bytes here) */
    s2n(payload, p);
    /* Sequence number */
    s2n(s->tlsext_hb_seq, p);
    /* 16 random bytes */
    if (RAND_bytes(p, 16) <= 0)
        goto err;
    p += 16;
    /* Random padding */
    if (RAND_bytes(p, padding) <= 0)
        goto err;

    ret = dtls1_write_bytes(s, TLS1_RT_HEARTBEAT, buf, 3 + payload + padding);
    if (ret >= 0) {
        if (s->msg_callback)
            s->msg_callback(1, s->version, TLS1_RT_HEARTBEAT,
                            buf, 3 + payload + padding,
                            s, s->msg_callback_arg);

        dtls1_start_timer(s);
        s->tlsext_hb_pending = 1;
    }

err:
    OPENSSL_free(buf);

    return ret;
}
#endif
/* ssl/d1_clnt.c */
/*
 * DTLS implementation written by Nagendra Modadugu
 * (nagendra@cs.stanford.edu) for the OpenSSL project 2005.
 */
/* ====================================================================
 * Copyright (c) 1999-2007 The OpenSSL Project.  All rights reserved.
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
// #include "ssl_locl.h"
#ifndef OPENSSL_NO_KRB5
# include "kssl_lcl.h"
#endif
// #include "buffer.h"
// #include "rand.h"
// #include "objects.h"
// #include "evp.h"
#include "md5.h"
#include "bn.h"
#ifndef OPENSSL_NO_DH
# include "dh.h"
#endif

static const SSL_METHOD *dtls1_get_client_method(int ver);
static int dtls1_get_hello_verify(SSL *s);

static const SSL_METHOD *dtls1_get_client_method(int ver)
{
    if (ver == DTLS_ANY_VERSION)
        return DTLS_client_method();
    else if (ver == DTLS1_VERSION || ver == DTLS1_BAD_VER)
        return DTLSv1_client_method();
    else if (ver == DTLS1_2_VERSION)
        return DTLSv1_2_client_method();
    else
        return NULL;
}

IMPLEMENT_dtls1_meth_func(DTLS1_VERSION,
                          DTLSv1_client_method,
                          ssl_undefined_function,
                          dtls1_connect,
                          dtls1_get_client_method, DTLSv1_enc_data)

IMPLEMENT_dtls1_meth_func(DTLS1_2_VERSION,
                          DTLSv1_2_client_method,
                          ssl_undefined_function,
                          dtls1_connect,
                          dtls1_get_client_method, DTLSv1_2_enc_data)

IMPLEMENT_dtls1_meth_func(DTLS_ANY_VERSION,
                          DTLS_client_method,
                          ssl_undefined_function,
                          dtls1_connect,
                          dtls1_get_client_method, DTLSv1_2_enc_data)

int dtls1_connect(SSL *s)
{
    BUF_MEM *buf = NULL;
    unsigned long Time = (unsigned long)time(NULL);
    void (*cb) (const SSL *ssl, int type, int val) = NULL;
    int ret = -1;
    int new_state, state, skip = 0;
#ifndef OPENSSL_NO_SCTP
    unsigned char sctpauthkey[64];
    char labelbuffer[sizeof(DTLS1_SCTP_AUTH_LABEL)];
#endif

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

#ifndef OPENSSL_NO_SCTP
    /*
     * Notify SCTP BIO socket to enter handshake mode and prevent stream
     * identifier other than 0. Will be ignored if no SCTP is used.
     */
    BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_SET_IN_HANDSHAKE,
             s->in_handshake, NULL);
#endif

#ifndef OPENSSL_NO_HEARTBEATS
    /*
     * If we're awaiting a HeartbeatResponse, pretend we already got and
     * don't await it anymore, because Heartbeats don't make sense during
     * handshakes anyway.
     */
    if (s->tlsext_hb_pending) {
        dtls1_stop_timer(s);
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

            if ((s->version & 0xff00) != (DTLS1_VERSION & 0xff00) &&
                (s->version & 0xff00) != (DTLS1_BAD_VER & 0xff00)) {
                SSLerr(SSL_F_DTLS1_CONNECT, ERR_R_INTERNAL_ERROR);
                ret = -1;
                s->state = SSL_ST_ERR;
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

            s->state = SSL3_ST_CW_CLNT_HELLO_A;
            s->ctx->stats.sess_connect++;
            s->init_num = 0;
            /* mark client_random uninitialized */
            memset(s->s3->client_random, 0, sizeof(s->s3->client_random));
            s->d1->send_cookie = 0;
            s->hit = 0;
            s->d1->change_cipher_spec_ok = 0;
            /*
             * Should have been reset by ssl3_get_finished, too.
             */
            s->s3->change_cipher_spec = 0;
            break;

#ifndef OPENSSL_NO_SCTP
        case DTLS1_SCTP_ST_CR_READ_SOCK:

            if (BIO_dgram_sctp_msg_waiting(SSL_get_rbio(s))) {
                s->s3->in_read_app_data = 2;
                s->rwstate = SSL_READING;
                BIO_clear_retry_flags(SSL_get_rbio(s));
                BIO_set_retry_read(SSL_get_rbio(s));
                ret = -1;
                goto end;
            }

            s->state = s->s3->tmp.next_state;
            break;

        case DTLS1_SCTP_ST_CW_WRITE_SOCK:
            /* read app data until dry event */

            ret = BIO_dgram_sctp_wait_for_dry(SSL_get_wbio(s));
            if (ret < 0)
                goto end;

            if (ret == 0) {
                s->s3->in_read_app_data = 2;
                s->rwstate = SSL_READING;
                BIO_clear_retry_flags(SSL_get_rbio(s));
                BIO_set_retry_read(SSL_get_rbio(s));
                ret = -1;
                goto end;
            }

            s->state = s->d1->next_state;
            break;
#endif

        case SSL3_ST_CW_CLNT_HELLO_A:
            s->shutdown = 0;

            /* every DTLS ClientHello resets Finished MAC */
            if (!ssl3_init_finished_mac(s)) {
                ret = -1;
                s->state = SSL_ST_ERR;
                goto end;
            }

            /* fall thru */
        case SSL3_ST_CW_CLNT_HELLO_B:
            dtls1_start_timer(s);
            ret = ssl3_client_hello(s);
            if (ret <= 0)
                goto end;

            if (s->d1->send_cookie) {
                s->state = SSL3_ST_CW_FLUSH;
                s->s3->tmp.next_state = SSL3_ST_CR_SRVR_HELLO_A;
            } else
                s->state = SSL3_ST_CR_SRVR_HELLO_A;

            s->init_num = 0;

#ifndef OPENSSL_NO_SCTP
            /* Disable buffering for SCTP */
            if (!BIO_dgram_is_sctp(SSL_get_wbio(s))) {
#endif
                /*
                 * turn on buffering for the next lot of output
                 */
                if (s->bbio != s->wbio)
                    s->wbio = BIO_push(s->bbio, s->wbio);
#ifndef OPENSSL_NO_SCTP
            }
#endif

            break;

        case SSL3_ST_CR_SRVR_HELLO_A:
        case SSL3_ST_CR_SRVR_HELLO_B:
            ret = ssl3_get_server_hello(s);
            if (ret <= 0)
                goto end;
            else {
                if (s->hit) {
#ifndef OPENSSL_NO_SCTP
                    /*
                     * Add new shared key for SCTP-Auth, will be ignored if
                     * no SCTP used.
                     */
                    snprintf((char *)labelbuffer,
                             sizeof(DTLS1_SCTP_AUTH_LABEL),
                             DTLS1_SCTP_AUTH_LABEL);

                    if (SSL_export_keying_material(s, sctpauthkey,
                                               sizeof(sctpauthkey),
                                               labelbuffer,
                                               sizeof(labelbuffer), NULL, 0,
                                               0) <= 0) {
                        ret = -1;
                        s->state = SSL_ST_ERR;
                        goto end;
                    }

                    BIO_ctrl(SSL_get_wbio(s),
                             BIO_CTRL_DGRAM_SCTP_ADD_AUTH_KEY,
                             sizeof(sctpauthkey), sctpauthkey);
#endif

                    s->state = SSL3_ST_CR_FINISHED_A;
                    if (s->tlsext_ticket_expected) {
                        /* receive renewed session ticket */
                        s->state = SSL3_ST_CR_SESSION_TICKET_A;
                    }
                } else
                    s->state = DTLS1_ST_CR_HELLO_VERIFY_REQUEST_A;
            }
            s->init_num = 0;
            break;

        case DTLS1_ST_CR_HELLO_VERIFY_REQUEST_A:
        case DTLS1_ST_CR_HELLO_VERIFY_REQUEST_B:

            ret = dtls1_get_hello_verify(s);
            if (ret <= 0)
                goto end;
            dtls1_stop_timer(s);
            if (s->d1->send_cookie) /* start again, with a cookie */
                s->state = SSL3_ST_CW_CLNT_HELLO_A;
            else
                s->state = SSL3_ST_CR_CERT_A;
            s->init_num = 0;
            break;

        case SSL3_ST_CR_CERT_A:
        case SSL3_ST_CR_CERT_B:
            /* Check if it is anon DH or PSK */
            if (!(s->s3->tmp.new_cipher->algorithm_auth & SSL_aNULL) &&
                !(s->s3->tmp.new_cipher->algorithm_mkey & SSL_kPSK)) {
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
            dtls1_stop_timer(s);
            if (s->s3->tmp.cert_req)
                s->s3->tmp.next_state = SSL3_ST_CW_CERT_A;
            else
                s->s3->tmp.next_state = SSL3_ST_CW_KEY_EXCH_A;
            s->init_num = 0;

#ifndef OPENSSL_NO_SCTP
            if (BIO_dgram_is_sctp(SSL_get_wbio(s)) &&
                state == SSL_ST_RENEGOTIATE)
                s->state = DTLS1_SCTP_ST_CR_READ_SOCK;
            else
#endif
                s->state = s->s3->tmp.next_state;
            break;

        case SSL3_ST_CW_CERT_A:
        case SSL3_ST_CW_CERT_B:
        case SSL3_ST_CW_CERT_C:
        case SSL3_ST_CW_CERT_D:
            dtls1_start_timer(s);
            ret = ssl3_send_client_certificate(s);
            if (ret <= 0)
                goto end;
            s->state = SSL3_ST_CW_KEY_EXCH_A;
            s->init_num = 0;
            break;

        case SSL3_ST_CW_KEY_EXCH_A:
        case SSL3_ST_CW_KEY_EXCH_B:
            dtls1_start_timer(s);
            ret = ssl3_send_client_key_exchange(s);
            if (ret <= 0)
                goto end;

#ifndef OPENSSL_NO_SCTP
            /*
             * Add new shared key for SCTP-Auth, will be ignored if no SCTP
             * used.
             */
            snprintf((char *)labelbuffer, sizeof(DTLS1_SCTP_AUTH_LABEL),
                     DTLS1_SCTP_AUTH_LABEL);

            if (SSL_export_keying_material(s, sctpauthkey,
                                       sizeof(sctpauthkey), labelbuffer,
                                       sizeof(labelbuffer), NULL, 0, 0) <= 0) {
                ret = -1;
                s->state = SSL_ST_ERR;
                goto end;
            }

            BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_ADD_AUTH_KEY,
                     sizeof(sctpauthkey), sctpauthkey);
#endif

            /*
             * EAY EAY EAY need to check for DH fix cert sent back
             */
            /*
             * For TLS, cert_req is set to 2, so a cert chain of nothing is
             * sent, but no verify packet is sent
             */
            if (s->s3->tmp.cert_req == 1) {
                s->state = SSL3_ST_CW_CERT_VRFY_A;
            } else {
#ifndef OPENSSL_NO_SCTP
                if (BIO_dgram_is_sctp(SSL_get_wbio(s))) {
                    s->d1->next_state = SSL3_ST_CW_CHANGE_A;
                    s->state = DTLS1_SCTP_ST_CW_WRITE_SOCK;
                } else
#endif
                    s->state = SSL3_ST_CW_CHANGE_A;
            }

            s->init_num = 0;
            break;

        case SSL3_ST_CW_CERT_VRFY_A:
        case SSL3_ST_CW_CERT_VRFY_B:
            dtls1_start_timer(s);
            ret = ssl3_send_client_verify(s);
            if (ret <= 0)
                goto end;
#ifndef OPENSSL_NO_SCTP
            if (BIO_dgram_is_sctp(SSL_get_wbio(s))) {
                s->d1->next_state = SSL3_ST_CW_CHANGE_A;
                s->state = DTLS1_SCTP_ST_CW_WRITE_SOCK;
            } else
#endif
                s->state = SSL3_ST_CW_CHANGE_A;
            s->init_num = 0;
            break;

        case SSL3_ST_CW_CHANGE_A:
        case SSL3_ST_CW_CHANGE_B:
            if (!s->hit)
                dtls1_start_timer(s);
            ret = dtls1_send_change_cipher_spec(s,
                                                SSL3_ST_CW_CHANGE_A,
                                                SSL3_ST_CW_CHANGE_B);
            if (ret <= 0)
                goto end;

            s->state = SSL3_ST_CW_FINISHED_A;
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
#ifndef OPENSSL_NO_SCTP
            if (s->hit) {
                /*
                 * Change to new shared key of SCTP-Auth, will be ignored if
                 * no SCTP used.
                 */
                BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_NEXT_AUTH_KEY,
                         0, NULL);
            }
#endif

            dtls1_reset_seq_numbers(s, SSL3_CC_WRITE);
            break;

        case SSL3_ST_CW_FINISHED_A:
        case SSL3_ST_CW_FINISHED_B:
            if (!s->hit)
                dtls1_start_timer(s);
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
#ifndef OPENSSL_NO_SCTP
                if (BIO_dgram_is_sctp(SSL_get_wbio(s))) {
                    s->d1->next_state = s->s3->tmp.next_state;
                    s->s3->tmp.next_state = DTLS1_SCTP_ST_CW_WRITE_SOCK;
                }
#endif
                if (s->s3->flags & SSL3_FLAGS_DELAY_CLIENT_FINISHED) {
                    s->state = SSL_ST_OK;
#ifndef OPENSSL_NO_SCTP
                    if (BIO_dgram_is_sctp(SSL_get_wbio(s))) {
                        s->d1->next_state = SSL_ST_OK;
                        s->state = DTLS1_SCTP_ST_CW_WRITE_SOCK;
                    }
#endif
                    s->s3->flags |= SSL3_FLAGS_POP_BUFFER;
                    s->s3->delay_buf_pop_ret = 0;
                }
            } else {
#ifndef OPENSSL_NO_SCTP
                /*
                 * Change to new shared key of SCTP-Auth, will be ignored if
                 * no SCTP used.
                 */
                BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_NEXT_AUTH_KEY,
                         0, NULL);
#endif

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
            s->d1->change_cipher_spec_ok = 1;
            ret = ssl3_get_finished(s, SSL3_ST_CR_FINISHED_A,
                                    SSL3_ST_CR_FINISHED_B);
            if (ret <= 0)
                goto end;
            dtls1_stop_timer(s);

            if (s->hit)
                s->state = SSL3_ST_CW_CHANGE_A;
            else
                s->state = SSL_ST_OK;

#ifndef OPENSSL_NO_SCTP
            if (BIO_dgram_is_sctp(SSL_get_wbio(s)) &&
                state == SSL_ST_RENEGOTIATE) {
                s->d1->next_state = s->state;
                s->state = DTLS1_SCTP_ST_CW_WRITE_SOCK;
            }
#endif

            s->init_num = 0;
            break;

        case SSL3_ST_CW_FLUSH:
            s->rwstate = SSL_WRITING;
            if (BIO_flush(s->wbio) <= 0) {
                /*
                 * If the write error was fatal, stop trying
                 */
                if (!BIO_should_retry(s->wbio)) {
                    s->rwstate = SSL_NOTHING;
                    s->state = s->s3->tmp.next_state;
                }

                ret = -1;
                goto end;
            }
            s->rwstate = SSL_NOTHING;
            s->state = s->s3->tmp.next_state;
            break;

        case SSL_ST_OK:
            /* clean a few things up */
            ssl3_cleanup_key_block(s);

#if 0
            if (s->init_buf != NULL) {
                BUF_MEM_free(s->init_buf);
                s->init_buf = NULL;
            }
#endif

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
            s->handshake_func = dtls1_connect;
            s->ctx->stats.sess_connect_good++;

            if (cb != NULL)
                cb(s, SSL_CB_HANDSHAKE_DONE, 1);

            /* done with handshaking */
            s->d1->handshake_read_seq = 0;
            s->d1->next_handshake_write_seq = 0;
            dtls1_clear_received_buffer(s);
            goto end;
            /* break; */

        case SSL_ST_ERR:
        default:
            SSLerr(SSL_F_DTLS1_CONNECT, SSL_R_UNKNOWN_STATE);
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

#ifndef OPENSSL_NO_SCTP
    /*
     * Notify SCTP BIO socket to leave handshake mode and allow stream
     * identifier other than 0. Will be ignored if no SCTP is used.
     */
    BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_SET_IN_HANDSHAKE,
             s->in_handshake, NULL);
#endif

    if (buf != NULL)
        BUF_MEM_free(buf);
    if (cb != NULL)
        cb(s, SSL_CB_CONNECT_EXIT, ret);
    return (ret);
}

static int dtls1_get_hello_verify(SSL *s)
{
    int n, al, ok = 0;
    unsigned char *data;
    unsigned int cookie_len;

    s->first_packet = 1;
    n = s->method->ssl_get_message(s,
                                   DTLS1_ST_CR_HELLO_VERIFY_REQUEST_A,
                                   DTLS1_ST_CR_HELLO_VERIFY_REQUEST_B,
                                   -1, s->max_cert_list, &ok);
    s->first_packet = 0;

    if (!ok)
        return ((int)n);

    if (s->s3->tmp.message_type != DTLS1_MT_HELLO_VERIFY_REQUEST) {
        s->d1->send_cookie = 0;
        s->s3->tmp.reuse_message = 1;
        return (1);
    }

    data = (unsigned char *)s->init_msg;
#if 0
    if (s->method->version != DTLS_ANY_VERSION &&
        ((data[0] != (s->version >> 8)) || (data[1] != (s->version & 0xff))))
    {
        SSLerr(SSL_F_DTLS1_GET_HELLO_VERIFY, SSL_R_WRONG_SSL_VERSION);
        s->version = (s->version & 0xff00) | data[1];
        al = SSL_AD_PROTOCOL_VERSION;
        goto f_err;
    }
#endif
    data += 2;

    cookie_len = *(data++);
    if (cookie_len > sizeof(s->d1->cookie)) {
        al = SSL_AD_ILLEGAL_PARAMETER;
        goto f_err;
    }

    memcpy(s->d1->cookie, data, cookie_len);
    s->d1->cookie_len = cookie_len;

    s->d1->send_cookie = 1;
    return 1;

 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
    s->state = SSL_ST_ERR;
    return -1;
}
/* ssl/d1_meth.h */
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
// #include "objects.h"
// #include "ssl_locl.h"

static const SSL_METHOD *dtls1_get_method(int ver);
static const SSL_METHOD *dtls1_get_method(int ver)
{
    if (ver == DTLS_ANY_VERSION)
        return DTLS_method();
    else if (ver == DTLS1_VERSION)
        return DTLSv1_method();
    else if (ver == DTLS1_2_VERSION)
        return DTLSv1_2_method();
    else
        return NULL;
}

IMPLEMENT_dtls1_meth_func(DTLS1_VERSION,
                          DTLSv1_method,
                          dtls1_accept,
                          dtls1_connect, dtls1_get_method, DTLSv1_enc_data)

IMPLEMENT_dtls1_meth_func(DTLS1_2_VERSION,
                          DTLSv1_2_method,
                          dtls1_accept,
                          dtls1_connect, dtls1_get_method, DTLSv1_2_enc_data)

IMPLEMENT_dtls1_meth_func(DTLS_ANY_VERSION,
                          DTLS_method,
                          dtls1_accept,
                          dtls1_connect, dtls1_get_method, DTLSv1_2_enc_data)
/* ssl/d1_pkt.c */
/*
 * DTLS implementation written by Nagendra Modadugu
 * (nagendra@cs.stanford.edu) for the OpenSSL project 2005.
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

#include <stdio.h>
#include <errno.h>
#define USE_SOCKETS
// #include "ssl_locl.h"
// #include "evp.h"
// #include "buffer.h"
#include "pqueue.h"
// #include "rand.h"

/* mod 128 saturating subtract of two 64-bit values in big-endian order */
static int satsub64be(const unsigned char *v1, const unsigned char *v2)
{
    int ret, i;

    if (sizeof(long) == 8)
        do {
            const union {
                long one;
                char little;
            } is_endian = {
                1
            };
            long l;

            if (is_endian.little)
                break;
            /* not reached on little-endians */
            /*
             * following test is redundant, because input is always aligned,
             * but I take no chances...
             */
            if (((size_t)v1 | (size_t)v2) & 0x7)
                break;

            l = *((long *)v1);
            l -= *((long *)v2);
            if (l > 128)
                return 128;
            else if (l < -128)
                return -128;
            else
                return (int)l;
        } while (0);

    ret = 0;
    for (i=0; i<7; i++) {
        if (v1[i] > v2[i]) {
            /* v1 is larger... but by how much? */
            if (v1[i] != v2[i] + 1)
                return 128;
            while (++i <= 6) {
                if (v1[i] != 0x00 || v2[i] != 0xff)
                    return 128; /* too much */
            }
            /* We checked all the way to the penultimate byte,
             * so despite higher bytes changing we actually
             * know that it only changed from (e.g.)
             *       ... (xx)  ff ff ff ??
             * to   ... (xx+1) 00 00 00 ??
             * so we add a 'bias' of 256 for the carry that
             * happened, and will eventually return
             * 256 + v1[7] - v2[7]. */
            ret = 256;
            break;
        } else if (v2[i] > v1[i]) {
            /* v2 is larger... but by how much? */
            if (v2[i] != v1[i] + 1)
                return -128;
            while (++i <= 6) {
                if (v2[i] != 0x00 || v1[i] != 0xff)
                    return -128; /* too much */
            }
            /* Similar to the case above, we know it changed
             * from    ... (xx)  00 00 00 ??
             * to     ... (xx-1) ff ff ff ??
             * so we add a 'bias' of -256 for the borrow,
             * to return -256 + v1[7] - v2[7]. */
            ret = -256;
        }
    }

    ret += (int)v1[7] - (int)v2[7];

    if (ret > 128)
        return 128;
    else if (ret < -128)
        return -128;
    else
        return ret;
}

static int have_handshake_fragment(SSL *s, int type, unsigned char *buf,
                                   int len, int peek);
static int dtls1_record_replay_check(SSL *s, DTLS1_BITMAP *bitmap);
static void dtls1_record_bitmap_update(SSL *s, DTLS1_BITMAP *bitmap);
static DTLS1_BITMAP *dtls1_get_bitmap(SSL *s, SSL3_RECORD *rr,
                                      unsigned int *is_next_epoch);
#if 0
static int dtls1_record_needs_buffering(SSL *s, SSL3_RECORD *rr,
                                        unsigned short *priority,
                                        unsigned long *offset);
#endif
static int dtls1_buffer_record(SSL *s, record_pqueue *q,
                               unsigned char *priority);
static int dtls1_process_record(SSL *s, DTLS1_BITMAP *bitmap);

/* copy buffered record into SSL structure */
static int dtls1_copy_record(SSL *s, pitem *item)
{
    DTLS1_RECORD_DATA *rdata;

    rdata = (DTLS1_RECORD_DATA *)item->data;

    if (s->s3->rbuf.buf != NULL)
        OPENSSL_free(s->s3->rbuf.buf);

    s->packet = rdata->packet;
    s->packet_length = rdata->packet_length;
    memcpy(&(s->s3->rbuf), &(rdata->rbuf), sizeof(SSL3_BUFFER));
    memcpy(&(s->s3->rrec), &(rdata->rrec), sizeof(SSL3_RECORD));

    /* Set proper sequence number for mac calculation */
    memcpy(&(s->s3->read_sequence[2]), &(rdata->packet[5]), 6);

    return (1);
}

static int
dtls1_buffer_record(SSL *s, record_pqueue *queue, unsigned char *priority)
{
    DTLS1_RECORD_DATA *rdata;
    pitem *item;

    /* Limit the size of the queue to prevent DOS attacks */
    if (pqueue_size(queue->q) >= 100)
        return 0;

    rdata = OPENSSL_malloc(sizeof(DTLS1_RECORD_DATA));
    item = pitem_new(priority, rdata);
    if (rdata == NULL || item == NULL) {
        if (rdata != NULL)
            OPENSSL_free(rdata);
        if (item != NULL)
            pitem_free(item);

        SSLerr(SSL_F_DTLS1_BUFFER_RECORD, ERR_R_INTERNAL_ERROR);
        return -1;
    }

    rdata->packet = s->packet;
    rdata->packet_length = s->packet_length;
    memcpy(&(rdata->rbuf), &(s->s3->rbuf), sizeof(SSL3_BUFFER));
    memcpy(&(rdata->rrec), &(s->s3->rrec), sizeof(SSL3_RECORD));

    item->data = rdata;

#ifndef OPENSSL_NO_SCTP
    /* Store bio_dgram_sctp_rcvinfo struct */
    if (BIO_dgram_is_sctp(SSL_get_rbio(s)) &&
        (s->state == SSL3_ST_SR_FINISHED_A
         || s->state == SSL3_ST_CR_FINISHED_A)) {
        BIO_ctrl(SSL_get_rbio(s), BIO_CTRL_DGRAM_SCTP_GET_RCVINFO,
                 sizeof(rdata->recordinfo), &rdata->recordinfo);
    }
#endif

    s->packet = NULL;
    s->packet_length = 0;
    memset(&(s->s3->rbuf), 0, sizeof(SSL3_BUFFER));
    memset(&(s->s3->rrec), 0, sizeof(SSL3_RECORD));

    if (!ssl3_setup_buffers(s)) {
        SSLerr(SSL_F_DTLS1_BUFFER_RECORD, ERR_R_INTERNAL_ERROR);
        if (rdata->rbuf.buf != NULL)
            OPENSSL_free(rdata->rbuf.buf);
        OPENSSL_free(rdata);
        pitem_free(item);
        return (-1);
    }

    if (pqueue_insert(queue->q, item) == NULL) {
        /* Must be a duplicate so ignore it */
        if (rdata->rbuf.buf != NULL)
            OPENSSL_free(rdata->rbuf.buf);
        OPENSSL_free(rdata);
        pitem_free(item);
    }

    return (1);
}

static int dtls1_retrieve_buffered_record(SSL *s, record_pqueue *queue)
{
    pitem *item;

    item = pqueue_pop(queue->q);
    if (item) {
        dtls1_copy_record(s, item);

        OPENSSL_free(item->data);
        pitem_free(item);

        return (1);
    }

    return (0);
}

/*
 * retrieve a buffered record that belongs to the new epoch, i.e., not
 * processed yet
 */
#define dtls1_get_unprocessed_record(s) \
                   dtls1_retrieve_buffered_record((s), \
                   &((s)->d1->unprocessed_rcds))

/*
 * retrieve a buffered record that belongs to the current epoch, ie,
 * processed
 */
#define dtls1_get_processed_record(s) \
                   dtls1_retrieve_buffered_record((s), \
                   &((s)->d1->processed_rcds))

static int dtls1_process_buffered_records(SSL *s)
{
    pitem *item;
    SSL3_BUFFER *rb;
    SSL3_RECORD *rr;
    DTLS1_BITMAP *bitmap;
    unsigned int is_next_epoch;
    int replayok = 1;

    item = pqueue_peek(s->d1->unprocessed_rcds.q);
    if (item) {
        /* Check if epoch is current. */
        if (s->d1->unprocessed_rcds.epoch != s->d1->r_epoch)
            return 1;         /* Nothing to do. */

        rr = &s->s3->rrec;
        rb = &s->s3->rbuf;

        if (rb->left > 0) {
            /*
             * We've still got data from the current packet to read. There could
             * be a record from the new epoch in it - so don't overwrite it
             * with the unprocessed records yet (we'll do it when we've
             * finished reading the current packet).
             */
            return 1;
        }


        /* Process all the records. */
        while (pqueue_peek(s->d1->unprocessed_rcds.q)) {
            dtls1_get_unprocessed_record(s);
            bitmap = dtls1_get_bitmap(s, rr, &is_next_epoch);
            if (bitmap == NULL) {
                /*
                 * Should not happen. This will only ever be NULL when the
                 * current record is from a different epoch. But that cannot
                 * be the case because we already checked the epoch above
                 */
                 SSLerr(SSL_F_DTLS1_PROCESS_BUFFERED_RECORDS,
                        ERR_R_INTERNAL_ERROR);
                 return 0;
            }
#ifndef OPENSSL_NO_SCTP
            /* Only do replay check if no SCTP bio */
            if (!BIO_dgram_is_sctp(SSL_get_rbio(s)))
#endif
            {
                /*
                 * Check whether this is a repeat, or aged record. We did this
                 * check once already when we first received the record - but
                 * we might have updated the window since then due to
                 * records we subsequently processed.
                 */
                replayok = dtls1_record_replay_check(s, bitmap);
            }

            if (!replayok || !dtls1_process_record(s, bitmap)) {
                /* dump this record */
                rr->length = 0;
                s->packet_length = 0;
                continue;
            }

            if (dtls1_buffer_record(s, &(s->d1->processed_rcds),
                                    s->s3->rrec.seq_num) < 0)
                return 0;
        }
    }

    /*
     * sync epoch numbers once all the unprocessed records have been
     * processed
     */
    s->d1->processed_rcds.epoch = s->d1->r_epoch;
    s->d1->unprocessed_rcds.epoch = s->d1->r_epoch + 1;

    return 1;
}

#if 0

static int dtls1_get_buffered_record(SSL *s)
{
    pitem *item;
    PQ_64BIT priority =
        (((PQ_64BIT) s->d1->handshake_read_seq) << 32) |
        ((PQ_64BIT) s->d1->r_msg_hdr.frag_off);

    /* if we're not (re)negotiating, nothing buffered */
    if (!SSL_in_init(s))
        return 0;

    item = pqueue_peek(s->d1->rcvd_records);
    if (item && item->priority == priority) {
        /*
         * Check if we've received the record of interest.  It must be a
         * handshake record, since data records as passed up without
         * buffering
         */
        DTLS1_RECORD_DATA *rdata;
        item = pqueue_pop(s->d1->rcvd_records);
        rdata = (DTLS1_RECORD_DATA *)item->data;

        if (s->s3->rbuf.buf != NULL)
            OPENSSL_free(s->s3->rbuf.buf);

        s->packet = rdata->packet;
        s->packet_length = rdata->packet_length;
        memcpy(&(s->s3->rbuf), &(rdata->rbuf), sizeof(SSL3_BUFFER));
        memcpy(&(s->s3->rrec), &(rdata->rrec), sizeof(SSL3_RECORD));

        OPENSSL_free(item->data);
        pitem_free(item);

        /* s->d1->next_expected_seq_num++; */
        return (1);
    }

    return 0;
}

#endif

static int dtls1_process_record(SSL *s, DTLS1_BITMAP *bitmap)
{
    int i, al;
    int enc_err;
    SSL_SESSION *sess;
    SSL3_RECORD *rr;
    unsigned int mac_size, orig_len;
    unsigned char md[EVP_MAX_MD_SIZE];

    rr = &(s->s3->rrec);
    sess = s->session;

    /*
     * At this point, s->packet_length == SSL3_RT_HEADER_LNGTH + rr->length,
     * and we have that many bytes in s->packet
     */
    rr->input = &(s->packet[DTLS1_RT_HEADER_LENGTH]);

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
    if (rr->length > SSL3_RT_MAX_ENCRYPTED_LENGTH) {
        al = SSL_AD_RECORD_OVERFLOW;
        SSLerr(SSL_F_DTLS1_PROCESS_RECORD, SSL_R_ENCRYPTED_LENGTH_TOO_LONG);
        goto f_err;
    }

    /* decrypt in place in 'rr->input' */
    rr->data = rr->input;

    enc_err = s->method->ssl3_enc->enc(s, 0);
    /*-
     * enc_err is:
     *    0: (in non-constant time) if the record is publically invalid.
     *    1: if the padding is valid
     *   -1: if the padding is invalid
     */
    if (enc_err == 0) {
        /* For DTLS we simply ignore bad packets. */
        rr->length = 0;
        s->packet_length = 0;
        goto err;
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
            SSLerr(SSL_F_DTLS1_PROCESS_RECORD, SSL_R_LENGTH_TOO_SHORT);
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
        if (rr->length > SSL3_RT_MAX_COMPRESSED_LENGTH + mac_size)
            enc_err = -1;
    }

    if (enc_err < 0) {
        /* decryption failed, silently discard message */
        rr->length = 0;
        s->packet_length = 0;
        goto err;
    }

    /* r->length is now just compressed */
    if (s->expand != NULL) {
        if (rr->length > SSL3_RT_MAX_COMPRESSED_LENGTH) {
            al = SSL_AD_RECORD_OVERFLOW;
            SSLerr(SSL_F_DTLS1_PROCESS_RECORD,
                   SSL_R_COMPRESSED_LENGTH_TOO_LONG);
            goto f_err;
        }
        if (!ssl3_do_uncompress(s)) {
            al = SSL_AD_DECOMPRESSION_FAILURE;
            SSLerr(SSL_F_DTLS1_PROCESS_RECORD, SSL_R_BAD_DECOMPRESSION);
            goto f_err;
        }
    }

    if (rr->length > SSL3_RT_MAX_PLAIN_LENGTH) {
        al = SSL_AD_RECORD_OVERFLOW;
        SSLerr(SSL_F_DTLS1_PROCESS_RECORD, SSL_R_DATA_LENGTH_TOO_LONG);
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

    /* Mark receipt of record. */
    dtls1_record_bitmap_update(s, bitmap);

    return (1);

 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
 err:
    return (0);
}

/*-
 * Call this to get a new input record.
 * It will return <= 0 if more data is needed, normally due to an error
 * or non-blocking IO.
 * When it finishes, one packet has been decoded and can be found in
 * ssl->s3->rrec.type    - is the type of record
 * ssl->s3->rrec.data,   - data
 * ssl->s3->rrec.length, - number of bytes
 */
/* used only by dtls1_read_bytes */
int dtls1_get_record(SSL *s)
{
    int ssl_major, ssl_minor;
    int i, n;
    SSL3_RECORD *rr;
    unsigned char *p = NULL;
    unsigned short version;
    DTLS1_BITMAP *bitmap;
    unsigned int is_next_epoch;

    rr = &(s->s3->rrec);

 again:
    /*
     * The epoch may have changed.  If so, process all the pending records.
     * This is a non-blocking operation.
     */
    if (!dtls1_process_buffered_records(s))
        return -1;

    /* if we're renegotiating, then there may be buffered records */
    if (dtls1_get_processed_record(s))
        return 1;

    /* get something from the wire */
    /* check if we have the header */
    if ((s->rstate != SSL_ST_READ_BODY) ||
        (s->packet_length < DTLS1_RT_HEADER_LENGTH)) {
        n = ssl3_read_n(s, DTLS1_RT_HEADER_LENGTH, s->s3->rbuf.len, 0);
        /* read timeout is handled by dtls1_read_bytes */
        if (n <= 0)
            return (n);         /* error or non-blocking */

        /* this packet contained a partial record, dump it */
        if (s->packet_length != DTLS1_RT_HEADER_LENGTH) {
            s->packet_length = 0;
            goto again;
        }

        s->rstate = SSL_ST_READ_BODY;

        p = s->packet;

        if (s->msg_callback)
            s->msg_callback(0, 0, SSL3_RT_HEADER, p, DTLS1_RT_HEADER_LENGTH,
                            s, s->msg_callback_arg);

        /* Pull apart the header into the DTLS1_RECORD */
        rr->type = *(p++);
        ssl_major = *(p++);
        ssl_minor = *(p++);
        version = (ssl_major << 8) | ssl_minor;

        /* sequence number is 64 bits, with top 2 bytes = epoch */
        n2s(p, rr->epoch);

        memcpy(&(s->s3->read_sequence[2]), p, 6);
        p += 6;

        n2s(p, rr->length);

        /*
         * Lets check the version. We tolerate alerts that don't have the exact
         * version number (e.g. because of protocol version errors)
         */
        if (!s->first_packet && rr->type != SSL3_RT_ALERT) {
            if (version != s->version) {
                /* unexpected version, silently discard */
                rr->length = 0;
                s->packet_length = 0;
                goto again;
            }
        }

        if ((version & 0xff00) != (s->version & 0xff00)) {
            /* wrong version, silently discard record */
            rr->length = 0;
            s->packet_length = 0;
            goto again;
        }

        if (rr->length > SSL3_RT_MAX_ENCRYPTED_LENGTH) {
            /* record too long, silently discard it */
            rr->length = 0;
            s->packet_length = 0;
            goto again;
        }

        /* now s->rstate == SSL_ST_READ_BODY */
    }

    /* s->rstate == SSL_ST_READ_BODY, get and decode the data */

    if (rr->length > s->packet_length - DTLS1_RT_HEADER_LENGTH) {
        /* now s->packet_length == DTLS1_RT_HEADER_LENGTH */
        i = rr->length;
        n = ssl3_read_n(s, i, i, 1);
        /* this packet contained a partial record, dump it */
        if (n != i) {
            rr->length = 0;
            s->packet_length = 0;
            goto again;
        }

        /*
         * now n == rr->length, and s->packet_length ==
         * DTLS1_RT_HEADER_LENGTH + rr->length
         */
    }
    s->rstate = SSL_ST_READ_HEADER; /* set state for later operations */

    /* match epochs.  NULL means the packet is dropped on the floor */
    bitmap = dtls1_get_bitmap(s, rr, &is_next_epoch);
    if (bitmap == NULL) {
        rr->length = 0;
        s->packet_length = 0;   /* dump this record */
        goto again;             /* get another record */
    }
#ifndef OPENSSL_NO_SCTP
    /* Only do replay check if no SCTP bio */
    if (!BIO_dgram_is_sctp(SSL_get_rbio(s))) {
#endif
        /*
         * Check whether this is a repeat, or aged record. Don't check if
         * we're listening and this message is a ClientHello. They can look
         * as if they're replayed, since they arrive from different
         * connections and would be dropped unnecessarily.
         */
        if (!(s->d1->listen && rr->type == SSL3_RT_HANDSHAKE &&
              s->packet_length > DTLS1_RT_HEADER_LENGTH &&
              s->packet[DTLS1_RT_HEADER_LENGTH] == SSL3_MT_CLIENT_HELLO) &&
            !dtls1_record_replay_check(s, bitmap)) {
            rr->length = 0;
            s->packet_length = 0; /* dump this record */
            goto again;         /* get another record */
        }
#ifndef OPENSSL_NO_SCTP
    }
#endif

    /* just read a 0 length packet */
    if (rr->length == 0)
        goto again;

    /*
     * If this record is from the next epoch (either HM or ALERT), and a
     * handshake is currently in progress, buffer it since it cannot be
     * processed at this time. However, do not buffer anything while
     * listening.
     */
    if (is_next_epoch) {
        if ((SSL_in_init(s) || s->in_handshake) && !s->d1->listen) {
            if (dtls1_buffer_record
                (s, &(s->d1->unprocessed_rcds), rr->seq_num) < 0)
                return -1;
        }
        rr->length = 0;
        s->packet_length = 0;
        goto again;
    }

    if (!dtls1_process_record(s, bitmap)) {
        rr->length = 0;
        s->packet_length = 0;   /* dump this record */
        goto again;             /* get another record */
    }

    return (1);

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
int dtls1_read_bytes(SSL *s, int type, unsigned char *buf, int len, int peek)
{
    int al, i, j, ret;
    unsigned int n;
    SSL3_RECORD *rr;
    void (*cb) (const SSL *ssl, int type2, int val) = NULL;

    if (s->s3->rbuf.buf == NULL) /* Not initialized yet */
        if (!ssl3_setup_buffers(s))
            return (-1);

    /* XXX: check what the second '&& type' is about */
    if ((type && (type != SSL3_RT_APPLICATION_DATA) &&
         (type != SSL3_RT_HANDSHAKE) && type) ||
        (peek && (type != SSL3_RT_APPLICATION_DATA))) {
        SSLerr(SSL_F_DTLS1_READ_BYTES, ERR_R_INTERNAL_ERROR);
        return -1;
    }

    /*
     * check whether there's a handshake message (client hello?) waiting
     */
    if ((ret = have_handshake_fragment(s, type, buf, len, peek)))
        return ret;

    /*
     * Now s->d1->handshake_fragment_len == 0 if type == SSL3_RT_HANDSHAKE.
     */

#ifndef OPENSSL_NO_SCTP
    /*
     * Continue handshake if it had to be interrupted to read app data with
     * SCTP.
     */
    if ((!s->in_handshake && SSL_in_init(s)) ||
        (BIO_dgram_is_sctp(SSL_get_rbio(s)) &&
         (s->state == DTLS1_SCTP_ST_SR_READ_SOCK
          || s->state == DTLS1_SCTP_ST_CR_READ_SOCK)
         && s->s3->in_read_app_data != 2))
#else
    if (!s->in_handshake && SSL_in_init(s))
#endif
    {
        /* type == SSL3_RT_APPLICATION_DATA */
        i = s->handshake_func(s);
        if (i < 0)
            return (i);
        if (i == 0) {
            SSLerr(SSL_F_DTLS1_READ_BYTES, SSL_R_SSL_HANDSHAKE_FAILURE);
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

    /*
     * We are not handshaking and have no data yet, so process data buffered
     * during the last handshake in advance, if any.
     */
    if (s->state == SSL_ST_OK && rr->length == 0) {
        pitem *item;
        item = pqueue_pop(s->d1->buffered_app_data.q);
        if (item) {
#ifndef OPENSSL_NO_SCTP
            /* Restore bio_dgram_sctp_rcvinfo struct */
            if (BIO_dgram_is_sctp(SSL_get_rbio(s))) {
                DTLS1_RECORD_DATA *rdata = (DTLS1_RECORD_DATA *)item->data;
                BIO_ctrl(SSL_get_rbio(s), BIO_CTRL_DGRAM_SCTP_SET_RCVINFO,
                         sizeof(rdata->recordinfo), &rdata->recordinfo);
            }
#endif

            dtls1_copy_record(s, item);

            OPENSSL_free(item->data);
            pitem_free(item);
        }
    }

    /* Check for timeout */
    if (dtls1_handle_timeout(s) > 0)
        goto start;

    /* get new packet if necessary */
    if ((rr->length == 0) || (s->rstate == SSL_ST_READ_BODY)) {
        ret = dtls1_get_record(s);
        if (ret <= 0) {
            ret = dtls1_read_failed(s, ret);
            /* anything other than a timeout is an error */
            if (ret <= 0)
                return (ret);
            else
                goto start;
        }
    }

    if (s->d1->listen && rr->type != SSL3_RT_HANDSHAKE) {
        rr->length = 0;
        goto start;
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
        /*
         * We now have application data between CCS and Finished. Most likely
         * the packets were reordered on their way, so buffer the application
         * data for later processing rather than dropping the connection.
         */
        if (dtls1_buffer_record(s, &(s->d1->buffered_app_data), rr->seq_num) <
            0) {
            SSLerr(SSL_F_DTLS1_READ_BYTES, ERR_R_INTERNAL_ERROR);
            return -1;
        }
        rr->length = 0;
        goto start;
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
            SSLerr(SSL_F_DTLS1_READ_BYTES, SSL_R_APP_DATA_IN_HANDSHAKE);
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
            }
        }
#ifndef OPENSSL_NO_SCTP
        /*
         * We were about to renegotiate but had to read belated application
         * data first, so retry.
         */
        if (BIO_dgram_is_sctp(SSL_get_rbio(s)) &&
            rr->type == SSL3_RT_APPLICATION_DATA &&
            (s->state == DTLS1_SCTP_ST_SR_READ_SOCK
             || s->state == DTLS1_SCTP_ST_CR_READ_SOCK)) {
            s->rwstate = SSL_READING;
            BIO_clear_retry_flags(SSL_get_rbio(s));
            BIO_set_retry_read(SSL_get_rbio(s));
        }

        /*
         * We might had to delay a close_notify alert because of reordered
         * app data. If there was an alert and there is no message to read
         * anymore, finally set shutdown.
         */
        if (BIO_dgram_is_sctp(SSL_get_rbio(s)) &&
            s->d1->shutdown_received
            && !BIO_dgram_sctp_msg_waiting(SSL_get_rbio(s))) {
            s->shutdown |= SSL_RECEIVED_SHUTDOWN;
            return (0);
        }
#endif
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
        unsigned int k, dest_maxlen = 0;
        unsigned char *dest = NULL;
        unsigned int *dest_len = NULL;

        if (rr->type == SSL3_RT_HANDSHAKE) {
            dest_maxlen = sizeof(s->d1->handshake_fragment);
            dest = s->d1->handshake_fragment;
            dest_len = &s->d1->handshake_fragment_len;
        } else if (rr->type == SSL3_RT_ALERT) {
            dest_maxlen = sizeof(s->d1->alert_fragment);
            dest = s->d1->alert_fragment;
            dest_len = &s->d1->alert_fragment_len;
        }
#ifndef OPENSSL_NO_HEARTBEATS
        else if (rr->type == TLS1_RT_HEARTBEAT) {
            dtls1_process_heartbeat(s);

            /* Exit and notify application to read again */
            rr->length = 0;
            s->rwstate = SSL_READING;
            BIO_clear_retry_flags(SSL_get_rbio(s));
            BIO_set_retry_read(SSL_get_rbio(s));
            return (-1);
        }
#endif
        /* else it's a CCS message, or application data or wrong */
        else if (rr->type != SSL3_RT_CHANGE_CIPHER_SPEC) {
            /*
             * Application data while renegotiating is allowed. Try again
             * reading.
             */
            if (rr->type == SSL3_RT_APPLICATION_DATA) {
                BIO *bio;
                s->s3->in_read_app_data = 2;
                bio = SSL_get_rbio(s);
                s->rwstate = SSL_READING;
                BIO_clear_retry_flags(bio);
                BIO_set_retry_read(bio);
                return (-1);
            }

            /* Not certain if this is the right error handling */
            al = SSL_AD_UNEXPECTED_MESSAGE;
            SSLerr(SSL_F_DTLS1_READ_BYTES, SSL_R_UNEXPECTED_RECORD);
            goto f_err;
        }

        if (dest_maxlen > 0) {
            /*
             * XDTLS: In a pathalogical case, the Client Hello may be
             * fragmented--don't always expect dest_maxlen bytes
             */
            if (rr->length < dest_maxlen) {
#ifdef DTLS1_AD_MISSING_HANDSHAKE_MESSAGE
                /*
                 * for normal alerts rr->length is 2, while
                 * dest_maxlen is 7 if we were to handle this
                 * non-existing alert...
                 */
                FIX ME
#endif
                 s->rstate = SSL_ST_READ_HEADER;
                rr->length = 0;
                goto start;
            }

            /* now move 'n' bytes: */
            for (k = 0; k < dest_maxlen; k++) {
                dest[k] = rr->data[rr->off++];
                rr->length--;
            }
            *dest_len = dest_maxlen;
        }
    }

    /*-
     * s->d1->handshake_fragment_len == 12  iff  rr->type == SSL3_RT_HANDSHAKE;
     * s->d1->alert_fragment_len == 7      iff  rr->type == SSL3_RT_ALERT.
     * (Possibly rr is 'empty' now, i.e. rr->length may be 0.)
     */

    /* If we are a client, check for an incoming 'Hello Request': */
    if ((!s->server) &&
        (s->d1->handshake_fragment_len >= DTLS1_HM_HEADER_LENGTH) &&
        (s->d1->handshake_fragment[0] == SSL3_MT_HELLO_REQUEST) &&
        (s->session != NULL) && (s->session->cipher != NULL)) {
        s->d1->handshake_fragment_len = 0;

        if ((s->d1->handshake_fragment[1] != 0) ||
            (s->d1->handshake_fragment[2] != 0) ||
            (s->d1->handshake_fragment[3] != 0)) {
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_DTLS1_READ_BYTES, SSL_R_BAD_HELLO_REQUEST);
            goto f_err;
        }

        /*
         * no need to check sequence number on HELLO REQUEST messages
         */

        if (s->msg_callback)
            s->msg_callback(0, s->version, SSL3_RT_HANDSHAKE,
                            s->d1->handshake_fragment, 4, s,
                            s->msg_callback_arg);

        if (SSL_is_init_finished(s) &&
            !(s->s3->flags & SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS) &&
            !s->s3->renegotiate) {
            s->d1->handshake_read_seq++;
            s->new_session = 1;
            ssl3_renegotiate(s);
            if (ssl3_renegotiate_check(s)) {
                i = s->handshake_func(s);
                if (i < 0)
                    return (i);
                if (i == 0) {
                    SSLerr(SSL_F_DTLS1_READ_BYTES,
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
            && s->d1->handshake_fragment_len >= DTLS1_HM_HEADER_LENGTH
            && s->d1->handshake_fragment[0] == SSL3_MT_CLIENT_HELLO
            && s->s3->previous_client_finished_len != 0
            && (s->options & SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION) == 0) {
        s->d1->handshake_fragment_len = 0;
        rr->length = 0;
        ssl3_send_alert(s, SSL3_AL_WARNING, SSL_AD_NO_RENEGOTIATION);
        goto start;
    }


    if (s->d1->alert_fragment_len >= DTLS1_AL_HEADER_LENGTH) {
        int alert_level = s->d1->alert_fragment[0];
        int alert_descr = s->d1->alert_fragment[1];

        s->d1->alert_fragment_len = 0;

        if (s->msg_callback)
            s->msg_callback(0, s->version, SSL3_RT_ALERT,
                            s->d1->alert_fragment, 2, s, s->msg_callback_arg);

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
                SSLerr(SSL_F_DTLS1_READ_BYTES, SSL_R_TOO_MANY_WARN_ALERTS);
                goto f_err;
            }

            if (alert_descr == SSL_AD_CLOSE_NOTIFY) {
#ifndef OPENSSL_NO_SCTP
                /*
                 * With SCTP and streams the socket may deliver app data
                 * after a close_notify alert. We have to check this first so
                 * that nothing gets discarded.
                 */
                if (BIO_dgram_is_sctp(SSL_get_rbio(s)) &&
                    BIO_dgram_sctp_msg_waiting(SSL_get_rbio(s))) {
                    s->d1->shutdown_received = 1;
                    s->rwstate = SSL_READING;
                    BIO_clear_retry_flags(SSL_get_rbio(s));
                    BIO_set_retry_read(SSL_get_rbio(s));
                    return -1;
                }
#endif
                s->shutdown |= SSL_RECEIVED_SHUTDOWN;
                return (0);
            }
#if 0
            /* XXX: this is a possible improvement in the future */
            /* now check if it's a missing record */
            if (alert_descr == DTLS1_AD_MISSING_HANDSHAKE_MESSAGE) {
                unsigned short seq;
                unsigned int frag_off;
                unsigned char *p = &(s->d1->alert_fragment[2]);

                n2s(p, seq);
                n2l3(p, frag_off);

                dtls1_retransmit_message(s,
                                         dtls1_get_queue_priority
                                         (frag->msg_header.seq, 0), frag_off,
                                         &found);
                if (!found && SSL_in_init(s)) {
                    /*
                     * fprintf( stderr,"in init = %d\n", SSL_in_init(s));
                     */
                    /*
                     * requested a message not yet sent, send an alert
                     * ourselves
                     */
                    ssl3_send_alert(s, SSL3_AL_WARNING,
                                    DTLS1_AD_MISSING_HANDSHAKE_MESSAGE);
                }
            }
#endif
        } else if (alert_level == SSL3_AL_FATAL) {
            char tmp[16];

            s->rwstate = SSL_NOTHING;
            s->s3->fatal_alert = alert_descr;
            SSLerr(SSL_F_DTLS1_READ_BYTES,
                   SSL_AD_REASON_OFFSET + alert_descr);
            BIO_snprintf(tmp, sizeof(tmp), "%d", alert_descr);
            ERR_add_error_data(2, "SSL alert number ", tmp);
            s->shutdown |= SSL_RECEIVED_SHUTDOWN;
            SSL_CTX_remove_session(s->session_ctx, s->session);
            return (0);
        } else {
            al = SSL_AD_ILLEGAL_PARAMETER;
            SSLerr(SSL_F_DTLS1_READ_BYTES, SSL_R_UNKNOWN_ALERT_TYPE);
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
        struct ccs_header_st ccs_hdr;
        unsigned int ccs_hdr_len = DTLS1_CCS_HEADER_LENGTH;

        dtls1_get_ccs_header(rr->data, &ccs_hdr);

        if (s->version == DTLS1_BAD_VER)
            ccs_hdr_len = 3;

        /*
         * 'Change Cipher Spec' is just a single byte, so we know exactly
         * what the record payload has to look like
         */
        /* XDTLS: check that epoch is consistent */
        if ((rr->length != ccs_hdr_len) ||
            (rr->off != 0) || (rr->data[0] != SSL3_MT_CCS)) {
            al = SSL_AD_ILLEGAL_PARAMETER;
            SSLerr(SSL_F_DTLS1_READ_BYTES, SSL_R_BAD_CHANGE_CIPHER_SPEC);
            goto f_err;
        }

        rr->length = 0;

        if (s->msg_callback)
            s->msg_callback(0, s->version, SSL3_RT_CHANGE_CIPHER_SPEC,
                            rr->data, 1, s, s->msg_callback_arg);

        /*
         * We can't process a CCS now, because previous handshake messages
         * are still missing, so just drop it.
         */
        if (!s->d1->change_cipher_spec_ok) {
            goto start;
        }

        s->d1->change_cipher_spec_ok = 0;

        s->s3->change_cipher_spec = 1;
        if (!ssl3_do_change_cipher_spec(s))
            goto err;

        /* do this whenever CCS is processed */
        dtls1_reset_seq_numbers(s, SSL3_CC_READ);

        if (s->version == DTLS1_BAD_VER)
            s->d1->handshake_read_seq++;

#ifndef OPENSSL_NO_SCTP
        /*
         * Remember that a CCS has been received, so that an old key of
         * SCTP-Auth can be deleted when a CCS is sent. Will be ignored if no
         * SCTP is used
         */
        BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_AUTH_CCS_RCVD, 1, NULL);
#endif

        goto start;
    }

    /*
     * Unexpected handshake message (Client Hello, or protocol violation)
     */
    if ((s->d1->handshake_fragment_len >= DTLS1_HM_HEADER_LENGTH) &&
        !s->in_handshake) {
        struct hm_header_st msg_hdr;

        /* this may just be a stale retransmit */
        dtls1_get_message_header(rr->data, &msg_hdr);
        if (rr->epoch != s->d1->r_epoch) {
            rr->length = 0;
            goto start;
        }

        /*
         * If we are server, we may have a repeated FINISHED of the client
         * here, then retransmit our CCS and FINISHED.
         */
        if (msg_hdr.type == SSL3_MT_FINISHED) {
            if (dtls1_check_timeout_num(s) < 0)
                return -1;

            dtls1_retransmit_buffered_messages(s);
            rr->length = 0;
            goto start;
        }

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
            SSLerr(SSL_F_DTLS1_READ_BYTES, SSL_R_SSL_HANDSHAKE_FAILURE);
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
#ifndef OPENSSL_NO_TLS
        /* TLS just ignores unknown message types */
        if (s->version == TLS1_VERSION) {
            rr->length = 0;
            goto start;
        }
#endif
        al = SSL_AD_UNEXPECTED_MESSAGE;
        SSLerr(SSL_F_DTLS1_READ_BYTES, SSL_R_UNEXPECTED_RECORD);
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
        SSLerr(SSL_F_DTLS1_READ_BYTES, ERR_R_INTERNAL_ERROR);
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
            SSLerr(SSL_F_DTLS1_READ_BYTES, SSL_R_UNEXPECTED_RECORD);
            goto f_err;
        }
    }
    /* not reached */

 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
 err:
    return (-1);
}

int dtls1_write_app_data_bytes(SSL *s, int type, const void *buf_, int len)
{
    int i;

#ifndef OPENSSL_NO_SCTP
    /*
     * Check if we have to continue an interrupted handshake for reading
     * belated app data with SCTP.
     */
    if ((SSL_in_init(s) && !s->in_handshake) ||
        (BIO_dgram_is_sctp(SSL_get_wbio(s)) &&
         (s->state == DTLS1_SCTP_ST_SR_READ_SOCK
          || s->state == DTLS1_SCTP_ST_CR_READ_SOCK)))
#else
    if (SSL_in_init(s) && !s->in_handshake)
#endif
    {
        i = s->handshake_func(s);
        if (i < 0)
            return (i);
        if (i == 0) {
            SSLerr(SSL_F_DTLS1_WRITE_APP_DATA_BYTES,
                   SSL_R_SSL_HANDSHAKE_FAILURE);
            return -1;
        }
    }

    if (len > SSL3_RT_MAX_PLAIN_LENGTH) {
        SSLerr(SSL_F_DTLS1_WRITE_APP_DATA_BYTES, SSL_R_DTLS_MESSAGE_TOO_BIG);
        return -1;
    }

    i = dtls1_write_bytes(s, type, buf_, len);
    return i;
}

        /*
         * this only happens when a client hello is received and a handshake
         * is started.
         */
static int
have_handshake_fragment(SSL *s, int type, unsigned char *buf,
                        int len, int peek)
{

    if ((type == SSL3_RT_HANDSHAKE) && (s->d1->handshake_fragment_len > 0))
        /* (partially) satisfy request from storage */
    {
        unsigned char *src = s->d1->handshake_fragment;
        unsigned char *dst = buf;
        unsigned int k, n;

        /* peek == 0 */
        n = 0;
        while ((len > 0) && (s->d1->handshake_fragment_len > 0)) {
            *dst++ = *src++;
            len--;
            s->d1->handshake_fragment_len--;
            n++;
        }
        /* move any remaining fragment bytes: */
        for (k = 0; k < s->d1->handshake_fragment_len; k++)
            s->d1->handshake_fragment[k] = *src++;
        return n;
    }

    return 0;
}

/*
 * Call this to write data in records of type 'type' It will return <= 0 if
 * not all data has been sent or non-blocking IO.
 */
int dtls1_write_bytes(SSL *s, int type, const void *buf, int len)
{
    int i;

    OPENSSL_assert(len <= SSL3_RT_MAX_PLAIN_LENGTH);
    s->rwstate = SSL_NOTHING;
    i = do_dtls1_write(s, type, buf, len, 0);
    return i;
}

int do_dtls1_write(SSL *s, int type, const unsigned char *buf,
                   unsigned int len, int create_empty_fragment)
{
    unsigned char *p, *pseq;
    int i, mac_size, clear = 0;
    int prefix_len = 0;
    int eivlen;
    SSL3_RECORD *wr;
    SSL3_BUFFER *wb;
    SSL_SESSION *sess;

    /*
     * first check if there is a SSL3_BUFFER still being written out.  This
     * will happen with non blocking IO
     */
    if (s->s3->wbuf.left != 0) {
        OPENSSL_assert(0);      /* XDTLS: want to see if we ever get here */
        return (ssl3_write_pending(s, type, buf, len));
    }

    /* If we have an alert to send, lets send it */
    if (s->s3->alert_dispatch) {
        i = s->method->ssl_dispatch_alert(s);
        if (i <= 0)
            return (i);
        /* if it went, fall through and send more stuff */
    }

    if (len == 0 && !create_empty_fragment)
        return 0;

    wr = &(s->s3->wrec);
    wb = &(s->s3->wbuf);
    sess = s->session;

    if ((sess == NULL) ||
        (s->enc_write_ctx == NULL) || (EVP_MD_CTX_md(s->write_hash) == NULL))
        clear = 1;

    if (clear)
        mac_size = 0;
    else {
        mac_size = EVP_MD_CTX_size(s->write_hash);
        if (mac_size < 0)
            goto err;
    }

    /* DTLS implements explicit IV, so no need for empty fragments */
#if 0
    /*
     * 'create_empty_fragment' is true only when this function calls itself
     */
    if (!clear && !create_empty_fragment && !s->s3->empty_fragment_done
        && SSL_version(s) != DTLS1_VERSION && SSL_version(s) != DTLS1_BAD_VER)
    {
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
            prefix_len = s->method->do_ssl_write(s, type, buf, 0, 1);
            if (prefix_len <= 0)
                goto err;

            if (s->s3->wbuf.len <
                (size_t)prefix_len + SSL3_RT_MAX_PACKET_SIZE) {
                /* insufficient space */
                SSLerr(SSL_F_DO_DTLS1_WRITE, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }

        s->s3->empty_fragment_done = 1;
    }
#endif
    p = wb->buf + prefix_len;

    /* write the header */

    *(p++) = type & 0xff;
    wr->type = type;
    /*
     * Special case: for hello verify request, client version 1.0 and we
     * haven't decided which version to use yet send back using version 1.0
     * header: otherwise some clients will ignore it.
     */
    if (s->method->version == DTLS_ANY_VERSION) {
        *(p++) = DTLS1_VERSION >> 8;
        *(p++) = DTLS1_VERSION & 0xff;
    } else {
        *(p++) = s->version >> 8;
        *(p++) = s->version & 0xff;
    }

    /* field where we are to write out packet epoch, seq num and len */
    pseq = p;
    p += 10;

    /* Explicit IV length, block ciphers appropriate version flag */
    if (s->enc_write_ctx) {
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
    wr->data = p + eivlen;      /* make room for IV in case of CBC */
    wr->length = (int)len;
    wr->input = (unsigned char *)buf;

    /*
     * we now 'read' from wr->input, wr->length bytes into wr->data
     */

    /* first we compress */
    if (s->compress != NULL) {
        if (!ssl3_do_compress(s)) {
            SSLerr(SSL_F_DO_DTLS1_WRITE, SSL_R_COMPRESSION_FAILURE);
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

    /* this is true regardless of mac size */
    wr->input = p;
    wr->data = p;

    if (eivlen)
        wr->length += eivlen;

    if (s->method->ssl3_enc->enc(s, 1) < 1)
        goto err;

    /* record length after mac and block padding */
    /*
     * if (type == SSL3_RT_APPLICATION_DATA || (type == SSL3_RT_ALERT && !
     * SSL_in_init(s)))
     */

    /* there's only one epoch between handshake and app data */

    s2n(s->d1->w_epoch, pseq);

    /* XDTLS: ?? */
    /*
     * else s2n(s->d1->handshake_epoch, pseq);
     */

    memcpy(pseq, &(s->s3->write_sequence[2]), 6);
    pseq += 6;
    s2n(wr->length, pseq);

    if (s->msg_callback)
        s->msg_callback(1, 0, SSL3_RT_HEADER, pseq - DTLS1_RT_HEADER_LENGTH,
                        DTLS1_RT_HEADER_LENGTH, s, s->msg_callback_arg);

    /*
     * we should now have wr->data pointing to the encrypted data, which is
     * wr->length long
     */
    wr->type = type;            /* not needed but helps for debugging */
    wr->length += DTLS1_RT_HEADER_LENGTH;

#if 0                           /* this is now done at the message layer */
    /* buffer the record, making it easy to handle retransmits */
    if (type == SSL3_RT_HANDSHAKE || type == SSL3_RT_CHANGE_CIPHER_SPEC)
        dtls1_buffer_record(s, wr->data, wr->length,
                            *((PQ_64BIT *) & (s->s3->write_sequence[0])));
#endif

    ssl3_record_sequence_update(&(s->s3->write_sequence[0]));

    if (create_empty_fragment) {
        /*
         * we are in a recursive call; just return the length, don't write
         * out anything here
         */
        return wr->length;
    }

    /* now let's set up wb */
    wb->left = prefix_len + wr->length;
    wb->offset = 0;

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

static int dtls1_record_replay_check(SSL *s, DTLS1_BITMAP *bitmap)
{
    int cmp;
    unsigned int shift;
    const unsigned char *seq = s->s3->read_sequence;

    cmp = satsub64be(seq, bitmap->max_seq_num);
    if (cmp > 0) {
        memcpy(s->s3->rrec.seq_num, seq, 8);
        return 1;               /* this record in new */
    }
    shift = -cmp;
    if (shift >= sizeof(bitmap->map) * 8)
        return 0;               /* stale, outside the window */
    else if (bitmap->map & (1UL << shift))
        return 0;               /* record previously received */

    memcpy(s->s3->rrec.seq_num, seq, 8);
    return 1;
}

static void dtls1_record_bitmap_update(SSL *s, DTLS1_BITMAP *bitmap)
{
    int cmp;
    unsigned int shift;
    const unsigned char *seq = s->s3->read_sequence;

    cmp = satsub64be(seq, bitmap->max_seq_num);
    if (cmp > 0) {
        shift = cmp;
        if (shift < sizeof(bitmap->map) * 8)
            bitmap->map <<= shift, bitmap->map |= 1UL;
        else
            bitmap->map = 1UL;
        memcpy(bitmap->max_seq_num, seq, 8);
    } else {
        shift = -cmp;
        if (shift < sizeof(bitmap->map) * 8)
            bitmap->map |= 1UL << shift;
    }
}

int dtls1_dispatch_alert(SSL *s)
{
    int i, j;
    void (*cb) (const SSL *ssl, int type, int val) = NULL;
    unsigned char buf[DTLS1_AL_HEADER_LENGTH];
    unsigned char *ptr = &buf[0];

    s->s3->alert_dispatch = 0;

    memset(buf, 0x00, sizeof(buf));
    *ptr++ = s->s3->send_alert[0];
    *ptr++ = s->s3->send_alert[1];

#ifdef DTLS1_AD_MISSING_HANDSHAKE_MESSAGE
    if (s->s3->send_alert[1] == DTLS1_AD_MISSING_HANDSHAKE_MESSAGE) {
        s2n(s->d1->handshake_read_seq, ptr);
# if 0
        if (s->d1->r_msg_hdr.frag_off == 0)
            /*
             * waiting for a new msg
             */
            else
            s2n(s->d1->r_msg_hdr.seq, ptr); /* partial msg read */
# endif

# if 0
        fprintf(stderr,
                "s->d1->handshake_read_seq = %d, s->d1->r_msg_hdr.seq = %d\n",
                s->d1->handshake_read_seq, s->d1->r_msg_hdr.seq);
# endif
        l2n3(s->d1->r_msg_hdr.frag_off, ptr);
    }
#endif

    i = do_dtls1_write(s, SSL3_RT_ALERT, &buf[0], sizeof(buf), 0);
    if (i <= 0) {
        s->s3->alert_dispatch = 1;
        /* fprintf( stderr, "not done with alert\n" ); */
    } else {
        if (s->s3->send_alert[0] == SSL3_AL_FATAL
#ifdef DTLS1_AD_MISSING_HANDSHAKE_MESSAGE
            || s->s3->send_alert[1] == DTLS1_AD_MISSING_HANDSHAKE_MESSAGE
#endif
            )
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

static DTLS1_BITMAP *dtls1_get_bitmap(SSL *s, SSL3_RECORD *rr,
                                      unsigned int *is_next_epoch)
{

    *is_next_epoch = 0;

    /* In current epoch, accept HM, CCS, DATA, & ALERT */
    if (rr->epoch == s->d1->r_epoch)
        return &s->d1->bitmap;

    /*
     * Only HM and ALERT messages can be from the next epoch and only if we
     * have already processed all of the unprocessed records from the last
     * epoch
     */
    else if (rr->epoch == (unsigned long)(s->d1->r_epoch + 1) &&
             s->d1->unprocessed_rcds.epoch != s->d1->r_epoch &&
             (rr->type == SSL3_RT_HANDSHAKE || rr->type == SSL3_RT_ALERT)) {
        *is_next_epoch = 1;
        return &s->d1->next_bitmap;
    }

    return NULL;
}

#if 0
static int
dtls1_record_needs_buffering(SSL *s, SSL3_RECORD *rr,
                             unsigned short *priority, unsigned long *offset)
{

    /* alerts are passed up immediately */
    if (rr->type == SSL3_RT_APPLICATION_DATA || rr->type == SSL3_RT_ALERT)
        return 0;

    /*
     * Only need to buffer if a handshake is underway. (this implies that
     * Hello Request and Client Hello are passed up immediately)
     */
    if (SSL_in_init(s)) {
        unsigned char *data = rr->data;
        /* need to extract the HM/CCS sequence number here */
        if (rr->type == SSL3_RT_HANDSHAKE ||
            rr->type == SSL3_RT_CHANGE_CIPHER_SPEC) {
            unsigned short seq_num;
            struct hm_header_st msg_hdr;
            struct ccs_header_st ccs_hdr;

            if (rr->type == SSL3_RT_HANDSHAKE) {
                dtls1_get_message_header(data, &msg_hdr);
                seq_num = msg_hdr.seq;
                *offset = msg_hdr.frag_off;
            } else {
                dtls1_get_ccs_header(data, &ccs_hdr);
                seq_num = ccs_hdr.seq;
                *offset = 0;
            }

            /*
             * this is either a record we're waiting for, or a retransmit of
             * something we happened to previously receive (higher layers
             * will drop the repeat silently
             */
            if (seq_num < s->d1->handshake_read_seq)
                return 0;
            if (rr->type == SSL3_RT_HANDSHAKE &&
                seq_num == s->d1->handshake_read_seq &&
                msg_hdr.frag_off < s->d1->r_msg_hdr.frag_off)
                return 0;
            else if (seq_num == s->d1->handshake_read_seq &&
                     (rr->type == SSL3_RT_CHANGE_CIPHER_SPEC ||
                      msg_hdr.frag_off == s->d1->r_msg_hdr.frag_off))
                return 0;
            else {
                *priority = seq_num;
                return 1;
            }
        } else                  /* unknown record type */
            return 0;
    }

    return 0;
}
#endif

void dtls1_reset_seq_numbers(SSL *s, int rw)
{
    unsigned char *seq;
    unsigned int seq_bytes = sizeof(s->s3->read_sequence);

    if (rw & SSL3_CC_READ) {
        seq = s->s3->read_sequence;
        s->d1->r_epoch++;
        memcpy(&(s->d1->bitmap), &(s->d1->next_bitmap), sizeof(DTLS1_BITMAP));
        memset(&(s->d1->next_bitmap), 0x00, sizeof(DTLS1_BITMAP));

        /*
         * We must not use any buffered messages received from the previous
         * epoch
         */
        dtls1_clear_received_buffer(s);
    } else {
        seq = s->s3->write_sequence;
        memcpy(s->d1->last_write_sequence, seq,
               sizeof(s->s3->write_sequence));
        s->d1->w_epoch++;
    }

    memset(seq, 0x00, seq_bytes);
}
/* ssl/t1_lib.c */
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
 * Copyright (c) 1998-2006 The OpenSSL Project.  All rights reserved.
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
 * DTLS code by Eric Rescorla <ekr@rtfm.com>
 *
 * Copyright (C) 2006, Network Resonance, Inc. Copyright (C) 2011, RTFM, Inc.
 */

#include <stdio.h>
// #include "objects.h"
// #include "ssl_locl.h"
#include "srtp.h"

#ifndef OPENSSL_NO_SRTP

static SRTP_PROTECTION_PROFILE srtp_known_profiles[] = {
    {
     "SRTP_AES128_CM_SHA1_80",
     SRTP_AES128_CM_SHA1_80,
     },
    {
     "SRTP_AES128_CM_SHA1_32",
     SRTP_AES128_CM_SHA1_32,
     },
# if 0
    {
     "SRTP_NULL_SHA1_80",
     SRTP_NULL_SHA1_80,
     },
    {
     "SRTP_NULL_SHA1_32",
     SRTP_NULL_SHA1_32,
     },
# endif
    {0}
};

static int find_profile_by_name(char *profile_name,
                                SRTP_PROTECTION_PROFILE **pptr, unsigned len)
{
    SRTP_PROTECTION_PROFILE *p;

    p = srtp_known_profiles;
    while (p->name) {
        if ((len == strlen(p->name)) && !strncmp(p->name, profile_name, len)) {
            *pptr = p;
            return 0;
        }

        p++;
    }

    return 1;
}

static int ssl_ctx_make_profiles(const char *profiles_string,
                                 STACK_OF(SRTP_PROTECTION_PROFILE) **out)
{
    STACK_OF(SRTP_PROTECTION_PROFILE) *profiles;

    char *col;
    char *ptr = (char *)profiles_string;

    SRTP_PROTECTION_PROFILE *p;

    if (!(profiles = sk_SRTP_PROTECTION_PROFILE_new_null())) {
        SSLerr(SSL_F_SSL_CTX_MAKE_PROFILES,
               SSL_R_SRTP_COULD_NOT_ALLOCATE_PROFILES);
        return 1;
    }

    do {
        col = strchr(ptr, ':');

        if (!find_profile_by_name(ptr, &p,
                                  col ? col - ptr : (int)strlen(ptr))) {
            if (sk_SRTP_PROTECTION_PROFILE_find(profiles, p) >= 0) {
                SSLerr(SSL_F_SSL_CTX_MAKE_PROFILES,
                       SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST);
                sk_SRTP_PROTECTION_PROFILE_free(profiles);
                return 1;
            }

            sk_SRTP_PROTECTION_PROFILE_push(profiles, p);
        } else {
            SSLerr(SSL_F_SSL_CTX_MAKE_PROFILES,
                   SSL_R_SRTP_UNKNOWN_PROTECTION_PROFILE);
            sk_SRTP_PROTECTION_PROFILE_free(profiles);
            return 1;
        }

        if (col)
            ptr = col + 1;
    } while (col);

    *out = profiles;

    return 0;
}

int SSL_CTX_set_tlsext_use_srtp(SSL_CTX *ctx, const char *profiles)
{
    return ssl_ctx_make_profiles(profiles, &ctx->srtp_profiles);
}

int SSL_set_tlsext_use_srtp(SSL *s, const char *profiles)
{
    return ssl_ctx_make_profiles(profiles, &s->srtp_profiles);
}

STACK_OF(SRTP_PROTECTION_PROFILE) *SSL_get_srtp_profiles(SSL *s)
{
    if (s != NULL) {
        if (s->srtp_profiles != NULL) {
            return s->srtp_profiles;
        } else if ((s->ctx != NULL) && (s->ctx->srtp_profiles != NULL)) {
            return s->ctx->srtp_profiles;
        }
    }

    return NULL;
}

SRTP_PROTECTION_PROFILE *SSL_get_selected_srtp_profile(SSL *s)
{
    return s->srtp_profile;
}

/*
 * Note: this function returns 0 length if there are no profiles specified
 */
int ssl_add_clienthello_use_srtp_ext(SSL *s, unsigned char *p, int *len,
                                     int maxlen)
{
    int ct = 0;
    int i;
    STACK_OF(SRTP_PROTECTION_PROFILE) *clnt = 0;
    SRTP_PROTECTION_PROFILE *prof;

    clnt = SSL_get_srtp_profiles(s);
    ct = sk_SRTP_PROTECTION_PROFILE_num(clnt); /* -1 if clnt == 0 */

    if (p) {
        if (ct == 0) {
            SSLerr(SSL_F_SSL_ADD_CLIENTHELLO_USE_SRTP_EXT,
                   SSL_R_EMPTY_SRTP_PROTECTION_PROFILE_LIST);
            return 1;
        }

        if ((2 + ct * 2 + 1) > maxlen) {
            SSLerr(SSL_F_SSL_ADD_CLIENTHELLO_USE_SRTP_EXT,
                   SSL_R_SRTP_PROTECTION_PROFILE_LIST_TOO_LONG);
            return 1;
        }

        /* Add the length */
        s2n(ct * 2, p);
        for (i = 0; i < ct; i++) {
            prof = sk_SRTP_PROTECTION_PROFILE_value(clnt, i);
            s2n(prof->id, p);
        }

        /* Add an empty use_mki value */
        *p++ = 0;
    }

    *len = 2 + ct * 2 + 1;

    return 0;
}

int ssl_parse_clienthello_use_srtp_ext(SSL *s, unsigned char *d, int len,
                                       int *al)
{
    SRTP_PROTECTION_PROFILE *sprof;
    STACK_OF(SRTP_PROTECTION_PROFILE) *srvr;
    int ct;
    int mki_len;
    int i, srtp_pref;
    unsigned int id;

    /* Length value + the MKI length */
    if (len < 3) {
        SSLerr(SSL_F_SSL_PARSE_CLIENTHELLO_USE_SRTP_EXT,
               SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST);
        *al = SSL_AD_DECODE_ERROR;
        return 1;
    }

    /* Pull off the length of the cipher suite list */
    n2s(d, ct);
    len -= 2;

    /* Check that it is even */
    if (ct % 2) {
        SSLerr(SSL_F_SSL_PARSE_CLIENTHELLO_USE_SRTP_EXT,
               SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST);
        *al = SSL_AD_DECODE_ERROR;
        return 1;
    }

    /* Check that lengths are consistent */
    if (len < (ct + 1)) {
        SSLerr(SSL_F_SSL_PARSE_CLIENTHELLO_USE_SRTP_EXT,
               SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST);
        *al = SSL_AD_DECODE_ERROR;
        return 1;
    }

    srvr = SSL_get_srtp_profiles(s);
    s->srtp_profile = NULL;
    /* Search all profiles for a match initially */
    srtp_pref = sk_SRTP_PROTECTION_PROFILE_num(srvr);

    while (ct) {
        n2s(d, id);
        ct -= 2;
        len -= 2;

        /*
         * Only look for match in profiles of higher preference than
         * current match.
         * If no profiles have been have been configured then this
         * does nothing.
         */
        for (i = 0; i < srtp_pref; i++) {
            sprof = sk_SRTP_PROTECTION_PROFILE_value(srvr, i);
            if (sprof->id == id) {
                s->srtp_profile = sprof;
                srtp_pref = i;
                break;
            }
        }
    }

    /*
     * Now extract the MKI value as a sanity check, but discard it for now
     */
    mki_len = *d;
    d++;
    len--;

    if (mki_len != len) {
        SSLerr(SSL_F_SSL_PARSE_CLIENTHELLO_USE_SRTP_EXT,
               SSL_R_BAD_SRTP_MKI_VALUE);
        *al = SSL_AD_DECODE_ERROR;
        return 1;
    }

    return 0;
}

int ssl_add_serverhello_use_srtp_ext(SSL *s, unsigned char *p, int *len,
                                     int maxlen)
{
    if (p) {
        if (maxlen < 5) {
            SSLerr(SSL_F_SSL_ADD_SERVERHELLO_USE_SRTP_EXT,
                   SSL_R_SRTP_PROTECTION_PROFILE_LIST_TOO_LONG);
            return 1;
        }

        if (s->srtp_profile == 0) {
            SSLerr(SSL_F_SSL_ADD_SERVERHELLO_USE_SRTP_EXT,
                   SSL_R_USE_SRTP_NOT_NEGOTIATED);
            return 1;
        }
        s2n(2, p);
        s2n(s->srtp_profile->id, p);
        *p++ = 0;
    }
    *len = 5;

    return 0;
}

int ssl_parse_serverhello_use_srtp_ext(SSL *s, unsigned char *d, int len,
                                       int *al)
{
    unsigned id;
    int i;
    int ct;

    STACK_OF(SRTP_PROTECTION_PROFILE) *clnt;
    SRTP_PROTECTION_PROFILE *prof;

    if (len != 5) {
        SSLerr(SSL_F_SSL_PARSE_SERVERHELLO_USE_SRTP_EXT,
               SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST);
        *al = SSL_AD_DECODE_ERROR;
        return 1;
    }

    n2s(d, ct);
    if (ct != 2) {
        SSLerr(SSL_F_SSL_PARSE_SERVERHELLO_USE_SRTP_EXT,
               SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST);
        *al = SSL_AD_DECODE_ERROR;
        return 1;
    }

    n2s(d, id);
    if (*d) {                   /* Must be no MKI, since we never offer one */
        SSLerr(SSL_F_SSL_PARSE_SERVERHELLO_USE_SRTP_EXT,
               SSL_R_BAD_SRTP_MKI_VALUE);
        *al = SSL_AD_ILLEGAL_PARAMETER;
        return 1;
    }

    clnt = SSL_get_srtp_profiles(s);

    /* Throw an error if the server gave us an unsolicited extension */
    if (clnt == NULL) {
        SSLerr(SSL_F_SSL_PARSE_SERVERHELLO_USE_SRTP_EXT,
               SSL_R_NO_SRTP_PROFILES);
        *al = SSL_AD_DECODE_ERROR;
        return 1;
    }

    /*
     * Check to see if the server gave us something we support (and
     * presumably offered)
     */
    for (i = 0; i < sk_SRTP_PROTECTION_PROFILE_num(clnt); i++) {
        prof = sk_SRTP_PROTECTION_PROFILE_value(clnt, i);

        if (prof->id == id) {
            s->srtp_profile = prof;
            *al = 0;
            return 0;
        }
    }

    SSLerr(SSL_F_SSL_PARSE_SERVERHELLO_USE_SRTP_EXT,
           SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST);
    *al = SSL_AD_DECODE_ERROR;
    return 1;
}

#endif
/* ssl/d1_srvr.c */
/*
 * DTLS implementation written by Nagendra Modadugu
 * (nagendra@cs.stanford.edu) for the OpenSSL project 2005.
 */
/* ====================================================================
 * Copyright (c) 1999-2007 The OpenSSL Project.  All rights reserved.
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
// #include "ssl_locl.h"
// #include "buffer.h"
// #include "rand.h"
// #include "objects.h"
// #include "evp.h"
// #include "x509.h"
// #include "md5.h"
// #include "bn.h"
#ifndef OPENSSL_NO_DH
# include "dh.h"
#endif

static const SSL_METHOD *dtls1_get_server_method(int ver);
static int dtls1_send_hello_verify_request(SSL *s);

static const SSL_METHOD *dtls1_get_server_method(int ver)
{
    if (ver == DTLS_ANY_VERSION)
        return DTLS_server_method();
    else if (ver == DTLS1_VERSION)
        return DTLSv1_server_method();
    else if (ver == DTLS1_2_VERSION)
        return DTLSv1_2_server_method();
    else
        return NULL;
}

IMPLEMENT_dtls1_meth_func(DTLS1_VERSION,
                          DTLSv1_server_method,
                          dtls1_accept,
                          ssl_undefined_function,
                          dtls1_get_server_method, DTLSv1_enc_data)

IMPLEMENT_dtls1_meth_func(DTLS1_2_VERSION,
                          DTLSv1_2_server_method,
                          dtls1_accept,
                          ssl_undefined_function,
                          dtls1_get_server_method, DTLSv1_2_enc_data)

IMPLEMENT_dtls1_meth_func(DTLS_ANY_VERSION,
                          DTLS_server_method,
                          dtls1_accept,
                          ssl_undefined_function,
                          dtls1_get_server_method, DTLSv1_2_enc_data)

int dtls1_accept(SSL *s)
{
    BUF_MEM *buf;
    unsigned long Time = (unsigned long)time(NULL);
    void (*cb) (const SSL *ssl, int type, int val) = NULL;
    unsigned long alg_k;
    int ret = -1;
    int new_state, state, skip = 0;
    int listen;
#ifndef OPENSSL_NO_SCTP
    unsigned char sctpauthkey[64];
    char labelbuffer[sizeof(DTLS1_SCTP_AUTH_LABEL)];
#endif

    RAND_add(&Time, sizeof(Time), 0);
    ERR_clear_error();
    clear_sys_error();

    if (s->info_callback != NULL)
        cb = s->info_callback;
    else if (s->ctx->info_callback != NULL)
        cb = s->ctx->info_callback;

    listen = s->d1->listen;

    /* init things to blank */
    s->in_handshake++;
    if (!SSL_in_init(s) || SSL_in_before(s))
        SSL_clear(s);

    s->d1->listen = listen;
#ifndef OPENSSL_NO_SCTP
    /*
     * Notify SCTP BIO socket to enter handshake mode and prevent stream
     * identifier other than 0. Will be ignored if no SCTP is used.
     */
    BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_SET_IN_HANDSHAKE,
             s->in_handshake, NULL);
#endif

    if (s->cert == NULL) {
        SSLerr(SSL_F_DTLS1_ACCEPT, SSL_R_NO_CERTIFICATE_SET);
        return (-1);
    }
#ifndef OPENSSL_NO_HEARTBEATS
    /*
     * If we're awaiting a HeartbeatResponse, pretend we already got and
     * don't await it anymore, because Heartbeats don't make sense during
     * handshakes anyway.
     */
    if (s->tlsext_hb_pending) {
        dtls1_stop_timer(s);
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

            if ((s->version & 0xff00) != (DTLS1_VERSION & 0xff00)) {
                SSLerr(SSL_F_DTLS1_ACCEPT, ERR_R_INTERNAL_ERROR);
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
            s->d1->change_cipher_spec_ok = 0;
            /*
             * Should have been reset by ssl3_get_finished, too.
             */
            s->s3->change_cipher_spec = 0;

            if (s->state != SSL_ST_RENEGOTIATE) {
                /*
                 * Ok, we now need to push on a buffering BIO so that the
                 * output is sent in a way that TCP likes :-) ...but not with
                 * SCTP :-)
                 */
#ifndef OPENSSL_NO_SCTP
                if (!BIO_dgram_is_sctp(SSL_get_wbio(s)))
#endif
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
                SSLerr(SSL_F_DTLS1_ACCEPT,
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
            dtls1_clear_sent_buffer(s);
            dtls1_start_timer(s);
            ret = ssl3_send_hello_request(s);
            if (ret <= 0)
                goto end;
            s->s3->tmp.next_state = SSL3_ST_SR_CLNT_HELLO_A;
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
            dtls1_stop_timer(s);

            if (ret == 1 && (SSL_get_options(s) & SSL_OP_COOKIE_EXCHANGE))
                s->state = DTLS1_ST_SW_HELLO_VERIFY_REQUEST_A;
            else
                s->state = SSL3_ST_SW_SRVR_HELLO_A;

            s->init_num = 0;

            /* If we're just listening, stop here */
            if (listen && s->state == SSL3_ST_SW_SRVR_HELLO_A) {
                ret = 2;
                s->d1->listen = 0;
                /*
                 * Set expected sequence numbers to continue the handshake.
                 */
                s->d1->handshake_read_seq = 2;
                s->d1->handshake_write_seq = 1;
                s->d1->next_handshake_write_seq = 1;
                goto end;
            }

            break;

        case DTLS1_ST_SW_HELLO_VERIFY_REQUEST_A:
        case DTLS1_ST_SW_HELLO_VERIFY_REQUEST_B:

            ret = dtls1_send_hello_verify_request(s);
            if (ret <= 0)
                goto end;
            s->state = SSL3_ST_SW_FLUSH;
            s->s3->tmp.next_state = SSL3_ST_SR_CLNT_HELLO_A;

            /* HelloVerifyRequest resets Finished MAC */
            if (s->version != DTLS1_BAD_VER)
                if (!ssl3_init_finished_mac(s)) {
                    ret = -1;
                    s->state = SSL_ST_ERR;
                    goto end;
                }
            break;

#ifndef OPENSSL_NO_SCTP
        case DTLS1_SCTP_ST_SR_READ_SOCK:

            if (BIO_dgram_sctp_msg_waiting(SSL_get_rbio(s))) {
                s->s3->in_read_app_data = 2;
                s->rwstate = SSL_READING;
                BIO_clear_retry_flags(SSL_get_rbio(s));
                BIO_set_retry_read(SSL_get_rbio(s));
                ret = -1;
                goto end;
            }

            s->state = SSL3_ST_SR_FINISHED_A;
            break;

        case DTLS1_SCTP_ST_SW_WRITE_SOCK:
            ret = BIO_dgram_sctp_wait_for_dry(SSL_get_wbio(s));
            if (ret < 0)
                goto end;

            if (ret == 0) {
                if (s->d1->next_state != SSL_ST_OK) {
                    s->s3->in_read_app_data = 2;
                    s->rwstate = SSL_READING;
                    BIO_clear_retry_flags(SSL_get_rbio(s));
                    BIO_set_retry_read(SSL_get_rbio(s));
                    ret = -1;
                    goto end;
                }
            }

            s->state = s->d1->next_state;
            break;
#endif

        case SSL3_ST_SW_SRVR_HELLO_A:
        case SSL3_ST_SW_SRVR_HELLO_B:
            s->renegotiate = 2;
            dtls1_start_timer(s);
            ret = ssl3_send_server_hello(s);
            if (ret <= 0)
                goto end;

            if (s->hit) {
#ifndef OPENSSL_NO_SCTP
                /*
                 * Add new shared key for SCTP-Auth, will be ignored if no
                 * SCTP used.
                 */
                snprintf((char *)labelbuffer, sizeof(DTLS1_SCTP_AUTH_LABEL),
                         DTLS1_SCTP_AUTH_LABEL);

                if (SSL_export_keying_material(s, sctpauthkey,
                        sizeof(sctpauthkey), labelbuffer,
                        sizeof(labelbuffer), NULL, 0, 0) <= 0) {
                    ret = -1;
                    s->state = SSL_ST_ERR;
                    goto end;
                }

                BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_ADD_AUTH_KEY,
                         sizeof(sctpauthkey), sctpauthkey);
#endif
#ifndef OPENSSL_NO_TLSEXT
                if (s->tlsext_ticket_expected)
                    s->state = SSL3_ST_SW_SESSION_TICKET_A;
                else
                    s->state = SSL3_ST_SW_CHANGE_A;
#else
                s->state = SSL3_ST_SW_CHANGE_A;
#endif
            } else
                s->state = SSL3_ST_SW_CERT_A;
            s->init_num = 0;
            break;

        case SSL3_ST_SW_CERT_A:
        case SSL3_ST_SW_CERT_B:
            /* Check if it is anon DH or normal PSK */
            if (!(s->s3->tmp.new_cipher->algorithm_auth & SSL_aNULL)
                && !(s->s3->tmp.new_cipher->algorithm_mkey & SSL_kPSK)) {
                dtls1_start_timer(s);
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
             * only send if a DH key exchange or RSA but we have a sign only
             * certificate
             */
            if (0
                /*
                 * PSK: send ServerKeyExchange if PSK identity hint if
                 * provided
                 */
#ifndef OPENSSL_NO_PSK
                || ((alg_k & SSL_kPSK) && s->ctx->psk_identity_hint)
#endif
                || (alg_k & SSL_kDHE)
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
                dtls1_start_timer(s);
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
                   ((s->session->peer != NULL) &&
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
                   (s->s3->tmp.new_cipher->algorithm_auth & SSL_aKRB5)
                   /*
                    * With normal PSK Certificates and Certificate Requests
                    * are omitted
                    */
                   || (s->s3->tmp.new_cipher->algorithm_mkey & SSL_kPSK)) {
                /* no cert request */
                skip = 1;
                s->s3->tmp.cert_request = 0;
                s->state = SSL3_ST_SW_SRVR_DONE_A;
#ifndef OPENSSL_NO_SCTP
                if (BIO_dgram_is_sctp(SSL_get_wbio(s))) {
                    s->d1->next_state = SSL3_ST_SW_SRVR_DONE_A;
                    s->state = DTLS1_SCTP_ST_SW_WRITE_SOCK;
                }
#endif
            } else {
                s->s3->tmp.cert_request = 1;
                dtls1_start_timer(s);
                ret = ssl3_send_certificate_request(s);
                if (ret <= 0)
                    goto end;
#ifndef NETSCAPE_HANG_BUG
                s->state = SSL3_ST_SW_SRVR_DONE_A;
# ifndef OPENSSL_NO_SCTP
                if (BIO_dgram_is_sctp(SSL_get_wbio(s))) {
                    s->d1->next_state = SSL3_ST_SW_SRVR_DONE_A;
                    s->state = DTLS1_SCTP_ST_SW_WRITE_SOCK;
                }
# endif
#else
                s->state = SSL3_ST_SW_FLUSH;
                s->s3->tmp.next_state = SSL3_ST_SR_CERT_A;
# ifndef OPENSSL_NO_SCTP
                if (BIO_dgram_is_sctp(SSL_get_wbio(s))) {
                    s->d1->next_state = s->s3->tmp.next_state;
                    s->s3->tmp.next_state = DTLS1_SCTP_ST_SW_WRITE_SOCK;
                }
# endif
#endif
                s->init_num = 0;
            }
            break;

        case SSL3_ST_SW_SRVR_DONE_A:
        case SSL3_ST_SW_SRVR_DONE_B:
            dtls1_start_timer(s);
            ret = ssl3_send_server_done(s);
            if (ret <= 0)
                goto end;
            s->s3->tmp.next_state = SSL3_ST_SR_CERT_A;
            s->state = SSL3_ST_SW_FLUSH;
            s->init_num = 0;
            break;

        case SSL3_ST_SW_FLUSH:
            s->rwstate = SSL_WRITING;
            if (BIO_flush(s->wbio) <= 0) {
                /*
                 * If the write error was fatal, stop trying
                 */
                if (!BIO_should_retry(s->wbio)) {
                    s->rwstate = SSL_NOTHING;
                    s->state = s->s3->tmp.next_state;
                }

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
#ifndef OPENSSL_NO_SCTP
            /*
             * Add new shared key for SCTP-Auth, will be ignored if no SCTP
             * used.
             */
            snprintf((char *)labelbuffer, sizeof(DTLS1_SCTP_AUTH_LABEL),
                     DTLS1_SCTP_AUTH_LABEL);

            if (SSL_export_keying_material(s, sctpauthkey,
                                       sizeof(sctpauthkey), labelbuffer,
                                       sizeof(labelbuffer), NULL, 0, 0) <= 0) {
                ret = -1;
                s->state = SSL_ST_ERR;
                goto end;
            }

            BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_ADD_AUTH_KEY,
                     sizeof(sctpauthkey), sctpauthkey);
#endif

            s->state = SSL3_ST_SR_CERT_VRFY_A;
            s->init_num = 0;

            if (ret == 2) {
                /*
                 * For the ECDH ciphersuites when the client sends its ECDH
                 * pub key in a certificate, the CertificateVerify message is
                 * not sent.
                 */
                s->state = SSL3_ST_SR_FINISHED_A;
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
                    SSLerr(SSL_F_DTLS1_ACCEPT, ERR_R_INTERNAL_ERROR);
                    s->state = SSL_ST_ERR;
                    return -1;
                }
                s->s3->flags |= TLS1_FLAGS_KEEP_HANDSHAKE;
                if (!ssl3_digest_cached_records(s)) {
                    s->state = SSL_ST_ERR;
                    return -1;
                }
            } else {
                s->state = SSL3_ST_SR_CERT_VRFY_A;
                s->init_num = 0;

                /*
                 * We need to get hashes here so if there is a client cert,
                 * it can be verified
                 */
                s->method->ssl3_enc->cert_verify_mac(s,
                                                     NID_md5,
                                                     &(s->s3->
                                                       tmp.cert_verify_md
                                                       [0]));
                s->method->ssl3_enc->cert_verify_mac(s, NID_sha1,
                                                     &(s->s3->
                                                       tmp.cert_verify_md
                                                       [MD5_DIGEST_LENGTH]));
            }
            break;

        case SSL3_ST_SR_CERT_VRFY_A:
        case SSL3_ST_SR_CERT_VRFY_B:
            ret = ssl3_get_cert_verify(s);
            if (ret <= 0)
                goto end;
#ifndef OPENSSL_NO_SCTP
            if (BIO_dgram_is_sctp(SSL_get_wbio(s)) &&
                state == SSL_ST_RENEGOTIATE)
                s->state = DTLS1_SCTP_ST_SR_READ_SOCK;
            else
#endif
                s->state = SSL3_ST_SR_FINISHED_A;
            s->init_num = 0;
            break;

        case SSL3_ST_SR_FINISHED_A:
        case SSL3_ST_SR_FINISHED_B:
            /*
             * Enable CCS. Receiving a CCS clears the flag, so make
             * sure not to re-enable it to ban duplicates. This *should* be the
             * first time we have received one - but we check anyway to be
             * cautious.
             * s->s3->change_cipher_spec is set when a CCS is
             * processed in d1_pkt.c, and remains set until
             * the client's Finished message is read.
             */
            if (!s->s3->change_cipher_spec)
                s->d1->change_cipher_spec_ok = 1;
            ret = ssl3_get_finished(s, SSL3_ST_SR_FINISHED_A,
                                    SSL3_ST_SR_FINISHED_B);
            if (ret <= 0)
                goto end;
            dtls1_stop_timer(s);
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

            ret = dtls1_send_change_cipher_spec(s,
                                                SSL3_ST_SW_CHANGE_A,
                                                SSL3_ST_SW_CHANGE_B);

            if (ret <= 0)
                goto end;

#ifndef OPENSSL_NO_SCTP
            if (!s->hit) {
                /*
                 * Change to new shared key of SCTP-Auth, will be ignored if
                 * no SCTP used.
                 */
                BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_NEXT_AUTH_KEY,
                         0, NULL);
            }
#endif

            s->state = SSL3_ST_SW_FINISHED_A;
            s->init_num = 0;

            if (!s->method->ssl3_enc->change_cipher_state(s,
                                                          SSL3_CHANGE_CIPHER_SERVER_WRITE))
            {
                ret = -1;
                s->state = SSL_ST_ERR;
                goto end;
            }

            dtls1_reset_seq_numbers(s, SSL3_CC_WRITE);
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
                s->s3->tmp.next_state = SSL3_ST_SR_FINISHED_A;

#ifndef OPENSSL_NO_SCTP
                /*
                 * Change to new shared key of SCTP-Auth, will be ignored if
                 * no SCTP used.
                 */
                BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_NEXT_AUTH_KEY,
                         0, NULL);
#endif
            } else {
                s->s3->tmp.next_state = SSL_ST_OK;
#ifndef OPENSSL_NO_SCTP
                if (BIO_dgram_is_sctp(SSL_get_wbio(s))) {
                    s->d1->next_state = s->s3->tmp.next_state;
                    s->s3->tmp.next_state = DTLS1_SCTP_ST_SW_WRITE_SOCK;
                }
#endif
            }
            s->init_num = 0;
            break;

        case SSL_ST_OK:
            /* clean a few things up */
            ssl3_cleanup_key_block(s);

#if 0
            BUF_MEM_free(s->init_buf);
            s->init_buf = NULL;
#endif

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
                s->handshake_func = dtls1_accept;

                if (cb != NULL)
                    cb(s, SSL_CB_HANDSHAKE_DONE, 1);
            }

            ret = 1;

            /* done handshaking, next message is client hello */
            s->d1->handshake_read_seq = 0;
            /* next message is server hello */
            s->d1->handshake_write_seq = 0;
            s->d1->next_handshake_write_seq = 0;
            dtls1_clear_received_buffer(s);
            goto end;
            /* break; */

        case SSL_ST_ERR:
        default:
            SSLerr(SSL_F_DTLS1_ACCEPT, SSL_R_UNKNOWN_STATE);
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
#ifndef OPENSSL_NO_SCTP
    /*
     * Notify SCTP BIO socket to leave handshake mode and prevent stream
     * identifier other than 0. Will be ignored if no SCTP is used.
     */
    BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_SET_IN_HANDSHAKE,
             s->in_handshake, NULL);
#endif

    if (cb != NULL)
        cb(s, SSL_CB_ACCEPT_EXIT, ret);
    return (ret);
}

int dtls1_send_hello_verify_request(SSL *s)
{
    unsigned int msg_len;
    unsigned char *msg, *buf, *p;

    if (s->state == DTLS1_ST_SW_HELLO_VERIFY_REQUEST_A) {
        buf = (unsigned char *)s->init_buf->data;

        msg = p = &(buf[DTLS1_HM_HEADER_LENGTH]);
        /* Always use DTLS 1.0 version: see RFC 6347 */
        *(p++) = DTLS1_VERSION >> 8;
        *(p++) = DTLS1_VERSION & 0xFF;

        if (s->ctx->app_gen_cookie_cb == NULL ||
            s->ctx->app_gen_cookie_cb(s, s->d1->cookie,
                                      &(s->d1->cookie_len)) == 0) {
            SSLerr(SSL_F_DTLS1_SEND_HELLO_VERIFY_REQUEST,
                   ERR_R_INTERNAL_ERROR);
            s->state = SSL_ST_ERR;
            return 0;
        }

        *(p++) = (unsigned char)s->d1->cookie_len;
        memcpy(p, s->d1->cookie, s->d1->cookie_len);
        p += s->d1->cookie_len;
        msg_len = p - msg;

        dtls1_set_message_header(s, buf,
                                 DTLS1_MT_HELLO_VERIFY_REQUEST, msg_len, 0,
                                 msg_len);

        s->state = DTLS1_ST_SW_HELLO_VERIFY_REQUEST_B;
        /* number of bytes to write */
        s->init_num = p - buf;
        s->init_off = 0;
    }

    /* s->state = DTLS1_ST_SW_HELLO_VERIFY_REQUEST_B */
    return (dtls1_do_write(s, SSL3_RT_HANDSHAKE));
}
