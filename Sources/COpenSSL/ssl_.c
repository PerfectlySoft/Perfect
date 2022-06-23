/* ssl/ssl_algs.c */
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
#include "objects.h"
#include "lhash.h"
#include "ssl_locl.h"

int SSL_library_init(void)
{

#ifndef OPENSSL_NO_DES
    EVP_add_cipher(EVP_des_cbc());
    EVP_add_cipher(EVP_des_ede3_cbc());
#endif
#ifndef OPENSSL_NO_IDEA
    EVP_add_cipher(EVP_idea_cbc());
#endif
#ifndef OPENSSL_NO_RC4
    EVP_add_cipher(EVP_rc4());
# if !defined(OPENSSL_NO_MD5) && (defined(__x86_64) || defined(__x86_64__))
    EVP_add_cipher(EVP_rc4_hmac_md5());
# endif
#endif
#ifndef OPENSSL_NO_RC2
    EVP_add_cipher(EVP_rc2_cbc());
    /*
     * Not actually used for SSL/TLS but this makes PKCS#12 work if an
     * application only calls SSL_library_init().
     */
    EVP_add_cipher(EVP_rc2_40_cbc());
#endif
#ifndef OPENSSL_NO_AES
    EVP_add_cipher(EVP_aes_128_cbc());
    EVP_add_cipher(EVP_aes_192_cbc());
    EVP_add_cipher(EVP_aes_256_cbc());
    EVP_add_cipher(EVP_aes_128_gcm());
    EVP_add_cipher(EVP_aes_256_gcm());
# if !defined(OPENSSL_NO_SHA) && !defined(OPENSSL_NO_SHA1)
    EVP_add_cipher(EVP_aes_128_cbc_hmac_sha1());
    EVP_add_cipher(EVP_aes_256_cbc_hmac_sha1());
# endif
# if !defined(OPENSSL_NO_SHA) && !defined(OPENSSL_NO_SHA256)
    EVP_add_cipher(EVP_aes_128_cbc_hmac_sha256());
    EVP_add_cipher(EVP_aes_256_cbc_hmac_sha256());
# endif

#endif
#ifndef OPENSSL_NO_CAMELLIA
    EVP_add_cipher(EVP_camellia_128_cbc());
    EVP_add_cipher(EVP_camellia_256_cbc());
#endif

#ifndef OPENSSL_NO_SEED
    EVP_add_cipher(EVP_seed_cbc());
#endif

#ifndef OPENSSL_NO_MD5
    EVP_add_digest(EVP_md5());
    EVP_add_digest_alias(SN_md5, "ssl2-md5");
    EVP_add_digest_alias(SN_md5, "ssl3-md5");
#endif
#ifndef OPENSSL_NO_SHA
    EVP_add_digest(EVP_sha1()); /* RSA with sha1 */
    EVP_add_digest_alias(SN_sha1, "ssl3-sha1");
    EVP_add_digest_alias(SN_sha1WithRSAEncryption, SN_sha1WithRSA);
#endif
#ifndef OPENSSL_NO_SHA256
    EVP_add_digest(EVP_sha224());
    EVP_add_digest(EVP_sha256());
#endif
#ifndef OPENSSL_NO_SHA512
    EVP_add_digest(EVP_sha384());
    EVP_add_digest(EVP_sha512());
#endif
#if !defined(OPENSSL_NO_SHA) && !defined(OPENSSL_NO_DSA)
    EVP_add_digest(EVP_dss1()); /* DSA with sha1 */
    EVP_add_digest_alias(SN_dsaWithSHA1, SN_dsaWithSHA1_2);
    EVP_add_digest_alias(SN_dsaWithSHA1, "DSS1");
    EVP_add_digest_alias(SN_dsaWithSHA1, "dss1");
#endif
#ifndef OPENSSL_NO_ECDSA
    EVP_add_digest(EVP_ecdsa());
#endif
    /* If you want support for phased out ciphers, add the following */
#if 0
    EVP_add_digest(EVP_sha());
    EVP_add_digest(EVP_dss());
#endif
#ifndef OPENSSL_NO_COMP
    /*
     * This will initialise the built-in compression algorithms. The value
     * returned is a STACK_OF(SSL_COMP), but that can be discarded safely
     */
    (void)SSL_COMP_get_compression_methods();
#endif
    /* initialize cipher/digest methods table */
    ssl_load_ciphers();
    return (1);
}
/* ssl/ssl_asn1.c */
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
#include <stdlib.h>
// #include "ssl_locl.h"
#include "asn1_mac.h"
// #include "objects.h"
#include "x509.h"

typedef struct ssl_session_asn1_st {
    ASN1_INTEGER version;
    ASN1_INTEGER ssl_version;
    ASN1_OCTET_STRING cipher;
    ASN1_OCTET_STRING comp_id;
    ASN1_OCTET_STRING master_key;
    ASN1_OCTET_STRING session_id;
    ASN1_OCTET_STRING session_id_context;
    ASN1_OCTET_STRING key_arg;
#ifndef OPENSSL_NO_KRB5
    ASN1_OCTET_STRING krb5_princ;
#endif                          /* OPENSSL_NO_KRB5 */
    ASN1_INTEGER time;
    ASN1_INTEGER timeout;
    ASN1_INTEGER verify_result;
#ifndef OPENSSL_NO_TLSEXT
    ASN1_OCTET_STRING tlsext_hostname;
    ASN1_INTEGER tlsext_tick_lifetime;
    ASN1_OCTET_STRING tlsext_tick;
#endif                          /* OPENSSL_NO_TLSEXT */
#ifndef OPENSSL_NO_PSK
    ASN1_OCTET_STRING psk_identity_hint;
    ASN1_OCTET_STRING psk_identity;
#endif                          /* OPENSSL_NO_PSK */
#ifndef OPENSSL_NO_SRP
    ASN1_OCTET_STRING srp_username;
#endif                          /* OPENSSL_NO_SRP */
} SSL_SESSION_ASN1;

int i2d_SSL_SESSION(SSL_SESSION *in, unsigned char **pp)
{
#define LSIZE2 (sizeof(long)*2)
    int v1 = 0, v2 = 0, v3 = 0, v4 = 0, v5 = 0;
    unsigned char buf[4], ibuf1[LSIZE2], ibuf2[LSIZE2];
    unsigned char ibuf3[LSIZE2], ibuf4[LSIZE2], ibuf5[LSIZE2];
#ifndef OPENSSL_NO_TLSEXT
    int v6 = 0, v9 = 0, v10 = 0;
    unsigned char ibuf6[LSIZE2];
#endif
#ifndef OPENSSL_NO_PSK
    int v7 = 0, v8 = 0;
#endif
#ifndef OPENSSL_NO_COMP
    unsigned char cbuf;
    int v11 = 0;
#endif
#ifndef OPENSSL_NO_SRP
    int v12 = 0;
#endif
    long l;
    SSL_SESSION_ASN1 a;
    M_ASN1_I2D_vars(in);

    if ((in == NULL) || ((in->cipher == NULL) && (in->cipher_id == 0)))
        return (0);

    /*
     * Note that I cheat in the following 2 assignments.  I know that if the
     * ASN1_INTEGER passed to ASN1_INTEGER_set is > sizeof(long)+1, the
     * buffer will not be re-OPENSSL_malloc()ed. This is a bit evil but makes
     * things simple, no dynamic allocation to clean up :-)
     */
    a.version.length = LSIZE2;
    a.version.type = V_ASN1_INTEGER;
    a.version.data = ibuf1;
    ASN1_INTEGER_set(&(a.version), SSL_SESSION_ASN1_VERSION);

    a.ssl_version.length = LSIZE2;
    a.ssl_version.type = V_ASN1_INTEGER;
    a.ssl_version.data = ibuf2;
    ASN1_INTEGER_set(&(a.ssl_version), in->ssl_version);

    a.cipher.type = V_ASN1_OCTET_STRING;
    a.cipher.data = buf;

    if (in->cipher == NULL)
        l = in->cipher_id;
    else
        l = in->cipher->id;
    if (in->ssl_version == SSL2_VERSION) {
        a.cipher.length = 3;
        buf[0] = ((unsigned char)(l >> 16L)) & 0xff;
        buf[1] = ((unsigned char)(l >> 8L)) & 0xff;
        buf[2] = ((unsigned char)(l)) & 0xff;
    } else {
        a.cipher.length = 2;
        buf[0] = ((unsigned char)(l >> 8L)) & 0xff;
        buf[1] = ((unsigned char)(l)) & 0xff;
    }

#ifndef OPENSSL_NO_COMP
    if (in->compress_meth) {
        cbuf = (unsigned char)in->compress_meth;
        a.comp_id.length = 1;
        a.comp_id.type = V_ASN1_OCTET_STRING;
        a.comp_id.data = &cbuf;
    }
#endif

    a.master_key.length = in->master_key_length;
    a.master_key.type = V_ASN1_OCTET_STRING;
    a.master_key.data = in->master_key;

    a.session_id.length = in->session_id_length;
    a.session_id.type = V_ASN1_OCTET_STRING;
    a.session_id.data = in->session_id;

    a.session_id_context.length = in->sid_ctx_length;
    a.session_id_context.type = V_ASN1_OCTET_STRING;
    a.session_id_context.data = in->sid_ctx;

    a.key_arg.length = in->key_arg_length;
    a.key_arg.type = V_ASN1_OCTET_STRING;
    a.key_arg.data = in->key_arg;

#ifndef OPENSSL_NO_KRB5
    if (in->krb5_client_princ_len) {
        a.krb5_princ.length = in->krb5_client_princ_len;
        a.krb5_princ.type = V_ASN1_OCTET_STRING;
        a.krb5_princ.data = in->krb5_client_princ;
    }
#endif                          /* OPENSSL_NO_KRB5 */

    if (in->time != 0L) {
        a.time.length = LSIZE2;
        a.time.type = V_ASN1_INTEGER;
        a.time.data = ibuf3;
        ASN1_INTEGER_set(&(a.time), in->time);
    }

    if (in->timeout != 0L) {
        a.timeout.length = LSIZE2;
        a.timeout.type = V_ASN1_INTEGER;
        a.timeout.data = ibuf4;
        ASN1_INTEGER_set(&(a.timeout), in->timeout);
    }

    if (in->verify_result != X509_V_OK) {
        a.verify_result.length = LSIZE2;
        a.verify_result.type = V_ASN1_INTEGER;
        a.verify_result.data = ibuf5;
        ASN1_INTEGER_set(&a.verify_result, in->verify_result);
    }
#ifndef OPENSSL_NO_TLSEXT
    if (in->tlsext_hostname) {
        a.tlsext_hostname.length = strlen(in->tlsext_hostname);
        a.tlsext_hostname.type = V_ASN1_OCTET_STRING;
        a.tlsext_hostname.data = (unsigned char *)in->tlsext_hostname;
    }
    if (in->tlsext_tick) {
        a.tlsext_tick.length = in->tlsext_ticklen;
        a.tlsext_tick.type = V_ASN1_OCTET_STRING;
        a.tlsext_tick.data = (unsigned char *)in->tlsext_tick;
    }
    if (in->tlsext_tick_lifetime_hint > 0) {
        a.tlsext_tick_lifetime.length = LSIZE2;
        a.tlsext_tick_lifetime.type = V_ASN1_INTEGER;
        a.tlsext_tick_lifetime.data = ibuf6;
        ASN1_INTEGER_set(&a.tlsext_tick_lifetime,
                         in->tlsext_tick_lifetime_hint);
    }
#endif                          /* OPENSSL_NO_TLSEXT */
#ifndef OPENSSL_NO_PSK
    if (in->psk_identity_hint) {
        a.psk_identity_hint.length = strlen(in->psk_identity_hint);
        a.psk_identity_hint.type = V_ASN1_OCTET_STRING;
        a.psk_identity_hint.data = (unsigned char *)(in->psk_identity_hint);
    }
    if (in->psk_identity) {
        a.psk_identity.length = strlen(in->psk_identity);
        a.psk_identity.type = V_ASN1_OCTET_STRING;
        a.psk_identity.data = (unsigned char *)(in->psk_identity);
    }
#endif                          /* OPENSSL_NO_PSK */
#ifndef OPENSSL_NO_SRP
    if (in->srp_username) {
        a.srp_username.length = strlen(in->srp_username);
        a.srp_username.type = V_ASN1_OCTET_STRING;
        a.srp_username.data = (unsigned char *)(in->srp_username);
    }
#endif                          /* OPENSSL_NO_SRP */

    M_ASN1_I2D_len(&(a.version), i2d_ASN1_INTEGER);
    M_ASN1_I2D_len(&(a.ssl_version), i2d_ASN1_INTEGER);
    M_ASN1_I2D_len(&(a.cipher), i2d_ASN1_OCTET_STRING);
    M_ASN1_I2D_len(&(a.session_id), i2d_ASN1_OCTET_STRING);
    M_ASN1_I2D_len(&(a.master_key), i2d_ASN1_OCTET_STRING);
#ifndef OPENSSL_NO_KRB5
    if (in->krb5_client_princ_len)
        M_ASN1_I2D_len(&(a.krb5_princ), i2d_ASN1_OCTET_STRING);
#endif                          /* OPENSSL_NO_KRB5 */
    if (in->key_arg_length > 0)
        M_ASN1_I2D_len_IMP_opt(&(a.key_arg), i2d_ASN1_OCTET_STRING);
    if (in->time != 0L)
        M_ASN1_I2D_len_EXP_opt(&(a.time), i2d_ASN1_INTEGER, 1, v1);
    if (in->timeout != 0L)
        M_ASN1_I2D_len_EXP_opt(&(a.timeout), i2d_ASN1_INTEGER, 2, v2);
    if (in->peer != NULL)
        M_ASN1_I2D_len_EXP_opt(in->peer, i2d_X509, 3, v3);
    M_ASN1_I2D_len_EXP_opt(&a.session_id_context, i2d_ASN1_OCTET_STRING, 4,
                           v4);
    if (in->verify_result != X509_V_OK)
        M_ASN1_I2D_len_EXP_opt(&(a.verify_result), i2d_ASN1_INTEGER, 5, v5);

#ifndef OPENSSL_NO_TLSEXT
    if (in->tlsext_tick_lifetime_hint > 0)
        M_ASN1_I2D_len_EXP_opt(&a.tlsext_tick_lifetime, i2d_ASN1_INTEGER, 9,
                               v9);
    if (in->tlsext_tick)
        M_ASN1_I2D_len_EXP_opt(&(a.tlsext_tick), i2d_ASN1_OCTET_STRING, 10,
                               v10);
    if (in->tlsext_hostname)
        M_ASN1_I2D_len_EXP_opt(&(a.tlsext_hostname), i2d_ASN1_OCTET_STRING, 6,
                               v6);
# ifndef OPENSSL_NO_COMP
    if (in->compress_meth)
        M_ASN1_I2D_len_EXP_opt(&(a.comp_id), i2d_ASN1_OCTET_STRING, 11, v11);
# endif
#endif                          /* OPENSSL_NO_TLSEXT */
#ifndef OPENSSL_NO_PSK
    if (in->psk_identity_hint)
        M_ASN1_I2D_len_EXP_opt(&(a.psk_identity_hint), i2d_ASN1_OCTET_STRING,
                               7, v7);
    if (in->psk_identity)
        M_ASN1_I2D_len_EXP_opt(&(a.psk_identity), i2d_ASN1_OCTET_STRING, 8,
                               v8);
#endif                          /* OPENSSL_NO_PSK */
#ifndef OPENSSL_NO_SRP
    if (in->srp_username)
        M_ASN1_I2D_len_EXP_opt(&(a.srp_username), i2d_ASN1_OCTET_STRING, 12,
                               v12);
#endif                          /* OPENSSL_NO_SRP */

    M_ASN1_I2D_seq_total();

    M_ASN1_I2D_put(&(a.version), i2d_ASN1_INTEGER);
    M_ASN1_I2D_put(&(a.ssl_version), i2d_ASN1_INTEGER);
    M_ASN1_I2D_put(&(a.cipher), i2d_ASN1_OCTET_STRING);
    M_ASN1_I2D_put(&(a.session_id), i2d_ASN1_OCTET_STRING);
    M_ASN1_I2D_put(&(a.master_key), i2d_ASN1_OCTET_STRING);
#ifndef OPENSSL_NO_KRB5
    if (in->krb5_client_princ_len)
        M_ASN1_I2D_put(&(a.krb5_princ), i2d_ASN1_OCTET_STRING);
#endif                          /* OPENSSL_NO_KRB5 */
    if (in->key_arg_length > 0)
        M_ASN1_I2D_put_IMP_opt(&(a.key_arg), i2d_ASN1_OCTET_STRING, 0);
    if (in->time != 0L)
        M_ASN1_I2D_put_EXP_opt(&(a.time), i2d_ASN1_INTEGER, 1, v1);
    if (in->timeout != 0L)
        M_ASN1_I2D_put_EXP_opt(&(a.timeout), i2d_ASN1_INTEGER, 2, v2);
    if (in->peer != NULL)
        M_ASN1_I2D_put_EXP_opt(in->peer, i2d_X509, 3, v3);
    M_ASN1_I2D_put_EXP_opt(&a.session_id_context, i2d_ASN1_OCTET_STRING, 4,
                           v4);
    if (in->verify_result != X509_V_OK)
        M_ASN1_I2D_put_EXP_opt(&a.verify_result, i2d_ASN1_INTEGER, 5, v5);
#ifndef OPENSSL_NO_TLSEXT
    if (in->tlsext_hostname)
        M_ASN1_I2D_put_EXP_opt(&(a.tlsext_hostname), i2d_ASN1_OCTET_STRING, 6,
                               v6);
#endif                          /* OPENSSL_NO_TLSEXT */
#ifndef OPENSSL_NO_PSK
    if (in->psk_identity_hint)
        M_ASN1_I2D_put_EXP_opt(&(a.psk_identity_hint), i2d_ASN1_OCTET_STRING,
                               7, v7);
    if (in->psk_identity)
        M_ASN1_I2D_put_EXP_opt(&(a.psk_identity), i2d_ASN1_OCTET_STRING, 8,
                               v8);
#endif                          /* OPENSSL_NO_PSK */
#ifndef OPENSSL_NO_TLSEXT
    if (in->tlsext_tick_lifetime_hint > 0)
        M_ASN1_I2D_put_EXP_opt(&a.tlsext_tick_lifetime, i2d_ASN1_INTEGER, 9,
                               v9);
    if (in->tlsext_tick)
        M_ASN1_I2D_put_EXP_opt(&(a.tlsext_tick), i2d_ASN1_OCTET_STRING, 10,
                               v10);
#endif                          /* OPENSSL_NO_TLSEXT */
#ifndef OPENSSL_NO_COMP
    if (in->compress_meth)
        M_ASN1_I2D_put_EXP_opt(&(a.comp_id), i2d_ASN1_OCTET_STRING, 11, v11);
#endif
#ifndef OPENSSL_NO_SRP
    if (in->srp_username)
        M_ASN1_I2D_put_EXP_opt(&(a.srp_username), i2d_ASN1_OCTET_STRING, 12,
                               v12);
#endif                          /* OPENSSL_NO_SRP */
    M_ASN1_I2D_finish();
}

SSL_SESSION *d2i_SSL_SESSION(SSL_SESSION **a, const unsigned char **pp,
                             long length)
{
    int ssl_version = 0, i;
    long id;
    ASN1_INTEGER ai, *aip;
    ASN1_OCTET_STRING os, *osp;
    M_ASN1_D2I_vars(a, SSL_SESSION *, SSL_SESSION_new);

    aip = &ai;
    osp = &os;

    M_ASN1_D2I_Init();
    M_ASN1_D2I_start_sequence();

    ai.data = NULL;
    ai.length = 0;
    M_ASN1_D2I_get_x(ASN1_INTEGER, aip, d2i_ASN1_INTEGER);
    if (ai.data != NULL) {
        OPENSSL_free(ai.data);
        ai.data = NULL;
        ai.length = 0;
    }

    /* we don't care about the version right now :-) */
    M_ASN1_D2I_get_x(ASN1_INTEGER, aip, d2i_ASN1_INTEGER);
    ssl_version = (int)ASN1_INTEGER_get(aip);
    ret->ssl_version = ssl_version;
    if (ai.data != NULL) {
        OPENSSL_free(ai.data);
        ai.data = NULL;
        ai.length = 0;
    }

    os.data = NULL;
    os.length = 0;
    M_ASN1_D2I_get_x(ASN1_OCTET_STRING, osp, d2i_ASN1_OCTET_STRING);
    if (ssl_version == SSL2_VERSION) {
        if (os.length != 3) {
            c.error = SSL_R_CIPHER_CODE_WRONG_LENGTH;
            c.line = __LINE__;
            goto err;
        }
        id = 0x02000000L |
            ((unsigned long)os.data[0] << 16L) |
            ((unsigned long)os.data[1] << 8L) | (unsigned long)os.data[2];
    } else if ((ssl_version >> 8) == SSL3_VERSION_MAJOR
        || (ssl_version >> 8) == DTLS1_VERSION_MAJOR
        || ssl_version == DTLS1_BAD_VER) {
        if (os.length != 2) {
            c.error = SSL_R_CIPHER_CODE_WRONG_LENGTH;
            c.line = __LINE__;
            goto err;
        }
        id = 0x03000000L |
            ((unsigned long)os.data[0] << 8L) | (unsigned long)os.data[1];
    } else {
        c.error = SSL_R_UNKNOWN_SSL_VERSION;
        c.line = __LINE__;
        goto err;
    }

    ret->cipher = NULL;
    ret->cipher_id = id;

    M_ASN1_D2I_get_x(ASN1_OCTET_STRING, osp, d2i_ASN1_OCTET_STRING);
    if ((ssl_version >> 8) >= SSL3_VERSION_MAJOR)
        i = SSL3_MAX_SSL_SESSION_ID_LENGTH;
    else                        /* if (ssl_version>>8 == SSL2_VERSION_MAJOR) */
        i = SSL2_MAX_SSL_SESSION_ID_LENGTH;

    if (os.length > i)
        os.length = i;
    if (os.length > (int)sizeof(ret->session_id)) /* can't happen */
        os.length = sizeof(ret->session_id);

    ret->session_id_length = os.length;
    OPENSSL_assert(os.length <= (int)sizeof(ret->session_id));
    memcpy(ret->session_id, os.data, os.length);

    M_ASN1_D2I_get_x(ASN1_OCTET_STRING, osp, d2i_ASN1_OCTET_STRING);
    if (os.length > SSL_MAX_MASTER_KEY_LENGTH)
        ret->master_key_length = SSL_MAX_MASTER_KEY_LENGTH;
    else
        ret->master_key_length = os.length;
    memcpy(ret->master_key, os.data, ret->master_key_length);

    os.length = 0;

#ifndef OPENSSL_NO_KRB5
    os.length = 0;
    M_ASN1_D2I_get_opt(osp, d2i_ASN1_OCTET_STRING, V_ASN1_OCTET_STRING);
    if (os.data) {
        if (os.length > SSL_MAX_KRB5_PRINCIPAL_LENGTH)
            ret->krb5_client_princ_len = 0;
        else
            ret->krb5_client_princ_len = os.length;
        memcpy(ret->krb5_client_princ, os.data, ret->krb5_client_princ_len);
        OPENSSL_free(os.data);
        os.data = NULL;
        os.length = 0;
    } else
        ret->krb5_client_princ_len = 0;
#endif                          /* OPENSSL_NO_KRB5 */

    M_ASN1_D2I_get_IMP_opt(osp, d2i_ASN1_OCTET_STRING, 0,
                           V_ASN1_OCTET_STRING);
    if (os.length > SSL_MAX_KEY_ARG_LENGTH)
        ret->key_arg_length = SSL_MAX_KEY_ARG_LENGTH;
    else
        ret->key_arg_length = os.length;
    memcpy(ret->key_arg, os.data, ret->key_arg_length);
    if (os.data != NULL)
        OPENSSL_free(os.data);

    ai.length = 0;
    M_ASN1_D2I_get_EXP_opt(aip, d2i_ASN1_INTEGER, 1);
    if (ai.data != NULL) {
        ret->time = ASN1_INTEGER_get(aip);
        OPENSSL_free(ai.data);
        ai.data = NULL;
        ai.length = 0;
    } else
        ret->time = (unsigned long)time(NULL);

    ai.length = 0;
    M_ASN1_D2I_get_EXP_opt(aip, d2i_ASN1_INTEGER, 2);
    if (ai.data != NULL) {
        ret->timeout = ASN1_INTEGER_get(aip);
        OPENSSL_free(ai.data);
        ai.data = NULL;
        ai.length = 0;
    } else
        ret->timeout = 3;

    if (ret->peer != NULL) {
        X509_free(ret->peer);
        ret->peer = NULL;
    }
    M_ASN1_D2I_get_EXP_opt(ret->peer, d2i_X509, 3);

    os.length = 0;
    os.data = NULL;
    M_ASN1_D2I_get_EXP_opt(osp, d2i_ASN1_OCTET_STRING, 4);

    if (os.data != NULL) {
        if (os.length > SSL_MAX_SID_CTX_LENGTH) {
            c.error = SSL_R_BAD_LENGTH;
            c.line = __LINE__;
            OPENSSL_free(os.data);
            os.data = NULL;
            os.length = 0;
            goto err;
        } else {
            ret->sid_ctx_length = os.length;
            memcpy(ret->sid_ctx, os.data, os.length);
        }
        OPENSSL_free(os.data);
        os.data = NULL;
        os.length = 0;
    } else
        ret->sid_ctx_length = 0;

    ai.length = 0;
    M_ASN1_D2I_get_EXP_opt(aip, d2i_ASN1_INTEGER, 5);
    if (ai.data != NULL) {
        ret->verify_result = ASN1_INTEGER_get(aip);
        OPENSSL_free(ai.data);
        ai.data = NULL;
        ai.length = 0;
    } else
        ret->verify_result = X509_V_OK;

#ifndef OPENSSL_NO_TLSEXT
    os.length = 0;
    os.data = NULL;
    M_ASN1_D2I_get_EXP_opt(osp, d2i_ASN1_OCTET_STRING, 6);
    if (os.data) {
        ret->tlsext_hostname = BUF_strndup((char *)os.data, os.length);
        OPENSSL_free(os.data);
        os.data = NULL;
        os.length = 0;
    } else
        ret->tlsext_hostname = NULL;
#endif                          /* OPENSSL_NO_TLSEXT */

#ifndef OPENSSL_NO_PSK
    os.length = 0;
    os.data = NULL;
    M_ASN1_D2I_get_EXP_opt(osp, d2i_ASN1_OCTET_STRING, 7);
    if (os.data) {
        ret->psk_identity_hint = BUF_strndup((char *)os.data, os.length);
        OPENSSL_free(os.data);
        os.data = NULL;
        os.length = 0;
    } else
        ret->psk_identity_hint = NULL;

    os.length = 0;
    os.data = NULL;
    M_ASN1_D2I_get_EXP_opt(osp, d2i_ASN1_OCTET_STRING, 8);
    if (os.data) {
        ret->psk_identity = BUF_strndup((char *)os.data, os.length);
        OPENSSL_free(os.data);
        os.data = NULL;
        os.length = 0;
    } else
        ret->psk_identity = NULL;
#endif                          /* OPENSSL_NO_PSK */

#ifndef OPENSSL_NO_TLSEXT
    ai.length = 0;
    M_ASN1_D2I_get_EXP_opt(aip, d2i_ASN1_INTEGER, 9);
    if (ai.data != NULL) {
        ret->tlsext_tick_lifetime_hint = ASN1_INTEGER_get(aip);
        OPENSSL_free(ai.data);
        ai.data = NULL;
        ai.length = 0;
    } else if (ret->tlsext_ticklen && ret->session_id_length)
        ret->tlsext_tick_lifetime_hint = -1;
    else
        ret->tlsext_tick_lifetime_hint = 0;
    os.length = 0;
    os.data = NULL;
    M_ASN1_D2I_get_EXP_opt(osp, d2i_ASN1_OCTET_STRING, 10);
    if (os.data) {
        ret->tlsext_tick = os.data;
        ret->tlsext_ticklen = os.length;
        os.data = NULL;
        os.length = 0;
    } else
        ret->tlsext_tick = NULL;
#endif                          /* OPENSSL_NO_TLSEXT */
#ifndef OPENSSL_NO_COMP
    os.length = 0;
    os.data = NULL;
    M_ASN1_D2I_get_EXP_opt(osp, d2i_ASN1_OCTET_STRING, 11);
    if (os.data) {
        ret->compress_meth = os.data[0];
        OPENSSL_free(os.data);
        os.data = NULL;
    }
#endif

#ifndef OPENSSL_NO_SRP
    os.length = 0;
    os.data = NULL;
    M_ASN1_D2I_get_EXP_opt(osp, d2i_ASN1_OCTET_STRING, 12);
    if (os.data) {
        ret->srp_username = BUF_strndup((char *)os.data, os.length);
        OPENSSL_free(os.data);
        os.data = NULL;
        os.length = 0;
    } else
        ret->srp_username = NULL;
#endif                          /* OPENSSL_NO_SRP */

    M_ASN1_D2I_Finish(a, SSL_SESSION_free, SSL_F_D2I_SSL_SESSION);
}
/*
 * ! \file ssl/ssl_cert.c
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
 * ECC cipher suite support in OpenSSL originally developed by
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
 */

#include <stdio.h>

#include "e_os.h"
#ifndef NO_SYS_TYPES_H
# include <sys/types.h>
#endif

#include "o_dir.h"
// #include "objects.h"
#include "bio.h"
#include "pem.h"
#include "x509v3.h"
#ifndef OPENSSL_NO_DH
# include "dh.h"
#endif
#include "bn.h"
// #include "ssl_locl.h"

int SSL_get_ex_data_X509_STORE_CTX_idx(void)
{
    static volatile int ssl_x509_store_ctx_idx = -1;
    int got_write_lock = 0;

    if (((size_t)&ssl_x509_store_ctx_idx &
         (sizeof(ssl_x509_store_ctx_idx) - 1))
        == 0) {                 /* check alignment, practically always true */
        int ret;

        if ((ret = ssl_x509_store_ctx_idx) < 0) {
            CRYPTO_w_lock(CRYPTO_LOCK_SSL_CTX);
            if ((ret = ssl_x509_store_ctx_idx) < 0) {
                ret = ssl_x509_store_ctx_idx =
                    X509_STORE_CTX_get_ex_new_index(0,
                                                    "SSL for verify callback",
                                                    NULL, NULL, NULL);
            }
            CRYPTO_w_unlock(CRYPTO_LOCK_SSL_CTX);
        }

        return ret;
    } else {                    /* commonly eliminated */

        CRYPTO_r_lock(CRYPTO_LOCK_SSL_CTX);

        if (ssl_x509_store_ctx_idx < 0) {
            CRYPTO_r_unlock(CRYPTO_LOCK_SSL_CTX);
            CRYPTO_w_lock(CRYPTO_LOCK_SSL_CTX);
            got_write_lock = 1;

            if (ssl_x509_store_ctx_idx < 0) {
                ssl_x509_store_ctx_idx =
                    X509_STORE_CTX_get_ex_new_index(0,
                                                    "SSL for verify callback",
                                                    NULL, NULL, NULL);
            }
        }

        if (got_write_lock)
            CRYPTO_w_unlock(CRYPTO_LOCK_SSL_CTX);
        else
            CRYPTO_r_unlock(CRYPTO_LOCK_SSL_CTX);

        return ssl_x509_store_ctx_idx;
    }
}

void ssl_cert_set_default_md(CERT *cert)
{
    /* Set digest values to defaults */
#ifndef OPENSSL_NO_DSA
    cert->pkeys[SSL_PKEY_DSA_SIGN].digest = EVP_sha1();
#endif
#ifndef OPENSSL_NO_RSA
    cert->pkeys[SSL_PKEY_RSA_SIGN].digest = EVP_sha1();
    cert->pkeys[SSL_PKEY_RSA_ENC].digest = EVP_sha1();
#endif
#ifndef OPENSSL_NO_ECDSA
    cert->pkeys[SSL_PKEY_ECC].digest = EVP_sha1();
#endif
}

CERT *ssl_cert_new(void)
{
    CERT *ret;

    ret = (CERT *)OPENSSL_malloc(sizeof(CERT));
    if (ret == NULL) {
        SSLerr(SSL_F_SSL_CERT_NEW, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }
    memset(ret, 0, sizeof(CERT));

    ret->key = &(ret->pkeys[SSL_PKEY_RSA_ENC]);
    ret->references = 1;
    ssl_cert_set_default_md(ret);
    return (ret);
}

CERT *ssl_cert_dup(CERT *cert)
{
    CERT *ret;
    int i;

    ret = (CERT *)OPENSSL_malloc(sizeof(CERT));
    if (ret == NULL) {
        SSLerr(SSL_F_SSL_CERT_DUP, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }

    memset(ret, 0, sizeof(CERT));

    ret->references = 1;
    ret->key = &ret->pkeys[cert->key - &cert->pkeys[0]];
    /*
     * or ret->key = ret->pkeys + (cert->key - cert->pkeys), if you find that
     * more readable
     */

    ret->valid = cert->valid;
    ret->mask_k = cert->mask_k;
    ret->mask_a = cert->mask_a;
    ret->export_mask_k = cert->export_mask_k;
    ret->export_mask_a = cert->export_mask_a;

#ifndef OPENSSL_NO_RSA
    if (cert->rsa_tmp != NULL) {
        RSA_up_ref(cert->rsa_tmp);
        ret->rsa_tmp = cert->rsa_tmp;
    }
    ret->rsa_tmp_cb = cert->rsa_tmp_cb;
#endif

#ifndef OPENSSL_NO_DH
    if (cert->dh_tmp != NULL) {
        ret->dh_tmp = DHparams_dup(cert->dh_tmp);
        if (ret->dh_tmp == NULL) {
            SSLerr(SSL_F_SSL_CERT_DUP, ERR_R_DH_LIB);
            goto err;
        }
        if (cert->dh_tmp->priv_key) {
            BIGNUM *b = BN_dup(cert->dh_tmp->priv_key);
            if (!b) {
                SSLerr(SSL_F_SSL_CERT_DUP, ERR_R_BN_LIB);
                goto err;
            }
            ret->dh_tmp->priv_key = b;
        }
        if (cert->dh_tmp->pub_key) {
            BIGNUM *b = BN_dup(cert->dh_tmp->pub_key);
            if (!b) {
                SSLerr(SSL_F_SSL_CERT_DUP, ERR_R_BN_LIB);
                goto err;
            }
            ret->dh_tmp->pub_key = b;
        }
    }
    ret->dh_tmp_cb = cert->dh_tmp_cb;
#endif

#ifndef OPENSSL_NO_ECDH
    if (cert->ecdh_tmp) {
        ret->ecdh_tmp = EC_KEY_dup(cert->ecdh_tmp);
        if (ret->ecdh_tmp == NULL) {
            SSLerr(SSL_F_SSL_CERT_DUP, ERR_R_EC_LIB);
            goto err;
        }
    }
    ret->ecdh_tmp_cb = cert->ecdh_tmp_cb;
    ret->ecdh_tmp_auto = cert->ecdh_tmp_auto;
#endif

    for (i = 0; i < SSL_PKEY_NUM; i++) {
        CERT_PKEY *cpk = cert->pkeys + i;
        CERT_PKEY *rpk = ret->pkeys + i;
        if (cpk->x509 != NULL) {
            rpk->x509 = cpk->x509;
            CRYPTO_add(&rpk->x509->references, 1, CRYPTO_LOCK_X509);
        }

        if (cpk->privatekey != NULL) {
            rpk->privatekey = cpk->privatekey;
            CRYPTO_add(&cpk->privatekey->references, 1, CRYPTO_LOCK_EVP_PKEY);
        }

        if (cpk->chain) {
            rpk->chain = X509_chain_up_ref(cpk->chain);
            if (!rpk->chain) {
                SSLerr(SSL_F_SSL_CERT_DUP, ERR_R_MALLOC_FAILURE);
                goto err;
            }
        }
        rpk->valid_flags = 0;
#ifndef OPENSSL_NO_TLSEXT
        if (cert->pkeys[i].serverinfo != NULL) {
            /* Just copy everything. */
            ret->pkeys[i].serverinfo =
                OPENSSL_malloc(cert->pkeys[i].serverinfo_length);
            if (ret->pkeys[i].serverinfo == NULL) {
                SSLerr(SSL_F_SSL_CERT_DUP, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            ret->pkeys[i].serverinfo_length =
                cert->pkeys[i].serverinfo_length;
            memcpy(ret->pkeys[i].serverinfo,
                   cert->pkeys[i].serverinfo,
                   cert->pkeys[i].serverinfo_length);
        }
#endif
    }

    /*
     * Set digests to defaults. NB: we don't copy existing values as they
     * will be set during handshake.
     */
    ssl_cert_set_default_md(ret);
    /* Peer sigalgs set to NULL as we get these from handshake too */
    ret->peer_sigalgs = NULL;
    ret->peer_sigalgslen = 0;
    /* Configured sigalgs however we copy across */

    if (cert->conf_sigalgs) {
        ret->conf_sigalgs = OPENSSL_malloc(cert->conf_sigalgslen);
        if (!ret->conf_sigalgs)
            goto err;
        memcpy(ret->conf_sigalgs, cert->conf_sigalgs, cert->conf_sigalgslen);
        ret->conf_sigalgslen = cert->conf_sigalgslen;
    } else
        ret->conf_sigalgs = NULL;

    if (cert->client_sigalgs) {
        ret->client_sigalgs = OPENSSL_malloc(cert->client_sigalgslen);
        if (!ret->client_sigalgs)
            goto err;
        memcpy(ret->client_sigalgs, cert->client_sigalgs,
               cert->client_sigalgslen);
        ret->client_sigalgslen = cert->client_sigalgslen;
    } else
        ret->client_sigalgs = NULL;
    /* Shared sigalgs also NULL */
    ret->shared_sigalgs = NULL;
    /* Copy any custom client certificate types */
    if (cert->ctypes) {
        ret->ctypes = OPENSSL_malloc(cert->ctype_num);
        if (!ret->ctypes)
            goto err;
        memcpy(ret->ctypes, cert->ctypes, cert->ctype_num);
        ret->ctype_num = cert->ctype_num;
    }

    ret->cert_flags = cert->cert_flags;

    ret->cert_cb = cert->cert_cb;
    ret->cert_cb_arg = cert->cert_cb_arg;

    if (cert->verify_store) {
        CRYPTO_add(&cert->verify_store->references, 1,
                   CRYPTO_LOCK_X509_STORE);
        ret->verify_store = cert->verify_store;
    }

    if (cert->chain_store) {
        CRYPTO_add(&cert->chain_store->references, 1, CRYPTO_LOCK_X509_STORE);
        ret->chain_store = cert->chain_store;
    }

    ret->ciphers_raw = NULL;

#ifndef OPENSSL_NO_TLSEXT
    if (!custom_exts_copy(&ret->cli_ext, &cert->cli_ext))
        goto err;
    if (!custom_exts_copy(&ret->srv_ext, &cert->srv_ext))
        goto err;
#endif

    return (ret);

 err:
#ifndef OPENSSL_NO_RSA
    if (ret->rsa_tmp != NULL)
        RSA_free(ret->rsa_tmp);
#endif
#ifndef OPENSSL_NO_DH
    if (ret->dh_tmp != NULL)
        DH_free(ret->dh_tmp);
#endif
#ifndef OPENSSL_NO_ECDH
    if (ret->ecdh_tmp != NULL)
        EC_KEY_free(ret->ecdh_tmp);
#endif

#ifndef OPENSSL_NO_TLSEXT
    custom_exts_free(&ret->cli_ext);
    custom_exts_free(&ret->srv_ext);
#endif

    ssl_cert_clear_certs(ret);
    OPENSSL_free(ret);

    return NULL;
}

/* Free up and clear all certificates and chains */

void ssl_cert_clear_certs(CERT *c)
{
    int i;
    if (c == NULL)
        return;
    for (i = 0; i < SSL_PKEY_NUM; i++) {
        CERT_PKEY *cpk = c->pkeys + i;
        if (cpk->x509) {
            X509_free(cpk->x509);
            cpk->x509 = NULL;
        }
        if (cpk->privatekey) {
            EVP_PKEY_free(cpk->privatekey);
            cpk->privatekey = NULL;
        }
        if (cpk->chain) {
            sk_X509_pop_free(cpk->chain, X509_free);
            cpk->chain = NULL;
        }
#ifndef OPENSSL_NO_TLSEXT
        if (cpk->serverinfo) {
            OPENSSL_free(cpk->serverinfo);
            cpk->serverinfo = NULL;
            cpk->serverinfo_length = 0;
        }
#endif
        /* Clear all flags apart from explicit sign */
        cpk->valid_flags &= CERT_PKEY_EXPLICIT_SIGN;
    }
}

void ssl_cert_free(CERT *c)
{
    int i;

    if (c == NULL)
        return;

    i = CRYPTO_add(&c->references, -1, CRYPTO_LOCK_SSL_CERT);
#ifdef REF_PRINT
    REF_PRINT("CERT", c);
#endif
    if (i > 0)
        return;
#ifdef REF_CHECK
    if (i < 0) {
        fprintf(stderr, "ssl_cert_free, bad reference count\n");
        abort();                /* ok */
    }
#endif

#ifndef OPENSSL_NO_RSA
    if (c->rsa_tmp)
        RSA_free(c->rsa_tmp);
#endif
#ifndef OPENSSL_NO_DH
    if (c->dh_tmp)
        DH_free(c->dh_tmp);
#endif
#ifndef OPENSSL_NO_ECDH
    if (c->ecdh_tmp)
        EC_KEY_free(c->ecdh_tmp);
#endif

    ssl_cert_clear_certs(c);
    if (c->peer_sigalgs)
        OPENSSL_free(c->peer_sigalgs);
    if (c->conf_sigalgs)
        OPENSSL_free(c->conf_sigalgs);
    if (c->client_sigalgs)
        OPENSSL_free(c->client_sigalgs);
    if (c->shared_sigalgs)
        OPENSSL_free(c->shared_sigalgs);
    if (c->ctypes)
        OPENSSL_free(c->ctypes);
    if (c->verify_store)
        X509_STORE_free(c->verify_store);
    if (c->chain_store)
        X509_STORE_free(c->chain_store);
    if (c->ciphers_raw)
        OPENSSL_free(c->ciphers_raw);
#ifndef OPENSSL_NO_TLSEXT
    custom_exts_free(&c->cli_ext);
    custom_exts_free(&c->srv_ext);
    if (c->alpn_proposed)
        OPENSSL_free(c->alpn_proposed);
#endif
    OPENSSL_free(c);
}

int ssl_cert_inst(CERT **o)
{
    /*
     * Create a CERT if there isn't already one (which cannot really happen,
     * as it is initially created in SSL_CTX_new; but the earlier code
     * usually allows for that one being non-existant, so we follow that
     * behaviour, as it might turn out that there actually is a reason for it
     * -- but I'm not sure that *all* of the existing code could cope with
     * s->cert being NULL, otherwise we could do without the initialization
     * in SSL_CTX_new).
     */

    if (o == NULL) {
        SSLerr(SSL_F_SSL_CERT_INST, ERR_R_PASSED_NULL_PARAMETER);
        return (0);
    }
    if (*o == NULL) {
        if ((*o = ssl_cert_new()) == NULL) {
            SSLerr(SSL_F_SSL_CERT_INST, ERR_R_MALLOC_FAILURE);
            return (0);
        }
    }
    return (1);
}

int ssl_cert_set0_chain(CERT *c, STACK_OF(X509) *chain)
{
    CERT_PKEY *cpk = c->key;
    if (!cpk)
        return 0;
    if (cpk->chain)
        sk_X509_pop_free(cpk->chain, X509_free);
    cpk->chain = chain;
    return 1;
}

int ssl_cert_set1_chain(CERT *c, STACK_OF(X509) *chain)
{
    STACK_OF(X509) *dchain;
    if (!chain)
        return ssl_cert_set0_chain(c, NULL);
    dchain = X509_chain_up_ref(chain);
    if (!dchain)
        return 0;
    if (!ssl_cert_set0_chain(c, dchain)) {
        sk_X509_pop_free(dchain, X509_free);
        return 0;
    }
    return 1;
}

int ssl_cert_add0_chain_cert(CERT *c, X509 *x)
{
    CERT_PKEY *cpk = c->key;
    if (!cpk)
        return 0;
    if (!cpk->chain)
        cpk->chain = sk_X509_new_null();
    if (!cpk->chain || !sk_X509_push(cpk->chain, x))
        return 0;
    return 1;
}

int ssl_cert_add1_chain_cert(CERT *c, X509 *x)
{
    if (!ssl_cert_add0_chain_cert(c, x))
        return 0;
    CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509);
    return 1;
}

int ssl_cert_select_current(CERT *c, X509 *x)
{
    int i;
    if (x == NULL)
        return 0;
    for (i = 0; i < SSL_PKEY_NUM; i++) {
        CERT_PKEY *cpk = c->pkeys + i;
        if (cpk->x509 == x && cpk->privatekey) {
            c->key = cpk;
            return 1;
        }
    }

    for (i = 0; i < SSL_PKEY_NUM; i++) {
        CERT_PKEY *cpk = c->pkeys + i;
        if (cpk->privatekey && cpk->x509 && !X509_cmp(cpk->x509, x)) {
            c->key = cpk;
            return 1;
        }
    }
    return 0;
}

int ssl_cert_set_current(CERT *c, long op)
{
    int i, idx;
    if (!c)
        return 0;
    if (op == SSL_CERT_SET_FIRST)
        idx = 0;
    else if (op == SSL_CERT_SET_NEXT) {
        idx = (int)(c->key - c->pkeys + 1);
        if (idx >= SSL_PKEY_NUM)
            return 0;
    } else
        return 0;
    for (i = idx; i < SSL_PKEY_NUM; i++) {
        CERT_PKEY *cpk = c->pkeys + i;
        if (cpk->x509 && cpk->privatekey) {
            c->key = cpk;
            return 1;
        }
    }
    return 0;
}

void ssl_cert_set_cert_cb(CERT *c, int (*cb) (SSL *ssl, void *arg), void *arg)
{
    c->cert_cb = cb;
    c->cert_cb_arg = arg;
}

SESS_CERT *ssl_sess_cert_new(void)
{
    SESS_CERT *ret;

    ret = OPENSSL_malloc(sizeof(*ret));
    if (ret == NULL) {
        SSLerr(SSL_F_SSL_SESS_CERT_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    memset(ret, 0, sizeof(*ret));
    ret->peer_key = &(ret->peer_pkeys[SSL_PKEY_RSA_ENC]);
    ret->references = 1;

    return ret;
}

void ssl_sess_cert_free(SESS_CERT *sc)
{
    int i;

    if (sc == NULL)
        return;

    i = CRYPTO_add(&sc->references, -1, CRYPTO_LOCK_SSL_SESS_CERT);
#ifdef REF_PRINT
    REF_PRINT("SESS_CERT", sc);
#endif
    if (i > 0)
        return;
#ifdef REF_CHECK
    if (i < 0) {
        fprintf(stderr, "ssl_sess_cert_free, bad reference count\n");
        abort();                /* ok */
    }
#endif

    /* i == 0 */
    if (sc->cert_chain != NULL)
        sk_X509_pop_free(sc->cert_chain, X509_free);
    for (i = 0; i < SSL_PKEY_NUM; i++) {
        if (sc->peer_pkeys[i].x509 != NULL)
            X509_free(sc->peer_pkeys[i].x509);
#if 0                           /* We don't have the peer's private key.
                                 * These lines are just * here as a reminder
                                 * that we're still using a
                                 * not-quite-appropriate * data structure. */
        if (sc->peer_pkeys[i].privatekey != NULL)
            EVP_PKEY_free(sc->peer_pkeys[i].privatekey);
#endif
    }

#ifndef OPENSSL_NO_RSA
    if (sc->peer_rsa_tmp != NULL)
        RSA_free(sc->peer_rsa_tmp);
#endif
#ifndef OPENSSL_NO_DH
    if (sc->peer_dh_tmp != NULL)
        DH_free(sc->peer_dh_tmp);
#endif
#ifndef OPENSSL_NO_ECDH
    if (sc->peer_ecdh_tmp != NULL)
        EC_KEY_free(sc->peer_ecdh_tmp);
#endif

    OPENSSL_free(sc);
}

int ssl_set_peer_cert_type(SESS_CERT *sc, int type)
{
    sc->peer_cert_type = type;
    return (1);
}

int ssl_verify_cert_chain(SSL *s, STACK_OF(X509) *sk)
{
    X509 *x;
    int i;
    X509_STORE *verify_store;
    X509_STORE_CTX ctx;

    if (s->cert->verify_store)
        verify_store = s->cert->verify_store;
    else
        verify_store = s->ctx->cert_store;

    if ((sk == NULL) || (sk_X509_num(sk) == 0))
        return (0);

    x = sk_X509_value(sk, 0);
    if (!X509_STORE_CTX_init(&ctx, verify_store, x, sk)) {
        SSLerr(SSL_F_SSL_VERIFY_CERT_CHAIN, ERR_R_X509_LIB);
        return (0);
    }
    /* Set suite B flags if needed */
    X509_STORE_CTX_set_flags(&ctx, tls1_suiteb(s));
#if 0
    if (SSL_get_verify_depth(s) >= 0)
        X509_STORE_CTX_set_depth(&ctx, SSL_get_verify_depth(s));
#endif
    X509_STORE_CTX_set_ex_data(&ctx, SSL_get_ex_data_X509_STORE_CTX_idx(), s);

    /*
     * We need to inherit the verify parameters. These can be determined by
     * the context: if its a server it will verify SSL client certificates or
     * vice versa.
     */

    X509_STORE_CTX_set_default(&ctx, s->server ? "ssl_client" : "ssl_server");
    /*
     * Anything non-default in "param" should overwrite anything in the ctx.
     */
    X509_VERIFY_PARAM_set1(X509_STORE_CTX_get0_param(&ctx), s->param);

    if (s->verify_callback)
        X509_STORE_CTX_set_verify_cb(&ctx, s->verify_callback);

    if (s->ctx->app_verify_callback != NULL)
#if 1                           /* new with OpenSSL 0.9.7 */
        i = s->ctx->app_verify_callback(&ctx, s->ctx->app_verify_arg);
#else
        i = s->ctx->app_verify_callback(&ctx); /* should pass app_verify_arg */
#endif
    else {
#ifndef OPENSSL_NO_X509_VERIFY
        i = X509_verify_cert(&ctx);
#else
        i = 0;
        ctx.error = X509_V_ERR_APPLICATION_VERIFICATION;
        SSLerr(SSL_F_SSL_VERIFY_CERT_CHAIN, SSL_R_NO_VERIFY_CALLBACK);
#endif
    }

    s->verify_result = ctx.error;
    X509_STORE_CTX_cleanup(&ctx);

    return (i);
}

static void set_client_CA_list(STACK_OF(X509_NAME) **ca_list,
                               STACK_OF(X509_NAME) *name_list)
{
    if (*ca_list != NULL)
        sk_X509_NAME_pop_free(*ca_list, X509_NAME_free);

    *ca_list = name_list;
}

STACK_OF(X509_NAME) *SSL_dup_CA_list(STACK_OF(X509_NAME) *sk)
{
    int i;
    STACK_OF(X509_NAME) *ret;
    X509_NAME *name;

    ret = sk_X509_NAME_new_null();
    for (i = 0; i < sk_X509_NAME_num(sk); i++) {
        name = X509_NAME_dup(sk_X509_NAME_value(sk, i));
        if ((name == NULL) || !sk_X509_NAME_push(ret, name)) {
            sk_X509_NAME_pop_free(ret, X509_NAME_free);
            return (NULL);
        }
    }
    return (ret);
}

void SSL_set_client_CA_list(SSL *s, STACK_OF(X509_NAME) *name_list)
{
    set_client_CA_list(&(s->client_CA), name_list);
}

void SSL_CTX_set_client_CA_list(SSL_CTX *ctx, STACK_OF(X509_NAME) *name_list)
{
    set_client_CA_list(&(ctx->client_CA), name_list);
}

STACK_OF(X509_NAME) *SSL_CTX_get_client_CA_list(const SSL_CTX *ctx)
{
    return (ctx->client_CA);
}

STACK_OF(X509_NAME) *SSL_get_client_CA_list(const SSL *s)
{
    if (s->type == SSL_ST_CONNECT) { /* we are in the client */
        if (((s->version >> 8) == SSL3_VERSION_MAJOR) && (s->s3 != NULL))
            return (s->s3->tmp.ca_names);
        else
            return (NULL);
    } else {
        if (s->client_CA != NULL)
            return (s->client_CA);
        else
            return (s->ctx->client_CA);
    }
}

static int add_client_CA(STACK_OF(X509_NAME) **sk, X509 *x)
{
    X509_NAME *name;

    if (x == NULL)
        return (0);
    if ((*sk == NULL) && ((*sk = sk_X509_NAME_new_null()) == NULL))
        return (0);

    if ((name = X509_NAME_dup(X509_get_subject_name(x))) == NULL)
        return (0);

    if (!sk_X509_NAME_push(*sk, name)) {
        X509_NAME_free(name);
        return (0);
    }
    return (1);
}

int SSL_add_client_CA(SSL *ssl, X509 *x)
{
    return (add_client_CA(&(ssl->client_CA), x));
}

int SSL_CTX_add_client_CA(SSL_CTX *ctx, X509 *x)
{
    return (add_client_CA(&(ctx->client_CA), x));
}

static int xname_cmp(const X509_NAME *const *a, const X509_NAME *const *b)
{
    return (X509_NAME_cmp(*a, *b));
}

#ifndef OPENSSL_NO_STDIO
/**
 * Load CA certs from a file into a ::STACK. Note that it is somewhat misnamed;
 * it doesn't really have anything to do with clients (except that a common use
 * for a stack of CAs is to send it to the client). Actually, it doesn't have
 * much to do with CAs, either, since it will load any old cert.
 * \param file the file containing one or more certs.
 * \return a ::STACK containing the certs.
 */
STACK_OF(X509_NAME) *SSL_load_client_CA_file(const char *file)
{
    BIO *in;
    X509 *x = NULL;
    X509_NAME *xn = NULL;
    STACK_OF(X509_NAME) *ret = NULL, *sk;

    sk = sk_X509_NAME_new(xname_cmp);

    in = BIO_new(BIO_s_file_internal());

    if ((sk == NULL) || (in == NULL)) {
        SSLerr(SSL_F_SSL_LOAD_CLIENT_CA_FILE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!BIO_read_filename(in, file))
        goto err;

    for (;;) {
        if (PEM_read_bio_X509(in, &x, NULL, NULL) == NULL)
            break;
        if (ret == NULL) {
            ret = sk_X509_NAME_new_null();
            if (ret == NULL) {
                SSLerr(SSL_F_SSL_LOAD_CLIENT_CA_FILE, ERR_R_MALLOC_FAILURE);
                goto err;
            }
        }
        if ((xn = X509_get_subject_name(x)) == NULL)
            goto err;
        /* check for duplicates */
        xn = X509_NAME_dup(xn);
        if (xn == NULL)
            goto err;
        if (sk_X509_NAME_find(sk, xn) >= 0)
            X509_NAME_free(xn);
        else {
            sk_X509_NAME_push(sk, xn);
            sk_X509_NAME_push(ret, xn);
        }
    }

    if (0) {
 err:
        if (ret != NULL)
            sk_X509_NAME_pop_free(ret, X509_NAME_free);
        ret = NULL;
    }
    if (sk != NULL)
        sk_X509_NAME_free(sk);
    if (in != NULL)
        BIO_free(in);
    if (x != NULL)
        X509_free(x);
    if (ret != NULL)
        ERR_clear_error();
    return (ret);
}
#endif

/**
 * Add a file of certs to a stack.
 * \param stack the stack to add to.
 * \param file the file to add from. All certs in this file that are not
 * already in the stack will be added.
 * \return 1 for success, 0 for failure. Note that in the case of failure some
 * certs may have been added to \c stack.
 */

int SSL_add_file_cert_subjects_to_stack(STACK_OF(X509_NAME) *stack,
                                        const char *file)
{
    BIO *in;
    X509 *x = NULL;
    X509_NAME *xn = NULL;
    int ret = 1;
    int (*oldcmp) (const X509_NAME *const *a, const X509_NAME *const *b);

    oldcmp = sk_X509_NAME_set_cmp_func(stack, xname_cmp);

    in = BIO_new(BIO_s_file_internal());

    if (in == NULL) {
        SSLerr(SSL_F_SSL_ADD_FILE_CERT_SUBJECTS_TO_STACK,
               ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!BIO_read_filename(in, file))
        goto err;

    for (;;) {
        if (PEM_read_bio_X509(in, &x, NULL, NULL) == NULL)
            break;
        if ((xn = X509_get_subject_name(x)) == NULL)
            goto err;
        xn = X509_NAME_dup(xn);
        if (xn == NULL)
            goto err;
        if (sk_X509_NAME_find(stack, xn) >= 0)
            X509_NAME_free(xn);
        else
            sk_X509_NAME_push(stack, xn);
    }

    ERR_clear_error();

    if (0) {
 err:
        ret = 0;
    }
    if (in != NULL)
        BIO_free(in);
    if (x != NULL)
        X509_free(x);

    (void)sk_X509_NAME_set_cmp_func(stack, oldcmp);

    return ret;
}

/**
 * Add a directory of certs to a stack.
 * \param stack the stack to append to.
 * \param dir the directory to append from. All files in this directory will be
 * examined as potential certs. Any that are acceptable to
 * SSL_add_dir_cert_subjects_to_stack() that are not already in the stack will be
 * included.
 * \return 1 for success, 0 for failure. Note that in the case of failure some
 * certs may have been added to \c stack.
 */

int SSL_add_dir_cert_subjects_to_stack(STACK_OF(X509_NAME) *stack,
                                       const char *dir)
{
    OPENSSL_DIR_CTX *d = NULL;
    const char *filename;
    int ret = 0;

    CRYPTO_w_lock(CRYPTO_LOCK_READDIR);

    /* Note that a side effect is that the CAs will be sorted by name */

    while ((filename = OPENSSL_DIR_read(&d, dir))) {
        char buf[1024];
        int r;

        if (strlen(dir) + strlen(filename) + 2 > sizeof(buf)) {
            SSLerr(SSL_F_SSL_ADD_DIR_CERT_SUBJECTS_TO_STACK,
                   SSL_R_PATH_TOO_LONG);
            goto err;
        }
#ifdef OPENSSL_SYS_VMS
        r = BIO_snprintf(buf, sizeof(buf), "%s%s", dir, filename);
#else
        r = BIO_snprintf(buf, sizeof(buf), "%s/%s", dir, filename);
#endif
        if (r <= 0 || r >= (int)sizeof(buf))
            goto err;
        if (!SSL_add_file_cert_subjects_to_stack(stack, buf))
            goto err;
    }

    if (errno) {
        SYSerr(SYS_F_OPENDIR, get_last_sys_error());
        ERR_add_error_data(3, "OPENSSL_DIR_read(&ctx, '", dir, "')");
        SSLerr(SSL_F_SSL_ADD_DIR_CERT_SUBJECTS_TO_STACK, ERR_R_SYS_LIB);
        goto err;
    }

    ret = 1;

 err:
    if (d)
        OPENSSL_DIR_end(&d);
    CRYPTO_w_unlock(CRYPTO_LOCK_READDIR);
    return ret;
}

/* Add a certificate to a BUF_MEM structure */

static int ssl_add_cert_to_buf(BUF_MEM *buf, unsigned long *l, X509 *x)
{
    int n;
    unsigned char *p;

    n = i2d_X509(x, NULL);
    if (n < 0 || !BUF_MEM_grow_clean(buf, (int)(n + (*l) + 3))) {
        SSLerr(SSL_F_SSL_ADD_CERT_TO_BUF, ERR_R_BUF_LIB);
        return 0;
    }
    p = (unsigned char *)&(buf->data[*l]);
    l2n3(n, p);
    n = i2d_X509(x, &p);
    if (n < 0) {
        /* Shouldn't happen */
        SSLerr(SSL_F_SSL_ADD_CERT_TO_BUF, ERR_R_BUF_LIB);
        return 0;
    }
    *l += n + 3;

    return 1;
}

/* Add certificate chain to internal SSL BUF_MEM strcuture */
int ssl_add_cert_chain(SSL *s, CERT_PKEY *cpk, unsigned long *l)
{
    BUF_MEM *buf = s->init_buf;
    int no_chain;
    int i;

    X509 *x;
    STACK_OF(X509) *extra_certs;
    X509_STORE *chain_store;

    if (cpk)
        x = cpk->x509;
    else
        x = NULL;

    if (s->cert->chain_store)
        chain_store = s->cert->chain_store;
    else
        chain_store = s->ctx->cert_store;

    /*
     * If we have a certificate specific chain use it, else use parent ctx.
     */
    if (cpk && cpk->chain)
        extra_certs = cpk->chain;
    else
        extra_certs = s->ctx->extra_certs;

    if ((s->mode & SSL_MODE_NO_AUTO_CHAIN) || extra_certs)
        no_chain = 1;
    else
        no_chain = 0;

    /* TLSv1 sends a chain with nothing in it, instead of an alert */
    if (!BUF_MEM_grow_clean(buf, 10)) {
        SSLerr(SSL_F_SSL_ADD_CERT_CHAIN, ERR_R_BUF_LIB);
        return 0;
    }
    if (x != NULL) {
        if (no_chain) {
            if (!ssl_add_cert_to_buf(buf, l, x))
                return 0;
        } else {
            X509_STORE_CTX xs_ctx;

            if (!X509_STORE_CTX_init(&xs_ctx, chain_store, x, NULL)) {
                SSLerr(SSL_F_SSL_ADD_CERT_CHAIN, ERR_R_X509_LIB);
                return (0);
            }
            X509_verify_cert(&xs_ctx);
            /* Don't leave errors in the queue */
            ERR_clear_error();
            for (i = 0; i < sk_X509_num(xs_ctx.chain); i++) {
                x = sk_X509_value(xs_ctx.chain, i);

                if (!ssl_add_cert_to_buf(buf, l, x)) {
                    X509_STORE_CTX_cleanup(&xs_ctx);
                    return 0;
                }
            }
            X509_STORE_CTX_cleanup(&xs_ctx);
        }
    }
    for (i = 0; i < sk_X509_num(extra_certs); i++) {
        x = sk_X509_value(extra_certs, i);
        if (!ssl_add_cert_to_buf(buf, l, x))
            return 0;
    }

    return 1;
}

/* Build a certificate chain for current certificate */
int ssl_build_cert_chain(CERT *c, X509_STORE *chain_store, int flags)
{
    CERT_PKEY *cpk = c->key;
    X509_STORE_CTX xs_ctx;
    STACK_OF(X509) *chain = NULL, *untrusted = NULL;
    X509 *x;
    int i, rv = 0;
    unsigned long error;

    if (!cpk->x509) {
        SSLerr(SSL_F_SSL_BUILD_CERT_CHAIN, SSL_R_NO_CERTIFICATE_SET);
        goto err;
    }
    /* Rearranging and check the chain: add everything to a store */
    if (flags & SSL_BUILD_CHAIN_FLAG_CHECK) {
        chain_store = X509_STORE_new();
        if (!chain_store)
            goto err;
        for (i = 0; i < sk_X509_num(cpk->chain); i++) {
            x = sk_X509_value(cpk->chain, i);
            if (!X509_STORE_add_cert(chain_store, x)) {
                error = ERR_peek_last_error();
                if (ERR_GET_LIB(error) != ERR_LIB_X509 ||
                    ERR_GET_REASON(error) !=
                    X509_R_CERT_ALREADY_IN_HASH_TABLE)
                    goto err;
                ERR_clear_error();
            }
        }
        /* Add EE cert too: it might be self signed */
        if (!X509_STORE_add_cert(chain_store, cpk->x509)) {
            error = ERR_peek_last_error();
            if (ERR_GET_LIB(error) != ERR_LIB_X509 ||
                ERR_GET_REASON(error) != X509_R_CERT_ALREADY_IN_HASH_TABLE)
                goto err;
            ERR_clear_error();
        }
    } else {
        if (c->chain_store)
            chain_store = c->chain_store;

        if (flags & SSL_BUILD_CHAIN_FLAG_UNTRUSTED)
            untrusted = cpk->chain;
    }

    if (!X509_STORE_CTX_init(&xs_ctx, chain_store, cpk->x509, untrusted)) {
        SSLerr(SSL_F_SSL_BUILD_CERT_CHAIN, ERR_R_X509_LIB);
        goto err;
    }
    /* Set suite B flags if needed */
    X509_STORE_CTX_set_flags(&xs_ctx,
                             c->cert_flags & SSL_CERT_FLAG_SUITEB_128_LOS);

    i = X509_verify_cert(&xs_ctx);
    if (i <= 0 && flags & SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR) {
        if (flags & SSL_BUILD_CHAIN_FLAG_CLEAR_ERROR)
            ERR_clear_error();
        i = 1;
        rv = 2;
    }
    if (i > 0)
        chain = X509_STORE_CTX_get1_chain(&xs_ctx);
    if (i <= 0) {
        SSLerr(SSL_F_SSL_BUILD_CERT_CHAIN, SSL_R_CERTIFICATE_VERIFY_FAILED);
        i = X509_STORE_CTX_get_error(&xs_ctx);
        ERR_add_error_data(2, "Verify error:",
                           X509_verify_cert_error_string(i));

        X509_STORE_CTX_cleanup(&xs_ctx);
        goto err;
    }
    X509_STORE_CTX_cleanup(&xs_ctx);
    if (cpk->chain)
        sk_X509_pop_free(cpk->chain, X509_free);
    /* Remove EE certificate from chain */
    x = sk_X509_shift(chain);
    X509_free(x);
    if (flags & SSL_BUILD_CHAIN_FLAG_NO_ROOT) {
        if (sk_X509_num(chain) > 0) {
            /* See if last cert is self signed */
            x = sk_X509_value(chain, sk_X509_num(chain) - 1);
            X509_check_purpose(x, -1, 0);
            if (x->ex_flags & EXFLAG_SS) {
                x = sk_X509_pop(chain);
                X509_free(x);
            }
        }
    }
    cpk->chain = chain;
    if (rv == 0)
        rv = 1;
 err:
    if (flags & SSL_BUILD_CHAIN_FLAG_CHECK)
        X509_STORE_free(chain_store);

    return rv;
}

int ssl_cert_set_cert_store(CERT *c, X509_STORE *store, int chain, int ref)
{
    X509_STORE **pstore;
    if (chain)
        pstore = &c->chain_store;
    else
        pstore = &c->verify_store;
    if (*pstore)
        X509_STORE_free(*pstore);
    *pstore = store;
    if (ref && store)
        CRYPTO_add(&store->references, 1, CRYPTO_LOCK_X509_STORE);
    return 1;
}
/* ssl/ssl_ciph.c */
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
 * ECC cipher suite support in OpenSSL originally developed by
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
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
#ifndef OPENSSL_NO_COMP
# include "comp.h"
#endif
#ifndef OPENSSL_NO_ENGINE
# include "engine.h"
#endif
// #include "ssl_locl.h"

#define SSL_ENC_DES_IDX         0
#define SSL_ENC_3DES_IDX        1
#define SSL_ENC_RC4_IDX         2
#define SSL_ENC_RC2_IDX         3
#define SSL_ENC_IDEA_IDX        4
#define SSL_ENC_NULL_IDX        5
#define SSL_ENC_AES128_IDX      6
#define SSL_ENC_AES256_IDX      7
#define SSL_ENC_CAMELLIA128_IDX 8
#define SSL_ENC_CAMELLIA256_IDX 9
#define SSL_ENC_GOST89_IDX      10
#define SSL_ENC_SEED_IDX        11
#define SSL_ENC_AES128GCM_IDX   12
#define SSL_ENC_AES256GCM_IDX   13
#define SSL_ENC_NUM_IDX         14

static const EVP_CIPHER *ssl_cipher_methods[SSL_ENC_NUM_IDX] = {
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL
};

#define SSL_COMP_NULL_IDX       0
#define SSL_COMP_ZLIB_IDX       1
#define SSL_COMP_NUM_IDX        2

static STACK_OF(SSL_COMP) *ssl_comp_methods = NULL;

#define SSL_MD_MD5_IDX  0
#define SSL_MD_SHA1_IDX 1
#define SSL_MD_GOST94_IDX 2
#define SSL_MD_GOST89MAC_IDX 3
#define SSL_MD_SHA256_IDX 4
#define SSL_MD_SHA384_IDX 5
/*
 * Constant SSL_MAX_DIGEST equal to size of digests array should be defined
 * in the ssl_locl.h
 */
#define SSL_MD_NUM_IDX  SSL_MAX_DIGEST
static const EVP_MD *ssl_digest_methods[SSL_MD_NUM_IDX] = {
    NULL, NULL, NULL, NULL, NULL, NULL
};

/*
 * PKEY_TYPE for GOST89MAC is known in advance, but, because implementation
 * is engine-provided, we'll fill it only if corresponding EVP_PKEY_METHOD is
 * found
 */
static int ssl_mac_pkey_id[SSL_MD_NUM_IDX] = {
    EVP_PKEY_HMAC, EVP_PKEY_HMAC, EVP_PKEY_HMAC, NID_undef,
    EVP_PKEY_HMAC, EVP_PKEY_HMAC
};

static int ssl_mac_secret_size[SSL_MD_NUM_IDX] = {
    0, 0, 0, 0, 0, 0
};

static int ssl_handshake_digest_flag[SSL_MD_NUM_IDX] = {
    SSL_HANDSHAKE_MAC_MD5, SSL_HANDSHAKE_MAC_SHA,
    SSL_HANDSHAKE_MAC_GOST94, 0, SSL_HANDSHAKE_MAC_SHA256,
    SSL_HANDSHAKE_MAC_SHA384
};

#define CIPHER_ADD      1
#define CIPHER_KILL     2
#define CIPHER_DEL      3
#define CIPHER_ORD      4
#define CIPHER_SPECIAL  5

typedef struct cipher_order_st {
    const SSL_CIPHER *cipher;
    int active;
    int dead;
    struct cipher_order_st *next, *prev;
} CIPHER_ORDER;

static const SSL_CIPHER cipher_aliases[] = {
    /* "ALL" doesn't include eNULL (must be specifically enabled) */
    {0, SSL_TXT_ALL, 0, 0, 0, ~SSL_eNULL, 0, 0, 0, 0, 0, 0},
    /* "COMPLEMENTOFALL" */
    {0, SSL_TXT_CMPALL, 0, 0, 0, SSL_eNULL, 0, 0, 0, 0, 0, 0},

    /*
     * "COMPLEMENTOFDEFAULT" (does *not* include ciphersuites not found in
     * ALL!)
     */
    {0, SSL_TXT_CMPDEF, 0, 0, 0, 0, 0, 0, SSL_NOT_DEFAULT, 0, 0, 0},

    /*
     * key exchange aliases (some of those using only a single bit here
     * combine multiple key exchange algs according to the RFCs, e.g. kEDH
     * combines DHE_DSS and DHE_RSA)
     */
    {0, SSL_TXT_kRSA, 0, SSL_kRSA, 0, 0, 0, 0, 0, 0, 0, 0},

    {0, SSL_TXT_kDHr, 0, SSL_kDHr, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kDHd, 0, SSL_kDHd, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kDH, 0, SSL_kDHr | SSL_kDHd, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kEDH, 0, SSL_kEDH, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kDHE, 0, SSL_kEDH, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_DH, 0, SSL_kDHr | SSL_kDHd | SSL_kEDH, 0, 0, 0, 0, 0, 0, 0,
     0},

    {0, SSL_TXT_kKRB5, 0, SSL_kKRB5, 0, 0, 0, 0, 0, 0, 0, 0},

    {0, SSL_TXT_kECDHr, 0, SSL_kECDHr, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kECDHe, 0, SSL_kECDHe, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kECDH, 0, SSL_kECDHr | SSL_kECDHe, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kEECDH, 0, SSL_kEECDH, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kECDHE, 0, SSL_kEECDH, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_ECDH, 0, SSL_kECDHr | SSL_kECDHe | SSL_kEECDH, 0, 0, 0, 0, 0,
     0, 0, 0},

    {0, SSL_TXT_kPSK, 0, SSL_kPSK, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kSRP, 0, SSL_kSRP, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kGOST, 0, SSL_kGOST, 0, 0, 0, 0, 0, 0, 0, 0},

    /* server authentication aliases */
    {0, SSL_TXT_aRSA, 0, 0, SSL_aRSA, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aDSS, 0, 0, SSL_aDSS, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_DSS, 0, 0, SSL_aDSS, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aKRB5, 0, 0, SSL_aKRB5, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aNULL, 0, 0, SSL_aNULL, 0, 0, 0, 0, 0, 0, 0},
    /* no such ciphersuites supported! */
    {0, SSL_TXT_aDH, 0, 0, SSL_aDH, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aECDH, 0, 0, SSL_aECDH, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aECDSA, 0, 0, SSL_aECDSA, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_ECDSA, 0, 0, SSL_aECDSA, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aPSK, 0, 0, SSL_aPSK, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aGOST94, 0, 0, SSL_aGOST94, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aGOST01, 0, 0, SSL_aGOST01, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aGOST, 0, 0, SSL_aGOST94 | SSL_aGOST01, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aSRP, 0, 0, SSL_aSRP, 0, 0, 0, 0, 0, 0, 0},

    /* aliases combining key exchange and server authentication */
    {0, SSL_TXT_EDH, 0, SSL_kEDH, ~SSL_aNULL, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_DHE, 0, SSL_kEDH, ~SSL_aNULL, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_EECDH, 0, SSL_kEECDH, ~SSL_aNULL, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_ECDHE, 0, SSL_kEECDH, ~SSL_aNULL, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_NULL, 0, 0, 0, SSL_eNULL, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_KRB5, 0, SSL_kKRB5, SSL_aKRB5, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_RSA, 0, SSL_kRSA, SSL_aRSA, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_ADH, 0, SSL_kEDH, SSL_aNULL, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_AECDH, 0, SSL_kEECDH, SSL_aNULL, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_PSK, 0, SSL_kPSK, SSL_aPSK, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_SRP, 0, SSL_kSRP, 0, 0, 0, 0, 0, 0, 0, 0},

    /* symmetric encryption aliases */
    {0, SSL_TXT_DES, 0, 0, 0, SSL_DES, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_3DES, 0, 0, 0, SSL_3DES, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_RC4, 0, 0, 0, SSL_RC4, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_RC2, 0, 0, 0, SSL_RC2, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_IDEA, 0, 0, 0, SSL_IDEA, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_SEED, 0, 0, 0, SSL_SEED, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_eNULL, 0, 0, 0, SSL_eNULL, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_AES128, 0, 0, 0, SSL_AES128 | SSL_AES128GCM, 0, 0, 0, 0, 0,
     0},
    {0, SSL_TXT_AES256, 0, 0, 0, SSL_AES256 | SSL_AES256GCM, 0, 0, 0, 0, 0,
     0},
    {0, SSL_TXT_AES, 0, 0, 0, SSL_AES, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_AES_GCM, 0, 0, 0, SSL_AES128GCM | SSL_AES256GCM, 0, 0, 0, 0,
     0, 0},
    {0, SSL_TXT_CAMELLIA128, 0, 0, 0, SSL_CAMELLIA128, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_CAMELLIA256, 0, 0, 0, SSL_CAMELLIA256, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_CAMELLIA, 0, 0, 0, SSL_CAMELLIA128 | SSL_CAMELLIA256, 0, 0, 0,
     0, 0, 0},

    /* MAC aliases */
    {0, SSL_TXT_MD5, 0, 0, 0, 0, SSL_MD5, 0, 0, 0, 0, 0},
    {0, SSL_TXT_SHA1, 0, 0, 0, 0, SSL_SHA1, 0, 0, 0, 0, 0},
    {0, SSL_TXT_SHA, 0, 0, 0, 0, SSL_SHA1, 0, 0, 0, 0, 0},
    {0, SSL_TXT_GOST94, 0, 0, 0, 0, SSL_GOST94, 0, 0, 0, 0, 0},
    {0, SSL_TXT_GOST89MAC, 0, 0, 0, 0, SSL_GOST89MAC, 0, 0, 0, 0, 0},
    {0, SSL_TXT_SHA256, 0, 0, 0, 0, SSL_SHA256, 0, 0, 0, 0, 0},
    {0, SSL_TXT_SHA384, 0, 0, 0, 0, SSL_SHA384, 0, 0, 0, 0, 0},

    /* protocol version aliases */
    {0, SSL_TXT_SSLV2, 0, 0, 0, 0, 0, SSL_SSLV2, 0, 0, 0, 0},
    {0, SSL_TXT_SSLV3, 0, 0, 0, 0, 0, SSL_SSLV3, 0, 0, 0, 0},
    {0, SSL_TXT_TLSV1, 0, 0, 0, 0, 0, SSL_TLSV1, 0, 0, 0, 0},
    {0, SSL_TXT_TLSV1_2, 0, 0, 0, 0, 0, SSL_TLSV1_2, 0, 0, 0, 0},

    /* export flag */
    {0, SSL_TXT_EXP, 0, 0, 0, 0, 0, 0, SSL_EXPORT, 0, 0, 0},
    {0, SSL_TXT_EXPORT, 0, 0, 0, 0, 0, 0, SSL_EXPORT, 0, 0, 0},

    /* strength classes */
    {0, SSL_TXT_EXP40, 0, 0, 0, 0, 0, 0, SSL_EXP40, 0, 0, 0},
    {0, SSL_TXT_EXP56, 0, 0, 0, 0, 0, 0, SSL_EXP56, 0, 0, 0},
    {0, SSL_TXT_LOW, 0, 0, 0, 0, 0, 0, SSL_LOW, 0, 0, 0},
    {0, SSL_TXT_MEDIUM, 0, 0, 0, 0, 0, 0, SSL_MEDIUM, 0, 0, 0},
    {0, SSL_TXT_HIGH, 0, 0, 0, 0, 0, 0, SSL_HIGH, 0, 0, 0},
    /* FIPS 140-2 approved ciphersuite */
    {0, SSL_TXT_FIPS, 0, 0, 0, ~SSL_eNULL, 0, 0, SSL_FIPS, 0, 0, 0},
    /* "DHE-" aliases to "EDH-" labels (for forward compatibility) */
    {0, SSL3_TXT_DHE_DSS_DES_40_CBC_SHA, 0,
     SSL_kDHE, SSL_aDSS, SSL_DES, SSL_SHA1, SSL_SSLV3, SSL_EXPORT | SSL_EXP40,
     0, 0, 0,},
    {0, SSL3_TXT_DHE_DSS_DES_64_CBC_SHA, 0,
     SSL_kDHE, SSL_aDSS, SSL_DES, SSL_SHA1, SSL_SSLV3, SSL_NOT_EXP | SSL_LOW,
     0, 0, 0,},
    {0, SSL3_TXT_DHE_DSS_DES_192_CBC3_SHA, 0,
     SSL_kDHE, SSL_aDSS, SSL_3DES, SSL_SHA1, SSL_SSLV3,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS, 0, 0, 0,},
    {0, SSL3_TXT_DHE_RSA_DES_40_CBC_SHA, 0,
     SSL_kDHE, SSL_aRSA, SSL_DES, SSL_SHA1, SSL_SSLV3, SSL_EXPORT | SSL_EXP40,
     0, 0, 0,},
    {0, SSL3_TXT_DHE_RSA_DES_64_CBC_SHA, 0,
     SSL_kDHE, SSL_aRSA, SSL_DES, SSL_SHA1, SSL_SSLV3, SSL_NOT_EXP | SSL_LOW,
     0, 0, 0,},
    {0, SSL3_TXT_DHE_RSA_DES_192_CBC3_SHA, 0,
     SSL_kDHE, SSL_aRSA, SSL_3DES, SSL_SHA1, SSL_SSLV3,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS, 0, 0, 0,},
};

/*
 * Search for public key algorithm with given name and return its pkey_id if
 * it is available. Otherwise return 0
 */
#ifdef OPENSSL_NO_ENGINE

static int get_optional_pkey_id(const char *pkey_name)
{
    const EVP_PKEY_ASN1_METHOD *ameth;
    int pkey_id = 0;
    ameth = EVP_PKEY_asn1_find_str(NULL, pkey_name, -1);
    if (ameth && EVP_PKEY_asn1_get0_info(&pkey_id, NULL, NULL, NULL, NULL,
                                         ameth) > 0) {
        return pkey_id;
    }
    return 0;
}

#else

static int get_optional_pkey_id(const char *pkey_name)
{
    const EVP_PKEY_ASN1_METHOD *ameth;
    ENGINE *tmpeng = NULL;
    int pkey_id = 0;
    ameth = EVP_PKEY_asn1_find_str(&tmpeng, pkey_name, -1);
    if (ameth) {
        if (EVP_PKEY_asn1_get0_info(&pkey_id, NULL, NULL, NULL, NULL,
                                    ameth) <= 0)
            pkey_id = 0;
    }
    if (tmpeng)
        ENGINE_finish(tmpeng);
    return pkey_id;
}

#endif

void ssl_load_ciphers(void)
{
    ssl_cipher_methods[SSL_ENC_DES_IDX] = EVP_get_cipherbyname(SN_des_cbc);
    ssl_cipher_methods[SSL_ENC_3DES_IDX] =
        EVP_get_cipherbyname(SN_des_ede3_cbc);
    ssl_cipher_methods[SSL_ENC_RC4_IDX] = EVP_get_cipherbyname(SN_rc4);
    ssl_cipher_methods[SSL_ENC_RC2_IDX] = EVP_get_cipherbyname(SN_rc2_cbc);
#ifndef OPENSSL_NO_IDEA
    ssl_cipher_methods[SSL_ENC_IDEA_IDX] = EVP_get_cipherbyname(SN_idea_cbc);
#else
    ssl_cipher_methods[SSL_ENC_IDEA_IDX] = NULL;
#endif
    ssl_cipher_methods[SSL_ENC_AES128_IDX] =
        EVP_get_cipherbyname(SN_aes_128_cbc);
    ssl_cipher_methods[SSL_ENC_AES256_IDX] =
        EVP_get_cipherbyname(SN_aes_256_cbc);
    ssl_cipher_methods[SSL_ENC_CAMELLIA128_IDX] =
        EVP_get_cipherbyname(SN_camellia_128_cbc);
    ssl_cipher_methods[SSL_ENC_CAMELLIA256_IDX] =
        EVP_get_cipherbyname(SN_camellia_256_cbc);
    ssl_cipher_methods[SSL_ENC_GOST89_IDX] =
        EVP_get_cipherbyname(SN_gost89_cnt);
    ssl_cipher_methods[SSL_ENC_SEED_IDX] = EVP_get_cipherbyname(SN_seed_cbc);

    ssl_cipher_methods[SSL_ENC_AES128GCM_IDX] =
        EVP_get_cipherbyname(SN_aes_128_gcm);
    ssl_cipher_methods[SSL_ENC_AES256GCM_IDX] =
        EVP_get_cipherbyname(SN_aes_256_gcm);

    ssl_digest_methods[SSL_MD_MD5_IDX] = EVP_get_digestbyname(SN_md5);
    ssl_mac_secret_size[SSL_MD_MD5_IDX] =
        EVP_MD_size(ssl_digest_methods[SSL_MD_MD5_IDX]);
    OPENSSL_assert(ssl_mac_secret_size[SSL_MD_MD5_IDX] >= 0);
    ssl_digest_methods[SSL_MD_SHA1_IDX] = EVP_get_digestbyname(SN_sha1);
    ssl_mac_secret_size[SSL_MD_SHA1_IDX] =
        EVP_MD_size(ssl_digest_methods[SSL_MD_SHA1_IDX]);
    OPENSSL_assert(ssl_mac_secret_size[SSL_MD_SHA1_IDX] >= 0);
    ssl_digest_methods[SSL_MD_GOST94_IDX] =
        EVP_get_digestbyname(SN_id_GostR3411_94);
    if (ssl_digest_methods[SSL_MD_GOST94_IDX]) {
        ssl_mac_secret_size[SSL_MD_GOST94_IDX] =
            EVP_MD_size(ssl_digest_methods[SSL_MD_GOST94_IDX]);
        OPENSSL_assert(ssl_mac_secret_size[SSL_MD_GOST94_IDX] >= 0);
    }
    ssl_digest_methods[SSL_MD_GOST89MAC_IDX] =
        EVP_get_digestbyname(SN_id_Gost28147_89_MAC);
    ssl_mac_pkey_id[SSL_MD_GOST89MAC_IDX] = get_optional_pkey_id("gost-mac");
    if (ssl_mac_pkey_id[SSL_MD_GOST89MAC_IDX]) {
        ssl_mac_secret_size[SSL_MD_GOST89MAC_IDX] = 32;
    }

    ssl_digest_methods[SSL_MD_SHA256_IDX] = EVP_get_digestbyname(SN_sha256);
    ssl_mac_secret_size[SSL_MD_SHA256_IDX] =
        EVP_MD_size(ssl_digest_methods[SSL_MD_SHA256_IDX]);
    ssl_digest_methods[SSL_MD_SHA384_IDX] = EVP_get_digestbyname(SN_sha384);
    ssl_mac_secret_size[SSL_MD_SHA384_IDX] =
        EVP_MD_size(ssl_digest_methods[SSL_MD_SHA384_IDX]);
}

#ifndef OPENSSL_NO_COMP

static int sk_comp_cmp(const SSL_COMP *const *a, const SSL_COMP *const *b)
{
    return ((*a)->id - (*b)->id);
}

static void load_builtin_compressions(void)
{
    int got_write_lock = 0;

    CRYPTO_r_lock(CRYPTO_LOCK_SSL);
    if (ssl_comp_methods == NULL) {
        CRYPTO_r_unlock(CRYPTO_LOCK_SSL);
        CRYPTO_w_lock(CRYPTO_LOCK_SSL);
        got_write_lock = 1;

        if (ssl_comp_methods == NULL) {
            SSL_COMP *comp = NULL;

            MemCheck_off();
            ssl_comp_methods = sk_SSL_COMP_new(sk_comp_cmp);
            if (ssl_comp_methods != NULL) {
                comp = (SSL_COMP *)OPENSSL_malloc(sizeof(SSL_COMP));
                if (comp != NULL) {
                    comp->method = COMP_zlib();
                    if (comp->method && comp->method->type == NID_undef)
                        OPENSSL_free(comp);
                    else {
                        comp->id = SSL_COMP_ZLIB_IDX;
                        comp->name = comp->method->name;
                        sk_SSL_COMP_push(ssl_comp_methods, comp);
                    }
                }
                sk_SSL_COMP_sort(ssl_comp_methods);
            }
            MemCheck_on();
        }
    }

    if (got_write_lock)
        CRYPTO_w_unlock(CRYPTO_LOCK_SSL);
    else
        CRYPTO_r_unlock(CRYPTO_LOCK_SSL);
}
#endif

int ssl_cipher_get_evp(const SSL_SESSION *s, const EVP_CIPHER **enc,
                       const EVP_MD **md, int *mac_pkey_type,
                       int *mac_secret_size, SSL_COMP **comp)
{
    int i;
    const SSL_CIPHER *c;

    c = s->cipher;
    if (c == NULL)
        return (0);
    if (comp != NULL) {
        SSL_COMP ctmp;
#ifndef OPENSSL_NO_COMP
        load_builtin_compressions();
#endif

        *comp = NULL;
        ctmp.id = s->compress_meth;
        if (ssl_comp_methods != NULL) {
            i = sk_SSL_COMP_find(ssl_comp_methods, &ctmp);
            if (i >= 0)
                *comp = sk_SSL_COMP_value(ssl_comp_methods, i);
            else
                *comp = NULL;
        }
    }

    if ((enc == NULL) || (md == NULL))
        return (0);

    switch (c->algorithm_enc) {
    case SSL_DES:
        i = SSL_ENC_DES_IDX;
        break;
    case SSL_3DES:
        i = SSL_ENC_3DES_IDX;
        break;
    case SSL_RC4:
        i = SSL_ENC_RC4_IDX;
        break;
    case SSL_RC2:
        i = SSL_ENC_RC2_IDX;
        break;
    case SSL_IDEA:
        i = SSL_ENC_IDEA_IDX;
        break;
    case SSL_eNULL:
        i = SSL_ENC_NULL_IDX;
        break;
    case SSL_AES128:
        i = SSL_ENC_AES128_IDX;
        break;
    case SSL_AES256:
        i = SSL_ENC_AES256_IDX;
        break;
    case SSL_CAMELLIA128:
        i = SSL_ENC_CAMELLIA128_IDX;
        break;
    case SSL_CAMELLIA256:
        i = SSL_ENC_CAMELLIA256_IDX;
        break;
    case SSL_eGOST2814789CNT:
        i = SSL_ENC_GOST89_IDX;
        break;
    case SSL_SEED:
        i = SSL_ENC_SEED_IDX;
        break;
    case SSL_AES128GCM:
        i = SSL_ENC_AES128GCM_IDX;
        break;
    case SSL_AES256GCM:
        i = SSL_ENC_AES256GCM_IDX;
        break;
    default:
        i = -1;
        break;
    }

    if ((i < 0) || (i >= SSL_ENC_NUM_IDX))
        *enc = NULL;
    else {
        if (i == SSL_ENC_NULL_IDX)
            *enc = EVP_enc_null();
        else
            *enc = ssl_cipher_methods[i];
    }

    switch (c->algorithm_mac) {
    case SSL_MD5:
        i = SSL_MD_MD5_IDX;
        break;
    case SSL_SHA1:
        i = SSL_MD_SHA1_IDX;
        break;
    case SSL_SHA256:
        i = SSL_MD_SHA256_IDX;
        break;
    case SSL_SHA384:
        i = SSL_MD_SHA384_IDX;
        break;
    case SSL_GOST94:
        i = SSL_MD_GOST94_IDX;
        break;
    case SSL_GOST89MAC:
        i = SSL_MD_GOST89MAC_IDX;
        break;
    default:
        i = -1;
        break;
    }
    if ((i < 0) || (i >= SSL_MD_NUM_IDX)) {
        *md = NULL;
        if (mac_pkey_type != NULL)
            *mac_pkey_type = NID_undef;
        if (mac_secret_size != NULL)
            *mac_secret_size = 0;
        if (c->algorithm_mac == SSL_AEAD)
            mac_pkey_type = NULL;
    } else {
        *md = ssl_digest_methods[i];
        if (mac_pkey_type != NULL)
            *mac_pkey_type = ssl_mac_pkey_id[i];
        if (mac_secret_size != NULL)
            *mac_secret_size = ssl_mac_secret_size[i];
    }

    if ((*enc != NULL) &&
        (*md != NULL || (EVP_CIPHER_flags(*enc) & EVP_CIPH_FLAG_AEAD_CIPHER))
        && (!mac_pkey_type || *mac_pkey_type != NID_undef)) {
        const EVP_CIPHER *evp;

        if (s->ssl_version >> 8 != TLS1_VERSION_MAJOR ||
            s->ssl_version < TLS1_VERSION)
            return 1;

#ifdef OPENSSL_FIPS
        if (FIPS_mode())
            return 1;
#endif

        if (c->algorithm_enc == SSL_RC4 &&
            c->algorithm_mac == SSL_MD5 &&
            (evp = EVP_get_cipherbyname("RC4-HMAC-MD5")))
            *enc = evp, *md = NULL;
        else if (c->algorithm_enc == SSL_AES128 &&
                 c->algorithm_mac == SSL_SHA1 &&
                 (evp = EVP_get_cipherbyname("AES-128-CBC-HMAC-SHA1")))
            *enc = evp, *md = NULL;
        else if (c->algorithm_enc == SSL_AES256 &&
                 c->algorithm_mac == SSL_SHA1 &&
                 (evp = EVP_get_cipherbyname("AES-256-CBC-HMAC-SHA1")))
            *enc = evp, *md = NULL;
        else if (c->algorithm_enc == SSL_AES128 &&
                 c->algorithm_mac == SSL_SHA256 &&
                 (evp = EVP_get_cipherbyname("AES-128-CBC-HMAC-SHA256")))
            *enc = evp, *md = NULL;
        else if (c->algorithm_enc == SSL_AES256 &&
                 c->algorithm_mac == SSL_SHA256 &&
                 (evp = EVP_get_cipherbyname("AES-256-CBC-HMAC-SHA256")))
            *enc = evp, *md = NULL;
        return (1);
    } else
        return (0);
}

int ssl_get_handshake_digest(int idx, long *mask, const EVP_MD **md)
{
    if (idx < 0 || idx >= SSL_MD_NUM_IDX) {
        return 0;
    }
    *mask = ssl_handshake_digest_flag[idx];
    if (*mask)
        *md = ssl_digest_methods[idx];
    else
        *md = NULL;
    return 1;
}

#define ITEM_SEP(a) \
        (((a) == ':') || ((a) == ' ') || ((a) == ';') || ((a) == ','))

static void ll_append_tail(CIPHER_ORDER **head, CIPHER_ORDER *curr,
                           CIPHER_ORDER **tail)
{
    if (curr == *tail)
        return;
    if (curr == *head)
        *head = curr->next;
    if (curr->prev != NULL)
        curr->prev->next = curr->next;
    if (curr->next != NULL)
        curr->next->prev = curr->prev;
    (*tail)->next = curr;
    curr->prev = *tail;
    curr->next = NULL;
    *tail = curr;
}

static void ll_append_head(CIPHER_ORDER **head, CIPHER_ORDER *curr,
                           CIPHER_ORDER **tail)
{
    if (curr == *head)
        return;
    if (curr == *tail)
        *tail = curr->prev;
    if (curr->next != NULL)
        curr->next->prev = curr->prev;
    if (curr->prev != NULL)
        curr->prev->next = curr->next;
    (*head)->prev = curr;
    curr->next = *head;
    curr->prev = NULL;
    *head = curr;
}

static void ssl_cipher_get_disabled(unsigned long *mkey, unsigned long *auth,
                                    unsigned long *enc, unsigned long *mac,
                                    unsigned long *ssl)
{
    *mkey = 0;
    *auth = 0;
    *enc = 0;
    *mac = 0;
    *ssl = 0;

#ifdef OPENSSL_NO_RSA
    *mkey |= SSL_kRSA;
    *auth |= SSL_aRSA;
#endif
#ifdef OPENSSL_NO_DSA
    *auth |= SSL_aDSS;
#endif
#ifdef OPENSSL_NO_DH
    *mkey |= SSL_kDHr | SSL_kDHd | SSL_kEDH;
    *auth |= SSL_aDH;
#endif
#ifdef OPENSSL_NO_KRB5
    *mkey |= SSL_kKRB5;
    *auth |= SSL_aKRB5;
#endif
#ifdef OPENSSL_NO_ECDSA
    *auth |= SSL_aECDSA;
#endif
#ifdef OPENSSL_NO_ECDH
    *mkey |= SSL_kECDHe | SSL_kECDHr;
    *auth |= SSL_aECDH;
#endif
#ifdef OPENSSL_NO_PSK
    *mkey |= SSL_kPSK;
    *auth |= SSL_aPSK;
#endif
#ifdef OPENSSL_NO_SRP
    *mkey |= SSL_kSRP;
#endif
    /*
     * Check for presence of GOST 34.10 algorithms, and if they do not
     * present, disable appropriate auth and key exchange
     */
    if (!get_optional_pkey_id("gost94")) {
        *auth |= SSL_aGOST94;
    }
    if (!get_optional_pkey_id("gost2001")) {
        *auth |= SSL_aGOST01;
    }
    /*
     * Disable GOST key exchange if no GOST signature algs are available *
     */
    if ((*auth & (SSL_aGOST94 | SSL_aGOST01)) == (SSL_aGOST94 | SSL_aGOST01)) {
        *mkey |= SSL_kGOST;
    }
#ifdef SSL_FORBID_ENULL
    *enc |= SSL_eNULL;
#endif

    *enc |= (ssl_cipher_methods[SSL_ENC_DES_IDX] == NULL) ? SSL_DES : 0;
    *enc |= (ssl_cipher_methods[SSL_ENC_3DES_IDX] == NULL) ? SSL_3DES : 0;
    *enc |= (ssl_cipher_methods[SSL_ENC_RC4_IDX] == NULL) ? SSL_RC4 : 0;
    *enc |= (ssl_cipher_methods[SSL_ENC_RC2_IDX] == NULL) ? SSL_RC2 : 0;
    *enc |= (ssl_cipher_methods[SSL_ENC_IDEA_IDX] == NULL) ? SSL_IDEA : 0;
    *enc |= (ssl_cipher_methods[SSL_ENC_AES128_IDX] == NULL) ? SSL_AES128 : 0;
    *enc |= (ssl_cipher_methods[SSL_ENC_AES256_IDX] == NULL) ? SSL_AES256 : 0;
    *enc |=
        (ssl_cipher_methods[SSL_ENC_AES128GCM_IDX] ==
         NULL) ? SSL_AES128GCM : 0;
    *enc |=
        (ssl_cipher_methods[SSL_ENC_AES256GCM_IDX] ==
         NULL) ? SSL_AES256GCM : 0;
    *enc |=
        (ssl_cipher_methods[SSL_ENC_CAMELLIA128_IDX] ==
         NULL) ? SSL_CAMELLIA128 : 0;
    *enc |=
        (ssl_cipher_methods[SSL_ENC_CAMELLIA256_IDX] ==
         NULL) ? SSL_CAMELLIA256 : 0;
    *enc |=
        (ssl_cipher_methods[SSL_ENC_GOST89_IDX] ==
         NULL) ? SSL_eGOST2814789CNT : 0;
    *enc |= (ssl_cipher_methods[SSL_ENC_SEED_IDX] == NULL) ? SSL_SEED : 0;

    *mac |= (ssl_digest_methods[SSL_MD_MD5_IDX] == NULL) ? SSL_MD5 : 0;
    *mac |= (ssl_digest_methods[SSL_MD_SHA1_IDX] == NULL) ? SSL_SHA1 : 0;
    *mac |= (ssl_digest_methods[SSL_MD_SHA256_IDX] == NULL) ? SSL_SHA256 : 0;
    *mac |= (ssl_digest_methods[SSL_MD_SHA384_IDX] == NULL) ? SSL_SHA384 : 0;
    *mac |= (ssl_digest_methods[SSL_MD_GOST94_IDX] == NULL) ? SSL_GOST94 : 0;
    *mac |= (ssl_digest_methods[SSL_MD_GOST89MAC_IDX] == NULL
             || ssl_mac_pkey_id[SSL_MD_GOST89MAC_IDX] ==
             NID_undef) ? SSL_GOST89MAC : 0;

}

static void ssl_cipher_collect_ciphers(const SSL_METHOD *ssl_method,
                                       int num_of_ciphers,
                                       unsigned long disabled_mkey,
                                       unsigned long disabled_auth,
                                       unsigned long disabled_enc,
                                       unsigned long disabled_mac,
                                       unsigned long disabled_ssl,
                                       CIPHER_ORDER *co_list,
                                       CIPHER_ORDER **head_p,
                                       CIPHER_ORDER **tail_p)
{
    int i, co_list_num;
    const SSL_CIPHER *c;

    /*
     * We have num_of_ciphers descriptions compiled in, depending on the
     * method selected (SSLv2 and/or SSLv3, TLSv1 etc).
     * These will later be sorted in a linked list with at most num
     * entries.
     */

    /* Get the initial list of ciphers */
    co_list_num = 0;            /* actual count of ciphers */
    for (i = 0; i < num_of_ciphers; i++) {
        c = ssl_method->get_cipher(i);
        /* drop those that use any of that is not available */
        if ((c != NULL) && c->valid &&
#ifdef OPENSSL_FIPS
            (!FIPS_mode() || (c->algo_strength & SSL_FIPS)) &&
#endif
            !(c->algorithm_mkey & disabled_mkey) &&
            !(c->algorithm_auth & disabled_auth) &&
            !(c->algorithm_enc & disabled_enc) &&
            !(c->algorithm_mac & disabled_mac) &&
            !(c->algorithm_ssl & disabled_ssl)) {
            co_list[co_list_num].cipher = c;
            co_list[co_list_num].next = NULL;
            co_list[co_list_num].prev = NULL;
            co_list[co_list_num].active = 0;
            co_list_num++;
#ifdef KSSL_DEBUG
            fprintf(stderr, "\t%d: %s %lx %lx %lx\n", i, c->name, c->id,
                    c->algorithm_mkey, c->algorithm_auth);
#endif                          /* KSSL_DEBUG */
            /*
             * if (!sk_push(ca_list,(char *)c)) goto err;
             */
        }
    }

    /*
     * Prepare linked list from list entries
     */
    if (co_list_num > 0) {
        co_list[0].prev = NULL;

        if (co_list_num > 1) {
            co_list[0].next = &co_list[1];

            for (i = 1; i < co_list_num - 1; i++) {
                co_list[i].prev = &co_list[i - 1];
                co_list[i].next = &co_list[i + 1];
            }

            co_list[co_list_num - 1].prev = &co_list[co_list_num - 2];
        }

        co_list[co_list_num - 1].next = NULL;

        *head_p = &co_list[0];
        *tail_p = &co_list[co_list_num - 1];
    }
}

static void ssl_cipher_collect_aliases(const SSL_CIPHER **ca_list,
                                       int num_of_group_aliases,
                                       unsigned long disabled_mkey,
                                       unsigned long disabled_auth,
                                       unsigned long disabled_enc,
                                       unsigned long disabled_mac,
                                       unsigned long disabled_ssl,
                                       CIPHER_ORDER *head)
{
    CIPHER_ORDER *ciph_curr;
    const SSL_CIPHER **ca_curr;
    int i;
    unsigned long mask_mkey = ~disabled_mkey;
    unsigned long mask_auth = ~disabled_auth;
    unsigned long mask_enc = ~disabled_enc;
    unsigned long mask_mac = ~disabled_mac;
    unsigned long mask_ssl = ~disabled_ssl;

    /*
     * First, add the real ciphers as already collected
     */
    ciph_curr = head;
    ca_curr = ca_list;
    while (ciph_curr != NULL) {
        *ca_curr = ciph_curr->cipher;
        ca_curr++;
        ciph_curr = ciph_curr->next;
    }

    /*
     * Now we add the available ones from the cipher_aliases[] table.
     * They represent either one or more algorithms, some of which
     * in any affected category must be supported (set in enabled_mask),
     * or represent a cipher strength value (will be added in any case because algorithms=0).
     */
    for (i = 0; i < num_of_group_aliases; i++) {
        unsigned long algorithm_mkey = cipher_aliases[i].algorithm_mkey;
        unsigned long algorithm_auth = cipher_aliases[i].algorithm_auth;
        unsigned long algorithm_enc = cipher_aliases[i].algorithm_enc;
        unsigned long algorithm_mac = cipher_aliases[i].algorithm_mac;
        unsigned long algorithm_ssl = cipher_aliases[i].algorithm_ssl;

        if (algorithm_mkey)
            if ((algorithm_mkey & mask_mkey) == 0)
                continue;

        if (algorithm_auth)
            if ((algorithm_auth & mask_auth) == 0)
                continue;

        if (algorithm_enc)
            if ((algorithm_enc & mask_enc) == 0)
                continue;

        if (algorithm_mac)
            if ((algorithm_mac & mask_mac) == 0)
                continue;

        if (algorithm_ssl)
            if ((algorithm_ssl & mask_ssl) == 0)
                continue;

        *ca_curr = (SSL_CIPHER *)(cipher_aliases + i);
        ca_curr++;
    }

    *ca_curr = NULL;            /* end of list */
}

static void ssl_cipher_apply_rule(unsigned long cipher_id,
                                  unsigned long alg_mkey,
                                  unsigned long alg_auth,
                                  unsigned long alg_enc,
                                  unsigned long alg_mac,
                                  unsigned long alg_ssl,
                                  unsigned long algo_strength, int rule,
                                  int strength_bits, CIPHER_ORDER **head_p,
                                  CIPHER_ORDER **tail_p)
{
    CIPHER_ORDER *head, *tail, *curr, *next, *last;
    const SSL_CIPHER *cp;
    int reverse = 0;

#ifdef CIPHER_DEBUG
    fprintf(stderr,
            "Applying rule %d with %08lx/%08lx/%08lx/%08lx/%08lx %08lx (%d)\n",
            rule, alg_mkey, alg_auth, alg_enc, alg_mac, alg_ssl,
            algo_strength, strength_bits);
#endif

    if (rule == CIPHER_DEL)
        reverse = 1;            /* needed to maintain sorting between
                                 * currently deleted ciphers */

    head = *head_p;
    tail = *tail_p;

    if (reverse) {
        next = tail;
        last = head;
    } else {
        next = head;
        last = tail;
    }

    curr = NULL;
    for (;;) {
        if (curr == last)
            break;

        curr = next;

        if (curr == NULL)
            break;

        next = reverse ? curr->prev : curr->next;

        cp = curr->cipher;

        /*
         * Selection criteria is either the value of strength_bits
         * or the algorithms used.
         */
        if (strength_bits >= 0) {
            if (strength_bits != cp->strength_bits)
                continue;
        } else {
#ifdef CIPHER_DEBUG
            fprintf(stderr,
                    "\nName: %s:\nAlgo = %08lx/%08lx/%08lx/%08lx/%08lx Algo_strength = %08lx\n",
                    cp->name, cp->algorithm_mkey, cp->algorithm_auth,
                    cp->algorithm_enc, cp->algorithm_mac, cp->algorithm_ssl,
                    cp->algo_strength);
#endif
#ifdef OPENSSL_SSL_DEBUG_BROKEN_PROTOCOL
            if (cipher_id && cipher_id != cp->id)
                continue;
#endif
            if (alg_mkey && !(alg_mkey & cp->algorithm_mkey))
                continue;
            if (alg_auth && !(alg_auth & cp->algorithm_auth))
                continue;
            if (alg_enc && !(alg_enc & cp->algorithm_enc))
                continue;
            if (alg_mac && !(alg_mac & cp->algorithm_mac))
                continue;
            if (alg_ssl && !(alg_ssl & cp->algorithm_ssl))
                continue;
            if ((algo_strength & SSL_EXP_MASK)
                && !(algo_strength & SSL_EXP_MASK & cp->algo_strength))
                continue;
            if ((algo_strength & SSL_STRONG_MASK)
                && !(algo_strength & SSL_STRONG_MASK & cp->algo_strength))
                continue;
            if ((algo_strength & SSL_NOT_DEFAULT)
                && !(cp->algo_strength & SSL_NOT_DEFAULT))
                continue;
        }

#ifdef CIPHER_DEBUG
        fprintf(stderr, "Action = %d\n", rule);
#endif

        /* add the cipher if it has not been added yet. */
        if (rule == CIPHER_ADD) {
            /* reverse == 0 */
            if (!curr->active) {
                ll_append_tail(&head, curr, &tail);
                curr->active = 1;
            }
        }
        /* Move the added cipher to this location */
        else if (rule == CIPHER_ORD) {
            /* reverse == 0 */
            if (curr->active) {
                ll_append_tail(&head, curr, &tail);
            }
        } else if (rule == CIPHER_DEL) {
            /* reverse == 1 */
            if (curr->active) {
                /*
                 * most recently deleted ciphersuites get best positions for
                 * any future CIPHER_ADD (note that the CIPHER_DEL loop works
                 * in reverse to maintain the order)
                 */
                ll_append_head(&head, curr, &tail);
                curr->active = 0;
            }
        } else if (rule == CIPHER_KILL) {
            /* reverse == 0 */
            if (head == curr)
                head = curr->next;
            else
                curr->prev->next = curr->next;
            if (tail == curr)
                tail = curr->prev;
            curr->active = 0;
            if (curr->next != NULL)
                curr->next->prev = curr->prev;
            if (curr->prev != NULL)
                curr->prev->next = curr->next;
            curr->next = NULL;
            curr->prev = NULL;
        }
    }

    *head_p = head;
    *tail_p = tail;
}

static int ssl_cipher_strength_sort(CIPHER_ORDER **head_p,
                                    CIPHER_ORDER **tail_p)
{
    int max_strength_bits, i, *number_uses;
    CIPHER_ORDER *curr;

    /*
     * This routine sorts the ciphers with descending strength. The sorting
     * must keep the pre-sorted sequence, so we apply the normal sorting
     * routine as '+' movement to the end of the list.
     */
    max_strength_bits = 0;
    curr = *head_p;
    while (curr != NULL) {
        if (curr->active && (curr->cipher->strength_bits > max_strength_bits))
            max_strength_bits = curr->cipher->strength_bits;
        curr = curr->next;
    }

    number_uses = OPENSSL_malloc((max_strength_bits + 1) * sizeof(int));
    if (!number_uses) {
        SSLerr(SSL_F_SSL_CIPHER_STRENGTH_SORT, ERR_R_MALLOC_FAILURE);
        return (0);
    }
    memset(number_uses, 0, (max_strength_bits + 1) * sizeof(int));

    /*
     * Now find the strength_bits values actually used
     */
    curr = *head_p;
    while (curr != NULL) {
        if (curr->active)
            number_uses[curr->cipher->strength_bits]++;
        curr = curr->next;
    }
    /*
     * Go through the list of used strength_bits values in descending
     * order.
     */
    for (i = max_strength_bits; i >= 0; i--)
        if (number_uses[i] > 0)
            ssl_cipher_apply_rule(0, 0, 0, 0, 0, 0, 0, CIPHER_ORD, i, head_p,
                                  tail_p);

    OPENSSL_free(number_uses);
    return (1);
}

static int ssl_cipher_process_rulestr(const char *rule_str,
                                      CIPHER_ORDER **head_p,
                                      CIPHER_ORDER **tail_p,
                                      const SSL_CIPHER **ca_list)
{
    unsigned long alg_mkey, alg_auth, alg_enc, alg_mac, alg_ssl,
        algo_strength;
    const char *l, *buf;
    int j, multi, found, rule, retval, ok, buflen;
    unsigned long cipher_id = 0;
    char ch;

    retval = 1;
    l = rule_str;
    for (;;) {
        ch = *l;

        if (ch == '\0')
            break;              /* done */
        if (ch == '-') {
            rule = CIPHER_DEL;
            l++;
        } else if (ch == '+') {
            rule = CIPHER_ORD;
            l++;
        } else if (ch == '!') {
            rule = CIPHER_KILL;
            l++;
        } else if (ch == '@') {
            rule = CIPHER_SPECIAL;
            l++;
        } else {
            rule = CIPHER_ADD;
        }

        if (ITEM_SEP(ch)) {
            l++;
            continue;
        }

        alg_mkey = 0;
        alg_auth = 0;
        alg_enc = 0;
        alg_mac = 0;
        alg_ssl = 0;
        algo_strength = 0;

        for (;;) {
            ch = *l;
            buf = l;
            buflen = 0;
#ifndef CHARSET_EBCDIC
            while (((ch >= 'A') && (ch <= 'Z')) ||
                   ((ch >= '0') && (ch <= '9')) ||
                   ((ch >= 'a') && (ch <= 'z')) || (ch == '-') || (ch == '.'))
#else
            while (isalnum((unsigned char)ch) || (ch == '-') || (ch == '.'))
#endif
            {
                ch = *(++l);
                buflen++;
            }

            if (buflen == 0) {
                /*
                 * We hit something we cannot deal with,
                 * it is no command or separator nor
                 * alphanumeric, so we call this an error.
                 */
                SSLerr(SSL_F_SSL_CIPHER_PROCESS_RULESTR,
                       SSL_R_INVALID_COMMAND);
                retval = found = 0;
                l++;
                break;
            }

            if (rule == CIPHER_SPECIAL) {
                found = 0;      /* unused -- avoid compiler warning */
                break;          /* special treatment */
            }

            /* check for multi-part specification */
            if (ch == '+') {
                multi = 1;
                l++;
            } else
                multi = 0;

            /*
             * Now search for the cipher alias in the ca_list. Be careful
             * with the strncmp, because the "buflen" limitation
             * will make the rule "ADH:SOME" and the cipher
             * "ADH-MY-CIPHER" look like a match for buflen=3.
             * So additionally check whether the cipher name found
             * has the correct length. We can save a strlen() call:
             * just checking for the '\0' at the right place is
             * sufficient, we have to strncmp() anyway. (We cannot
             * use strcmp(), because buf is not '\0' terminated.)
             */
            j = found = 0;
            cipher_id = 0;
            while (ca_list[j]) {
                if (!strncmp(buf, ca_list[j]->name, buflen) &&
                    (ca_list[j]->name[buflen] == '\0')) {
                    found = 1;
                    break;
                } else
                    j++;
            }

            if (!found)
                break;          /* ignore this entry */

            if (ca_list[j]->algorithm_mkey) {
                if (alg_mkey) {
                    alg_mkey &= ca_list[j]->algorithm_mkey;
                    if (!alg_mkey) {
                        found = 0;
                        break;
                    }
                } else
                    alg_mkey = ca_list[j]->algorithm_mkey;
            }

            if (ca_list[j]->algorithm_auth) {
                if (alg_auth) {
                    alg_auth &= ca_list[j]->algorithm_auth;
                    if (!alg_auth) {
                        found = 0;
                        break;
                    }
                } else
                    alg_auth = ca_list[j]->algorithm_auth;
            }

            if (ca_list[j]->algorithm_enc) {
                if (alg_enc) {
                    alg_enc &= ca_list[j]->algorithm_enc;
                    if (!alg_enc) {
                        found = 0;
                        break;
                    }
                } else
                    alg_enc = ca_list[j]->algorithm_enc;
            }

            if (ca_list[j]->algorithm_mac) {
                if (alg_mac) {
                    alg_mac &= ca_list[j]->algorithm_mac;
                    if (!alg_mac) {
                        found = 0;
                        break;
                    }
                } else
                    alg_mac = ca_list[j]->algorithm_mac;
            }

            if (ca_list[j]->algo_strength & SSL_EXP_MASK) {
                if (algo_strength & SSL_EXP_MASK) {
                    algo_strength &=
                        (ca_list[j]->algo_strength & SSL_EXP_MASK) |
                        ~SSL_EXP_MASK;
                    if (!(algo_strength & SSL_EXP_MASK)) {
                        found = 0;
                        break;
                    }
                } else
                    algo_strength |= ca_list[j]->algo_strength & SSL_EXP_MASK;
            }

            if (ca_list[j]->algo_strength & SSL_STRONG_MASK) {
                if (algo_strength & SSL_STRONG_MASK) {
                    algo_strength &=
                        (ca_list[j]->algo_strength & SSL_STRONG_MASK) |
                        ~SSL_STRONG_MASK;
                    if (!(algo_strength & SSL_STRONG_MASK)) {
                        found = 0;
                        break;
                    }
                } else
                    algo_strength |=
                        ca_list[j]->algo_strength & SSL_STRONG_MASK;
            }

            if (ca_list[j]->algo_strength & SSL_NOT_DEFAULT) {
                algo_strength |= SSL_NOT_DEFAULT;
            }

            if (ca_list[j]->valid) {
                /*
                 * explicit ciphersuite found; its protocol version does not
                 * become part of the search pattern!
                 */

                cipher_id = ca_list[j]->id;
            } else {
                /*
                 * not an explicit ciphersuite; only in this case, the
                 * protocol version is considered part of the search pattern
                 */

                if (ca_list[j]->algorithm_ssl) {
                    if (alg_ssl) {
                        alg_ssl &= ca_list[j]->algorithm_ssl;
                        if (!alg_ssl) {
                            found = 0;
                            break;
                        }
                    } else
                        alg_ssl = ca_list[j]->algorithm_ssl;
                }
            }

            if (!multi)
                break;
        }

        /*
         * Ok, we have the rule, now apply it
         */
        if (rule == CIPHER_SPECIAL) { /* special command */
            ok = 0;
            if ((buflen == 8) && !strncmp(buf, "STRENGTH", 8))
                ok = ssl_cipher_strength_sort(head_p, tail_p);
            else
                SSLerr(SSL_F_SSL_CIPHER_PROCESS_RULESTR,
                       SSL_R_INVALID_COMMAND);
            if (ok == 0)
                retval = 0;
            /*
             * We do not support any "multi" options
             * together with "@", so throw away the
             * rest of the command, if any left, until
             * end or ':' is found.
             */
            while ((*l != '\0') && !ITEM_SEP(*l))
                l++;
        } else if (found) {
            ssl_cipher_apply_rule(cipher_id,
                                  alg_mkey, alg_auth, alg_enc, alg_mac,
                                  alg_ssl, algo_strength, rule, -1, head_p,
                                  tail_p);
        } else {
            while ((*l != '\0') && !ITEM_SEP(*l))
                l++;
        }
        if (*l == '\0')
            break;              /* done */
    }

    return (retval);
}

#ifndef OPENSSL_NO_EC
static int check_suiteb_cipher_list(const SSL_METHOD *meth, CERT *c,
                                    const char **prule_str)
{
    unsigned int suiteb_flags = 0;
# ifndef OPENSSL_NO_ECDH
    unsigned int suiteb_comb2 = 0;
#endif

    if (strncmp(*prule_str, "SUITEB128ONLY", 13) == 0) {
        suiteb_flags = SSL_CERT_FLAG_SUITEB_128_LOS_ONLY;
    } else if (strncmp(*prule_str, "SUITEB128C2", 11) == 0) {
# ifndef OPENSSL_NO_ECDH
        suiteb_comb2 = 1;
# endif
        suiteb_flags = SSL_CERT_FLAG_SUITEB_128_LOS;
    } else if (strncmp(*prule_str, "SUITEB128", 9) == 0) {
        suiteb_flags = SSL_CERT_FLAG_SUITEB_128_LOS;
    } else if (strncmp(*prule_str, "SUITEB192", 9) == 0) {
        suiteb_flags = SSL_CERT_FLAG_SUITEB_192_LOS;
    }

    if (suiteb_flags) {
        c->cert_flags &= ~SSL_CERT_FLAG_SUITEB_128_LOS;
        c->cert_flags |= suiteb_flags;
    } else
        suiteb_flags = c->cert_flags & SSL_CERT_FLAG_SUITEB_128_LOS;

    if (!suiteb_flags)
        return 1;
    /* Check version: if TLS 1.2 ciphers allowed we can use Suite B */

    if (!(meth->ssl3_enc->enc_flags & SSL_ENC_FLAG_TLS1_2_CIPHERS)) {
        if (meth->ssl3_enc->enc_flags & SSL_ENC_FLAG_DTLS)
            SSLerr(SSL_F_CHECK_SUITEB_CIPHER_LIST,
                   SSL_R_ONLY_DTLS_1_2_ALLOWED_IN_SUITEB_MODE);
        else
            SSLerr(SSL_F_CHECK_SUITEB_CIPHER_LIST,
                   SSL_R_ONLY_TLS_1_2_ALLOWED_IN_SUITEB_MODE);
        return 0;
    }
# ifndef OPENSSL_NO_ECDH
    switch (suiteb_flags) {
    case SSL_CERT_FLAG_SUITEB_128_LOS:
        if (suiteb_comb2)
            *prule_str = "ECDHE-ECDSA-AES256-GCM-SHA384";
        else
            *prule_str =
                "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384";
        break;
    case SSL_CERT_FLAG_SUITEB_128_LOS_ONLY:
        *prule_str = "ECDHE-ECDSA-AES128-GCM-SHA256";
        break;
    case SSL_CERT_FLAG_SUITEB_192_LOS:
        *prule_str = "ECDHE-ECDSA-AES256-GCM-SHA384";
        break;
    }
    /* Set auto ECDH parameter determination */
    c->ecdh_tmp_auto = 1;
    return 1;
# else
    SSLerr(SSL_F_CHECK_SUITEB_CIPHER_LIST,
           SSL_R_ECDH_REQUIRED_FOR_SUITEB_MODE);
    return 0;
# endif
}
#endif

STACK_OF(SSL_CIPHER) *ssl_create_cipher_list(const SSL_METHOD *ssl_method, STACK_OF(SSL_CIPHER)
                                             **cipher_list, STACK_OF(SSL_CIPHER)
                                             **cipher_list_by_id,
                                             const char *rule_str, CERT *c)
{
    int ok, num_of_ciphers, num_of_alias_max, num_of_group_aliases;
    unsigned long disabled_mkey, disabled_auth, disabled_enc, disabled_mac,
        disabled_ssl;
    STACK_OF(SSL_CIPHER) *cipherstack, *tmp_cipher_list;
    const char *rule_p;
    CIPHER_ORDER *co_list = NULL, *head = NULL, *tail = NULL, *curr;
    const SSL_CIPHER **ca_list = NULL;

    /*
     * Return with error if nothing to do.
     */
    if (rule_str == NULL || cipher_list == NULL || cipher_list_by_id == NULL)
        return NULL;
#ifndef OPENSSL_NO_EC
    if (!check_suiteb_cipher_list(ssl_method, c, &rule_str))
        return NULL;
#endif

    /*
     * To reduce the work to do we only want to process the compiled
     * in algorithms, so we first get the mask of disabled ciphers.
     */
    ssl_cipher_get_disabled(&disabled_mkey, &disabled_auth, &disabled_enc,
                            &disabled_mac, &disabled_ssl);

    /*
     * Now we have to collect the available ciphers from the compiled
     * in ciphers. We cannot get more than the number compiled in, so
     * it is used for allocation.
     */
    num_of_ciphers = ssl_method->num_ciphers();
#ifdef KSSL_DEBUG
    fprintf(stderr, "ssl_create_cipher_list() for %d ciphers\n",
            num_of_ciphers);
#endif                          /* KSSL_DEBUG */
    co_list =
        (CIPHER_ORDER *)OPENSSL_malloc(sizeof(CIPHER_ORDER) * num_of_ciphers);
    if (co_list == NULL) {
        SSLerr(SSL_F_SSL_CREATE_CIPHER_LIST, ERR_R_MALLOC_FAILURE);
        return (NULL);          /* Failure */
    }

    ssl_cipher_collect_ciphers(ssl_method, num_of_ciphers,
                               disabled_mkey, disabled_auth, disabled_enc,
                               disabled_mac, disabled_ssl, co_list, &head,
                               &tail);

    /* Now arrange all ciphers by preference: */

    /*
     * Everything else being equal, prefer ephemeral ECDH over other key
     * exchange mechanisms
     */
    ssl_cipher_apply_rule(0, SSL_kEECDH, 0, 0, 0, 0, 0, CIPHER_ADD, -1, &head,
                          &tail);
    ssl_cipher_apply_rule(0, SSL_kEECDH, 0, 0, 0, 0, 0, CIPHER_DEL, -1, &head,
                          &tail);

    /* AES is our preferred symmetric cipher */
    ssl_cipher_apply_rule(0, 0, 0, SSL_AES, 0, 0, 0, CIPHER_ADD, -1, &head,
                          &tail);

    /* Temporarily enable everything else for sorting */
    ssl_cipher_apply_rule(0, 0, 0, 0, 0, 0, 0, CIPHER_ADD, -1, &head, &tail);

    /* Low priority for MD5 */
    ssl_cipher_apply_rule(0, 0, 0, 0, SSL_MD5, 0, 0, CIPHER_ORD, -1, &head,
                          &tail);

    /*
     * Move anonymous ciphers to the end.  Usually, these will remain
     * disabled. (For applications that allow them, they aren't too bad, but
     * we prefer authenticated ciphers.)
     */
    ssl_cipher_apply_rule(0, 0, SSL_aNULL, 0, 0, 0, 0, CIPHER_ORD, -1, &head,
                          &tail);

    /* Move ciphers without forward secrecy to the end */
    ssl_cipher_apply_rule(0, 0, SSL_aECDH, 0, 0, 0, 0, CIPHER_ORD, -1, &head,
                          &tail);
    /*
     * ssl_cipher_apply_rule(0, 0, SSL_aDH, 0, 0, 0, 0, CIPHER_ORD, -1,
     * &head, &tail);
     */
    ssl_cipher_apply_rule(0, SSL_kRSA, 0, 0, 0, 0, 0, CIPHER_ORD, -1, &head,
                          &tail);
    ssl_cipher_apply_rule(0, SSL_kPSK, 0, 0, 0, 0, 0, CIPHER_ORD, -1, &head,
                          &tail);
    ssl_cipher_apply_rule(0, SSL_kKRB5, 0, 0, 0, 0, 0, CIPHER_ORD, -1, &head,
                          &tail);

    /* RC4 is sort-of broken -- move the the end */
    ssl_cipher_apply_rule(0, 0, 0, SSL_RC4, 0, 0, 0, CIPHER_ORD, -1, &head,
                          &tail);

    /*
     * Now sort by symmetric encryption strength.  The above ordering remains
     * in force within each class
     */
    if (!ssl_cipher_strength_sort(&head, &tail)) {
        OPENSSL_free(co_list);
        return NULL;
    }

    /* Now disable everything (maintaining the ordering!) */
    ssl_cipher_apply_rule(0, 0, 0, 0, 0, 0, 0, CIPHER_DEL, -1, &head, &tail);

    /*
     * We also need cipher aliases for selecting based on the rule_str.
     * There might be two types of entries in the rule_str: 1) names
     * of ciphers themselves 2) aliases for groups of ciphers.
     * For 1) we need the available ciphers and for 2) the cipher
     * groups of cipher_aliases added together in one list (otherwise
     * we would be happy with just the cipher_aliases table).
     */
    num_of_group_aliases = sizeof(cipher_aliases) / sizeof(SSL_CIPHER);
    num_of_alias_max = num_of_ciphers + num_of_group_aliases + 1;
    ca_list = OPENSSL_malloc(sizeof(SSL_CIPHER *) * num_of_alias_max);
    if (ca_list == NULL) {
        OPENSSL_free(co_list);
        SSLerr(SSL_F_SSL_CREATE_CIPHER_LIST, ERR_R_MALLOC_FAILURE);
        return (NULL);          /* Failure */
    }
    ssl_cipher_collect_aliases(ca_list, num_of_group_aliases,
                               disabled_mkey, disabled_auth, disabled_enc,
                               disabled_mac, disabled_ssl, head);

    /*
     * If the rule_string begins with DEFAULT, apply the default rule
     * before using the (possibly available) additional rules.
     */
    ok = 1;
    rule_p = rule_str;
    if (strncmp(rule_str, "DEFAULT", 7) == 0) {
        ok = ssl_cipher_process_rulestr(SSL_DEFAULT_CIPHER_LIST,
                                        &head, &tail, ca_list);
        rule_p += 7;
        if (*rule_p == ':')
            rule_p++;
    }

    if (ok && (strlen(rule_p) > 0))
        ok = ssl_cipher_process_rulestr(rule_p, &head, &tail, ca_list);

    OPENSSL_free((void *)ca_list); /* Not needed anymore */

    if (!ok) {                  /* Rule processing failure */
        OPENSSL_free(co_list);
        return (NULL);
    }

    /*
     * Allocate new "cipherstack" for the result, return with error
     * if we cannot get one.
     */
    if ((cipherstack = sk_SSL_CIPHER_new_null()) == NULL) {
        OPENSSL_free(co_list);
        return (NULL);
    }

    /*
     * The cipher selection for the list is done. The ciphers are added
     * to the resulting precedence to the STACK_OF(SSL_CIPHER).
     */
    for (curr = head; curr != NULL; curr = curr->next) {
#ifdef OPENSSL_FIPS
        if (curr->active
            && (!FIPS_mode() || curr->cipher->algo_strength & SSL_FIPS))
#else
        if (curr->active)
#endif
        {
            sk_SSL_CIPHER_push(cipherstack, curr->cipher);
#ifdef CIPHER_DEBUG
            fprintf(stderr, "<%s>\n", curr->cipher->name);
#endif
        }
    }
    OPENSSL_free(co_list);      /* Not needed any longer */

    tmp_cipher_list = sk_SSL_CIPHER_dup(cipherstack);
    if (tmp_cipher_list == NULL) {
        sk_SSL_CIPHER_free(cipherstack);
        return NULL;
    }
    if (*cipher_list != NULL)
        sk_SSL_CIPHER_free(*cipher_list);
    *cipher_list = cipherstack;
    if (*cipher_list_by_id != NULL)
        sk_SSL_CIPHER_free(*cipher_list_by_id);
    *cipher_list_by_id = tmp_cipher_list;
    (void)sk_SSL_CIPHER_set_cmp_func(*cipher_list_by_id,
                                     ssl_cipher_ptr_id_cmp);

    sk_SSL_CIPHER_sort(*cipher_list_by_id);
    return (cipherstack);
}

char *SSL_CIPHER_description(const SSL_CIPHER *cipher, char *buf, int len)
{
    int is_export, pkl, kl;
    const char *ver, *exp_str;
    const char *kx, *au, *enc, *mac;
    unsigned long alg_mkey, alg_auth, alg_enc, alg_mac, alg_ssl, alg2;
#ifdef KSSL_DEBUG
    static const char *format =
        "%-23s %s Kx=%-8s Au=%-4s Enc=%-9s Mac=%-4s%s AL=%lx/%lx/%lx/%lx/%lx\n";
#else
    static const char *format =
        "%-23s %s Kx=%-8s Au=%-4s Enc=%-9s Mac=%-4s%s\n";
#endif                          /* KSSL_DEBUG */

    alg_mkey = cipher->algorithm_mkey;
    alg_auth = cipher->algorithm_auth;
    alg_enc = cipher->algorithm_enc;
    alg_mac = cipher->algorithm_mac;
    alg_ssl = cipher->algorithm_ssl;

    alg2 = cipher->algorithm2;

    is_export = SSL_C_IS_EXPORT(cipher);
    pkl = SSL_C_EXPORT_PKEYLENGTH(cipher);
    kl = SSL_C_EXPORT_KEYLENGTH(cipher);
    exp_str = is_export ? " export" : "";

    if (alg_ssl & SSL_SSLV2)
        ver = "SSLv2";
    else if (alg_ssl & SSL_SSLV3)
        ver = "SSLv3";
    else if (alg_ssl & SSL_TLSV1_2)
        ver = "TLSv1.2";
    else
        ver = "unknown";

    switch (alg_mkey) {
    case SSL_kRSA:
        kx = is_export ? (pkl == 512 ? "RSA(512)" : "RSA(1024)") : "RSA";
        break;
    case SSL_kDHr:
        kx = "DH/RSA";
        break;
    case SSL_kDHd:
        kx = "DH/DSS";
        break;
    case SSL_kKRB5:
        kx = "KRB5";
        break;
    case SSL_kEDH:
        kx = is_export ? (pkl == 512 ? "DH(512)" : "DH(1024)") : "DH";
        break;
    case SSL_kECDHr:
        kx = "ECDH/RSA";
        break;
    case SSL_kECDHe:
        kx = "ECDH/ECDSA";
        break;
    case SSL_kEECDH:
        kx = "ECDH";
        break;
    case SSL_kPSK:
        kx = "PSK";
        break;
    case SSL_kSRP:
        kx = "SRP";
        break;
    case SSL_kGOST:
        kx = "GOST";
        break;
    default:
        kx = "unknown";
    }

    switch (alg_auth) {
    case SSL_aRSA:
        au = "RSA";
        break;
    case SSL_aDSS:
        au = "DSS";
        break;
    case SSL_aDH:
        au = "DH";
        break;
    case SSL_aKRB5:
        au = "KRB5";
        break;
    case SSL_aECDH:
        au = "ECDH";
        break;
    case SSL_aNULL:
        au = "None";
        break;
    case SSL_aECDSA:
        au = "ECDSA";
        break;
    case SSL_aPSK:
        au = "PSK";
        break;
    case SSL_aSRP:
        au = "SRP";
        break;
    case SSL_aGOST94:
        au = "GOST94";
        break;
    case SSL_aGOST01:
        au = "GOST01";
        break;
    default:
        au = "unknown";
        break;
    }

    switch (alg_enc) {
    case SSL_DES:
        enc = (is_export && kl == 5) ? "DES(40)" : "DES(56)";
        break;
    case SSL_3DES:
        enc = "3DES(168)";
        break;
    case SSL_RC4:
        enc = is_export ? (kl == 5 ? "RC4(40)" : "RC4(56)")
            : ((alg2 & SSL2_CF_8_BYTE_ENC) ? "RC4(64)" : "RC4(128)");
        break;
    case SSL_RC2:
        enc = is_export ? (kl == 5 ? "RC2(40)" : "RC2(56)") : "RC2(128)";
        break;
    case SSL_IDEA:
        enc = "IDEA(128)";
        break;
    case SSL_eNULL:
        enc = "None";
        break;
    case SSL_AES128:
        enc = "AES(128)";
        break;
    case SSL_AES256:
        enc = "AES(256)";
        break;
    case SSL_AES128GCM:
        enc = "AESGCM(128)";
        break;
    case SSL_AES256GCM:
        enc = "AESGCM(256)";
        break;
    case SSL_CAMELLIA128:
        enc = "Camellia(128)";
        break;
    case SSL_CAMELLIA256:
        enc = "Camellia(256)";
        break;
    case SSL_SEED:
        enc = "SEED(128)";
        break;
    case SSL_eGOST2814789CNT:
        enc = "GOST89(256)";
        break;
    default:
        enc = "unknown";
        break;
    }

    switch (alg_mac) {
    case SSL_MD5:
        mac = "MD5";
        break;
    case SSL_SHA1:
        mac = "SHA1";
        break;
    case SSL_SHA256:
        mac = "SHA256";
        break;
    case SSL_SHA384:
        mac = "SHA384";
        break;
    case SSL_AEAD:
        mac = "AEAD";
        break;
    case SSL_GOST89MAC:
        mac = "GOST89";
        break;
    case SSL_GOST94:
        mac = "GOST94";
        break;
    default:
        mac = "unknown";
        break;
    }

    if (buf == NULL) {
        len = 128;
        buf = OPENSSL_malloc(len);
        if (buf == NULL)
            return ("OPENSSL_malloc Error");
    } else if (len < 128)
        return ("Buffer too small");

#ifdef KSSL_DEBUG
    BIO_snprintf(buf, len, format, cipher->name, ver, kx, au, enc, mac,
                 exp_str, alg_mkey, alg_auth, alg_enc, alg_mac, alg_ssl);
#else
    BIO_snprintf(buf, len, format, cipher->name, ver, kx, au, enc, mac,
                 exp_str);
#endif                          /* KSSL_DEBUG */
    return (buf);
}

char *SSL_CIPHER_get_version(const SSL_CIPHER *c)
{
    int i;

    if (c == NULL)
        return ("(NONE)");
    i = (int)(c->id >> 24L);
    if (i == 3)
        return ("TLSv1/SSLv3");
    else if (i == 2)
        return ("SSLv2");
    else
        return ("unknown");
}

/* return the actual cipher being used */
const char *SSL_CIPHER_get_name(const SSL_CIPHER *c)
{
    if (c != NULL)
        return (c->name);
    return ("(NONE)");
}

/* number of bits for symmetric cipher */
int SSL_CIPHER_get_bits(const SSL_CIPHER *c, int *alg_bits)
{
    int ret = 0;

    if (c != NULL) {
        if (alg_bits != NULL)
            *alg_bits = c->alg_bits;
        ret = c->strength_bits;
    }
    return (ret);
}

unsigned long SSL_CIPHER_get_id(const SSL_CIPHER *c)
{
    return c->id;
}

SSL_COMP *ssl3_comp_find(STACK_OF(SSL_COMP) *sk, int n)
{
    SSL_COMP *ctmp;
    int i, nn;

    if ((n == 0) || (sk == NULL))
        return (NULL);
    nn = sk_SSL_COMP_num(sk);
    for (i = 0; i < nn; i++) {
        ctmp = sk_SSL_COMP_value(sk, i);
        if (ctmp->id == n)
            return (ctmp);
    }
    return (NULL);
}

#ifdef OPENSSL_NO_COMP
STACK_OF(SSL_COMP) *SSL_COMP_get_compression_methods(void)
{
    return NULL;
}

STACK_OF(SSL_COMP) *SSL_COMP_set0_compression_methods(STACK_OF(SSL_COMP)
                                                      *meths)
{
    return NULL;
}

void SSL_COMP_free_compression_methods(void)
{
}

int SSL_COMP_add_compression_method(int id, COMP_METHOD *cm)
{
    return 1;
}

const char *SSL_COMP_get_name(const COMP_METHOD *comp)
{
    return NULL;
}
#else
STACK_OF(SSL_COMP) *SSL_COMP_get_compression_methods(void)
{
    load_builtin_compressions();
    return (ssl_comp_methods);
}

STACK_OF(SSL_COMP) *SSL_COMP_set0_compression_methods(STACK_OF(SSL_COMP)
                                                      *meths)
{
    STACK_OF(SSL_COMP) *old_meths = ssl_comp_methods;
    ssl_comp_methods = meths;
    return old_meths;
}

static void cmeth_free(SSL_COMP *cm)
{
    OPENSSL_free(cm);
}

void SSL_COMP_free_compression_methods(void)
{
    STACK_OF(SSL_COMP) *old_meths = ssl_comp_methods;
    ssl_comp_methods = NULL;
    sk_SSL_COMP_pop_free(old_meths, cmeth_free);
}

int SSL_COMP_add_compression_method(int id, COMP_METHOD *cm)
{
    SSL_COMP *comp;

    if (cm == NULL || cm->type == NID_undef)
        return 1;

    /*-
     * According to draft-ietf-tls-compression-04.txt, the
     * compression number ranges should be the following:
     *
     *   0 to  63:  methods defined by the IETF
     *  64 to 192:  external party methods assigned by IANA
     * 193 to 255:  reserved for private use
     */
    if (id < 193 || id > 255) {
        SSLerr(SSL_F_SSL_COMP_ADD_COMPRESSION_METHOD,
               SSL_R_COMPRESSION_ID_NOT_WITHIN_PRIVATE_RANGE);
        return 1;
    }

    MemCheck_off();
    comp = (SSL_COMP *)OPENSSL_malloc(sizeof(SSL_COMP));
    if (comp == NULL) {
        MemCheck_on();
        SSLerr(SSL_F_SSL_COMP_ADD_COMPRESSION_METHOD, ERR_R_MALLOC_FAILURE);
        return 1;
    }
    comp->id = id;
    comp->method = cm;
    comp->name = cm->name;
    load_builtin_compressions();
    if (ssl_comp_methods && sk_SSL_COMP_find(ssl_comp_methods, comp) >= 0) {
        OPENSSL_free(comp);
        MemCheck_on();
        SSLerr(SSL_F_SSL_COMP_ADD_COMPRESSION_METHOD,
               SSL_R_DUPLICATE_COMPRESSION_ID);
        return (1);
    } else if ((ssl_comp_methods == NULL)
               || !sk_SSL_COMP_push(ssl_comp_methods, comp)) {
        OPENSSL_free(comp);
        MemCheck_on();
        SSLerr(SSL_F_SSL_COMP_ADD_COMPRESSION_METHOD, ERR_R_MALLOC_FAILURE);
        return (1);
    } else {
        MemCheck_on();
        return (0);
    }
}

const char *SSL_COMP_get_name(const COMP_METHOD *comp)
{
    if (comp)
        return comp->name;
    return NULL;
}
#endif
/* For a cipher return the index corresponding to the certificate type */
int ssl_cipher_get_cert_index(const SSL_CIPHER *c)
{
    unsigned long alg_k, alg_a;

    alg_k = c->algorithm_mkey;
    alg_a = c->algorithm_auth;

    if (alg_k & (SSL_kECDHr | SSL_kECDHe)) {
        /*
         * we don't need to look at SSL_kEECDH since no certificate is needed
         * for anon ECDH and for authenticated EECDH, the check for the auth
         * algorithm will set i correctly NOTE: For ECDH-RSA, we need an ECC
         * not an RSA cert but for EECDH-RSA we need an RSA cert. Placing the
         * checks for SSL_kECDH before RSA checks ensures the correct cert is
         * chosen.
         */
        return SSL_PKEY_ECC;
    } else if (alg_a & SSL_aECDSA)
        return SSL_PKEY_ECC;
    else if (alg_k & SSL_kDHr)
        return SSL_PKEY_DH_RSA;
    else if (alg_k & SSL_kDHd)
        return SSL_PKEY_DH_DSA;
    else if (alg_a & SSL_aDSS)
        return SSL_PKEY_DSA_SIGN;
    else if (alg_a & SSL_aRSA)
        return SSL_PKEY_RSA_ENC;
    else if (alg_a & SSL_aKRB5)
        /* VRS something else here? */
        return -1;
    else if (alg_a & SSL_aGOST94)
        return SSL_PKEY_GOST94;
    else if (alg_a & SSL_aGOST01)
        return SSL_PKEY_GOST01;
    return -1;
}

const SSL_CIPHER *ssl_get_cipher_by_char(SSL *ssl, const unsigned char *ptr)
{
    const SSL_CIPHER *c;
    c = ssl->method->get_cipher_by_char(ptr);
    if (c == NULL || c->valid == 0)
        return NULL;
    return c;
}

const SSL_CIPHER *SSL_CIPHER_find(SSL *ssl, const unsigned char *ptr)
{
    return ssl->method->get_cipher_by_char(ptr);
}
/*
 * ! \file ssl/ssl_conf.c \brief SSL configuration functions
 */
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

#ifdef REF_CHECK
# include <assert.h>
#endif
#include <stdio.h>
// #include "ssl_locl.h"
#include "conf.h"
// #include "objects.h"
#ifndef OPENSSL_NO_DH
# include "dh.h"
#endif

/*
 * structure holding name tables. This is used for pemitted elements in lists
 * such as TLSv1 and single command line switches such as no_tls1
 */

typedef struct {
    const char *name;
    int namelen;
    unsigned int name_flags;
    unsigned long option_value;
} ssl_flag_tbl;

/* Sense of name is inverted e.g. "TLSv1" will clear SSL_OP_NO_TLSv1 */
#define SSL_TFLAG_INV   0x1
/* Flags refers to cert_flags not options */
#define SSL_TFLAG_CERT  0x2
/* Option can only be used for clients */
#define SSL_TFLAG_CLIENT SSL_CONF_FLAG_CLIENT
/* Option can only be used for servers */
#define SSL_TFLAG_SERVER SSL_CONF_FLAG_SERVER
#define SSL_TFLAG_BOTH (SSL_TFLAG_CLIENT|SSL_TFLAG_SERVER)

#define SSL_FLAG_TBL(str, flag) \
        {str, (int)(sizeof(str) - 1), SSL_TFLAG_BOTH, flag}
#define SSL_FLAG_TBL_SRV(str, flag) \
        {str, (int)(sizeof(str) - 1), SSL_TFLAG_SERVER, flag}
#define SSL_FLAG_TBL_CLI(str, flag) \
        {str, (int)(sizeof(str) - 1), SSL_TFLAG_CLIENT, flag}
#define SSL_FLAG_TBL_INV(str, flag) \
        {str, (int)(sizeof(str) - 1), SSL_TFLAG_INV|SSL_TFLAG_BOTH, flag}
#define SSL_FLAG_TBL_SRV_INV(str, flag) \
        {str, (int)(sizeof(str) - 1), SSL_TFLAG_INV|SSL_TFLAG_SERVER, flag}
#define SSL_FLAG_TBL_CERT(str, flag) \
        {str, (int)(sizeof(str) - 1), SSL_TFLAG_CERT|SSL_TFLAG_BOTH, flag}

/*
 * Opaque structure containing SSL configuration context.
 */

struct ssl_conf_ctx_st {
    /*
     * Various flags indicating (among other things) which options we will
     * recognise.
     */
    unsigned int flags;
    /* Prefix and length of commands */
    char *prefix;
    size_t prefixlen;
    /* SSL_CTX or SSL structure to perform operations on */
    SSL_CTX *ctx;
    SSL *ssl;
    /* Pointer to SSL or SSL_CTX options field or NULL if none */
    unsigned long *poptions;
    /* Pointer to SSL or SSL_CTX cert_flags or NULL if none */
    unsigned int *pcert_flags;
    /* Current flag table being worked on */
    const ssl_flag_tbl *tbl;
    /* Size of table */
    size_t ntbl;
};

static int ssl_match_option(SSL_CONF_CTX *cctx, const ssl_flag_tbl *tbl,
                            const char *name, int namelen, int onoff)
{
    /* If name not relevant for context skip */
    if (!(cctx->flags & tbl->name_flags & SSL_TFLAG_BOTH))
        return 0;
    if (namelen == -1) {
        if (strcmp(tbl->name, name))
            return 0;
    } else if (tbl->namelen != namelen
               || strncasecmp(tbl->name, name, namelen))
        return 0;
    if (cctx->poptions) {
        if (tbl->name_flags & SSL_TFLAG_INV)
            onoff ^= 1;
        if (tbl->name_flags & SSL_TFLAG_CERT) {
            if (onoff)
                *cctx->pcert_flags |= tbl->option_value;
            else
                *cctx->pcert_flags &= ~tbl->option_value;
        } else {
            if (onoff)
                *cctx->poptions |= tbl->option_value;
            else
                *cctx->poptions &= ~tbl->option_value;
        }
    }
    return 1;
}

static int ssl_set_option_list(const char *elem, int len, void *usr)
{
    SSL_CONF_CTX *cctx = usr;
    size_t i;
    const ssl_flag_tbl *tbl;
    int onoff = 1;
    /*
     * len == -1 indicates not being called in list context, just for single
     * command line switches, so don't allow +, -.
     */
    if (elem == NULL)
        return 0;
    if (len != -1) {
        if (*elem == '+') {
            elem++;
            len--;
            onoff = 1;
        } else if (*elem == '-') {
            elem++;
            len--;
            onoff = 0;
        }
    }
    for (i = 0, tbl = cctx->tbl; i < cctx->ntbl; i++, tbl++) {
        if (ssl_match_option(cctx, tbl, elem, len, onoff))
            return 1;
    }
    return 0;
}

/* Single command line switches with no argument e.g. -no_ssl3 */
static int ctrl_str_option(SSL_CONF_CTX *cctx, const char *cmd)
{
    static const ssl_flag_tbl ssl_option_single[] = {
        SSL_FLAG_TBL("no_ssl2", SSL_OP_NO_SSLv2),
        SSL_FLAG_TBL("no_ssl3", SSL_OP_NO_SSLv3),
        SSL_FLAG_TBL("no_tls1", SSL_OP_NO_TLSv1),
        SSL_FLAG_TBL("no_tls1_1", SSL_OP_NO_TLSv1_1),
        SSL_FLAG_TBL("no_tls1_2", SSL_OP_NO_TLSv1_2),
        SSL_FLAG_TBL("bugs", SSL_OP_ALL),
        SSL_FLAG_TBL("no_comp", SSL_OP_NO_COMPRESSION),
        SSL_FLAG_TBL_SRV("ecdh_single", SSL_OP_SINGLE_ECDH_USE),
#ifndef OPENSSL_NO_TLSEXT
        SSL_FLAG_TBL("no_ticket", SSL_OP_NO_TICKET),
#endif
        SSL_FLAG_TBL_SRV("serverpref", SSL_OP_CIPHER_SERVER_PREFERENCE),
        SSL_FLAG_TBL("legacy_renegotiation",
                     SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION),
        SSL_FLAG_TBL_SRV("legacy_server_connect",
                         SSL_OP_LEGACY_SERVER_CONNECT),
        SSL_FLAG_TBL_SRV("no_resumption_on_reneg",
                         SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION),
        SSL_FLAG_TBL_SRV_INV("no_legacy_server_connect",
                             SSL_OP_LEGACY_SERVER_CONNECT),
        SSL_FLAG_TBL_CERT("strict", SSL_CERT_FLAG_TLS_STRICT),
#ifdef OPENSSL_SSL_DEBUG_BROKEN_PROTOCOL
        SSL_FLAG_TBL_CERT("debug_broken_protocol",
                          SSL_CERT_FLAG_BROKEN_PROTOCOL),
#endif
    };
    cctx->tbl = ssl_option_single;
    cctx->ntbl = sizeof(ssl_option_single) / sizeof(ssl_flag_tbl);
    return ssl_set_option_list(cmd, -1, cctx);
}

/* Set supported signature algorithms */
static int cmd_SignatureAlgorithms(SSL_CONF_CTX *cctx, const char *value)
{
    int rv;
    if (cctx->ssl)
        rv = SSL_set1_sigalgs_list(cctx->ssl, value);
    /* NB: ctx == NULL performs syntax checking only */
    else
        rv = SSL_CTX_set1_sigalgs_list(cctx->ctx, value);
    return rv > 0;
}

/* Set supported client signature algorithms */
static int cmd_ClientSignatureAlgorithms(SSL_CONF_CTX *cctx,
                                         const char *value)
{
    int rv;
    if (cctx->ssl)
        rv = SSL_set1_client_sigalgs_list(cctx->ssl, value);
    /* NB: ctx == NULL performs syntax checking only */
    else
        rv = SSL_CTX_set1_client_sigalgs_list(cctx->ctx, value);
    return rv > 0;
}

static int cmd_Curves(SSL_CONF_CTX *cctx, const char *value)
{
    int rv;
    if (cctx->ssl)
        rv = SSL_set1_curves_list(cctx->ssl, value);
    /* NB: ctx == NULL performs syntax checking only */
    else
        rv = SSL_CTX_set1_curves_list(cctx->ctx, value);
    return rv > 0;
}

#ifndef OPENSSL_NO_ECDH
/* ECDH temporary parameters */
static int cmd_ECDHParameters(SSL_CONF_CTX *cctx, const char *value)
{
    int onoff = -1, rv = 1;
    if (!(cctx->flags & SSL_CONF_FLAG_SERVER))
        return -2;
    if (cctx->flags & SSL_CONF_FLAG_FILE) {
        if (*value == '+') {
            onoff = 1;
            value++;
        }
        if (*value == '-') {
            onoff = 0;
            value++;
        }
        if (!strcasecmp(value, "automatic")) {
            if (onoff == -1)
                onoff = 1;
        } else if (onoff != -1)
            return 0;
    } else if (cctx->flags & SSL_CONF_FLAG_CMDLINE) {
        if (!strcmp(value, "auto"))
            onoff = 1;
    }

    if (onoff != -1) {
        if (cctx->ctx)
            rv = SSL_CTX_set_ecdh_auto(cctx->ctx, onoff);
        else if (cctx->ssl)
            rv = SSL_set_ecdh_auto(cctx->ssl, onoff);
    } else {
        EC_KEY *ecdh;
        int nid;
        nid = EC_curve_nist2nid(value);
        if (nid == NID_undef)
            nid = OBJ_sn2nid(value);
        if (nid == 0)
            return 0;
        ecdh = EC_KEY_new_by_curve_name(nid);
        if (!ecdh)
            return 0;
        if (cctx->ctx)
            rv = SSL_CTX_set_tmp_ecdh(cctx->ctx, ecdh);
        else if (cctx->ssl)
            rv = SSL_set_tmp_ecdh(cctx->ssl, ecdh);
        EC_KEY_free(ecdh);
    }

    return rv > 0;
}
#endif
static int cmd_CipherString(SSL_CONF_CTX *cctx, const char *value)
{
    int rv = 1;
    if (cctx->ctx)
        rv = SSL_CTX_set_cipher_list(cctx->ctx, value);
    if (cctx->ssl)
        rv = SSL_set_cipher_list(cctx->ssl, value);
    return rv > 0;
}

static int cmd_Protocol(SSL_CONF_CTX *cctx, const char *value)
{
    static const ssl_flag_tbl ssl_protocol_list[] = {
        SSL_FLAG_TBL_INV("ALL", SSL_OP_NO_SSL_MASK),
        SSL_FLAG_TBL_INV("SSLv2", SSL_OP_NO_SSLv2),
        SSL_FLAG_TBL_INV("SSLv3", SSL_OP_NO_SSLv3),
        SSL_FLAG_TBL_INV("TLSv1", SSL_OP_NO_TLSv1),
        SSL_FLAG_TBL_INV("TLSv1.1", SSL_OP_NO_TLSv1_1),
        SSL_FLAG_TBL_INV("TLSv1.2", SSL_OP_NO_TLSv1_2)
    };
    int ret;
    int sslv2off;

    if (!(cctx->flags & SSL_CONF_FLAG_FILE))
        return -2;
    cctx->tbl = ssl_protocol_list;
    cctx->ntbl = sizeof(ssl_protocol_list) / sizeof(ssl_flag_tbl);

    sslv2off = *cctx->poptions & SSL_OP_NO_SSLv2;
    ret = CONF_parse_list(value, ',', 1, ssl_set_option_list, cctx);
    /* Never turn on SSLv2 through configuration */
    *cctx->poptions |= sslv2off;
    return ret;
}

static int cmd_Options(SSL_CONF_CTX *cctx, const char *value)
{
    static const ssl_flag_tbl ssl_option_list[] = {
        SSL_FLAG_TBL_INV("SessionTicket", SSL_OP_NO_TICKET),
        SSL_FLAG_TBL_INV("EmptyFragments",
                         SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS),
        SSL_FLAG_TBL("Bugs", SSL_OP_ALL),
        SSL_FLAG_TBL_INV("Compression", SSL_OP_NO_COMPRESSION),
        SSL_FLAG_TBL_SRV("ServerPreference", SSL_OP_CIPHER_SERVER_PREFERENCE),
        SSL_FLAG_TBL_SRV("NoResumptionOnRenegotiation",
                         SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION),
        SSL_FLAG_TBL_SRV("DHSingle", SSL_OP_SINGLE_DH_USE),
        SSL_FLAG_TBL_SRV("ECDHSingle", SSL_OP_SINGLE_ECDH_USE),
        SSL_FLAG_TBL("UnsafeLegacyRenegotiation",
                     SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION),
    };
    if (!(cctx->flags & SSL_CONF_FLAG_FILE))
        return -2;
    if (value == NULL)
        return -3;
    cctx->tbl = ssl_option_list;
    cctx->ntbl = sizeof(ssl_option_list) / sizeof(ssl_flag_tbl);
    return CONF_parse_list(value, ',', 1, ssl_set_option_list, cctx);
}

static int cmd_Certificate(SSL_CONF_CTX *cctx, const char *value)
{
    int rv = 1;
    if (!(cctx->flags & SSL_CONF_FLAG_CERTIFICATE))
        return -2;
    if (cctx->ctx)
        rv = SSL_CTX_use_certificate_chain_file(cctx->ctx, value);
    if (cctx->ssl)
        rv = SSL_use_certificate_file(cctx->ssl, value, SSL_FILETYPE_PEM);
    return rv > 0;
}

static int cmd_PrivateKey(SSL_CONF_CTX *cctx, const char *value)
{
    int rv = 1;
    if (!(cctx->flags & SSL_CONF_FLAG_CERTIFICATE))
        return -2;
    if (cctx->ctx)
        rv = SSL_CTX_use_PrivateKey_file(cctx->ctx, value, SSL_FILETYPE_PEM);
    if (cctx->ssl)
        rv = SSL_use_PrivateKey_file(cctx->ssl, value, SSL_FILETYPE_PEM);
    return rv > 0;
}

static int cmd_ServerInfoFile(SSL_CONF_CTX *cctx, const char *value)
{
    int rv = 1;
    if (!(cctx->flags & SSL_CONF_FLAG_CERTIFICATE))
        return -2;
    if (!(cctx->flags & SSL_CONF_FLAG_SERVER))
        return -2;
    if (cctx->ctx)
        rv = SSL_CTX_use_serverinfo_file(cctx->ctx, value);
    return rv > 0;
}

#ifndef OPENSSL_NO_DH
static int cmd_DHParameters(SSL_CONF_CTX *cctx, const char *value)
{
    int rv = 0;
    DH *dh = NULL;
    BIO *in = NULL;
    if (!(cctx->flags & SSL_CONF_FLAG_CERTIFICATE))
        return -2;
    if (cctx->ctx || cctx->ssl) {
        in = BIO_new(BIO_s_file_internal());
        if (!in)
            goto end;
        if (BIO_read_filename(in, value) <= 0)
            goto end;
        dh = PEM_read_bio_DHparams(in, NULL, NULL, NULL);
        if (!dh)
            goto end;
    } else
        return 1;
    if (cctx->ctx)
        rv = SSL_CTX_set_tmp_dh(cctx->ctx, dh);
    if (cctx->ssl)
        rv = SSL_set_tmp_dh(cctx->ssl, dh);
 end:
    if (dh)
        DH_free(dh);
    if (in)
        BIO_free(in);
    return rv > 0;
}
#endif
typedef struct {
    int (*cmd) (SSL_CONF_CTX *cctx, const char *value);
    const char *str_file;
    const char *str_cmdline;
    unsigned int value_type;
} ssl_conf_cmd_tbl;

/* Table of supported parameters */

#define SSL_CONF_CMD(name, cmdopt, type) \
        {cmd_##name, #name, cmdopt, type}

#define SSL_CONF_CMD_STRING(name, cmdopt) \
        SSL_CONF_CMD(name, cmdopt, SSL_CONF_TYPE_STRING)

static const ssl_conf_cmd_tbl ssl_conf_cmds[] = {
    SSL_CONF_CMD_STRING(SignatureAlgorithms, "sigalgs"),
    SSL_CONF_CMD_STRING(ClientSignatureAlgorithms, "client_sigalgs"),
    SSL_CONF_CMD_STRING(Curves, "curves"),
#ifndef OPENSSL_NO_ECDH
    SSL_CONF_CMD_STRING(ECDHParameters, "named_curve"),
#endif
    SSL_CONF_CMD_STRING(CipherString, "cipher"),
    SSL_CONF_CMD_STRING(Protocol, NULL),
    SSL_CONF_CMD_STRING(Options, NULL),
    SSL_CONF_CMD(Certificate, "cert", SSL_CONF_TYPE_FILE),
    SSL_CONF_CMD(PrivateKey, "key", SSL_CONF_TYPE_FILE),
    SSL_CONF_CMD(ServerInfoFile, NULL, SSL_CONF_TYPE_FILE),
#ifndef OPENSSL_NO_DH
    SSL_CONF_CMD(DHParameters, "dhparam", SSL_CONF_TYPE_FILE)
#endif
};

static int ssl_conf_cmd_skip_prefix(SSL_CONF_CTX *cctx, const char **pcmd)
{
    if (!pcmd || !*pcmd)
        return 0;
    /* If a prefix is set, check and skip */
    if (cctx->prefix) {
        if (strlen(*pcmd) <= cctx->prefixlen)
            return 0;
        if (cctx->flags & SSL_CONF_FLAG_CMDLINE &&
            strncmp(*pcmd, cctx->prefix, cctx->prefixlen))
            return 0;
        if (cctx->flags & SSL_CONF_FLAG_FILE &&
            strncasecmp(*pcmd, cctx->prefix, cctx->prefixlen))
            return 0;
        *pcmd += cctx->prefixlen;
    } else if (cctx->flags & SSL_CONF_FLAG_CMDLINE) {
        if (**pcmd != '-' || !(*pcmd)[1])
            return 0;
        *pcmd += 1;
    }
    return 1;
}

static const ssl_conf_cmd_tbl *ssl_conf_cmd_lookup(SSL_CONF_CTX *cctx,
                                                   const char *cmd)
{
    const ssl_conf_cmd_tbl *t;
    size_t i;
    if (cmd == NULL)
        return NULL;

    /* Look for matching parameter name in table */
    for (i = 0, t = ssl_conf_cmds;
         i < sizeof(ssl_conf_cmds) / sizeof(ssl_conf_cmd_tbl); i++, t++) {
        if (cctx->flags & SSL_CONF_FLAG_CMDLINE) {
            if (t->str_cmdline && !strcmp(t->str_cmdline, cmd))
                return t;
        }
        if (cctx->flags & SSL_CONF_FLAG_FILE) {
            if (t->str_file && !strcasecmp(t->str_file, cmd))
                return t;
        }
    }
    return NULL;
}

int SSL_CONF_cmd(SSL_CONF_CTX *cctx, const char *cmd, const char *value)
{
    const ssl_conf_cmd_tbl *runcmd;
    if (cmd == NULL) {
        SSLerr(SSL_F_SSL_CONF_CMD, SSL_R_INVALID_NULL_CMD_NAME);
        return 0;
    }

    if (!ssl_conf_cmd_skip_prefix(cctx, &cmd))
        return -2;

    runcmd = ssl_conf_cmd_lookup(cctx, cmd);

    if (runcmd) {
        int rv;
        if (value == NULL)
            return -3;
        rv = runcmd->cmd(cctx, value);
        if (rv > 0)
            return 2;
        if (rv == -2)
            return -2;
        if (cctx->flags & SSL_CONF_FLAG_SHOW_ERRORS) {
            SSLerr(SSL_F_SSL_CONF_CMD, SSL_R_BAD_VALUE);
            ERR_add_error_data(4, "cmd=", cmd, ", value=", value);
        }
        return 0;
    }

    if (cctx->flags & SSL_CONF_FLAG_CMDLINE) {
        if (ctrl_str_option(cctx, cmd))
            return 1;
    }

    if (cctx->flags & SSL_CONF_FLAG_SHOW_ERRORS) {
        SSLerr(SSL_F_SSL_CONF_CMD, SSL_R_UNKNOWN_CMD_NAME);
        ERR_add_error_data(2, "cmd=", cmd);
    }

    return -2;
}

int SSL_CONF_cmd_argv(SSL_CONF_CTX *cctx, int *pargc, char ***pargv)
{
    int rv;
    const char *arg = NULL, *argn;
    if (pargc && *pargc == 0)
        return 0;
    if (!pargc || *pargc > 0)
        arg = **pargv;
    if (arg == NULL)
        return 0;
    if (!pargc || *pargc > 1)
        argn = (*pargv)[1];
    else
        argn = NULL;
    cctx->flags &= ~SSL_CONF_FLAG_FILE;
    cctx->flags |= SSL_CONF_FLAG_CMDLINE;
    rv = SSL_CONF_cmd(cctx, arg, argn);
    if (rv > 0) {
        /* Success: update pargc, pargv */
        (*pargv) += rv;
        if (pargc)
            (*pargc) -= rv;
        return rv;
    }
    /* Unknown switch: indicate no arguments processed */
    if (rv == -2)
        return 0;
    /* Some error occurred processing command, return fatal error */
    if (rv == 0)
        return -1;
    return rv;
}

int SSL_CONF_cmd_value_type(SSL_CONF_CTX *cctx, const char *cmd)
{
    if (ssl_conf_cmd_skip_prefix(cctx, &cmd)) {
        const ssl_conf_cmd_tbl *runcmd;
        runcmd = ssl_conf_cmd_lookup(cctx, cmd);
        if (runcmd)
            return runcmd->value_type;
    }
    return SSL_CONF_TYPE_UNKNOWN;
}

SSL_CONF_CTX *SSL_CONF_CTX_new(void)
{
    SSL_CONF_CTX *ret;
    ret = OPENSSL_malloc(sizeof(SSL_CONF_CTX));
    if (ret) {
        ret->flags = 0;
        ret->prefix = NULL;
        ret->prefixlen = 0;
        ret->ssl = NULL;
        ret->ctx = NULL;
        ret->poptions = NULL;
        ret->pcert_flags = NULL;
        ret->tbl = NULL;
        ret->ntbl = 0;
    }
    return ret;
}

int SSL_CONF_CTX_finish(SSL_CONF_CTX *cctx)
{
    return 1;
}

void SSL_CONF_CTX_free(SSL_CONF_CTX *cctx)
{
    if (cctx) {
        if (cctx->prefix)
            OPENSSL_free(cctx->prefix);
        OPENSSL_free(cctx);
    }
}

unsigned int SSL_CONF_CTX_set_flags(SSL_CONF_CTX *cctx, unsigned int flags)
{
    cctx->flags |= flags;
    return cctx->flags;
}

unsigned int SSL_CONF_CTX_clear_flags(SSL_CONF_CTX *cctx, unsigned int flags)
{
    cctx->flags &= ~flags;
    return cctx->flags;
}

int SSL_CONF_CTX_set1_prefix(SSL_CONF_CTX *cctx, const char *pre)
{
    char *tmp = NULL;
    if (pre) {
        tmp = BUF_strdup(pre);
        if (tmp == NULL)
            return 0;
    }
    if (cctx->prefix)
        OPENSSL_free(cctx->prefix);
    cctx->prefix = tmp;
    if (tmp)
        cctx->prefixlen = strlen(tmp);
    else
        cctx->prefixlen = 0;
    return 1;
}

void SSL_CONF_CTX_set_ssl(SSL_CONF_CTX *cctx, SSL *ssl)
{
    cctx->ssl = ssl;
    cctx->ctx = NULL;
    if (ssl) {
        cctx->poptions = &ssl->options;
        cctx->pcert_flags = &ssl->cert->cert_flags;
    } else {
        cctx->poptions = NULL;
        cctx->pcert_flags = NULL;
    }
}

void SSL_CONF_CTX_set_ssl_ctx(SSL_CONF_CTX *cctx, SSL_CTX *ctx)
{
    cctx->ctx = ctx;
    cctx->ssl = NULL;
    if (ctx) {
        cctx->poptions = &ctx->options;
        cctx->pcert_flags = &ctx->cert->cert_flags;
    } else {
        cctx->poptions = NULL;
        cctx->pcert_flags = NULL;
    }
}
/* ssl/ssl_err.c */
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
#include "ssl.h"

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

# define ERR_FUNC(func) ERR_PACK(ERR_LIB_SSL,func,0)
# define ERR_REASON(reason) ERR_PACK(ERR_LIB_SSL,0,reason)

static ERR_STRING_DATA SSL_str_functs[] = {
    {ERR_FUNC(SSL_F_CHECK_SUITEB_CIPHER_LIST), "CHECK_SUITEB_CIPHER_LIST"},
    {ERR_FUNC(SSL_F_CLIENT_CERTIFICATE), "CLIENT_CERTIFICATE"},
    {ERR_FUNC(SSL_F_CLIENT_FINISHED), "CLIENT_FINISHED"},
    {ERR_FUNC(SSL_F_CLIENT_HELLO), "CLIENT_HELLO"},
    {ERR_FUNC(SSL_F_CLIENT_MASTER_KEY), "CLIENT_MASTER_KEY"},
    {ERR_FUNC(SSL_F_D2I_SSL_SESSION), "d2i_SSL_SESSION"},
    {ERR_FUNC(SSL_F_DO_DTLS1_WRITE), "do_dtls1_write"},
    {ERR_FUNC(SSL_F_DO_SSL3_WRITE), "DO_SSL3_WRITE"},
    {ERR_FUNC(SSL_F_DTLS1_ACCEPT), "dtls1_accept"},
    {ERR_FUNC(SSL_F_DTLS1_ADD_CERT_TO_BUF), "DTLS1_ADD_CERT_TO_BUF"},
    {ERR_FUNC(SSL_F_DTLS1_BUFFER_RECORD), "DTLS1_BUFFER_RECORD"},
    {ERR_FUNC(SSL_F_DTLS1_CHECK_TIMEOUT_NUM), "dtls1_check_timeout_num"},
    {ERR_FUNC(SSL_F_DTLS1_CLIENT_HELLO), "dtls1_client_hello"},
    {ERR_FUNC(SSL_F_DTLS1_CONNECT), "dtls1_connect"},
    {ERR_FUNC(SSL_F_DTLS1_GET_HELLO_VERIFY), "DTLS1_GET_HELLO_VERIFY"},
    {ERR_FUNC(SSL_F_DTLS1_GET_MESSAGE), "dtls1_get_message"},
    {ERR_FUNC(SSL_F_DTLS1_GET_MESSAGE_FRAGMENT),
     "DTLS1_GET_MESSAGE_FRAGMENT"},
    {ERR_FUNC(SSL_F_DTLS1_GET_RECORD), "dtls1_get_record"},
    {ERR_FUNC(SSL_F_DTLS1_HANDLE_TIMEOUT), "dtls1_handle_timeout"},
    {ERR_FUNC(SSL_F_DTLS1_HEARTBEAT), "dtls1_heartbeat"},
    {ERR_FUNC(SSL_F_DTLS1_OUTPUT_CERT_CHAIN), "dtls1_output_cert_chain"},
    {ERR_FUNC(SSL_F_DTLS1_PREPROCESS_FRAGMENT), "DTLS1_PREPROCESS_FRAGMENT"},
    {ERR_FUNC(SSL_F_DTLS1_PROCESS_BUFFERED_RECORDS),
     "DTLS1_PROCESS_BUFFERED_RECORDS"},
    {ERR_FUNC(SSL_F_DTLS1_PROCESS_OUT_OF_SEQ_MESSAGE),
     "DTLS1_PROCESS_OUT_OF_SEQ_MESSAGE"},
    {ERR_FUNC(SSL_F_DTLS1_PROCESS_RECORD), "DTLS1_PROCESS_RECORD"},
    {ERR_FUNC(SSL_F_DTLS1_READ_BYTES), "dtls1_read_bytes"},
    {ERR_FUNC(SSL_F_DTLS1_READ_FAILED), "dtls1_read_failed"},
    {ERR_FUNC(SSL_F_DTLS1_SEND_CERTIFICATE_REQUEST),
     "dtls1_send_certificate_request"},
    {ERR_FUNC(SSL_F_DTLS1_SEND_CLIENT_CERTIFICATE),
     "dtls1_send_client_certificate"},
    {ERR_FUNC(SSL_F_DTLS1_SEND_CLIENT_KEY_EXCHANGE),
     "dtls1_send_client_key_exchange"},
    {ERR_FUNC(SSL_F_DTLS1_SEND_CLIENT_VERIFY), "dtls1_send_client_verify"},
    {ERR_FUNC(SSL_F_DTLS1_SEND_HELLO_VERIFY_REQUEST),
     "DTLS1_SEND_HELLO_VERIFY_REQUEST"},
    {ERR_FUNC(SSL_F_DTLS1_SEND_SERVER_CERTIFICATE),
     "dtls1_send_server_certificate"},
    {ERR_FUNC(SSL_F_DTLS1_SEND_SERVER_HELLO), "dtls1_send_server_hello"},
    {ERR_FUNC(SSL_F_DTLS1_SEND_SERVER_KEY_EXCHANGE),
     "dtls1_send_server_key_exchange"},
    {ERR_FUNC(SSL_F_DTLS1_WRITE_APP_DATA_BYTES),
     "dtls1_write_app_data_bytes"},
    {ERR_FUNC(SSL_F_GET_CLIENT_FINISHED), "GET_CLIENT_FINISHED"},
    {ERR_FUNC(SSL_F_GET_CLIENT_HELLO), "GET_CLIENT_HELLO"},
    {ERR_FUNC(SSL_F_GET_CLIENT_MASTER_KEY), "GET_CLIENT_MASTER_KEY"},
    {ERR_FUNC(SSL_F_GET_SERVER_FINISHED), "GET_SERVER_FINISHED"},
    {ERR_FUNC(SSL_F_GET_SERVER_HELLO), "GET_SERVER_HELLO"},
    {ERR_FUNC(SSL_F_GET_SERVER_STATIC_DH_KEY), "GET_SERVER_STATIC_DH_KEY"},
    {ERR_FUNC(SSL_F_GET_SERVER_VERIFY), "GET_SERVER_VERIFY"},
    {ERR_FUNC(SSL_F_I2D_SSL_SESSION), "i2d_SSL_SESSION"},
    {ERR_FUNC(SSL_F_READ_N), "READ_N"},
    {ERR_FUNC(SSL_F_REQUEST_CERTIFICATE), "REQUEST_CERTIFICATE"},
    {ERR_FUNC(SSL_F_SERVER_FINISH), "SERVER_FINISH"},
    {ERR_FUNC(SSL_F_SERVER_HELLO), "SERVER_HELLO"},
    {ERR_FUNC(SSL_F_SERVER_VERIFY), "SERVER_VERIFY"},
    {ERR_FUNC(SSL_F_SSL23_ACCEPT), "ssl23_accept"},
    {ERR_FUNC(SSL_F_SSL23_CLIENT_HELLO), "SSL23_CLIENT_HELLO"},
    {ERR_FUNC(SSL_F_SSL23_CONNECT), "ssl23_connect"},
    {ERR_FUNC(SSL_F_SSL23_GET_CLIENT_HELLO), "SSL23_GET_CLIENT_HELLO"},
    {ERR_FUNC(SSL_F_SSL23_GET_SERVER_HELLO), "SSL23_GET_SERVER_HELLO"},
    {ERR_FUNC(SSL_F_SSL23_PEEK), "ssl23_peek"},
    {ERR_FUNC(SSL_F_SSL23_READ), "ssl23_read"},
    {ERR_FUNC(SSL_F_SSL23_WRITE), "ssl23_write"},
    {ERR_FUNC(SSL_F_SSL2_ACCEPT), "ssl2_accept"},
    {ERR_FUNC(SSL_F_SSL2_CONNECT), "ssl2_connect"},
    {ERR_FUNC(SSL_F_SSL2_ENC_INIT), "ssl2_enc_init"},
    {ERR_FUNC(SSL_F_SSL2_GENERATE_KEY_MATERIAL),
     "ssl2_generate_key_material"},
    {ERR_FUNC(SSL_F_SSL2_PEEK), "ssl2_peek"},
    {ERR_FUNC(SSL_F_SSL2_READ), "ssl2_read"},
    {ERR_FUNC(SSL_F_SSL2_READ_INTERNAL), "SSL2_READ_INTERNAL"},
    {ERR_FUNC(SSL_F_SSL2_SET_CERTIFICATE), "ssl2_set_certificate"},
    {ERR_FUNC(SSL_F_SSL2_WRITE), "ssl2_write"},
    {ERR_FUNC(SSL_F_SSL3_ACCEPT), "ssl3_accept"},
    {ERR_FUNC(SSL_F_SSL3_ADD_CERT_TO_BUF), "SSL3_ADD_CERT_TO_BUF"},
    {ERR_FUNC(SSL_F_SSL3_CALLBACK_CTRL), "ssl3_callback_ctrl"},
    {ERR_FUNC(SSL_F_SSL3_CHANGE_CIPHER_STATE), "ssl3_change_cipher_state"},
    {ERR_FUNC(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM),
     "ssl3_check_cert_and_algorithm"},
    {ERR_FUNC(SSL_F_SSL3_CHECK_CLIENT_HELLO), "ssl3_check_client_hello"},
    {ERR_FUNC(SSL_F_SSL3_CHECK_FINISHED), "SSL3_CHECK_FINISHED"},
    {ERR_FUNC(SSL_F_SSL3_CLIENT_HELLO), "ssl3_client_hello"},
    {ERR_FUNC(SSL_F_SSL3_CONNECT), "ssl3_connect"},
    {ERR_FUNC(SSL_F_SSL3_CTRL), "ssl3_ctrl"},
    {ERR_FUNC(SSL_F_SSL3_CTX_CTRL), "ssl3_ctx_ctrl"},
    {ERR_FUNC(SSL_F_SSL3_DIGEST_CACHED_RECORDS),
     "ssl3_digest_cached_records"},
    {ERR_FUNC(SSL_F_SSL3_DO_CHANGE_CIPHER_SPEC),
     "ssl3_do_change_cipher_spec"},
    {ERR_FUNC(SSL_F_SSL3_ENC), "ssl3_enc"},
    {ERR_FUNC(SSL_F_SSL3_GENERATE_KEY_BLOCK), "SSL3_GENERATE_KEY_BLOCK"},
    {ERR_FUNC(SSL_F_SSL3_GENERATE_MASTER_SECRET),
     "ssl3_generate_master_secret"},
    {ERR_FUNC(SSL_F_SSL3_GET_CERTIFICATE_REQUEST),
     "ssl3_get_certificate_request"},
    {ERR_FUNC(SSL_F_SSL3_GET_CERT_STATUS), "ssl3_get_cert_status"},
    {ERR_FUNC(SSL_F_SSL3_GET_CERT_VERIFY), "ssl3_get_cert_verify"},
    {ERR_FUNC(SSL_F_SSL3_GET_CLIENT_CERTIFICATE),
     "ssl3_get_client_certificate"},
    {ERR_FUNC(SSL_F_SSL3_GET_CLIENT_HELLO), "ssl3_get_client_hello"},
    {ERR_FUNC(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE),
     "ssl3_get_client_key_exchange"},
    {ERR_FUNC(SSL_F_SSL3_GET_FINISHED), "ssl3_get_finished"},
    {ERR_FUNC(SSL_F_SSL3_GET_KEY_EXCHANGE), "ssl3_get_key_exchange"},
    {ERR_FUNC(SSL_F_SSL3_GET_MESSAGE), "ssl3_get_message"},
    {ERR_FUNC(SSL_F_SSL3_GET_NEW_SESSION_TICKET),
     "ssl3_get_new_session_ticket"},
    {ERR_FUNC(SSL_F_SSL3_GET_NEXT_PROTO), "ssl3_get_next_proto"},
    {ERR_FUNC(SSL_F_SSL3_GET_RECORD), "SSL3_GET_RECORD"},
    {ERR_FUNC(SSL_F_SSL3_GET_SERVER_CERTIFICATE),
     "ssl3_get_server_certificate"},
    {ERR_FUNC(SSL_F_SSL3_GET_SERVER_DONE), "ssl3_get_server_done"},
    {ERR_FUNC(SSL_F_SSL3_GET_SERVER_HELLO), "ssl3_get_server_hello"},
    {ERR_FUNC(SSL_F_SSL3_HANDSHAKE_MAC), "ssl3_handshake_mac"},
    {ERR_FUNC(SSL_F_SSL3_NEW_SESSION_TICKET), "SSL3_NEW_SESSION_TICKET"},
    {ERR_FUNC(SSL_F_SSL3_OUTPUT_CERT_CHAIN), "ssl3_output_cert_chain"},
    {ERR_FUNC(SSL_F_SSL3_PEEK), "ssl3_peek"},
    {ERR_FUNC(SSL_F_SSL3_READ_BYTES), "ssl3_read_bytes"},
    {ERR_FUNC(SSL_F_SSL3_READ_N), "ssl3_read_n"},
    {ERR_FUNC(SSL_F_SSL3_SEND_CERTIFICATE_REQUEST),
     "ssl3_send_certificate_request"},
    {ERR_FUNC(SSL_F_SSL3_SEND_CLIENT_CERTIFICATE),
     "ssl3_send_client_certificate"},
    {ERR_FUNC(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE),
     "ssl3_send_client_key_exchange"},
    {ERR_FUNC(SSL_F_SSL3_SEND_CLIENT_VERIFY), "ssl3_send_client_verify"},
    {ERR_FUNC(SSL_F_SSL3_SEND_SERVER_CERTIFICATE),
     "ssl3_send_server_certificate"},
    {ERR_FUNC(SSL_F_SSL3_SEND_SERVER_HELLO), "ssl3_send_server_hello"},
    {ERR_FUNC(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE),
     "ssl3_send_server_key_exchange"},
    {ERR_FUNC(SSL_F_SSL3_SETUP_KEY_BLOCK), "ssl3_setup_key_block"},
    {ERR_FUNC(SSL_F_SSL3_SETUP_READ_BUFFER), "ssl3_setup_read_buffer"},
    {ERR_FUNC(SSL_F_SSL3_SETUP_WRITE_BUFFER), "ssl3_setup_write_buffer"},
    {ERR_FUNC(SSL_F_SSL3_WRITE_BYTES), "ssl3_write_bytes"},
    {ERR_FUNC(SSL_F_SSL3_WRITE_PENDING), "ssl3_write_pending"},
    {ERR_FUNC(SSL_F_SSL_ADD_CERT_CHAIN), "ssl_add_cert_chain"},
    {ERR_FUNC(SSL_F_SSL_ADD_CERT_TO_BUF), "SSL_ADD_CERT_TO_BUF"},
    {ERR_FUNC(SSL_F_SSL_ADD_CLIENTHELLO_RENEGOTIATE_EXT),
     "ssl_add_clienthello_renegotiate_ext"},
    {ERR_FUNC(SSL_F_SSL_ADD_CLIENTHELLO_TLSEXT),
     "ssl_add_clienthello_tlsext"},
    {ERR_FUNC(SSL_F_SSL_ADD_CLIENTHELLO_USE_SRTP_EXT),
     "ssl_add_clienthello_use_srtp_ext"},
    {ERR_FUNC(SSL_F_SSL_ADD_DIR_CERT_SUBJECTS_TO_STACK),
     "SSL_add_dir_cert_subjects_to_stack"},
    {ERR_FUNC(SSL_F_SSL_ADD_FILE_CERT_SUBJECTS_TO_STACK),
     "SSL_add_file_cert_subjects_to_stack"},
    {ERR_FUNC(SSL_F_SSL_ADD_SERVERHELLO_RENEGOTIATE_EXT),
     "ssl_add_serverhello_renegotiate_ext"},
    {ERR_FUNC(SSL_F_SSL_ADD_SERVERHELLO_TLSEXT),
     "ssl_add_serverhello_tlsext"},
    {ERR_FUNC(SSL_F_SSL_ADD_SERVERHELLO_USE_SRTP_EXT),
     "ssl_add_serverhello_use_srtp_ext"},
    {ERR_FUNC(SSL_F_SSL_BAD_METHOD), "ssl_bad_method"},
    {ERR_FUNC(SSL_F_SSL_BUILD_CERT_CHAIN), "ssl_build_cert_chain"},
    {ERR_FUNC(SSL_F_SSL_BYTES_TO_CIPHER_LIST), "ssl_bytes_to_cipher_list"},
    {ERR_FUNC(SSL_F_SSL_CERT_DUP), "ssl_cert_dup"},
    {ERR_FUNC(SSL_F_SSL_CERT_INST), "ssl_cert_inst"},
    {ERR_FUNC(SSL_F_SSL_CERT_INSTANTIATE), "SSL_CERT_INSTANTIATE"},
    {ERR_FUNC(SSL_F_SSL_CERT_NEW), "ssl_cert_new"},
    {ERR_FUNC(SSL_F_SSL_CHECK_PRIVATE_KEY), "SSL_check_private_key"},
    {ERR_FUNC(SSL_F_SSL_CHECK_SERVERHELLO_TLSEXT),
     "SSL_CHECK_SERVERHELLO_TLSEXT"},
    {ERR_FUNC(SSL_F_SSL_CHECK_SRVR_ECC_CERT_AND_ALG),
     "ssl_check_srvr_ecc_cert_and_alg"},
    {ERR_FUNC(SSL_F_SSL_CIPHER_PROCESS_RULESTR),
     "SSL_CIPHER_PROCESS_RULESTR"},
    {ERR_FUNC(SSL_F_SSL_CIPHER_STRENGTH_SORT), "SSL_CIPHER_STRENGTH_SORT"},
    {ERR_FUNC(SSL_F_SSL_CLEAR), "SSL_clear"},
    {ERR_FUNC(SSL_F_SSL_COMP_ADD_COMPRESSION_METHOD),
     "SSL_COMP_add_compression_method"},
    {ERR_FUNC(SSL_F_SSL_CONF_CMD), "SSL_CONF_cmd"},
    {ERR_FUNC(SSL_F_SSL_CREATE_CIPHER_LIST), "ssl_create_cipher_list"},
    {ERR_FUNC(SSL_F_SSL_CTRL), "SSL_ctrl"},
    {ERR_FUNC(SSL_F_SSL_CTX_CHECK_PRIVATE_KEY), "SSL_CTX_check_private_key"},
    {ERR_FUNC(SSL_F_SSL_CTX_MAKE_PROFILES), "SSL_CTX_MAKE_PROFILES"},
    {ERR_FUNC(SSL_F_SSL_CTX_NEW), "SSL_CTX_new"},
    {ERR_FUNC(SSL_F_SSL_CTX_SET_CIPHER_LIST), "SSL_CTX_set_cipher_list"},
    {ERR_FUNC(SSL_F_SSL_CTX_SET_CLIENT_CERT_ENGINE),
     "SSL_CTX_set_client_cert_engine"},
    {ERR_FUNC(SSL_F_SSL_CTX_SET_PURPOSE), "SSL_CTX_set_purpose"},
    {ERR_FUNC(SSL_F_SSL_CTX_SET_SESSION_ID_CONTEXT),
     "SSL_CTX_set_session_id_context"},
    {ERR_FUNC(SSL_F_SSL_CTX_SET_SSL_VERSION), "SSL_CTX_set_ssl_version"},
    {ERR_FUNC(SSL_F_SSL_CTX_SET_TRUST), "SSL_CTX_set_trust"},
    {ERR_FUNC(SSL_F_SSL_CTX_USE_CERTIFICATE), "SSL_CTX_use_certificate"},
    {ERR_FUNC(SSL_F_SSL_CTX_USE_CERTIFICATE_ASN1),
     "SSL_CTX_use_certificate_ASN1"},
    {ERR_FUNC(SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE),
     "SSL_CTX_use_certificate_chain_file"},
    {ERR_FUNC(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE),
     "SSL_CTX_use_certificate_file"},
    {ERR_FUNC(SSL_F_SSL_CTX_USE_PRIVATEKEY), "SSL_CTX_use_PrivateKey"},
    {ERR_FUNC(SSL_F_SSL_CTX_USE_PRIVATEKEY_ASN1),
     "SSL_CTX_use_PrivateKey_ASN1"},
    {ERR_FUNC(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE),
     "SSL_CTX_use_PrivateKey_file"},
    {ERR_FUNC(SSL_F_SSL_CTX_USE_PSK_IDENTITY_HINT),
     "SSL_CTX_use_psk_identity_hint"},
    {ERR_FUNC(SSL_F_SSL_CTX_USE_RSAPRIVATEKEY), "SSL_CTX_use_RSAPrivateKey"},
    {ERR_FUNC(SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_ASN1),
     "SSL_CTX_use_RSAPrivateKey_ASN1"},
    {ERR_FUNC(SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_FILE),
     "SSL_CTX_use_RSAPrivateKey_file"},
    {ERR_FUNC(SSL_F_SSL_CTX_USE_SERVERINFO), "SSL_CTX_use_serverinfo"},
    {ERR_FUNC(SSL_F_SSL_CTX_USE_SERVERINFO_FILE),
     "SSL_CTX_use_serverinfo_file"},
    {ERR_FUNC(SSL_F_SSL_DO_HANDSHAKE), "SSL_do_handshake"},
    {ERR_FUNC(SSL_F_SSL_GET_NEW_SESSION), "ssl_get_new_session"},
    {ERR_FUNC(SSL_F_SSL_GET_PREV_SESSION), "ssl_get_prev_session"},
    {ERR_FUNC(SSL_F_SSL_GET_SERVER_CERT_INDEX), "SSL_GET_SERVER_CERT_INDEX"},
    {ERR_FUNC(SSL_F_SSL_GET_SERVER_SEND_CERT), "SSL_GET_SERVER_SEND_CERT"},
    {ERR_FUNC(SSL_F_SSL_GET_SERVER_SEND_PKEY), "ssl_get_server_send_pkey"},
    {ERR_FUNC(SSL_F_SSL_GET_SIGN_PKEY), "ssl_get_sign_pkey"},
    {ERR_FUNC(SSL_F_SSL_INIT_WBIO_BUFFER), "ssl_init_wbio_buffer"},
    {ERR_FUNC(SSL_F_SSL_LOAD_CLIENT_CA_FILE), "SSL_load_client_CA_file"},
    {ERR_FUNC(SSL_F_SSL_NEW), "SSL_new"},
    {ERR_FUNC(SSL_F_SSL_PARSE_CLIENTHELLO_RENEGOTIATE_EXT),
     "ssl_parse_clienthello_renegotiate_ext"},
    {ERR_FUNC(SSL_F_SSL_PARSE_CLIENTHELLO_TLSEXT),
     "ssl_parse_clienthello_tlsext"},
    {ERR_FUNC(SSL_F_SSL_PARSE_CLIENTHELLO_USE_SRTP_EXT),
     "ssl_parse_clienthello_use_srtp_ext"},
    {ERR_FUNC(SSL_F_SSL_PARSE_SERVERHELLO_RENEGOTIATE_EXT),
     "ssl_parse_serverhello_renegotiate_ext"},
    {ERR_FUNC(SSL_F_SSL_PARSE_SERVERHELLO_TLSEXT),
     "ssl_parse_serverhello_tlsext"},
    {ERR_FUNC(SSL_F_SSL_PARSE_SERVERHELLO_USE_SRTP_EXT),
     "ssl_parse_serverhello_use_srtp_ext"},
    {ERR_FUNC(SSL_F_SSL_PEEK), "SSL_peek"},
    {ERR_FUNC(SSL_F_SSL_PREPARE_CLIENTHELLO_TLSEXT),
     "ssl_prepare_clienthello_tlsext"},
    {ERR_FUNC(SSL_F_SSL_PREPARE_SERVERHELLO_TLSEXT),
     "ssl_prepare_serverhello_tlsext"},
    {ERR_FUNC(SSL_F_SSL_READ), "SSL_read"},
    {ERR_FUNC(SSL_F_SSL_RSA_PRIVATE_DECRYPT), "SSL_RSA_PRIVATE_DECRYPT"},
    {ERR_FUNC(SSL_F_SSL_RSA_PUBLIC_ENCRYPT), "SSL_RSA_PUBLIC_ENCRYPT"},
    {ERR_FUNC(SSL_F_SSL_SCAN_CLIENTHELLO_TLSEXT),
     "SSL_SCAN_CLIENTHELLO_TLSEXT"},
    {ERR_FUNC(SSL_F_SSL_SCAN_SERVERHELLO_TLSEXT),
     "SSL_SCAN_SERVERHELLO_TLSEXT"},
    {ERR_FUNC(SSL_F_SSL_SESSION_DUP), "ssl_session_dup"},
    {ERR_FUNC(SSL_F_SSL_SESSION_NEW), "SSL_SESSION_new"},
    {ERR_FUNC(SSL_F_SSL_SESSION_PRINT_FP), "SSL_SESSION_print_fp"},
    {ERR_FUNC(SSL_F_SSL_SESSION_SET1_ID_CONTEXT),
     "SSL_SESSION_set1_id_context"},
    {ERR_FUNC(SSL_F_SSL_SESS_CERT_NEW), "ssl_sess_cert_new"},
    {ERR_FUNC(SSL_F_SSL_SET_CERT), "SSL_SET_CERT"},
    {ERR_FUNC(SSL_F_SSL_SET_CIPHER_LIST), "SSL_set_cipher_list"},
    {ERR_FUNC(SSL_F_SSL_SET_FD), "SSL_set_fd"},
    {ERR_FUNC(SSL_F_SSL_SET_PKEY), "SSL_SET_PKEY"},
    {ERR_FUNC(SSL_F_SSL_SET_PURPOSE), "SSL_set_purpose"},
    {ERR_FUNC(SSL_F_SSL_SET_RFD), "SSL_set_rfd"},
    {ERR_FUNC(SSL_F_SSL_SET_SESSION), "SSL_set_session"},
    {ERR_FUNC(SSL_F_SSL_SET_SESSION_ID_CONTEXT),
     "SSL_set_session_id_context"},
    {ERR_FUNC(SSL_F_SSL_SET_SESSION_TICKET_EXT),
     "SSL_set_session_ticket_ext"},
    {ERR_FUNC(SSL_F_SSL_SET_TRUST), "SSL_set_trust"},
    {ERR_FUNC(SSL_F_SSL_SET_WFD), "SSL_set_wfd"},
    {ERR_FUNC(SSL_F_SSL_SHUTDOWN), "SSL_shutdown"},
    {ERR_FUNC(SSL_F_SSL_SRP_CTX_INIT), "SSL_SRP_CTX_init"},
    {ERR_FUNC(SSL_F_SSL_UNDEFINED_CONST_FUNCTION),
     "ssl_undefined_const_function"},
    {ERR_FUNC(SSL_F_SSL_UNDEFINED_FUNCTION), "ssl_undefined_function"},
    {ERR_FUNC(SSL_F_SSL_UNDEFINED_VOID_FUNCTION),
     "ssl_undefined_void_function"},
    {ERR_FUNC(SSL_F_SSL_USE_CERTIFICATE), "SSL_use_certificate"},
    {ERR_FUNC(SSL_F_SSL_USE_CERTIFICATE_ASN1), "SSL_use_certificate_ASN1"},
    {ERR_FUNC(SSL_F_SSL_USE_CERTIFICATE_FILE), "SSL_use_certificate_file"},
    {ERR_FUNC(SSL_F_SSL_USE_PRIVATEKEY), "SSL_use_PrivateKey"},
    {ERR_FUNC(SSL_F_SSL_USE_PRIVATEKEY_ASN1), "SSL_use_PrivateKey_ASN1"},
    {ERR_FUNC(SSL_F_SSL_USE_PRIVATEKEY_FILE), "SSL_use_PrivateKey_file"},
    {ERR_FUNC(SSL_F_SSL_USE_PSK_IDENTITY_HINT), "SSL_use_psk_identity_hint"},
    {ERR_FUNC(SSL_F_SSL_USE_RSAPRIVATEKEY), "SSL_use_RSAPrivateKey"},
    {ERR_FUNC(SSL_F_SSL_USE_RSAPRIVATEKEY_ASN1),
     "SSL_use_RSAPrivateKey_ASN1"},
    {ERR_FUNC(SSL_F_SSL_USE_RSAPRIVATEKEY_FILE),
     "SSL_use_RSAPrivateKey_file"},
    {ERR_FUNC(SSL_F_SSL_VERIFY_CERT_CHAIN), "ssl_verify_cert_chain"},
    {ERR_FUNC(SSL_F_SSL_WRITE), "SSL_write"},
    {ERR_FUNC(SSL_F_TLS12_CHECK_PEER_SIGALG), "tls12_check_peer_sigalg"},
    {ERR_FUNC(SSL_F_TLS1_CERT_VERIFY_MAC), "tls1_cert_verify_mac"},
    {ERR_FUNC(SSL_F_TLS1_CHANGE_CIPHER_STATE), "tls1_change_cipher_state"},
    {ERR_FUNC(SSL_F_TLS1_CHECK_SERVERHELLO_TLSEXT),
     "TLS1_CHECK_SERVERHELLO_TLSEXT"},
    {ERR_FUNC(SSL_F_TLS1_ENC), "tls1_enc"},
    {ERR_FUNC(SSL_F_TLS1_EXPORT_KEYING_MATERIAL),
     "tls1_export_keying_material"},
    {ERR_FUNC(SSL_F_TLS1_GET_CURVELIST), "TLS1_GET_CURVELIST"},
    {ERR_FUNC(SSL_F_TLS1_HEARTBEAT), "tls1_heartbeat"},
    {ERR_FUNC(SSL_F_TLS1_PREPARE_CLIENTHELLO_TLSEXT),
     "TLS1_PREPARE_CLIENTHELLO_TLSEXT"},
    {ERR_FUNC(SSL_F_TLS1_PREPARE_SERVERHELLO_TLSEXT),
     "TLS1_PREPARE_SERVERHELLO_TLSEXT"},
    {ERR_FUNC(SSL_F_TLS1_PRF), "tls1_prf"},
    {ERR_FUNC(SSL_F_TLS1_SETUP_KEY_BLOCK), "tls1_setup_key_block"},
    {ERR_FUNC(SSL_F_TLS1_SET_SERVER_SIGALGS), "tls1_set_server_sigalgs"},
    {ERR_FUNC(SSL_F_WRITE_PENDING), "WRITE_PENDING"},
    {0, NULL}
};

static ERR_STRING_DATA SSL_str_reasons[] = {
    {ERR_REASON(SSL_R_APP_DATA_IN_HANDSHAKE), "app data in handshake"},
    {ERR_REASON(SSL_R_ATTEMPT_TO_REUSE_SESSION_IN_DIFFERENT_CONTEXT),
     "attempt to reuse session in different context"},
    {ERR_REASON(SSL_R_BAD_ALERT_RECORD), "bad alert record"},
    {ERR_REASON(SSL_R_BAD_AUTHENTICATION_TYPE), "bad authentication type"},
    {ERR_REASON(SSL_R_BAD_CHANGE_CIPHER_SPEC), "bad change cipher spec"},
    {ERR_REASON(SSL_R_BAD_CHECKSUM), "bad checksum"},
    {ERR_REASON(SSL_R_BAD_DATA), "bad data"},
    {ERR_REASON(SSL_R_BAD_DATA_RETURNED_BY_CALLBACK),
     "bad data returned by callback"},
    {ERR_REASON(SSL_R_BAD_DECOMPRESSION), "bad decompression"},
    {ERR_REASON(SSL_R_BAD_DH_G_LENGTH), "bad dh g length"},
    {ERR_REASON(SSL_R_BAD_DH_G_VALUE), "bad dh g value"},
    {ERR_REASON(SSL_R_BAD_DH_PUB_KEY_LENGTH), "bad dh pub key length"},
    {ERR_REASON(SSL_R_BAD_DH_PUB_KEY_VALUE), "bad dh pub key value"},
    {ERR_REASON(SSL_R_BAD_DH_P_LENGTH), "bad dh p length"},
    {ERR_REASON(SSL_R_BAD_DH_P_VALUE), "bad dh p value"},
    {ERR_REASON(SSL_R_BAD_DIGEST_LENGTH), "bad digest length"},
    {ERR_REASON(SSL_R_BAD_DSA_SIGNATURE), "bad dsa signature"},
    {ERR_REASON(SSL_R_BAD_ECC_CERT), "bad ecc cert"},
    {ERR_REASON(SSL_R_BAD_ECDSA_SIGNATURE), "bad ecdsa signature"},
    {ERR_REASON(SSL_R_BAD_ECPOINT), "bad ecpoint"},
    {ERR_REASON(SSL_R_BAD_HANDSHAKE_LENGTH), "bad handshake length"},
    {ERR_REASON(SSL_R_BAD_HELLO_REQUEST), "bad hello request"},
    {ERR_REASON(SSL_R_BAD_LENGTH), "bad length"},
    {ERR_REASON(SSL_R_BAD_MAC_DECODE), "bad mac decode"},
    {ERR_REASON(SSL_R_BAD_MAC_LENGTH), "bad mac length"},
    {ERR_REASON(SSL_R_BAD_MESSAGE_TYPE), "bad message type"},
    {ERR_REASON(SSL_R_BAD_PACKET_LENGTH), "bad packet length"},
    {ERR_REASON(SSL_R_BAD_PROTOCOL_VERSION_NUMBER),
     "bad protocol version number"},
    {ERR_REASON(SSL_R_BAD_PSK_IDENTITY_HINT_LENGTH),
     "bad psk identity hint length"},
    {ERR_REASON(SSL_R_BAD_RESPONSE_ARGUMENT), "bad response argument"},
    {ERR_REASON(SSL_R_BAD_RSA_DECRYPT), "bad rsa decrypt"},
    {ERR_REASON(SSL_R_BAD_RSA_ENCRYPT), "bad rsa encrypt"},
    {ERR_REASON(SSL_R_BAD_RSA_E_LENGTH), "bad rsa e length"},
    {ERR_REASON(SSL_R_BAD_RSA_MODULUS_LENGTH), "bad rsa modulus length"},
    {ERR_REASON(SSL_R_BAD_RSA_SIGNATURE), "bad rsa signature"},
    {ERR_REASON(SSL_R_BAD_SIGNATURE), "bad signature"},
    {ERR_REASON(SSL_R_BAD_SRP_A_LENGTH), "bad srp a length"},
    {ERR_REASON(SSL_R_BAD_SRP_B_LENGTH), "bad srp b length"},
    {ERR_REASON(SSL_R_BAD_SRP_G_LENGTH), "bad srp g length"},
    {ERR_REASON(SSL_R_BAD_SRP_N_LENGTH), "bad srp n length"},
    {ERR_REASON(SSL_R_BAD_SRP_PARAMETERS), "bad srp parameters"},
    {ERR_REASON(SSL_R_BAD_SRP_S_LENGTH), "bad srp s length"},
    {ERR_REASON(SSL_R_BAD_SRTP_MKI_VALUE), "bad srtp mki value"},
    {ERR_REASON(SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST),
     "bad srtp protection profile list"},
    {ERR_REASON(SSL_R_BAD_SSL_FILETYPE), "bad ssl filetype"},
    {ERR_REASON(SSL_R_BAD_SSL_SESSION_ID_LENGTH),
     "bad ssl session id length"},
    {ERR_REASON(SSL_R_BAD_STATE), "bad state"},
    {ERR_REASON(SSL_R_BAD_VALUE), "bad value"},
    {ERR_REASON(SSL_R_BAD_WRITE_RETRY), "bad write retry"},
    {ERR_REASON(SSL_R_BIO_NOT_SET), "bio not set"},
    {ERR_REASON(SSL_R_BLOCK_CIPHER_PAD_IS_WRONG),
     "block cipher pad is wrong"},
    {ERR_REASON(SSL_R_BN_LIB), "bn lib"},
    {ERR_REASON(SSL_R_CA_DN_LENGTH_MISMATCH), "ca dn length mismatch"},
    {ERR_REASON(SSL_R_CA_DN_TOO_LONG), "ca dn too long"},
    {ERR_REASON(SSL_R_CCS_RECEIVED_EARLY), "ccs received early"},
    {ERR_REASON(SSL_R_CERTIFICATE_VERIFY_FAILED),
     "certificate verify failed"},
    {ERR_REASON(SSL_R_CERT_CB_ERROR), "cert cb error"},
    {ERR_REASON(SSL_R_CERT_LENGTH_MISMATCH), "cert length mismatch"},
    {ERR_REASON(SSL_R_CHALLENGE_IS_DIFFERENT), "challenge is different"},
    {ERR_REASON(SSL_R_CIPHER_CODE_WRONG_LENGTH), "cipher code wrong length"},
    {ERR_REASON(SSL_R_CIPHER_OR_HASH_UNAVAILABLE),
     "cipher or hash unavailable"},
    {ERR_REASON(SSL_R_CIPHER_TABLE_SRC_ERROR), "cipher table src error"},
    {ERR_REASON(SSL_R_CLIENTHELLO_TLSEXT), "clienthello tlsext"},
    {ERR_REASON(SSL_R_COMPRESSED_LENGTH_TOO_LONG),
     "compressed length too long"},
    {ERR_REASON(SSL_R_COMPRESSION_DISABLED), "compression disabled"},
    {ERR_REASON(SSL_R_COMPRESSION_FAILURE), "compression failure"},
    {ERR_REASON(SSL_R_COMPRESSION_ID_NOT_WITHIN_PRIVATE_RANGE),
     "compression id not within private range"},
    {ERR_REASON(SSL_R_COMPRESSION_LIBRARY_ERROR),
     "compression library error"},
    {ERR_REASON(SSL_R_CONNECTION_ID_IS_DIFFERENT),
     "connection id is different"},
    {ERR_REASON(SSL_R_CONNECTION_TYPE_NOT_SET), "connection type not set"},
    {ERR_REASON(SSL_R_COOKIE_MISMATCH), "cookie mismatch"},
    {ERR_REASON(SSL_R_DATA_BETWEEN_CCS_AND_FINISHED),
     "data between ccs and finished"},
    {ERR_REASON(SSL_R_DATA_LENGTH_TOO_LONG), "data length too long"},
    {ERR_REASON(SSL_R_DECRYPTION_FAILED), "decryption failed"},
    {ERR_REASON(SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC),
     "decryption failed or bad record mac"},
    {ERR_REASON(SSL_R_DH_KEY_TOO_SMALL), "dh key too small"},
    {ERR_REASON(SSL_R_DH_PUBLIC_VALUE_LENGTH_IS_WRONG),
     "dh public value length is wrong"},
    {ERR_REASON(SSL_R_DIGEST_CHECK_FAILED), "digest check failed"},
    {ERR_REASON(SSL_R_DTLS_MESSAGE_TOO_BIG), "dtls message too big"},
    {ERR_REASON(SSL_R_DUPLICATE_COMPRESSION_ID), "duplicate compression id"},
    {ERR_REASON(SSL_R_ECC_CERT_NOT_FOR_KEY_AGREEMENT),
     "ecc cert not for key agreement"},
    {ERR_REASON(SSL_R_ECC_CERT_NOT_FOR_SIGNING), "ecc cert not for signing"},
    {ERR_REASON(SSL_R_ECC_CERT_SHOULD_HAVE_RSA_SIGNATURE),
     "ecc cert should have rsa signature"},
    {ERR_REASON(SSL_R_ECC_CERT_SHOULD_HAVE_SHA1_SIGNATURE),
     "ecc cert should have sha1 signature"},
    {ERR_REASON(SSL_R_ECDH_REQUIRED_FOR_SUITEB_MODE),
     "ecdh required for suiteb mode"},
    {ERR_REASON(SSL_R_ECGROUP_TOO_LARGE_FOR_CIPHER),
     "ecgroup too large for cipher"},
    {ERR_REASON(SSL_R_EMPTY_SRTP_PROTECTION_PROFILE_LIST),
     "empty srtp protection profile list"},
    {ERR_REASON(SSL_R_ENCRYPTED_LENGTH_TOO_LONG),
     "encrypted length too long"},
    {ERR_REASON(SSL_R_ERROR_GENERATING_TMP_RSA_KEY),
     "error generating tmp rsa key"},
    {ERR_REASON(SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST),
     "error in received cipher list"},
    {ERR_REASON(SSL_R_EXCESSIVE_MESSAGE_SIZE), "excessive message size"},
    {ERR_REASON(SSL_R_EXTRA_DATA_IN_MESSAGE), "extra data in message"},
    {ERR_REASON(SSL_R_GOT_A_FIN_BEFORE_A_CCS), "got a fin before a ccs"},
    {ERR_REASON(SSL_R_GOT_NEXT_PROTO_BEFORE_A_CCS),
     "got next proto before a ccs"},
    {ERR_REASON(SSL_R_GOT_NEXT_PROTO_WITHOUT_EXTENSION),
     "got next proto without seeing extension"},
    {ERR_REASON(SSL_R_HTTPS_PROXY_REQUEST), "https proxy request"},
    {ERR_REASON(SSL_R_HTTP_REQUEST), "http request"},
    {ERR_REASON(SSL_R_ILLEGAL_PADDING), "illegal padding"},
    {ERR_REASON(SSL_R_ILLEGAL_SUITEB_DIGEST), "illegal Suite B digest"},
    {ERR_REASON(SSL_R_INAPPROPRIATE_FALLBACK), "inappropriate fallback"},
    {ERR_REASON(SSL_R_INCONSISTENT_COMPRESSION), "inconsistent compression"},
    {ERR_REASON(SSL_R_INVALID_CHALLENGE_LENGTH), "invalid challenge length"},
    {ERR_REASON(SSL_R_INVALID_COMMAND), "invalid command"},
    {ERR_REASON(SSL_R_INVALID_COMPRESSION_ALGORITHM),
     "invalid compression algorithm"},
    {ERR_REASON(SSL_R_INVALID_NULL_CMD_NAME), "invalid null cmd name"},
    {ERR_REASON(SSL_R_INVALID_PURPOSE), "invalid purpose"},
    {ERR_REASON(SSL_R_INVALID_SERVERINFO_DATA), "invalid serverinfo data"},
    {ERR_REASON(SSL_R_INVALID_SRP_USERNAME), "invalid srp username"},
    {ERR_REASON(SSL_R_INVALID_STATUS_RESPONSE), "invalid status response"},
    {ERR_REASON(SSL_R_INVALID_TICKET_KEYS_LENGTH),
     "invalid ticket keys length"},
    {ERR_REASON(SSL_R_INVALID_TRUST), "invalid trust"},
    {ERR_REASON(SSL_R_KEY_ARG_TOO_LONG), "key arg too long"},
    {ERR_REASON(SSL_R_KRB5), "krb5"},
    {ERR_REASON(SSL_R_KRB5_C_CC_PRINC), "krb5 client cc principal (no tkt?)"},
    {ERR_REASON(SSL_R_KRB5_C_GET_CRED), "krb5 client get cred"},
    {ERR_REASON(SSL_R_KRB5_C_INIT), "krb5 client init"},
    {ERR_REASON(SSL_R_KRB5_C_MK_REQ), "krb5 client mk_req (expired tkt?)"},
    {ERR_REASON(SSL_R_KRB5_S_BAD_TICKET), "krb5 server bad ticket"},
    {ERR_REASON(SSL_R_KRB5_S_INIT), "krb5 server init"},
    {ERR_REASON(SSL_R_KRB5_S_RD_REQ), "krb5 server rd_req (keytab perms?)"},
    {ERR_REASON(SSL_R_KRB5_S_TKT_EXPIRED), "krb5 server tkt expired"},
    {ERR_REASON(SSL_R_KRB5_S_TKT_NYV), "krb5 server tkt not yet valid"},
    {ERR_REASON(SSL_R_KRB5_S_TKT_SKEW), "krb5 server tkt skew"},
    {ERR_REASON(SSL_R_LENGTH_MISMATCH), "length mismatch"},
    {ERR_REASON(SSL_R_LENGTH_TOO_SHORT), "length too short"},
    {ERR_REASON(SSL_R_LIBRARY_BUG), "library bug"},
    {ERR_REASON(SSL_R_LIBRARY_HAS_NO_CIPHERS), "library has no ciphers"},
    {ERR_REASON(SSL_R_MESSAGE_TOO_LONG), "message too long"},
    {ERR_REASON(SSL_R_MISSING_DH_DSA_CERT), "missing dh dsa cert"},
    {ERR_REASON(SSL_R_MISSING_DH_KEY), "missing dh key"},
    {ERR_REASON(SSL_R_MISSING_DH_RSA_CERT), "missing dh rsa cert"},
    {ERR_REASON(SSL_R_MISSING_DSA_SIGNING_CERT), "missing dsa signing cert"},
    {ERR_REASON(SSL_R_MISSING_ECDH_CERT), "missing ecdh cert"},
    {ERR_REASON(SSL_R_MISSING_ECDSA_SIGNING_CERT),
     "missing ecdsa signing cert"},
    {ERR_REASON(SSL_R_MISSING_EXPORT_TMP_DH_KEY),
     "missing export tmp dh key"},
    {ERR_REASON(SSL_R_MISSING_EXPORT_TMP_RSA_KEY),
     "missing export tmp rsa key"},
    {ERR_REASON(SSL_R_MISSING_RSA_CERTIFICATE), "missing rsa certificate"},
    {ERR_REASON(SSL_R_MISSING_RSA_ENCRYPTING_CERT),
     "missing rsa encrypting cert"},
    {ERR_REASON(SSL_R_MISSING_RSA_SIGNING_CERT), "missing rsa signing cert"},
    {ERR_REASON(SSL_R_MISSING_SRP_PARAM), "can't find SRP server param"},
    {ERR_REASON(SSL_R_MISSING_TMP_DH_KEY), "missing tmp dh key"},
    {ERR_REASON(SSL_R_MISSING_TMP_ECDH_KEY), "missing tmp ecdh key"},
    {ERR_REASON(SSL_R_MISSING_TMP_RSA_KEY), "missing tmp rsa key"},
    {ERR_REASON(SSL_R_MISSING_TMP_RSA_PKEY), "missing tmp rsa pkey"},
    {ERR_REASON(SSL_R_MISSING_VERIFY_MESSAGE), "missing verify message"},
    {ERR_REASON(SSL_R_MULTIPLE_SGC_RESTARTS), "multiple sgc restarts"},
    {ERR_REASON(SSL_R_NON_SSLV2_INITIAL_PACKET), "non sslv2 initial packet"},
    {ERR_REASON(SSL_R_NO_CERTIFICATES_RETURNED), "no certificates returned"},
    {ERR_REASON(SSL_R_NO_CERTIFICATE_ASSIGNED), "no certificate assigned"},
    {ERR_REASON(SSL_R_NO_CERTIFICATE_RETURNED), "no certificate returned"},
    {ERR_REASON(SSL_R_NO_CERTIFICATE_SET), "no certificate set"},
    {ERR_REASON(SSL_R_NO_CERTIFICATE_SPECIFIED), "no certificate specified"},
    {ERR_REASON(SSL_R_NO_CIPHERS_AVAILABLE), "no ciphers available"},
    {ERR_REASON(SSL_R_NO_CIPHERS_PASSED), "no ciphers passed"},
    {ERR_REASON(SSL_R_NO_CIPHERS_SPECIFIED), "no ciphers specified"},
    {ERR_REASON(SSL_R_NO_CIPHER_LIST), "no cipher list"},
    {ERR_REASON(SSL_R_NO_CIPHER_MATCH), "no cipher match"},
    {ERR_REASON(SSL_R_NO_CLIENT_CERT_METHOD), "no client cert method"},
    {ERR_REASON(SSL_R_NO_CLIENT_CERT_RECEIVED), "no client cert received"},
    {ERR_REASON(SSL_R_NO_COMPRESSION_SPECIFIED), "no compression specified"},
    {ERR_REASON(SSL_R_NO_GOST_CERTIFICATE_SENT_BY_PEER),
     "Peer haven't sent GOST certificate, required for selected ciphersuite"},
    {ERR_REASON(SSL_R_NO_METHOD_SPECIFIED), "no method specified"},
    {ERR_REASON(SSL_R_NO_PEM_EXTENSIONS), "no pem extensions"},
    {ERR_REASON(SSL_R_NO_PRIVATEKEY), "no privatekey"},
    {ERR_REASON(SSL_R_NO_PRIVATE_KEY_ASSIGNED), "no private key assigned"},
    {ERR_REASON(SSL_R_NO_PROTOCOLS_AVAILABLE), "no protocols available"},
    {ERR_REASON(SSL_R_NO_PUBLICKEY), "no publickey"},
    {ERR_REASON(SSL_R_NO_RENEGOTIATION), "no renegotiation"},
    {ERR_REASON(SSL_R_NO_REQUIRED_DIGEST),
     "digest requred for handshake isn't computed"},
    {ERR_REASON(SSL_R_NO_SHARED_CIPHER), "no shared cipher"},
    {ERR_REASON(SSL_R_NO_SHARED_SIGATURE_ALGORITHMS),
     "no shared sigature algorithms"},
    {ERR_REASON(SSL_R_NO_SRTP_PROFILES), "no srtp profiles"},
    {ERR_REASON(SSL_R_NO_VERIFY_CALLBACK), "no verify callback"},
    {ERR_REASON(SSL_R_NULL_SSL_CTX), "null ssl ctx"},
    {ERR_REASON(SSL_R_NULL_SSL_METHOD_PASSED), "null ssl method passed"},
    {ERR_REASON(SSL_R_OLD_SESSION_CIPHER_NOT_RETURNED),
     "old session cipher not returned"},
    {ERR_REASON(SSL_R_OLD_SESSION_COMPRESSION_ALGORITHM_NOT_RETURNED),
     "old session compression algorithm not returned"},
    {ERR_REASON(SSL_R_ONLY_DTLS_1_2_ALLOWED_IN_SUITEB_MODE),
     "only DTLS 1.2 allowed in Suite B mode"},
    {ERR_REASON(SSL_R_ONLY_TLS_1_2_ALLOWED_IN_SUITEB_MODE),
     "only TLS 1.2 allowed in Suite B mode"},
    {ERR_REASON(SSL_R_ONLY_TLS_ALLOWED_IN_FIPS_MODE),
     "only tls allowed in fips mode"},
    {ERR_REASON(SSL_R_OPAQUE_PRF_INPUT_TOO_LONG),
     "opaque PRF input too long"},
    {ERR_REASON(SSL_R_PACKET_LENGTH_TOO_LONG), "packet length too long"},
    {ERR_REASON(SSL_R_PARSE_TLSEXT), "parse tlsext"},
    {ERR_REASON(SSL_R_PATH_TOO_LONG), "path too long"},
    {ERR_REASON(SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE),
     "peer did not return a certificate"},
    {ERR_REASON(SSL_R_PEER_ERROR), "peer error"},
    {ERR_REASON(SSL_R_PEER_ERROR_CERTIFICATE), "peer error certificate"},
    {ERR_REASON(SSL_R_PEER_ERROR_NO_CERTIFICATE),
     "peer error no certificate"},
    {ERR_REASON(SSL_R_PEER_ERROR_NO_CIPHER), "peer error no cipher"},
    {ERR_REASON(SSL_R_PEER_ERROR_UNSUPPORTED_CERTIFICATE_TYPE),
     "peer error unsupported certificate type"},
    {ERR_REASON(SSL_R_PEM_NAME_BAD_PREFIX), "pem name bad prefix"},
    {ERR_REASON(SSL_R_PEM_NAME_TOO_SHORT), "pem name too short"},
    {ERR_REASON(SSL_R_PRE_MAC_LENGTH_TOO_LONG), "pre mac length too long"},
    {ERR_REASON(SSL_R_PROBLEMS_MAPPING_CIPHER_FUNCTIONS),
     "problems mapping cipher functions"},
    {ERR_REASON(SSL_R_PROTOCOL_IS_SHUTDOWN), "protocol is shutdown"},
    {ERR_REASON(SSL_R_PSK_IDENTITY_NOT_FOUND), "psk identity not found"},
    {ERR_REASON(SSL_R_PSK_NO_CLIENT_CB), "psk no client cb"},
    {ERR_REASON(SSL_R_PSK_NO_SERVER_CB), "psk no server cb"},
    {ERR_REASON(SSL_R_PUBLIC_KEY_ENCRYPT_ERROR), "public key encrypt error"},
    {ERR_REASON(SSL_R_PUBLIC_KEY_IS_NOT_RSA), "public key is not rsa"},
    {ERR_REASON(SSL_R_PUBLIC_KEY_NOT_RSA), "public key not rsa"},
    {ERR_REASON(SSL_R_READ_BIO_NOT_SET), "read bio not set"},
    {ERR_REASON(SSL_R_READ_TIMEOUT_EXPIRED), "read timeout expired"},
    {ERR_REASON(SSL_R_READ_WRONG_PACKET_TYPE), "read wrong packet type"},
    {ERR_REASON(SSL_R_RECORD_LENGTH_MISMATCH), "record length mismatch"},
    {ERR_REASON(SSL_R_RECORD_TOO_LARGE), "record too large"},
    {ERR_REASON(SSL_R_RECORD_TOO_SMALL), "record too small"},
    {ERR_REASON(SSL_R_RENEGOTIATE_EXT_TOO_LONG), "renegotiate ext too long"},
    {ERR_REASON(SSL_R_RENEGOTIATION_ENCODING_ERR),
     "renegotiation encoding err"},
    {ERR_REASON(SSL_R_RENEGOTIATION_MISMATCH), "renegotiation mismatch"},
    {ERR_REASON(SSL_R_REQUIRED_CIPHER_MISSING), "required cipher missing"},
    {ERR_REASON(SSL_R_REQUIRED_COMPRESSSION_ALGORITHM_MISSING),
     "required compresssion algorithm missing"},
    {ERR_REASON(SSL_R_REUSE_CERT_LENGTH_NOT_ZERO),
     "reuse cert length not zero"},
    {ERR_REASON(SSL_R_REUSE_CERT_TYPE_NOT_ZERO), "reuse cert type not zero"},
    {ERR_REASON(SSL_R_REUSE_CIPHER_LIST_NOT_ZERO),
     "reuse cipher list not zero"},
    {ERR_REASON(SSL_R_SCSV_RECEIVED_WHEN_RENEGOTIATING),
     "scsv received when renegotiating"},
    {ERR_REASON(SSL_R_SERVERHELLO_TLSEXT), "serverhello tlsext"},
    {ERR_REASON(SSL_R_SESSION_ID_CONTEXT_UNINITIALIZED),
     "session id context uninitialized"},
    {ERR_REASON(SSL_R_SHORT_READ), "short read"},
    {ERR_REASON(SSL_R_SHUTDOWN_WHILE_IN_INIT), "shutdown while in init"},
    {ERR_REASON(SSL_R_SIGNATURE_ALGORITHMS_ERROR),
     "signature algorithms error"},
    {ERR_REASON(SSL_R_SIGNATURE_FOR_NON_SIGNING_CERTIFICATE),
     "signature for non signing certificate"},
    {ERR_REASON(SSL_R_SRP_A_CALC), "error with the srp params"},
    {ERR_REASON(SSL_R_SRTP_COULD_NOT_ALLOCATE_PROFILES),
     "srtp could not allocate profiles"},
    {ERR_REASON(SSL_R_SRTP_PROTECTION_PROFILE_LIST_TOO_LONG),
     "srtp protection profile list too long"},
    {ERR_REASON(SSL_R_SRTP_UNKNOWN_PROTECTION_PROFILE),
     "srtp unknown protection profile"},
    {ERR_REASON(SSL_R_SSL23_DOING_SESSION_ID_REUSE),
     "ssl23 doing session id reuse"},
    {ERR_REASON(SSL_R_SSL2_CONNECTION_ID_TOO_LONG),
     "ssl2 connection id too long"},
    {ERR_REASON(SSL_R_SSL3_EXT_INVALID_ECPOINTFORMAT),
     "ssl3 ext invalid ecpointformat"},
    {ERR_REASON(SSL_R_SSL3_EXT_INVALID_SERVERNAME),
     "ssl3 ext invalid servername"},
    {ERR_REASON(SSL_R_SSL3_EXT_INVALID_SERVERNAME_TYPE),
     "ssl3 ext invalid servername type"},
    {ERR_REASON(SSL_R_SSL3_SESSION_ID_TOO_LONG), "ssl3 session id too long"},
    {ERR_REASON(SSL_R_SSL3_SESSION_ID_TOO_SHORT),
     "ssl3 session id too short"},
    {ERR_REASON(SSL_R_SSLV3_ALERT_BAD_CERTIFICATE),
     "sslv3 alert bad certificate"},
    {ERR_REASON(SSL_R_SSLV3_ALERT_BAD_RECORD_MAC),
     "sslv3 alert bad record mac"},
    {ERR_REASON(SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED),
     "sslv3 alert certificate expired"},
    {ERR_REASON(SSL_R_SSLV3_ALERT_CERTIFICATE_REVOKED),
     "sslv3 alert certificate revoked"},
    {ERR_REASON(SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN),
     "sslv3 alert certificate unknown"},
    {ERR_REASON(SSL_R_SSLV3_ALERT_DECOMPRESSION_FAILURE),
     "sslv3 alert decompression failure"},
    {ERR_REASON(SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE),
     "sslv3 alert handshake failure"},
    {ERR_REASON(SSL_R_SSLV3_ALERT_ILLEGAL_PARAMETER),
     "sslv3 alert illegal parameter"},
    {ERR_REASON(SSL_R_SSLV3_ALERT_NO_CERTIFICATE),
     "sslv3 alert no certificate"},
    {ERR_REASON(SSL_R_SSLV3_ALERT_UNEXPECTED_MESSAGE),
     "sslv3 alert unexpected message"},
    {ERR_REASON(SSL_R_SSLV3_ALERT_UNSUPPORTED_CERTIFICATE),
     "sslv3 alert unsupported certificate"},
    {ERR_REASON(SSL_R_SSL_CTX_HAS_NO_DEFAULT_SSL_VERSION),
     "ssl ctx has no default ssl version"},
    {ERR_REASON(SSL_R_SSL_HANDSHAKE_FAILURE), "ssl handshake failure"},
    {ERR_REASON(SSL_R_SSL_LIBRARY_HAS_NO_CIPHERS),
     "ssl library has no ciphers"},
    {ERR_REASON(SSL_R_SSL_SESSION_ID_CALLBACK_FAILED),
     "ssl session id callback failed"},
    {ERR_REASON(SSL_R_SSL_SESSION_ID_CONFLICT), "ssl session id conflict"},
    {ERR_REASON(SSL_R_SSL_SESSION_ID_CONTEXT_TOO_LONG),
     "ssl session id context too long"},
    {ERR_REASON(SSL_R_SSL_SESSION_ID_HAS_BAD_LENGTH),
     "ssl session id has bad length"},
    {ERR_REASON(SSL_R_SSL_SESSION_ID_IS_DIFFERENT),
     "ssl session id is different"},
    {ERR_REASON(SSL_R_TLSV1_ALERT_ACCESS_DENIED),
     "tlsv1 alert access denied"},
    {ERR_REASON(SSL_R_TLSV1_ALERT_DECODE_ERROR), "tlsv1 alert decode error"},
    {ERR_REASON(SSL_R_TLSV1_ALERT_DECRYPTION_FAILED),
     "tlsv1 alert decryption failed"},
    {ERR_REASON(SSL_R_TLSV1_ALERT_DECRYPT_ERROR),
     "tlsv1 alert decrypt error"},
    {ERR_REASON(SSL_R_TLSV1_ALERT_EXPORT_RESTRICTION),
     "tlsv1 alert export restriction"},
    {ERR_REASON(SSL_R_TLSV1_ALERT_INAPPROPRIATE_FALLBACK),
     "tlsv1 alert inappropriate fallback"},
    {ERR_REASON(SSL_R_TLSV1_ALERT_INSUFFICIENT_SECURITY),
     "tlsv1 alert insufficient security"},
    {ERR_REASON(SSL_R_TLSV1_ALERT_INTERNAL_ERROR),
     "tlsv1 alert internal error"},
    {ERR_REASON(SSL_R_TLSV1_ALERT_NO_RENEGOTIATION),
     "tlsv1 alert no renegotiation"},
    {ERR_REASON(SSL_R_TLSV1_ALERT_PROTOCOL_VERSION),
     "tlsv1 alert protocol version"},
    {ERR_REASON(SSL_R_TLSV1_ALERT_RECORD_OVERFLOW),
     "tlsv1 alert record overflow"},
    {ERR_REASON(SSL_R_TLSV1_ALERT_UNKNOWN_CA), "tlsv1 alert unknown ca"},
    {ERR_REASON(SSL_R_TLSV1_ALERT_USER_CANCELLED),
     "tlsv1 alert user cancelled"},
    {ERR_REASON(SSL_R_TLSV1_BAD_CERTIFICATE_HASH_VALUE),
     "tlsv1 bad certificate hash value"},
    {ERR_REASON(SSL_R_TLSV1_BAD_CERTIFICATE_STATUS_RESPONSE),
     "tlsv1 bad certificate status response"},
    {ERR_REASON(SSL_R_TLSV1_CERTIFICATE_UNOBTAINABLE),
     "tlsv1 certificate unobtainable"},
    {ERR_REASON(SSL_R_TLSV1_UNRECOGNIZED_NAME), "tlsv1 unrecognized name"},
    {ERR_REASON(SSL_R_TLSV1_UNSUPPORTED_EXTENSION),
     "tlsv1 unsupported extension"},
    {ERR_REASON(SSL_R_TLS_CLIENT_CERT_REQ_WITH_ANON_CIPHER),
     "tls client cert req with anon cipher"},
    {ERR_REASON(SSL_R_TLS_HEARTBEAT_PEER_DOESNT_ACCEPT),
     "peer does not accept heartbeats"},
    {ERR_REASON(SSL_R_TLS_HEARTBEAT_PENDING),
     "heartbeat request already pending"},
    {ERR_REASON(SSL_R_TLS_ILLEGAL_EXPORTER_LABEL),
     "tls illegal exporter label"},
    {ERR_REASON(SSL_R_TLS_INVALID_ECPOINTFORMAT_LIST),
     "tls invalid ecpointformat list"},
    {ERR_REASON(SSL_R_TOO_MANY_WARN_ALERTS), "too many warn alerts"},
    {ERR_REASON(SSL_R_TLS_PEER_DID_NOT_RESPOND_WITH_CERTIFICATE_LIST),
     "tls peer did not respond with certificate list"},
    {ERR_REASON(SSL_R_TLS_RSA_ENCRYPTED_VALUE_LENGTH_IS_WRONG),
     "tls rsa encrypted value length is wrong"},
    {ERR_REASON(SSL_R_TRIED_TO_USE_UNSUPPORTED_CIPHER),
     "tried to use unsupported cipher"},
    {ERR_REASON(SSL_R_UNABLE_TO_DECODE_DH_CERTS),
     "unable to decode dh certs"},
    {ERR_REASON(SSL_R_UNABLE_TO_DECODE_ECDH_CERTS),
     "unable to decode ecdh certs"},
    {ERR_REASON(SSL_R_UNABLE_TO_EXTRACT_PUBLIC_KEY),
     "unable to extract public key"},
    {ERR_REASON(SSL_R_UNABLE_TO_FIND_DH_PARAMETERS),
     "unable to find dh parameters"},
    {ERR_REASON(SSL_R_UNABLE_TO_FIND_ECDH_PARAMETERS),
     "unable to find ecdh parameters"},
    {ERR_REASON(SSL_R_UNABLE_TO_FIND_PUBLIC_KEY_PARAMETERS),
     "unable to find public key parameters"},
    {ERR_REASON(SSL_R_UNABLE_TO_FIND_SSL_METHOD),
     "unable to find ssl method"},
    {ERR_REASON(SSL_R_UNABLE_TO_LOAD_SSL2_MD5_ROUTINES),
     "unable to load ssl2 md5 routines"},
    {ERR_REASON(SSL_R_UNABLE_TO_LOAD_SSL3_MD5_ROUTINES),
     "unable to load ssl3 md5 routines"},
    {ERR_REASON(SSL_R_UNABLE_TO_LOAD_SSL3_SHA1_ROUTINES),
     "unable to load ssl3 sha1 routines"},
    {ERR_REASON(SSL_R_UNEXPECTED_MESSAGE), "unexpected message"},
    {ERR_REASON(SSL_R_UNEXPECTED_RECORD), "unexpected record"},
    {ERR_REASON(SSL_R_UNINITIALIZED), "uninitialized"},
    {ERR_REASON(SSL_R_UNKNOWN_ALERT_TYPE), "unknown alert type"},
    {ERR_REASON(SSL_R_UNKNOWN_CERTIFICATE_TYPE), "unknown certificate type"},
    {ERR_REASON(SSL_R_UNKNOWN_CIPHER_RETURNED), "unknown cipher returned"},
    {ERR_REASON(SSL_R_UNKNOWN_CIPHER_TYPE), "unknown cipher type"},
    {ERR_REASON(SSL_R_UNKNOWN_CMD_NAME), "unknown cmd name"},
    {ERR_REASON(SSL_R_UNKNOWN_DIGEST), "unknown digest"},
    {ERR_REASON(SSL_R_UNKNOWN_KEY_EXCHANGE_TYPE),
     "unknown key exchange type"},
    {ERR_REASON(SSL_R_UNKNOWN_PKEY_TYPE), "unknown pkey type"},
    {ERR_REASON(SSL_R_UNKNOWN_PROTOCOL), "unknown protocol"},
    {ERR_REASON(SSL_R_UNKNOWN_REMOTE_ERROR_TYPE),
     "unknown remote error type"},
    {ERR_REASON(SSL_R_UNKNOWN_SSL_VERSION), "unknown ssl version"},
    {ERR_REASON(SSL_R_UNKNOWN_STATE), "unknown state"},
    {ERR_REASON(SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED),
     "unsafe legacy renegotiation disabled"},
    {ERR_REASON(SSL_R_UNSUPPORTED_CIPHER), "unsupported cipher"},
    {ERR_REASON(SSL_R_UNSUPPORTED_COMPRESSION_ALGORITHM),
     "unsupported compression algorithm"},
    {ERR_REASON(SSL_R_UNSUPPORTED_DIGEST_TYPE), "unsupported digest type"},
    {ERR_REASON(SSL_R_UNSUPPORTED_ELLIPTIC_CURVE),
     "unsupported elliptic curve"},
    {ERR_REASON(SSL_R_UNSUPPORTED_PROTOCOL), "unsupported protocol"},
    {ERR_REASON(SSL_R_UNSUPPORTED_SSL_VERSION), "unsupported ssl version"},
    {ERR_REASON(SSL_R_UNSUPPORTED_STATUS_TYPE), "unsupported status type"},
    {ERR_REASON(SSL_R_USE_SRTP_NOT_NEGOTIATED), "use srtp not negotiated"},
    {ERR_REASON(SSL_R_WRITE_BIO_NOT_SET), "write bio not set"},
    {ERR_REASON(SSL_R_WRONG_CERTIFICATE_TYPE), "wrong certificate type"},
    {ERR_REASON(SSL_R_WRONG_CIPHER_RETURNED), "wrong cipher returned"},
    {ERR_REASON(SSL_R_WRONG_CURVE), "wrong curve"},
    {ERR_REASON(SSL_R_WRONG_MESSAGE_TYPE), "wrong message type"},
    {ERR_REASON(SSL_R_WRONG_NUMBER_OF_KEY_BITS), "wrong number of key bits"},
    {ERR_REASON(SSL_R_WRONG_SIGNATURE_LENGTH), "wrong signature length"},
    {ERR_REASON(SSL_R_WRONG_SIGNATURE_SIZE), "wrong signature size"},
    {ERR_REASON(SSL_R_WRONG_SIGNATURE_TYPE), "wrong signature type"},
    {ERR_REASON(SSL_R_WRONG_SSL_VERSION), "wrong ssl version"},
    {ERR_REASON(SSL_R_WRONG_VERSION_NUMBER), "wrong version number"},
    {ERR_REASON(SSL_R_X509_LIB), "x509 lib"},
    {ERR_REASON(SSL_R_X509_VERIFICATION_SETUP_PROBLEMS),
     "x509 verification setup problems"},
    {0, NULL}
};

#endif

void ERR_load_SSL_strings(void)
{
#ifndef OPENSSL_NO_ERR

    if (ERR_func_error_string(SSL_str_functs[0].error) == NULL) {
        ERR_load_strings(0, SSL_str_functs);
        ERR_load_strings(0, SSL_str_reasons);
    }
#endif
}
/* ssl/ssl_err2.c */
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
// #include "err.h"
// #include "ssl.h"

void SSL_load_error_strings(void)
{
#ifndef OPENSSL_NO_ERR
    ERR_load_crypto_strings();
    ERR_load_SSL_strings();
#endif
}
/*
 * ! \file ssl/ssl_lib.c \brief Version independent SSL functions.
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
 * ECC cipher suite support in OpenSSL originally developed by
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
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

#ifdef REF_CHECK
# include <assert.h>
#endif
#include <stdio.h>
// #include "ssl_locl.h"
#include "kssl_lcl.h"
// #include "objects.h"
// #include "lhash.h"
// #include "x509v3.h"
#include "rand.h"
#include "ocsp.h"
#ifndef OPENSSL_NO_DH
# include "dh.h"
#endif
#ifndef OPENSSL_NO_ENGINE
# include "engine.h"
#endif

const char *SSL_version_str = OPENSSL_VERSION_TEXT;

SSL3_ENC_METHOD ssl3_undef_enc_method = {
    /*
     * evil casts, but these functions are only called if there's a library
     * bug
     */
    (int (*)(SSL *, int))ssl_undefined_function,
    (int (*)(SSL *, unsigned char *, int))ssl_undefined_function,
    ssl_undefined_function,
    (int (*)(SSL *, unsigned char *, unsigned char *, int))
        ssl_undefined_function,
    (int (*)(SSL *, int))ssl_undefined_function,
    (int (*)(SSL *, const char *, int, unsigned char *))
        ssl_undefined_function,
    0,                          /* finish_mac_length */
    (int (*)(SSL *, int, unsigned char *))ssl_undefined_function,
    NULL,                       /* client_finished_label */
    0,                          /* client_finished_label_len */
    NULL,                       /* server_finished_label */
    0,                          /* server_finished_label_len */
    (int (*)(int))ssl_undefined_function,
    (int (*)(SSL *, unsigned char *, size_t, const char *,
             size_t, const unsigned char *, size_t,
             int use_context))ssl_undefined_function,
};

int SSL_clear(SSL *s)
{

    if (s->method == NULL) {
        SSLerr(SSL_F_SSL_CLEAR, SSL_R_NO_METHOD_SPECIFIED);
        return (0);
    }

    if (ssl_clear_bad_session(s)) {
        SSL_SESSION_free(s->session);
        s->session = NULL;
    }

    s->error = 0;
    s->hit = 0;
    s->shutdown = 0;

#if 0
    /*
     * Disabled since version 1.10 of this file (early return not
     * needed because SSL_clear is not called when doing renegotiation)
     */
    /*
     * This is set if we are doing dynamic renegotiation so keep
     * the old cipher.  It is sort of a SSL_clear_lite :-)
     */
    if (s->renegotiate)
        return (1);
#else
    if (s->renegotiate) {
        SSLerr(SSL_F_SSL_CLEAR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
#endif

    s->type = 0;

    s->state = SSL_ST_BEFORE | ((s->server) ? SSL_ST_ACCEPT : SSL_ST_CONNECT);

    s->version = s->method->version;
    s->client_version = s->version;
    s->rwstate = SSL_NOTHING;
    s->rstate = SSL_ST_READ_HEADER;
#if 0
    s->read_ahead = s->ctx->read_ahead;
#endif

    if (s->init_buf != NULL) {
        BUF_MEM_free(s->init_buf);
        s->init_buf = NULL;
    }

    ssl_clear_cipher_ctx(s);
    ssl_clear_hash_ctx(&s->read_hash);
    ssl_clear_hash_ctx(&s->write_hash);

    s->first_packet = 0;
#ifndef OPENSSL_NO_TLSEXT
    if (s->cert != NULL) {
        if (s->cert->alpn_proposed) {
            OPENSSL_free(s->cert->alpn_proposed);
            s->cert->alpn_proposed = NULL;
        }
        s->cert->alpn_proposed_len = 0;
        s->cert->alpn_sent = 0;
    }
#endif
#if 1
    /*
     * Check to see if we were changed into a different method, if so, revert
     * back if we are not doing session-id reuse.
     */
    if (!s->in_handshake && (s->session == NULL)
        && (s->method != s->ctx->method)) {
        s->method->ssl_free(s);
        s->method = s->ctx->method;
        if (!s->method->ssl_new(s))
            return (0);
    } else
#endif
        s->method->ssl_clear(s);
    return (1);
}

/** Used to change an SSL_CTXs default SSL method type */
int SSL_CTX_set_ssl_version(SSL_CTX *ctx, const SSL_METHOD *meth)
{
    STACK_OF(SSL_CIPHER) *sk;

    ctx->method = meth;

    sk = ssl_create_cipher_list(ctx->method, &(ctx->cipher_list),
                                &(ctx->cipher_list_by_id),
                                meth->version ==
                                SSL2_VERSION ? "SSLv2" :
                                SSL_DEFAULT_CIPHER_LIST, ctx->cert);
    if ((sk == NULL) || (sk_SSL_CIPHER_num(sk) <= 0)) {
        SSLerr(SSL_F_SSL_CTX_SET_SSL_VERSION,
               SSL_R_SSL_LIBRARY_HAS_NO_CIPHERS);
        return (0);
    }
    return (1);
}

SSL *SSL_new(SSL_CTX *ctx)
{
    SSL *s;

    if (ctx == NULL) {
        SSLerr(SSL_F_SSL_NEW, SSL_R_NULL_SSL_CTX);
        return (NULL);
    }
    if (ctx->method == NULL) {
        SSLerr(SSL_F_SSL_NEW, SSL_R_SSL_CTX_HAS_NO_DEFAULT_SSL_VERSION);
        return (NULL);
    }

    s = (SSL *)OPENSSL_malloc(sizeof(SSL));
    if (s == NULL)
        goto err;
    memset(s, 0, sizeof(SSL));

#ifndef OPENSSL_NO_KRB5
    s->kssl_ctx = kssl_ctx_new();
#endif                          /* OPENSSL_NO_KRB5 */

    s->options = ctx->options;
    s->mode = ctx->mode;
    s->max_cert_list = ctx->max_cert_list;
    s->references = 1;

    if (ctx->cert != NULL) {
        /*
         * Earlier library versions used to copy the pointer to the CERT, not
         * its contents; only when setting new parameters for the per-SSL
         * copy, ssl_cert_new would be called (and the direct reference to
         * the per-SSL_CTX settings would be lost, but those still were
         * indirectly accessed for various purposes, and for that reason they
         * used to be known as s->ctx->default_cert). Now we don't look at the
         * SSL_CTX's CERT after having duplicated it once.
         */

        s->cert = ssl_cert_dup(ctx->cert);
        if (s->cert == NULL)
            goto err;
    } else
        s->cert = NULL;         /* Cannot really happen (see SSL_CTX_new) */

    s->read_ahead = ctx->read_ahead;
    s->msg_callback = ctx->msg_callback;
    s->msg_callback_arg = ctx->msg_callback_arg;
    s->verify_mode = ctx->verify_mode;
#if 0
    s->verify_depth = ctx->verify_depth;
#endif
    s->sid_ctx_length = ctx->sid_ctx_length;
    OPENSSL_assert(s->sid_ctx_length <= sizeof(s->sid_ctx));
    memcpy(&s->sid_ctx, &ctx->sid_ctx, sizeof(s->sid_ctx));
    s->verify_callback = ctx->default_verify_callback;
    s->generate_session_id = ctx->generate_session_id;

    s->param = X509_VERIFY_PARAM_new();
    if (!s->param)
        goto err;
    X509_VERIFY_PARAM_inherit(s->param, ctx->param);
#if 0
    s->purpose = ctx->purpose;
    s->trust = ctx->trust;
#endif
    s->quiet_shutdown = ctx->quiet_shutdown;
    s->max_send_fragment = ctx->max_send_fragment;

    CRYPTO_add(&ctx->references, 1, CRYPTO_LOCK_SSL_CTX);
    s->ctx = ctx;
#ifndef OPENSSL_NO_TLSEXT
    s->tlsext_debug_cb = 0;
    s->tlsext_debug_arg = NULL;
    s->tlsext_ticket_expected = 0;
    s->tlsext_status_type = -1;
    s->tlsext_status_expected = 0;
    s->tlsext_ocsp_ids = NULL;
    s->tlsext_ocsp_exts = NULL;
    s->tlsext_ocsp_resp = NULL;
    s->tlsext_ocsp_resplen = -1;
    CRYPTO_add(&ctx->references, 1, CRYPTO_LOCK_SSL_CTX);
    s->initial_ctx = ctx;
# ifndef OPENSSL_NO_EC
    if (ctx->tlsext_ecpointformatlist) {
        s->tlsext_ecpointformatlist =
            BUF_memdup(ctx->tlsext_ecpointformatlist,
                       ctx->tlsext_ecpointformatlist_length);
        if (!s->tlsext_ecpointformatlist)
            goto err;
        s->tlsext_ecpointformatlist_length =
            ctx->tlsext_ecpointformatlist_length;
    }
    if (ctx->tlsext_ellipticcurvelist) {
        s->tlsext_ellipticcurvelist =
            BUF_memdup(ctx->tlsext_ellipticcurvelist,
                       ctx->tlsext_ellipticcurvelist_length);
        if (!s->tlsext_ellipticcurvelist)
            goto err;
        s->tlsext_ellipticcurvelist_length =
            ctx->tlsext_ellipticcurvelist_length;
    }
# endif
# ifndef OPENSSL_NO_NEXTPROTONEG
    s->next_proto_negotiated = NULL;
# endif

    if (s->ctx->alpn_client_proto_list) {
        s->alpn_client_proto_list =
            OPENSSL_malloc(s->ctx->alpn_client_proto_list_len);
        if (s->alpn_client_proto_list == NULL)
            goto err;
        memcpy(s->alpn_client_proto_list, s->ctx->alpn_client_proto_list,
               s->ctx->alpn_client_proto_list_len);
        s->alpn_client_proto_list_len = s->ctx->alpn_client_proto_list_len;
    }
#endif

    s->verify_result = X509_V_OK;

    s->method = ctx->method;

    if (!s->method->ssl_new(s))
        goto err;

    s->server = (ctx->method->ssl_accept == ssl_undefined_function) ? 0 : 1;

    SSL_clear(s);

    CRYPTO_new_ex_data(CRYPTO_EX_INDEX_SSL, s, &s->ex_data);

#ifndef OPENSSL_NO_PSK
    s->psk_client_callback = ctx->psk_client_callback;
    s->psk_server_callback = ctx->psk_server_callback;
#endif

    return (s);
 err:
    if (s != NULL)
        SSL_free(s);
    SSLerr(SSL_F_SSL_NEW, ERR_R_MALLOC_FAILURE);
    return (NULL);
}

int SSL_CTX_set_session_id_context(SSL_CTX *ctx, const unsigned char *sid_ctx,
                                   unsigned int sid_ctx_len)
{
    if (sid_ctx_len > sizeof(ctx->sid_ctx)) {
        SSLerr(SSL_F_SSL_CTX_SET_SESSION_ID_CONTEXT,
               SSL_R_SSL_SESSION_ID_CONTEXT_TOO_LONG);
        return 0;
    }
    ctx->sid_ctx_length = sid_ctx_len;
    memcpy(ctx->sid_ctx, sid_ctx, sid_ctx_len);

    return 1;
}

int SSL_set_session_id_context(SSL *ssl, const unsigned char *sid_ctx,
                               unsigned int sid_ctx_len)
{
    if (sid_ctx_len > SSL_MAX_SID_CTX_LENGTH) {
        SSLerr(SSL_F_SSL_SET_SESSION_ID_CONTEXT,
               SSL_R_SSL_SESSION_ID_CONTEXT_TOO_LONG);
        return 0;
    }
    ssl->sid_ctx_length = sid_ctx_len;
    memcpy(ssl->sid_ctx, sid_ctx, sid_ctx_len);

    return 1;
}

int SSL_CTX_set_generate_session_id(SSL_CTX *ctx, GEN_SESSION_CB cb)
{
    CRYPTO_w_lock(CRYPTO_LOCK_SSL_CTX);
    ctx->generate_session_id = cb;
    CRYPTO_w_unlock(CRYPTO_LOCK_SSL_CTX);
    return 1;
}

int SSL_set_generate_session_id(SSL *ssl, GEN_SESSION_CB cb)
{
    CRYPTO_w_lock(CRYPTO_LOCK_SSL);
    ssl->generate_session_id = cb;
    CRYPTO_w_unlock(CRYPTO_LOCK_SSL);
    return 1;
}

int SSL_has_matching_session_id(const SSL *ssl, const unsigned char *id,
                                unsigned int id_len)
{
    /*
     * A quick examination of SSL_SESSION_hash and SSL_SESSION_cmp shows how
     * we can "construct" a session to give us the desired check - ie. to
     * find if there's a session in the hash table that would conflict with
     * any new session built out of this id/id_len and the ssl_version in use
     * by this SSL.
     */
    SSL_SESSION r, *p;

    if (id_len > sizeof(r.session_id))
        return 0;

    r.ssl_version = ssl->version;
    r.session_id_length = id_len;
    memcpy(r.session_id, id, id_len);
    /*
     * NB: SSLv2 always uses a fixed 16-byte session ID, so even if a
     * callback is calling us to check the uniqueness of a shorter ID, it
     * must be compared as a padded-out ID because that is what it will be
     * converted to when the callback has finished choosing it.
     */
    if ((r.ssl_version == SSL2_VERSION) &&
        (id_len < SSL2_SSL_SESSION_ID_LENGTH)) {
        memset(r.session_id + id_len, 0, SSL2_SSL_SESSION_ID_LENGTH - id_len);
        r.session_id_length = SSL2_SSL_SESSION_ID_LENGTH;
    }

    CRYPTO_r_lock(CRYPTO_LOCK_SSL_CTX);
    p = lh_SSL_SESSION_retrieve(ssl->ctx->sessions, &r);
    CRYPTO_r_unlock(CRYPTO_LOCK_SSL_CTX);
    return (p != NULL);
}

int SSL_CTX_set_purpose(SSL_CTX *s, int purpose)
{
    return X509_VERIFY_PARAM_set_purpose(s->param, purpose);
}

int SSL_set_purpose(SSL *s, int purpose)
{
    return X509_VERIFY_PARAM_set_purpose(s->param, purpose);
}

int SSL_CTX_set_trust(SSL_CTX *s, int trust)
{
    return X509_VERIFY_PARAM_set_trust(s->param, trust);
}

int SSL_set_trust(SSL *s, int trust)
{
    return X509_VERIFY_PARAM_set_trust(s->param, trust);
}

int SSL_CTX_set1_param(SSL_CTX *ctx, X509_VERIFY_PARAM *vpm)
{
    return X509_VERIFY_PARAM_set1(ctx->param, vpm);
}

int SSL_set1_param(SSL *ssl, X509_VERIFY_PARAM *vpm)
{
    return X509_VERIFY_PARAM_set1(ssl->param, vpm);
}

X509_VERIFY_PARAM *SSL_CTX_get0_param(SSL_CTX *ctx)
{
    return ctx->param;
}

X509_VERIFY_PARAM *SSL_get0_param(SSL *ssl)
{
    return ssl->param;
}

void SSL_certs_clear(SSL *s)
{
    ssl_cert_clear_certs(s->cert);
}

void SSL_free(SSL *s)
{
    int i;

    if (s == NULL)
        return;

    i = CRYPTO_add(&s->references, -1, CRYPTO_LOCK_SSL);
#ifdef REF_PRINT
    REF_PRINT("SSL", s);
#endif
    if (i > 0)
        return;
#ifdef REF_CHECK
    if (i < 0) {
        fprintf(stderr, "SSL_free, bad reference count\n");
        abort();                /* ok */
    }
#endif

    if (s->param)
        X509_VERIFY_PARAM_free(s->param);

    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_SSL, s, &s->ex_data);

    if (s->bbio != NULL) {
        /* If the buffering BIO is in place, pop it off */
        if (s->bbio == s->wbio) {
            s->wbio = BIO_pop(s->wbio);
        }
        BIO_free(s->bbio);
        s->bbio = NULL;
    }
    if (s->rbio != NULL)
        BIO_free_all(s->rbio);
    if ((s->wbio != NULL) && (s->wbio != s->rbio))
        BIO_free_all(s->wbio);

    if (s->init_buf != NULL)
        BUF_MEM_free(s->init_buf);

    /* add extra stuff */
    if (s->cipher_list != NULL)
        sk_SSL_CIPHER_free(s->cipher_list);
    if (s->cipher_list_by_id != NULL)
        sk_SSL_CIPHER_free(s->cipher_list_by_id);

    /* Make the next call work :-) */
    if (s->session != NULL) {
        ssl_clear_bad_session(s);
        SSL_SESSION_free(s->session);
    }

    ssl_clear_cipher_ctx(s);
    ssl_clear_hash_ctx(&s->read_hash);
    ssl_clear_hash_ctx(&s->write_hash);

    if (s->cert != NULL)
        ssl_cert_free(s->cert);
    /* Free up if allocated */

#ifndef OPENSSL_NO_TLSEXT
    if (s->tlsext_hostname)
        OPENSSL_free(s->tlsext_hostname);
    if (s->initial_ctx)
        SSL_CTX_free(s->initial_ctx);
# ifndef OPENSSL_NO_EC
    if (s->tlsext_ecpointformatlist)
        OPENSSL_free(s->tlsext_ecpointformatlist);
    if (s->tlsext_ellipticcurvelist)
        OPENSSL_free(s->tlsext_ellipticcurvelist);
# endif                         /* OPENSSL_NO_EC */
    if (s->tlsext_opaque_prf_input)
        OPENSSL_free(s->tlsext_opaque_prf_input);
    if (s->tlsext_ocsp_exts)
        sk_X509_EXTENSION_pop_free(s->tlsext_ocsp_exts, X509_EXTENSION_free);
    if (s->tlsext_ocsp_ids)
        sk_OCSP_RESPID_pop_free(s->tlsext_ocsp_ids, OCSP_RESPID_free);
    if (s->tlsext_ocsp_resp)
        OPENSSL_free(s->tlsext_ocsp_resp);
    if (s->alpn_client_proto_list)
        OPENSSL_free(s->alpn_client_proto_list);
#endif

    if (s->client_CA != NULL)
        sk_X509_NAME_pop_free(s->client_CA, X509_NAME_free);

    if (s->method != NULL)
        s->method->ssl_free(s);

    if (s->ctx)
        SSL_CTX_free(s->ctx);

#ifndef OPENSSL_NO_KRB5
    if (s->kssl_ctx != NULL)
        kssl_ctx_free(s->kssl_ctx);
#endif                          /* OPENSSL_NO_KRB5 */

#if !defined(OPENSSL_NO_TLSEXT) && !defined(OPENSSL_NO_NEXTPROTONEG)
    if (s->next_proto_negotiated)
        OPENSSL_free(s->next_proto_negotiated);
#endif

#ifndef OPENSSL_NO_SRTP
    if (s->srtp_profiles)
        sk_SRTP_PROTECTION_PROFILE_free(s->srtp_profiles);
#endif

    OPENSSL_free(s);
}

void SSL_set_bio(SSL *s, BIO *rbio, BIO *wbio)
{
    /*
     * If the output buffering BIO is still in place, remove it
     */
    if (s->bbio != NULL) {
        if (s->wbio == s->bbio) {
            s->wbio = s->wbio->next_bio;
            s->bbio->next_bio = NULL;
        }
    }
    if ((s->rbio != NULL) && (s->rbio != rbio))
        BIO_free_all(s->rbio);
    if ((s->wbio != NULL) && (s->wbio != wbio) && (s->rbio != s->wbio))
        BIO_free_all(s->wbio);
    s->rbio = rbio;
    s->wbio = wbio;
}

BIO *SSL_get_rbio(const SSL *s)
{
    return (s->rbio);
}

BIO *SSL_get_wbio(const SSL *s)
{
    return (s->wbio);
}

int SSL_get_fd(const SSL *s)
{
    return (SSL_get_rfd(s));
}

int SSL_get_rfd(const SSL *s)
{
    int ret = -1;
    BIO *b, *r;

    b = SSL_get_rbio(s);
    r = BIO_find_type(b, BIO_TYPE_DESCRIPTOR);
    if (r != NULL)
        BIO_get_fd(r, &ret);
    return (ret);
}

int SSL_get_wfd(const SSL *s)
{
    int ret = -1;
    BIO *b, *r;

    b = SSL_get_wbio(s);
    r = BIO_find_type(b, BIO_TYPE_DESCRIPTOR);
    if (r != NULL)
        BIO_get_fd(r, &ret);
    return (ret);
}

#ifndef OPENSSL_NO_SOCK
int SSL_set_fd(SSL *s, int fd)
{
    int ret = 0;
    BIO *bio = NULL;

    bio = BIO_new(BIO_s_socket());

    if (bio == NULL) {
        SSLerr(SSL_F_SSL_SET_FD, ERR_R_BUF_LIB);
        goto err;
    }
    BIO_set_fd(bio, fd, BIO_NOCLOSE);
    SSL_set_bio(s, bio, bio);
    ret = 1;
 err:
    return (ret);
}

int SSL_set_wfd(SSL *s, int fd)
{
    int ret = 0;
    BIO *bio = NULL;

    if ((s->rbio == NULL) || (BIO_method_type(s->rbio) != BIO_TYPE_SOCKET)
        || ((int)BIO_get_fd(s->rbio, NULL) != fd)) {
        bio = BIO_new(BIO_s_socket());

        if (bio == NULL) {
            SSLerr(SSL_F_SSL_SET_WFD, ERR_R_BUF_LIB);
            goto err;
        }
        BIO_set_fd(bio, fd, BIO_NOCLOSE);
        SSL_set_bio(s, SSL_get_rbio(s), bio);
    } else
        SSL_set_bio(s, SSL_get_rbio(s), SSL_get_rbio(s));
    ret = 1;
 err:
    return (ret);
}

int SSL_set_rfd(SSL *s, int fd)
{
    int ret = 0;
    BIO *bio = NULL;

    if ((s->wbio == NULL) || (BIO_method_type(s->wbio) != BIO_TYPE_SOCKET)
        || ((int)BIO_get_fd(s->wbio, NULL) != fd)) {
        bio = BIO_new(BIO_s_socket());

        if (bio == NULL) {
            SSLerr(SSL_F_SSL_SET_RFD, ERR_R_BUF_LIB);
            goto err;
        }
        BIO_set_fd(bio, fd, BIO_NOCLOSE);
        SSL_set_bio(s, bio, SSL_get_wbio(s));
    } else
        SSL_set_bio(s, SSL_get_wbio(s), SSL_get_wbio(s));
    ret = 1;
 err:
    return (ret);
}
#endif

/* return length of latest Finished message we sent, copy to 'buf' */
size_t SSL_get_finished(const SSL *s, void *buf, size_t count)
{
    size_t ret = 0;

    if (s->s3 != NULL) {
        ret = s->s3->tmp.finish_md_len;
        if (count > ret)
            count = ret;
        memcpy(buf, s->s3->tmp.finish_md, count);
    }
    return ret;
}

/* return length of latest Finished message we expected, copy to 'buf' */
size_t SSL_get_peer_finished(const SSL *s, void *buf, size_t count)
{
    size_t ret = 0;

    if (s->s3 != NULL) {
        ret = s->s3->tmp.peer_finish_md_len;
        if (count > ret)
            count = ret;
        memcpy(buf, s->s3->tmp.peer_finish_md, count);
    }
    return ret;
}

int SSL_get_verify_mode(const SSL *s)
{
    return (s->verify_mode);
}

int SSL_get_verify_depth(const SSL *s)
{
    return X509_VERIFY_PARAM_get_depth(s->param);
}

int (*SSL_get_verify_callback(const SSL *s)) (int, X509_STORE_CTX *) {
    return (s->verify_callback);
}

int SSL_CTX_get_verify_mode(const SSL_CTX *ctx)
{
    return (ctx->verify_mode);
}

int SSL_CTX_get_verify_depth(const SSL_CTX *ctx)
{
    return X509_VERIFY_PARAM_get_depth(ctx->param);
}

int (*SSL_CTX_get_verify_callback(const SSL_CTX *ctx)) (int, X509_STORE_CTX *) {
    return (ctx->default_verify_callback);
}

void SSL_set_verify(SSL *s, int mode,
                    int (*callback) (int ok, X509_STORE_CTX *ctx))
{
    s->verify_mode = mode;
    if (callback != NULL)
        s->verify_callback = callback;
}

void SSL_set_verify_depth(SSL *s, int depth)
{
    X509_VERIFY_PARAM_set_depth(s->param, depth);
}

void SSL_set_read_ahead(SSL *s, int yes)
{
    s->read_ahead = yes;
}

int SSL_get_read_ahead(const SSL *s)
{
    return (s->read_ahead);
}

int SSL_pending(const SSL *s)
{
    /*
     * SSL_pending cannot work properly if read-ahead is enabled
     * (SSL_[CTX_]ctrl(..., SSL_CTRL_SET_READ_AHEAD, 1, NULL)), and it is
     * impossible to fix since SSL_pending cannot report errors that may be
     * observed while scanning the new data. (Note that SSL_pending() is
     * often used as a boolean value, so we'd better not return -1.)
     */
    return (s->method->ssl_pending(s));
}

X509 *SSL_get_peer_certificate(const SSL *s)
{
    X509 *r;

    if ((s == NULL) || (s->session == NULL))
        r = NULL;
    else
        r = s->session->peer;

    if (r == NULL)
        return (r);

    CRYPTO_add(&r->references, 1, CRYPTO_LOCK_X509);

    return (r);
}

STACK_OF(X509) *SSL_get_peer_cert_chain(const SSL *s)
{
    STACK_OF(X509) *r;

    if ((s == NULL) || (s->session == NULL)
        || (s->session->sess_cert == NULL))
        r = NULL;
    else
        r = s->session->sess_cert->cert_chain;

    /*
     * If we are a client, cert_chain includes the peer's own certificate; if
     * we are a server, it does not.
     */

    return (r);
}

/*
 * Now in theory, since the calling process own 't' it should be safe to
 * modify.  We need to be able to read f without being hassled
 */
void SSL_copy_session_id(SSL *t, const SSL *f)
{
    CERT *tmp;

    /* Do we need to to SSL locking? */
    SSL_set_session(t, SSL_get_session(f));

    /*
     * what if we are setup as SSLv2 but want to talk SSLv3 or vice-versa
     */
    if (t->method != f->method) {
        t->method->ssl_free(t); /* cleanup current */
        t->method = f->method;  /* change method */
        t->method->ssl_new(t);  /* setup new */
    }

    tmp = t->cert;
    if (f->cert != NULL) {
        CRYPTO_add(&f->cert->references, 1, CRYPTO_LOCK_SSL_CERT);
        t->cert = f->cert;
    } else
        t->cert = NULL;
    if (tmp != NULL)
        ssl_cert_free(tmp);
    SSL_set_session_id_context(t, f->sid_ctx, f->sid_ctx_length);
}

/* Fix this so it checks all the valid key/cert options */
int SSL_CTX_check_private_key(const SSL_CTX *ctx)
{
    if ((ctx == NULL) ||
        (ctx->cert == NULL) || (ctx->cert->key->x509 == NULL)) {
        SSLerr(SSL_F_SSL_CTX_CHECK_PRIVATE_KEY,
               SSL_R_NO_CERTIFICATE_ASSIGNED);
        return (0);
    }
    if (ctx->cert->key->privatekey == NULL) {
        SSLerr(SSL_F_SSL_CTX_CHECK_PRIVATE_KEY,
               SSL_R_NO_PRIVATE_KEY_ASSIGNED);
        return (0);
    }
    return (X509_check_private_key
            (ctx->cert->key->x509, ctx->cert->key->privatekey));
}

/* Fix this function so that it takes an optional type parameter */
int SSL_check_private_key(const SSL *ssl)
{
    if (ssl == NULL) {
        SSLerr(SSL_F_SSL_CHECK_PRIVATE_KEY, ERR_R_PASSED_NULL_PARAMETER);
        return (0);
    }
    if (ssl->cert == NULL) {
        SSLerr(SSL_F_SSL_CHECK_PRIVATE_KEY, SSL_R_NO_CERTIFICATE_ASSIGNED);
        return 0;
    }
    if (ssl->cert->key->x509 == NULL) {
        SSLerr(SSL_F_SSL_CHECK_PRIVATE_KEY, SSL_R_NO_CERTIFICATE_ASSIGNED);
        return (0);
    }
    if (ssl->cert->key->privatekey == NULL) {
        SSLerr(SSL_F_SSL_CHECK_PRIVATE_KEY, SSL_R_NO_PRIVATE_KEY_ASSIGNED);
        return (0);
    }
    return (X509_check_private_key(ssl->cert->key->x509,
                                   ssl->cert->key->privatekey));
}

int SSL_accept(SSL *s)
{
    if (s->handshake_func == 0)
        /* Not properly initialized yet */
        SSL_set_accept_state(s);

    return (s->method->ssl_accept(s));
}

int SSL_connect(SSL *s)
{
    if (s->handshake_func == 0)
        /* Not properly initialized yet */
        SSL_set_connect_state(s);

    return (s->method->ssl_connect(s));
}

long SSL_get_default_timeout(const SSL *s)
{
    return (s->method->get_timeout());
}

int SSL_read(SSL *s, void *buf, int num)
{
    if (s->handshake_func == 0) {
        SSLerr(SSL_F_SSL_READ, SSL_R_UNINITIALIZED);
        return -1;
    }

    if (s->shutdown & SSL_RECEIVED_SHUTDOWN) {
        s->rwstate = SSL_NOTHING;
        return (0);
    }
    return (s->method->ssl_read(s, buf, num));
}

int SSL_peek(SSL *s, void *buf, int num)
{
    if (s->handshake_func == 0) {
        SSLerr(SSL_F_SSL_PEEK, SSL_R_UNINITIALIZED);
        return -1;
    }

    if (s->shutdown & SSL_RECEIVED_SHUTDOWN) {
        return (0);
    }
    return (s->method->ssl_peek(s, buf, num));
}

int SSL_write(SSL *s, const void *buf, int num)
{
    if (s->handshake_func == 0) {
        SSLerr(SSL_F_SSL_WRITE, SSL_R_UNINITIALIZED);
        return -1;
    }

    if (s->shutdown & SSL_SENT_SHUTDOWN) {
        s->rwstate = SSL_NOTHING;
        SSLerr(SSL_F_SSL_WRITE, SSL_R_PROTOCOL_IS_SHUTDOWN);
        return (-1);
    }
    return (s->method->ssl_write(s, buf, num));
}

int SSL_shutdown(SSL *s)
{
    /*
     * Note that this function behaves differently from what one might
     * expect.  Return values are 0 for no success (yet), 1 for success; but
     * calling it once is usually not enough, even if blocking I/O is used
     * (see ssl3_shutdown).
     */

    if (s->handshake_func == 0) {
        SSLerr(SSL_F_SSL_SHUTDOWN, SSL_R_UNINITIALIZED);
        return -1;
    }

    if (!SSL_in_init(s)) {
        return s->method->ssl_shutdown(s);
    } else {
        SSLerr(SSL_F_SSL_SHUTDOWN, SSL_R_SHUTDOWN_WHILE_IN_INIT);
        return -1;
    }
}

int SSL_renegotiate(SSL *s)
{
    if (s->renegotiate == 0)
        s->renegotiate = 1;

    s->new_session = 1;

    return (s->method->ssl_renegotiate(s));
}

int SSL_renegotiate_abbreviated(SSL *s)
{
    if (s->renegotiate == 0)
        s->renegotiate = 1;

    s->new_session = 0;

    return (s->method->ssl_renegotiate(s));
}

int SSL_renegotiate_pending(SSL *s)
{
    /*
     * becomes true when negotiation is requested; false again once a
     * handshake has finished
     */
    return (s->renegotiate != 0);
}

long SSL_ctrl(SSL *s, int cmd, long larg, void *parg)
{
    long l;

    switch (cmd) {
    case SSL_CTRL_GET_READ_AHEAD:
        return (s->read_ahead);
    case SSL_CTRL_SET_READ_AHEAD:
        l = s->read_ahead;
        s->read_ahead = larg;
        return (l);

    case SSL_CTRL_SET_MSG_CALLBACK_ARG:
        s->msg_callback_arg = parg;
        return 1;

    case SSL_CTRL_OPTIONS:
        return (s->options |= larg);
    case SSL_CTRL_CLEAR_OPTIONS:
        return (s->options &= ~larg);
    case SSL_CTRL_MODE:
        return (s->mode |= larg);
    case SSL_CTRL_CLEAR_MODE:
        return (s->mode &= ~larg);
    case SSL_CTRL_GET_MAX_CERT_LIST:
        return (s->max_cert_list);
    case SSL_CTRL_SET_MAX_CERT_LIST:
        l = s->max_cert_list;
        s->max_cert_list = larg;
        return (l);
    case SSL_CTRL_SET_MAX_SEND_FRAGMENT:
        if (larg < 512 || larg > SSL3_RT_MAX_PLAIN_LENGTH)
            return 0;
        s->max_send_fragment = larg;
        return 1;
    case SSL_CTRL_GET_RI_SUPPORT:
        if (s->s3)
            return s->s3->send_connection_binding;
        else
            return 0;
    case SSL_CTRL_CERT_FLAGS:
        return (s->cert->cert_flags |= larg);
    case SSL_CTRL_CLEAR_CERT_FLAGS:
        return (s->cert->cert_flags &= ~larg);

    case SSL_CTRL_GET_RAW_CIPHERLIST:
        if (parg) {
            if (s->cert->ciphers_raw == NULL)
                return 0;
            *(unsigned char **)parg = s->cert->ciphers_raw;
            return (int)s->cert->ciphers_rawlen;
        } else
            return ssl_put_cipher_by_char(s, NULL, NULL);
    default:
        return (s->method->ssl_ctrl(s, cmd, larg, parg));
    }
}

long SSL_callback_ctrl(SSL *s, int cmd, void (*fp) (void))
{
    switch (cmd) {
    case SSL_CTRL_SET_MSG_CALLBACK:
        s->msg_callback = (void (*)
                           (int write_p, int version, int content_type,
                            const void *buf, size_t len, SSL *ssl,
                            void *arg))(fp);
        return 1;

    default:
        return (s->method->ssl_callback_ctrl(s, cmd, fp));
    }
}

LHASH_OF(SSL_SESSION) *SSL_CTX_sessions(SSL_CTX *ctx)
{
    return ctx->sessions;
}

long SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg)
{
    long l;
    /* For some cases with ctx == NULL perform syntax checks */
    if (ctx == NULL) {
        switch (cmd) {
#ifndef OPENSSL_NO_EC
        case SSL_CTRL_SET_CURVES_LIST:
            return tls1_set_curves_list(NULL, NULL, parg);
#endif
        case SSL_CTRL_SET_SIGALGS_LIST:
        case SSL_CTRL_SET_CLIENT_SIGALGS_LIST:
            return tls1_set_sigalgs_list(NULL, parg, 0);
        default:
            return 0;
        }
    }

    switch (cmd) {
    case SSL_CTRL_GET_READ_AHEAD:
        return (ctx->read_ahead);
    case SSL_CTRL_SET_READ_AHEAD:
        l = ctx->read_ahead;
        ctx->read_ahead = larg;
        return (l);

    case SSL_CTRL_SET_MSG_CALLBACK_ARG:
        ctx->msg_callback_arg = parg;
        return 1;

    case SSL_CTRL_GET_MAX_CERT_LIST:
        return (ctx->max_cert_list);
    case SSL_CTRL_SET_MAX_CERT_LIST:
        l = ctx->max_cert_list;
        ctx->max_cert_list = larg;
        return (l);

    case SSL_CTRL_SET_SESS_CACHE_SIZE:
        l = ctx->session_cache_size;
        ctx->session_cache_size = larg;
        return (l);
    case SSL_CTRL_GET_SESS_CACHE_SIZE:
        return (ctx->session_cache_size);
    case SSL_CTRL_SET_SESS_CACHE_MODE:
        l = ctx->session_cache_mode;
        ctx->session_cache_mode = larg;
        return (l);
    case SSL_CTRL_GET_SESS_CACHE_MODE:
        return (ctx->session_cache_mode);

    case SSL_CTRL_SESS_NUMBER:
        return (lh_SSL_SESSION_num_items(ctx->sessions));
    case SSL_CTRL_SESS_CONNECT:
        return (ctx->stats.sess_connect);
    case SSL_CTRL_SESS_CONNECT_GOOD:
        return (ctx->stats.sess_connect_good);
    case SSL_CTRL_SESS_CONNECT_RENEGOTIATE:
        return (ctx->stats.sess_connect_renegotiate);
    case SSL_CTRL_SESS_ACCEPT:
        return (ctx->stats.sess_accept);
    case SSL_CTRL_SESS_ACCEPT_GOOD:
        return (ctx->stats.sess_accept_good);
    case SSL_CTRL_SESS_ACCEPT_RENEGOTIATE:
        return (ctx->stats.sess_accept_renegotiate);
    case SSL_CTRL_SESS_HIT:
        return (ctx->stats.sess_hit);
    case SSL_CTRL_SESS_CB_HIT:
        return (ctx->stats.sess_cb_hit);
    case SSL_CTRL_SESS_MISSES:
        return (ctx->stats.sess_miss);
    case SSL_CTRL_SESS_TIMEOUTS:
        return (ctx->stats.sess_timeout);
    case SSL_CTRL_SESS_CACHE_FULL:
        return (ctx->stats.sess_cache_full);
    case SSL_CTRL_OPTIONS:
        return (ctx->options |= larg);
    case SSL_CTRL_CLEAR_OPTIONS:
        return (ctx->options &= ~larg);
    case SSL_CTRL_MODE:
        return (ctx->mode |= larg);
    case SSL_CTRL_CLEAR_MODE:
        return (ctx->mode &= ~larg);
    case SSL_CTRL_SET_MAX_SEND_FRAGMENT:
        if (larg < 512 || larg > SSL3_RT_MAX_PLAIN_LENGTH)
            return 0;
        ctx->max_send_fragment = larg;
        return 1;
    case SSL_CTRL_CERT_FLAGS:
        return (ctx->cert->cert_flags |= larg);
    case SSL_CTRL_CLEAR_CERT_FLAGS:
        return (ctx->cert->cert_flags &= ~larg);
    default:
        return (ctx->method->ssl_ctx_ctrl(ctx, cmd, larg, parg));
    }
}

long SSL_CTX_callback_ctrl(SSL_CTX *ctx, int cmd, void (*fp) (void))
{
    switch (cmd) {
    case SSL_CTRL_SET_MSG_CALLBACK:
        ctx->msg_callback = (void (*)
                             (int write_p, int version, int content_type,
                              const void *buf, size_t len, SSL *ssl,
                              void *arg))(fp);
        return 1;

    default:
        return (ctx->method->ssl_ctx_callback_ctrl(ctx, cmd, fp));
    }
}

int ssl_cipher_id_cmp(const SSL_CIPHER *a, const SSL_CIPHER *b)
{
    long l;

    l = a->id - b->id;
    if (l == 0L)
        return (0);
    else
        return ((l > 0) ? 1 : -1);
}

int ssl_cipher_ptr_id_cmp(const SSL_CIPHER *const *ap,
                          const SSL_CIPHER *const *bp)
{
    long l;

    l = (*ap)->id - (*bp)->id;
    if (l == 0L)
        return (0);
    else
        return ((l > 0) ? 1 : -1);
}

/** return a STACK of the ciphers available for the SSL and in order of
 * preference */
STACK_OF(SSL_CIPHER) *SSL_get_ciphers(const SSL *s)
{
    if (s != NULL) {
        if (s->cipher_list != NULL) {
            return (s->cipher_list);
        } else if ((s->ctx != NULL) && (s->ctx->cipher_list != NULL)) {
            return (s->ctx->cipher_list);
        }
    }
    return (NULL);
}

/** return a STACK of the ciphers available for the SSL and in order of
 * algorithm id */
STACK_OF(SSL_CIPHER) *ssl_get_ciphers_by_id(SSL *s)
{
    if (s != NULL) {
        if (s->cipher_list_by_id != NULL) {
            return (s->cipher_list_by_id);
        } else if ((s->ctx != NULL) && (s->ctx->cipher_list_by_id != NULL)) {
            return (s->ctx->cipher_list_by_id);
        }
    }
    return (NULL);
}

/** The old interface to get the same thing as SSL_get_ciphers() */
const char *SSL_get_cipher_list(const SSL *s, int n)
{
    SSL_CIPHER *c;
    STACK_OF(SSL_CIPHER) *sk;

    if (s == NULL)
        return (NULL);
    sk = SSL_get_ciphers(s);
    if ((sk == NULL) || (sk_SSL_CIPHER_num(sk) <= n))
        return (NULL);
    c = sk_SSL_CIPHER_value(sk, n);
    if (c == NULL)
        return (NULL);
    return (c->name);
}

/** specify the ciphers to be used by default by the SSL_CTX */
int SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str)
{
    STACK_OF(SSL_CIPHER) *sk;

    sk = ssl_create_cipher_list(ctx->method, &ctx->cipher_list,
                                &ctx->cipher_list_by_id, str, ctx->cert);
    /*
     * ssl_create_cipher_list may return an empty stack if it was unable to
     * find a cipher matching the given rule string (for example if the rule
     * string specifies a cipher which has been disabled). This is not an
     * error as far as ssl_create_cipher_list is concerned, and hence
     * ctx->cipher_list and ctx->cipher_list_by_id has been updated.
     */
    if (sk == NULL)
        return 0;
    else if (sk_SSL_CIPHER_num(sk) == 0) {
        SSLerr(SSL_F_SSL_CTX_SET_CIPHER_LIST, SSL_R_NO_CIPHER_MATCH);
        return 0;
    }
    return 1;
}

/** specify the ciphers to be used by the SSL */
int SSL_set_cipher_list(SSL *s, const char *str)
{
    STACK_OF(SSL_CIPHER) *sk;

    sk = ssl_create_cipher_list(s->ctx->method, &s->cipher_list,
                                &s->cipher_list_by_id, str, s->cert);
    /* see comment in SSL_CTX_set_cipher_list */
    if (sk == NULL)
        return 0;
    else if (sk_SSL_CIPHER_num(sk) == 0) {
        SSLerr(SSL_F_SSL_SET_CIPHER_LIST, SSL_R_NO_CIPHER_MATCH);
        return 0;
    }
    return 1;
}

/* works well for SSLv2, not so good for SSLv3 */
char *SSL_get_shared_ciphers(const SSL *s, char *buf, int size)
{
    char *p;
    STACK_OF(SSL_CIPHER) *clntsk, *srvrsk;
    SSL_CIPHER *c;
    int i;

    if (!s->server
            || s->session == NULL
            || s->session->ciphers == NULL
            || size < 2)
        return NULL;

    p = buf;
    clntsk = s->session->ciphers;
    srvrsk = SSL_get_ciphers(s);
    if (clntsk == NULL || srvrsk == NULL)
        return NULL;

    if (sk_SSL_CIPHER_num(clntsk) == 0 || sk_SSL_CIPHER_num(srvrsk) == 0)
        return NULL;

    for (i = 0; i < sk_SSL_CIPHER_num(clntsk); i++) {
        int n;

        c = sk_SSL_CIPHER_value(clntsk, i);
        if (sk_SSL_CIPHER_find(srvrsk, c) < 0)
            continue;

        n = strlen(c->name);
        if (n + 1 > size) {
            if (p != buf)
                --p;
            *p = '\0';
            return buf;
        }
        strcpy(p, c->name);
        p += n;
        *(p++) = ':';
        size -= n + 1;
    }
    p[-1] = '\0';
    return (buf);
}

int ssl_cipher_list_to_bytes(SSL *s, STACK_OF(SSL_CIPHER) *sk,
                             unsigned char *p,
                             int (*put_cb) (const SSL_CIPHER *,
                                            unsigned char *))
{
    int i, j = 0;
    SSL_CIPHER *c;
    CERT *ct = s->cert;
    unsigned char *q;
    int empty_reneg_info_scsv = !s->renegotiate;
    /* Set disabled masks for this session */
    ssl_set_client_disabled(s);

    if (sk == NULL)
        return (0);
    q = p;
    if (put_cb == NULL)
        put_cb = s->method->put_cipher_by_char;

    for (i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
        c = sk_SSL_CIPHER_value(sk, i);
        /* Skip disabled ciphers */
        if (c->algorithm_ssl & ct->mask_ssl ||
            c->algorithm_mkey & ct->mask_k || c->algorithm_auth & ct->mask_a)
            continue;
#ifdef OPENSSL_SSL_DEBUG_BROKEN_PROTOCOL
        if (c->id == SSL3_CK_SCSV) {
            if (!empty_reneg_info_scsv)
                continue;
            else
                empty_reneg_info_scsv = 0;
        }
#endif
        j = put_cb(c, p);
        p += j;
    }
    /*
     * If p == q, no ciphers; caller indicates an error. Otherwise, add
     * applicable SCSVs.
     */
    if (p != q) {
        if (empty_reneg_info_scsv) {
            static SSL_CIPHER scsv = {
                0, NULL, SSL3_CK_SCSV, 0, 0, 0, 0, 0, 0, 0, 0, 0
            };
            j = put_cb(&scsv, p);
            p += j;
#ifdef OPENSSL_RI_DEBUG
            fprintf(stderr,
                    "TLS_EMPTY_RENEGOTIATION_INFO_SCSV sent by client\n");
#endif
        }
        if (s->mode & SSL_MODE_SEND_FALLBACK_SCSV) {
            static SSL_CIPHER scsv = {
                0, NULL, SSL3_CK_FALLBACK_SCSV, 0, 0, 0, 0, 0, 0, 0, 0, 0
            };
            j = put_cb(&scsv, p);
            p += j;
        }
    }

    return (p - q);
}

STACK_OF(SSL_CIPHER) *ssl_bytes_to_cipher_list(SSL *s, unsigned char *p,
                                               int num,
                                               STACK_OF(SSL_CIPHER) **skp)
{
    const SSL_CIPHER *c;
    STACK_OF(SSL_CIPHER) *sk;
    int i, n;

    if (s->s3)
        s->s3->send_connection_binding = 0;

    n = ssl_put_cipher_by_char(s, NULL, NULL);
    if (n == 0 || (num % n) != 0) {
        SSLerr(SSL_F_SSL_BYTES_TO_CIPHER_LIST,
               SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST);
        return (NULL);
    }
    if ((skp == NULL) || (*skp == NULL)) {
        sk = sk_SSL_CIPHER_new_null(); /* change perhaps later */
        if(sk == NULL) {
            SSLerr(SSL_F_SSL_BYTES_TO_CIPHER_LIST, ERR_R_MALLOC_FAILURE);
            return NULL;
        }
    } else {
        sk = *skp;
        sk_SSL_CIPHER_zero(sk);
    }

    if (s->cert->ciphers_raw)
        OPENSSL_free(s->cert->ciphers_raw);
    s->cert->ciphers_raw = BUF_memdup(p, num);
    if (s->cert->ciphers_raw == NULL) {
        SSLerr(SSL_F_SSL_BYTES_TO_CIPHER_LIST, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    s->cert->ciphers_rawlen = (size_t)num;

    for (i = 0; i < num; i += n) {
        /* Check for TLS_EMPTY_RENEGOTIATION_INFO_SCSV */
        if (s->s3 && (n != 3 || !p[0]) &&
            (p[n - 2] == ((SSL3_CK_SCSV >> 8) & 0xff)) &&
            (p[n - 1] == (SSL3_CK_SCSV & 0xff))) {
            /* SCSV fatal if renegotiating */
            if (s->renegotiate) {
                SSLerr(SSL_F_SSL_BYTES_TO_CIPHER_LIST,
                       SSL_R_SCSV_RECEIVED_WHEN_RENEGOTIATING);
                ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
                goto err;
            }
            s->s3->send_connection_binding = 1;
            p += n;
#ifdef OPENSSL_RI_DEBUG
            fprintf(stderr, "SCSV received by server\n");
#endif
            continue;
        }

        /* Check for TLS_FALLBACK_SCSV */
        if ((n != 3 || !p[0]) &&
            (p[n - 2] == ((SSL3_CK_FALLBACK_SCSV >> 8) & 0xff)) &&
            (p[n - 1] == (SSL3_CK_FALLBACK_SCSV & 0xff))) {
            /*
             * The SCSV indicates that the client previously tried a higher
             * version. Fail if the current version is an unexpected
             * downgrade.
             */
            if (!SSL_ctrl(s, SSL_CTRL_CHECK_PROTO_VERSION, 0, NULL)) {
                SSLerr(SSL_F_SSL_BYTES_TO_CIPHER_LIST,
                       SSL_R_INAPPROPRIATE_FALLBACK);
                if (s->s3)
                    ssl3_send_alert(s, SSL3_AL_FATAL,
                                    SSL_AD_INAPPROPRIATE_FALLBACK);
                goto err;
            }
            p += n;
            continue;
        }

        c = ssl_get_cipher_by_char(s, p);
        p += n;
        if (c != NULL) {
            if (!sk_SSL_CIPHER_push(sk, c)) {
                SSLerr(SSL_F_SSL_BYTES_TO_CIPHER_LIST, ERR_R_MALLOC_FAILURE);
                goto err;
            }
        }
    }

    if (skp != NULL)
        *skp = sk;
    return (sk);
 err:
    if ((skp == NULL) || (*skp == NULL))
        sk_SSL_CIPHER_free(sk);
    return (NULL);
}

#ifndef OPENSSL_NO_TLSEXT
/** return a servername extension value if provided in Client Hello, or NULL.
 * So far, only host_name types are defined (RFC 3546).
 */

const char *SSL_get_servername(const SSL *s, const int type)
{
    if (type != TLSEXT_NAMETYPE_host_name)
        return NULL;

    return s->session && !s->tlsext_hostname ?
        s->session->tlsext_hostname : s->tlsext_hostname;
}

int SSL_get_servername_type(const SSL *s)
{
    if (s->session
        && (!s->tlsext_hostname ? s->session->
            tlsext_hostname : s->tlsext_hostname))
        return TLSEXT_NAMETYPE_host_name;
    return -1;
}

/*
 * SSL_select_next_proto implements the standard protocol selection. It is
 * expected that this function is called from the callback set by
 * SSL_CTX_set_next_proto_select_cb. The protocol data is assumed to be a
 * vector of 8-bit, length prefixed byte strings. The length byte itself is
 * not included in the length. A byte string of length 0 is invalid. No byte
 * string may be truncated. The current, but experimental algorithm for
 * selecting the protocol is: 1) If the server doesn't support NPN then this
 * is indicated to the callback. In this case, the client application has to
 * abort the connection or have a default application level protocol. 2) If
 * the server supports NPN, but advertises an empty list then the client
 * selects the first protcol in its list, but indicates via the API that this
 * fallback case was enacted. 3) Otherwise, the client finds the first
 * protocol in the server's list that it supports and selects this protocol.
 * This is because it's assumed that the server has better information about
 * which protocol a client should use. 4) If the client doesn't support any
 * of the server's advertised protocols, then this is treated the same as
 * case 2. It returns either OPENSSL_NPN_NEGOTIATED if a common protocol was
 * found, or OPENSSL_NPN_NO_OVERLAP if the fallback case was reached.
 */
int SSL_select_next_proto(unsigned char **out, unsigned char *outlen,
                          const unsigned char *server,
                          unsigned int server_len,
                          const unsigned char *client,
                          unsigned int client_len)
{
    unsigned int i, j;
    const unsigned char *result;
    int status = OPENSSL_NPN_UNSUPPORTED;

    /*
     * For each protocol in server preference order, see if we support it.
     */
    for (i = 0; i < server_len;) {
        for (j = 0; j < client_len;) {
            if (server[i] == client[j] &&
                memcmp(&server[i + 1], &client[j + 1], server[i]) == 0) {
                /* We found a match */
                result = &server[i];
                status = OPENSSL_NPN_NEGOTIATED;
                goto found;
            }
            j += client[j];
            j++;
        }
        i += server[i];
        i++;
    }

    /* There's no overlap between our protocols and the server's list. */
    result = client;
    status = OPENSSL_NPN_NO_OVERLAP;

 found:
    *out = (unsigned char *)result + 1;
    *outlen = result[0];
    return status;
}

# ifndef OPENSSL_NO_NEXTPROTONEG
/*
 * SSL_get0_next_proto_negotiated sets *data and *len to point to the
 * client's requested protocol for this connection and returns 0. If the
 * client didn't request any protocol, then *data is set to NULL. Note that
 * the client can request any protocol it chooses. The value returned from
 * this function need not be a member of the list of supported protocols
 * provided by the callback.
 */
void SSL_get0_next_proto_negotiated(const SSL *s, const unsigned char **data,
                                    unsigned *len)
{
    *data = s->next_proto_negotiated;
    if (!*data) {
        *len = 0;
    } else {
        *len = s->next_proto_negotiated_len;
    }
}

/*
 * SSL_CTX_set_next_protos_advertised_cb sets a callback that is called when
 * a TLS server needs a list of supported protocols for Next Protocol
 * Negotiation. The returned list must be in wire format.  The list is
 * returned by setting |out| to point to it and |outlen| to its length. This
 * memory will not be modified, but one should assume that the SSL* keeps a
 * reference to it. The callback should return SSL_TLSEXT_ERR_OK if it
 * wishes to advertise. Otherwise, no such extension will be included in the
 * ServerHello.
 */
void SSL_CTX_set_next_protos_advertised_cb(SSL_CTX *ctx,
                                           int (*cb) (SSL *ssl,
                                                      const unsigned char
                                                      **out,
                                                      unsigned int *outlen,
                                                      void *arg), void *arg)
{
    ctx->next_protos_advertised_cb = cb;
    ctx->next_protos_advertised_cb_arg = arg;
}

/*
 * SSL_CTX_set_next_proto_select_cb sets a callback that is called when a
 * client needs to select a protocol from the server's provided list. |out|
 * must be set to point to the selected protocol (which may be within |in|).
 * The length of the protocol name must be written into |outlen|. The
 * server's advertised protocols are provided in |in| and |inlen|. The
 * callback can assume that |in| is syntactically valid. The client must
 * select a protocol. It is fatal to the connection if this callback returns
 * a value other than SSL_TLSEXT_ERR_OK.
 */
void SSL_CTX_set_next_proto_select_cb(SSL_CTX *ctx,
                                      int (*cb) (SSL *s, unsigned char **out,
                                                 unsigned char *outlen,
                                                 const unsigned char *in,
                                                 unsigned int inlen,
                                                 void *arg), void *arg)
{
    ctx->next_proto_select_cb = cb;
    ctx->next_proto_select_cb_arg = arg;
}
# endif

/*
 * SSL_CTX_set_alpn_protos sets the ALPN protocol list on |ctx| to |protos|.
 * |protos| must be in wire-format (i.e. a series of non-empty, 8-bit
 * length-prefixed strings). Returns 0 on success.
 */
int SSL_CTX_set_alpn_protos(SSL_CTX *ctx, const unsigned char *protos,
                            unsigned protos_len)
{
    if (ctx->alpn_client_proto_list)
        OPENSSL_free(ctx->alpn_client_proto_list);

    ctx->alpn_client_proto_list = OPENSSL_malloc(protos_len);
    if (!ctx->alpn_client_proto_list)
        return 1;
    memcpy(ctx->alpn_client_proto_list, protos, protos_len);
    ctx->alpn_client_proto_list_len = protos_len;

    return 0;
}

/*
 * SSL_set_alpn_protos sets the ALPN protocol list on |ssl| to |protos|.
 * |protos| must be in wire-format (i.e. a series of non-empty, 8-bit
 * length-prefixed strings). Returns 0 on success.
 */
int SSL_set_alpn_protos(SSL *ssl, const unsigned char *protos,
                        unsigned protos_len)
{
    if (ssl->alpn_client_proto_list)
        OPENSSL_free(ssl->alpn_client_proto_list);

    ssl->alpn_client_proto_list = OPENSSL_malloc(protos_len);
    if (!ssl->alpn_client_proto_list)
        return 1;
    memcpy(ssl->alpn_client_proto_list, protos, protos_len);
    ssl->alpn_client_proto_list_len = protos_len;

    return 0;
}

/*
 * SSL_CTX_set_alpn_select_cb sets a callback function on |ctx| that is
 * called during ClientHello processing in order to select an ALPN protocol
 * from the client's list of offered protocols.
 */
void SSL_CTX_set_alpn_select_cb(SSL_CTX *ctx,
                                int (*cb) (SSL *ssl,
                                           const unsigned char **out,
                                           unsigned char *outlen,
                                           const unsigned char *in,
                                           unsigned int inlen,
                                           void *arg), void *arg)
{
    ctx->alpn_select_cb = cb;
    ctx->alpn_select_cb_arg = arg;
}

/*
 * SSL_get0_alpn_selected gets the selected ALPN protocol (if any) from
 * |ssl|. On return it sets |*data| to point to |*len| bytes of protocol name
 * (not including the leading length-prefix byte). If the server didn't
 * respond with a negotiated protocol then |*len| will be zero.
 */
void SSL_get0_alpn_selected(const SSL *ssl, const unsigned char **data,
                            unsigned *len)
{
    *data = NULL;
    if (ssl->s3)
        *data = ssl->s3->alpn_selected;
    if (*data == NULL)
        *len = 0;
    else
        *len = ssl->s3->alpn_selected_len;
}

#endif                          /* !OPENSSL_NO_TLSEXT */

int SSL_export_keying_material(SSL *s, unsigned char *out, size_t olen,
                               const char *label, size_t llen,
                               const unsigned char *context, size_t contextlen,
                               int use_context)
{
    if (s->version < TLS1_VERSION && s->version != DTLS1_BAD_VER)
        return -1;

    return s->method->ssl3_enc->export_keying_material(s, out, olen, label,
                                                       llen, context,
                                                       contextlen, use_context);
}

static unsigned long ssl_session_hash(const SSL_SESSION *a)
{
    const unsigned char *session_id = a->session_id;
    unsigned long l;
    unsigned char tmp_storage[4];

    if (a->session_id_length < sizeof(tmp_storage)) {
        memset(tmp_storage, 0, sizeof(tmp_storage));
        memcpy(tmp_storage, a->session_id, a->session_id_length);
        session_id = tmp_storage;
    }

    l = (unsigned long)
        ((unsigned long)session_id[0]) |
        ((unsigned long)session_id[1] << 8L) |
        ((unsigned long)session_id[2] << 16L) |
        ((unsigned long)session_id[3] << 24L);
    return (l);
}

/*
 * NB: If this function (or indeed the hash function which uses a sort of
 * coarser function than this one) is changed, ensure
 * SSL_CTX_has_matching_session_id() is checked accordingly. It relies on
 * being able to construct an SSL_SESSION that will collide with any existing
 * session with a matching session ID.
 */
static int ssl_session_cmp(const SSL_SESSION *a, const SSL_SESSION *b)
{
    if (a->ssl_version != b->ssl_version)
        return (1);
    if (a->session_id_length != b->session_id_length)
        return (1);
    return (memcmp(a->session_id, b->session_id, a->session_id_length));
}

/*
 * These wrapper functions should remain rather than redeclaring
 * SSL_SESSION_hash and SSL_SESSION_cmp for void* types and casting each
 * variable. The reason is that the functions aren't static, they're exposed
 * via ssl.h.
 */
static IMPLEMENT_LHASH_HASH_FN(ssl_session, SSL_SESSION)
static IMPLEMENT_LHASH_COMP_FN(ssl_session, SSL_SESSION)

SSL_CTX *SSL_CTX_new(const SSL_METHOD *meth)
{
    SSL_CTX *ret = NULL;

    if (meth == NULL) {
        SSLerr(SSL_F_SSL_CTX_NEW, SSL_R_NULL_SSL_METHOD_PASSED);
        return (NULL);
    }
#ifdef OPENSSL_FIPS
    if (FIPS_mode() && (meth->version < TLS1_VERSION)) {
        SSLerr(SSL_F_SSL_CTX_NEW, SSL_R_ONLY_TLS_ALLOWED_IN_FIPS_MODE);
        return NULL;
    }
#endif

    if (SSL_get_ex_data_X509_STORE_CTX_idx() < 0) {
        SSLerr(SSL_F_SSL_CTX_NEW, SSL_R_X509_VERIFICATION_SETUP_PROBLEMS);
        goto err;
    }
    ret = (SSL_CTX *)OPENSSL_malloc(sizeof(SSL_CTX));
    if (ret == NULL)
        goto err;

    memset(ret, 0, sizeof(SSL_CTX));

    ret->method = meth;

    ret->cert_store = NULL;
    ret->session_cache_mode = SSL_SESS_CACHE_SERVER;
    ret->session_cache_size = SSL_SESSION_CACHE_MAX_SIZE_DEFAULT;
    ret->session_cache_head = NULL;
    ret->session_cache_tail = NULL;

    /* We take the system default */
    ret->session_timeout = meth->get_timeout();

    ret->new_session_cb = 0;
    ret->remove_session_cb = 0;
    ret->get_session_cb = 0;
    ret->generate_session_id = 0;

    memset((char *)&ret->stats, 0, sizeof(ret->stats));

    ret->references = 1;
    ret->quiet_shutdown = 0;

/*  ret->cipher=NULL;*/
/*-
    ret->s2->challenge=NULL;
    ret->master_key=NULL;
    ret->key_arg=NULL;
    ret->s2->conn_id=NULL; */

    ret->info_callback = NULL;

    ret->app_verify_callback = 0;
    ret->app_verify_arg = NULL;

    ret->max_cert_list = SSL_MAX_CERT_LIST_DEFAULT;
    ret->read_ahead = 0;
    ret->msg_callback = 0;
    ret->msg_callback_arg = NULL;
    ret->verify_mode = SSL_VERIFY_NONE;
#if 0
    ret->verify_depth = -1;     /* Don't impose a limit (but x509_lu.c does) */
#endif
    ret->sid_ctx_length = 0;
    ret->default_verify_callback = NULL;
    if ((ret->cert = ssl_cert_new()) == NULL)
        goto err;

    ret->default_passwd_callback = 0;
    ret->default_passwd_callback_userdata = NULL;
    ret->client_cert_cb = 0;
    ret->app_gen_cookie_cb = 0;
    ret->app_verify_cookie_cb = 0;

    ret->sessions = lh_SSL_SESSION_new();
    if (ret->sessions == NULL)
        goto err;
    ret->cert_store = X509_STORE_new();
    if (ret->cert_store == NULL)
        goto err;

    ssl_create_cipher_list(ret->method,
                           &ret->cipher_list, &ret->cipher_list_by_id,
                           meth->version ==
                           SSL2_VERSION ? "SSLv2" : SSL_DEFAULT_CIPHER_LIST,
                           ret->cert);
    if (ret->cipher_list == NULL || sk_SSL_CIPHER_num(ret->cipher_list) <= 0) {
        SSLerr(SSL_F_SSL_CTX_NEW, SSL_R_LIBRARY_HAS_NO_CIPHERS);
        goto err2;
    }

    ret->param = X509_VERIFY_PARAM_new();
    if (!ret->param)
        goto err;

    if ((ret->rsa_md5 = EVP_get_digestbyname("ssl2-md5")) == NULL) {
        SSLerr(SSL_F_SSL_CTX_NEW, SSL_R_UNABLE_TO_LOAD_SSL2_MD5_ROUTINES);
        goto err2;
    }
    if ((ret->md5 = EVP_get_digestbyname("ssl3-md5")) == NULL) {
        SSLerr(SSL_F_SSL_CTX_NEW, SSL_R_UNABLE_TO_LOAD_SSL3_MD5_ROUTINES);
        goto err2;
    }
    if ((ret->sha1 = EVP_get_digestbyname("ssl3-sha1")) == NULL) {
        SSLerr(SSL_F_SSL_CTX_NEW, SSL_R_UNABLE_TO_LOAD_SSL3_SHA1_ROUTINES);
        goto err2;
    }

    if ((ret->client_CA = sk_X509_NAME_new_null()) == NULL)
        goto err;

    CRYPTO_new_ex_data(CRYPTO_EX_INDEX_SSL_CTX, ret, &ret->ex_data);

    ret->extra_certs = NULL;
    /* No compression for DTLS */
    if (!(meth->ssl3_enc->enc_flags & SSL_ENC_FLAG_DTLS))
        ret->comp_methods = SSL_COMP_get_compression_methods();

    ret->max_send_fragment = SSL3_RT_MAX_PLAIN_LENGTH;

#ifndef OPENSSL_NO_TLSEXT
    ret->tlsext_servername_callback = 0;
    ret->tlsext_servername_arg = NULL;
    /* Setup RFC4507 ticket keys */
    if ((RAND_bytes(ret->tlsext_tick_key_name, 16) <= 0)
        || (RAND_bytes(ret->tlsext_tick_hmac_key, 16) <= 0)
        || (RAND_bytes(ret->tlsext_tick_aes_key, 16) <= 0))
        ret->options |= SSL_OP_NO_TICKET;

    ret->tlsext_status_cb = 0;
    ret->tlsext_status_arg = NULL;

# ifndef OPENSSL_NO_NEXTPROTONEG
    ret->next_protos_advertised_cb = 0;
    ret->next_proto_select_cb = 0;
# endif
#endif
#ifndef OPENSSL_NO_PSK
    ret->psk_identity_hint = NULL;
    ret->psk_client_callback = NULL;
    ret->psk_server_callback = NULL;
#endif
#ifndef OPENSSL_NO_SRP
    SSL_CTX_SRP_CTX_init(ret);
#endif
#ifndef OPENSSL_NO_BUF_FREELISTS
    ret->freelist_max_len = SSL_MAX_BUF_FREELIST_LEN_DEFAULT;
    ret->rbuf_freelist = OPENSSL_malloc(sizeof(SSL3_BUF_FREELIST));
    if (!ret->rbuf_freelist)
        goto err;
    ret->rbuf_freelist->chunklen = 0;
    ret->rbuf_freelist->len = 0;
    ret->rbuf_freelist->head = NULL;
    ret->wbuf_freelist = OPENSSL_malloc(sizeof(SSL3_BUF_FREELIST));
    if (!ret->wbuf_freelist)
        goto err;
    ret->wbuf_freelist->chunklen = 0;
    ret->wbuf_freelist->len = 0;
    ret->wbuf_freelist->head = NULL;
#endif
#ifndef OPENSSL_NO_ENGINE
    ret->client_cert_engine = NULL;
# ifdef OPENSSL_SSL_CLIENT_ENGINE_AUTO
#  define eng_strx(x)     #x
#  define eng_str(x)      eng_strx(x)
    /* Use specific client engine automatically... ignore errors */
    {
        ENGINE *eng;
        eng = ENGINE_by_id(eng_str(OPENSSL_SSL_CLIENT_ENGINE_AUTO));
        if (!eng) {
            ERR_clear_error();
            ENGINE_load_builtin_engines();
            eng = ENGINE_by_id(eng_str(OPENSSL_SSL_CLIENT_ENGINE_AUTO));
        }
        if (!eng || !SSL_CTX_set_client_cert_engine(ret, eng))
            ERR_clear_error();
    }
# endif
#endif
    /*
     * Default is to connect to non-RI servers. When RI is more widely
     * deployed might change this.
     */
    ret->options |= SSL_OP_LEGACY_SERVER_CONNECT;

    /*
     * Disable SSLv2 by default, callers that want to enable SSLv2 will have to
     * explicitly clear this option via either of SSL_CTX_clear_options() or
     * SSL_clear_options().
     */
    ret->options |= SSL_OP_NO_SSLv2;

    return (ret);
 err:
    SSLerr(SSL_F_SSL_CTX_NEW, ERR_R_MALLOC_FAILURE);
 err2:
    if (ret != NULL)
        SSL_CTX_free(ret);
    return (NULL);
}

#if 0
static void SSL_COMP_free(SSL_COMP *comp)
{
    OPENSSL_free(comp);
}
#endif

#ifndef OPENSSL_NO_BUF_FREELISTS
static void ssl_buf_freelist_free(SSL3_BUF_FREELIST *list)
{
    SSL3_BUF_FREELIST_ENTRY *ent, *next;
    for (ent = list->head; ent; ent = next) {
        next = ent->next;
        OPENSSL_free(ent);
    }
    OPENSSL_free(list);
}
#endif

void SSL_CTX_free(SSL_CTX *a)
{
    int i;

    if (a == NULL)
        return;

    i = CRYPTO_add(&a->references, -1, CRYPTO_LOCK_SSL_CTX);
#ifdef REF_PRINT
    REF_PRINT("SSL_CTX", a);
#endif
    if (i > 0)
        return;
#ifdef REF_CHECK
    if (i < 0) {
        fprintf(stderr, "SSL_CTX_free, bad reference count\n");
        abort();                /* ok */
    }
#endif

    if (a->param)
        X509_VERIFY_PARAM_free(a->param);

    /*
     * Free internal session cache. However: the remove_cb() may reference
     * the ex_data of SSL_CTX, thus the ex_data store can only be removed
     * after the sessions were flushed.
     * As the ex_data handling routines might also touch the session cache,
     * the most secure solution seems to be: empty (flush) the cache, then
     * free ex_data, then finally free the cache.
     * (See ticket [openssl.org #212].)
     */
    if (a->sessions != NULL)
        SSL_CTX_flush_sessions(a, 0);

    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_SSL_CTX, a, &a->ex_data);

    if (a->sessions != NULL)
        lh_SSL_SESSION_free(a->sessions);

    if (a->cert_store != NULL)
        X509_STORE_free(a->cert_store);
    if (a->cipher_list != NULL)
        sk_SSL_CIPHER_free(a->cipher_list);
    if (a->cipher_list_by_id != NULL)
        sk_SSL_CIPHER_free(a->cipher_list_by_id);
    if (a->cert != NULL)
        ssl_cert_free(a->cert);
    if (a->client_CA != NULL)
        sk_X509_NAME_pop_free(a->client_CA, X509_NAME_free);
    if (a->extra_certs != NULL)
        sk_X509_pop_free(a->extra_certs, X509_free);
#if 0                           /* This should never be done, since it
                                 * removes a global database */
    if (a->comp_methods != NULL)
        sk_SSL_COMP_pop_free(a->comp_methods, SSL_COMP_free);
#else
    a->comp_methods = NULL;
#endif

#ifndef OPENSSL_NO_SRTP
    if (a->srtp_profiles)
        sk_SRTP_PROTECTION_PROFILE_free(a->srtp_profiles);
#endif

#ifndef OPENSSL_NO_PSK
    if (a->psk_identity_hint)
        OPENSSL_free(a->psk_identity_hint);
#endif
#ifndef OPENSSL_NO_SRP
    SSL_CTX_SRP_CTX_free(a);
#endif
#ifndef OPENSSL_NO_ENGINE
    if (a->client_cert_engine)
        ENGINE_finish(a->client_cert_engine);
#endif

#ifndef OPENSSL_NO_BUF_FREELISTS
    if (a->wbuf_freelist)
        ssl_buf_freelist_free(a->wbuf_freelist);
    if (a->rbuf_freelist)
        ssl_buf_freelist_free(a->rbuf_freelist);
#endif
#ifndef OPENSSL_NO_TLSEXT
# ifndef OPENSSL_NO_EC
    if (a->tlsext_ecpointformatlist)
        OPENSSL_free(a->tlsext_ecpointformatlist);
    if (a->tlsext_ellipticcurvelist)
        OPENSSL_free(a->tlsext_ellipticcurvelist);
# endif                         /* OPENSSL_NO_EC */
    if (a->alpn_client_proto_list != NULL)
        OPENSSL_free(a->alpn_client_proto_list);
#endif

    OPENSSL_free(a);
}

void SSL_CTX_set_default_passwd_cb(SSL_CTX *ctx, pem_password_cb *cb)
{
    ctx->default_passwd_callback = cb;
}

void SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX *ctx, void *u)
{
    ctx->default_passwd_callback_userdata = u;
}

void SSL_CTX_set_cert_verify_callback(SSL_CTX *ctx,
                                      int (*cb) (X509_STORE_CTX *, void *),
                                      void *arg)
{
    ctx->app_verify_callback = cb;
    ctx->app_verify_arg = arg;
}

void SSL_CTX_set_verify(SSL_CTX *ctx, int mode,
                        int (*cb) (int, X509_STORE_CTX *))
{
    ctx->verify_mode = mode;
    ctx->default_verify_callback = cb;
}

void SSL_CTX_set_verify_depth(SSL_CTX *ctx, int depth)
{
    X509_VERIFY_PARAM_set_depth(ctx->param, depth);
}

void SSL_CTX_set_cert_cb(SSL_CTX *c, int (*cb) (SSL *ssl, void *arg),
                         void *arg)
{
    ssl_cert_set_cert_cb(c->cert, cb, arg);
}

void SSL_set_cert_cb(SSL *s, int (*cb) (SSL *ssl, void *arg), void *arg)
{
    ssl_cert_set_cert_cb(s->cert, cb, arg);
}

void ssl_set_cert_masks(CERT *c, const SSL_CIPHER *cipher)
{
    CERT_PKEY *cpk;
    int rsa_enc, rsa_tmp, rsa_sign, dh_tmp, dh_rsa, dh_dsa, dsa_sign;
    int rsa_enc_export, dh_rsa_export, dh_dsa_export;
    int rsa_tmp_export, dh_tmp_export, kl;
    unsigned long mask_k, mask_a, emask_k, emask_a;
#ifndef OPENSSL_NO_ECDSA
    int have_ecc_cert, ecdsa_ok;
#endif
#ifndef OPENSSL_NO_ECDH
    int have_ecdh_tmp, ecdh_ok, ecc_pkey_size;
#endif
#ifndef OPENSSL_NO_EC
    X509 *x = NULL;
    EVP_PKEY *ecc_pkey = NULL;
    int signature_nid = 0, pk_nid = 0, md_nid = 0;
#endif
    if (c == NULL)
        return;

    kl = SSL_C_EXPORT_PKEYLENGTH(cipher);

#ifndef OPENSSL_NO_RSA
    rsa_tmp = (c->rsa_tmp != NULL || c->rsa_tmp_cb != NULL);
    rsa_tmp_export = (c->rsa_tmp_cb != NULL ||
                      (rsa_tmp && RSA_size(c->rsa_tmp) * 8 <= kl));
#else
    rsa_tmp = rsa_tmp_export = 0;
#endif
#ifndef OPENSSL_NO_DH
    dh_tmp = (c->dh_tmp != NULL || c->dh_tmp_cb != NULL);
    dh_tmp_export = (c->dh_tmp_cb != NULL ||
                     (dh_tmp && DH_size(c->dh_tmp) * 8 <= kl));
#else
    dh_tmp = dh_tmp_export = 0;
#endif

#ifndef OPENSSL_NO_ECDH
    have_ecdh_tmp = (c->ecdh_tmp || c->ecdh_tmp_cb || c->ecdh_tmp_auto);
#endif
    cpk = &(c->pkeys[SSL_PKEY_RSA_ENC]);
    rsa_enc = cpk->valid_flags & CERT_PKEY_VALID;
    rsa_enc_export = (rsa_enc && EVP_PKEY_size(cpk->privatekey) * 8 <= kl);
    cpk = &(c->pkeys[SSL_PKEY_RSA_SIGN]);
    rsa_sign = cpk->valid_flags & CERT_PKEY_SIGN;
    cpk = &(c->pkeys[SSL_PKEY_DSA_SIGN]);
    dsa_sign = cpk->valid_flags & CERT_PKEY_SIGN;
    cpk = &(c->pkeys[SSL_PKEY_DH_RSA]);
    dh_rsa = cpk->valid_flags & CERT_PKEY_VALID;
    dh_rsa_export = (dh_rsa && EVP_PKEY_size(cpk->privatekey) * 8 <= kl);
    cpk = &(c->pkeys[SSL_PKEY_DH_DSA]);
/* FIX THIS EAY EAY EAY */
    dh_dsa = cpk->valid_flags & CERT_PKEY_VALID;
    dh_dsa_export = (dh_dsa && EVP_PKEY_size(cpk->privatekey) * 8 <= kl);
    cpk = &(c->pkeys[SSL_PKEY_ECC]);
#ifndef OPENSSL_NO_EC
    have_ecc_cert = cpk->valid_flags & CERT_PKEY_VALID;
#endif
    mask_k = 0;
    mask_a = 0;
    emask_k = 0;
    emask_a = 0;

#ifdef CIPHER_DEBUG
    fprintf(stderr,
            "rt=%d rte=%d dht=%d ecdht=%d re=%d ree=%d rs=%d ds=%d dhr=%d dhd=%d\n",
            rsa_tmp, rsa_tmp_export, dh_tmp, have_ecdh_tmp, rsa_enc,
            rsa_enc_export, rsa_sign, dsa_sign, dh_rsa, dh_dsa);
#endif

    cpk = &(c->pkeys[SSL_PKEY_GOST01]);
    if (cpk->x509 != NULL && cpk->privatekey != NULL) {
        mask_k |= SSL_kGOST;
        mask_a |= SSL_aGOST01;
    }
    cpk = &(c->pkeys[SSL_PKEY_GOST94]);
    if (cpk->x509 != NULL && cpk->privatekey != NULL) {
        mask_k |= SSL_kGOST;
        mask_a |= SSL_aGOST94;
    }

    if (rsa_enc || (rsa_tmp && rsa_sign))
        mask_k |= SSL_kRSA;
    if (rsa_enc_export || (rsa_tmp_export && (rsa_sign || rsa_enc)))
        emask_k |= SSL_kRSA;

#if 0
    /* The match needs to be both kEDH and aRSA or aDSA, so don't worry */
    if ((dh_tmp || dh_rsa || dh_dsa) && (rsa_enc || rsa_sign || dsa_sign))
        mask_k |= SSL_kEDH;
    if ((dh_tmp_export || dh_rsa_export || dh_dsa_export) &&
        (rsa_enc || rsa_sign || dsa_sign))
        emask_k |= SSL_kEDH;
#endif

    if (dh_tmp_export)
        emask_k |= SSL_kEDH;

    if (dh_tmp)
        mask_k |= SSL_kEDH;

    if (dh_rsa)
        mask_k |= SSL_kDHr;
    if (dh_rsa_export)
        emask_k |= SSL_kDHr;

    if (dh_dsa)
        mask_k |= SSL_kDHd;
    if (dh_dsa_export)
        emask_k |= SSL_kDHd;

    if (mask_k & (SSL_kDHr | SSL_kDHd))
        mask_a |= SSL_aDH;

    if (rsa_enc || rsa_sign) {
        mask_a |= SSL_aRSA;
        emask_a |= SSL_aRSA;
    }

    if (dsa_sign) {
        mask_a |= SSL_aDSS;
        emask_a |= SSL_aDSS;
    }

    mask_a |= SSL_aNULL;
    emask_a |= SSL_aNULL;

#ifndef OPENSSL_NO_KRB5
    mask_k |= SSL_kKRB5;
    mask_a |= SSL_aKRB5;
    emask_k |= SSL_kKRB5;
    emask_a |= SSL_aKRB5;
#endif

    /*
     * An ECC certificate may be usable for ECDH and/or ECDSA cipher suites
     * depending on the key usage extension.
     */
#ifndef OPENSSL_NO_EC
    if (have_ecc_cert) {
        cpk = &c->pkeys[SSL_PKEY_ECC];
        x = cpk->x509;
        /* This call populates extension flags (ex_flags) */
        X509_check_purpose(x, -1, 0);
# ifndef OPENSSL_NO_ECDH
        ecdh_ok = (x->ex_flags & EXFLAG_KUSAGE) ?
            (x->ex_kusage & X509v3_KU_KEY_AGREEMENT) : 1;
# endif
        ecdsa_ok = (x->ex_flags & EXFLAG_KUSAGE) ?
            (x->ex_kusage & X509v3_KU_DIGITAL_SIGNATURE) : 1;
        if (!(cpk->valid_flags & CERT_PKEY_SIGN))
            ecdsa_ok = 0;
        ecc_pkey = X509_get_pubkey(x);
# ifndef OPENSSL_NO_ECDH
        ecc_pkey_size = (ecc_pkey != NULL) ? EVP_PKEY_bits(ecc_pkey) : 0;
# endif
        EVP_PKEY_free(ecc_pkey);
        if ((x->sig_alg) && (x->sig_alg->algorithm)) {
            signature_nid = OBJ_obj2nid(x->sig_alg->algorithm);
            OBJ_find_sigid_algs(signature_nid, &md_nid, &pk_nid);
        }
# ifndef OPENSSL_NO_ECDH
        if (ecdh_ok) {

            if (pk_nid == NID_rsaEncryption || pk_nid == NID_rsa) {
                mask_k |= SSL_kECDHr;
                mask_a |= SSL_aECDH;
                if (ecc_pkey_size <= 163) {
                    emask_k |= SSL_kECDHr;
                    emask_a |= SSL_aECDH;
                }
            }

            if (pk_nid == NID_X9_62_id_ecPublicKey) {
                mask_k |= SSL_kECDHe;
                mask_a |= SSL_aECDH;
                if (ecc_pkey_size <= 163) {
                    emask_k |= SSL_kECDHe;
                    emask_a |= SSL_aECDH;
                }
            }
        }
# endif
# ifndef OPENSSL_NO_ECDSA
        if (ecdsa_ok) {
            mask_a |= SSL_aECDSA;
            emask_a |= SSL_aECDSA;
        }
# endif
    }
#endif

#ifndef OPENSSL_NO_ECDH
    if (have_ecdh_tmp) {
        mask_k |= SSL_kEECDH;
        emask_k |= SSL_kEECDH;
    }
#endif

#ifndef OPENSSL_NO_PSK
    mask_k |= SSL_kPSK;
    mask_a |= SSL_aPSK;
    emask_k |= SSL_kPSK;
    emask_a |= SSL_aPSK;
#endif

    c->mask_k = mask_k;
    c->mask_a = mask_a;
    c->export_mask_k = emask_k;
    c->export_mask_a = emask_a;
    c->valid = 1;
}

/* This handy macro borrowed from crypto/x509v3/v3_purp.c */
#define ku_reject(x, usage) \
        (((x)->ex_flags & EXFLAG_KUSAGE) && !((x)->ex_kusage & (usage)))

#ifndef OPENSSL_NO_ECDH

int ssl_check_srvr_ecc_cert_and_alg(X509 *x, SSL *s)
{
    unsigned long alg_k, alg_a;
    EVP_PKEY *pkey = NULL;
    int keysize = 0;
    int signature_nid = 0, md_nid = 0, pk_nid = 0;
    const SSL_CIPHER *cs = s->s3->tmp.new_cipher;

    alg_k = cs->algorithm_mkey;
    alg_a = cs->algorithm_auth;

    if (SSL_C_IS_EXPORT(cs)) {
        /* ECDH key length in export ciphers must be <= 163 bits */
        pkey = X509_get_pubkey(x);
        if (pkey == NULL)
            return 0;
        keysize = EVP_PKEY_bits(pkey);
        EVP_PKEY_free(pkey);
        if (keysize > 163)
            return 0;
    }

    /* This call populates the ex_flags field correctly */
    X509_check_purpose(x, -1, 0);
    if ((x->sig_alg) && (x->sig_alg->algorithm)) {
        signature_nid = OBJ_obj2nid(x->sig_alg->algorithm);
        OBJ_find_sigid_algs(signature_nid, &md_nid, &pk_nid);
    }
    if (alg_k & SSL_kECDHe || alg_k & SSL_kECDHr) {
        /* key usage, if present, must allow key agreement */
        if (ku_reject(x, X509v3_KU_KEY_AGREEMENT)) {
            SSLerr(SSL_F_SSL_CHECK_SRVR_ECC_CERT_AND_ALG,
                   SSL_R_ECC_CERT_NOT_FOR_KEY_AGREEMENT);
            return 0;
        }
        if ((alg_k & SSL_kECDHe) && TLS1_get_version(s) < TLS1_2_VERSION) {
            /* signature alg must be ECDSA */
            if (pk_nid != NID_X9_62_id_ecPublicKey) {
                SSLerr(SSL_F_SSL_CHECK_SRVR_ECC_CERT_AND_ALG,
                       SSL_R_ECC_CERT_SHOULD_HAVE_SHA1_SIGNATURE);
                return 0;
            }
        }
        if ((alg_k & SSL_kECDHr) && TLS1_get_version(s) < TLS1_2_VERSION) {
            /* signature alg must be RSA */

            if (pk_nid != NID_rsaEncryption && pk_nid != NID_rsa) {
                SSLerr(SSL_F_SSL_CHECK_SRVR_ECC_CERT_AND_ALG,
                       SSL_R_ECC_CERT_SHOULD_HAVE_RSA_SIGNATURE);
                return 0;
            }
        }
    }
    if (alg_a & SSL_aECDSA) {
        /* key usage, if present, must allow signing */
        if (ku_reject(x, X509v3_KU_DIGITAL_SIGNATURE)) {
            SSLerr(SSL_F_SSL_CHECK_SRVR_ECC_CERT_AND_ALG,
                   SSL_R_ECC_CERT_NOT_FOR_SIGNING);
            return 0;
        }
    }

    return 1;                   /* all checks are ok */
}

#endif

static int ssl_get_server_cert_index(const SSL *s)
{
    int idx;
    idx = ssl_cipher_get_cert_index(s->s3->tmp.new_cipher);
    if (idx == SSL_PKEY_RSA_ENC && !s->cert->pkeys[SSL_PKEY_RSA_ENC].x509)
        idx = SSL_PKEY_RSA_SIGN;
    if (idx == -1)
        SSLerr(SSL_F_SSL_GET_SERVER_CERT_INDEX, ERR_R_INTERNAL_ERROR);
    return idx;
}

CERT_PKEY *ssl_get_server_send_pkey(const SSL *s)
{
    CERT *c;
    int i;

    c = s->cert;
    if (!s->s3 || !s->s3->tmp.new_cipher)
        return NULL;
    ssl_set_cert_masks(c, s->s3->tmp.new_cipher);

#ifdef OPENSSL_SSL_DEBUG_BROKEN_PROTOCOL
    /*
     * Broken protocol test: return last used certificate: which may mismatch
     * the one expected.
     */
    if (c->cert_flags & SSL_CERT_FLAG_BROKEN_PROTOCOL)
        return c->key;
#endif

    i = ssl_get_server_cert_index(s);

    /* This may or may not be an error. */
    if (i < 0)
        return NULL;

    /* May be NULL. */
    return &c->pkeys[i];
}

EVP_PKEY *ssl_get_sign_pkey(SSL *s, const SSL_CIPHER *cipher,
                            const EVP_MD **pmd)
{
    unsigned long alg_a;
    CERT *c;
    int idx = -1;

    alg_a = cipher->algorithm_auth;
    c = s->cert;

#ifdef OPENSSL_SSL_DEBUG_BROKEN_PROTOCOL
    /*
     * Broken protocol test: use last key: which may mismatch the one
     * expected.
     */
    if (c->cert_flags & SSL_CERT_FLAG_BROKEN_PROTOCOL)
        idx = c->key - c->pkeys;
    else
#endif

    if ((alg_a & SSL_aDSS) &&
            (c->pkeys[SSL_PKEY_DSA_SIGN].privatekey != NULL))
        idx = SSL_PKEY_DSA_SIGN;
    else if (alg_a & SSL_aRSA) {
        if (c->pkeys[SSL_PKEY_RSA_SIGN].privatekey != NULL)
            idx = SSL_PKEY_RSA_SIGN;
        else if (c->pkeys[SSL_PKEY_RSA_ENC].privatekey != NULL)
            idx = SSL_PKEY_RSA_ENC;
    } else if ((alg_a & SSL_aECDSA) &&
               (c->pkeys[SSL_PKEY_ECC].privatekey != NULL))
        idx = SSL_PKEY_ECC;
    if (idx == -1) {
        SSLerr(SSL_F_SSL_GET_SIGN_PKEY, ERR_R_INTERNAL_ERROR);
        return (NULL);
    }
    if (pmd)
        *pmd = c->pkeys[idx].digest;
    return c->pkeys[idx].privatekey;
}

#ifndef OPENSSL_NO_TLSEXT
int ssl_get_server_cert_serverinfo(SSL *s, const unsigned char **serverinfo,
                                   size_t *serverinfo_length)
{
    CERT *c = NULL;
    int i = 0;
    *serverinfo_length = 0;

    c = s->cert;
    i = ssl_get_server_cert_index(s);

    if (i == -1)
        return 0;
    if (c->pkeys[i].serverinfo == NULL)
        return 0;

    *serverinfo = c->pkeys[i].serverinfo;
    *serverinfo_length = c->pkeys[i].serverinfo_length;
    return 1;
}
#endif

void ssl_update_cache(SSL *s, int mode)
{
    int i;

    /*
     * If the session_id_length is 0, we are not supposed to cache it, and it
     * would be rather hard to do anyway :-)
     */
    if (s->session->session_id_length == 0)
        return;

    i = s->session_ctx->session_cache_mode;
    if ((i & mode) && (!s->hit)
        && ((i & SSL_SESS_CACHE_NO_INTERNAL_STORE)
            || SSL_CTX_add_session(s->session_ctx, s->session))
        && (s->session_ctx->new_session_cb != NULL)) {
        CRYPTO_add(&s->session->references, 1, CRYPTO_LOCK_SSL_SESSION);
        if (!s->session_ctx->new_session_cb(s, s->session))
            SSL_SESSION_free(s->session);
    }

    /* auto flush every 255 connections */
    if ((!(i & SSL_SESS_CACHE_NO_AUTO_CLEAR)) && ((i & mode) == mode)) {
        if ((((mode & SSL_SESS_CACHE_CLIENT)
              ? s->session_ctx->stats.sess_connect_good
              : s->session_ctx->stats.sess_accept_good) & 0xff) == 0xff) {
            SSL_CTX_flush_sessions(s->session_ctx, (unsigned long)time(NULL));
        }
    }
}

const SSL_METHOD *SSL_CTX_get_ssl_method(SSL_CTX *ctx)
{
    return ctx->method;
}

const SSL_METHOD *SSL_get_ssl_method(SSL *s)
{
    return (s->method);
}

int SSL_set_ssl_method(SSL *s, const SSL_METHOD *meth)
{
    int conn = -1;
    int ret = 1;

    if (s->method != meth) {
        if (s->handshake_func != NULL)
            conn = (s->handshake_func == s->method->ssl_connect);

        if (s->method->version == meth->version)
            s->method = meth;
        else {
            s->method->ssl_free(s);
            s->method = meth;
            ret = s->method->ssl_new(s);
        }

        if (conn == 1)
            s->handshake_func = meth->ssl_connect;
        else if (conn == 0)
            s->handshake_func = meth->ssl_accept;
    }
    return (ret);
}

int SSL_get_error(const SSL *s, int i)
{
    int reason;
    unsigned long l;
    BIO *bio;

    if (i > 0)
        return (SSL_ERROR_NONE);

    /*
     * Make things return SSL_ERROR_SYSCALL when doing SSL_do_handshake etc,
     * where we do encode the error
     */
    if ((l = ERR_peek_error()) != 0) {
        if (ERR_GET_LIB(l) == ERR_LIB_SYS)
            return (SSL_ERROR_SYSCALL);
        else
            return (SSL_ERROR_SSL);
    }

    if ((i < 0) && SSL_want_read(s)) {
        bio = SSL_get_rbio(s);
        if (BIO_should_read(bio))
            return (SSL_ERROR_WANT_READ);
        else if (BIO_should_write(bio))
            /*
             * This one doesn't make too much sense ... We never try to write
             * to the rbio, and an application program where rbio and wbio
             * are separate couldn't even know what it should wait for.
             * However if we ever set s->rwstate incorrectly (so that we have
             * SSL_want_read(s) instead of SSL_want_write(s)) and rbio and
             * wbio *are* the same, this test works around that bug; so it
             * might be safer to keep it.
             */
            return (SSL_ERROR_WANT_WRITE);
        else if (BIO_should_io_special(bio)) {
            reason = BIO_get_retry_reason(bio);
            if (reason == BIO_RR_CONNECT)
                return (SSL_ERROR_WANT_CONNECT);
            else if (reason == BIO_RR_ACCEPT)
                return (SSL_ERROR_WANT_ACCEPT);
            else
                return (SSL_ERROR_SYSCALL); /* unknown */
        }
    }

    if ((i < 0) && SSL_want_write(s)) {
        bio = SSL_get_wbio(s);
        if (BIO_should_write(bio))
            return (SSL_ERROR_WANT_WRITE);
        else if (BIO_should_read(bio))
            /*
             * See above (SSL_want_read(s) with BIO_should_write(bio))
             */
            return (SSL_ERROR_WANT_READ);
        else if (BIO_should_io_special(bio)) {
            reason = BIO_get_retry_reason(bio);
            if (reason == BIO_RR_CONNECT)
                return (SSL_ERROR_WANT_CONNECT);
            else if (reason == BIO_RR_ACCEPT)
                return (SSL_ERROR_WANT_ACCEPT);
            else
                return (SSL_ERROR_SYSCALL);
        }
    }
    if ((i < 0) && SSL_want_x509_lookup(s)) {
        return (SSL_ERROR_WANT_X509_LOOKUP);
    }

    if (i == 0) {
        if (s->version == SSL2_VERSION) {
            /* assume it is the socket being closed */
            return (SSL_ERROR_ZERO_RETURN);
        } else {
            if ((s->shutdown & SSL_RECEIVED_SHUTDOWN) &&
                (s->s3->warn_alert == SSL_AD_CLOSE_NOTIFY))
                return (SSL_ERROR_ZERO_RETURN);
        }
    }
    return (SSL_ERROR_SYSCALL);
}

int SSL_do_handshake(SSL *s)
{
    int ret = 1;

    if (s->handshake_func == NULL) {
        SSLerr(SSL_F_SSL_DO_HANDSHAKE, SSL_R_CONNECTION_TYPE_NOT_SET);
        return (-1);
    }

    s->method->ssl_renegotiate_check(s);

    if (SSL_in_init(s) || SSL_in_before(s)) {
        ret = s->handshake_func(s);
    }
    return (ret);
}

/*
 * For the next 2 functions, SSL_clear() sets shutdown and so one of these
 * calls will reset it
 */
void SSL_set_accept_state(SSL *s)
{
    s->server = 1;
    s->shutdown = 0;
    s->state = SSL_ST_ACCEPT | SSL_ST_BEFORE;
    s->handshake_func = s->method->ssl_accept;
    /* clear the current cipher */
    ssl_clear_cipher_ctx(s);
    ssl_clear_hash_ctx(&s->read_hash);
    ssl_clear_hash_ctx(&s->write_hash);
}

void SSL_set_connect_state(SSL *s)
{
    s->server = 0;
    s->shutdown = 0;
    s->state = SSL_ST_CONNECT | SSL_ST_BEFORE;
    s->handshake_func = s->method->ssl_connect;
    /* clear the current cipher */
    ssl_clear_cipher_ctx(s);
    ssl_clear_hash_ctx(&s->read_hash);
    ssl_clear_hash_ctx(&s->write_hash);
}

int ssl_undefined_function(SSL *s)
{
    SSLerr(SSL_F_SSL_UNDEFINED_FUNCTION, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
    return (0);
}

int ssl_undefined_void_function(void)
{
    SSLerr(SSL_F_SSL_UNDEFINED_VOID_FUNCTION,
           ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
    return (0);
}

int ssl_undefined_const_function(const SSL *s)
{
    SSLerr(SSL_F_SSL_UNDEFINED_CONST_FUNCTION,
           ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
    return (0);
}

SSL_METHOD *ssl_bad_method(int ver)
{
    SSLerr(SSL_F_SSL_BAD_METHOD, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
    return (NULL);
}

const char *SSL_get_version(const SSL *s)
{
    if (s->version == TLS1_2_VERSION)
        return ("TLSv1.2");
    else if (s->version == TLS1_1_VERSION)
        return ("TLSv1.1");
    else if (s->version == TLS1_VERSION)
        return ("TLSv1");
    else if (s->version == SSL3_VERSION)
        return ("SSLv3");
    else if (s->version == SSL2_VERSION)
        return ("SSLv2");
    else if (s->version == DTLS1_BAD_VER)
        return ("DTLSv0.9");
    else if (s->version == DTLS1_VERSION)
        return ("DTLSv1");
    else if (s->version == DTLS1_2_VERSION)
        return ("DTLSv1.2");
    else
        return ("unknown");
}

SSL *SSL_dup(SSL *s)
{
    STACK_OF(X509_NAME) *sk;
    X509_NAME *xn;
    SSL *ret;
    int i;

    if ((ret = SSL_new(SSL_get_SSL_CTX(s))) == NULL)
        return (NULL);

    ret->version = s->version;
    ret->type = s->type;
    ret->method = s->method;

    if (s->session != NULL) {
        /* This copies session-id, SSL_METHOD, sid_ctx, and 'cert' */
        SSL_copy_session_id(ret, s);
    } else {
        /*
         * No session has been established yet, so we have to expect that
         * s->cert or ret->cert will be changed later -- they should not both
         * point to the same object, and thus we can't use
         * SSL_copy_session_id.
         */

        ret->method->ssl_free(ret);
        ret->method = s->method;
        ret->method->ssl_new(ret);

        if (s->cert != NULL) {
            if (ret->cert != NULL) {
                ssl_cert_free(ret->cert);
            }
            ret->cert = ssl_cert_dup(s->cert);
            if (ret->cert == NULL)
                goto err;
        }

        SSL_set_session_id_context(ret, s->sid_ctx, s->sid_ctx_length);
    }

    ret->options = s->options;
    ret->mode = s->mode;
    SSL_set_max_cert_list(ret, SSL_get_max_cert_list(s));
    SSL_set_read_ahead(ret, SSL_get_read_ahead(s));
    ret->msg_callback = s->msg_callback;
    ret->msg_callback_arg = s->msg_callback_arg;
    SSL_set_verify(ret, SSL_get_verify_mode(s), SSL_get_verify_callback(s));
    SSL_set_verify_depth(ret, SSL_get_verify_depth(s));
    ret->generate_session_id = s->generate_session_id;

    SSL_set_info_callback(ret, SSL_get_info_callback(s));

    ret->debug = s->debug;

    /* copy app data, a little dangerous perhaps */
    if (!CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_SSL, &ret->ex_data, &s->ex_data))
        goto err;

    /* setup rbio, and wbio */
    if (s->rbio != NULL) {
        if (!BIO_dup_state(s->rbio, (char *)&ret->rbio))
            goto err;
    }
    if (s->wbio != NULL) {
        if (s->wbio != s->rbio) {
            if (!BIO_dup_state(s->wbio, (char *)&ret->wbio))
                goto err;
        } else
            ret->wbio = ret->rbio;
    }
    ret->rwstate = s->rwstate;
    ret->in_handshake = s->in_handshake;
    ret->handshake_func = s->handshake_func;
    ret->server = s->server;
    ret->renegotiate = s->renegotiate;
    ret->new_session = s->new_session;
    ret->quiet_shutdown = s->quiet_shutdown;
    ret->shutdown = s->shutdown;
    ret->state = s->state;      /* SSL_dup does not really work at any state,
                                 * though */
    ret->rstate = s->rstate;
    ret->init_num = 0;          /* would have to copy ret->init_buf,
                                 * ret->init_msg, ret->init_num,
                                 * ret->init_off */
    ret->hit = s->hit;

    X509_VERIFY_PARAM_inherit(ret->param, s->param);

    /* dup the cipher_list and cipher_list_by_id stacks */
    if (s->cipher_list != NULL) {
        if ((ret->cipher_list = sk_SSL_CIPHER_dup(s->cipher_list)) == NULL)
            goto err;
    }
    if (s->cipher_list_by_id != NULL)
        if ((ret->cipher_list_by_id = sk_SSL_CIPHER_dup(s->cipher_list_by_id))
            == NULL)
            goto err;

    /* Dup the client_CA list */
    if (s->client_CA != NULL) {
        if ((sk = sk_X509_NAME_dup(s->client_CA)) == NULL)
            goto err;
        ret->client_CA = sk;
        for (i = 0; i < sk_X509_NAME_num(sk); i++) {
            xn = sk_X509_NAME_value(sk, i);
            if (sk_X509_NAME_set(sk, i, X509_NAME_dup(xn)) == NULL) {
                X509_NAME_free(xn);
                goto err;
            }
        }
    }

    if (0) {
 err:
        if (ret != NULL)
            SSL_free(ret);
        ret = NULL;
    }
    return (ret);
}

void ssl_clear_cipher_ctx(SSL *s)
{
    if (s->enc_read_ctx != NULL) {
        EVP_CIPHER_CTX_cleanup(s->enc_read_ctx);
        OPENSSL_free(s->enc_read_ctx);
        s->enc_read_ctx = NULL;
    }
    if (s->enc_write_ctx != NULL) {
        EVP_CIPHER_CTX_cleanup(s->enc_write_ctx);
        OPENSSL_free(s->enc_write_ctx);
        s->enc_write_ctx = NULL;
    }
#ifndef OPENSSL_NO_COMP
    if (s->expand != NULL) {
        COMP_CTX_free(s->expand);
        s->expand = NULL;
    }
    if (s->compress != NULL) {
        COMP_CTX_free(s->compress);
        s->compress = NULL;
    }
#endif
}

X509 *SSL_get_certificate(const SSL *s)
{
    if (s->cert != NULL)
        return (s->cert->key->x509);
    else
        return (NULL);
}

EVP_PKEY *SSL_get_privatekey(const SSL *s)
{
    if (s->cert != NULL)
        return (s->cert->key->privatekey);
    else
        return (NULL);
}

X509 *SSL_CTX_get0_certificate(const SSL_CTX *ctx)
{
    if (ctx->cert != NULL)
        return ctx->cert->key->x509;
    else
        return NULL;
}

EVP_PKEY *SSL_CTX_get0_privatekey(const SSL_CTX *ctx)
{
    if (ctx->cert != NULL)
        return ctx->cert->key->privatekey;
    else
        return NULL;
}

const SSL_CIPHER *SSL_get_current_cipher(const SSL *s)
{
    if ((s->session != NULL) && (s->session->cipher != NULL))
        return (s->session->cipher);
    return (NULL);
}

#ifdef OPENSSL_NO_COMP
const COMP_METHOD *SSL_get_current_compression(SSL *s)
{
    return NULL;
}

const COMP_METHOD *SSL_get_current_expansion(SSL *s)
{
    return NULL;
}
#else

const COMP_METHOD *SSL_get_current_compression(SSL *s)
{
    if (s->compress != NULL)
        return (s->compress->meth);
    return (NULL);
}

const COMP_METHOD *SSL_get_current_expansion(SSL *s)
{
    if (s->expand != NULL)
        return (s->expand->meth);
    return (NULL);
}
#endif

int ssl_init_wbio_buffer(SSL *s, int push)
{
    BIO *bbio;

    if (s->bbio == NULL) {
        bbio = BIO_new(BIO_f_buffer());
        if (bbio == NULL)
            return (0);
        s->bbio = bbio;
    } else {
        bbio = s->bbio;
        if (s->bbio == s->wbio)
            s->wbio = BIO_pop(s->wbio);
    }
    (void)BIO_reset(bbio);
/*      if (!BIO_set_write_buffer_size(bbio,16*1024)) */
    if (!BIO_set_read_buffer_size(bbio, 1)) {
        SSLerr(SSL_F_SSL_INIT_WBIO_BUFFER, ERR_R_BUF_LIB);
        return (0);
    }
    if (push) {
        if (s->wbio != bbio)
            s->wbio = BIO_push(bbio, s->wbio);
    } else {
        if (s->wbio == bbio)
            s->wbio = BIO_pop(bbio);
    }
    return (1);
}

void ssl_free_wbio_buffer(SSL *s)
{
    if (s->bbio == NULL)
        return;

    if (s->bbio == s->wbio) {
        /* remove buffering */
        s->wbio = BIO_pop(s->wbio);
#ifdef REF_CHECK                /* not the usual REF_CHECK, but this avoids
                                 * adding one more preprocessor symbol */
        assert(s->wbio != NULL);
#endif
    }
    BIO_free(s->bbio);
    s->bbio = NULL;
}

void SSL_CTX_set_quiet_shutdown(SSL_CTX *ctx, int mode)
{
    ctx->quiet_shutdown = mode;
}

int SSL_CTX_get_quiet_shutdown(const SSL_CTX *ctx)
{
    return (ctx->quiet_shutdown);
}

void SSL_set_quiet_shutdown(SSL *s, int mode)
{
    s->quiet_shutdown = mode;
}

int SSL_get_quiet_shutdown(const SSL *s)
{
    return (s->quiet_shutdown);
}

void SSL_set_shutdown(SSL *s, int mode)
{
    s->shutdown = mode;
}

int SSL_get_shutdown(const SSL *s)
{
    return (s->shutdown);
}

int SSL_version(const SSL *s)
{
    return (s->version);
}

SSL_CTX *SSL_get_SSL_CTX(const SSL *ssl)
{
    return (ssl->ctx);
}

SSL_CTX *SSL_set_SSL_CTX(SSL *ssl, SSL_CTX *ctx)
{
    CERT *ocert = ssl->cert;
    if (ssl->ctx == ctx)
        return ssl->ctx;
#ifndef OPENSSL_NO_TLSEXT
    if (ctx == NULL)
        ctx = ssl->initial_ctx;
#endif
    ssl->cert = ssl_cert_dup(ctx->cert);
    if (ocert) {
        int i;
        /* Preserve any already negotiated parameters */
        if (ssl->server) {
            ssl->cert->peer_sigalgs = ocert->peer_sigalgs;
            ssl->cert->peer_sigalgslen = ocert->peer_sigalgslen;
            ocert->peer_sigalgs = NULL;
            ssl->cert->ciphers_raw = ocert->ciphers_raw;
            ssl->cert->ciphers_rawlen = ocert->ciphers_rawlen;
            ocert->ciphers_raw = NULL;
        }
        for (i = 0; i < SSL_PKEY_NUM; i++) {
            ssl->cert->pkeys[i].digest = ocert->pkeys[i].digest;
        }
#ifndef OPENSSL_NO_TLSEXT
        ssl->cert->alpn_proposed = ocert->alpn_proposed;
        ssl->cert->alpn_proposed_len = ocert->alpn_proposed_len;
        ocert->alpn_proposed = NULL;
        ssl->cert->alpn_sent = ocert->alpn_sent;

        if (!custom_exts_copy_flags(&ssl->cert->srv_ext, &ocert->srv_ext))
            return NULL;
#endif
        ssl_cert_free(ocert);
    }

    /*
     * Program invariant: |sid_ctx| has fixed size (SSL_MAX_SID_CTX_LENGTH),
     * so setter APIs must prevent invalid lengths from entering the system.
     */
    OPENSSL_assert(ssl->sid_ctx_length <= sizeof(ssl->sid_ctx));

    /*
     * If the session ID context matches that of the parent SSL_CTX,
     * inherit it from the new SSL_CTX as well. If however the context does
     * not match (i.e., it was set per-ssl with SSL_set_session_id_context),
     * leave it unchanged.
     */
    if ((ssl->ctx != NULL) &&
        (ssl->sid_ctx_length == ssl->ctx->sid_ctx_length) &&
        (memcmp(ssl->sid_ctx, ssl->ctx->sid_ctx, ssl->sid_ctx_length) == 0)) {
        ssl->sid_ctx_length = ctx->sid_ctx_length;
        memcpy(&ssl->sid_ctx, &ctx->sid_ctx, sizeof(ssl->sid_ctx));
    }

    CRYPTO_add(&ctx->references, 1, CRYPTO_LOCK_SSL_CTX);
    if (ssl->ctx != NULL)
        SSL_CTX_free(ssl->ctx); /* decrement reference count */
    ssl->ctx = ctx;

    return (ssl->ctx);
}

#ifndef OPENSSL_NO_STDIO
int SSL_CTX_set_default_verify_paths(SSL_CTX *ctx)
{
    return (X509_STORE_set_default_paths(ctx->cert_store));
}

int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile,
                                  const char *CApath)
{
    return (X509_STORE_load_locations(ctx->cert_store, CAfile, CApath));
}
#endif

void SSL_set_info_callback(SSL *ssl,
                           void (*cb) (const SSL *ssl, int type, int val))
{
    ssl->info_callback = cb;
}

/*
 * One compiler (Diab DCC) doesn't like argument names in returned function
 * pointer.
 */
void (*SSL_get_info_callback(const SSL *ssl)) (const SSL * /* ssl */ ,
                                               int /* type */ ,
                                               int /* val */ ) {
    return ssl->info_callback;
}

int SSL_state(const SSL *ssl)
{
    return (ssl->state);
}

void SSL_set_state(SSL *ssl, int state)
{
    ssl->state = state;
}

void SSL_set_verify_result(SSL *ssl, long arg)
{
    ssl->verify_result = arg;
}

long SSL_get_verify_result(const SSL *ssl)
{
    return (ssl->verify_result);
}

int SSL_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
                         CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func)
{
    return CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL, argl, argp,
                                   new_func, dup_func, free_func);
}

int SSL_set_ex_data(SSL *s, int idx, void *arg)
{
    return (CRYPTO_set_ex_data(&s->ex_data, idx, arg));
}

void *SSL_get_ex_data(const SSL *s, int idx)
{
    return (CRYPTO_get_ex_data(&s->ex_data, idx));
}

int SSL_CTX_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
                             CRYPTO_EX_dup *dup_func,
                             CRYPTO_EX_free *free_func)
{
    return CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL_CTX, argl, argp,
                                   new_func, dup_func, free_func);
}

int SSL_CTX_set_ex_data(SSL_CTX *s, int idx, void *arg)
{
    return (CRYPTO_set_ex_data(&s->ex_data, idx, arg));
}

void *SSL_CTX_get_ex_data(const SSL_CTX *s, int idx)
{
    return (CRYPTO_get_ex_data(&s->ex_data, idx));
}

int ssl_ok(SSL *s)
{
    return (1);
}

X509_STORE *SSL_CTX_get_cert_store(const SSL_CTX *ctx)
{
    return (ctx->cert_store);
}

void SSL_CTX_set_cert_store(SSL_CTX *ctx, X509_STORE *store)
{
    if (ctx->cert_store != NULL)
        X509_STORE_free(ctx->cert_store);
    ctx->cert_store = store;
}

int SSL_want(const SSL *s)
{
    return (s->rwstate);
}

/**
 * \brief Set the callback for generating temporary RSA keys.
 * \param ctx the SSL context.
 * \param cb the callback
 */

#ifndef OPENSSL_NO_RSA
void SSL_CTX_set_tmp_rsa_callback(SSL_CTX *ctx, RSA *(*cb) (SSL *ssl,
                                                            int is_export,
                                                            int keylength))
{
    SSL_CTX_callback_ctrl(ctx, SSL_CTRL_SET_TMP_RSA_CB, (void (*)(void))cb);
}

void SSL_set_tmp_rsa_callback(SSL *ssl, RSA *(*cb) (SSL *ssl,
                                                    int is_export,
                                                    int keylength))
{
    SSL_callback_ctrl(ssl, SSL_CTRL_SET_TMP_RSA_CB, (void (*)(void))cb);
}
#endif

#ifdef DOXYGEN
/**
 * \brief The RSA temporary key callback function.
 * \param ssl the SSL session.
 * \param is_export \c TRUE if the temp RSA key is for an export ciphersuite.
 * \param keylength if \c is_export is \c TRUE, then \c keylength is the size
 * of the required key in bits.
 * \return the temporary RSA key.
 * \sa SSL_CTX_set_tmp_rsa_callback, SSL_set_tmp_rsa_callback
 */

RSA *cb(SSL *ssl, int is_export, int keylength)
{
}
#endif

/**
 * \brief Set the callback for generating temporary DH keys.
 * \param ctx the SSL context.
 * \param dh the callback
 */

#ifndef OPENSSL_NO_DH
void SSL_CTX_set_tmp_dh_callback(SSL_CTX *ctx,
                                 DH *(*dh) (SSL *ssl, int is_export,
                                            int keylength))
{
    SSL_CTX_callback_ctrl(ctx, SSL_CTRL_SET_TMP_DH_CB, (void (*)(void))dh);
}

void SSL_set_tmp_dh_callback(SSL *ssl, DH *(*dh) (SSL *ssl, int is_export,
                                                  int keylength))
{
    SSL_callback_ctrl(ssl, SSL_CTRL_SET_TMP_DH_CB, (void (*)(void))dh);
}
#endif

#ifndef OPENSSL_NO_ECDH
void SSL_CTX_set_tmp_ecdh_callback(SSL_CTX *ctx,
                                   EC_KEY *(*ecdh) (SSL *ssl, int is_export,
                                                    int keylength))
{
    SSL_CTX_callback_ctrl(ctx, SSL_CTRL_SET_TMP_ECDH_CB,
                          (void (*)(void))ecdh);
}

void SSL_set_tmp_ecdh_callback(SSL *ssl,
                               EC_KEY *(*ecdh) (SSL *ssl, int is_export,
                                                int keylength))
{
    SSL_callback_ctrl(ssl, SSL_CTRL_SET_TMP_ECDH_CB, (void (*)(void))ecdh);
}
#endif

#ifndef OPENSSL_NO_PSK
int SSL_CTX_use_psk_identity_hint(SSL_CTX *ctx, const char *identity_hint)
{
    if (identity_hint != NULL && strlen(identity_hint) > PSK_MAX_IDENTITY_LEN) {
        SSLerr(SSL_F_SSL_CTX_USE_PSK_IDENTITY_HINT,
               SSL_R_DATA_LENGTH_TOO_LONG);
        return 0;
    }
    if (ctx->psk_identity_hint != NULL)
        OPENSSL_free(ctx->psk_identity_hint);
    if (identity_hint != NULL) {
        ctx->psk_identity_hint = BUF_strdup(identity_hint);
        if (ctx->psk_identity_hint == NULL)
            return 0;
    } else
        ctx->psk_identity_hint = NULL;
    return 1;
}

int SSL_use_psk_identity_hint(SSL *s, const char *identity_hint)
{
    if (s == NULL)
        return 0;

    if (s->session == NULL)
        return 1;               /* session not created yet, ignored */

    if (identity_hint != NULL && strlen(identity_hint) > PSK_MAX_IDENTITY_LEN) {
        SSLerr(SSL_F_SSL_USE_PSK_IDENTITY_HINT, SSL_R_DATA_LENGTH_TOO_LONG);
        return 0;
    }
    if (s->session->psk_identity_hint != NULL)
        OPENSSL_free(s->session->psk_identity_hint);
    if (identity_hint != NULL) {
        s->session->psk_identity_hint = BUF_strdup(identity_hint);
        if (s->session->psk_identity_hint == NULL)
            return 0;
    } else
        s->session->psk_identity_hint = NULL;
    return 1;
}

const char *SSL_get_psk_identity_hint(const SSL *s)
{
    if (s == NULL || s->session == NULL)
        return NULL;
    return (s->session->psk_identity_hint);
}

const char *SSL_get_psk_identity(const SSL *s)
{
    if (s == NULL || s->session == NULL)
        return NULL;
    return (s->session->psk_identity);
}

void SSL_set_psk_client_callback(SSL *s,
                                 unsigned int (*cb) (SSL *ssl,
                                                     const char *hint,
                                                     char *identity,
                                                     unsigned int
                                                     max_identity_len,
                                                     unsigned char *psk,
                                                     unsigned int
                                                     max_psk_len))
{
    s->psk_client_callback = cb;
}

void SSL_CTX_set_psk_client_callback(SSL_CTX *ctx,
                                     unsigned int (*cb) (SSL *ssl,
                                                         const char *hint,
                                                         char *identity,
                                                         unsigned int
                                                         max_identity_len,
                                                         unsigned char *psk,
                                                         unsigned int
                                                         max_psk_len))
{
    ctx->psk_client_callback = cb;
}

void SSL_set_psk_server_callback(SSL *s,
                                 unsigned int (*cb) (SSL *ssl,
                                                     const char *identity,
                                                     unsigned char *psk,
                                                     unsigned int
                                                     max_psk_len))
{
    s->psk_server_callback = cb;
}

void SSL_CTX_set_psk_server_callback(SSL_CTX *ctx,
                                     unsigned int (*cb) (SSL *ssl,
                                                         const char *identity,
                                                         unsigned char *psk,
                                                         unsigned int
                                                         max_psk_len))
{
    ctx->psk_server_callback = cb;
}
#endif

void SSL_CTX_set_msg_callback(SSL_CTX *ctx,
                              void (*cb) (int write_p, int version,
                                          int content_type, const void *buf,
                                          size_t len, SSL *ssl, void *arg))
{
    SSL_CTX_callback_ctrl(ctx, SSL_CTRL_SET_MSG_CALLBACK, (void (*)(void))cb);
}

void SSL_set_msg_callback(SSL *ssl,
                          void (*cb) (int write_p, int version,
                                      int content_type, const void *buf,
                                      size_t len, SSL *ssl, void *arg))
{
    SSL_callback_ctrl(ssl, SSL_CTRL_SET_MSG_CALLBACK, (void (*)(void))cb);
}

/*
 * Allocates new EVP_MD_CTX and sets pointer to it into given pointer
 * vairable, freeing EVP_MD_CTX previously stored in that variable, if any.
 * If EVP_MD pointer is passed, initializes ctx with this md Returns newly
 * allocated ctx;
 */

EVP_MD_CTX *ssl_replace_hash(EVP_MD_CTX **hash, const EVP_MD *md)
{
    ssl_clear_hash_ctx(hash);
    *hash = EVP_MD_CTX_create();
    if (*hash == NULL || (md && EVP_DigestInit_ex(*hash, md, NULL) <= 0)) {
        EVP_MD_CTX_destroy(*hash);
        *hash = NULL;
        return NULL;
    }
    return *hash;
}

void ssl_clear_hash_ctx(EVP_MD_CTX **hash)
{

    if (*hash)
        EVP_MD_CTX_destroy(*hash);
    *hash = NULL;
}

void SSL_set_debug(SSL *s, int debug)
{
    s->debug = debug;
}

int SSL_cache_hit(SSL *s)
{
    return s->hit;
}

int SSL_is_server(SSL *s)
{
    return s->server;
}

#if defined(_WINDLL) && defined(OPENSSL_SYS_WIN16)
# include "bio/bss_file.c"
#endif

IMPLEMENT_STACK_OF(SSL_CIPHER)
IMPLEMENT_STACK_OF(SSL_COMP)
IMPLEMENT_OBJ_BSEARCH_GLOBAL_CMP_FN(SSL_CIPHER, SSL_CIPHER, ssl_cipher_id);
/* ssl/ssl_rsa.c */
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
// #include "bio.h"
// #include "objects.h"
#include "evp.h"
// #include "x509.h"
// #include "pem.h"

static int ssl_set_cert(CERT *c, X509 *x509);
static int ssl_set_pkey(CERT *c, EVP_PKEY *pkey);
int SSL_use_certificate(SSL *ssl, X509 *x)
{
    if (x == NULL) {
        SSLerr(SSL_F_SSL_USE_CERTIFICATE, ERR_R_PASSED_NULL_PARAMETER);
        return (0);
    }
    if (!ssl_cert_inst(&ssl->cert)) {
        SSLerr(SSL_F_SSL_USE_CERTIFICATE, ERR_R_MALLOC_FAILURE);
        return (0);
    }
    return (ssl_set_cert(ssl->cert, x));
}

#ifndef OPENSSL_NO_STDIO
int SSL_use_certificate_file(SSL *ssl, const char *file, int type)
{
    int j;
    BIO *in;
    int ret = 0;
    X509 *x = NULL;

    in = BIO_new(BIO_s_file_internal());
    if (in == NULL) {
        SSLerr(SSL_F_SSL_USE_CERTIFICATE_FILE, ERR_R_BUF_LIB);
        goto end;
    }

    if (BIO_read_filename(in, file) <= 0) {
        SSLerr(SSL_F_SSL_USE_CERTIFICATE_FILE, ERR_R_SYS_LIB);
        goto end;
    }
    if (type == SSL_FILETYPE_ASN1) {
        j = ERR_R_ASN1_LIB;
        x = d2i_X509_bio(in, NULL);
    } else if (type == SSL_FILETYPE_PEM) {
        j = ERR_R_PEM_LIB;
        x = PEM_read_bio_X509(in, NULL, ssl->ctx->default_passwd_callback,
                              ssl->ctx->default_passwd_callback_userdata);
    } else {
        SSLerr(SSL_F_SSL_USE_CERTIFICATE_FILE, SSL_R_BAD_SSL_FILETYPE);
        goto end;
    }

    if (x == NULL) {
        SSLerr(SSL_F_SSL_USE_CERTIFICATE_FILE, j);
        goto end;
    }

    ret = SSL_use_certificate(ssl, x);
 end:
    if (x != NULL)
        X509_free(x);
    if (in != NULL)
        BIO_free(in);
    return (ret);
}
#endif

int SSL_use_certificate_ASN1(SSL *ssl, const unsigned char *d, int len)
{
    X509 *x;
    int ret;

    x = d2i_X509(NULL, &d, (long)len);
    if (x == NULL) {
        SSLerr(SSL_F_SSL_USE_CERTIFICATE_ASN1, ERR_R_ASN1_LIB);
        return (0);
    }

    ret = SSL_use_certificate(ssl, x);
    X509_free(x);
    return (ret);
}

#ifndef OPENSSL_NO_RSA
int SSL_use_RSAPrivateKey(SSL *ssl, RSA *rsa)
{
    EVP_PKEY *pkey;
    int ret;

    if (rsa == NULL) {
        SSLerr(SSL_F_SSL_USE_RSAPRIVATEKEY, ERR_R_PASSED_NULL_PARAMETER);
        return (0);
    }
    if (!ssl_cert_inst(&ssl->cert)) {
        SSLerr(SSL_F_SSL_USE_RSAPRIVATEKEY, ERR_R_MALLOC_FAILURE);
        return (0);
    }
    if ((pkey = EVP_PKEY_new()) == NULL) {
        SSLerr(SSL_F_SSL_USE_RSAPRIVATEKEY, ERR_R_EVP_LIB);
        return (0);
    }

    RSA_up_ref(rsa);
    if (EVP_PKEY_assign_RSA(pkey, rsa) <= 0) {
        RSA_free(rsa);
        return 0;
    }

    ret = ssl_set_pkey(ssl->cert, pkey);
    EVP_PKEY_free(pkey);
    return (ret);
}
#endif

static int ssl_set_pkey(CERT *c, EVP_PKEY *pkey)
{
    int i;
    /*
     * Special case for DH: check two DH certificate types for a match. This
     * means for DH certificates we must set the certificate first.
     */
    if (pkey->type == EVP_PKEY_DH) {
        X509 *x;
        i = -1;
        x = c->pkeys[SSL_PKEY_DH_RSA].x509;
        if (x && X509_check_private_key(x, pkey))
            i = SSL_PKEY_DH_RSA;
        x = c->pkeys[SSL_PKEY_DH_DSA].x509;
        if (i == -1 && x && X509_check_private_key(x, pkey))
            i = SSL_PKEY_DH_DSA;
        ERR_clear_error();
    } else
        i = ssl_cert_type(NULL, pkey);
    if (i < 0) {
        SSLerr(SSL_F_SSL_SET_PKEY, SSL_R_UNKNOWN_CERTIFICATE_TYPE);
        return (0);
    }

    if (c->pkeys[i].x509 != NULL) {
        EVP_PKEY *pktmp;
        pktmp = X509_get_pubkey(c->pkeys[i].x509);
        if (pktmp == NULL) {
            SSLerr(SSL_F_SSL_SET_PKEY, ERR_R_MALLOC_FAILURE);
            EVP_PKEY_free(pktmp);
            return 0;
        }
        /*
         * The return code from EVP_PKEY_copy_parameters is deliberately
         * ignored. Some EVP_PKEY types cannot do this.
         */
        EVP_PKEY_copy_parameters(pktmp, pkey);
        EVP_PKEY_free(pktmp);
        ERR_clear_error();

#ifndef OPENSSL_NO_RSA
        /*
         * Don't check the public/private key, this is mostly for smart
         * cards.
         */
        if ((pkey->type == EVP_PKEY_RSA) &&
            (RSA_flags(pkey->pkey.rsa) & RSA_METHOD_FLAG_NO_CHECK)) ;
        else
#endif
        if (!X509_check_private_key(c->pkeys[i].x509, pkey)) {
            X509_free(c->pkeys[i].x509);
            c->pkeys[i].x509 = NULL;
            return 0;
        }
    }

    if (c->pkeys[i].privatekey != NULL)
        EVP_PKEY_free(c->pkeys[i].privatekey);
    CRYPTO_add(&pkey->references, 1, CRYPTO_LOCK_EVP_PKEY);
    c->pkeys[i].privatekey = pkey;
    c->key = &(c->pkeys[i]);

    c->valid = 0;
    return (1);
}

#ifndef OPENSSL_NO_RSA
# ifndef OPENSSL_NO_STDIO
int SSL_use_RSAPrivateKey_file(SSL *ssl, const char *file, int type)
{
    int j, ret = 0;
    BIO *in;
    RSA *rsa = NULL;

    in = BIO_new(BIO_s_file_internal());
    if (in == NULL) {
        SSLerr(SSL_F_SSL_USE_RSAPRIVATEKEY_FILE, ERR_R_BUF_LIB);
        goto end;
    }

    if (BIO_read_filename(in, file) <= 0) {
        SSLerr(SSL_F_SSL_USE_RSAPRIVATEKEY_FILE, ERR_R_SYS_LIB);
        goto end;
    }
    if (type == SSL_FILETYPE_ASN1) {
        j = ERR_R_ASN1_LIB;
        rsa = d2i_RSAPrivateKey_bio(in, NULL);
    } else if (type == SSL_FILETYPE_PEM) {
        j = ERR_R_PEM_LIB;
        rsa = PEM_read_bio_RSAPrivateKey(in, NULL,
                                         ssl->ctx->default_passwd_callback,
                                         ssl->
                                         ctx->default_passwd_callback_userdata);
    } else {
        SSLerr(SSL_F_SSL_USE_RSAPRIVATEKEY_FILE, SSL_R_BAD_SSL_FILETYPE);
        goto end;
    }
    if (rsa == NULL) {
        SSLerr(SSL_F_SSL_USE_RSAPRIVATEKEY_FILE, j);
        goto end;
    }
    ret = SSL_use_RSAPrivateKey(ssl, rsa);
    RSA_free(rsa);
 end:
    if (in != NULL)
        BIO_free(in);
    return (ret);
}
# endif

int SSL_use_RSAPrivateKey_ASN1(SSL *ssl, unsigned char *d, long len)
{
    int ret;
    const unsigned char *p;
    RSA *rsa;

    p = d;
    if ((rsa = d2i_RSAPrivateKey(NULL, &p, (long)len)) == NULL) {
        SSLerr(SSL_F_SSL_USE_RSAPRIVATEKEY_ASN1, ERR_R_ASN1_LIB);
        return (0);
    }

    ret = SSL_use_RSAPrivateKey(ssl, rsa);
    RSA_free(rsa);
    return (ret);
}
#endif                          /* !OPENSSL_NO_RSA */

int SSL_use_PrivateKey(SSL *ssl, EVP_PKEY *pkey)
{
    int ret;

    if (pkey == NULL) {
        SSLerr(SSL_F_SSL_USE_PRIVATEKEY, ERR_R_PASSED_NULL_PARAMETER);
        return (0);
    }
    if (!ssl_cert_inst(&ssl->cert)) {
        SSLerr(SSL_F_SSL_USE_PRIVATEKEY, ERR_R_MALLOC_FAILURE);
        return (0);
    }
    ret = ssl_set_pkey(ssl->cert, pkey);
    return (ret);
}

#ifndef OPENSSL_NO_STDIO
int SSL_use_PrivateKey_file(SSL *ssl, const char *file, int type)
{
    int j, ret = 0;
    BIO *in;
    EVP_PKEY *pkey = NULL;

    in = BIO_new(BIO_s_file_internal());
    if (in == NULL) {
        SSLerr(SSL_F_SSL_USE_PRIVATEKEY_FILE, ERR_R_BUF_LIB);
        goto end;
    }

    if (BIO_read_filename(in, file) <= 0) {
        SSLerr(SSL_F_SSL_USE_PRIVATEKEY_FILE, ERR_R_SYS_LIB);
        goto end;
    }
    if (type == SSL_FILETYPE_PEM) {
        j = ERR_R_PEM_LIB;
        pkey = PEM_read_bio_PrivateKey(in, NULL,
                                       ssl->ctx->default_passwd_callback,
                                       ssl->
                                       ctx->default_passwd_callback_userdata);
    } else if (type == SSL_FILETYPE_ASN1) {
        j = ERR_R_ASN1_LIB;
        pkey = d2i_PrivateKey_bio(in, NULL);
    } else {
        SSLerr(SSL_F_SSL_USE_PRIVATEKEY_FILE, SSL_R_BAD_SSL_FILETYPE);
        goto end;
    }
    if (pkey == NULL) {
        SSLerr(SSL_F_SSL_USE_PRIVATEKEY_FILE, j);
        goto end;
    }
    ret = SSL_use_PrivateKey(ssl, pkey);
    EVP_PKEY_free(pkey);
 end:
    if (in != NULL)
        BIO_free(in);
    return (ret);
}
#endif

int SSL_use_PrivateKey_ASN1(int type, SSL *ssl, const unsigned char *d,
                            long len)
{
    int ret;
    const unsigned char *p;
    EVP_PKEY *pkey;

    p = d;
    if ((pkey = d2i_PrivateKey(type, NULL, &p, (long)len)) == NULL) {
        SSLerr(SSL_F_SSL_USE_PRIVATEKEY_ASN1, ERR_R_ASN1_LIB);
        return (0);
    }

    ret = SSL_use_PrivateKey(ssl, pkey);
    EVP_PKEY_free(pkey);
    return (ret);
}

int SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *x)
{
    if (x == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE, ERR_R_PASSED_NULL_PARAMETER);
        return (0);
    }
    if (!ssl_cert_inst(&ctx->cert)) {
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE, ERR_R_MALLOC_FAILURE);
        return (0);
    }
    return (ssl_set_cert(ctx->cert, x));
}

static int ssl_set_cert(CERT *c, X509 *x)
{
    EVP_PKEY *pkey;
    int i;

    pkey = X509_get_pubkey(x);
    if (pkey == NULL) {
        SSLerr(SSL_F_SSL_SET_CERT, SSL_R_X509_LIB);
        return (0);
    }

    i = ssl_cert_type(x, pkey);
    if (i < 0) {
        SSLerr(SSL_F_SSL_SET_CERT, SSL_R_UNKNOWN_CERTIFICATE_TYPE);
        EVP_PKEY_free(pkey);
        return (0);
    }

    if (c->pkeys[i].privatekey != NULL) {
        /*
         * The return code from EVP_PKEY_copy_parameters is deliberately
         * ignored. Some EVP_PKEY types cannot do this.
         */
        EVP_PKEY_copy_parameters(pkey, c->pkeys[i].privatekey);
        ERR_clear_error();

#ifndef OPENSSL_NO_RSA
        /*
         * Don't check the public/private key, this is mostly for smart
         * cards.
         */
        if ((c->pkeys[i].privatekey->type == EVP_PKEY_RSA) &&
            (RSA_flags(c->pkeys[i].privatekey->pkey.rsa) &
             RSA_METHOD_FLAG_NO_CHECK)) ;
        else
#endif                          /* OPENSSL_NO_RSA */
        if (!X509_check_private_key(x, c->pkeys[i].privatekey)) {
            /*
             * don't fail for a cert/key mismatch, just free current private
             * key (when switching to a different cert & key, first this
             * function should be used, then ssl_set_pkey
             */
            EVP_PKEY_free(c->pkeys[i].privatekey);
            c->pkeys[i].privatekey = NULL;
            /* clear error queue */
            ERR_clear_error();
        }
    }

    EVP_PKEY_free(pkey);

    if (c->pkeys[i].x509 != NULL)
        X509_free(c->pkeys[i].x509);
    CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509);
    c->pkeys[i].x509 = x;
    c->key = &(c->pkeys[i]);

    c->valid = 0;
    return (1);
}

#ifndef OPENSSL_NO_STDIO
int SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type)
{
    int j;
    BIO *in;
    int ret = 0;
    X509 *x = NULL;

    in = BIO_new(BIO_s_file_internal());
    if (in == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_BUF_LIB);
        goto end;
    }

    if (BIO_read_filename(in, file) <= 0) {
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_SYS_LIB);
        goto end;
    }
    if (type == SSL_FILETYPE_ASN1) {
        j = ERR_R_ASN1_LIB;
        x = d2i_X509_bio(in, NULL);
    } else if (type == SSL_FILETYPE_PEM) {
        j = ERR_R_PEM_LIB;
        x = PEM_read_bio_X509(in, NULL, ctx->default_passwd_callback,
                              ctx->default_passwd_callback_userdata);
    } else {
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, SSL_R_BAD_SSL_FILETYPE);
        goto end;
    }

    if (x == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, j);
        goto end;
    }

    ret = SSL_CTX_use_certificate(ctx, x);
 end:
    if (x != NULL)
        X509_free(x);
    if (in != NULL)
        BIO_free(in);
    return (ret);
}
#endif

int SSL_CTX_use_certificate_ASN1(SSL_CTX *ctx, int len,
                                 const unsigned char *d)
{
    X509 *x;
    int ret;

    x = d2i_X509(NULL, &d, (long)len);
    if (x == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_ASN1, ERR_R_ASN1_LIB);
        return (0);
    }

    ret = SSL_CTX_use_certificate(ctx, x);
    X509_free(x);
    return (ret);
}

#ifndef OPENSSL_NO_RSA
int SSL_CTX_use_RSAPrivateKey(SSL_CTX *ctx, RSA *rsa)
{
    int ret;
    EVP_PKEY *pkey;

    if (rsa == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_RSAPRIVATEKEY, ERR_R_PASSED_NULL_PARAMETER);
        return (0);
    }
    if (!ssl_cert_inst(&ctx->cert)) {
        SSLerr(SSL_F_SSL_CTX_USE_RSAPRIVATEKEY, ERR_R_MALLOC_FAILURE);
        return (0);
    }
    if ((pkey = EVP_PKEY_new()) == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_RSAPRIVATEKEY, ERR_R_EVP_LIB);
        return (0);
    }

    RSA_up_ref(rsa);
    if (EVP_PKEY_assign_RSA(pkey, rsa) <= 0) {
        RSA_free(rsa);
        return 0;
    }

    ret = ssl_set_pkey(ctx->cert, pkey);
    EVP_PKEY_free(pkey);
    return (ret);
}

# ifndef OPENSSL_NO_STDIO
int SSL_CTX_use_RSAPrivateKey_file(SSL_CTX *ctx, const char *file, int type)
{
    int j, ret = 0;
    BIO *in;
    RSA *rsa = NULL;

    in = BIO_new(BIO_s_file_internal());
    if (in == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_FILE, ERR_R_BUF_LIB);
        goto end;
    }

    if (BIO_read_filename(in, file) <= 0) {
        SSLerr(SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_FILE, ERR_R_SYS_LIB);
        goto end;
    }
    if (type == SSL_FILETYPE_ASN1) {
        j = ERR_R_ASN1_LIB;
        rsa = d2i_RSAPrivateKey_bio(in, NULL);
    } else if (type == SSL_FILETYPE_PEM) {
        j = ERR_R_PEM_LIB;
        rsa = PEM_read_bio_RSAPrivateKey(in, NULL,
                                         ctx->default_passwd_callback,
                                         ctx->default_passwd_callback_userdata);
    } else {
        SSLerr(SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_FILE, SSL_R_BAD_SSL_FILETYPE);
        goto end;
    }
    if (rsa == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_FILE, j);
        goto end;
    }
    ret = SSL_CTX_use_RSAPrivateKey(ctx, rsa);
    RSA_free(rsa);
 end:
    if (in != NULL)
        BIO_free(in);
    return (ret);
}
# endif

int SSL_CTX_use_RSAPrivateKey_ASN1(SSL_CTX *ctx, const unsigned char *d,
                                   long len)
{
    int ret;
    const unsigned char *p;
    RSA *rsa;

    p = d;
    if ((rsa = d2i_RSAPrivateKey(NULL, &p, (long)len)) == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_ASN1, ERR_R_ASN1_LIB);
        return (0);
    }

    ret = SSL_CTX_use_RSAPrivateKey(ctx, rsa);
    RSA_free(rsa);
    return (ret);
}
#endif                          /* !OPENSSL_NO_RSA */

int SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey)
{
    if (pkey == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY, ERR_R_PASSED_NULL_PARAMETER);
        return (0);
    }
    if (!ssl_cert_inst(&ctx->cert)) {
        SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY, ERR_R_MALLOC_FAILURE);
        return (0);
    }
    return (ssl_set_pkey(ctx->cert, pkey));
}

#ifndef OPENSSL_NO_STDIO
int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type)
{
    int j, ret = 0;
    BIO *in;
    EVP_PKEY *pkey = NULL;

    in = BIO_new(BIO_s_file_internal());
    if (in == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, ERR_R_BUF_LIB);
        goto end;
    }

    if (BIO_read_filename(in, file) <= 0) {
        SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, ERR_R_SYS_LIB);
        goto end;
    }
    if (type == SSL_FILETYPE_PEM) {
        j = ERR_R_PEM_LIB;
        pkey = PEM_read_bio_PrivateKey(in, NULL,
                                       ctx->default_passwd_callback,
                                       ctx->default_passwd_callback_userdata);
    } else if (type == SSL_FILETYPE_ASN1) {
        j = ERR_R_ASN1_LIB;
        pkey = d2i_PrivateKey_bio(in, NULL);
    } else {
        SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, SSL_R_BAD_SSL_FILETYPE);
        goto end;
    }
    if (pkey == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, j);
        goto end;
    }
    ret = SSL_CTX_use_PrivateKey(ctx, pkey);
    EVP_PKEY_free(pkey);
 end:
    if (in != NULL)
        BIO_free(in);
    return (ret);
}
#endif

int SSL_CTX_use_PrivateKey_ASN1(int type, SSL_CTX *ctx,
                                const unsigned char *d, long len)
{
    int ret;
    const unsigned char *p;
    EVP_PKEY *pkey;

    p = d;
    if ((pkey = d2i_PrivateKey(type, NULL, &p, (long)len)) == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_ASN1, ERR_R_ASN1_LIB);
        return (0);
    }

    ret = SSL_CTX_use_PrivateKey(ctx, pkey);
    EVP_PKEY_free(pkey);
    return (ret);
}

#ifndef OPENSSL_NO_STDIO
/*
 * Read a file that contains our certificate in "PEM" format, possibly
 * followed by a sequence of CA certificates that should be sent to the peer
 * in the Certificate message.
 */
int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file)
{
    BIO *in;
    int ret = 0;
    X509 *x = NULL;

    ERR_clear_error();          /* clear error stack for
                                 * SSL_CTX_use_certificate() */

    in = BIO_new(BIO_s_file_internal());
    if (in == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE, ERR_R_BUF_LIB);
        goto end;
    }

    if (BIO_read_filename(in, file) <= 0) {
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE, ERR_R_SYS_LIB);
        goto end;
    }

    x = PEM_read_bio_X509_AUX(in, NULL, ctx->default_passwd_callback,
                              ctx->default_passwd_callback_userdata);
    if (x == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE, ERR_R_PEM_LIB);
        goto end;
    }

    ret = SSL_CTX_use_certificate(ctx, x);

    if (ERR_peek_error() != 0)
        ret = 0;                /* Key/certificate mismatch doesn't imply
                                 * ret==0 ... */
    if (ret) {
        /*
         * If we could set up our certificate, now proceed to the CA
         * certificates.
         */
        X509 *ca;
        int r;
        unsigned long err;

        SSL_CTX_clear_chain_certs(ctx);

        while ((ca = PEM_read_bio_X509(in, NULL,
                                       ctx->default_passwd_callback,
                                       ctx->default_passwd_callback_userdata))
               != NULL) {
            r = SSL_CTX_add0_chain_cert(ctx, ca);
            if (!r) {
                X509_free(ca);
                ret = 0;
                goto end;
            }
            /*
             * Note that we must not free r if it was successfully added to
             * the chain (while we must free the main certificate, since its
             * reference count is increased by SSL_CTX_use_certificate).
             */
        }
        /* When the while loop ends, it's usually just EOF. */
        err = ERR_peek_last_error();
        if (ERR_GET_LIB(err) == ERR_LIB_PEM
            && ERR_GET_REASON(err) == PEM_R_NO_START_LINE)
            ERR_clear_error();
        else
            ret = 0;            /* some real error */
    }

 end:
    if (x != NULL)
        X509_free(x);
    if (in != NULL)
        BIO_free(in);
    return (ret);
}
#endif

#ifndef OPENSSL_NO_TLSEXT
static int serverinfo_find_extension(const unsigned char *serverinfo,
                                     size_t serverinfo_length,
                                     unsigned int extension_type,
                                     const unsigned char **extension_data,
                                     size_t *extension_length)
{
    *extension_data = NULL;
    *extension_length = 0;
    if (serverinfo == NULL || serverinfo_length == 0)
        return -1;
    for (;;) {
        unsigned int type = 0;
        size_t len = 0;

        /* end of serverinfo */
        if (serverinfo_length == 0)
            return 0;           /* Extension not found */

        /* read 2-byte type field */
        if (serverinfo_length < 2)
            return -1;          /* Error */
        type = (serverinfo[0] << 8) + serverinfo[1];
        serverinfo += 2;
        serverinfo_length -= 2;

        /* read 2-byte len field */
        if (serverinfo_length < 2)
            return -1;          /* Error */
        len = (serverinfo[0] << 8) + serverinfo[1];
        serverinfo += 2;
        serverinfo_length -= 2;

        if (len > serverinfo_length)
            return -1;          /* Error */

        if (type == extension_type) {
            *extension_data = serverinfo;
            *extension_length = len;
            return 1;           /* Success */
        }

        serverinfo += len;
        serverinfo_length -= len;
    }
    return 0;                   /* Error */
}

static int serverinfo_srv_parse_cb(SSL *s, unsigned int ext_type,
                                   const unsigned char *in,
                                   size_t inlen, int *al, void *arg)
{

    if (inlen != 0) {
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }

    return 1;
}

static int serverinfo_srv_add_cb(SSL *s, unsigned int ext_type,
                                 const unsigned char **out, size_t *outlen,
                                 int *al, void *arg)
{
    const unsigned char *serverinfo = NULL;
    size_t serverinfo_length = 0;

    /* Is there serverinfo data for the chosen server cert? */
    if ((ssl_get_server_cert_serverinfo(s, &serverinfo,
                                        &serverinfo_length)) != 0) {
        /* Find the relevant extension from the serverinfo */
        int retval = serverinfo_find_extension(serverinfo, serverinfo_length,
                                               ext_type, out, outlen);
        if (retval == -1) {
            *al = SSL_AD_DECODE_ERROR;
            return -1;          /* Error */
        }
        if (retval == 0)
            return 0;           /* No extension found, don't send extension */
        return 1;               /* Send extension */
    }
    return 0;                   /* No serverinfo data found, don't send
                                 * extension */
}

/*
 * With a NULL context, this function just checks that the serverinfo data
 * parses correctly.  With a non-NULL context, it registers callbacks for
 * the included extensions.
 */
static int serverinfo_process_buffer(const unsigned char *serverinfo,
                                     size_t serverinfo_length, SSL_CTX *ctx)
{
    if (serverinfo == NULL || serverinfo_length == 0)
        return 0;
    for (;;) {
        unsigned int ext_type = 0;
        size_t len = 0;

        /* end of serverinfo */
        if (serverinfo_length == 0)
            return 1;

        /* read 2-byte type field */
        if (serverinfo_length < 2)
            return 0;
        /* FIXME: check for types we understand explicitly? */

        /* Register callbacks for extensions */
        ext_type = (serverinfo[0] << 8) + serverinfo[1];
        if (ctx) {
            int have_ext_cbs = 0;
            size_t i;
            custom_ext_methods *exts = &ctx->cert->srv_ext;
            custom_ext_method *meth = exts->meths;

            for (i = 0; i < exts->meths_count; i++, meth++) {
                if (ext_type == meth->ext_type) {
                    have_ext_cbs = 1;
                    break;
                }
            }

            if (!have_ext_cbs && !SSL_CTX_add_server_custom_ext(ctx, ext_type,
                                                                serverinfo_srv_add_cb,
                                                                NULL, NULL,
                                                                serverinfo_srv_parse_cb,
                                                                NULL))
                return 0;
        }

        serverinfo += 2;
        serverinfo_length -= 2;

        /* read 2-byte len field */
        if (serverinfo_length < 2)
            return 0;
        len = (serverinfo[0] << 8) + serverinfo[1];
        serverinfo += 2;
        serverinfo_length -= 2;

        if (len > serverinfo_length)
            return 0;

        serverinfo += len;
        serverinfo_length -= len;
    }
}

int SSL_CTX_use_serverinfo(SSL_CTX *ctx, const unsigned char *serverinfo,
                           size_t serverinfo_length)
{
    unsigned char *new_serverinfo;

    if (ctx == NULL || serverinfo == NULL || serverinfo_length == 0) {
        SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (!serverinfo_process_buffer(serverinfo, serverinfo_length, NULL)) {
        SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO, SSL_R_INVALID_SERVERINFO_DATA);
        return 0;
    }
    if (!ssl_cert_inst(&ctx->cert)) {
        SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    if (ctx->cert->key == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    new_serverinfo = OPENSSL_realloc(ctx->cert->key->serverinfo,
                                     serverinfo_length);
    if (new_serverinfo == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    ctx->cert->key->serverinfo = new_serverinfo;
    memcpy(ctx->cert->key->serverinfo, serverinfo, serverinfo_length);
    ctx->cert->key->serverinfo_length = serverinfo_length;

    /*
     * Now that the serverinfo is validated and stored, go ahead and
     * register callbacks.
     */
    if (!serverinfo_process_buffer(serverinfo, serverinfo_length, ctx)) {
        SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO, SSL_R_INVALID_SERVERINFO_DATA);
        return 0;
    }
    return 1;
}

# ifndef OPENSSL_NO_STDIO
int SSL_CTX_use_serverinfo_file(SSL_CTX *ctx, const char *file)
{
    unsigned char *serverinfo = NULL;
    size_t serverinfo_length = 0;
    unsigned char *extension = 0;
    long extension_length = 0;
    char *name = NULL;
    char *header = NULL;
    char namePrefix[] = "SERVERINFO FOR ";
    int ret = 0;
    BIO *bin = NULL;
    size_t num_extensions = 0;
    unsigned char *new_serverinfo;

    if (ctx == NULL || file == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO_FILE,
               ERR_R_PASSED_NULL_PARAMETER);
        goto end;
    }

    bin = BIO_new(BIO_s_file_internal());
    if (bin == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO_FILE, ERR_R_BUF_LIB);
        goto end;
    }
    if (BIO_read_filename(bin, file) <= 0) {
        SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO_FILE, ERR_R_SYS_LIB);
        goto end;
    }

    for (num_extensions = 0;; num_extensions++) {
        if (PEM_read_bio(bin, &name, &header, &extension, &extension_length)
            == 0) {
            /*
             * There must be at least one extension in this file
             */
            if (num_extensions == 0) {
                SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO_FILE,
                       SSL_R_NO_PEM_EXTENSIONS);
                goto end;
            } else              /* End of file, we're done */
                break;
        }
        /* Check that PEM name starts with "BEGIN SERVERINFO FOR " */
        if (strlen(name) < strlen(namePrefix)) {
            SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO_FILE,
                   SSL_R_PEM_NAME_TOO_SHORT);
            goto end;
        }
        if (strncmp(name, namePrefix, strlen(namePrefix)) != 0) {
            SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO_FILE,
                   SSL_R_PEM_NAME_BAD_PREFIX);
            goto end;
        }
        /*
         * Check that the decoded PEM data is plausible (valid length field)
         */
        if (extension_length < 4
            || (extension[2] << 8) + extension[3] != extension_length - 4) {
            SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO_FILE, SSL_R_BAD_DATA);
            goto end;
        }
        /* Append the decoded extension to the serverinfo buffer */
        new_serverinfo =
            OPENSSL_realloc(serverinfo, serverinfo_length + extension_length);
        if (new_serverinfo == NULL) {
            SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO_FILE, ERR_R_MALLOC_FAILURE);
            goto end;
        }
        serverinfo = new_serverinfo;
        memcpy(serverinfo + serverinfo_length, extension, extension_length);
        serverinfo_length += extension_length;

        OPENSSL_free(name);
        name = NULL;
        OPENSSL_free(header);
        header = NULL;
        OPENSSL_free(extension);
        extension = NULL;
    }

    ret = SSL_CTX_use_serverinfo(ctx, serverinfo, serverinfo_length);
 end:
    /* SSL_CTX_use_serverinfo makes a local copy of the serverinfo. */
    OPENSSL_free(name);
    OPENSSL_free(header);
    OPENSSL_free(extension);
    OPENSSL_free(serverinfo);
    if (bin != NULL)
        BIO_free(bin);
    return ret;
}
# endif                         /* OPENSSL_NO_STDIO */
#endif                          /* OPENSSL_NO_TLSEXT */
/* ssl/ssl_sess.c */
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
// #include "lhash.h"
// #include "rand.h"
#ifndef OPENSSL_NO_ENGINE
# include "engine.h"
#endif
// #include "ssl_locl.h"

static void SSL_SESSION_list_remove(SSL_CTX *ctx, SSL_SESSION *s);
static void SSL_SESSION_list_add(SSL_CTX *ctx, SSL_SESSION *s);
static int remove_session_lock(SSL_CTX *ctx, SSL_SESSION *c, int lck);

SSL_SESSION *SSL_get_session(const SSL *ssl)
/* aka SSL_get0_session; gets 0 objects, just returns a copy of the pointer */
{
    return (ssl->session);
}

SSL_SESSION *SSL_get1_session(SSL *ssl)
/* variant of SSL_get_session: caller really gets something */
{
    SSL_SESSION *sess;
    /*
     * Need to lock this all up rather than just use CRYPTO_add so that
     * somebody doesn't free ssl->session between when we check it's non-null
     * and when we up the reference count.
     */
    CRYPTO_w_lock(CRYPTO_LOCK_SSL_SESSION);
    sess = ssl->session;
    if (sess)
        sess->references++;
    CRYPTO_w_unlock(CRYPTO_LOCK_SSL_SESSION);
    return (sess);
}

int SSL_SESSION_get_ex_new_index(long argl, void *argp,
                                 CRYPTO_EX_new *new_func,
                                 CRYPTO_EX_dup *dup_func,
                                 CRYPTO_EX_free *free_func)
{
    return CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL_SESSION, argl, argp,
                                   new_func, dup_func, free_func);
}

int SSL_SESSION_set_ex_data(SSL_SESSION *s, int idx, void *arg)
{
    return (CRYPTO_set_ex_data(&s->ex_data, idx, arg));
}

void *SSL_SESSION_get_ex_data(const SSL_SESSION *s, int idx)
{
    return (CRYPTO_get_ex_data(&s->ex_data, idx));
}

SSL_SESSION *SSL_SESSION_new(void)
{
    SSL_SESSION *ss;

    ss = (SSL_SESSION *)OPENSSL_malloc(sizeof(SSL_SESSION));
    if (ss == NULL) {
        SSLerr(SSL_F_SSL_SESSION_NEW, ERR_R_MALLOC_FAILURE);
        return (0);
    }
    memset(ss, 0, sizeof(SSL_SESSION));

    ss->verify_result = 1;      /* avoid 0 (= X509_V_OK) just in case */
    ss->references = 1;
    ss->timeout = 60 * 5 + 4;   /* 5 minute timeout by default */
    ss->time = (unsigned long)time(NULL);
    ss->prev = NULL;
    ss->next = NULL;
    ss->compress_meth = 0;
#ifndef OPENSSL_NO_TLSEXT
    ss->tlsext_hostname = NULL;
# ifndef OPENSSL_NO_EC
    ss->tlsext_ecpointformatlist_length = 0;
    ss->tlsext_ecpointformatlist = NULL;
    ss->tlsext_ellipticcurvelist_length = 0;
    ss->tlsext_ellipticcurvelist = NULL;
# endif
#endif
    CRYPTO_new_ex_data(CRYPTO_EX_INDEX_SSL_SESSION, ss, &ss->ex_data);
#ifndef OPENSSL_NO_PSK
    ss->psk_identity_hint = NULL;
    ss->psk_identity = NULL;
#endif
#ifndef OPENSSL_NO_SRP
    ss->srp_username = NULL;
#endif
    return (ss);
}

/*
 * Create a new SSL_SESSION and duplicate the contents of |src| into it. If
 * ticket == 0 then no ticket information is duplicated, otherwise it is.
 */
SSL_SESSION *ssl_session_dup(SSL_SESSION *src, int ticket)
{
    SSL_SESSION *dest;

    dest = OPENSSL_malloc(sizeof(*src));
    if (dest == NULL) {
        goto err;
    }
    memcpy(dest, src, sizeof(*dest));

    /*
     * Set the various pointers to NULL so that we can call SSL_SESSION_free in
     * the case of an error whilst halfway through constructing dest
     */
#ifndef OPENSSL_NO_PSK
    dest->psk_identity_hint = NULL;
    dest->psk_identity = NULL;
#endif
    dest->ciphers = NULL;
#ifndef OPENSSL_NO_TLSEXT
    dest->tlsext_hostname = NULL;
# ifndef OPENSSL_NO_EC
    dest->tlsext_ecpointformatlist = NULL;
    dest->tlsext_ellipticcurvelist = NULL;
# endif
    dest->tlsext_tick = NULL;
#endif
#ifndef OPENSSL_NO_SRP
    dest->srp_username = NULL;
#endif

    /* We deliberately don't copy the prev and next pointers */
    dest->prev = NULL;
    dest->next = NULL;

    dest->references = 1;

    if (src->sess_cert != NULL)
        CRYPTO_add(&src->sess_cert->references, 1, CRYPTO_LOCK_SSL_SESS_CERT);

    if (src->peer != NULL)
        CRYPTO_add(&src->peer->references, 1, CRYPTO_LOCK_X509);

    if (!CRYPTO_new_ex_data(CRYPTO_EX_INDEX_SSL_SESSION, dest, &dest->ex_data))
        goto err;

#ifndef OPENSSL_NO_PSK
    if (src->psk_identity_hint) {
        dest->psk_identity_hint = BUF_strdup(src->psk_identity_hint);
        if (dest->psk_identity_hint == NULL) {
            goto err;
        }
    }
    if (src->psk_identity) {
        dest->psk_identity = BUF_strdup(src->psk_identity);
        if (dest->psk_identity == NULL) {
            goto err;
        }
    }
#endif

    if(src->ciphers != NULL) {
        dest->ciphers = sk_SSL_CIPHER_dup(src->ciphers);
        if (dest->ciphers == NULL)
            goto err;
    }

    if (!CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_SSL_SESSION,
                                            &dest->ex_data, &src->ex_data)) {
        goto err;
    }

#ifndef OPENSSL_NO_TLSEXT
    if (src->tlsext_hostname) {
        dest->tlsext_hostname = BUF_strdup(src->tlsext_hostname);
        if (dest->tlsext_hostname == NULL) {
            goto err;
        }
    }
# ifndef OPENSSL_NO_EC
    if (src->tlsext_ecpointformatlist) {
        dest->tlsext_ecpointformatlist =
            BUF_memdup(src->tlsext_ecpointformatlist,
                       src->tlsext_ecpointformatlist_length);
        if (dest->tlsext_ecpointformatlist == NULL)
            goto err;
    }
    if (src->tlsext_ellipticcurvelist) {
        dest->tlsext_ellipticcurvelist =
            BUF_memdup(src->tlsext_ellipticcurvelist,
                       src->tlsext_ellipticcurvelist_length);
        if (dest->tlsext_ellipticcurvelist == NULL)
            goto err;
    }
# endif

    if (ticket != 0 && src->tlsext_tick != NULL) {
        dest->tlsext_tick = BUF_memdup(src->tlsext_tick, src->tlsext_ticklen);
        if(dest->tlsext_tick == NULL)
            goto err;
    } else {
        dest->tlsext_tick_lifetime_hint = 0;
        dest->tlsext_ticklen = 0;
    }
#endif

#ifndef OPENSSL_NO_SRP
    if (src->srp_username) {
        dest->srp_username = BUF_strdup(src->srp_username);
        if (dest->srp_username == NULL) {
            goto err;
        }
    }
#endif

    return dest;
err:
    SSLerr(SSL_F_SSL_SESSION_DUP, ERR_R_MALLOC_FAILURE);
    SSL_SESSION_free(dest);
    return NULL;
}

const unsigned char *SSL_SESSION_get_id(const SSL_SESSION *s,
                                        unsigned int *len)
{
    if (len)
        *len = s->session_id_length;
    return s->session_id;
}

unsigned int SSL_SESSION_get_compress_id(const SSL_SESSION *s)
{
    return s->compress_meth;
}

/*
 * Even with SSLv2, we have 16 bytes (128 bits) of session ID space.
 * SSLv3/TLSv1 has 32 bytes (256 bits). As such, filling the ID with random
 * gunk repeatedly until we have no conflict is going to complete in one
 * iteration pretty much "most" of the time (btw: understatement). So, if it
 * takes us 10 iterations and we still can't avoid a conflict - well that's a
 * reasonable point to call it quits. Either the RAND code is broken or
 * someone is trying to open roughly very close to 2^128 (or 2^256) SSL
 * sessions to our server. How you might store that many sessions is perhaps
 * a more interesting question ...
 */

#define MAX_SESS_ID_ATTEMPTS 10
static int def_generate_session_id(const SSL *ssl, unsigned char *id,
                                   unsigned int *id_len)
{
    unsigned int retry = 0;
    do
        if (RAND_bytes(id, *id_len) <= 0)
            return 0;
    while (SSL_has_matching_session_id(ssl, id, *id_len) &&
           (++retry < MAX_SESS_ID_ATTEMPTS)) ;
    if (retry < MAX_SESS_ID_ATTEMPTS)
        return 1;
    /* else - woops a session_id match */
    /*
     * XXX We should also check the external cache -- but the probability of
     * a collision is negligible, and we could not prevent the concurrent
     * creation of sessions with identical IDs since we currently don't have
     * means to atomically check whether a session ID already exists and make
     * a reservation for it if it does not (this problem applies to the
     * internal cache as well).
     */
    return 0;
}

int ssl_get_new_session(SSL *s, int session)
{
    /* This gets used by clients and servers. */

    unsigned int tmp;
    SSL_SESSION *ss = NULL;
    GEN_SESSION_CB cb = def_generate_session_id;

    if ((ss = SSL_SESSION_new()) == NULL)
        return (0);

    /* If the context has a default timeout, use it */
    if (s->session_ctx->session_timeout == 0)
        ss->timeout = SSL_get_default_timeout(s);
    else
        ss->timeout = s->session_ctx->session_timeout;

    if (s->session != NULL) {
        SSL_SESSION_free(s->session);
        s->session = NULL;
    }

    if (session) {
        if (s->version == SSL2_VERSION) {
            ss->ssl_version = SSL2_VERSION;
            ss->session_id_length = SSL2_SSL_SESSION_ID_LENGTH;
        } else if (s->version == SSL3_VERSION) {
            ss->ssl_version = SSL3_VERSION;
            ss->session_id_length = SSL3_SSL_SESSION_ID_LENGTH;
        } else if (s->version == TLS1_VERSION) {
            ss->ssl_version = TLS1_VERSION;
            ss->session_id_length = SSL3_SSL_SESSION_ID_LENGTH;
        } else if (s->version == TLS1_1_VERSION) {
            ss->ssl_version = TLS1_1_VERSION;
            ss->session_id_length = SSL3_SSL_SESSION_ID_LENGTH;
        } else if (s->version == TLS1_2_VERSION) {
            ss->ssl_version = TLS1_2_VERSION;
            ss->session_id_length = SSL3_SSL_SESSION_ID_LENGTH;
        } else if (s->version == DTLS1_BAD_VER) {
            ss->ssl_version = DTLS1_BAD_VER;
            ss->session_id_length = SSL3_SSL_SESSION_ID_LENGTH;
        } else if (s->version == DTLS1_VERSION) {
            ss->ssl_version = DTLS1_VERSION;
            ss->session_id_length = SSL3_SSL_SESSION_ID_LENGTH;
        } else if (s->version == DTLS1_2_VERSION) {
            ss->ssl_version = DTLS1_2_VERSION;
            ss->session_id_length = SSL3_SSL_SESSION_ID_LENGTH;
        } else {
            SSLerr(SSL_F_SSL_GET_NEW_SESSION, SSL_R_UNSUPPORTED_SSL_VERSION);
            SSL_SESSION_free(ss);
            return (0);
        }
#ifndef OPENSSL_NO_TLSEXT
        /*-
         * If RFC5077 ticket, use empty session ID (as server).
         * Note that:
         * (a) ssl_get_prev_session() does lookahead into the
         *     ClientHello extensions to find the session ticket.
         *     When ssl_get_prev_session() fails, s3_srvr.c calls
         *     ssl_get_new_session() in ssl3_get_client_hello().
         *     At that point, it has not yet parsed the extensions,
         *     however, because of the lookahead, it already knows
         *     whether a ticket is expected or not.
         *
         * (b) s3_clnt.c calls ssl_get_new_session() before parsing
         *     ServerHello extensions, and before recording the session
         *     ID received from the server, so this block is a noop.
         */
        if (s->tlsext_ticket_expected) {
            ss->session_id_length = 0;
            goto sess_id_done;
        }
#endif
        /* Choose which callback will set the session ID */
        CRYPTO_r_lock(CRYPTO_LOCK_SSL_CTX);
        if (s->generate_session_id)
            cb = s->generate_session_id;
        else if (s->session_ctx->generate_session_id)
            cb = s->session_ctx->generate_session_id;
        CRYPTO_r_unlock(CRYPTO_LOCK_SSL_CTX);
        /* Choose a session ID */
        tmp = ss->session_id_length;
        if (!cb(s, ss->session_id, &tmp)) {
            /* The callback failed */
            SSLerr(SSL_F_SSL_GET_NEW_SESSION,
                   SSL_R_SSL_SESSION_ID_CALLBACK_FAILED);
            SSL_SESSION_free(ss);
            return (0);
        }
        /*
         * Don't allow the callback to set the session length to zero. nor
         * set it higher than it was.
         */
        if (!tmp || (tmp > ss->session_id_length)) {
            /* The callback set an illegal length */
            SSLerr(SSL_F_SSL_GET_NEW_SESSION,
                   SSL_R_SSL_SESSION_ID_HAS_BAD_LENGTH);
            SSL_SESSION_free(ss);
            return (0);
        }
        /* If the session length was shrunk and we're SSLv2, pad it */
        if ((tmp < ss->session_id_length) && (s->version == SSL2_VERSION))
            memset(ss->session_id + tmp, 0, ss->session_id_length - tmp);
        else
            ss->session_id_length = tmp;
        /* Finally, check for a conflict */
        if (SSL_has_matching_session_id(s, ss->session_id,
                                        ss->session_id_length)) {
            SSLerr(SSL_F_SSL_GET_NEW_SESSION, SSL_R_SSL_SESSION_ID_CONFLICT);
            SSL_SESSION_free(ss);
            return (0);
        }
#ifndef OPENSSL_NO_TLSEXT
 sess_id_done:
        if (s->tlsext_hostname) {
            ss->tlsext_hostname = BUF_strdup(s->tlsext_hostname);
            if (ss->tlsext_hostname == NULL) {
                SSLerr(SSL_F_SSL_GET_NEW_SESSION, ERR_R_INTERNAL_ERROR);
                SSL_SESSION_free(ss);
                return 0;
            }
        }
#endif
    } else {
        ss->session_id_length = 0;
    }

    if (s->sid_ctx_length > sizeof(ss->sid_ctx)) {
        SSLerr(SSL_F_SSL_GET_NEW_SESSION, ERR_R_INTERNAL_ERROR);
        SSL_SESSION_free(ss);
        return 0;
    }
    memcpy(ss->sid_ctx, s->sid_ctx, s->sid_ctx_length);
    ss->sid_ctx_length = s->sid_ctx_length;
    s->session = ss;
    ss->ssl_version = s->version;
    ss->verify_result = X509_V_OK;

    return (1);
}

/*-
 * ssl_get_prev attempts to find an SSL_SESSION to be used to resume this
 * connection. It is only called by servers.
 *
 *   session_id: points at the session ID in the ClientHello. This code will
 *       read past the end of this in order to parse out the session ticket
 *       extension, if any.
 *   len: the length of the session ID.
 *   limit: a pointer to the first byte after the ClientHello.
 *
 * Returns:
 *   -1: error
 *    0: a session may have been found.
 *
 * Side effects:
 *   - If a session is found then s->session is pointed at it (after freeing an
 *     existing session if need be) and s->verify_result is set from the session.
 *   - Both for new and resumed sessions, s->tlsext_ticket_expected is set to 1
 *     if the server should issue a new session ticket (to 0 otherwise).
 */
int ssl_get_prev_session(SSL *s, unsigned char *session_id, int len,
                         const unsigned char *limit)
{
    /* This is used only by servers. */

    SSL_SESSION *ret = NULL;
    int fatal = 0;
    int try_session_cache = 1;
#ifndef OPENSSL_NO_TLSEXT
    int r;
#endif

    if (limit - session_id < len) {
        fatal = 1;
        goto err;
    }

    if (len == 0)
        try_session_cache = 0;

#ifndef OPENSSL_NO_TLSEXT
    /* sets s->tlsext_ticket_expected */
    r = tls1_process_ticket(s, session_id, len, limit, &ret);
    switch (r) {
    case -1:                   /* Error during processing */
        fatal = 1;
        goto err;
    case 0:                    /* No ticket found */
    case 1:                    /* Zero length ticket found */
        break;                  /* Ok to carry on processing session id. */
    case 2:                    /* Ticket found but not decrypted. */
    case 3:                    /* Ticket decrypted, *ret has been set. */
        try_session_cache = 0;
        break;
    default:
        abort();
    }
#endif

    if (try_session_cache &&
        ret == NULL &&
        !(s->session_ctx->session_cache_mode &
          SSL_SESS_CACHE_NO_INTERNAL_LOOKUP)) {
        SSL_SESSION data;
        data.ssl_version = s->version;
        data.session_id_length = len;
        if (len == 0)
            return 0;
        memcpy(data.session_id, session_id, len);
        CRYPTO_r_lock(CRYPTO_LOCK_SSL_CTX);
        ret = lh_SSL_SESSION_retrieve(s->session_ctx->sessions, &data);
        if (ret != NULL) {
            /* don't allow other threads to steal it: */
            CRYPTO_add(&ret->references, 1, CRYPTO_LOCK_SSL_SESSION);
        }
        CRYPTO_r_unlock(CRYPTO_LOCK_SSL_CTX);
        if (ret == NULL)
            s->session_ctx->stats.sess_miss++;
    }

    if (try_session_cache &&
        ret == NULL && s->session_ctx->get_session_cb != NULL) {
        int copy = 1;

        if ((ret = s->session_ctx->get_session_cb(s, session_id, len, &copy))) {
            s->session_ctx->stats.sess_cb_hit++;

            /*
             * Increment reference count now if the session callback asks us
             * to do so (note that if the session structures returned by the
             * callback are shared between threads, it must handle the
             * reference count itself [i.e. copy == 0], or things won't be
             * thread-safe).
             */
            if (copy)
                CRYPTO_add(&ret->references, 1, CRYPTO_LOCK_SSL_SESSION);

            /*
             * Add the externally cached session to the internal cache as
             * well if and only if we are supposed to.
             */
            if (!
                (s->session_ctx->session_cache_mode &
                 SSL_SESS_CACHE_NO_INTERNAL_STORE))
                /*
                 * The following should not return 1, otherwise, things are
                 * very strange
                 */
                SSL_CTX_add_session(s->session_ctx, ret);
        }
    }

    if (ret == NULL)
        goto err;

    /* Now ret is non-NULL and we own one of its reference counts. */

    if (ret->sid_ctx_length != s->sid_ctx_length
        || memcmp(ret->sid_ctx, s->sid_ctx, ret->sid_ctx_length)) {
        /*
         * We have the session requested by the client, but we don't want to
         * use it in this context.
         */
        goto err;               /* treat like cache miss */
    }

    if ((s->verify_mode & SSL_VERIFY_PEER) && s->sid_ctx_length == 0) {
        /*
         * We can't be sure if this session is being used out of context,
         * which is especially important for SSL_VERIFY_PEER. The application
         * should have used SSL[_CTX]_set_session_id_context. For this error
         * case, we generate an error instead of treating the event like a
         * cache miss (otherwise it would be easy for applications to
         * effectively disable the session cache by accident without anyone
         * noticing).
         */

        SSLerr(SSL_F_SSL_GET_PREV_SESSION,
               SSL_R_SESSION_ID_CONTEXT_UNINITIALIZED);
        fatal = 1;
        goto err;
    }

    if (ret->cipher == NULL) {
        unsigned char buf[5], *p;
        unsigned long l;

        p = buf;
        l = ret->cipher_id;
        l2n(l, p);
        if ((ret->ssl_version >> 8) >= SSL3_VERSION_MAJOR)
            ret->cipher = ssl_get_cipher_by_char(s, &(buf[2]));
        else
            ret->cipher = ssl_get_cipher_by_char(s, &(buf[1]));
        if (ret->cipher == NULL)
            goto err;
    }

    if (ret->timeout < (long)(time(NULL) - ret->time)) { /* timeout */
        s->session_ctx->stats.sess_timeout++;
        if (try_session_cache) {
            /* session was from the cache, so remove it */
            SSL_CTX_remove_session(s->session_ctx, ret);
        }
        goto err;
    }

    s->session_ctx->stats.sess_hit++;

    if (s->session != NULL)
        SSL_SESSION_free(s->session);
    s->session = ret;
    s->verify_result = s->session->verify_result;
    return 1;

 err:
    if (ret != NULL) {
        SSL_SESSION_free(ret);
#ifndef OPENSSL_NO_TLSEXT
        if (!try_session_cache) {
            /*
             * The session was from a ticket, so we should issue a ticket for
             * the new session
             */
            s->tlsext_ticket_expected = 1;
        }
#endif
    }
    if (fatal)
        return -1;
    else
        return 0;
}

int SSL_CTX_add_session(SSL_CTX *ctx, SSL_SESSION *c)
{
    int ret = 0;
    SSL_SESSION *s;

    /*
     * add just 1 reference count for the SSL_CTX's session cache even though
     * it has two ways of access: each session is in a doubly linked list and
     * an lhash
     */
    CRYPTO_add(&c->references, 1, CRYPTO_LOCK_SSL_SESSION);
    /*
     * if session c is in already in cache, we take back the increment later
     */

    CRYPTO_w_lock(CRYPTO_LOCK_SSL_CTX);
    s = lh_SSL_SESSION_insert(ctx->sessions, c);

    /*
     * s != NULL iff we already had a session with the given PID. In this
     * case, s == c should hold (then we did not really modify
     * ctx->sessions), or we're in trouble.
     */
    if (s != NULL && s != c) {
        /* We *are* in trouble ... */
        SSL_SESSION_list_remove(ctx, s);
        SSL_SESSION_free(s);
        /*
         * ... so pretend the other session did not exist in cache (we cannot
         * handle two SSL_SESSION structures with identical session ID in the
         * same cache, which could happen e.g. when two threads concurrently
         * obtain the same session from an external cache)
         */
        s = NULL;
    } else if (s == NULL &&
               lh_SSL_SESSION_retrieve(ctx->sessions, c) == NULL) {
        /* s == NULL can also mean OOM error in lh_SSL_SESSION_insert ... */

        /*
         * ... so take back the extra reference and also don't add
         * the session to the SSL_SESSION_list at this time
         */
        s = c;
    }

    /* Put at the head of the queue unless it is already in the cache */
    if (s == NULL)
        SSL_SESSION_list_add(ctx, c);

    if (s != NULL) {
        /*
         * existing cache entry -- decrement previously incremented reference
         * count because it already takes into account the cache
         */

        SSL_SESSION_free(s);    /* s == c */
        ret = 0;
    } else {
        /*
         * new cache entry -- remove old ones if cache has become too large
         */

        ret = 1;

        if (SSL_CTX_sess_get_cache_size(ctx) > 0) {
            while (SSL_CTX_sess_number(ctx) >
                   SSL_CTX_sess_get_cache_size(ctx)) {
                if (!remove_session_lock(ctx, ctx->session_cache_tail, 0))
                    break;
                else
                    ctx->stats.sess_cache_full++;
            }
        }
    }
    CRYPTO_w_unlock(CRYPTO_LOCK_SSL_CTX);
    return (ret);
}

int SSL_CTX_remove_session(SSL_CTX *ctx, SSL_SESSION *c)
{
    return remove_session_lock(ctx, c, 1);
}

static int remove_session_lock(SSL_CTX *ctx, SSL_SESSION *c, int lck)
{
    SSL_SESSION *r;
    int ret = 0;

    if ((c != NULL) && (c->session_id_length != 0)) {
        if (lck)
            CRYPTO_w_lock(CRYPTO_LOCK_SSL_CTX);
        if ((r = lh_SSL_SESSION_retrieve(ctx->sessions, c)) == c) {
            ret = 1;
            r = lh_SSL_SESSION_delete(ctx->sessions, c);
            SSL_SESSION_list_remove(ctx, c);
        }

        if (lck)
            CRYPTO_w_unlock(CRYPTO_LOCK_SSL_CTX);

        if (ret) {
            r->not_resumable = 1;
            if (ctx->remove_session_cb != NULL)
                ctx->remove_session_cb(ctx, r);
            SSL_SESSION_free(r);
        }
    } else
        ret = 0;
    return (ret);
}

void SSL_SESSION_free(SSL_SESSION *ss)
{
    int i;

    if (ss == NULL)
        return;

    i = CRYPTO_add(&ss->references, -1, CRYPTO_LOCK_SSL_SESSION);
#ifdef REF_PRINT
    REF_PRINT("SSL_SESSION", ss);
#endif
    if (i > 0)
        return;
#ifdef REF_CHECK
    if (i < 0) {
        fprintf(stderr, "SSL_SESSION_free, bad reference count\n");
        abort();                /* ok */
    }
#endif

    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_SSL_SESSION, ss, &ss->ex_data);

    OPENSSL_cleanse(ss->key_arg, sizeof(ss->key_arg));
    OPENSSL_cleanse(ss->master_key, sizeof(ss->master_key));
    OPENSSL_cleanse(ss->session_id, sizeof(ss->session_id));
    if (ss->sess_cert != NULL)
        ssl_sess_cert_free(ss->sess_cert);
    if (ss->peer != NULL)
        X509_free(ss->peer);
    if (ss->ciphers != NULL)
        sk_SSL_CIPHER_free(ss->ciphers);
#ifndef OPENSSL_NO_TLSEXT
    if (ss->tlsext_hostname != NULL)
        OPENSSL_free(ss->tlsext_hostname);
    if (ss->tlsext_tick != NULL)
        OPENSSL_free(ss->tlsext_tick);
# ifndef OPENSSL_NO_EC
    ss->tlsext_ecpointformatlist_length = 0;
    if (ss->tlsext_ecpointformatlist != NULL)
        OPENSSL_free(ss->tlsext_ecpointformatlist);
    ss->tlsext_ellipticcurvelist_length = 0;
    if (ss->tlsext_ellipticcurvelist != NULL)
        OPENSSL_free(ss->tlsext_ellipticcurvelist);
# endif                         /* OPENSSL_NO_EC */
#endif
#ifndef OPENSSL_NO_PSK
    if (ss->psk_identity_hint != NULL)
        OPENSSL_free(ss->psk_identity_hint);
    if (ss->psk_identity != NULL)
        OPENSSL_free(ss->psk_identity);
#endif
#ifndef OPENSSL_NO_SRP
    if (ss->srp_username != NULL)
        OPENSSL_free(ss->srp_username);
#endif
    OPENSSL_cleanse(ss, sizeof(*ss));
    OPENSSL_free(ss);
}

int SSL_set_session(SSL *s, SSL_SESSION *session)
{
    int ret = 0;
    const SSL_METHOD *meth;

    if (session != NULL) {
        meth = s->ctx->method->get_ssl_method(session->ssl_version);
        if (meth == NULL)
            meth = s->method->get_ssl_method(session->ssl_version);
        if (meth == NULL) {
            SSLerr(SSL_F_SSL_SET_SESSION, SSL_R_UNABLE_TO_FIND_SSL_METHOD);
            return (0);
        }

        if (meth != s->method) {
            if (!SSL_set_ssl_method(s, meth))
                return (0);
        }
#ifndef OPENSSL_NO_KRB5
        if (s->kssl_ctx && !s->kssl_ctx->client_princ &&
            session->krb5_client_princ_len > 0) {
            s->kssl_ctx->client_princ =
                (char *)OPENSSL_malloc(session->krb5_client_princ_len + 1);
            if (s->kssl_ctx->client_princ == NULL) {
                SSLerr(SSL_F_SSL_SET_SESSION, ERR_R_MALLOC_FAILURE);
                return 0;
            }
            memcpy(s->kssl_ctx->client_princ, session->krb5_client_princ,
                   session->krb5_client_princ_len);
            s->kssl_ctx->client_princ[session->krb5_client_princ_len] = '\0';
        }
#endif                          /* OPENSSL_NO_KRB5 */

        /* CRYPTO_w_lock(CRYPTO_LOCK_SSL); */
        CRYPTO_add(&session->references, 1, CRYPTO_LOCK_SSL_SESSION);
        if (s->session != NULL)
            SSL_SESSION_free(s->session);
        s->session = session;
        s->verify_result = s->session->verify_result;
        /* CRYPTO_w_unlock(CRYPTO_LOCK_SSL); */
        ret = 1;
    } else {
        if (s->session != NULL) {
            SSL_SESSION_free(s->session);
            s->session = NULL;
        }

        meth = s->ctx->method;
        if (meth != s->method) {
            if (!SSL_set_ssl_method(s, meth))
                return (0);
        }
        ret = 1;
    }
    return (ret);
}

long SSL_SESSION_set_timeout(SSL_SESSION *s, long t)
{
    if (s == NULL)
        return (0);
    s->timeout = t;
    return (1);
}

long SSL_SESSION_get_timeout(const SSL_SESSION *s)
{
    if (s == NULL)
        return (0);
    return (s->timeout);
}

long SSL_SESSION_get_time(const SSL_SESSION *s)
{
    if (s == NULL)
        return (0);
    return (s->time);
}

long SSL_SESSION_set_time(SSL_SESSION *s, long t)
{
    if (s == NULL)
        return (0);
    s->time = t;
    return (t);
}

X509 *SSL_SESSION_get0_peer(SSL_SESSION *s)
{
    return s->peer;
}

int SSL_SESSION_set1_id_context(SSL_SESSION *s, const unsigned char *sid_ctx,
                                unsigned int sid_ctx_len)
{
    if (sid_ctx_len > SSL_MAX_SID_CTX_LENGTH) {
        SSLerr(SSL_F_SSL_SESSION_SET1_ID_CONTEXT,
               SSL_R_SSL_SESSION_ID_CONTEXT_TOO_LONG);
        return 0;
    }
    s->sid_ctx_length = sid_ctx_len;
    if (s->sid_ctx != sid_ctx)
        memcpy(s->sid_ctx, sid_ctx, sid_ctx_len);

    return 1;
}

long SSL_CTX_set_timeout(SSL_CTX *s, long t)
{
    long l;
    if (s == NULL)
        return (0);
    l = s->session_timeout;
    s->session_timeout = t;
    return (l);
}

long SSL_CTX_get_timeout(const SSL_CTX *s)
{
    if (s == NULL)
        return (0);
    return (s->session_timeout);
}

#ifndef OPENSSL_NO_TLSEXT
int SSL_set_session_secret_cb(SSL *s,
                              int (*tls_session_secret_cb) (SSL *s,
                                                            void *secret,
                                                            int *secret_len,
                                                            STACK_OF(SSL_CIPHER)
                                                            *peer_ciphers,
                                                            SSL_CIPHER
                                                            **cipher,
                                                            void *arg),
                              void *arg)
{
    if (s == NULL)
        return (0);
    s->tls_session_secret_cb = tls_session_secret_cb;
    s->tls_session_secret_cb_arg = arg;
    return (1);
}

int SSL_set_session_ticket_ext_cb(SSL *s, tls_session_ticket_ext_cb_fn cb,
                                  void *arg)
{
    if (s == NULL)
        return (0);
    s->tls_session_ticket_ext_cb = cb;
    s->tls_session_ticket_ext_cb_arg = arg;
    return (1);
}

int SSL_set_session_ticket_ext(SSL *s, void *ext_data, int ext_len)
{
    if (s->version >= TLS1_VERSION) {
        if (s->tlsext_session_ticket) {
            OPENSSL_free(s->tlsext_session_ticket);
            s->tlsext_session_ticket = NULL;
        }

        s->tlsext_session_ticket =
            OPENSSL_malloc(sizeof(TLS_SESSION_TICKET_EXT) + ext_len);
        if (!s->tlsext_session_ticket) {
            SSLerr(SSL_F_SSL_SET_SESSION_TICKET_EXT, ERR_R_MALLOC_FAILURE);
            return 0;
        }

        if (ext_data) {
            s->tlsext_session_ticket->length = ext_len;
            s->tlsext_session_ticket->data = s->tlsext_session_ticket + 1;
            memcpy(s->tlsext_session_ticket->data, ext_data, ext_len);
        } else {
            s->tlsext_session_ticket->length = 0;
            s->tlsext_session_ticket->data = NULL;
        }

        return 1;
    }

    return 0;
}
#endif                          /* OPENSSL_NO_TLSEXT */

typedef struct timeout_param_st {
    SSL_CTX *ctx;
    long time;
    LHASH_OF(SSL_SESSION) *cache;
} TIMEOUT_PARAM;

static void timeout_doall_arg(SSL_SESSION *s, TIMEOUT_PARAM *p)
{
    if ((p->time == 0) || (p->time > (s->time + s->timeout))) { /* timeout */
        /*
         * The reason we don't call SSL_CTX_remove_session() is to save on
         * locking overhead
         */
        (void)lh_SSL_SESSION_delete(p->cache, s);
        SSL_SESSION_list_remove(p->ctx, s);
        s->not_resumable = 1;
        if (p->ctx->remove_session_cb != NULL)
            p->ctx->remove_session_cb(p->ctx, s);
        SSL_SESSION_free(s);
    }
}

static IMPLEMENT_LHASH_DOALL_ARG_FN(timeout, SSL_SESSION, TIMEOUT_PARAM)

void SSL_CTX_flush_sessions(SSL_CTX *s, long t)
{
    unsigned long i;
    TIMEOUT_PARAM tp;

    tp.ctx = s;
    tp.cache = s->sessions;
    if (tp.cache == NULL)
        return;
    tp.time = t;
    CRYPTO_w_lock(CRYPTO_LOCK_SSL_CTX);
    i = CHECKED_LHASH_OF(SSL_SESSION, tp.cache)->down_load;
    CHECKED_LHASH_OF(SSL_SESSION, tp.cache)->down_load = 0;
    lh_SSL_SESSION_doall_arg(tp.cache, LHASH_DOALL_ARG_FN(timeout),
                             TIMEOUT_PARAM, &tp);
    CHECKED_LHASH_OF(SSL_SESSION, tp.cache)->down_load = i;
    CRYPTO_w_unlock(CRYPTO_LOCK_SSL_CTX);
}

int ssl_clear_bad_session(SSL *s)
{
    if ((s->session != NULL) &&
        !(s->shutdown & SSL_SENT_SHUTDOWN) &&
        !(SSL_in_init(s) || SSL_in_before(s))) {
        SSL_CTX_remove_session(s->session_ctx, s->session);
        return (1);
    } else
        return (0);
}

/* locked by SSL_CTX in the calling function */
static void SSL_SESSION_list_remove(SSL_CTX *ctx, SSL_SESSION *s)
{
    if ((s->next == NULL) || (s->prev == NULL))
        return;

    if (s->next == (SSL_SESSION *)&(ctx->session_cache_tail)) {
        /* last element in list */
        if (s->prev == (SSL_SESSION *)&(ctx->session_cache_head)) {
            /* only one element in list */
            ctx->session_cache_head = NULL;
            ctx->session_cache_tail = NULL;
        } else {
            ctx->session_cache_tail = s->prev;
            s->prev->next = (SSL_SESSION *)&(ctx->session_cache_tail);
        }
    } else {
        if (s->prev == (SSL_SESSION *)&(ctx->session_cache_head)) {
            /* first element in list */
            ctx->session_cache_head = s->next;
            s->next->prev = (SSL_SESSION *)&(ctx->session_cache_head);
        } else {
            /* middle of list */
            s->next->prev = s->prev;
            s->prev->next = s->next;
        }
    }
    s->prev = s->next = NULL;
}

static void SSL_SESSION_list_add(SSL_CTX *ctx, SSL_SESSION *s)
{
    if ((s->next != NULL) && (s->prev != NULL))
        SSL_SESSION_list_remove(ctx, s);

    if (ctx->session_cache_head == NULL) {
        ctx->session_cache_head = s;
        ctx->session_cache_tail = s;
        s->prev = (SSL_SESSION *)&(ctx->session_cache_head);
        s->next = (SSL_SESSION *)&(ctx->session_cache_tail);
    } else {
        s->next = ctx->session_cache_head;
        s->next->prev = s;
        s->prev = (SSL_SESSION *)&(ctx->session_cache_head);
        ctx->session_cache_head = s;
    }
}

void SSL_CTX_sess_set_new_cb(SSL_CTX *ctx,
                             int (*cb) (struct ssl_st *ssl,
                                        SSL_SESSION *sess))
{
    ctx->new_session_cb = cb;
}

int (*SSL_CTX_sess_get_new_cb(SSL_CTX *ctx)) (SSL *ssl, SSL_SESSION *sess) {
    return ctx->new_session_cb;
}

void SSL_CTX_sess_set_remove_cb(SSL_CTX *ctx,
                                void (*cb) (SSL_CTX *ctx, SSL_SESSION *sess))
{
    ctx->remove_session_cb = cb;
}

void (*SSL_CTX_sess_get_remove_cb(SSL_CTX *ctx)) (SSL_CTX *ctx,
                                                  SSL_SESSION *sess) {
    return ctx->remove_session_cb;
}

void SSL_CTX_sess_set_get_cb(SSL_CTX *ctx,
                             SSL_SESSION *(*cb) (struct ssl_st *ssl,
                                                 unsigned char *data, int len,
                                                 int *copy))
{
    ctx->get_session_cb = cb;
}

SSL_SESSION *(*SSL_CTX_sess_get_get_cb(SSL_CTX *ctx)) (SSL *ssl,
                                                       unsigned char *data,
                                                       int len, int *copy) {
    return ctx->get_session_cb;
}

void SSL_CTX_set_info_callback(SSL_CTX *ctx,
                               void (*cb) (const SSL *ssl, int type, int val))
{
    ctx->info_callback = cb;
}

void (*SSL_CTX_get_info_callback(SSL_CTX *ctx)) (const SSL *ssl, int type,
                                                 int val) {
    return ctx->info_callback;
}

void SSL_CTX_set_client_cert_cb(SSL_CTX *ctx,
                                int (*cb) (SSL *ssl, X509 **x509,
                                           EVP_PKEY **pkey))
{
    ctx->client_cert_cb = cb;
}

int (*SSL_CTX_get_client_cert_cb(SSL_CTX *ctx)) (SSL *ssl, X509 **x509,
                                                 EVP_PKEY **pkey) {
    return ctx->client_cert_cb;
}

#ifndef OPENSSL_NO_ENGINE
int SSL_CTX_set_client_cert_engine(SSL_CTX *ctx, ENGINE *e)
{
    if (!ENGINE_init(e)) {
        SSLerr(SSL_F_SSL_CTX_SET_CLIENT_CERT_ENGINE, ERR_R_ENGINE_LIB);
        return 0;
    }
    if (!ENGINE_get_ssl_client_cert_function(e)) {
        SSLerr(SSL_F_SSL_CTX_SET_CLIENT_CERT_ENGINE,
               SSL_R_NO_CLIENT_CERT_METHOD);
        ENGINE_finish(e);
        return 0;
    }
    ctx->client_cert_engine = e;
    return 1;
}
#endif

void SSL_CTX_set_cookie_generate_cb(SSL_CTX *ctx,
                                    int (*cb) (SSL *ssl,
                                               unsigned char *cookie,
                                               unsigned int *cookie_len))
{
    ctx->app_gen_cookie_cb = cb;
}

void SSL_CTX_set_cookie_verify_cb(SSL_CTX *ctx,
                                  int (*cb) (SSL *ssl, unsigned char *cookie,
                                             unsigned int cookie_len))
{
    ctx->app_verify_cookie_cb = cb;
}

IMPLEMENT_PEM_rw(SSL_SESSION, SSL_SESSION, PEM_STRING_SSL_SESSION,
                 SSL_SESSION)
/* ssl/ssl_stat.c */
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

const char *SSL_state_string_long(const SSL *s)
{
    const char *str;

    switch (s->state) {
    case SSL_ST_BEFORE:
        str = "before SSL initialization";
        break;
    case SSL_ST_ACCEPT:
        str = "before accept initialization";
        break;
    case SSL_ST_CONNECT:
        str = "before connect initialization";
        break;
    case SSL_ST_OK:
        str = "SSL negotiation finished successfully";
        break;
    case SSL_ST_RENEGOTIATE:
        str = "SSL renegotiate ciphers";
        break;
    case SSL_ST_BEFORE | SSL_ST_CONNECT:
        str = "before/connect initialization";
        break;
    case SSL_ST_OK | SSL_ST_CONNECT:
        str = "ok/connect SSL initialization";
        break;
    case SSL_ST_BEFORE | SSL_ST_ACCEPT:
        str = "before/accept initialization";
        break;
    case SSL_ST_OK | SSL_ST_ACCEPT:
        str = "ok/accept SSL initialization";
        break;
    case SSL_ST_ERR:
        str = "error";
        break;
#ifndef OPENSSL_NO_SSL2
    case SSL2_ST_CLIENT_START_ENCRYPTION:
        str = "SSLv2 client start encryption";
        break;
    case SSL2_ST_SERVER_START_ENCRYPTION:
        str = "SSLv2 server start encryption";
        break;
    case SSL2_ST_SEND_CLIENT_HELLO_A:
        str = "SSLv2 write client hello A";
        break;
    case SSL2_ST_SEND_CLIENT_HELLO_B:
        str = "SSLv2 write client hello B";
        break;
    case SSL2_ST_GET_SERVER_HELLO_A:
        str = "SSLv2 read server hello A";
        break;
    case SSL2_ST_GET_SERVER_HELLO_B:
        str = "SSLv2 read server hello B";
        break;
    case SSL2_ST_SEND_CLIENT_MASTER_KEY_A:
        str = "SSLv2 write client master key A";
        break;
    case SSL2_ST_SEND_CLIENT_MASTER_KEY_B:
        str = "SSLv2 write client master key B";
        break;
    case SSL2_ST_SEND_CLIENT_FINISHED_A:
        str = "SSLv2 write client finished A";
        break;
    case SSL2_ST_SEND_CLIENT_FINISHED_B:
        str = "SSLv2 write client finished B";
        break;
    case SSL2_ST_SEND_CLIENT_CERTIFICATE_A:
        str = "SSLv2 write client certificate A";
        break;
    case SSL2_ST_SEND_CLIENT_CERTIFICATE_B:
        str = "SSLv2 write client certificate B";
        break;
    case SSL2_ST_SEND_CLIENT_CERTIFICATE_C:
        str = "SSLv2 write client certificate C";
        break;
    case SSL2_ST_SEND_CLIENT_CERTIFICATE_D:
        str = "SSLv2 write client certificate D";
        break;
    case SSL2_ST_GET_SERVER_VERIFY_A:
        str = "SSLv2 read server verify A";
        break;
    case SSL2_ST_GET_SERVER_VERIFY_B:
        str = "SSLv2 read server verify B";
        break;
    case SSL2_ST_GET_SERVER_FINISHED_A:
        str = "SSLv2 read server finished A";
        break;
    case SSL2_ST_GET_SERVER_FINISHED_B:
        str = "SSLv2 read server finished B";
        break;
    case SSL2_ST_GET_CLIENT_HELLO_A:
        str = "SSLv2 read client hello A";
        break;
    case SSL2_ST_GET_CLIENT_HELLO_B:
        str = "SSLv2 read client hello B";
        break;
    case SSL2_ST_GET_CLIENT_HELLO_C:
        str = "SSLv2 read client hello C";
        break;
    case SSL2_ST_SEND_SERVER_HELLO_A:
        str = "SSLv2 write server hello A";
        break;
    case SSL2_ST_SEND_SERVER_HELLO_B:
        str = "SSLv2 write server hello B";
        break;
    case SSL2_ST_GET_CLIENT_MASTER_KEY_A:
        str = "SSLv2 read client master key A";
        break;
    case SSL2_ST_GET_CLIENT_MASTER_KEY_B:
        str = "SSLv2 read client master key B";
        break;
    case SSL2_ST_SEND_SERVER_VERIFY_A:
        str = "SSLv2 write server verify A";
        break;
    case SSL2_ST_SEND_SERVER_VERIFY_B:
        str = "SSLv2 write server verify B";
        break;
    case SSL2_ST_SEND_SERVER_VERIFY_C:
        str = "SSLv2 write server verify C";
        break;
    case SSL2_ST_GET_CLIENT_FINISHED_A:
        str = "SSLv2 read client finished A";
        break;
    case SSL2_ST_GET_CLIENT_FINISHED_B:
        str = "SSLv2 read client finished B";
        break;
    case SSL2_ST_SEND_SERVER_FINISHED_A:
        str = "SSLv2 write server finished A";
        break;
    case SSL2_ST_SEND_SERVER_FINISHED_B:
        str = "SSLv2 write server finished B";
        break;
    case SSL2_ST_SEND_REQUEST_CERTIFICATE_A:
        str = "SSLv2 write request certificate A";
        break;
    case SSL2_ST_SEND_REQUEST_CERTIFICATE_B:
        str = "SSLv2 write request certificate B";
        break;
    case SSL2_ST_SEND_REQUEST_CERTIFICATE_C:
        str = "SSLv2 write request certificate C";
        break;
    case SSL2_ST_SEND_REQUEST_CERTIFICATE_D:
        str = "SSLv2 write request certificate D";
        break;
    case SSL2_ST_X509_GET_SERVER_CERTIFICATE:
        str = "SSLv2 X509 read server certificate";
        break;
    case SSL2_ST_X509_GET_CLIENT_CERTIFICATE:
        str = "SSLv2 X509 read client certificate";
        break;
#endif

#ifndef OPENSSL_NO_SSL3
/* SSLv3 additions */
    case SSL3_ST_CW_CLNT_HELLO_A:
        str = "SSLv3 write client hello A";
        break;
    case SSL3_ST_CW_CLNT_HELLO_B:
        str = "SSLv3 write client hello B";
        break;
    case SSL3_ST_CR_SRVR_HELLO_A:
        str = "SSLv3 read server hello A";
        break;
    case SSL3_ST_CR_SRVR_HELLO_B:
        str = "SSLv3 read server hello B";
        break;
    case SSL3_ST_CR_CERT_A:
        str = "SSLv3 read server certificate A";
        break;
    case SSL3_ST_CR_CERT_B:
        str = "SSLv3 read server certificate B";
        break;
    case SSL3_ST_CR_KEY_EXCH_A:
        str = "SSLv3 read server key exchange A";
        break;
    case SSL3_ST_CR_KEY_EXCH_B:
        str = "SSLv3 read server key exchange B";
        break;
    case SSL3_ST_CR_CERT_REQ_A:
        str = "SSLv3 read server certificate request A";
        break;
    case SSL3_ST_CR_CERT_REQ_B:
        str = "SSLv3 read server certificate request B";
        break;
    case SSL3_ST_CR_SESSION_TICKET_A:
        str = "SSLv3 read server session ticket A";
        break;
    case SSL3_ST_CR_SESSION_TICKET_B:
        str = "SSLv3 read server session ticket B";
        break;
    case SSL3_ST_CR_SRVR_DONE_A:
        str = "SSLv3 read server done A";
        break;
    case SSL3_ST_CR_SRVR_DONE_B:
        str = "SSLv3 read server done B";
        break;
    case SSL3_ST_CW_CERT_A:
        str = "SSLv3 write client certificate A";
        break;
    case SSL3_ST_CW_CERT_B:
        str = "SSLv3 write client certificate B";
        break;
    case SSL3_ST_CW_CERT_C:
        str = "SSLv3 write client certificate C";
        break;
    case SSL3_ST_CW_CERT_D:
        str = "SSLv3 write client certificate D";
        break;
    case SSL3_ST_CW_KEY_EXCH_A:
        str = "SSLv3 write client key exchange A";
        break;
    case SSL3_ST_CW_KEY_EXCH_B:
        str = "SSLv3 write client key exchange B";
        break;
    case SSL3_ST_CW_CERT_VRFY_A:
        str = "SSLv3 write certificate verify A";
        break;
    case SSL3_ST_CW_CERT_VRFY_B:
        str = "SSLv3 write certificate verify B";
        break;

    case SSL3_ST_CW_CHANGE_A:
    case SSL3_ST_SW_CHANGE_A:
        str = "SSLv3 write change cipher spec A";
        break;
    case SSL3_ST_CW_CHANGE_B:
    case SSL3_ST_SW_CHANGE_B:
        str = "SSLv3 write change cipher spec B";
        break;
    case SSL3_ST_CW_FINISHED_A:
    case SSL3_ST_SW_FINISHED_A:
        str = "SSLv3 write finished A";
        break;
    case SSL3_ST_CW_FINISHED_B:
    case SSL3_ST_SW_FINISHED_B:
        str = "SSLv3 write finished B";
        break;
    case SSL3_ST_CR_CHANGE_A:
    case SSL3_ST_SR_CHANGE_A:
        str = "SSLv3 read change cipher spec A";
        break;
    case SSL3_ST_CR_CHANGE_B:
    case SSL3_ST_SR_CHANGE_B:
        str = "SSLv3 read change cipher spec B";
        break;
    case SSL3_ST_CR_FINISHED_A:
    case SSL3_ST_SR_FINISHED_A:
        str = "SSLv3 read finished A";
        break;
    case SSL3_ST_CR_FINISHED_B:
    case SSL3_ST_SR_FINISHED_B:
        str = "SSLv3 read finished B";
        break;

    case SSL3_ST_CW_FLUSH:
    case SSL3_ST_SW_FLUSH:
        str = "SSLv3 flush data";
        break;

    case SSL3_ST_SR_CLNT_HELLO_A:
        str = "SSLv3 read client hello A";
        break;
    case SSL3_ST_SR_CLNT_HELLO_B:
        str = "SSLv3 read client hello B";
        break;
    case SSL3_ST_SR_CLNT_HELLO_C:
        str = "SSLv3 read client hello C";
        break;
    case SSL3_ST_SW_HELLO_REQ_A:
        str = "SSLv3 write hello request A";
        break;
    case SSL3_ST_SW_HELLO_REQ_B:
        str = "SSLv3 write hello request B";
        break;
    case SSL3_ST_SW_HELLO_REQ_C:
        str = "SSLv3 write hello request C";
        break;
    case SSL3_ST_SW_SRVR_HELLO_A:
        str = "SSLv3 write server hello A";
        break;
    case SSL3_ST_SW_SRVR_HELLO_B:
        str = "SSLv3 write server hello B";
        break;
    case SSL3_ST_SW_CERT_A:
        str = "SSLv3 write certificate A";
        break;
    case SSL3_ST_SW_CERT_B:
        str = "SSLv3 write certificate B";
        break;
    case SSL3_ST_SW_KEY_EXCH_A:
        str = "SSLv3 write key exchange A";
        break;
    case SSL3_ST_SW_KEY_EXCH_B:
        str = "SSLv3 write key exchange B";
        break;
    case SSL3_ST_SW_CERT_REQ_A:
        str = "SSLv3 write certificate request A";
        break;
    case SSL3_ST_SW_CERT_REQ_B:
        str = "SSLv3 write certificate request B";
        break;
    case SSL3_ST_SW_SESSION_TICKET_A:
        str = "SSLv3 write session ticket A";
        break;
    case SSL3_ST_SW_SESSION_TICKET_B:
        str = "SSLv3 write session ticket B";
        break;
    case SSL3_ST_SW_SRVR_DONE_A:
        str = "SSLv3 write server done A";
        break;
    case SSL3_ST_SW_SRVR_DONE_B:
        str = "SSLv3 write server done B";
        break;
    case SSL3_ST_SR_CERT_A:
        str = "SSLv3 read client certificate A";
        break;
    case SSL3_ST_SR_CERT_B:
        str = "SSLv3 read client certificate B";
        break;
    case SSL3_ST_SR_KEY_EXCH_A:
        str = "SSLv3 read client key exchange A";
        break;
    case SSL3_ST_SR_KEY_EXCH_B:
        str = "SSLv3 read client key exchange B";
        break;
    case SSL3_ST_SR_CERT_VRFY_A:
        str = "SSLv3 read certificate verify A";
        break;
    case SSL3_ST_SR_CERT_VRFY_B:
        str = "SSLv3 read certificate verify B";
        break;
#endif

/* SSLv2/v3 compatibility states */
/* client */
    case SSL23_ST_CW_CLNT_HELLO_A:
        str = "SSLv2/v3 write client hello A";
        break;
    case SSL23_ST_CW_CLNT_HELLO_B:
        str = "SSLv2/v3 write client hello B";
        break;
    case SSL23_ST_CR_SRVR_HELLO_A:
        str = "SSLv2/v3 read server hello A";
        break;
    case SSL23_ST_CR_SRVR_HELLO_B:
        str = "SSLv2/v3 read server hello B";
        break;
/* server */
    case SSL23_ST_SR_CLNT_HELLO_A:
        str = "SSLv2/v3 read client hello A";
        break;
    case SSL23_ST_SR_CLNT_HELLO_B:
        str = "SSLv2/v3 read client hello B";
        break;

/* DTLS */
    case DTLS1_ST_CR_HELLO_VERIFY_REQUEST_A:
        str = "DTLS1 read hello verify request A";
        break;
    case DTLS1_ST_CR_HELLO_VERIFY_REQUEST_B:
        str = "DTLS1 read hello verify request B";
        break;
    case DTLS1_ST_SW_HELLO_VERIFY_REQUEST_A:
        str = "DTLS1 write hello verify request A";
        break;
    case DTLS1_ST_SW_HELLO_VERIFY_REQUEST_B:
        str = "DTLS1 write hello verify request B";
        break;

    default:
        str = "unknown state";
        break;
    }
    return (str);
}

const char *SSL_rstate_string_long(const SSL *s)
{
    const char *str;

    switch (s->rstate) {
    case SSL_ST_READ_HEADER:
        str = "read header";
        break;
    case SSL_ST_READ_BODY:
        str = "read body";
        break;
    case SSL_ST_READ_DONE:
        str = "read done";
        break;
    default:
        str = "unknown";
        break;
    }
    return (str);
}

const char *SSL_state_string(const SSL *s)
{
    const char *str;

    switch (s->state) {
    case SSL_ST_BEFORE:
        str = "PINIT ";
        break;
    case SSL_ST_ACCEPT:
        str = "AINIT ";
        break;
    case SSL_ST_CONNECT:
        str = "CINIT ";
        break;
    case SSL_ST_OK:
        str = "SSLOK ";
        break;
    case SSL_ST_ERR:
        str = "SSLERR";
        break;
#ifndef OPENSSL_NO_SSL2
    case SSL2_ST_CLIENT_START_ENCRYPTION:
        str = "2CSENC";
        break;
    case SSL2_ST_SERVER_START_ENCRYPTION:
        str = "2SSENC";
        break;
    case SSL2_ST_SEND_CLIENT_HELLO_A:
        str = "2SCH_A";
        break;
    case SSL2_ST_SEND_CLIENT_HELLO_B:
        str = "2SCH_B";
        break;
    case SSL2_ST_GET_SERVER_HELLO_A:
        str = "2GSH_A";
        break;
    case SSL2_ST_GET_SERVER_HELLO_B:
        str = "2GSH_B";
        break;
    case SSL2_ST_SEND_CLIENT_MASTER_KEY_A:
        str = "2SCMKA";
        break;
    case SSL2_ST_SEND_CLIENT_MASTER_KEY_B:
        str = "2SCMKB";
        break;
    case SSL2_ST_SEND_CLIENT_FINISHED_A:
        str = "2SCF_A";
        break;
    case SSL2_ST_SEND_CLIENT_FINISHED_B:
        str = "2SCF_B";
        break;
    case SSL2_ST_SEND_CLIENT_CERTIFICATE_A:
        str = "2SCC_A";
        break;
    case SSL2_ST_SEND_CLIENT_CERTIFICATE_B:
        str = "2SCC_B";
        break;
    case SSL2_ST_SEND_CLIENT_CERTIFICATE_C:
        str = "2SCC_C";
        break;
    case SSL2_ST_SEND_CLIENT_CERTIFICATE_D:
        str = "2SCC_D";
        break;
    case SSL2_ST_GET_SERVER_VERIFY_A:
        str = "2GSV_A";
        break;
    case SSL2_ST_GET_SERVER_VERIFY_B:
        str = "2GSV_B";
        break;
    case SSL2_ST_GET_SERVER_FINISHED_A:
        str = "2GSF_A";
        break;
    case SSL2_ST_GET_SERVER_FINISHED_B:
        str = "2GSF_B";
        break;
    case SSL2_ST_GET_CLIENT_HELLO_A:
        str = "2GCH_A";
        break;
    case SSL2_ST_GET_CLIENT_HELLO_B:
        str = "2GCH_B";
        break;
    case SSL2_ST_GET_CLIENT_HELLO_C:
        str = "2GCH_C";
        break;
    case SSL2_ST_SEND_SERVER_HELLO_A:
        str = "2SSH_A";
        break;
    case SSL2_ST_SEND_SERVER_HELLO_B:
        str = "2SSH_B";
        break;
    case SSL2_ST_GET_CLIENT_MASTER_KEY_A:
        str = "2GCMKA";
        break;
    case SSL2_ST_GET_CLIENT_MASTER_KEY_B:
        str = "2GCMKA";
        break;
    case SSL2_ST_SEND_SERVER_VERIFY_A:
        str = "2SSV_A";
        break;
    case SSL2_ST_SEND_SERVER_VERIFY_B:
        str = "2SSV_B";
        break;
    case SSL2_ST_SEND_SERVER_VERIFY_C:
        str = "2SSV_C";
        break;
    case SSL2_ST_GET_CLIENT_FINISHED_A:
        str = "2GCF_A";
        break;
    case SSL2_ST_GET_CLIENT_FINISHED_B:
        str = "2GCF_B";
        break;
    case SSL2_ST_SEND_SERVER_FINISHED_A:
        str = "2SSF_A";
        break;
    case SSL2_ST_SEND_SERVER_FINISHED_B:
        str = "2SSF_B";
        break;
    case SSL2_ST_SEND_REQUEST_CERTIFICATE_A:
        str = "2SRC_A";
        break;
    case SSL2_ST_SEND_REQUEST_CERTIFICATE_B:
        str = "2SRC_B";
        break;
    case SSL2_ST_SEND_REQUEST_CERTIFICATE_C:
        str = "2SRC_C";
        break;
    case SSL2_ST_SEND_REQUEST_CERTIFICATE_D:
        str = "2SRC_D";
        break;
    case SSL2_ST_X509_GET_SERVER_CERTIFICATE:
        str = "2X9GSC";
        break;
    case SSL2_ST_X509_GET_CLIENT_CERTIFICATE:
        str = "2X9GCC";
        break;
#endif

#ifndef OPENSSL_NO_SSL3
/* SSLv3 additions */
    case SSL3_ST_SW_FLUSH:
    case SSL3_ST_CW_FLUSH:
        str = "3FLUSH";
        break;
    case SSL3_ST_CW_CLNT_HELLO_A:
        str = "3WCH_A";
        break;
    case SSL3_ST_CW_CLNT_HELLO_B:
        str = "3WCH_B";
        break;
    case SSL3_ST_CR_SRVR_HELLO_A:
        str = "3RSH_A";
        break;
    case SSL3_ST_CR_SRVR_HELLO_B:
        str = "3RSH_B";
        break;
    case SSL3_ST_CR_CERT_A:
        str = "3RSC_A";
        break;
    case SSL3_ST_CR_CERT_B:
        str = "3RSC_B";
        break;
    case SSL3_ST_CR_KEY_EXCH_A:
        str = "3RSKEA";
        break;
    case SSL3_ST_CR_KEY_EXCH_B:
        str = "3RSKEB";
        break;
    case SSL3_ST_CR_CERT_REQ_A:
        str = "3RCR_A";
        break;
    case SSL3_ST_CR_CERT_REQ_B:
        str = "3RCR_B";
        break;
    case SSL3_ST_CR_SRVR_DONE_A:
        str = "3RSD_A";
        break;
    case SSL3_ST_CR_SRVR_DONE_B:
        str = "3RSD_B";
        break;
    case SSL3_ST_CW_CERT_A:
        str = "3WCC_A";
        break;
    case SSL3_ST_CW_CERT_B:
        str = "3WCC_B";
        break;
    case SSL3_ST_CW_CERT_C:
        str = "3WCC_C";
        break;
    case SSL3_ST_CW_CERT_D:
        str = "3WCC_D";
        break;
    case SSL3_ST_CW_KEY_EXCH_A:
        str = "3WCKEA";
        break;
    case SSL3_ST_CW_KEY_EXCH_B:
        str = "3WCKEB";
        break;
    case SSL3_ST_CW_CERT_VRFY_A:
        str = "3WCV_A";
        break;
    case SSL3_ST_CW_CERT_VRFY_B:
        str = "3WCV_B";
        break;

    case SSL3_ST_SW_CHANGE_A:
    case SSL3_ST_CW_CHANGE_A:
        str = "3WCCSA";
        break;
    case SSL3_ST_SW_CHANGE_B:
    case SSL3_ST_CW_CHANGE_B:
        str = "3WCCSB";
        break;
    case SSL3_ST_SW_FINISHED_A:
    case SSL3_ST_CW_FINISHED_A:
        str = "3WFINA";
        break;
    case SSL3_ST_SW_FINISHED_B:
    case SSL3_ST_CW_FINISHED_B:
        str = "3WFINB";
        break;
    case SSL3_ST_SR_CHANGE_A:
    case SSL3_ST_CR_CHANGE_A:
        str = "3RCCSA";
        break;
    case SSL3_ST_SR_CHANGE_B:
    case SSL3_ST_CR_CHANGE_B:
        str = "3RCCSB";
        break;
    case SSL3_ST_SR_FINISHED_A:
    case SSL3_ST_CR_FINISHED_A:
        str = "3RFINA";
        break;
    case SSL3_ST_SR_FINISHED_B:
    case SSL3_ST_CR_FINISHED_B:
        str = "3RFINB";
        break;

    case SSL3_ST_SW_HELLO_REQ_A:
        str = "3WHR_A";
        break;
    case SSL3_ST_SW_HELLO_REQ_B:
        str = "3WHR_B";
        break;
    case SSL3_ST_SW_HELLO_REQ_C:
        str = "3WHR_C";
        break;
    case SSL3_ST_SR_CLNT_HELLO_A:
        str = "3RCH_A";
        break;
    case SSL3_ST_SR_CLNT_HELLO_B:
        str = "3RCH_B";
        break;
    case SSL3_ST_SR_CLNT_HELLO_C:
        str = "3RCH_C";
        break;
    case SSL3_ST_SW_SRVR_HELLO_A:
        str = "3WSH_A";
        break;
    case SSL3_ST_SW_SRVR_HELLO_B:
        str = "3WSH_B";
        break;
    case SSL3_ST_SW_CERT_A:
        str = "3WSC_A";
        break;
    case SSL3_ST_SW_CERT_B:
        str = "3WSC_B";
        break;
    case SSL3_ST_SW_KEY_EXCH_A:
        str = "3WSKEA";
        break;
    case SSL3_ST_SW_KEY_EXCH_B:
        str = "3WSKEB";
        break;
    case SSL3_ST_SW_CERT_REQ_A:
        str = "3WCR_A";
        break;
    case SSL3_ST_SW_CERT_REQ_B:
        str = "3WCR_B";
        break;
    case SSL3_ST_SW_SRVR_DONE_A:
        str = "3WSD_A";
        break;
    case SSL3_ST_SW_SRVR_DONE_B:
        str = "3WSD_B";
        break;
    case SSL3_ST_SR_CERT_A:
        str = "3RCC_A";
        break;
    case SSL3_ST_SR_CERT_B:
        str = "3RCC_B";
        break;
    case SSL3_ST_SR_KEY_EXCH_A:
        str = "3RCKEA";
        break;
    case SSL3_ST_SR_KEY_EXCH_B:
        str = "3RCKEB";
        break;
    case SSL3_ST_SR_CERT_VRFY_A:
        str = "3RCV_A";
        break;
    case SSL3_ST_SR_CERT_VRFY_B:
        str = "3RCV_B";
        break;
#endif

/* SSLv2/v3 compatibility states */
/* client */
    case SSL23_ST_CW_CLNT_HELLO_A:
        str = "23WCHA";
        break;
    case SSL23_ST_CW_CLNT_HELLO_B:
        str = "23WCHB";
        break;
    case SSL23_ST_CR_SRVR_HELLO_A:
        str = "23RSHA";
        break;
    case SSL23_ST_CR_SRVR_HELLO_B:
        str = "23RSHA";
        break;
/* server */
    case SSL23_ST_SR_CLNT_HELLO_A:
        str = "23RCHA";
        break;
    case SSL23_ST_SR_CLNT_HELLO_B:
        str = "23RCHB";
        break;

/* DTLS */
    case DTLS1_ST_CR_HELLO_VERIFY_REQUEST_A:
        str = "DRCHVA";
        break;
    case DTLS1_ST_CR_HELLO_VERIFY_REQUEST_B:
        str = "DRCHVB";
        break;
    case DTLS1_ST_SW_HELLO_VERIFY_REQUEST_A:
        str = "DWCHVA";
        break;
    case DTLS1_ST_SW_HELLO_VERIFY_REQUEST_B:
        str = "DWCHVB";
        break;

    default:
        str = "UNKWN ";
        break;
    }
    return (str);
}

const char *SSL_alert_type_string_long(int value)
{
    value >>= 8;
    if (value == SSL3_AL_WARNING)
        return ("warning");
    else if (value == SSL3_AL_FATAL)
        return ("fatal");
    else
        return ("unknown");
}

const char *SSL_alert_type_string(int value)
{
    value >>= 8;
    if (value == SSL3_AL_WARNING)
        return ("W");
    else if (value == SSL3_AL_FATAL)
        return ("F");
    else
        return ("U");
}

const char *SSL_alert_desc_string(int value)
{
    const char *str;

    switch (value & 0xff) {
    case SSL3_AD_CLOSE_NOTIFY:
        str = "CN";
        break;
    case SSL3_AD_UNEXPECTED_MESSAGE:
        str = "UM";
        break;
    case SSL3_AD_BAD_RECORD_MAC:
        str = "BM";
        break;
    case SSL3_AD_DECOMPRESSION_FAILURE:
        str = "DF";
        break;
    case SSL3_AD_HANDSHAKE_FAILURE:
        str = "HF";
        break;
    case SSL3_AD_NO_CERTIFICATE:
        str = "NC";
        break;
    case SSL3_AD_BAD_CERTIFICATE:
        str = "BC";
        break;
    case SSL3_AD_UNSUPPORTED_CERTIFICATE:
        str = "UC";
        break;
    case SSL3_AD_CERTIFICATE_REVOKED:
        str = "CR";
        break;
    case SSL3_AD_CERTIFICATE_EXPIRED:
        str = "CE";
        break;
    case SSL3_AD_CERTIFICATE_UNKNOWN:
        str = "CU";
        break;
    case SSL3_AD_ILLEGAL_PARAMETER:
        str = "IP";
        break;
    case TLS1_AD_DECRYPTION_FAILED:
        str = "DC";
        break;
    case TLS1_AD_RECORD_OVERFLOW:
        str = "RO";
        break;
    case TLS1_AD_UNKNOWN_CA:
        str = "CA";
        break;
    case TLS1_AD_ACCESS_DENIED:
        str = "AD";
        break;
    case TLS1_AD_DECODE_ERROR:
        str = "DE";
        break;
    case TLS1_AD_DECRYPT_ERROR:
        str = "CY";
        break;
    case TLS1_AD_EXPORT_RESTRICTION:
        str = "ER";
        break;
    case TLS1_AD_PROTOCOL_VERSION:
        str = "PV";
        break;
    case TLS1_AD_INSUFFICIENT_SECURITY:
        str = "IS";
        break;
    case TLS1_AD_INTERNAL_ERROR:
        str = "IE";
        break;
    case TLS1_AD_USER_CANCELLED:
        str = "US";
        break;
    case TLS1_AD_NO_RENEGOTIATION:
        str = "NR";
        break;
    case TLS1_AD_UNSUPPORTED_EXTENSION:
        str = "UE";
        break;
    case TLS1_AD_CERTIFICATE_UNOBTAINABLE:
        str = "CO";
        break;
    case TLS1_AD_UNRECOGNIZED_NAME:
        str = "UN";
        break;
    case TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE:
        str = "BR";
        break;
    case TLS1_AD_BAD_CERTIFICATE_HASH_VALUE:
        str = "BH";
        break;
    case TLS1_AD_UNKNOWN_PSK_IDENTITY:
        str = "UP";
        break;
    default:
        str = "UK";
        break;
    }
    return (str);
}

const char *SSL_alert_desc_string_long(int value)
{
    const char *str;

    switch (value & 0xff) {
    case SSL3_AD_CLOSE_NOTIFY:
        str = "close notify";
        break;
    case SSL3_AD_UNEXPECTED_MESSAGE:
        str = "unexpected_message";
        break;
    case SSL3_AD_BAD_RECORD_MAC:
        str = "bad record mac";
        break;
    case SSL3_AD_DECOMPRESSION_FAILURE:
        str = "decompression failure";
        break;
    case SSL3_AD_HANDSHAKE_FAILURE:
        str = "handshake failure";
        break;
    case SSL3_AD_NO_CERTIFICATE:
        str = "no certificate";
        break;
    case SSL3_AD_BAD_CERTIFICATE:
        str = "bad certificate";
        break;
    case SSL3_AD_UNSUPPORTED_CERTIFICATE:
        str = "unsupported certificate";
        break;
    case SSL3_AD_CERTIFICATE_REVOKED:
        str = "certificate revoked";
        break;
    case SSL3_AD_CERTIFICATE_EXPIRED:
        str = "certificate expired";
        break;
    case SSL3_AD_CERTIFICATE_UNKNOWN:
        str = "certificate unknown";
        break;
    case SSL3_AD_ILLEGAL_PARAMETER:
        str = "illegal parameter";
        break;
    case TLS1_AD_DECRYPTION_FAILED:
        str = "decryption failed";
        break;
    case TLS1_AD_RECORD_OVERFLOW:
        str = "record overflow";
        break;
    case TLS1_AD_UNKNOWN_CA:
        str = "unknown CA";
        break;
    case TLS1_AD_ACCESS_DENIED:
        str = "access denied";
        break;
    case TLS1_AD_DECODE_ERROR:
        str = "decode error";
        break;
    case TLS1_AD_DECRYPT_ERROR:
        str = "decrypt error";
        break;
    case TLS1_AD_EXPORT_RESTRICTION:
        str = "export restriction";
        break;
    case TLS1_AD_PROTOCOL_VERSION:
        str = "protocol version";
        break;
    case TLS1_AD_INSUFFICIENT_SECURITY:
        str = "insufficient security";
        break;
    case TLS1_AD_INTERNAL_ERROR:
        str = "internal error";
        break;
    case TLS1_AD_USER_CANCELLED:
        str = "user canceled";
        break;
    case TLS1_AD_NO_RENEGOTIATION:
        str = "no renegotiation";
        break;
    case TLS1_AD_UNSUPPORTED_EXTENSION:
        str = "unsupported extension";
        break;
    case TLS1_AD_CERTIFICATE_UNOBTAINABLE:
        str = "certificate unobtainable";
        break;
    case TLS1_AD_UNRECOGNIZED_NAME:
        str = "unrecognized name";
        break;
    case TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE:
        str = "bad certificate status response";
        break;
    case TLS1_AD_BAD_CERTIFICATE_HASH_VALUE:
        str = "bad certificate hash value";
        break;
    case TLS1_AD_UNKNOWN_PSK_IDENTITY:
        str = "unknown PSK identity";
        break;
    default:
        str = "unknown";
        break;
    }
    return (str);
}

const char *SSL_rstate_string(const SSL *s)
{
    const char *str;

    switch (s->rstate) {
    case SSL_ST_READ_HEADER:
        str = "RH";
        break;
    case SSL_ST_READ_BODY:
        str = "RB";
        break;
    case SSL_ST_READ_DONE:
        str = "RD";
        break;
    default:
        str = "unknown";
        break;
    }
    return (str);
}
/* ssl/ssl_txt.c */
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
#include "buffer.h"
// #include "ssl_locl.h"

#ifndef OPENSSL_NO_FP_API
int SSL_SESSION_print_fp(FILE *fp, const SSL_SESSION *x)
{
    BIO *b;
    int ret;

    if ((b = BIO_new(BIO_s_file_internal())) == NULL) {
        SSLerr(SSL_F_SSL_SESSION_PRINT_FP, ERR_R_BUF_LIB);
        return (0);
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = SSL_SESSION_print(b, x);
    BIO_free(b);
    return (ret);
}
#endif

int SSL_SESSION_print(BIO *bp, const SSL_SESSION *x)
{
    unsigned int i;
    const char *s;

    if (x == NULL)
        goto err;
    if (BIO_puts(bp, "SSL-Session:\n") <= 0)
        goto err;
    if (x->ssl_version == SSL2_VERSION)
        s = "SSLv2";
    else if (x->ssl_version == SSL3_VERSION)
        s = "SSLv3";
    else if (x->ssl_version == TLS1_2_VERSION)
        s = "TLSv1.2";
    else if (x->ssl_version == TLS1_1_VERSION)
        s = "TLSv1.1";
    else if (x->ssl_version == TLS1_VERSION)
        s = "TLSv1";
    else if (x->ssl_version == DTLS1_VERSION)
        s = "DTLSv1";
    else if (x->ssl_version == DTLS1_2_VERSION)
        s = "DTLSv1.2";
    else if (x->ssl_version == DTLS1_BAD_VER)
        s = "DTLSv1-bad";
    else
        s = "unknown";
    if (BIO_printf(bp, "    Protocol  : %s\n", s) <= 0)
        goto err;

    if (x->cipher == NULL) {
        if (((x->cipher_id) & 0xff000000) == 0x02000000) {
            if (BIO_printf
                (bp, "    Cipher    : %06lX\n", x->cipher_id & 0xffffff) <= 0)
                goto err;
        } else {
            if (BIO_printf
                (bp, "    Cipher    : %04lX\n", x->cipher_id & 0xffff) <= 0)
                goto err;
        }
    } else {
        if (BIO_printf
            (bp, "    Cipher    : %s\n",
             ((x->cipher == NULL) ? "unknown" : x->cipher->name)) <= 0)
            goto err;
    }
    if (BIO_puts(bp, "    Session-ID: ") <= 0)
        goto err;
    for (i = 0; i < x->session_id_length; i++) {
        if (BIO_printf(bp, "%02X", x->session_id[i]) <= 0)
            goto err;
    }
    if (BIO_puts(bp, "\n    Session-ID-ctx: ") <= 0)
        goto err;
    for (i = 0; i < x->sid_ctx_length; i++) {
        if (BIO_printf(bp, "%02X", x->sid_ctx[i]) <= 0)
            goto err;
    }
    if (BIO_puts(bp, "\n    Master-Key: ") <= 0)
        goto err;
    for (i = 0; i < (unsigned int)x->master_key_length; i++) {
        if (BIO_printf(bp, "%02X", x->master_key[i]) <= 0)
            goto err;
    }
    if (BIO_puts(bp, "\n    Key-Arg   : ") <= 0)
        goto err;
    if (x->key_arg_length == 0) {
        if (BIO_puts(bp, "None") <= 0)
            goto err;
    } else
        for (i = 0; i < x->key_arg_length; i++) {
            if (BIO_printf(bp, "%02X", x->key_arg[i]) <= 0)
                goto err;
        }
#ifndef OPENSSL_NO_KRB5
    if (BIO_puts(bp, "\n    Krb5 Principal: ") <= 0)
        goto err;
    if (x->krb5_client_princ_len == 0) {
        if (BIO_puts(bp, "None") <= 0)
            goto err;
    } else
        for (i = 0; i < x->krb5_client_princ_len; i++) {
            if (BIO_printf(bp, "%02X", x->krb5_client_princ[i]) <= 0)
                goto err;
        }
#endif                          /* OPENSSL_NO_KRB5 */
#ifndef OPENSSL_NO_PSK
    if (BIO_puts(bp, "\n    PSK identity: ") <= 0)
        goto err;
    if (BIO_printf(bp, "%s", x->psk_identity ? x->psk_identity : "None") <= 0)
        goto err;
    if (BIO_puts(bp, "\n    PSK identity hint: ") <= 0)
        goto err;
    if (BIO_printf
        (bp, "%s", x->psk_identity_hint ? x->psk_identity_hint : "None") <= 0)
        goto err;
#endif
#ifndef OPENSSL_NO_SRP
    if (BIO_puts(bp, "\n    SRP username: ") <= 0)
        goto err;
    if (BIO_printf(bp, "%s", x->srp_username ? x->srp_username : "None") <= 0)
        goto err;
#endif
#ifndef OPENSSL_NO_TLSEXT
    if (x->tlsext_tick_lifetime_hint) {
        if (BIO_printf(bp,
                       "\n    TLS session ticket lifetime hint: %ld (seconds)",
                       x->tlsext_tick_lifetime_hint) <= 0)
            goto err;
    }
    if (x->tlsext_tick) {
        if (BIO_puts(bp, "\n    TLS session ticket:\n") <= 0)
            goto err;
        if (BIO_dump_indent(bp, (char *)x->tlsext_tick, x->tlsext_ticklen, 4)
            <= 0)
            goto err;
    }
#endif

#ifndef OPENSSL_NO_COMP
    if (x->compress_meth != 0) {
        SSL_COMP *comp = NULL;

        ssl_cipher_get_evp(x, NULL, NULL, NULL, NULL, &comp);
        if (comp == NULL) {
            if (BIO_printf(bp, "\n    Compression: %d", x->compress_meth) <=
                0)
                goto err;
        } else {
            if (BIO_printf
                (bp, "\n    Compression: %d (%s)", comp->id,
                 comp->method->name) <= 0)
                goto err;
        }
    }
#endif
    if (x->time != 0L) {
        if (BIO_printf(bp, "\n    Start Time: %ld", x->time) <= 0)
            goto err;
    }
    if (x->timeout != 0L) {
        if (BIO_printf(bp, "\n    Timeout   : %ld (sec)", x->timeout) <= 0)
            goto err;
    }
    if (BIO_puts(bp, "\n") <= 0)
        goto err;

    if (BIO_puts(bp, "    Verify return code: ") <= 0)
        goto err;
    if (BIO_printf(bp, "%ld (%s)\n", x->verify_result,
                   X509_verify_cert_error_string(x->verify_result)) <= 0)
        goto err;

    return (1);
 err:
    return (0);
}
/* ssl_utst.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 2014 The OpenSSL Project.  All rights reserved.
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
 */

// #include "ssl_locl.h"

#ifndef OPENSSL_NO_UNIT_TEST

static const struct openssl_ssl_test_functions ssl_test_functions = {
    ssl_init_wbio_buffer,
    ssl3_setup_buffers,
    tls1_process_heartbeat,
    dtls1_process_heartbeat
};

const struct openssl_ssl_test_functions *SSL_test_functions(void)
{
    return &ssl_test_functions;
}

#endif
