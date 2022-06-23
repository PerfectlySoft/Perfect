/* crypto/err/err_all.c */
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
#include "asn1.h"
#include "bn.h"
#ifndef OPENSSL_NO_EC
# include "ec.h"
#endif
#include "buffer.h"
#include "bio.h"
#ifndef OPENSSL_NO_COMP
# include "comp.h"
#endif
#ifndef OPENSSL_NO_RSA
# include "rsa.h"
#endif
#ifndef OPENSSL_NO_DH
# include "dh.h"
#endif
#ifndef OPENSSL_NO_DSA
# include "dsa.h"
#endif
#ifndef OPENSSL_NO_ECDSA
# include "ecdsa.h"
#endif
#ifndef OPENSSL_NO_ECDH
# include "ecdh.h"
#endif
#include "evp.h"
#include "objects.h"
#include "pem2.h"
#include "x509.h"
#include "x509v3.h"
#include "conf.h"
#include "pkcs12.h"
#include "rand.h"
#include "dso.h"
#ifndef OPENSSL_NO_ENGINE
# include "engine.h"
#endif
#include "ui.h"
#include "ocsp.h"
#include "err.h"
#ifdef OPENSSL_FIPS
# include <fips.h>
#endif
#include "ts.h"
#ifndef OPENSSL_NO_CMS
# include "cms.h"
#endif
#ifndef OPENSSL_NO_JPAKE
# include <jpake.h>
#endif

void ERR_load_crypto_strings(void)
{
#ifndef OPENSSL_NO_ERR
    ERR_load_ERR_strings();     /* include error strings for SYSerr */
    ERR_load_BN_strings();
# ifndef OPENSSL_NO_RSA
    ERR_load_RSA_strings();
# endif
# ifndef OPENSSL_NO_DH
    ERR_load_DH_strings();
# endif
    ERR_load_EVP_strings();
    ERR_load_BUF_strings();
    ERR_load_OBJ_strings();
    ERR_load_PEM_strings();
# ifndef OPENSSL_NO_DSA
    ERR_load_DSA_strings();
# endif
    ERR_load_X509_strings();
    ERR_load_ASN1_strings();
    ERR_load_CONF_strings();
    ERR_load_CRYPTO_strings();
# ifndef OPENSSL_NO_COMP
    ERR_load_COMP_strings();
# endif
# ifndef OPENSSL_NO_EC
    ERR_load_EC_strings();
# endif
# ifndef OPENSSL_NO_ECDSA
    ERR_load_ECDSA_strings();
# endif
# ifndef OPENSSL_NO_ECDH
    ERR_load_ECDH_strings();
# endif
    /* skip ERR_load_SSL_strings() because it is not in this library */
    ERR_load_BIO_strings();
    ERR_load_PKCS7_strings();
    ERR_load_X509V3_strings();
    ERR_load_PKCS12_strings();
    ERR_load_RAND_strings();
    ERR_load_DSO_strings();
    ERR_load_TS_strings();
# ifndef OPENSSL_NO_ENGINE
    ERR_load_ENGINE_strings();
# endif
    ERR_load_OCSP_strings();
    ERR_load_UI_strings();
# ifdef OPENSSL_FIPS
    ERR_load_FIPS_strings();
# endif
# ifndef OPENSSL_NO_CMS
    ERR_load_CMS_strings();
# endif
# ifndef OPENSSL_NO_JPAKE
    ERR_load_JPAKE_strings();
# endif
#endif
}
/* crypto/err/err_prn.c */
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
#include "lhash.h"
#include "crypto.h"
// #include "buffer.h"
// #include "err.h"

void ERR_print_errors_cb(int (*cb) (const char *str, size_t len, void *u),
                         void *u)
{
    unsigned long l;
    char buf[256];
    char buf2[4096];
    const char *file, *data;
    int line, flags;
    unsigned long es;
    CRYPTO_THREADID cur;

    CRYPTO_THREADID_current(&cur);
    es = CRYPTO_THREADID_hash(&cur);
    while ((l = ERR_get_error_line_data(&file, &line, &data, &flags)) != 0) {
        ERR_error_string_n(l, buf, sizeof(buf));
        BIO_snprintf(buf2, sizeof(buf2), "%lu:%s:%s:%d:%s\n", es, buf,
                     file, line, (flags & ERR_TXT_STRING) ? data : "");
        if (cb(buf2, strlen(buf2), u) <= 0)
            break;              /* abort outputting the error report */
    }
}

#ifndef OPENSSL_NO_FP_API
static int print_fp(const char *str, size_t len, void *fp)
{
    BIO bio;

    BIO_set(&bio, BIO_s_file());
    BIO_set_fp(&bio, fp, BIO_NOCLOSE);

    return BIO_printf(&bio, "%s", str);
}

void ERR_print_errors_fp(FILE *fp)
{
    ERR_print_errors_cb(print_fp, fp);
}
#endif

static int print_bio(const char *str, size_t len, void *bp)
{
    return BIO_write((BIO *)bp, str, len);
}

void ERR_print_errors(BIO *bp)
{
    ERR_print_errors_cb(print_bio, bp);
}
