/* crypto/evp/c_all.c */
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
#include "evp.h"
#ifndef OPENSSL_NO_ENGINE
# include "engine.h"
#endif

#if 0
# undef OpenSSL_add_all_algorithms

void OpenSSL_add_all_algorithms(void)
{
    OPENSSL_add_all_algorithms_noconf();
}
#endif

void OPENSSL_add_all_algorithms_noconf(void)
{
    /*
     * For the moment OPENSSL_cpuid_setup does something
     * only on IA-32, but we reserve the option for all
     * platforms...
     */
    OPENSSL_cpuid_setup();
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();
}
/* crypto/evp/c_allc.c */
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
// #include "evp.h"
#include "pkcs12.h"
#include "objects.h"

void OpenSSL_add_all_ciphers(void)
{

#ifndef OPENSSL_NO_DES
    EVP_add_cipher(EVP_des_cfb());
    EVP_add_cipher(EVP_des_cfb1());
    EVP_add_cipher(EVP_des_cfb8());
    EVP_add_cipher(EVP_des_ede_cfb());
    EVP_add_cipher(EVP_des_ede3_cfb());
    EVP_add_cipher(EVP_des_ede3_cfb1());
    EVP_add_cipher(EVP_des_ede3_cfb8());

    EVP_add_cipher(EVP_des_ofb());
    EVP_add_cipher(EVP_des_ede_ofb());
    EVP_add_cipher(EVP_des_ede3_ofb());

    EVP_add_cipher(EVP_desx_cbc());
    EVP_add_cipher_alias(SN_desx_cbc, "DESX");
    EVP_add_cipher_alias(SN_desx_cbc, "desx");

    EVP_add_cipher(EVP_des_cbc());
    EVP_add_cipher_alias(SN_des_cbc, "DES");
    EVP_add_cipher_alias(SN_des_cbc, "des");
    EVP_add_cipher(EVP_des_ede_cbc());
    EVP_add_cipher(EVP_des_ede3_cbc());
    EVP_add_cipher_alias(SN_des_ede3_cbc, "DES3");
    EVP_add_cipher_alias(SN_des_ede3_cbc, "des3");

    EVP_add_cipher(EVP_des_ecb());
    EVP_add_cipher(EVP_des_ede());
    EVP_add_cipher(EVP_des_ede3());
    EVP_add_cipher(EVP_des_ede3_wrap());
#endif

#ifndef OPENSSL_NO_RC4
    EVP_add_cipher(EVP_rc4());
    EVP_add_cipher(EVP_rc4_40());
# ifndef OPENSSL_NO_MD5
    EVP_add_cipher(EVP_rc4_hmac_md5());
# endif
#endif

#ifndef OPENSSL_NO_IDEA
    EVP_add_cipher(EVP_idea_ecb());
    EVP_add_cipher(EVP_idea_cfb());
    EVP_add_cipher(EVP_idea_ofb());
    EVP_add_cipher(EVP_idea_cbc());
    EVP_add_cipher_alias(SN_idea_cbc, "IDEA");
    EVP_add_cipher_alias(SN_idea_cbc, "idea");
#endif

#ifndef OPENSSL_NO_SEED
    EVP_add_cipher(EVP_seed_ecb());
    EVP_add_cipher(EVP_seed_cfb());
    EVP_add_cipher(EVP_seed_ofb());
    EVP_add_cipher(EVP_seed_cbc());
    EVP_add_cipher_alias(SN_seed_cbc, "SEED");
    EVP_add_cipher_alias(SN_seed_cbc, "seed");
#endif

#ifndef OPENSSL_NO_RC2
    EVP_add_cipher(EVP_rc2_ecb());
    EVP_add_cipher(EVP_rc2_cfb());
    EVP_add_cipher(EVP_rc2_ofb());
    EVP_add_cipher(EVP_rc2_cbc());
    EVP_add_cipher(EVP_rc2_40_cbc());
    EVP_add_cipher(EVP_rc2_64_cbc());
    EVP_add_cipher_alias(SN_rc2_cbc, "RC2");
    EVP_add_cipher_alias(SN_rc2_cbc, "rc2");
#endif

#ifndef OPENSSL_NO_BF
    EVP_add_cipher(EVP_bf_ecb());
    EVP_add_cipher(EVP_bf_cfb());
    EVP_add_cipher(EVP_bf_ofb());
    EVP_add_cipher(EVP_bf_cbc());
    EVP_add_cipher_alias(SN_bf_cbc, "BF");
    EVP_add_cipher_alias(SN_bf_cbc, "bf");
    EVP_add_cipher_alias(SN_bf_cbc, "blowfish");
#endif

#ifndef OPENSSL_NO_CAST
    EVP_add_cipher(EVP_cast5_ecb());
    EVP_add_cipher(EVP_cast5_cfb());
    EVP_add_cipher(EVP_cast5_ofb());
    EVP_add_cipher(EVP_cast5_cbc());
    EVP_add_cipher_alias(SN_cast5_cbc, "CAST");
    EVP_add_cipher_alias(SN_cast5_cbc, "cast");
    EVP_add_cipher_alias(SN_cast5_cbc, "CAST-cbc");
    EVP_add_cipher_alias(SN_cast5_cbc, "cast-cbc");
#endif

#ifndef OPENSSL_NO_RC5
    EVP_add_cipher(EVP_rc5_32_12_16_ecb());
    EVP_add_cipher(EVP_rc5_32_12_16_cfb());
    EVP_add_cipher(EVP_rc5_32_12_16_ofb());
    EVP_add_cipher(EVP_rc5_32_12_16_cbc());
    EVP_add_cipher_alias(SN_rc5_cbc, "rc5");
    EVP_add_cipher_alias(SN_rc5_cbc, "RC5");
#endif

#ifndef OPENSSL_NO_AES
    EVP_add_cipher(EVP_aes_128_ecb());
    EVP_add_cipher(EVP_aes_128_cbc());
    EVP_add_cipher(EVP_aes_128_cfb());
    EVP_add_cipher(EVP_aes_128_cfb1());
    EVP_add_cipher(EVP_aes_128_cfb8());
    EVP_add_cipher(EVP_aes_128_ofb());
    EVP_add_cipher(EVP_aes_128_ctr());
    EVP_add_cipher(EVP_aes_128_gcm());
    EVP_add_cipher(EVP_aes_128_xts());
    EVP_add_cipher(EVP_aes_128_ccm());
    EVP_add_cipher(EVP_aes_128_wrap());
    EVP_add_cipher_alias(SN_aes_128_cbc, "AES128");
    EVP_add_cipher_alias(SN_aes_128_cbc, "aes128");
    EVP_add_cipher(EVP_aes_192_ecb());
    EVP_add_cipher(EVP_aes_192_cbc());
    EVP_add_cipher(EVP_aes_192_cfb());
    EVP_add_cipher(EVP_aes_192_cfb1());
    EVP_add_cipher(EVP_aes_192_cfb8());
    EVP_add_cipher(EVP_aes_192_ofb());
    EVP_add_cipher(EVP_aes_192_ctr());
    EVP_add_cipher(EVP_aes_192_gcm());
    EVP_add_cipher(EVP_aes_192_ccm());
    EVP_add_cipher(EVP_aes_192_wrap());
    EVP_add_cipher_alias(SN_aes_192_cbc, "AES192");
    EVP_add_cipher_alias(SN_aes_192_cbc, "aes192");
    EVP_add_cipher(EVP_aes_256_ecb());
    EVP_add_cipher(EVP_aes_256_cbc());
    EVP_add_cipher(EVP_aes_256_cfb());
    EVP_add_cipher(EVP_aes_256_cfb1());
    EVP_add_cipher(EVP_aes_256_cfb8());
    EVP_add_cipher(EVP_aes_256_ofb());
    EVP_add_cipher(EVP_aes_256_ctr());
    EVP_add_cipher(EVP_aes_256_gcm());
    EVP_add_cipher(EVP_aes_256_xts());
    EVP_add_cipher(EVP_aes_256_ccm());
    EVP_add_cipher(EVP_aes_256_wrap());
    EVP_add_cipher_alias(SN_aes_256_cbc, "AES256");
    EVP_add_cipher_alias(SN_aes_256_cbc, "aes256");
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
    EVP_add_cipher(EVP_camellia_128_ecb());
    EVP_add_cipher(EVP_camellia_128_cbc());
    EVP_add_cipher(EVP_camellia_128_cfb());
    EVP_add_cipher(EVP_camellia_128_cfb1());
    EVP_add_cipher(EVP_camellia_128_cfb8());
    EVP_add_cipher(EVP_camellia_128_ofb());
    EVP_add_cipher_alias(SN_camellia_128_cbc, "CAMELLIA128");
    EVP_add_cipher_alias(SN_camellia_128_cbc, "camellia128");
    EVP_add_cipher(EVP_camellia_192_ecb());
    EVP_add_cipher(EVP_camellia_192_cbc());
    EVP_add_cipher(EVP_camellia_192_cfb());
    EVP_add_cipher(EVP_camellia_192_cfb1());
    EVP_add_cipher(EVP_camellia_192_cfb8());
    EVP_add_cipher(EVP_camellia_192_ofb());
    EVP_add_cipher_alias(SN_camellia_192_cbc, "CAMELLIA192");
    EVP_add_cipher_alias(SN_camellia_192_cbc, "camellia192");
    EVP_add_cipher(EVP_camellia_256_ecb());
    EVP_add_cipher(EVP_camellia_256_cbc());
    EVP_add_cipher(EVP_camellia_256_cfb());
    EVP_add_cipher(EVP_camellia_256_cfb1());
    EVP_add_cipher(EVP_camellia_256_cfb8());
    EVP_add_cipher(EVP_camellia_256_ofb());
    EVP_add_cipher_alias(SN_camellia_256_cbc, "CAMELLIA256");
    EVP_add_cipher_alias(SN_camellia_256_cbc, "camellia256");
#endif
}
/* crypto/evp/c_alld.c */
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
// #include "evp.h"
// #include "pkcs12.h"
// #include "objects.h"

void OpenSSL_add_all_digests(void)
{
#ifndef OPENSSL_NO_MD4
    EVP_add_digest(EVP_md4());
#endif
#ifndef OPENSSL_NO_MD5
    EVP_add_digest(EVP_md5());
    EVP_add_digest_alias(SN_md5, "ssl2-md5");
    EVP_add_digest_alias(SN_md5, "ssl3-md5");
#endif
#if !defined(OPENSSL_NO_SHA) && !defined(OPENSSL_NO_SHA0)
    EVP_add_digest(EVP_sha());
# ifndef OPENSSL_NO_DSA
    EVP_add_digest(EVP_dss());
# endif
#endif
#if !defined(OPENSSL_NO_SHA) && !defined(OPENSSL_NO_SHA1)
    EVP_add_digest(EVP_sha1());
    EVP_add_digest_alias(SN_sha1, "ssl3-sha1");
    EVP_add_digest_alias(SN_sha1WithRSAEncryption, SN_sha1WithRSA);
# ifndef OPENSSL_NO_DSA
    EVP_add_digest(EVP_dss1());
    EVP_add_digest_alias(SN_dsaWithSHA1, SN_dsaWithSHA1_2);
    EVP_add_digest_alias(SN_dsaWithSHA1, "DSS1");
    EVP_add_digest_alias(SN_dsaWithSHA1, "dss1");
# endif
# ifndef OPENSSL_NO_ECDSA
    EVP_add_digest(EVP_ecdsa());
# endif
#endif
#if !defined(OPENSSL_NO_MDC2) && !defined(OPENSSL_NO_DES)
    EVP_add_digest(EVP_mdc2());
#endif
#ifndef OPENSSL_NO_RIPEMD
    EVP_add_digest(EVP_ripemd160());
    EVP_add_digest_alias(SN_ripemd160, "ripemd");
    EVP_add_digest_alias(SN_ripemd160, "rmd160");
#endif
#ifndef OPENSSL_NO_SHA256
    EVP_add_digest(EVP_sha224());
    EVP_add_digest(EVP_sha256());
#endif
#ifndef OPENSSL_NO_SHA512
    EVP_add_digest(EVP_sha384());
    EVP_add_digest(EVP_sha512());
#endif
#ifndef OPENSSL_NO_WHIRLPOOL
    EVP_add_digest(EVP_whirlpool());
#endif
}
/* crypto/cast/c_cfb64.c */
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

#include "cast.h"
#include "cast_lcl.h"

/*
 * The input and output encrypted as though 64bit cfb mode is being used.
 * The extra state information to record how much of the 64bit block we have
 * used is contained in *num;
 */

void CAST_cfb64_encrypt(const unsigned char *in, unsigned char *out,
                        long length, const CAST_KEY *schedule,
                        unsigned char *ivec, int *num, int enc)
{
    register CAST_LONG v0, v1, t;
    register int n = *num;
    register long l = length;
    CAST_LONG ti[2];
    unsigned char *iv, c, cc;

    iv = ivec;
    if (enc) {
        while (l--) {
            if (n == 0) {
                n2l(iv, v0);
                ti[0] = v0;
                n2l(iv, v1);
                ti[1] = v1;
                CAST_encrypt((CAST_LONG *)ti, schedule);
                iv = ivec;
                t = ti[0];
                l2n(t, iv);
                t = ti[1];
                l2n(t, iv);
                iv = ivec;
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
                CAST_encrypt((CAST_LONG *)ti, schedule);
                iv = ivec;
                t = ti[0];
                l2n(t, iv);
                t = ti[1];
                l2n(t, iv);
                iv = ivec;
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
/* crypto/cast/c_ecb.c */
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

// #include "cast.h"
// #include "cast_lcl.h"
#include "opensslv.h"

const char CAST_version[] = "CAST" OPENSSL_VERSION_PTEXT;

void CAST_ecb_encrypt(const unsigned char *in, unsigned char *out,
                      const CAST_KEY *ks, int enc)
{
    CAST_LONG l, d[2];

    n2l(in, l);
    d[0] = l;
    n2l(in, l);
    d[1] = l;
    if (enc)
        CAST_encrypt(d, ks);
    else
        CAST_decrypt(d, ks);
    l = d[0];
    l2n(l, out);
    l = d[1];
    l2n(l, out);
    l = d[0] = d[1] = 0;
}
/* crypto/cast/c_enc.c */
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

// #include "cast.h"
// #include "cast_lcl.h"

void CAST_encrypt(CAST_LONG *data, const CAST_KEY *key)
{
    register CAST_LONG l, r, t;
    const register CAST_LONG *k;

    k = &(key->data[0]);
    l = data[0];
    r = data[1];

    E_CAST(0, k, l, r, +, ^, -);
    E_CAST(1, k, r, l, ^, -, +);
    E_CAST(2, k, l, r, -, +, ^);
    E_CAST(3, k, r, l, +, ^, -);
    E_CAST(4, k, l, r, ^, -, +);
    E_CAST(5, k, r, l, -, +, ^);
    E_CAST(6, k, l, r, +, ^, -);
    E_CAST(7, k, r, l, ^, -, +);
    E_CAST(8, k, l, r, -, +, ^);
    E_CAST(9, k, r, l, +, ^, -);
    E_CAST(10, k, l, r, ^, -, +);
    E_CAST(11, k, r, l, -, +, ^);
    if (!key->short_key) {
        E_CAST(12, k, l, r, +, ^, -);
        E_CAST(13, k, r, l, ^, -, +);
        E_CAST(14, k, l, r, -, +, ^);
        E_CAST(15, k, r, l, +, ^, -);
    }

    data[1] = l & 0xffffffffL;
    data[0] = r & 0xffffffffL;
}

void CAST_decrypt(CAST_LONG *data, const CAST_KEY *key)
{
    register CAST_LONG l, r, t;
    const register CAST_LONG *k;

    k = &(key->data[0]);
    l = data[0];
    r = data[1];

    if (!key->short_key) {
        E_CAST(15, k, l, r, +, ^, -);
        E_CAST(14, k, r, l, -, +, ^);
        E_CAST(13, k, l, r, ^, -, +);
        E_CAST(12, k, r, l, +, ^, -);
    }
    E_CAST(11, k, l, r, -, +, ^);
    E_CAST(10, k, r, l, ^, -, +);
    E_CAST(9, k, l, r, +, ^, -);
    E_CAST(8, k, r, l, -, +, ^);
    E_CAST(7, k, l, r, ^, -, +);
    E_CAST(6, k, r, l, +, ^, -);
    E_CAST(5, k, l, r, -, +, ^);
    E_CAST(4, k, r, l, ^, -, +);
    E_CAST(3, k, l, r, +, ^, -);
    E_CAST(2, k, r, l, -, +, ^);
    E_CAST(1, k, l, r, ^, -, +);
    E_CAST(0, k, r, l, +, ^, -);

    data[1] = l & 0xffffffffL;
    data[0] = r & 0xffffffffL;
}

void CAST_cbc_encrypt(const unsigned char *in, unsigned char *out,
                      long length, const CAST_KEY *ks, unsigned char *iv,
                      int enc)
{
    register CAST_LONG tin0, tin1;
    register CAST_LONG tout0, tout1, xor0, xor1;
    register long l = length;
    CAST_LONG tin[2];

    if (enc) {
        n2l(iv, tout0);
        n2l(iv, tout1);
        iv -= 8;
        for (l -= 8; l >= 0; l -= 8) {
            n2l(in, tin0);
            n2l(in, tin1);
            tin0 ^= tout0;
            tin1 ^= tout1;
            tin[0] = tin0;
            tin[1] = tin1;
            CAST_encrypt(tin, ks);
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
            CAST_encrypt(tin, ks);
            tout0 = tin[0];
            tout1 = tin[1];
            l2n(tout0, out);
            l2n(tout1, out);
        }
        l2n(tout0, iv);
        l2n(tout1, iv);
    } else {
        n2l(iv, xor0);
        n2l(iv, xor1);
        iv -= 8;
        for (l -= 8; l >= 0; l -= 8) {
            n2l(in, tin0);
            n2l(in, tin1);
            tin[0] = tin0;
            tin[1] = tin1;
            CAST_decrypt(tin, ks);
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
            CAST_decrypt(tin, ks);
            tout0 = tin[0] ^ xor0;
            tout1 = tin[1] ^ xor1;
            l2nn(tout0, tout1, out, l + 8);
            xor0 = tin0;
            xor1 = tin1;
        }
        l2n(xor0, iv);
        l2n(xor1, iv);
    }
    tin0 = tin1 = tout0 = tout1 = xor0 = xor1 = 0;
    tin[0] = tin[1] = 0;
}
/* crypto/cast/c_ofb64.c */
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

// #include "cast.h"
// #include "cast_lcl.h"

/*
 * The input and output encrypted as though 64bit ofb mode is being used.
 * The extra state information to record how much of the 64bit block we have
 * used is contained in *num;
 */
void CAST_ofb64_encrypt(const unsigned char *in, unsigned char *out,
                        long length, const CAST_KEY *schedule,
                        unsigned char *ivec, int *num)
{
    register CAST_LONG v0, v1, t;
    register int n = *num;
    register long l = length;
    unsigned char d[8];
    register char *dp;
    CAST_LONG ti[2];
    unsigned char *iv;
    int save = 0;

    iv = ivec;
    n2l(iv, v0);
    n2l(iv, v1);
    ti[0] = v0;
    ti[1] = v1;
    dp = (char *)d;
    l2n(v0, dp);
    l2n(v1, dp);
    while (l--) {
        if (n == 0) {
            CAST_encrypt((CAST_LONG *)ti, schedule);
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
        iv = ivec;
        l2n(v0, iv);
        l2n(v1, iv);
    }
    t = v0 = v1 = ti[0] = ti[1] = 0;
    *num = n;
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// #include "objects.h"
#include "comp.h"

static int rle_compress_block(COMP_CTX *ctx, unsigned char *out,
                              unsigned int olen, unsigned char *in,
                              unsigned int ilen);
static int rle_expand_block(COMP_CTX *ctx, unsigned char *out,
                            unsigned int olen, unsigned char *in,
                            unsigned int ilen);

static COMP_METHOD rle_method = {
    NID_rle_compression,
    LN_rle_compression,
    NULL,
    NULL,
    rle_compress_block,
    rle_expand_block,
    NULL,
    NULL,
};

COMP_METHOD *COMP_rle(void)
{
    return (&rle_method);
}

static int rle_compress_block(COMP_CTX *ctx, unsigned char *out,
                              unsigned int olen, unsigned char *in,
                              unsigned int ilen)
{
    if (ilen == 0)
        return 0;

    if (olen <= ilen)
        return -1;

    *(out++) = 0;
    memcpy(out, in, ilen);
    return (ilen + 1);
}

static int rle_expand_block(COMP_CTX *ctx, unsigned char *out,
                            unsigned int olen, unsigned char *in,
                            unsigned int ilen)
{
    int i;

    if (ilen == 0)
        return 0;

    if (olen < (ilen - 1))
        return -1;

    i = *(in++);
    if (i != 0)
        return -1;

    memcpy(out, in, ilen - 1);
    return (ilen - 1);
}
/* crypto/cast/c_skey.c */
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

#include "crypto.h"
// #include "cast.h"
// #include "cast_lcl.h"
#include "cast_s.h"

#define CAST_exp(l,A,a,n) \
        A[n/4]=l; \
        a[n+3]=(l    )&0xff; \
        a[n+2]=(l>> 8)&0xff; \
        a[n+1]=(l>>16)&0xff; \
        a[n+0]=(l>>24)&0xff;

#define S4 CAST_S_table4
#define S5 CAST_S_table5
#define S6 CAST_S_table6
#define S7 CAST_S_table7
void CAST_set_key(CAST_KEY *key, int len, const unsigned char *data)
#ifdef OPENSSL_FIPS
{
    fips_cipher_abort(CAST);
    private_CAST_set_key(key, len, data);
}

void private_CAST_set_key(CAST_KEY *key, int len, const unsigned char *data)
#endif
{
    CAST_LONG x[16];
    CAST_LONG z[16];
    CAST_LONG k[32];
    CAST_LONG X[4], Z[4];
    CAST_LONG l, *K;
    int i;

    for (i = 0; i < 16; i++)
        x[i] = 0;
    if (len > 16)
        len = 16;
    for (i = 0; i < len; i++)
        x[i] = data[i];
    if (len <= 10)
        key->short_key = 1;
    else
        key->short_key = 0;

    K = &k[0];
    X[0] = ((x[0] << 24) | (x[1] << 16) | (x[2] << 8) | x[3]) & 0xffffffffL;
    X[1] = ((x[4] << 24) | (x[5] << 16) | (x[6] << 8) | x[7]) & 0xffffffffL;
    X[2] = ((x[8] << 24) | (x[9] << 16) | (x[10] << 8) | x[11]) & 0xffffffffL;
    X[3] =
        ((x[12] << 24) | (x[13] << 16) | (x[14] << 8) | x[15]) & 0xffffffffL;

    for (;;) {
        l = X[0] ^ S4[x[13]] ^ S5[x[15]] ^ S6[x[12]] ^ S7[x[14]] ^ S6[x[8]];
        CAST_exp(l, Z, z, 0);
        l = X[2] ^ S4[z[0]] ^ S5[z[2]] ^ S6[z[1]] ^ S7[z[3]] ^ S7[x[10]];
        CAST_exp(l, Z, z, 4);
        l = X[3] ^ S4[z[7]] ^ S5[z[6]] ^ S6[z[5]] ^ S7[z[4]] ^ S4[x[9]];
        CAST_exp(l, Z, z, 8);
        l = X[1] ^ S4[z[10]] ^ S5[z[9]] ^ S6[z[11]] ^ S7[z[8]] ^ S5[x[11]];
        CAST_exp(l, Z, z, 12);

        K[0] = S4[z[8]] ^ S5[z[9]] ^ S6[z[7]] ^ S7[z[6]] ^ S4[z[2]];
        K[1] = S4[z[10]] ^ S5[z[11]] ^ S6[z[5]] ^ S7[z[4]] ^ S5[z[6]];
        K[2] = S4[z[12]] ^ S5[z[13]] ^ S6[z[3]] ^ S7[z[2]] ^ S6[z[9]];
        K[3] = S4[z[14]] ^ S5[z[15]] ^ S6[z[1]] ^ S7[z[0]] ^ S7[z[12]];

        l = Z[2] ^ S4[z[5]] ^ S5[z[7]] ^ S6[z[4]] ^ S7[z[6]] ^ S6[z[0]];
        CAST_exp(l, X, x, 0);
        l = Z[0] ^ S4[x[0]] ^ S5[x[2]] ^ S6[x[1]] ^ S7[x[3]] ^ S7[z[2]];
        CAST_exp(l, X, x, 4);
        l = Z[1] ^ S4[x[7]] ^ S5[x[6]] ^ S6[x[5]] ^ S7[x[4]] ^ S4[z[1]];
        CAST_exp(l, X, x, 8);
        l = Z[3] ^ S4[x[10]] ^ S5[x[9]] ^ S6[x[11]] ^ S7[x[8]] ^ S5[z[3]];
        CAST_exp(l, X, x, 12);

        K[4] = S4[x[3]] ^ S5[x[2]] ^ S6[x[12]] ^ S7[x[13]] ^ S4[x[8]];
        K[5] = S4[x[1]] ^ S5[x[0]] ^ S6[x[14]] ^ S7[x[15]] ^ S5[x[13]];
        K[6] = S4[x[7]] ^ S5[x[6]] ^ S6[x[8]] ^ S7[x[9]] ^ S6[x[3]];
        K[7] = S4[x[5]] ^ S5[x[4]] ^ S6[x[10]] ^ S7[x[11]] ^ S7[x[7]];

        l = X[0] ^ S4[x[13]] ^ S5[x[15]] ^ S6[x[12]] ^ S7[x[14]] ^ S6[x[8]];
        CAST_exp(l, Z, z, 0);
        l = X[2] ^ S4[z[0]] ^ S5[z[2]] ^ S6[z[1]] ^ S7[z[3]] ^ S7[x[10]];
        CAST_exp(l, Z, z, 4);
        l = X[3] ^ S4[z[7]] ^ S5[z[6]] ^ S6[z[5]] ^ S7[z[4]] ^ S4[x[9]];
        CAST_exp(l, Z, z, 8);
        l = X[1] ^ S4[z[10]] ^ S5[z[9]] ^ S6[z[11]] ^ S7[z[8]] ^ S5[x[11]];
        CAST_exp(l, Z, z, 12);

        K[8] = S4[z[3]] ^ S5[z[2]] ^ S6[z[12]] ^ S7[z[13]] ^ S4[z[9]];
        K[9] = S4[z[1]] ^ S5[z[0]] ^ S6[z[14]] ^ S7[z[15]] ^ S5[z[12]];
        K[10] = S4[z[7]] ^ S5[z[6]] ^ S6[z[8]] ^ S7[z[9]] ^ S6[z[2]];
        K[11] = S4[z[5]] ^ S5[z[4]] ^ S6[z[10]] ^ S7[z[11]] ^ S7[z[6]];

        l = Z[2] ^ S4[z[5]] ^ S5[z[7]] ^ S6[z[4]] ^ S7[z[6]] ^ S6[z[0]];
        CAST_exp(l, X, x, 0);
        l = Z[0] ^ S4[x[0]] ^ S5[x[2]] ^ S6[x[1]] ^ S7[x[3]] ^ S7[z[2]];
        CAST_exp(l, X, x, 4);
        l = Z[1] ^ S4[x[7]] ^ S5[x[6]] ^ S6[x[5]] ^ S7[x[4]] ^ S4[z[1]];
        CAST_exp(l, X, x, 8);
        l = Z[3] ^ S4[x[10]] ^ S5[x[9]] ^ S6[x[11]] ^ S7[x[8]] ^ S5[z[3]];
        CAST_exp(l, X, x, 12);

        K[12] = S4[x[8]] ^ S5[x[9]] ^ S6[x[7]] ^ S7[x[6]] ^ S4[x[3]];
        K[13] = S4[x[10]] ^ S5[x[11]] ^ S6[x[5]] ^ S7[x[4]] ^ S5[x[7]];
        K[14] = S4[x[12]] ^ S5[x[13]] ^ S6[x[3]] ^ S7[x[2]] ^ S6[x[8]];
        K[15] = S4[x[14]] ^ S5[x[15]] ^ S6[x[1]] ^ S7[x[0]] ^ S7[x[13]];
        if (K != k)
            break;
        K += 16;
    }

    for (i = 0; i < 16; i++) {
        key->data[i * 2] = k[i];
        key->data[i * 2 + 1] = ((k[i + 16]) + 16) & 0x1f;
    }
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// #include "objects.h"
// #include "comp.h"
#include "err.h"

COMP_METHOD *COMP_zlib(void);

static COMP_METHOD zlib_method_nozlib = {
    NID_undef,
    "(undef)",
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
};

#ifndef ZLIB
# undef ZLIB_SHARED
#else

# include <zlib.h>

static int zlib_stateful_init(COMP_CTX *ctx);
static void zlib_stateful_finish(COMP_CTX *ctx);
static int zlib_stateful_compress_block(COMP_CTX *ctx, unsigned char *out,
                                        unsigned int olen, unsigned char *in,
                                        unsigned int ilen);
static int zlib_stateful_expand_block(COMP_CTX *ctx, unsigned char *out,
                                      unsigned int olen, unsigned char *in,
                                      unsigned int ilen);

/* memory allocations functions for zlib intialization */
static void *zlib_zalloc(void *opaque, unsigned int no, unsigned int size)
{
    void *p;

    p = OPENSSL_malloc(no * size);
    if (p)
        memset(p, 0, no * size);
    return p;
}

static void zlib_zfree(void *opaque, void *address)
{
    OPENSSL_free(address);
}

# if 0
static int zlib_compress_block(COMP_CTX *ctx, unsigned char *out,
                               unsigned int olen, unsigned char *in,
                               unsigned int ilen);
static int zlib_expand_block(COMP_CTX *ctx, unsigned char *out,
                             unsigned int olen, unsigned char *in,
                             unsigned int ilen);

static int zz_uncompress(Bytef *dest, uLongf * destLen, const Bytef *source,
                         uLong sourceLen);

static COMP_METHOD zlib_stateless_method = {
    NID_zlib_compression,
    LN_zlib_compression,
    NULL,
    NULL,
    zlib_compress_block,
    zlib_expand_block,
    NULL,
    NULL,
};
# endif

static COMP_METHOD zlib_stateful_method = {
    NID_zlib_compression,
    LN_zlib_compression,
    zlib_stateful_init,
    zlib_stateful_finish,
    zlib_stateful_compress_block,
    zlib_stateful_expand_block,
    NULL,
    NULL,
};

/*
 * When OpenSSL is built on Windows, we do not want to require that
 * the ZLIB.DLL be available in order for the OpenSSL DLLs to
 * work.  Therefore, all ZLIB routines are loaded at run time
 * and we do not link to a .LIB file when ZLIB_SHARED is set.
 */
# if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_WIN32)
#  include <windows.h>
# endif                         /* !(OPENSSL_SYS_WINDOWS ||
                                 * OPENSSL_SYS_WIN32) */

# ifdef ZLIB_SHARED
#  include "dso.h"

/* Function pointers */
typedef int (*compress_ft) (Bytef *dest, uLongf * destLen,
                            const Bytef *source, uLong sourceLen);
typedef int (*inflateEnd_ft) (z_streamp strm);
typedef int (*inflate_ft) (z_streamp strm, int flush);
typedef int (*inflateInit__ft) (z_streamp strm,
                                const char *version, int stream_size);
typedef int (*deflateEnd_ft) (z_streamp strm);
typedef int (*deflate_ft) (z_streamp strm, int flush);
typedef int (*deflateInit__ft) (z_streamp strm, int level,
                                const char *version, int stream_size);
typedef const char *(*zError__ft) (int err);
static compress_ft p_compress = NULL;
static inflateEnd_ft p_inflateEnd = NULL;
static inflate_ft p_inflate = NULL;
static inflateInit__ft p_inflateInit_ = NULL;
static deflateEnd_ft p_deflateEnd = NULL;
static deflate_ft p_deflate = NULL;
static deflateInit__ft p_deflateInit_ = NULL;
static zError__ft p_zError = NULL;

static int zlib_loaded = 0;     /* only attempt to init func pts once */
static DSO *zlib_dso = NULL;

#  define compress                p_compress
#  define inflateEnd              p_inflateEnd
#  define inflate                 p_inflate
#  define inflateInit_            p_inflateInit_
#  define deflateEnd              p_deflateEnd
#  define deflate                 p_deflate
#  define deflateInit_            p_deflateInit_
#  define zError                  p_zError
# endif                         /* ZLIB_SHARED */

struct zlib_state {
    z_stream istream;
    z_stream ostream;
};

static int zlib_stateful_ex_idx = -1;

static int zlib_stateful_init(COMP_CTX *ctx)
{
    int err;
    struct zlib_state *state =
        (struct zlib_state *)OPENSSL_malloc(sizeof(struct zlib_state));

    if (state == NULL)
        goto err;

    state->istream.zalloc = zlib_zalloc;
    state->istream.zfree = zlib_zfree;
    state->istream.opaque = Z_NULL;
    state->istream.next_in = Z_NULL;
    state->istream.next_out = Z_NULL;
    state->istream.avail_in = 0;
    state->istream.avail_out = 0;
    err = inflateInit_(&state->istream, ZLIB_VERSION, sizeof(z_stream));
    if (err != Z_OK)
        goto err;

    state->ostream.zalloc = zlib_zalloc;
    state->ostream.zfree = zlib_zfree;
    state->ostream.opaque = Z_NULL;
    state->ostream.next_in = Z_NULL;
    state->ostream.next_out = Z_NULL;
    state->ostream.avail_in = 0;
    state->ostream.avail_out = 0;
    err = deflateInit_(&state->ostream, Z_DEFAULT_COMPRESSION,
                       ZLIB_VERSION, sizeof(z_stream));
    if (err != Z_OK)
        goto err;

    CRYPTO_new_ex_data(CRYPTO_EX_INDEX_COMP, ctx, &ctx->ex_data);
    CRYPTO_set_ex_data(&ctx->ex_data, zlib_stateful_ex_idx, state);
    return 1;
 err:
    if (state)
        OPENSSL_free(state);
    return 0;
}

static void zlib_stateful_finish(COMP_CTX *ctx)
{
    struct zlib_state *state =
        (struct zlib_state *)CRYPTO_get_ex_data(&ctx->ex_data,
                                                zlib_stateful_ex_idx);
    inflateEnd(&state->istream);
    deflateEnd(&state->ostream);
    OPENSSL_free(state);
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_COMP, ctx, &ctx->ex_data);
}

static int zlib_stateful_compress_block(COMP_CTX *ctx, unsigned char *out,
                                        unsigned int olen, unsigned char *in,
                                        unsigned int ilen)
{
    int err = Z_OK;
    struct zlib_state *state =
        (struct zlib_state *)CRYPTO_get_ex_data(&ctx->ex_data,
                                                zlib_stateful_ex_idx);

    if (state == NULL)
        return -1;

    state->ostream.next_in = in;
    state->ostream.avail_in = ilen;
    state->ostream.next_out = out;
    state->ostream.avail_out = olen;
    if (ilen > 0)
        err = deflate(&state->ostream, Z_SYNC_FLUSH);
    if (err != Z_OK)
        return -1;
# ifdef DEBUG_ZLIB
    fprintf(stderr, "compress(%4d)->%4d %s\n",
            ilen, olen - state->ostream.avail_out,
            (ilen != olen - state->ostream.avail_out) ? "zlib" : "clear");
# endif
    return olen - state->ostream.avail_out;
}

static int zlib_stateful_expand_block(COMP_CTX *ctx, unsigned char *out,
                                      unsigned int olen, unsigned char *in,
                                      unsigned int ilen)
{
    int err = Z_OK;

    struct zlib_state *state =
        (struct zlib_state *)CRYPTO_get_ex_data(&ctx->ex_data,
                                                zlib_stateful_ex_idx);

    if (state == NULL)
        return 0;

    state->istream.next_in = in;
    state->istream.avail_in = ilen;
    state->istream.next_out = out;
    state->istream.avail_out = olen;
    if (ilen > 0)
        err = inflate(&state->istream, Z_SYNC_FLUSH);
    if (err != Z_OK)
        return -1;
# ifdef DEBUG_ZLIB
    fprintf(stderr, "expand(%4d)->%4d %s\n",
            ilen, olen - state->istream.avail_out,
            (ilen != olen - state->istream.avail_out) ? "zlib" : "clear");
# endif
    return olen - state->istream.avail_out;
}

# if 0
static int zlib_compress_block(COMP_CTX *ctx, unsigned char *out,
                               unsigned int olen, unsigned char *in,
                               unsigned int ilen)
{
    unsigned long l;
    int i;
    int clear = 1;

    if (ilen > 128) {
        out[0] = 1;
        l = olen - 1;
        i = compress(&(out[1]), &l, in, (unsigned long)ilen);
        if (i != Z_OK)
            return (-1);
        if (ilen > l) {
            clear = 0;
            l++;
        }
    }
    if (clear) {
        out[0] = 0;
        memcpy(&(out[1]), in, ilen);
        l = ilen + 1;
    }
#  ifdef DEBUG_ZLIB
    fprintf(stderr, "compress(%4d)->%4d %s\n",
            ilen, (int)l, (clear) ? "clear" : "zlib");
#  endif
    return ((int)l);
}

static int zlib_expand_block(COMP_CTX *ctx, unsigned char *out,
                             unsigned int olen, unsigned char *in,
                             unsigned int ilen)
{
    unsigned long l;
    int i;

    if (in[0]) {
        l = olen;
        i = zz_uncompress(out, &l, &(in[1]), (unsigned long)ilen - 1);
        if (i != Z_OK)
            return (-1);
    } else {
        memcpy(out, &(in[1]), ilen - 1);
        l = ilen - 1;
    }
#  ifdef DEBUG_ZLIB
    fprintf(stderr, "expand  (%4d)->%4d %s\n",
            ilen, (int)l, in[0] ? "zlib" : "clear");
#  endif
    return ((int)l);
}

static int zz_uncompress(Bytef *dest, uLongf * destLen, const Bytef *source,
                         uLong sourceLen)
{
    z_stream stream;
    int err;

    stream.next_in = (Bytef *)source;
    stream.avail_in = (uInt) sourceLen;
    /* Check for source > 64K on 16-bit machine: */
    if ((uLong) stream.avail_in != sourceLen)
        return Z_BUF_ERROR;

    stream.next_out = dest;
    stream.avail_out = (uInt) * destLen;
    if ((uLong) stream.avail_out != *destLen)
        return Z_BUF_ERROR;

    stream.zalloc = (alloc_func) 0;
    stream.zfree = (free_func) 0;

    err = inflateInit_(&stream, ZLIB_VERSION, sizeof(z_stream));
    if (err != Z_OK)
        return err;

    err = inflate(&stream, Z_FINISH);
    if (err != Z_STREAM_END) {
        inflateEnd(&stream);
        return err;
    }
    *destLen = stream.total_out;

    err = inflateEnd(&stream);
    return err;
}
# endif

#endif

COMP_METHOD *COMP_zlib(void)
{
    COMP_METHOD *meth = &zlib_method_nozlib;

#ifdef ZLIB_SHARED
    if (!zlib_loaded) {
# if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_WIN32)
        zlib_dso = DSO_load(NULL, "ZLIB1", NULL, 0);
# else
        zlib_dso = DSO_load(NULL, "z", NULL, 0);
# endif
        if (zlib_dso != NULL) {
            p_compress = (compress_ft) DSO_bind_func(zlib_dso, "compress");
            p_inflateEnd
                = (inflateEnd_ft) DSO_bind_func(zlib_dso, "inflateEnd");
            p_inflate = (inflate_ft) DSO_bind_func(zlib_dso, "inflate");
            p_inflateInit_
                = (inflateInit__ft) DSO_bind_func(zlib_dso, "inflateInit_");
            p_deflateEnd
                = (deflateEnd_ft) DSO_bind_func(zlib_dso, "deflateEnd");
            p_deflate = (deflate_ft) DSO_bind_func(zlib_dso, "deflate");
            p_deflateInit_
                = (deflateInit__ft) DSO_bind_func(zlib_dso, "deflateInit_");
            p_zError = (zError__ft) DSO_bind_func(zlib_dso, "zError");

            if (p_compress && p_inflateEnd && p_inflate
                && p_inflateInit_ && p_deflateEnd
                && p_deflate && p_deflateInit_ && p_zError)
                zlib_loaded++;
        }
    }
#endif
#ifdef ZLIB_SHARED
    if (zlib_loaded)
#endif
#if defined(ZLIB) || defined(ZLIB_SHARED)
    {
        /*
         * init zlib_stateful_ex_idx here so that in a multi-process
         * application it's enough to intialize openssl before forking (idx
         * will be inherited in all the children)
         */
        if (zlib_stateful_ex_idx == -1) {
            CRYPTO_w_lock(CRYPTO_LOCK_COMP);
            if (zlib_stateful_ex_idx == -1)
                zlib_stateful_ex_idx =
                    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_COMP,
                                            0, NULL, NULL, NULL, NULL);
            CRYPTO_w_unlock(CRYPTO_LOCK_COMP);
            if (zlib_stateful_ex_idx == -1)
                goto err;
        }

        meth = &zlib_stateful_method;
    }
 err:
#endif

    return (meth);
}

void COMP_zlib_cleanup(void)
{
#ifdef ZLIB_SHARED
    if (zlib_dso != NULL)
        DSO_free(zlib_dso);
    zlib_dso = NULL;
#endif
}

#ifdef ZLIB

/* Zlib based compression/decompression filter BIO */

typedef struct {
    unsigned char *ibuf;        /* Input buffer */
    int ibufsize;               /* Buffer size */
    z_stream zin;               /* Input decompress context */
    unsigned char *obuf;        /* Output buffer */
    int obufsize;               /* Output buffer size */
    unsigned char *optr;        /* Position in output buffer */
    int ocount;                 /* Amount of data in output buffer */
    int odone;                  /* deflate EOF */
    int comp_level;             /* Compression level to use */
    z_stream zout;              /* Output compression context */
} BIO_ZLIB_CTX;

# define ZLIB_DEFAULT_BUFSIZE 1024

static int bio_zlib_new(BIO *bi);
static int bio_zlib_free(BIO *bi);
static int bio_zlib_read(BIO *b, char *out, int outl);
static int bio_zlib_write(BIO *b, const char *in, int inl);
static long bio_zlib_ctrl(BIO *b, int cmd, long num, void *ptr);
static long bio_zlib_callback_ctrl(BIO *b, int cmd, bio_info_cb *fp);

static BIO_METHOD bio_meth_zlib = {
    BIO_TYPE_COMP,
    "zlib",
    bio_zlib_write,
    bio_zlib_read,
    NULL,
    NULL,
    bio_zlib_ctrl,
    bio_zlib_new,
    bio_zlib_free,
    bio_zlib_callback_ctrl
};

BIO_METHOD *BIO_f_zlib(void)
{
    return &bio_meth_zlib;
}

static int bio_zlib_new(BIO *bi)
{
    BIO_ZLIB_CTX *ctx;
# ifdef ZLIB_SHARED
    (void)COMP_zlib();
    if (!zlib_loaded) {
        COMPerr(COMP_F_BIO_ZLIB_NEW, COMP_R_ZLIB_NOT_SUPPORTED);
        return 0;
    }
# endif
    ctx = OPENSSL_malloc(sizeof(BIO_ZLIB_CTX));
    if (!ctx) {
        COMPerr(COMP_F_BIO_ZLIB_NEW, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    ctx->ibuf = NULL;
    ctx->obuf = NULL;
    ctx->ibufsize = ZLIB_DEFAULT_BUFSIZE;
    ctx->obufsize = ZLIB_DEFAULT_BUFSIZE;
    ctx->zin.zalloc = Z_NULL;
    ctx->zin.zfree = Z_NULL;
    ctx->zin.next_in = NULL;
    ctx->zin.avail_in = 0;
    ctx->zin.next_out = NULL;
    ctx->zin.avail_out = 0;
    ctx->zout.zalloc = Z_NULL;
    ctx->zout.zfree = Z_NULL;
    ctx->zout.next_in = NULL;
    ctx->zout.avail_in = 0;
    ctx->zout.next_out = NULL;
    ctx->zout.avail_out = 0;
    ctx->odone = 0;
    ctx->comp_level = Z_DEFAULT_COMPRESSION;
    bi->init = 1;
    bi->ptr = (char *)ctx;
    bi->flags = 0;
    return 1;
}

static int bio_zlib_free(BIO *bi)
{
    BIO_ZLIB_CTX *ctx;
    if (!bi)
        return 0;
    ctx = (BIO_ZLIB_CTX *) bi->ptr;
    if (ctx->ibuf) {
        /* Destroy decompress context */
        inflateEnd(&ctx->zin);
        OPENSSL_free(ctx->ibuf);
    }
    if (ctx->obuf) {
        /* Destroy compress context */
        deflateEnd(&ctx->zout);
        OPENSSL_free(ctx->obuf);
    }
    OPENSSL_free(ctx);
    bi->ptr = NULL;
    bi->init = 0;
    bi->flags = 0;
    return 1;
}

static int bio_zlib_read(BIO *b, char *out, int outl)
{
    BIO_ZLIB_CTX *ctx;
    int ret;
    z_stream *zin;
    if (!out || !outl)
        return 0;
    ctx = (BIO_ZLIB_CTX *) b->ptr;
    zin = &ctx->zin;
    BIO_clear_retry_flags(b);
    if (!ctx->ibuf) {
        ctx->ibuf = OPENSSL_malloc(ctx->ibufsize);
        if (!ctx->ibuf) {
            COMPerr(COMP_F_BIO_ZLIB_READ, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        inflateInit(zin);
        zin->next_in = ctx->ibuf;
        zin->avail_in = 0;
    }

    /* Copy output data directly to supplied buffer */
    zin->next_out = (unsigned char *)out;
    zin->avail_out = (unsigned int)outl;
    for (;;) {
        /* Decompress while data available */
        while (zin->avail_in) {
            ret = inflate(zin, 0);
            if ((ret != Z_OK) && (ret != Z_STREAM_END)) {
                COMPerr(COMP_F_BIO_ZLIB_READ, COMP_R_ZLIB_INFLATE_ERROR);
                ERR_add_error_data(2, "zlib error:", zError(ret));
                return 0;
            }
            /* If EOF or we've read everything then return */
            if ((ret == Z_STREAM_END) || !zin->avail_out)
                return outl - zin->avail_out;
        }

        /*
         * No data in input buffer try to read some in, if an error then
         * return the total data read.
         */
        ret = BIO_read(b->next_bio, ctx->ibuf, ctx->ibufsize);
        if (ret <= 0) {
            /* Total data read */
            int tot = outl - zin->avail_out;
            BIO_copy_next_retry(b);
            if (ret < 0)
                return (tot > 0) ? tot : ret;
            return tot;
        }
        zin->avail_in = ret;
        zin->next_in = ctx->ibuf;
    }
}

static int bio_zlib_write(BIO *b, const char *in, int inl)
{
    BIO_ZLIB_CTX *ctx;
    int ret;
    z_stream *zout;
    if (!in || !inl)
        return 0;
    ctx = (BIO_ZLIB_CTX *) b->ptr;
    if (ctx->odone)
        return 0;
    zout = &ctx->zout;
    BIO_clear_retry_flags(b);
    if (!ctx->obuf) {
        ctx->obuf = OPENSSL_malloc(ctx->obufsize);
        /* Need error here */
        if (!ctx->obuf) {
            COMPerr(COMP_F_BIO_ZLIB_WRITE, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        ctx->optr = ctx->obuf;
        ctx->ocount = 0;
        deflateInit(zout, ctx->comp_level);
        zout->next_out = ctx->obuf;
        zout->avail_out = ctx->obufsize;
    }
    /* Obtain input data directly from supplied buffer */
    zout->next_in = (void *)in;
    zout->avail_in = inl;
    for (;;) {
        /* If data in output buffer write it first */
        while (ctx->ocount) {
            ret = BIO_write(b->next_bio, ctx->optr, ctx->ocount);
            if (ret <= 0) {
                /* Total data written */
                int tot = inl - zout->avail_in;
                BIO_copy_next_retry(b);
                if (ret < 0)
                    return (tot > 0) ? tot : ret;
                return tot;
            }
            ctx->optr += ret;
            ctx->ocount -= ret;
        }

        /* Have we consumed all supplied data? */
        if (!zout->avail_in)
            return inl;

        /* Compress some more */

        /* Reset buffer */
        ctx->optr = ctx->obuf;
        zout->next_out = ctx->obuf;
        zout->avail_out = ctx->obufsize;
        /* Compress some more */
        ret = deflate(zout, 0);
        if (ret != Z_OK) {
            COMPerr(COMP_F_BIO_ZLIB_WRITE, COMP_R_ZLIB_DEFLATE_ERROR);
            ERR_add_error_data(2, "zlib error:", zError(ret));
            return 0;
        }
        ctx->ocount = ctx->obufsize - zout->avail_out;
    }
}

static int bio_zlib_flush(BIO *b)
{
    BIO_ZLIB_CTX *ctx;
    int ret;
    z_stream *zout;
    ctx = (BIO_ZLIB_CTX *) b->ptr;
    /* If no data written or already flush show success */
    if (!ctx->obuf || (ctx->odone && !ctx->ocount))
        return 1;
    zout = &ctx->zout;
    BIO_clear_retry_flags(b);
    /* No more input data */
    zout->next_in = NULL;
    zout->avail_in = 0;
    for (;;) {
        /* If data in output buffer write it first */
        while (ctx->ocount) {
            ret = BIO_write(b->next_bio, ctx->optr, ctx->ocount);
            if (ret <= 0) {
                BIO_copy_next_retry(b);
                return ret;
            }
            ctx->optr += ret;
            ctx->ocount -= ret;
        }
        if (ctx->odone)
            return 1;

        /* Compress some more */

        /* Reset buffer */
        ctx->optr = ctx->obuf;
        zout->next_out = ctx->obuf;
        zout->avail_out = ctx->obufsize;
        /* Compress some more */
        ret = deflate(zout, Z_FINISH);
        if (ret == Z_STREAM_END)
            ctx->odone = 1;
        else if (ret != Z_OK) {
            COMPerr(COMP_F_BIO_ZLIB_FLUSH, COMP_R_ZLIB_DEFLATE_ERROR);
            ERR_add_error_data(2, "zlib error:", zError(ret));
            return 0;
        }
        ctx->ocount = ctx->obufsize - zout->avail_out;
    }
}

static long bio_zlib_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    BIO_ZLIB_CTX *ctx;
    int ret, *ip;
    int ibs, obs;
    if (!b->next_bio)
        return 0;
    ctx = (BIO_ZLIB_CTX *) b->ptr;
    switch (cmd) {

    case BIO_CTRL_RESET:
        ctx->ocount = 0;
        ctx->odone = 0;
        ret = 1;
        break;

    case BIO_CTRL_FLUSH:
        ret = bio_zlib_flush(b);
        if (ret > 0)
            ret = BIO_flush(b->next_bio);
        break;

    case BIO_C_SET_BUFF_SIZE:
        ibs = -1;
        obs = -1;
        if (ptr != NULL) {
            ip = ptr;
            if (*ip == 0)
                ibs = (int)num;
            else
                obs = (int)num;
        } else {
            ibs = (int)num;
            obs = ibs;
        }

        if (ibs != -1) {
            if (ctx->ibuf) {
                OPENSSL_free(ctx->ibuf);
                ctx->ibuf = NULL;
            }
            ctx->ibufsize = ibs;
        }

        if (obs != -1) {
            if (ctx->obuf) {
                OPENSSL_free(ctx->obuf);
                ctx->obuf = NULL;
            }
            ctx->obufsize = obs;
        }
        ret = 1;
        break;

    case BIO_C_DO_STATE_MACHINE:
        BIO_clear_retry_flags(b);
        ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        BIO_copy_next_retry(b);
        break;

    default:
        ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        break;

    }

    return ret;
}

static long bio_zlib_callback_ctrl(BIO *b, int cmd, bio_info_cb *fp)
{
    if (!b->next_bio)
        return 0;
    return BIO_callback_ctrl(b->next_bio, cmd, fp);
}

#endif
