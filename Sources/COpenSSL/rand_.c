/* crypto/rand/rand_egd.c */
/* Written by Ulf Moeller and Lutz Jaenicke for the OpenSSL project. */
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

#include "e_os2.h"
#include "rand.h"
#include "buffer.h"

/*-
 * Query the EGD <URL: http://www.lothar.com/tech/crypto/>.
 *
 * This module supplies three routines:
 *
 * RAND_query_egd_bytes(path, buf, bytes)
 *   will actually query "bytes" bytes of entropy form the egd-socket located
 *   at path and will write them to buf (if supplied) or will directly feed
 *   it to RAND_seed() if buf==NULL.
 *   The number of bytes is not limited by the maximum chunk size of EGD,
 *   which is 255 bytes. If more than 255 bytes are wanted, several chunks
 *   of entropy bytes are requested. The connection is left open until the
 *   query is competed.
 *   RAND_query_egd_bytes() returns with
 *     -1  if an error occured during connection or communication.
 *     num the number of bytes read from the EGD socket. This number is either
 *         the number of bytes requested or smaller, if the EGD pool is
 *         drained and the daemon signals that the pool is empty.
 *   This routine does not touch any RAND_status(). This is necessary, since
 *   PRNG functions may call it during initialization.
 *
 * RAND_egd_bytes(path, bytes) will query "bytes" bytes and have them
 *   used to seed the PRNG.
 *   RAND_egd_bytes() is a wrapper for RAND_query_egd_bytes() with buf=NULL.
 *   Unlike RAND_query_egd_bytes(), RAND_status() is used to test the
 *   seed status so that the return value can reflect the seed state:
 *     -1  if an error occured during connection or communication _or_
 *         if the PRNG has still not received the required seeding.
 *     num the number of bytes read from the EGD socket. This number is either
 *         the number of bytes requested or smaller, if the EGD pool is
 *         drained and the daemon signals that the pool is empty.
 *
 * RAND_egd(path) will query 255 bytes and use the bytes retreived to seed
 *   the PRNG.
 *   RAND_egd() is a wrapper for RAND_egd_bytes() with numbytes=255.
 */

#if defined(OPENSSL_SYS_WIN32) || defined(OPENSSL_SYS_VMS) || defined(OPENSSL_SYS_MSDOS) || defined(OPENSSL_SYS_VXWORKS) || defined(OPENSSL_SYS_NETWARE) || defined(OPENSSL_SYS_VOS) || defined(OPENSSL_SYS_BEOS)
int RAND_query_egd_bytes(const char *path, unsigned char *buf, int bytes)
{
    return (-1);
}

int RAND_egd(const char *path)
{
    return (-1);
}

int RAND_egd_bytes(const char *path, int bytes)
{
    return (-1);
}
#else
# include "opensslconf.h"
# include OPENSSL_UNISTD
# include <stddef.h>
# include <sys/types.h>
# include <sys/socket.h>
# ifndef NO_SYS_UN_H
#  ifdef OPENSSL_SYS_VXWORKS
#   include <streams/un.h>
#  else
#   include <sys/un.h>
#  endif
# else
struct sockaddr_un {
    short sun_family;           /* AF_UNIX */
    char sun_path[108];         /* path name (gag) */
};
# endif                         /* NO_SYS_UN_H */
# include <string.h>
# include <errno.h>

# ifndef offsetof
#  define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
# endif

int RAND_query_egd_bytes(const char *path, unsigned char *buf, int bytes)
{
    int ret = 0;
    struct sockaddr_un addr;
    int len, num, numbytes;
    int fd = -1;
    int success;
    unsigned char egdbuf[2], tempbuf[255], *retrievebuf;

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(addr.sun_path))
        return (-1);
    BUF_strlcpy(addr.sun_path, path, sizeof(addr.sun_path));
    len = offsetof(struct sockaddr_un, sun_path) + strlen(path);
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1)
        return (-1);
    success = 0;
    while (!success) {
        if (connect(fd, (struct sockaddr *)&addr, len) == 0)
            success = 1;
        else {
            switch (errno) {
# ifdef EINTR
            case EINTR:
# endif
# ifdef EAGAIN
            case EAGAIN:
# endif
# ifdef EINPROGRESS
            case EINPROGRESS:
# endif
# ifdef EALREADY
            case EALREADY:
# endif
                /* No error, try again */
                break;
# ifdef EISCONN
            case EISCONN:
                success = 1;
                break;
# endif
            default:
                goto err;       /* failure */
            }
        }
    }

    while (bytes > 0) {
        egdbuf[0] = 1;
        egdbuf[1] = bytes < 255 ? bytes : 255;
        numbytes = 0;
        while (numbytes != 2) {
            num = write(fd, egdbuf + numbytes, 2 - numbytes);
            if (num >= 0)
                numbytes += num;
            else {
                switch (errno) {
# ifdef EINTR
                case EINTR:
# endif
# ifdef EAGAIN
                case EAGAIN:
# endif
                    /* No error, try again */
                    break;
                default:
                    ret = -1;
                    goto err;   /* failure */
                }
            }
        }
        numbytes = 0;
        while (numbytes != 1) {
            num = read(fd, egdbuf, 1);
            if (num == 0)
                goto err;       /* descriptor closed */
            else if (num > 0)
                numbytes += num;
            else {
                switch (errno) {
# ifdef EINTR
                case EINTR:
# endif
# ifdef EAGAIN
                case EAGAIN:
# endif
                    /* No error, try again */
                    break;
                default:
                    ret = -1;
                    goto err;   /* failure */
                }
            }
        }
        if (egdbuf[0] == 0)
            goto err;
        if (buf)
            retrievebuf = buf + ret;
        else
            retrievebuf = tempbuf;
        numbytes = 0;
        while (numbytes != egdbuf[0]) {
            num = read(fd, retrievebuf + numbytes, egdbuf[0] - numbytes);
            if (num == 0)
                goto err;       /* descriptor closed */
            else if (num > 0)
                numbytes += num;
            else {
                switch (errno) {
# ifdef EINTR
                case EINTR:
# endif
# ifdef EAGAIN
                case EAGAIN:
# endif
                    /* No error, try again */
                    break;
                default:
                    ret = -1;
                    goto err;   /* failure */
                }
            }
        }
        ret += egdbuf[0];
        bytes -= egdbuf[0];
        if (!buf)
            RAND_seed(tempbuf, egdbuf[0]);
    }
 err:
    if (fd != -1)
        close(fd);
    return (ret);
}

int RAND_egd_bytes(const char *path, int bytes)
{
    int num, ret = 0;

    num = RAND_query_egd_bytes(path, NULL, bytes);
    if (num < 1)
        goto err;
    if (RAND_status() == 1)
        ret = num;
 err:
    return (ret);
}

int RAND_egd(const char *path)
{
    return (RAND_egd_bytes(path, 255));
}

#endif
/* crypto/rand/rand_err.c */
/* ====================================================================
 * Copyright (c) 1999-2011 The OpenSSL Project.  All rights reserved.
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
// #include "rand.h"

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

# define ERR_FUNC(func) ERR_PACK(ERR_LIB_RAND,func,0)
# define ERR_REASON(reason) ERR_PACK(ERR_LIB_RAND,0,reason)

static ERR_STRING_DATA RAND_str_functs[] = {
    {ERR_FUNC(RAND_F_RAND_GET_RAND_METHOD), "RAND_get_rand_method"},
    {ERR_FUNC(RAND_F_RAND_INIT_FIPS), "RAND_init_fips"},
    {ERR_FUNC(RAND_F_SSLEAY_RAND_BYTES), "SSLEAY_RAND_BYTES"},
    {0, NULL}
};

static ERR_STRING_DATA RAND_str_reasons[] = {
    {ERR_REASON(RAND_R_DUAL_EC_DRBG_DISABLED), "dual ec drbg disabled"},
    {ERR_REASON(RAND_R_ERROR_INITIALISING_DRBG), "error initialising drbg"},
    {ERR_REASON(RAND_R_ERROR_INSTANTIATING_DRBG), "error instantiating drbg"},
    {ERR_REASON(RAND_R_NO_FIPS_RANDOM_METHOD_SET),
     "no fips random method set"},
    {ERR_REASON(RAND_R_PRNG_NOT_SEEDED), "PRNG not seeded"},
    {0, NULL}
};

#endif

void ERR_load_RAND_strings(void)
{
#ifndef OPENSSL_NO_ERR

    if (ERR_func_error_string(RAND_str_functs[0].error) == NULL) {
        ERR_load_strings(0, RAND_str_functs);
        ERR_load_strings(0, RAND_str_reasons);
    }
#endif
}
/* crypto/des/rand_key.c */
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

#include "des.h"
// #include "rand.h"

int DES_random_key(DES_cblock *ret)
{
    do {
        if (RAND_bytes((unsigned char *)ret, sizeof(DES_cblock)) != 1)
            return (0);
    } while (DES_is_weak_key(ret));
    DES_set_odd_parity(ret);
    return (1);
}
/* crypto/rand/rand_lib.c */
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
#include <time.h>
#include "cryptlib.h"
// #include "rand.h"

#ifndef OPENSSL_NO_ENGINE
# include "engine.h"
#endif

#ifdef OPENSSL_FIPS
# include <fips.h>
# include <fips_rand.h>
# include "rand_lcl.h"
#endif

#ifndef OPENSSL_NO_ENGINE
/* non-NULL if default_RAND_meth is ENGINE-provided */
static ENGINE *funct_ref = NULL;
#endif
static const RAND_METHOD *default_RAND_meth = NULL;

int RAND_set_rand_method(const RAND_METHOD *meth)
{
#ifndef OPENSSL_NO_ENGINE
    if (funct_ref) {
        ENGINE_finish(funct_ref);
        funct_ref = NULL;
    }
#endif
    default_RAND_meth = meth;
    return 1;
}

const RAND_METHOD *RAND_get_rand_method(void)
{
    if (!default_RAND_meth) {
#ifndef OPENSSL_NO_ENGINE
        ENGINE *e = ENGINE_get_default_RAND();
        if (e) {
            default_RAND_meth = ENGINE_get_RAND(e);
            if (!default_RAND_meth) {
                ENGINE_finish(e);
                e = NULL;
            }
        }
        if (e)
            funct_ref = e;
        else
#endif
            default_RAND_meth = RAND_SSLeay();
    }
    return default_RAND_meth;
}

#ifndef OPENSSL_NO_ENGINE
int RAND_set_rand_engine(ENGINE *engine)
{
    const RAND_METHOD *tmp_meth = NULL;
    if (engine) {
        if (!ENGINE_init(engine))
            return 0;
        tmp_meth = ENGINE_get_RAND(engine);
        if (!tmp_meth) {
            ENGINE_finish(engine);
            return 0;
        }
    }
    /* This function releases any prior ENGINE so call it first */
    RAND_set_rand_method(tmp_meth);
    funct_ref = engine;
    return 1;
}
#endif

void RAND_cleanup(void)
{
    const RAND_METHOD *meth = RAND_get_rand_method();
    if (meth && meth->cleanup)
        meth->cleanup();
    RAND_set_rand_method(NULL);
}

void RAND_seed(const void *buf, int num)
{
    const RAND_METHOD *meth = RAND_get_rand_method();
    if (meth && meth->seed)
        meth->seed(buf, num);
}

void RAND_add(const void *buf, int num, double entropy)
{
    const RAND_METHOD *meth = RAND_get_rand_method();
    if (meth && meth->add)
        meth->add(buf, num, entropy);
}

int RAND_bytes(unsigned char *buf, int num)
{
    const RAND_METHOD *meth = RAND_get_rand_method();
    if (meth && meth->bytes)
        return meth->bytes(buf, num);
    return (-1);
}

int RAND_pseudo_bytes(unsigned char *buf, int num)
{
    const RAND_METHOD *meth = RAND_get_rand_method();
    if (meth && meth->pseudorand)
        return meth->pseudorand(buf, num);
    return (-1);
}

int RAND_status(void)
{
    const RAND_METHOD *meth = RAND_get_rand_method();
    if (meth && meth->status)
        return meth->status();
    return 0;
}

#ifdef OPENSSL_FIPS

/*
 * FIPS DRBG initialisation code. This sets up the DRBG for use by the rest
 * of OpenSSL.
 */

/*
 * Entropy gatherer: use standard OpenSSL PRNG to seed (this will gather
 * entropy internally through RAND_poll()).
 */

static size_t drbg_get_entropy(DRBG_CTX *ctx, unsigned char **pout,
                               int entropy, size_t min_len, size_t max_len)
{
    /* Round up request to multiple of block size */
    min_len = ((min_len + 19) / 20) * 20;
    *pout = OPENSSL_malloc(min_len);
    if (!*pout)
        return 0;

    /* Enforces a reseed of the SSLEAY PRNG before generating random bytes */
    if (ssleay_rand_bytes_from_system(*pout, min_len) <= 0) {
        OPENSSL_free(*pout);
        *pout = NULL;
        return 0;
    }
    return min_len;
}

static size_t drbg_get_nonce(DRBG_CTX *ctx, unsigned char **pout,
                               int entropy, size_t min_len, size_t max_len)
{
    /* Round up request to multiple of block size */
    min_len = ((min_len + 19) / 20) * 20;
    *pout = OPENSSL_malloc(min_len);
    if (!*pout)
        return 0;
    if (ssleay_rand_bytes(*pout, min_len, 0, 0) <= 0) {
        OPENSSL_free(*pout);
        *pout = NULL;
        return 0;
    }
    return min_len;
}

static void drbg_free_entropy(DRBG_CTX *ctx, unsigned char *out, size_t olen)
{
    if (out) {
        OPENSSL_cleanse(out, olen);
        OPENSSL_free(out);
    }
}

/*
 * Set "additional input" when generating random data. This uses the current
 * PID, a time value and a counter.
 */

static size_t drbg_get_adin(DRBG_CTX *ctx, unsigned char **pout)
{
    /* Use of static variables is OK as this happens under a lock */
    static unsigned char buf[16];
    static unsigned long counter;
    FIPS_get_timevec(buf, &counter);
    *pout = buf;
    return sizeof(buf);
}

/*
 * RAND_add() and RAND_seed() pass through to OpenSSL PRNG so it is
 * correctly seeded by RAND_poll().
 */

static int drbg_rand_add(DRBG_CTX *ctx, const void *in, int inlen,
                         double entropy)
{
    RAND_SSLeay()->add(in, inlen, entropy);
    return 1;
}

static int drbg_rand_seed(DRBG_CTX *ctx, const void *in, int inlen)
{
    RAND_SSLeay()->seed(in, inlen);
    return 1;
}

# ifndef OPENSSL_DRBG_DEFAULT_TYPE
#  define OPENSSL_DRBG_DEFAULT_TYPE       NID_aes_256_ctr
# endif
# ifndef OPENSSL_DRBG_DEFAULT_FLAGS
#  define OPENSSL_DRBG_DEFAULT_FLAGS      DRBG_FLAG_CTR_USE_DF
# endif

static int fips_drbg_type = OPENSSL_DRBG_DEFAULT_TYPE;
static int fips_drbg_flags = OPENSSL_DRBG_DEFAULT_FLAGS;

void RAND_set_fips_drbg_type(int type, int flags)
{
    fips_drbg_type = type;
    fips_drbg_flags = flags;
}

int RAND_init_fips(void)
{
    DRBG_CTX *dctx;
    size_t plen;
    unsigned char pers[32], *p;
# ifndef OPENSSL_ALLOW_DUAL_EC_DRBG
    if (fips_drbg_type >> 16) {
        RANDerr(RAND_F_RAND_INIT_FIPS, RAND_R_DUAL_EC_DRBG_DISABLED);
        return 0;
    }
# endif

    dctx = FIPS_get_default_drbg();
    if (FIPS_drbg_init(dctx, fips_drbg_type, fips_drbg_flags) <= 0) {
        RANDerr(RAND_F_RAND_INIT_FIPS, RAND_R_ERROR_INITIALISING_DRBG);
        return 0;
    }

    FIPS_drbg_set_callbacks(dctx,
                            drbg_get_entropy, drbg_free_entropy, 20,
                            drbg_get_nonce, drbg_free_entropy);
    FIPS_drbg_set_rand_callbacks(dctx, drbg_get_adin, 0,
                                 drbg_rand_seed, drbg_rand_add);
    /* Personalisation string: a string followed by date time vector */
    strcpy((char *)pers, "OpenSSL DRBG2.0");
    plen = drbg_get_adin(dctx, &p);
    memcpy(pers + 16, p, plen);

    if (FIPS_drbg_instantiate(dctx, pers, sizeof(pers)) <= 0) {
        RANDerr(RAND_F_RAND_INIT_FIPS, RAND_R_ERROR_INSTANTIATING_DRBG);
        return 0;
    }
    FIPS_rand_set_method(FIPS_drbg_method());
    return 1;
}

#endif
/* crypto/rand/rand_nw.c */
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

// #include "cryptlib.h"
// #include "rand.h"
#include "rand_lcl.h"

#if defined (OPENSSL_SYS_NETWARE)

# if defined(NETWARE_LIBC)
#  include <nks/thread.h>
# else
#  include <nwthread.h>
# endif

extern int GetProcessSwitchCount(void);
# if !defined(NETWARE_LIBC) || (CURRENT_NDK_THRESHOLD < 509220000)
extern void *RunningProcess;    /* declare here same as found in newer NDKs */
extern unsigned long GetSuperHighResolutionTimer(void);
# endif

   /*
    * the FAQ indicates we need to provide at least 20 bytes (160 bits) of
    * seed
    */
int RAND_poll(void)
{
    unsigned long l;
    unsigned long tsc;
    int i;

    /*
     * There are several options to gather miscellaneous data but for now we
     * will loop checking the time stamp counter (rdtsc) and the
     * SuperHighResolutionTimer.  Each iteration will collect 8 bytes of data
     * but it is treated as only 1 byte of entropy.  The call to
     * ThreadSwitchWithDelay() will introduce additional variability into the
     * data returned by rdtsc. Applications can agument the seed material by
     * adding additional stuff with RAND_add() and should probably do so.
     */
    l = GetProcessSwitchCount();
    RAND_add(&l, sizeof(l), 1);

    /* need to cast the void* to unsigned long here */
    l = (unsigned long)RunningProcess;
    RAND_add(&l, sizeof(l), 1);

    for (i = 2; i < ENTROPY_NEEDED; i++) {
# ifdef __MWERKS__
        asm {
        rdtsc mov tsc, eax}
# elif defined(__GNUC__) && __GNUC__>=2 && !defined(OPENSSL_NO_ASM) && !defined(OPENSSL_NO_INLINE_ASM)
        asm volatile ("rdtsc":"=a" (tsc)::"edx");
# endif

        RAND_add(&tsc, sizeof(tsc), 1);

        l = GetSuperHighResolutionTimer();
        RAND_add(&l, sizeof(l), 0);

# if defined(NETWARE_LIBC)
        NXThreadYield();
# else                          /* NETWARE_CLIB */
        ThreadSwitchWithDelay();
# endif
    }

    return 1;
}

#endif
/* crypto/rand/rand_os2.c */
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
// #include "rand.h"
// #include "rand_lcl.h"

#ifdef OPENSSL_SYS_OS2

# define INCL_DOSPROCESS
# define INCL_DOSPROFILE
# define INCL_DOSMISC
# define INCL_DOSMODULEMGR
# include <os2.h>

# define   CMD_KI_RDCNT    (0x63)

typedef struct _CPUUTIL {
    ULONG ulTimeLow;            /* Low 32 bits of time stamp */
    ULONG ulTimeHigh;           /* High 32 bits of time stamp */
    ULONG ulIdleLow;            /* Low 32 bits of idle time */
    ULONG ulIdleHigh;           /* High 32 bits of idle time */
    ULONG ulBusyLow;            /* Low 32 bits of busy time */
    ULONG ulBusyHigh;           /* High 32 bits of busy time */
    ULONG ulIntrLow;            /* Low 32 bits of interrupt time */
    ULONG ulIntrHigh;           /* High 32 bits of interrupt time */
} CPUUTIL;

# ifndef __KLIBC__
APIRET APIENTRY(*DosPerfSysCall) (ULONG ulCommand, ULONG ulParm1,
                                  ULONG ulParm2, ULONG ulParm3) = NULL;
APIRET APIENTRY(*DosQuerySysState) (ULONG func, ULONG arg1, ULONG pid,
                                    ULONG _res_, PVOID buf, ULONG bufsz) =
    NULL;
# endif
HMODULE hDoscalls = 0;

int RAND_poll(void)
{
    char failed_module[20];
    QWORD qwTime;
    ULONG SysVars[QSV_FOREGROUND_PROCESS];

    if (hDoscalls == 0) {
        ULONG rc =
            DosLoadModule(failed_module, sizeof(failed_module), "DOSCALLS",
                          &hDoscalls);

# ifndef __KLIBC__
        if (rc == 0) {
            rc = DosQueryProcAddr(hDoscalls, 976, NULL,
                                  (PFN *) & DosPerfSysCall);

            if (rc)
                DosPerfSysCall = NULL;

            rc = DosQueryProcAddr(hDoscalls, 368, NULL,
                                  (PFN *) & DosQuerySysState);

            if (rc)
                DosQuerySysState = NULL;
        }
# endif
    }

    /* Sample the hi-res timer, runs at around 1.1 MHz */
    DosTmrQueryTime(&qwTime);
    RAND_add(&qwTime, sizeof(qwTime), 2);

    /*
     * Sample a bunch of system variables, includes various process & memory
     * statistics
     */
    DosQuerySysInfo(1, QSV_FOREGROUND_PROCESS, SysVars, sizeof(SysVars));
    RAND_add(SysVars, sizeof(SysVars), 4);

    /*
     * If available, sample CPU registers that count at CPU MHz Only fairly
     * new CPUs (PPro & K6 onwards) & OS/2 versions support this
     */
    if (DosPerfSysCall) {
        CPUUTIL util;

        if (DosPerfSysCall(CMD_KI_RDCNT, (ULONG) & util, 0, 0) == 0) {
            RAND_add(&util, sizeof(util), 10);
        } else {
# ifndef __KLIBC__
            DosPerfSysCall = NULL;
# endif
        }
    }

    /*
     * DosQuerySysState() gives us a huge quantity of process, thread, memory
     * & handle stats
     */
    if (DosQuerySysState) {
        char *buffer = OPENSSL_malloc(256 * 1024);

        if (!buffer)
            return 0;

        if (DosQuerySysState(0x1F, 0, 0, 0, buffer, 256 * 1024) == 0) {
            /*
             * First 4 bytes in buffer is a pointer to the thread count there
             * should be at least 1 byte of entropy per thread
             */
            RAND_add(buffer, 256 * 1024, **(ULONG **) buffer);
        }

        OPENSSL_free(buffer);
        return 1;
    }

    return 0;
}

#endif                          /* OPENSSL_SYS_OS2 */
/* crypto/rand/rand_unix.c */
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
#include <stdio.h>

#define USE_SOCKETS
#include "e_os.h"
// #include "cryptlib.h"
// #include "rand.h"
// #include "rand_lcl.h"

#if !(defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_WIN32) || defined(OPENSSL_SYS_VMS) || defined(OPENSSL_SYS_OS2) || defined(OPENSSL_SYS_VXWORKS) || defined(OPENSSL_SYS_NETWARE))

# include <sys/types.h>
# include <sys/time.h>
# include <sys/times.h>
# include <sys/stat.h>
# include <fcntl.h>
# include <unistd.h>
# include <time.h>
# if defined(OPENSSL_SYS_LINUX) /* should actually be available virtually
                                 * everywhere */
#  include <poll.h>
# endif
# include <limits.h>
# ifndef FD_SETSIZE
#  define FD_SETSIZE (8*sizeof(fd_set))
# endif

# if defined(OPENSSL_SYS_VOS)

/*
 * The following algorithm repeatedly samples the real-time clock (RTC) to
 * generate a sequence of unpredictable data.  The algorithm relies upon the
 * uneven execution speed of the code (due to factors such as cache misses,
 * interrupts, bus activity, and scheduling) and upon the rather large
 * relative difference between the speed of the clock and the rate at which
 * it can be read.
 *
 * If this code is ported to an environment where execution speed is more
 * constant or where the RTC ticks at a much slower rate, or the clock can be
 * read with fewer instructions, it is likely that the results would be far
 * more predictable.
 *
 * As a precaution, we generate 4 times the minimum required amount of seed
 * data.
 */

int RAND_poll(void)
{
    short int code;
    gid_t curr_gid;
    pid_t curr_pid;
    uid_t curr_uid;
    int i, k;
    struct timespec ts;
    unsigned char v;

#  ifdef OPENSSL_SYS_VOS_HPPA
    long duration;
    extern void s$sleep(long *_duration, short int *_code);
#  else
#   ifdef OPENSSL_SYS_VOS_IA32
    long long duration;
    extern void s$sleep2(long long *_duration, short int *_code);
#   else
#    error "Unsupported Platform."
#   endif                       /* OPENSSL_SYS_VOS_IA32 */
#  endif                        /* OPENSSL_SYS_VOS_HPPA */

    /*
     * Seed with the gid, pid, and uid, to ensure *some* variation between
     * different processes.
     */

    curr_gid = getgid();
    RAND_add(&curr_gid, sizeof(curr_gid), 1);
    curr_gid = 0;

    curr_pid = getpid();
    RAND_add(&curr_pid, sizeof(curr_pid), 1);
    curr_pid = 0;

    curr_uid = getuid();
    RAND_add(&curr_uid, sizeof(curr_uid), 1);
    curr_uid = 0;

    for (i = 0; i < (ENTROPY_NEEDED * 4); i++) {
        /*
         * burn some cpu; hope for interrupts, cache collisions, bus
         * interference, etc.
         */
        for (k = 0; k < 99; k++)
            ts.tv_nsec = random();

#  ifdef OPENSSL_SYS_VOS_HPPA
        /* sleep for 1/1024 of a second (976 us).  */
        duration = 1;
        s$sleep(&duration, &code);
#  else
#   ifdef OPENSSL_SYS_VOS_IA32
        /* sleep for 1/65536 of a second (15 us).  */
        duration = 1;
        s$sleep2(&duration, &code);
#   endif                       /* OPENSSL_SYS_VOS_IA32 */
#  endif                        /* OPENSSL_SYS_VOS_HPPA */

        /* get wall clock time.  */
        clock_gettime(CLOCK_REALTIME, &ts);

        /* take 8 bits */
        v = (unsigned char)(ts.tv_nsec % 256);
        RAND_add(&v, sizeof(v), 1);
        v = 0;
    }
    return 1;
}
# elif defined __OpenBSD__
int RAND_poll(void)
{
    u_int32_t rnd = 0, i;
    unsigned char buf[ENTROPY_NEEDED];

    for (i = 0; i < sizeof(buf); i++) {
        if (i % 4 == 0)
            rnd = arc4random();
        buf[i] = rnd;
        rnd >>= 8;
    }
    RAND_add(buf, sizeof(buf), ENTROPY_NEEDED);
    OPENSSL_cleanse(buf, sizeof(buf));

    return 1;
}
# else                          /* !defined(__OpenBSD__) */
int RAND_poll(void)
{
    unsigned long l;
    pid_t curr_pid = getpid();
#  if defined(DEVRANDOM) || defined(DEVRANDOM_EGD)
    unsigned char tmpbuf[ENTROPY_NEEDED];
    int n = 0;
#  endif
#  ifdef DEVRANDOM
    static const char *randomfiles[] = { DEVRANDOM };
    struct stat randomstats[sizeof(randomfiles) / sizeof(randomfiles[0])];
    int fd;
    unsigned int i;
#  endif
#  ifdef DEVRANDOM_EGD
    static const char *egdsockets[] = { DEVRANDOM_EGD, NULL };
    const char **egdsocket = NULL;
#  endif

#  ifdef DEVRANDOM
    memset(randomstats, 0, sizeof(randomstats));
    /*
     * Use a random entropy pool device. Linux, FreeBSD and OpenBSD have
     * this. Use /dev/urandom if you can as /dev/random may block if it runs
     * out of random entries.
     */

    for (i = 0; (i < sizeof(randomfiles) / sizeof(randomfiles[0])) &&
         (n < ENTROPY_NEEDED); i++) {
        if ((fd = open(randomfiles[i], O_RDONLY
#   ifdef O_NONBLOCK
                       | O_NONBLOCK
#   endif
#   ifdef O_BINARY
                       | O_BINARY
#   endif
#   ifdef O_NOCTTY              /* If it happens to be a TTY (god forbid), do
                                 * not make it our controlling tty */
                       | O_NOCTTY
#   endif
             )) >= 0) {
            int usec = 10 * 1000; /* spend 10ms on each file */
            int r;
            unsigned int j;
            struct stat *st = &randomstats[i];

            /*
             * Avoid using same input... Used to be O_NOFOLLOW above, but
             * it's not universally appropriate...
             */
            if (fstat(fd, st) != 0) {
                close(fd);
                continue;
            }
            for (j = 0; j < i; j++) {
                if (randomstats[j].st_ino == st->st_ino &&
                    randomstats[j].st_dev == st->st_dev)
                    break;
            }
            if (j < i) {
                close(fd);
                continue;
            }

            do {
                int try_read = 0;

#   if defined(OPENSSL_SYS_BEOS_R5)
                /*
                 * select() is broken in BeOS R5, so we simply try to read
                 * something and snooze if we couldn't
                 */
                try_read = 1;

#   elif defined(OPENSSL_SYS_LINUX)
                /* use poll() */
                struct pollfd pset;

                pset.fd = fd;
                pset.events = POLLIN;
                pset.revents = 0;

                if (poll(&pset, 1, usec / 1000) < 0)
                    usec = 0;
                else
                    try_read = (pset.revents & POLLIN) != 0;

#   else
                /* use select() */
                fd_set fset;
                struct timeval t;

                t.tv_sec = 0;
                t.tv_usec = usec;

                if (FD_SETSIZE > 0 && (unsigned)fd >= FD_SETSIZE) {
                    /*
                     * can't use select, so just try to read once anyway
                     */
                    try_read = 1;
                } else {
                    FD_ZERO(&fset);
                    FD_SET(fd, &fset);

                    if (select(fd + 1, &fset, NULL, NULL, &t) >= 0) {
                        usec = t.tv_usec;
                        if (FD_ISSET(fd, &fset))
                            try_read = 1;
                    } else
                        usec = 0;
                }
#   endif

                if (try_read) {
                    r = read(fd, (unsigned char *)tmpbuf + n,
                             ENTROPY_NEEDED - n);
                    if (r > 0)
                        n += r;
#   if defined(OPENSSL_SYS_BEOS_R5)
                    if (r == 0)
                        snooze(t.tv_usec);
#   endif
                } else
                    r = -1;

                /*
                 * Some Unixen will update t in select(), some won't.  For
                 * those who won't, or if we didn't use select() in the first
                 * place, give up here, otherwise, we will do this once again
                 * for the remaining time.
                 */
                if (usec == 10 * 1000)
                    usec = 0;
            }
            while ((r > 0 ||
                    (errno == EINTR || errno == EAGAIN)) && usec != 0
                   && n < ENTROPY_NEEDED);

            close(fd);
        }
    }
#  endif                        /* defined(DEVRANDOM) */

#  ifdef DEVRANDOM_EGD
    /*
     * Use an EGD socket to read entropy from an EGD or PRNGD entropy
     * collecting daemon.
     */

    for (egdsocket = egdsockets; *egdsocket && n < ENTROPY_NEEDED;
         egdsocket++) {
        int r;

        r = RAND_query_egd_bytes(*egdsocket, (unsigned char *)tmpbuf + n,
                                 ENTROPY_NEEDED - n);
        if (r > 0)
            n += r;
    }
#  endif                        /* defined(DEVRANDOM_EGD) */

#  if defined(DEVRANDOM) || defined(DEVRANDOM_EGD)
    if (n > 0) {
        RAND_add(tmpbuf, sizeof(tmpbuf), (double)n);
        OPENSSL_cleanse(tmpbuf, n);
    }
#  endif

    /* put in some default random data, we need more than just this */
    l = curr_pid;
    RAND_add(&l, sizeof(l), 0.0);
    l = getuid();
    RAND_add(&l, sizeof(l), 0.0);

    l = time(NULL);
    RAND_add(&l, sizeof(l), 0.0);

#  if defined(OPENSSL_SYS_BEOS)
    {
        system_info sysInfo;
        get_system_info(&sysInfo);
        RAND_add(&sysInfo, sizeof(sysInfo), 0);
    }
#  endif

#  if defined(DEVRANDOM) || defined(DEVRANDOM_EGD)
    return 1;
#  else
    return 0;
#  endif
}

# endif                         /* defined(__OpenBSD__) */
#endif                          /* !(defined(OPENSSL_SYS_WINDOWS) ||
                                 * defined(OPENSSL_SYS_WIN32) ||
                                 * defined(OPENSSL_SYS_VMS) ||
                                 * defined(OPENSSL_SYS_OS2) ||
                                 * defined(OPENSSL_SYS_VXWORKS) ||
                                 * defined(OPENSSL_SYS_NETWARE)) */

#if defined(OPENSSL_SYS_VXWORKS)
int RAND_poll(void)
{
    return 0;
}
#endif
/* crypto/rand/rand_vms.c */
/*
 * Written by Richard Levitte <richard@levitte.org> for the OpenSSL project
 * 2000.
 */
/*
 * Modified by VMS Software, Inc (2016)
 *    Eliminate looping through all processes (performance)
 *    Add additional randomizations using rand() function
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

// #include "rand.h"
// #include "rand_lcl.h"

#if defined(OPENSSL_SYS_VMS)
# include <descrip.h>
# include <jpidef.h>
# include <ssdef.h>
# include <starlet.h>
# include <efndef>
# ifdef __DECC
#  pragma message disable DOLLARID
# endif

/*
 * Use 32-bit pointers almost everywhere.  Define the type to which to cast a
 * pointer passed to an external function.
 */
# if __INITIAL_POINTER_SIZE == 64
#  define PTR_T __void_ptr64
#  pragma pointer_size save
#  pragma pointer_size 32
# else                          /* __INITIAL_POINTER_SIZE == 64 */
#  define PTR_T void *
# endif                         /* __INITIAL_POINTER_SIZE == 64 [else] */

static struct items_data_st {
    short length, code;         /* length is number of bytes */
} items_data[] = {
    {4, JPI$_BUFIO},
    {4, JPI$_CPUTIM},
    {4, JPI$_DIRIO},
    {4, JPI$_IMAGECOUNT},
    {8, JPI$_LAST_LOGIN_I},
    {8, JPI$_LOGINTIM},
    {4, JPI$_PAGEFLTS},
    {4, JPI$_PID},
    {4, JPI$_PPGCNT},
    {4, JPI$_WSPEAK},
    {4, JPI$_FINALEXC},
    {0, 0}                      /* zero terminated */
};

int RAND_poll(void)
{

    /* determine the number of items in the JPI array */

    struct items_data_st item_entry;
    int item_entry_count = sizeof(items_data)/sizeof(item_entry);

    /* Create the JPI itemlist array to hold item_data content */

    struct {
        short length, code;
        int *buffer;
        int *retlen;
    } item[item_entry_count], *pitem; /* number of entries in items_data */

    struct items_data_st *pitems_data;
    pitems_data = items_data;
    pitem = item;
    int data_buffer[(item_entry_count*2)+4]; /* 8 bytes per entry max */
    int iosb[2];
    int sys_time[2];
    int *ptr;
    int i, j ;
    int tmp_length   = 0;
    int total_length = 0;

    /* Setup itemlist for GETJPI */

    while (pitems_data->length) {
        pitem->length = pitems_data->length;
        pitem->code   = pitems_data->code;
        pitem->buffer = &data_buffer[total_length];
        pitem->retlen = 0;
        /* total_length is in longwords */
        total_length += pitems_data->length/4;
        pitems_data++;
        pitem ++;
    }
    pitem->length = pitem->code = 0;

    /* Fill data_buffer with various info bits from this process */
    /* and twist that data to seed the SSL random number init    */

    if (sys$getjpiw(EFN$C_ENF, NULL, NULL, item, &iosb, 0, 0) == SS$_NORMAL) {
        for (i = 0; i < total_length; i++) {
            sys$gettim((struct _generic_64 *)&sys_time[0]);
            srand(sys_time[0] * data_buffer[0] * data_buffer[1] + i);

            if (i == (total_length - 1)) { /* for JPI$_FINALEXC */
                ptr = &data_buffer[i];
                for (j = 0; j < 4; j++) {
                    data_buffer[i + j] = ptr[j];
                    /* OK to use rand() just to scramble the seed */
                    data_buffer[i + j] ^= (sys_time[0] ^ rand());
                    tmp_length++;
                }
            } else {
                /* OK to use rand() just to scramble the seed */
                data_buffer[i] ^= (sys_time[0] ^ rand());
            }
        }

        total_length += (tmp_length - 1);

        /* size of seed is total_length*4 bytes (64bytes) */
        RAND_add((PTR_T) data_buffer, total_length*4, total_length * 2);
    } else {
        return 0;
    }

    return 1;
}
#endif
/* crypto/rand/rand_win.c */
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

// #include "cryptlib.h"
// #include "rand.h"
// #include "rand_lcl.h"

#if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_WIN32)
# include <windows.h>
# ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0400
# endif
# include <wincrypt.h>
# include <tlhelp32.h>

/*
 * Limit the time spent walking through the heap, processes, threads and
 * modules to a maximum of 1000 miliseconds each, unless CryptoGenRandom
 * failed
 */
# define MAXDELAY 1000

/*
 * Intel hardware RNG CSP -- available from
 * http://developer.intel.com/design/security/rng/redist_license.htm
 */
# define PROV_INTEL_SEC 22
# define INTEL_DEF_PROV L"Intel Hardware Cryptographic Service Provider"

static void readtimer(void);
static void readscreen(void);

/*
 * It appears like CURSORINFO, PCURSORINFO and LPCURSORINFO are only defined
 * when WINVER is 0x0500 and up, which currently only happens on Win2000.
 * Unfortunately, those are typedefs, so they're a little bit difficult to
 * detect properly.  On the other hand, the macro CURSOR_SHOWING is defined
 * within the same conditional, so it can be use to detect the absence of
 * said typedefs.
 */

# ifndef CURSOR_SHOWING
/*
 * Information about the global cursor.
 */
typedef struct tagCURSORINFO {
    DWORD cbSize;
    DWORD flags;
    HCURSOR hCursor;
    POINT ptScreenPos;
} CURSORINFO, *PCURSORINFO, *LPCURSORINFO;

#  define CURSOR_SHOWING     0x00000001
# endif                         /* CURSOR_SHOWING */

# if !defined(OPENSSL_SYS_WINCE)
typedef BOOL(WINAPI *CRYPTACQUIRECONTEXTW) (HCRYPTPROV *, LPCWSTR, LPCWSTR,
                                            DWORD, DWORD);
typedef BOOL(WINAPI *CRYPTGENRANDOM) (HCRYPTPROV, DWORD, BYTE *);
typedef BOOL(WINAPI *CRYPTRELEASECONTEXT) (HCRYPTPROV, DWORD);

typedef HWND(WINAPI *GETFOREGROUNDWINDOW) (VOID);
typedef BOOL(WINAPI *GETCURSORINFO) (PCURSORINFO);
typedef DWORD(WINAPI *GETQUEUESTATUS) (UINT);

typedef HANDLE(WINAPI *CREATETOOLHELP32SNAPSHOT) (DWORD, DWORD);
typedef BOOL(WINAPI *CLOSETOOLHELP32SNAPSHOT) (HANDLE);
typedef BOOL(WINAPI *HEAP32FIRST) (LPHEAPENTRY32, DWORD, size_t);
typedef BOOL(WINAPI *HEAP32NEXT) (LPHEAPENTRY32);
typedef BOOL(WINAPI *HEAP32LIST) (HANDLE, LPHEAPLIST32);
typedef BOOL(WINAPI *PROCESS32) (HANDLE, LPPROCESSENTRY32);
typedef BOOL(WINAPI *THREAD32) (HANDLE, LPTHREADENTRY32);
typedef BOOL(WINAPI *MODULE32) (HANDLE, LPMODULEENTRY32);

#  include <lmcons.h>
#  include <lmstats.h>
#  if 1
/*
 * The NET API is Unicode only.  It requires the use of the UNICODE macro.
 * When UNICODE is defined LPTSTR becomes LPWSTR.  LMSTR was was added to the
 * Platform SDK to allow the NET API to be used in non-Unicode applications
 * provided that Unicode strings were still used for input.  LMSTR is defined
 * as LPWSTR.
 */
typedef NET_API_STATUS(NET_API_FUNCTION *NETSTATGET)
 (LPWSTR, LPWSTR, DWORD, DWORD, LPBYTE *);
typedef NET_API_STATUS(NET_API_FUNCTION *NETFREE) (LPBYTE);
#  endif                        /* 1 */
# endif                         /* !OPENSSL_SYS_WINCE */

#define NOTTOOLONG(start) ((GetTickCount() - (start)) < MAXDELAY)

int RAND_poll(void)
{
    MEMORYSTATUS m;
    HCRYPTPROV hProvider = 0;
    DWORD w;
    int good = 0;

# if defined(OPENSSL_SYS_WINCE)
#  if defined(_WIN32_WCE) && _WIN32_WCE>=300
    /*
     * Even though MSDN says _WIN32_WCE>=210, it doesn't seem to be available
     * in commonly available implementations prior 300...
     */
    {
        BYTE buf[64];
        /* poll the CryptoAPI PRNG */
        /* The CryptoAPI returns sizeof(buf) bytes of randomness */
        if (CryptAcquireContextW(&hProvider, NULL, NULL, PROV_RSA_FULL,
                                 CRYPT_VERIFYCONTEXT)) {
            if (CryptGenRandom(hProvider, sizeof(buf), buf))
                RAND_add(buf, sizeof(buf), sizeof(buf));
            CryptReleaseContext(hProvider, 0);
        }
    }
#  endif
# else                          /* OPENSSL_SYS_WINCE */
    /*
     * None of below libraries are present on Windows CE, which is
     * why we #ifndef the whole section. This also excuses us from
     * handling the GetProcAddress issue. The trouble is that in
     * real Win32 API GetProcAddress is available in ANSI flavor
     * only. In WinCE on the other hand GetProcAddress is a macro
     * most commonly defined as GetProcAddressW, which accepts
     * Unicode argument. If we were to call GetProcAddress under
     * WinCE, I'd recommend to either redefine GetProcAddress as
     * GetProcAddressA (there seem to be one in common CE spec) or
     * implement own shim routine, which would accept ANSI argument
     * and expand it to Unicode.
     */
    {
        /* load functions dynamically - not available on all systems */
        HMODULE advapi = LoadLibrary(TEXT("ADVAPI32.DLL"));
        HMODULE kernel = LoadLibrary(TEXT("KERNEL32.DLL"));
        HMODULE user = NULL;
        HMODULE netapi = LoadLibrary(TEXT("NETAPI32.DLL"));
        CRYPTACQUIRECONTEXTW acquire = NULL;
        CRYPTGENRANDOM gen = NULL;
        CRYPTRELEASECONTEXT release = NULL;
        NETSTATGET netstatget = NULL;
        NETFREE netfree = NULL;
        BYTE buf[64];

        if (netapi) {
            netstatget =
                (NETSTATGET) GetProcAddress(netapi, "NetStatisticsGet");
            netfree = (NETFREE) GetProcAddress(netapi, "NetApiBufferFree");
        }

        if (netstatget && netfree) {
            LPBYTE outbuf;
            /*
             * NetStatisticsGet() is a Unicode only function
             * STAT_WORKSTATION_0 contains 45 fields and STAT_SERVER_0
             * contains 17 fields.  We treat each field as a source of one
             * byte of entropy.
             */

            if (netstatget(NULL, L"LanmanWorkstation", 0, 0, &outbuf) == 0) {
                RAND_add(outbuf, sizeof(STAT_WORKSTATION_0), 45);
                netfree(outbuf);
            }
            if (netstatget(NULL, L"LanmanServer", 0, 0, &outbuf) == 0) {
                RAND_add(outbuf, sizeof(STAT_SERVER_0), 17);
                netfree(outbuf);
            }
        }

        if (netapi)
            FreeLibrary(netapi);

        /*
         * It appears like this can cause an exception deep within
         * ADVAPI32.DLL at random times on Windows 2000.  Reported by Jeffrey
         * Altman. Only use it on NT.
         */

        if (advapi) {
            /*
             * If it's available, then it's available in both ANSI
             * and UNICODE flavors even in Win9x, documentation says.
             * We favor Unicode...
             */
            acquire = (CRYPTACQUIRECONTEXTW) GetProcAddress(advapi,
                                                            "CryptAcquireContextW");
            gen = (CRYPTGENRANDOM) GetProcAddress(advapi, "CryptGenRandom");
            release = (CRYPTRELEASECONTEXT) GetProcAddress(advapi,
                                                           "CryptReleaseContext");
        }

        if (acquire && gen && release) {
            /* poll the CryptoAPI PRNG */
            /* The CryptoAPI returns sizeof(buf) bytes of randomness */
            if (acquire(&hProvider, NULL, NULL, PROV_RSA_FULL,
                        CRYPT_VERIFYCONTEXT)) {
                if (gen(hProvider, sizeof(buf), buf) != 0) {
                    RAND_add(buf, sizeof(buf), 0);
                    good = 1;
#  if 0
                    printf("randomness from PROV_RSA_FULL\n");
#  endif
                }
                release(hProvider, 0);
            }

            /* poll the Pentium PRG with CryptoAPI */
            if (acquire(&hProvider, 0, INTEL_DEF_PROV, PROV_INTEL_SEC, 0)) {
                if (gen(hProvider, sizeof(buf), buf) != 0) {
                    RAND_add(buf, sizeof(buf), sizeof(buf));
                    good = 1;
#  if 0
                    printf("randomness from PROV_INTEL_SEC\n");
#  endif
                }
                release(hProvider, 0);
            }
        }

        if (advapi)
            FreeLibrary(advapi);

        if ((!check_winnt() ||
             !OPENSSL_isservice()) &&
            (user = LoadLibrary(TEXT("USER32.DLL")))) {
            GETCURSORINFO cursor;
            GETFOREGROUNDWINDOW win;
            GETQUEUESTATUS queue;

            win =
                (GETFOREGROUNDWINDOW) GetProcAddress(user,
                                                     "GetForegroundWindow");
            cursor = (GETCURSORINFO) GetProcAddress(user, "GetCursorInfo");
            queue = (GETQUEUESTATUS) GetProcAddress(user, "GetQueueStatus");

            if (win) {
                /* window handle */
                HWND h = win();
                RAND_add(&h, sizeof(h), 0);
            }
            if (cursor) {
                /*
                 * unfortunately, its not safe to call GetCursorInfo() on NT4
                 * even though it exists in SP3 (or SP6) and higher.
                 */
                if (check_winnt() && !check_win_minplat(5))
                    cursor = 0;
            }
            if (cursor) {
                /* cursor position */
                /* assume 2 bytes of entropy */
                CURSORINFO ci;
                ci.cbSize = sizeof(CURSORINFO);
                if (cursor(&ci))
                    RAND_add(&ci, ci.cbSize, 2);
            }

            if (queue) {
                /* message queue status */
                /* assume 1 byte of entropy */
                w = queue(QS_ALLEVENTS);
                RAND_add(&w, sizeof(w), 1);
            }

            FreeLibrary(user);
        }

        /*-
         * Toolhelp32 snapshot: enumerate processes, threads, modules and heap
         * http://msdn.microsoft.com/library/psdk/winbase/toolhelp_5pfd.htm
         * (Win 9x and 2000 only, not available on NT)
         *
         * This seeding method was proposed in Peter Gutmann, Software
         * Generation of Practically Strong Random Numbers,
         * http://www.usenix.org/publications/library/proceedings/sec98/gutmann.html
         * revised version at http://www.cryptoengines.com/~peter/06_random.pdf
         * (The assignment of entropy estimates below is arbitrary, but based
         * on Peter's analysis the full poll appears to be safe. Additional
         * interactive seeding is encouraged.)
         */

        if (kernel) {
            CREATETOOLHELP32SNAPSHOT snap;
            CLOSETOOLHELP32SNAPSHOT close_snap;
            HANDLE handle;

            HEAP32FIRST heap_first;
            HEAP32NEXT heap_next;
            HEAP32LIST heaplist_first, heaplist_next;
            PROCESS32 process_first, process_next;
            THREAD32 thread_first, thread_next;
            MODULE32 module_first, module_next;

            HEAPLIST32 hlist;
            HEAPENTRY32 hentry;
            PROCESSENTRY32 p;
            THREADENTRY32 t;
            MODULEENTRY32 m;
            DWORD starttime = 0;

            snap = (CREATETOOLHELP32SNAPSHOT)
                GetProcAddress(kernel, "CreateToolhelp32Snapshot");
            close_snap = (CLOSETOOLHELP32SNAPSHOT)
                GetProcAddress(kernel, "CloseToolhelp32Snapshot");
            heap_first = (HEAP32FIRST) GetProcAddress(kernel, "Heap32First");
            heap_next = (HEAP32NEXT) GetProcAddress(kernel, "Heap32Next");
            heaplist_first =
                (HEAP32LIST) GetProcAddress(kernel, "Heap32ListFirst");
            heaplist_next =
                (HEAP32LIST) GetProcAddress(kernel, "Heap32ListNext");
            process_first =
                (PROCESS32) GetProcAddress(kernel, "Process32First");
            process_next =
                (PROCESS32) GetProcAddress(kernel, "Process32Next");
            thread_first = (THREAD32) GetProcAddress(kernel, "Thread32First");
            thread_next = (THREAD32) GetProcAddress(kernel, "Thread32Next");
            module_first = (MODULE32) GetProcAddress(kernel, "Module32First");
            module_next = (MODULE32) GetProcAddress(kernel, "Module32Next");

            if (snap && heap_first && heap_next && heaplist_first &&
                heaplist_next && process_first && process_next &&
                thread_first && thread_next && module_first &&
                module_next && (handle = snap(TH32CS_SNAPALL, 0))
                != INVALID_HANDLE_VALUE) {
                /* heap list and heap walking */
                /*
                 * HEAPLIST32 contains 3 fields that will change with each
                 * entry.  Consider each field a source of 1 byte of entropy.
                 * HEAPENTRY32 contains 5 fields that will change with each
                 * entry.  Consider each field a source of 1 byte of entropy.
                 */
                ZeroMemory(&hlist, sizeof(HEAPLIST32));
                hlist.dwSize = sizeof(HEAPLIST32);
                if (good)
                    starttime = GetTickCount();
#  ifdef _MSC_VER
                if (heaplist_first(handle, &hlist)) {
                    /*
                     * following discussion on dev ML, exception on WinCE (or
                     * other Win platform) is theoretically of unknown
                     * origin; prevent infinite loop here when this
                     * theoretical case occurs; otherwise cope with the
                     * expected (MSDN documented) exception-throwing
                     * behaviour of Heap32Next() on WinCE.
                     *
                     * based on patch in original message by Tanguy Fautré
                     * (2009/03/02) Subject: RAND_poll() and
                     * CreateToolhelp32Snapshot() stability
                     */
                    int ex_cnt_limit = 42;
                    do {
                        RAND_add(&hlist, hlist.dwSize, 3);
                        __try {
                            ZeroMemory(&hentry, sizeof(HEAPENTRY32));
                            hentry.dwSize = sizeof(HEAPENTRY32);
                            if (heap_first(&hentry,
                                           hlist.th32ProcessID,
                                           hlist.th32HeapID)) {
                                int entrycnt = 80;
                                do
                                    RAND_add(&hentry, hentry.dwSize, 5);
                                while (heap_next(&hentry)
                                       && (!good || NOTTOOLONG(starttime))
                                       && --entrycnt > 0);
                            }
                        }
                        __except(EXCEPTION_EXECUTE_HANDLER) {
                            /*
                             * ignore access violations when walking the heap
                             * list
                             */
                            ex_cnt_limit--;
                        }
                    } while (heaplist_next(handle, &hlist)
                             && (!good || NOTTOOLONG(starttime))
                             && ex_cnt_limit > 0);
                }
#  else
                if (heaplist_first(handle, &hlist)) {
                    do {
                        RAND_add(&hlist, hlist.dwSize, 3);
                        hentry.dwSize = sizeof(HEAPENTRY32);
                        if (heap_first(&hentry,
                                       hlist.th32ProcessID,
                                       hlist.th32HeapID)) {
                            int entrycnt = 80;
                            do
                                RAND_add(&hentry, hentry.dwSize, 5);
                            while (heap_next(&hentry)
                                   && (!good || NOTTOOLONG(starttime))
                                   && --entrycnt > 0);
                        }
                    } while (heaplist_next(handle, &hlist)
                             && (!good || NOTTOOLONG(starttime)));
                }
#  endif

                /* process walking */
                /*
                 * PROCESSENTRY32 contains 9 fields that will change with
                 * each entry.  Consider each field a source of 1 byte of
                 * entropy.
                 */
                p.dwSize = sizeof(PROCESSENTRY32);

                if (good)
                    starttime = GetTickCount();
                if (process_first(handle, &p))
                    do
                        RAND_add(&p, p.dwSize, 9);
                    while (process_next(handle, &p)
                           && (!good || NOTTOOLONG(starttime)));

                /* thread walking */
                /*
                 * THREADENTRY32 contains 6 fields that will change with each
                 * entry.  Consider each field a source of 1 byte of entropy.
                 */
                t.dwSize = sizeof(THREADENTRY32);
                if (good)
                    starttime = GetTickCount();
                if (thread_first(handle, &t))
                    do
                        RAND_add(&t, t.dwSize, 6);
                    while (thread_next(handle, &t)
                           && (!good || NOTTOOLONG(starttime)));

                /* module walking */
                /*
                 * MODULEENTRY32 contains 9 fields that will change with each
                 * entry.  Consider each field a source of 1 byte of entropy.
                 */
                m.dwSize = sizeof(MODULEENTRY32);
                if (good)
                    starttime = GetTickCount();
                if (module_first(handle, &m))
                    do
                        RAND_add(&m, m.dwSize, 9);
                    while (module_next(handle, &m)
                           && (!good || NOTTOOLONG(starttime)));
                if (close_snap)
                    close_snap(handle);
                else
                    CloseHandle(handle);

            }

            FreeLibrary(kernel);
        }
    }
# endif                         /* !OPENSSL_SYS_WINCE */

    /* timer data */
    readtimer();

    /* memory usage statistics */
    GlobalMemoryStatus(&m);
    RAND_add(&m, sizeof(m), 1);

    /* process ID */
    w = GetCurrentProcessId();
    RAND_add(&w, sizeof(w), 1);

# if 0
    printf("Exiting RAND_poll\n");
# endif

    return (1);
}

int RAND_event(UINT iMsg, WPARAM wParam, LPARAM lParam)
{
    double add_entropy = 0;

    switch (iMsg) {
    case WM_KEYDOWN:
        {
            static WPARAM key;
            if (key != wParam)
                add_entropy = 0.05;
            key = wParam;
        }
        break;
    case WM_MOUSEMOVE:
        {
            static int lastx, lasty, lastdx, lastdy;
            int x, y, dx, dy;

            x = LOWORD(lParam);
            y = HIWORD(lParam);
            dx = lastx - x;
            dy = lasty - y;
            if (dx != 0 && dy != 0 && dx - lastdx != 0 && dy - lastdy != 0)
                add_entropy = .2;
            lastx = x, lasty = y;
            lastdx = dx, lastdy = dy;
        }
        break;
    }

    readtimer();
    RAND_add(&iMsg, sizeof(iMsg), add_entropy);
    RAND_add(&wParam, sizeof(wParam), 0);
    RAND_add(&lParam, sizeof(lParam), 0);

    return (RAND_status());
}

void RAND_screen(void)
{                               /* function available for backward
                                 * compatibility */
    RAND_poll();
    readscreen();
}

/* feed timing information to the PRNG */
static void readtimer(void)
{
    DWORD w;
    LARGE_INTEGER l;
    static int have_perfc = 1;
# if defined(_MSC_VER) && defined(_M_X86)
    static int have_tsc = 1;
    DWORD cyclecount;

    if (have_tsc) {
        __try {
            __asm {
            _emit 0x0f _emit 0x31 mov cyclecount, eax}
            RAND_add(&cyclecount, sizeof(cyclecount), 1);
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            have_tsc = 0;
        }
    }
# else
#  define have_tsc 0
# endif

    if (have_perfc) {
        if (QueryPerformanceCounter(&l) == 0)
            have_perfc = 0;
        else
            RAND_add(&l, sizeof(l), 0);
    }

    if (!have_tsc && !have_perfc) {
        w = GetTickCount();
        RAND_add(&w, sizeof(w), 0);
    }
}

/* feed screen contents to PRNG */
/*****************************************************************************
 *
 * Created 960901 by Gertjan van Oosten, gertjan@West.NL, West Consulting B.V.
 *
 * Code adapted from
 * <URL:http://support.microsoft.com/default.aspx?scid=kb;[LN];97193>;
 * the original copyright message is:
 *
 *   (C) Copyright Microsoft Corp. 1993.  All rights reserved.
 *
 *   You have a royalty-free right to use, modify, reproduce and
 *   distribute the Sample Files (and/or any modified version) in
 *   any way you find useful, provided that you agree that
 *   Microsoft has no warranty obligations or liability for any
 *   Sample Application Files which are modified.
 */

static void readscreen(void)
{
# if !defined(OPENSSL_SYS_WINCE) && !defined(OPENSSL_SYS_WIN32_CYGWIN)
    HDC hScrDC;                 /* screen DC */
    HBITMAP hBitmap;            /* handle for our bitmap */
    BITMAP bm;                  /* bitmap properties */
    unsigned int size;          /* size of bitmap */
    char *bmbits;               /* contents of bitmap */
    int w;                      /* screen width */
    int h;                      /* screen height */
    int y;                      /* y-coordinate of screen lines to grab */
    int n = 16;                 /* number of screen lines to grab at a time */
    BITMAPINFOHEADER bi;        /* info about the bitmap */

    if (check_winnt() && OPENSSL_isservice() > 0)
        return;

    /* Get a reference to the screen DC */
    hScrDC = GetDC(NULL);

    /* Get screen resolution */
    w = GetDeviceCaps(hScrDC, HORZRES);
    h = GetDeviceCaps(hScrDC, VERTRES);

    /* Create a bitmap compatible with the screen DC */
    hBitmap = CreateCompatibleBitmap(hScrDC, w, n);

    /* Get bitmap properties */
    GetObject(hBitmap, sizeof(bm), (LPSTR)&bm);
    size = (unsigned int)4 * bm.bmHeight * bm.bmWidth;
    bi.biSize = sizeof(bi);
    bi.biWidth = bm.bmWidth;
    bi.biHeight = bm.bmHeight;
    bi.biPlanes = 1;
    bi.biBitCount = 32;
    bi.biCompression = BI_RGB;
    bi.biSizeImage = 0;
    bi.biXPelsPerMeter = 0;
    bi.biYPelsPerMeter = 0;
    bi.biClrUsed = 0;
    bi.biClrImportant = 0;

    bmbits = OPENSSL_malloc(size);
    if (bmbits) {
        /* Now go through the whole screen, repeatedly grabbing n lines */
        for (y = 0; y < h - n; y += n) {
            unsigned char md[MD_DIGEST_LENGTH];

            /* Copy the bits of the current line range into the buffer */
            GetDIBits(hScrDC, hBitmap, y, n,
                      bmbits, (LPBITMAPINFO)&bi, DIB_RGB_COLORS);

            /* Get the hash of the bitmap */
            MD(bmbits, size, md);

            /* Seed the random generator with the hash value */
            RAND_add(md, MD_DIGEST_LENGTH, 0);
        }

        OPENSSL_free(bmbits);
    }

    /* Clean up */
    DeleteObject(hBitmap);
    ReleaseDC(NULL, hScrDC);
# endif                         /* !OPENSSL_SYS_WINCE */
}

#endif
