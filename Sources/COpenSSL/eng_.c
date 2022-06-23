/* crypto/engine/eng_all.c */
/*
 * Written by Richard Levitte <richard@levitte.org> for the OpenSSL project
 * 2000.
 */
/* ====================================================================
 * Copyright (c) 2000-2001 The OpenSSL Project.  All rights reserved.
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

#include "cryptlib.h"
#include "eng_int.h"

void ENGINE_load_builtin_engines(void)
{
    /* Some ENGINEs need this */
    OPENSSL_cpuid_setup();
#if 0
    /*
     * There's no longer any need for an "openssl" ENGINE unless, one day, it
     * is the *only* way for standard builtin implementations to be be
     * accessed (ie. it would be possible to statically link binaries with
     * *no* builtin implementations).
     */
    ENGINE_load_openssl();
#endif
#if !defined(OPENSSL_NO_HW) && (defined(__OpenBSD__) || defined(__FreeBSD__) || defined(HAVE_CRYPTODEV))
    ENGINE_load_cryptodev();
#endif
#ifndef OPENSSL_NO_RDRAND
    ENGINE_load_rdrand();
#endif
    ENGINE_load_dynamic();
#ifndef OPENSSL_NO_STATIC_ENGINE
# ifndef OPENSSL_NO_HW
#  ifndef OPENSSL_NO_HW_4758_CCA
    ENGINE_load_4758cca();
#  endif
#  ifndef OPENSSL_NO_HW_AEP
    ENGINE_load_aep();
#  endif
#  ifndef OPENSSL_NO_HW_ATALLA
    ENGINE_load_atalla();
#  endif
#  ifndef OPENSSL_NO_HW_CSWIFT
    ENGINE_load_cswift();
#  endif
#  ifndef OPENSSL_NO_HW_NCIPHER
    ENGINE_load_chil();
#  endif
#  ifndef OPENSSL_NO_HW_NURON
    ENGINE_load_nuron();
#  endif
#  ifndef OPENSSL_NO_HW_SUREWARE
    ENGINE_load_sureware();
#  endif
#  ifndef OPENSSL_NO_HW_UBSEC
    ENGINE_load_ubsec();
#  endif
#  ifndef OPENSSL_NO_HW_PADLOCK
    ENGINE_load_padlock();
#  endif
# endif
# ifndef OPENSSL_NO_GOST
    ENGINE_load_gost();
# endif
# ifndef OPENSSL_NO_GMP
    ENGINE_load_gmp();
# endif
# if defined(OPENSSL_SYS_WIN32) && !defined(OPENSSL_NO_CAPIENG)
    ENGINE_load_capi();
# endif
#endif
    ENGINE_register_all_complete();
}

#if defined(__OpenBSD__) || defined(__FreeBSD__) || defined(HAVE_CRYPTODEV)
void ENGINE_setup_bsd_cryptodev(void)
{
    static int bsd_cryptodev_default_loaded = 0;
    if (!bsd_cryptodev_default_loaded) {
        ENGINE_load_cryptodev();
        ENGINE_register_all_complete();
    }
    bsd_cryptodev_default_loaded = 1;
}
#endif
/* eng_cnf.c */
/*
 * Written by Stephen Henson (steve@openssl.org) for the OpenSSL project
 * 2001.
 */
/* ====================================================================
 * Copyright (c) 2001 The OpenSSL Project.  All rights reserved.
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

// #include "eng_int.h"
#include "conf.h"

/* #define ENGINE_CONF_DEBUG */

/* ENGINE config module */

static char *skip_dot(char *name)
{
    char *p;
    p = strchr(name, '.');
    if (p)
        return p + 1;
    return name;
}

static STACK_OF(ENGINE) *initialized_engines = NULL;

static int int_engine_init(ENGINE *e)
{
    if (!ENGINE_init(e))
        return 0;
    if (!initialized_engines)
        initialized_engines = sk_ENGINE_new_null();
    if (!initialized_engines || !sk_ENGINE_push(initialized_engines, e)) {
        ENGINE_finish(e);
        return 0;
    }
    return 1;
}

static int int_engine_configure(char *name, char *value, const CONF *cnf)
{
    int i;
    int ret = 0;
    long do_init = -1;
    STACK_OF(CONF_VALUE) *ecmds;
    CONF_VALUE *ecmd = NULL;
    char *ctrlname, *ctrlvalue;
    ENGINE *e = NULL;
    int soft = 0;

    name = skip_dot(name);
#ifdef ENGINE_CONF_DEBUG
    fprintf(stderr, "Configuring engine %s\n", name);
#endif
    /* Value is a section containing ENGINE commands */
    ecmds = NCONF_get_section(cnf, value);

    if (!ecmds) {
        ENGINEerr(ENGINE_F_INT_ENGINE_CONFIGURE,
                  ENGINE_R_ENGINE_SECTION_ERROR);
        return 0;
    }

    for (i = 0; i < sk_CONF_VALUE_num(ecmds); i++) {
        ecmd = sk_CONF_VALUE_value(ecmds, i);
        ctrlname = skip_dot(ecmd->name);
        ctrlvalue = ecmd->value;
#ifdef ENGINE_CONF_DEBUG
        fprintf(stderr, "ENGINE conf: doing ctrl(%s,%s)\n", ctrlname,
                ctrlvalue);
#endif

        /* First handle some special pseudo ctrls */

        /* Override engine name to use */
        if (!strcmp(ctrlname, "engine_id"))
            name = ctrlvalue;
        else if (!strcmp(ctrlname, "soft_load"))
            soft = 1;
        /* Load a dynamic ENGINE */
        else if (!strcmp(ctrlname, "dynamic_path")) {
            e = ENGINE_by_id("dynamic");
            if (!e)
                goto err;
            if (!ENGINE_ctrl_cmd_string(e, "SO_PATH", ctrlvalue, 0))
                goto err;
            if (!ENGINE_ctrl_cmd_string(e, "LIST_ADD", "2", 0))
                goto err;
            if (!ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0))
                goto err;
        }
        /* ... add other pseudos here ... */
        else {
            /*
             * At this point we need an ENGINE structural reference if we
             * don't already have one.
             */
            if (!e) {
                e = ENGINE_by_id(name);
                if (!e && soft) {
                    ERR_clear_error();
                    return 1;
                }
                if (!e)
                    goto err;
            }
            /*
             * Allow "EMPTY" to mean no value: this allows a valid "value" to
             * be passed to ctrls of type NO_INPUT
             */
            if (!strcmp(ctrlvalue, "EMPTY"))
                ctrlvalue = NULL;
            if (!strcmp(ctrlname, "init")) {
                if (!NCONF_get_number_e(cnf, value, "init", &do_init))
                    goto err;
                if (do_init == 1) {
                    if (!int_engine_init(e))
                        goto err;
                } else if (do_init != 0) {
                    ENGINEerr(ENGINE_F_INT_ENGINE_CONFIGURE,
                              ENGINE_R_INVALID_INIT_VALUE);
                    goto err;
                }
            } else if (!strcmp(ctrlname, "default_algorithms")) {
                if (!ENGINE_set_default_string(e, ctrlvalue))
                    goto err;
            } else if (!ENGINE_ctrl_cmd_string(e, ctrlname, ctrlvalue, 0))
                goto err;
        }

    }
    if (e && (do_init == -1) && !int_engine_init(e)) {
        ecmd = NULL;
        goto err;
    }
    ret = 1;
 err:
    if (ret != 1) {
        ENGINEerr(ENGINE_F_INT_ENGINE_CONFIGURE,
                  ENGINE_R_ENGINE_CONFIGURATION_ERROR);
        if (ecmd)
            ERR_add_error_data(6, "section=", ecmd->section,
                               ", name=", ecmd->name,
                               ", value=", ecmd->value);
    }
    if (e)
        ENGINE_free(e);
    return ret;
}

static int int_engine_module_init(CONF_IMODULE *md, const CONF *cnf)
{
    STACK_OF(CONF_VALUE) *elist;
    CONF_VALUE *cval;
    int i;
#ifdef ENGINE_CONF_DEBUG
    fprintf(stderr, "Called engine module: name %s, value %s\n",
            CONF_imodule_get_name(md), CONF_imodule_get_value(md));
#endif
    /* Value is a section containing ENGINEs to configure */
    elist = NCONF_get_section(cnf, CONF_imodule_get_value(md));

    if (!elist) {
        ENGINEerr(ENGINE_F_INT_ENGINE_MODULE_INIT,
                  ENGINE_R_ENGINES_SECTION_ERROR);
        return 0;
    }

    for (i = 0; i < sk_CONF_VALUE_num(elist); i++) {
        cval = sk_CONF_VALUE_value(elist, i);
        if (!int_engine_configure(cval->name, cval->value, cnf))
            return 0;
    }

    return 1;
}

static void int_engine_module_finish(CONF_IMODULE *md)
{
    ENGINE *e;
    while ((e = sk_ENGINE_pop(initialized_engines)))
        ENGINE_finish(e);
    sk_ENGINE_free(initialized_engines);
    initialized_engines = NULL;
}

void ENGINE_add_conf_module(void)
{
    CONF_module_add("engines",
                    int_engine_module_init, int_engine_module_finish);
}
/*
 * Copyright (c) 2002 Bob Beck <beck@openbsd.org>
 * Copyright (c) 2002 Theo de Raadt
 * Copyright (c) 2002 Markus Friedl
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <string.h>
#include "objects.h"
#include "engine.h"
#include "evp.h"
#include "bn.h"

#if (defined(__unix__) || defined(unix)) && !defined(USG) && \
        (defined(OpenBSD) || defined(__FreeBSD__))
# include <sys/param.h>
# if (OpenBSD >= 200112) || ((__FreeBSD_version >= 470101 && __FreeBSD_version < 500000) || __FreeBSD_version >= 500041)
#  define HAVE_CRYPTODEV
# endif
# if (OpenBSD >= 200110)
#  define HAVE_SYSLOG_R
# endif
#endif

#ifndef HAVE_CRYPTODEV

void ENGINE_load_cryptodev(void)
{
    /* This is a NOP on platforms without /dev/crypto */
    return;
}

#else

# include <sys/types.h>
# include <crypto/cryptodev.h>
# include "dh.h"
# include "dsa.h"
# include "err.h"
# include "rsa.h"
# include <sys/ioctl.h>
# include <errno.h>
# include <stdio.h>
# include <unistd.h>
# include <fcntl.h>
# include <stdarg.h>
# include <syslog.h>
# include <errno.h>
# include <string.h>

struct dev_crypto_state {
    struct session_op d_sess;
    int d_fd;
# ifdef USE_CRYPTODEV_DIGESTS
    char dummy_mac_key[HASH_MAX_LEN];
    unsigned char digest_res[HASH_MAX_LEN];
    char *mac_data;
    int mac_len;
# endif
};

static u_int32_t cryptodev_asymfeat = 0;

static int get_asym_dev_crypto(void);
static int open_dev_crypto(void);
static int get_dev_crypto(void);
static int get_cryptodev_ciphers(const int **cnids);
# ifdef USE_CRYPTODEV_DIGESTS
static int get_cryptodev_digests(const int **cnids);
# endif
static int cryptodev_usable_ciphers(const int **nids);
static int cryptodev_usable_digests(const int **nids);
static int cryptodev_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                            const unsigned char *in, size_t inl);
static int cryptodev_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                              const unsigned char *iv, int enc);
static int cryptodev_cleanup(EVP_CIPHER_CTX *ctx);
static int cryptodev_engine_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                                    const int **nids, int nid);
static int cryptodev_engine_digests(ENGINE *e, const EVP_MD **digest,
                                    const int **nids, int nid);
static int bn2crparam(const BIGNUM *a, struct crparam *crp);
static int crparam2bn(struct crparam *crp, BIGNUM *a);
static void zapparams(struct crypt_kop *kop);
static int cryptodev_asym(struct crypt_kop *kop, int rlen, BIGNUM *r,
                          int slen, BIGNUM *s);

static int cryptodev_bn_mod_exp(BIGNUM *r, const BIGNUM *a,
                                const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx,
                                BN_MONT_CTX *m_ctx);
static int cryptodev_rsa_nocrt_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa,
                                       BN_CTX *ctx);
static int cryptodev_rsa_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa,
                                 BN_CTX *ctx);
static int cryptodev_dsa_bn_mod_exp(DSA *dsa, BIGNUM *r, BIGNUM *a,
                                    const BIGNUM *p, const BIGNUM *m,
                                    BN_CTX *ctx, BN_MONT_CTX *m_ctx);
static int cryptodev_dsa_dsa_mod_exp(DSA *dsa, BIGNUM *t1, BIGNUM *g,
                                     BIGNUM *u1, BIGNUM *pub_key, BIGNUM *u2,
                                     BIGNUM *p, BN_CTX *ctx,
                                     BN_MONT_CTX *mont);
static DSA_SIG *cryptodev_dsa_do_sign(const unsigned char *dgst, int dlen,
                                      DSA *dsa);
static int cryptodev_dsa_verify(const unsigned char *dgst, int dgst_len,
                                DSA_SIG *sig, DSA *dsa);
static int cryptodev_mod_exp_dh(const DH *dh, BIGNUM *r, const BIGNUM *a,
                                const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx,
                                BN_MONT_CTX *m_ctx);
static int cryptodev_dh_compute_key(unsigned char *key, const BIGNUM *pub_key,
                                    DH *dh);
static int cryptodev_ctrl(ENGINE *e, int cmd, long i, void *p,
                          void (*f) (void));
void ENGINE_load_cryptodev(void);

static const ENGINE_CMD_DEFN cryptodev_defns[] = {
    {0, NULL, NULL, 0}
};

static struct {
    int id;
    int nid;
    int ivmax;
    int keylen;
} ciphers[] = {
    {
        CRYPTO_ARC4, NID_rc4, 0, 16,
    },
    {
        CRYPTO_DES_CBC, NID_des_cbc, 8, 8,
    },
    {
        CRYPTO_3DES_CBC, NID_des_ede3_cbc, 8, 24,
    },
    {
        CRYPTO_AES_CBC, NID_aes_128_cbc, 16, 16,
    },
    {
        CRYPTO_AES_CBC, NID_aes_192_cbc, 16, 24,
    },
    {
        CRYPTO_AES_CBC, NID_aes_256_cbc, 16, 32,
    },
# ifdef CRYPTO_AES_CTR
    {
        CRYPTO_AES_CTR, NID_aes_128_ctr, 14, 16,
    },
    {
        CRYPTO_AES_CTR, NID_aes_192_ctr, 14, 24,
    },
    {
        CRYPTO_AES_CTR, NID_aes_256_ctr, 14, 32,
    },
# endif
    {
        CRYPTO_BLF_CBC, NID_bf_cbc, 8, 16,
    },
    {
        CRYPTO_CAST_CBC, NID_cast5_cbc, 8, 16,
    },
    {
        CRYPTO_SKIPJACK_CBC, NID_undef, 0, 0,
    },
    {
        0, NID_undef, 0, 0,
    },
};

# ifdef USE_CRYPTODEV_DIGESTS
static struct {
    int id;
    int nid;
    int keylen;
} digests[] = {
    {
        CRYPTO_MD5_HMAC, NID_hmacWithMD5, 16
    },
    {
        CRYPTO_SHA1_HMAC, NID_hmacWithSHA1, 20
    },
    {
        CRYPTO_RIPEMD160_HMAC, NID_ripemd160, 16
        /* ? */
    },
    {
        CRYPTO_MD5_KPDK, NID_undef, 0
    },
    {
        CRYPTO_SHA1_KPDK, NID_undef, 0
    },
    {
        CRYPTO_MD5, NID_md5, 16
    },
    {
        CRYPTO_SHA1, NID_sha1, 20
    },
    {
        0, NID_undef, 0
    },
};
# endif

/*
 * Return a fd if /dev/crypto seems usable, 0 otherwise.
 */
static int open_dev_crypto(void)
{
    static int fd = -1;

    if (fd == -1) {
        if ((fd = open("/dev/crypto", O_RDWR, 0)) == -1)
            return (-1);
        /* close on exec */
        if (fcntl(fd, F_SETFD, 1) == -1) {
            close(fd);
            fd = -1;
            return (-1);
        }
    }
    return (fd);
}

static int get_dev_crypto(void)
{
    int fd, retfd;

    if ((fd = open_dev_crypto()) == -1)
        return (-1);
# ifndef CRIOGET_NOT_NEEDED
    if (ioctl(fd, CRIOGET, &retfd) == -1)
        return (-1);

    /* close on exec */
    if (fcntl(retfd, F_SETFD, 1) == -1) {
        close(retfd);
        return (-1);
    }
# else
    retfd = fd;
# endif
    return (retfd);
}

static void put_dev_crypto(int fd)
{
# ifndef CRIOGET_NOT_NEEDED
    close(fd);
# endif
}

/* Caching version for asym operations */
static int get_asym_dev_crypto(void)
{
    static int fd = -1;

    if (fd == -1)
        fd = get_dev_crypto();
    return fd;
}

/*
 * Find out what ciphers /dev/crypto will let us have a session for.
 * XXX note, that some of these openssl doesn't deal with yet!
 * returning them here is harmless, as long as we return NULL
 * when asked for a handler in the cryptodev_engine_ciphers routine
 */
static int get_cryptodev_ciphers(const int **cnids)
{
    static int nids[CRYPTO_ALGORITHM_MAX];
    struct session_op sess;
    int fd, i, count = 0;

    if ((fd = get_dev_crypto()) < 0) {
        *cnids = NULL;
        return (0);
    }
    memset(&sess, 0, sizeof(sess));
    sess.key = (caddr_t) "123456789abcdefghijklmno";

    for (i = 0; ciphers[i].id && count < CRYPTO_ALGORITHM_MAX; i++) {
        if (ciphers[i].nid == NID_undef)
            continue;
        sess.cipher = ciphers[i].id;
        sess.keylen = ciphers[i].keylen;
        sess.mac = 0;
        if (ioctl(fd, CIOCGSESSION, &sess) != -1 &&
            ioctl(fd, CIOCFSESSION, &sess.ses) != -1)
            nids[count++] = ciphers[i].nid;
    }
    put_dev_crypto(fd);

    if (count > 0)
        *cnids = nids;
    else
        *cnids = NULL;
    return (count);
}

# ifdef USE_CRYPTODEV_DIGESTS
/*
 * Find out what digests /dev/crypto will let us have a session for.
 * XXX note, that some of these openssl doesn't deal with yet!
 * returning them here is harmless, as long as we return NULL
 * when asked for a handler in the cryptodev_engine_digests routine
 */
static int get_cryptodev_digests(const int **cnids)
{
    static int nids[CRYPTO_ALGORITHM_MAX];
    struct session_op sess;
    int fd, i, count = 0;

    if ((fd = get_dev_crypto()) < 0) {
        *cnids = NULL;
        return (0);
    }
    memset(&sess, 0, sizeof(sess));
    sess.mackey = (caddr_t) "123456789abcdefghijklmno";
    for (i = 0; digests[i].id && count < CRYPTO_ALGORITHM_MAX; i++) {
        if (digests[i].nid == NID_undef)
            continue;
        sess.mac = digests[i].id;
        sess.mackeylen = digests[i].keylen;
        sess.cipher = 0;
        if (ioctl(fd, CIOCGSESSION, &sess) != -1 &&
            ioctl(fd, CIOCFSESSION, &sess.ses) != -1)
            nids[count++] = digests[i].nid;
    }
    put_dev_crypto(fd);

    if (count > 0)
        *cnids = nids;
    else
        *cnids = NULL;
    return (count);
}
# endif                         /* 0 */

/*
 * Find the useable ciphers|digests from dev/crypto - this is the first
 * thing called by the engine init crud which determines what it
 * can use for ciphers from this engine. We want to return
 * only what we can do, anythine else is handled by software.
 *
 * If we can't initialize the device to do anything useful for
 * any reason, we want to return a NULL array, and 0 length,
 * which forces everything to be done is software. By putting
 * the initalization of the device in here, we ensure we can
 * use this engine as the default, and if for whatever reason
 * /dev/crypto won't do what we want it will just be done in
 * software
 *
 * This can (should) be greatly expanded to perhaps take into
 * account speed of the device, and what we want to do.
 * (although the disabling of particular alg's could be controlled
 * by the device driver with sysctl's.) - this is where we
 * want most of the decisions made about what we actually want
 * to use from /dev/crypto.
 */
static int cryptodev_usable_ciphers(const int **nids)
{
    return (get_cryptodev_ciphers(nids));
}

static int cryptodev_usable_digests(const int **nids)
{
# ifdef USE_CRYPTODEV_DIGESTS
    return (get_cryptodev_digests(nids));
# else
    /*
     * XXXX just disable all digests for now, because it sucks.
     * we need a better way to decide this - i.e. I may not
     * want digests on slow cards like hifn on fast machines,
     * but might want them on slow or loaded machines, etc.
     * will also want them when using crypto cards that don't
     * suck moose gonads - would be nice to be able to decide something
     * as reasonable default without having hackery that's card dependent.
     * of course, the default should probably be just do everything,
     * with perhaps a sysctl to turn algoritms off (or have them off
     * by default) on cards that generally suck like the hifn.
     */
    *nids = NULL;
    return (0);
# endif
}

static int
cryptodev_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                 const unsigned char *in, size_t inl)
{
    struct crypt_op cryp;
    struct dev_crypto_state *state = ctx->cipher_data;
    struct session_op *sess = &state->d_sess;
    const void *iiv;
    unsigned char save_iv[EVP_MAX_IV_LENGTH];

    if (state->d_fd < 0)
        return (0);
    if (!inl)
        return (1);
    if ((inl % ctx->cipher->block_size) != 0)
        return (0);

    memset(&cryp, 0, sizeof(cryp));

    cryp.ses = sess->ses;
    cryp.flags = 0;
    cryp.len = inl;
    cryp.src = (caddr_t) in;
    cryp.dst = (caddr_t) out;
    cryp.mac = 0;

    cryp.op = ctx->encrypt ? COP_ENCRYPT : COP_DECRYPT;

    if (ctx->cipher->iv_len) {
        cryp.iv = (caddr_t) ctx->iv;
        if (!ctx->encrypt) {
            iiv = in + inl - ctx->cipher->iv_len;
            memcpy(save_iv, iiv, ctx->cipher->iv_len);
        }
    } else
        cryp.iv = NULL;

    if (ioctl(state->d_fd, CIOCCRYPT, &cryp) == -1) {
        /*
         * XXX need better errror handling this can fail for a number of
         * different reasons.
         */
        return (0);
    }

    if (ctx->cipher->iv_len) {
        if (ctx->encrypt)
            iiv = out + inl - ctx->cipher->iv_len;
        else
            iiv = save_iv;
        memcpy(ctx->iv, iiv, ctx->cipher->iv_len);
    }
    return (1);
}

static int
cryptodev_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                   const unsigned char *iv, int enc)
{
    struct dev_crypto_state *state = ctx->cipher_data;
    struct session_op *sess = &state->d_sess;
    int cipher = -1, i;

    for (i = 0; ciphers[i].id; i++)
        if (ctx->cipher->nid == ciphers[i].nid &&
            ctx->cipher->iv_len <= ciphers[i].ivmax &&
            ctx->key_len == ciphers[i].keylen) {
            cipher = ciphers[i].id;
            break;
        }

    if (!ciphers[i].id) {
        state->d_fd = -1;
        return (0);
    }

    memset(sess, 0, sizeof(struct session_op));

    if ((state->d_fd = get_dev_crypto()) < 0)
        return (0);

    sess->key = (caddr_t) key;
    sess->keylen = ctx->key_len;
    sess->cipher = cipher;

    if (ioctl(state->d_fd, CIOCGSESSION, sess) == -1) {
        put_dev_crypto(state->d_fd);
        state->d_fd = -1;
        return (0);
    }
    return (1);
}

/*
 * free anything we allocated earlier when initting a
 * session, and close the session.
 */
static int cryptodev_cleanup(EVP_CIPHER_CTX *ctx)
{
    int ret = 0;
    struct dev_crypto_state *state = ctx->cipher_data;
    struct session_op *sess = &state->d_sess;

    if (state->d_fd < 0)
        return (0);

    /*
     * XXX if this ioctl fails, someting's wrong. the invoker may have called
     * us with a bogus ctx, or we could have a device that for whatever
     * reason just doesn't want to play ball - it's not clear what's right
     * here - should this be an error? should it just increase a counter,
     * hmm. For right now, we return 0 - I don't believe that to be "right".
     * we could call the gorpy openssl lib error handlers that print messages
     * to users of the library. hmm..
     */

    if (ioctl(state->d_fd, CIOCFSESSION, &sess->ses) == -1) {
        ret = 0;
    } else {
        ret = 1;
    }
    put_dev_crypto(state->d_fd);
    state->d_fd = -1;

    return (ret);
}

/*
 * libcrypto EVP stuff - this is how we get wired to EVP so the engine
 * gets called when libcrypto requests a cipher NID.
 */

/* RC4 */
const EVP_CIPHER cryptodev_rc4 = {
    NID_rc4,
    1, 16, 0,
    EVP_CIPH_VARIABLE_LENGTH,
    cryptodev_init_key,
    cryptodev_cipher,
    cryptodev_cleanup,
    sizeof(struct dev_crypto_state),
    NULL,
    NULL,
    NULL
};

/* DES CBC EVP */
const EVP_CIPHER cryptodev_des_cbc = {
    NID_des_cbc,
    8, 8, 8,
    EVP_CIPH_CBC_MODE,
    cryptodev_init_key,
    cryptodev_cipher,
    cryptodev_cleanup,
    sizeof(struct dev_crypto_state),
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL
};

/* 3DES CBC EVP */
const EVP_CIPHER cryptodev_3des_cbc = {
    NID_des_ede3_cbc,
    8, 24, 8,
    EVP_CIPH_CBC_MODE,
    cryptodev_init_key,
    cryptodev_cipher,
    cryptodev_cleanup,
    sizeof(struct dev_crypto_state),
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL
};

const EVP_CIPHER cryptodev_bf_cbc = {
    NID_bf_cbc,
    8, 16, 8,
    EVP_CIPH_CBC_MODE,
    cryptodev_init_key,
    cryptodev_cipher,
    cryptodev_cleanup,
    sizeof(struct dev_crypto_state),
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL
};

const EVP_CIPHER cryptodev_cast_cbc = {
    NID_cast5_cbc,
    8, 16, 8,
    EVP_CIPH_CBC_MODE,
    cryptodev_init_key,
    cryptodev_cipher,
    cryptodev_cleanup,
    sizeof(struct dev_crypto_state),
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL
};

const EVP_CIPHER cryptodev_aes_cbc = {
    NID_aes_128_cbc,
    16, 16, 16,
    EVP_CIPH_CBC_MODE,
    cryptodev_init_key,
    cryptodev_cipher,
    cryptodev_cleanup,
    sizeof(struct dev_crypto_state),
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL
};

const EVP_CIPHER cryptodev_aes_192_cbc = {
    NID_aes_192_cbc,
    16, 24, 16,
    EVP_CIPH_CBC_MODE,
    cryptodev_init_key,
    cryptodev_cipher,
    cryptodev_cleanup,
    sizeof(struct dev_crypto_state),
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL
};

const EVP_CIPHER cryptodev_aes_256_cbc = {
    NID_aes_256_cbc,
    16, 32, 16,
    EVP_CIPH_CBC_MODE,
    cryptodev_init_key,
    cryptodev_cipher,
    cryptodev_cleanup,
    sizeof(struct dev_crypto_state),
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL
};

# ifdef CRYPTO_AES_CTR
const EVP_CIPHER cryptodev_aes_ctr = {
    NID_aes_128_ctr,
    16, 16, 14,
    EVP_CIPH_CTR_MODE,
    cryptodev_init_key,
    cryptodev_cipher,
    cryptodev_cleanup,
    sizeof(struct dev_crypto_state),
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL
};

const EVP_CIPHER cryptodev_aes_ctr_192 = {
    NID_aes_192_ctr,
    16, 24, 14,
    EVP_CIPH_CTR_MODE,
    cryptodev_init_key,
    cryptodev_cipher,
    cryptodev_cleanup,
    sizeof(struct dev_crypto_state),
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL
};

const EVP_CIPHER cryptodev_aes_ctr_256 = {
    NID_aes_256_ctr,
    16, 32, 14,
    EVP_CIPH_CTR_MODE,
    cryptodev_init_key,
    cryptodev_cipher,
    cryptodev_cleanup,
    sizeof(struct dev_crypto_state),
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL
};
# endif
/*
 * Registered by the ENGINE when used to find out how to deal with
 * a particular NID in the ENGINE. this says what we'll do at the
 * top level - note, that list is restricted by what we answer with
 */
static int
cryptodev_engine_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                         const int **nids, int nid)
{
    if (!cipher)
        return (cryptodev_usable_ciphers(nids));

    switch (nid) {
    case NID_rc4:
        *cipher = &cryptodev_rc4;
        break;
    case NID_des_ede3_cbc:
        *cipher = &cryptodev_3des_cbc;
        break;
    case NID_des_cbc:
        *cipher = &cryptodev_des_cbc;
        break;
    case NID_bf_cbc:
        *cipher = &cryptodev_bf_cbc;
        break;
    case NID_cast5_cbc:
        *cipher = &cryptodev_cast_cbc;
        break;
    case NID_aes_128_cbc:
        *cipher = &cryptodev_aes_cbc;
        break;
    case NID_aes_192_cbc:
        *cipher = &cryptodev_aes_192_cbc;
        break;
    case NID_aes_256_cbc:
        *cipher = &cryptodev_aes_256_cbc;
        break;
# ifdef CRYPTO_AES_CTR
    case NID_aes_128_ctr:
        *cipher = &cryptodev_aes_ctr;
        break;
    case NID_aes_192_ctr:
        *cipher = &cryptodev_aes_ctr_192;
        break;
    case NID_aes_256_ctr:
        *cipher = &cryptodev_aes_ctr_256;
        break;
# endif
    default:
        *cipher = NULL;
        break;
    }
    return (*cipher != NULL);
}

# ifdef USE_CRYPTODEV_DIGESTS

/* convert digest type to cryptodev */
static int digest_nid_to_cryptodev(int nid)
{
    int i;

    for (i = 0; digests[i].id; i++)
        if (digests[i].nid == nid)
            return (digests[i].id);
    return (0);
}

static int digest_key_length(int nid)
{
    int i;

    for (i = 0; digests[i].id; i++)
        if (digests[i].nid == nid)
            return digests[i].keylen;
    return (0);
}

static int cryptodev_digest_init(EVP_MD_CTX *ctx)
{
    struct dev_crypto_state *state = ctx->md_data;
    struct session_op *sess = &state->d_sess;
    int digest;

    if ((digest = digest_nid_to_cryptodev(ctx->digest->type)) == NID_undef) {
        printf("cryptodev_digest_init: Can't get digest \n");
        return (0);
    }

    memset(state, 0, sizeof(struct dev_crypto_state));

    if ((state->d_fd = get_dev_crypto()) < 0) {
        printf("cryptodev_digest_init: Can't get Dev \n");
        return (0);
    }

    sess->mackey = state->dummy_mac_key;
    sess->mackeylen = digest_key_length(ctx->digest->type);
    sess->mac = digest;

    if (ioctl(state->d_fd, CIOCGSESSION, sess) < 0) {
        put_dev_crypto(state->d_fd);
        state->d_fd = -1;
        printf("cryptodev_digest_init: Open session failed\n");
        return (0);
    }

    return (1);
}

static int cryptodev_digest_update(EVP_MD_CTX *ctx, const void *data,
                                   size_t count)
{
    struct crypt_op cryp;
    struct dev_crypto_state *state = ctx->md_data;
    struct session_op *sess = &state->d_sess;

    if (!data || state->d_fd < 0) {
        printf("cryptodev_digest_update: illegal inputs \n");
        return (0);
    }

    if (!count) {
        return (0);
    }

    if (!(ctx->flags & EVP_MD_CTX_FLAG_ONESHOT)) {
        /* if application doesn't support one buffer */
        char *mac_data =
            OPENSSL_realloc(state->mac_data, state->mac_len + count);

        if (mac_data == NULL) {
            printf("cryptodev_digest_update: realloc failed\n");
            return (0);
        }

        state->mac_data = mac_data;
        memcpy(state->mac_data + state->mac_len, data, count);
        state->mac_len += count;

        return (1);
    }

    memset(&cryp, 0, sizeof(cryp));

    cryp.ses = sess->ses;
    cryp.flags = 0;
    cryp.len = count;
    cryp.src = (caddr_t) data;
    cryp.dst = NULL;
    cryp.mac = (caddr_t) state->digest_res;
    if (ioctl(state->d_fd, CIOCCRYPT, &cryp) < 0) {
        printf("cryptodev_digest_update: digest failed\n");
        return (0);
    }
    return (1);
}

static int cryptodev_digest_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    struct crypt_op cryp;
    struct dev_crypto_state *state = ctx->md_data;
    struct session_op *sess = &state->d_sess;

    int ret = 1;

    if (!md || state->d_fd < 0) {
        printf("cryptodev_digest_final: illegal input\n");
        return (0);
    }

    if (!(ctx->flags & EVP_MD_CTX_FLAG_ONESHOT)) {
        /* if application doesn't support one buffer */
        memset(&cryp, 0, sizeof(cryp));
        cryp.ses = sess->ses;
        cryp.flags = 0;
        cryp.len = state->mac_len;
        cryp.src = state->mac_data;
        cryp.dst = NULL;
        cryp.mac = (caddr_t) md;
        if (ioctl(state->d_fd, CIOCCRYPT, &cryp) < 0) {
            printf("cryptodev_digest_final: digest failed\n");
            return (0);
        }

        return 1;
    }

    memcpy(md, state->digest_res, ctx->digest->md_size);

    return (ret);
}

static int cryptodev_digest_cleanup(EVP_MD_CTX *ctx)
{
    int ret = 1;
    struct dev_crypto_state *state = ctx->md_data;
    struct session_op *sess = &state->d_sess;

    if (state == NULL)
        return 0;

    if (state->d_fd < 0) {
        printf("cryptodev_digest_cleanup: illegal input\n");
        return (0);
    }

    if (state->mac_data) {
        OPENSSL_free(state->mac_data);
        state->mac_data = NULL;
        state->mac_len = 0;
    }

    if (ioctl(state->d_fd, CIOCFSESSION, &sess->ses) < 0) {
        printf("cryptodev_digest_cleanup: failed to close session\n");
        ret = 0;
    } else {
        ret = 1;
    }
    put_dev_crypto(state->d_fd);
    state->d_fd = -1;

    return (ret);
}

static int cryptodev_digest_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
    struct dev_crypto_state *fstate = from->md_data;
    struct dev_crypto_state *dstate = to->md_data;
    struct session_op *sess;
    int digest;

    if (dstate == NULL || fstate == NULL)
        return 1;

    memcpy(dstate, fstate, sizeof(struct dev_crypto_state));

    sess = &dstate->d_sess;

    digest = digest_nid_to_cryptodev(to->digest->type);

    sess->mackey = dstate->dummy_mac_key;
    sess->mackeylen = digest_key_length(to->digest->type);
    sess->mac = digest;

    dstate->d_fd = get_dev_crypto();

    if (ioctl(dstate->d_fd, CIOCGSESSION, sess) < 0) {
        put_dev_crypto(dstate->d_fd);
        dstate->d_fd = -1;
        printf("cryptodev_digest_init: Open session failed\n");
        return (0);
    }

    dstate->mac_len = fstate->mac_len;
    if (fstate->mac_len != 0) {
        if (fstate->mac_data != NULL) {
            dstate->mac_data = OPENSSL_malloc(fstate->mac_len);
            if (dstate->mac_data == NULL) {
                printf("cryptodev_digest_init: malloc failed\n");
                return 0;
            }
            memcpy(dstate->mac_data, fstate->mac_data, fstate->mac_len);
        }
    }

    return 1;
}

const EVP_MD cryptodev_sha1 = {
    NID_sha1,
    NID_undef,
    SHA_DIGEST_LENGTH,
    EVP_MD_FLAG_ONESHOT,
    cryptodev_digest_init,
    cryptodev_digest_update,
    cryptodev_digest_final,
    cryptodev_digest_copy,
    cryptodev_digest_cleanup,
    EVP_PKEY_NULL_method,
    SHA_CBLOCK,
    sizeof(struct dev_crypto_state),
};

const EVP_MD cryptodev_md5 = {
    NID_md5,
    NID_undef,
    16 /* MD5_DIGEST_LENGTH */ ,
    EVP_MD_FLAG_ONESHOT,
    cryptodev_digest_init,
    cryptodev_digest_update,
    cryptodev_digest_final,
    cryptodev_digest_copy,
    cryptodev_digest_cleanup,
    EVP_PKEY_NULL_method,
    64 /* MD5_CBLOCK */ ,
    sizeof(struct dev_crypto_state),
};

# endif                         /* USE_CRYPTODEV_DIGESTS */

static int
cryptodev_engine_digests(ENGINE *e, const EVP_MD **digest,
                         const int **nids, int nid)
{
    if (!digest)
        return (cryptodev_usable_digests(nids));

    switch (nid) {
# ifdef USE_CRYPTODEV_DIGESTS
    case NID_md5:
        *digest = &cryptodev_md5;
        break;
    case NID_sha1:
        *digest = &cryptodev_sha1;
        break;
    default:
# endif                         /* USE_CRYPTODEV_DIGESTS */
        *digest = NULL;
        break;
    }
    return (*digest != NULL);
}

/*
 * Convert a BIGNUM to the representation that /dev/crypto needs.
 * Upon completion of use, the caller is responsible for freeing
 * crp->crp_p.
 */
static int bn2crparam(const BIGNUM *a, struct crparam *crp)
{
    int i, j, k;
    ssize_t bytes, bits;
    u_char *b;

    crp->crp_p = NULL;
    crp->crp_nbits = 0;

    bits = BN_num_bits(a);
    bytes = (bits + 7) / 8;

    b = malloc(bytes);
    if (b == NULL)
        return (1);
    memset(b, 0, bytes);

    crp->crp_p = (caddr_t) b;
    crp->crp_nbits = bits;

    for (i = 0, j = 0; i < a->top; i++) {
        for (k = 0; k < BN_BITS2 / 8; k++) {
            if ((j + k) >= bytes)
                return (0);
            b[j + k] = a->d[i] >> (k * 8);
        }
        j += BN_BITS2 / 8;
    }
    return (0);
}

/* Convert a /dev/crypto parameter to a BIGNUM */
static int crparam2bn(struct crparam *crp, BIGNUM *a)
{
    u_int8_t *pd;
    int i, bytes;

    bytes = (crp->crp_nbits + 7) / 8;

    if (bytes == 0)
        return (-1);

    if ((pd = (u_int8_t *) malloc(bytes)) == NULL)
        return (-1);

    for (i = 0; i < bytes; i++)
        pd[i] = ((char *)crp->crp_p)[bytes - i - 1];

    BN_bin2bn(pd, bytes, a);
    free(pd);

    return (0);
}

static void zapparams(struct crypt_kop *kop)
{
    int i;

    for (i = 0; i < kop->crk_iparams + kop->crk_oparams; i++) {
        OPENSSL_free(kop->crk_param[i].crp_p);
        kop->crk_param[i].crp_p = NULL;
        kop->crk_param[i].crp_nbits = 0;
    }
}

static int
cryptodev_asym(struct crypt_kop *kop, int rlen, BIGNUM *r, int slen,
               BIGNUM *s)
{
    int fd, ret = -1;

    if ((fd = get_asym_dev_crypto()) < 0)
        return ret;

    if (r) {
        kop->crk_param[kop->crk_iparams].crp_p = OPENSSL_malloc(rlen);
        if (kop->crk_param[kop->crk_iparams].crp_p == NULL)
            return ret;
        memset(kop->crk_param[kop->crk_iparams].crp_p, 0, (size_t)rlen);
        kop->crk_param[kop->crk_iparams].crp_nbits = rlen * 8;
        kop->crk_oparams++;
    }
    if (s) {
        kop->crk_param[kop->crk_iparams + 1].crp_p = OPENSSL_malloc(slen);
        /* No need to free the kop->crk_iparams parameter if it was allocated,
         * callers of this routine have to free allocated parameters through
         * zapparams both in case of success and failure
         */
        if (kop->crk_param[kop->crk_iparams+1].crp_p == NULL)
            return ret;
        memset(kop->crk_param[kop->crk_iparams + 1].crp_p, 0, (size_t)slen);
        kop->crk_param[kop->crk_iparams + 1].crp_nbits = slen * 8;
        kop->crk_oparams++;
    }

    if (ioctl(fd, CIOCKEY, kop) == 0) {
        if (r)
            crparam2bn(&kop->crk_param[kop->crk_iparams], r);
        if (s)
            crparam2bn(&kop->crk_param[kop->crk_iparams + 1], s);
        ret = 0;
    }

    return ret;
}

static int
cryptodev_bn_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                     const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *in_mont)
{
    struct crypt_kop kop;
    int ret = 1;

    /*
     * Currently, we know we can do mod exp iff we can do any asymmetric
     * operations at all.
     */
    if (cryptodev_asymfeat == 0) {
        ret = BN_mod_exp(r, a, p, m, ctx);
        return (ret);
    }

    memset(&kop, 0, sizeof(kop));
    kop.crk_op = CRK_MOD_EXP;

    /* inputs: a^p % m */
    if (bn2crparam(a, &kop.crk_param[0]))
        goto err;
    if (bn2crparam(p, &kop.crk_param[1]))
        goto err;
    if (bn2crparam(m, &kop.crk_param[2]))
        goto err;
    kop.crk_iparams = 3;

    if (cryptodev_asym(&kop, BN_num_bytes(m), r, 0, NULL)) {
        const RSA_METHOD *meth = RSA_PKCS1_SSLeay();
        printf("OCF asym process failed, Running in software\n");
        ret = meth->bn_mod_exp(r, a, p, m, ctx, in_mont);

    } else if (ECANCELED == kop.crk_status) {
        const RSA_METHOD *meth = RSA_PKCS1_SSLeay();
        printf("OCF hardware operation cancelled. Running in Software\n");
        ret = meth->bn_mod_exp(r, a, p, m, ctx, in_mont);
    }
    /* else cryptodev operation worked ok ==> ret = 1 */

 err:
    zapparams(&kop);
    return (ret);
}

static int
cryptodev_rsa_nocrt_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa,
                            BN_CTX *ctx)
{
    int r;
    ctx = BN_CTX_new();
    r = cryptodev_bn_mod_exp(r0, I, rsa->d, rsa->n, ctx, NULL);
    BN_CTX_free(ctx);
    return (r);
}

static int
cryptodev_rsa_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx)
{
    struct crypt_kop kop;
    int ret = 1;

    if (!rsa->p || !rsa->q || !rsa->dmp1 || !rsa->dmq1 || !rsa->iqmp) {
        /* XXX 0 means failure?? */
        return (0);
    }

    memset(&kop, 0, sizeof(kop));
    kop.crk_op = CRK_MOD_EXP_CRT;
    /* inputs: rsa->p rsa->q I rsa->dmp1 rsa->dmq1 rsa->iqmp */
    if (bn2crparam(rsa->p, &kop.crk_param[0]))
        goto err;
    if (bn2crparam(rsa->q, &kop.crk_param[1]))
        goto err;
    if (bn2crparam(I, &kop.crk_param[2]))
        goto err;
    if (bn2crparam(rsa->dmp1, &kop.crk_param[3]))
        goto err;
    if (bn2crparam(rsa->dmq1, &kop.crk_param[4]))
        goto err;
    if (bn2crparam(rsa->iqmp, &kop.crk_param[5]))
        goto err;
    kop.crk_iparams = 6;

    if (cryptodev_asym(&kop, BN_num_bytes(rsa->n), r0, 0, NULL)) {
        const RSA_METHOD *meth = RSA_PKCS1_SSLeay();
        printf("OCF asym process failed, running in Software\n");
        ret = (*meth->rsa_mod_exp) (r0, I, rsa, ctx);

    } else if (ECANCELED == kop.crk_status) {
        const RSA_METHOD *meth = RSA_PKCS1_SSLeay();
        printf("OCF hardware operation cancelled. Running in Software\n");
        ret = (*meth->rsa_mod_exp) (r0, I, rsa, ctx);
    }
    /* else cryptodev operation worked ok ==> ret = 1 */

 err:
    zapparams(&kop);
    return (ret);
}

static RSA_METHOD cryptodev_rsa = {
    "cryptodev RSA method",
    NULL,                       /* rsa_pub_enc */
    NULL,                       /* rsa_pub_dec */
    NULL,                       /* rsa_priv_enc */
    NULL,                       /* rsa_priv_dec */
    NULL,
    NULL,
    NULL,                       /* init */
    NULL,                       /* finish */
    0,                          /* flags */
    NULL,                       /* app_data */
    NULL,                       /* rsa_sign */
    NULL                        /* rsa_verify */
};

static int
cryptodev_dsa_bn_mod_exp(DSA *dsa, BIGNUM *r, BIGNUM *a, const BIGNUM *p,
                         const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
{
    return (cryptodev_bn_mod_exp(r, a, p, m, ctx, m_ctx));
}

static int
cryptodev_dsa_dsa_mod_exp(DSA *dsa, BIGNUM *t1, BIGNUM *g,
                          BIGNUM *u1, BIGNUM *pub_key, BIGNUM *u2, BIGNUM *p,
                          BN_CTX *ctx, BN_MONT_CTX *mont)
{
    BIGNUM t2;
    int ret = 0;

    BN_init(&t2);

    /* v = ( g^u1 * y^u2 mod p ) mod q */
    /* let t1 = g ^ u1 mod p */
    ret = 0;

    if (!dsa->meth->bn_mod_exp(dsa, t1, dsa->g, u1, dsa->p, ctx, mont))
        goto err;

    /* let t2 = y ^ u2 mod p */
    if (!dsa->meth->bn_mod_exp(dsa, &t2, dsa->pub_key, u2, dsa->p, ctx, mont))
        goto err;
    /* let u1 = t1 * t2 mod p */
    if (!BN_mod_mul(u1, t1, &t2, dsa->p, ctx))
        goto err;

    BN_copy(t1, u1);

    ret = 1;
 err:
    BN_free(&t2);
    return (ret);
}

static DSA_SIG *cryptodev_dsa_do_sign(const unsigned char *dgst, int dlen,
                                      DSA *dsa)
{
    struct crypt_kop kop;
    BIGNUM *r = NULL, *s = NULL;
    DSA_SIG *dsaret = NULL;

    if ((r = BN_new()) == NULL)
        goto err;
    if ((s = BN_new()) == NULL) {
        BN_free(r);
        goto err;
    }

    memset(&kop, 0, sizeof(kop));
    kop.crk_op = CRK_DSA_SIGN;

    /* inputs: dgst dsa->p dsa->q dsa->g dsa->priv_key */
    kop.crk_param[0].crp_p = (caddr_t) dgst;
    kop.crk_param[0].crp_nbits = dlen * 8;
    if (bn2crparam(dsa->p, &kop.crk_param[1]))
        goto err;
    if (bn2crparam(dsa->q, &kop.crk_param[2]))
        goto err;
    if (bn2crparam(dsa->g, &kop.crk_param[3]))
        goto err;
    if (bn2crparam(dsa->priv_key, &kop.crk_param[4]))
        goto err;
    kop.crk_iparams = 5;

    if (cryptodev_asym(&kop, BN_num_bytes(dsa->q), r,
                       BN_num_bytes(dsa->q), s) == 0) {
        dsaret = DSA_SIG_new();
        if (dsaret == NULL)
            goto err;
        dsaret->r = r;
        dsaret->s = s;
        r = s = NULL;
    } else {
        const DSA_METHOD *meth = DSA_OpenSSL();
        dsaret = (meth->dsa_do_sign) (dgst, dlen, dsa);
    }
 err:
    BN_free(r);
    BN_free(s);
    kop.crk_param[0].crp_p = NULL;
    zapparams(&kop);
    return (dsaret);
}

static int
cryptodev_dsa_verify(const unsigned char *dgst, int dlen,
                     DSA_SIG *sig, DSA *dsa)
{
    struct crypt_kop kop;
    int dsaret = 1;

    memset(&kop, 0, sizeof(kop));
    kop.crk_op = CRK_DSA_VERIFY;

    /* inputs: dgst dsa->p dsa->q dsa->g dsa->pub_key sig->r sig->s */
    kop.crk_param[0].crp_p = (caddr_t) dgst;
    kop.crk_param[0].crp_nbits = dlen * 8;
    if (bn2crparam(dsa->p, &kop.crk_param[1]))
        goto err;
    if (bn2crparam(dsa->q, &kop.crk_param[2]))
        goto err;
    if (bn2crparam(dsa->g, &kop.crk_param[3]))
        goto err;
    if (bn2crparam(dsa->pub_key, &kop.crk_param[4]))
        goto err;
    if (bn2crparam(sig->r, &kop.crk_param[5]))
        goto err;
    if (bn2crparam(sig->s, &kop.crk_param[6]))
        goto err;
    kop.crk_iparams = 7;

    if (cryptodev_asym(&kop, 0, NULL, 0, NULL) == 0) {
        /*
         * OCF success value is 0, if not zero, change dsaret to fail
         */
        if (0 != kop.crk_status)
            dsaret = 0;
    } else {
        const DSA_METHOD *meth = DSA_OpenSSL();

        dsaret = (meth->dsa_do_verify) (dgst, dlen, sig, dsa);
    }
 err:
    kop.crk_param[0].crp_p = NULL;
    zapparams(&kop);
    return (dsaret);
}

static DSA_METHOD cryptodev_dsa = {
    "cryptodev DSA method",
    NULL,
    NULL,                       /* dsa_sign_setup */
    NULL,
    NULL,                       /* dsa_mod_exp */
    NULL,
    NULL,                       /* init */
    NULL,                       /* finish */
    0,                          /* flags */
    NULL                        /* app_data */
};

static int
cryptodev_mod_exp_dh(const DH *dh, BIGNUM *r, const BIGNUM *a,
                     const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx,
                     BN_MONT_CTX *m_ctx)
{
    return (cryptodev_bn_mod_exp(r, a, p, m, ctx, m_ctx));
}

static int
cryptodev_dh_compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh)
{
    struct crypt_kop kop;
    int dhret = 1;
    int fd, keylen;

    if ((fd = get_asym_dev_crypto()) < 0) {
        const DH_METHOD *meth = DH_OpenSSL();

        return ((meth->compute_key) (key, pub_key, dh));
    }

    keylen = BN_num_bits(dh->p);

    memset(&kop, 0, sizeof(kop));
    kop.crk_op = CRK_DH_COMPUTE_KEY;

    /* inputs: dh->priv_key pub_key dh->p key */
    if (bn2crparam(dh->priv_key, &kop.crk_param[0]))
        goto err;
    if (bn2crparam(pub_key, &kop.crk_param[1]))
        goto err;
    if (bn2crparam(dh->p, &kop.crk_param[2]))
        goto err;
    kop.crk_iparams = 3;

    kop.crk_param[3].crp_p = (caddr_t) key;
    kop.crk_param[3].crp_nbits = keylen * 8;
    kop.crk_oparams = 1;

    if (ioctl(fd, CIOCKEY, &kop) == -1) {
        const DH_METHOD *meth = DH_OpenSSL();

        dhret = (meth->compute_key) (key, pub_key, dh);
    }
 err:
    kop.crk_param[3].crp_p = NULL;
    zapparams(&kop);
    return (dhret);
}

static DH_METHOD cryptodev_dh = {
    "cryptodev DH method",
    NULL,                       /* cryptodev_dh_generate_key */
    NULL,
    NULL,
    NULL,
    NULL,
    0,                          /* flags */
    NULL                        /* app_data */
};

/*
 * ctrl right now is just a wrapper that doesn't do much
 * but I expect we'll want some options soon.
 */
static int
cryptodev_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f) (void))
{
# ifdef HAVE_SYSLOG_R
    struct syslog_data sd = SYSLOG_DATA_INIT;
# endif

    switch (cmd) {
    default:
# ifdef HAVE_SYSLOG_R
        syslog_r(LOG_ERR, &sd, "cryptodev_ctrl: unknown command %d", cmd);
# else
        syslog(LOG_ERR, "cryptodev_ctrl: unknown command %d", cmd);
# endif
        break;
    }
    return (1);
}

void ENGINE_load_cryptodev(void)
{
    ENGINE *engine = ENGINE_new();
    int fd;

    if (engine == NULL)
        return;
    if ((fd = get_dev_crypto()) < 0) {
        ENGINE_free(engine);
        return;
    }

    /*
     * find out what asymmetric crypto algorithms we support
     */
    if (ioctl(fd, CIOCASYMFEAT, &cryptodev_asymfeat) == -1) {
        put_dev_crypto(fd);
        ENGINE_free(engine);
        return;
    }
    put_dev_crypto(fd);

    if (!ENGINE_set_id(engine, "cryptodev") ||
        !ENGINE_set_name(engine, "BSD cryptodev engine") ||
        !ENGINE_set_ciphers(engine, cryptodev_engine_ciphers) ||
        !ENGINE_set_digests(engine, cryptodev_engine_digests) ||
        !ENGINE_set_ctrl_function(engine, cryptodev_ctrl) ||
        !ENGINE_set_cmd_defns(engine, cryptodev_defns)) {
        ENGINE_free(engine);
        return;
    }

    if (ENGINE_set_RSA(engine, &cryptodev_rsa)) {
        const RSA_METHOD *rsa_meth = RSA_PKCS1_SSLeay();

        cryptodev_rsa.bn_mod_exp = rsa_meth->bn_mod_exp;
        cryptodev_rsa.rsa_mod_exp = rsa_meth->rsa_mod_exp;
        cryptodev_rsa.rsa_pub_enc = rsa_meth->rsa_pub_enc;
        cryptodev_rsa.rsa_pub_dec = rsa_meth->rsa_pub_dec;
        cryptodev_rsa.rsa_priv_enc = rsa_meth->rsa_priv_enc;
        cryptodev_rsa.rsa_priv_dec = rsa_meth->rsa_priv_dec;
        if (cryptodev_asymfeat & CRF_MOD_EXP) {
            cryptodev_rsa.bn_mod_exp = cryptodev_bn_mod_exp;
            if (cryptodev_asymfeat & CRF_MOD_EXP_CRT)
                cryptodev_rsa.rsa_mod_exp = cryptodev_rsa_mod_exp;
            else
                cryptodev_rsa.rsa_mod_exp = cryptodev_rsa_nocrt_mod_exp;
        }
    }

    if (ENGINE_set_DSA(engine, &cryptodev_dsa)) {
        const DSA_METHOD *meth = DSA_OpenSSL();

        memcpy(&cryptodev_dsa, meth, sizeof(DSA_METHOD));
        if (cryptodev_asymfeat & CRF_DSA_SIGN)
            cryptodev_dsa.dsa_do_sign = cryptodev_dsa_do_sign;
        if (cryptodev_asymfeat & CRF_MOD_EXP) {
            cryptodev_dsa.bn_mod_exp = cryptodev_dsa_bn_mod_exp;
            cryptodev_dsa.dsa_mod_exp = cryptodev_dsa_dsa_mod_exp;
        }
        if (cryptodev_asymfeat & CRF_DSA_VERIFY)
            cryptodev_dsa.dsa_do_verify = cryptodev_dsa_verify;
    }

    if (ENGINE_set_DH(engine, &cryptodev_dh)) {
        const DH_METHOD *dh_meth = DH_OpenSSL();

        cryptodev_dh.generate_key = dh_meth->generate_key;
        cryptodev_dh.compute_key = dh_meth->compute_key;
        cryptodev_dh.bn_mod_exp = dh_meth->bn_mod_exp;
        if (cryptodev_asymfeat & CRF_MOD_EXP) {
            cryptodev_dh.bn_mod_exp = cryptodev_mod_exp_dh;
            if (cryptodev_asymfeat & CRF_DH_COMPUTE_KEY)
                cryptodev_dh.compute_key = cryptodev_dh_compute_key;
        }
    }

    ENGINE_add(engine);
    ENGINE_free(engine);
    ERR_clear_error();
}

#endif                          /* HAVE_CRYPTODEV */
/* crypto/engine/eng_ctrl.c */
/* ====================================================================
 * Copyright (c) 1999-2001 The OpenSSL Project.  All rights reserved.
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

// #include "eng_int.h"

/*
 * When querying a ENGINE-specific control command's 'description', this
 * string is used if the ENGINE_CMD_DEFN has cmd_desc set to NULL.
 */
static const char *int_no_description = "";

/*
 * These internal functions handle 'CMD'-related control commands when the
 * ENGINE in question has asked us to take care of it (ie. the ENGINE did not
 * set the ENGINE_FLAGS_MANUAL_CMD_CTRL flag.
 */

static int int_ctrl_cmd_is_null(const ENGINE_CMD_DEFN *defn)
{
    if ((defn->cmd_num == 0) || (defn->cmd_name == NULL))
        return 1;
    return 0;
}

static int int_ctrl_cmd_by_name(const ENGINE_CMD_DEFN *defn, const char *s)
{
    int idx = 0;
    while (!int_ctrl_cmd_is_null(defn) && (strcmp(defn->cmd_name, s) != 0)) {
        idx++;
        defn++;
    }
    if (int_ctrl_cmd_is_null(defn))
        /* The given name wasn't found */
        return -1;
    return idx;
}

static int int_ctrl_cmd_by_num(const ENGINE_CMD_DEFN *defn, unsigned int num)
{
    int idx = 0;
    /*
     * NB: It is stipulated that 'cmd_defn' lists are ordered by cmd_num. So
     * our searches don't need to take any longer than necessary.
     */
    while (!int_ctrl_cmd_is_null(defn) && (defn->cmd_num < num)) {
        idx++;
        defn++;
    }
    if (defn->cmd_num == num)
        return idx;
    /* The given cmd_num wasn't found */
    return -1;
}

static int int_ctrl_helper(ENGINE *e, int cmd, long i, void *p,
                           void (*f) (void))
{
    int idx;
    char *s = (char *)p;
    /* Take care of the easy one first (eg. it requires no searches) */
    if (cmd == ENGINE_CTRL_GET_FIRST_CMD_TYPE) {
        if ((e->cmd_defns == NULL) || int_ctrl_cmd_is_null(e->cmd_defns))
            return 0;
        return e->cmd_defns->cmd_num;
    }
    /* One or two commands require that "p" be a valid string buffer */
    if ((cmd == ENGINE_CTRL_GET_CMD_FROM_NAME) ||
        (cmd == ENGINE_CTRL_GET_NAME_FROM_CMD) ||
        (cmd == ENGINE_CTRL_GET_DESC_FROM_CMD)) {
        if (s == NULL) {
            ENGINEerr(ENGINE_F_INT_CTRL_HELPER, ERR_R_PASSED_NULL_PARAMETER);
            return -1;
        }
    }
    /* Now handle cmd_name -> cmd_num conversion */
    if (cmd == ENGINE_CTRL_GET_CMD_FROM_NAME) {
        if ((e->cmd_defns == NULL)
            || ((idx = int_ctrl_cmd_by_name(e->cmd_defns, s)) < 0)) {
            ENGINEerr(ENGINE_F_INT_CTRL_HELPER, ENGINE_R_INVALID_CMD_NAME);
            return -1;
        }
        return e->cmd_defns[idx].cmd_num;
    }
    /*
     * For the rest of the commands, the 'long' argument must specify a valie
     * command number - so we need to conduct a search.
     */
    if ((e->cmd_defns == NULL) || ((idx = int_ctrl_cmd_by_num(e->cmd_defns,
                                                              (unsigned int)
                                                              i)) < 0)) {
        ENGINEerr(ENGINE_F_INT_CTRL_HELPER, ENGINE_R_INVALID_CMD_NUMBER);
        return -1;
    }
    /* Now the logic splits depending on command type */
    switch (cmd) {
    case ENGINE_CTRL_GET_NEXT_CMD_TYPE:
        idx++;
        if (int_ctrl_cmd_is_null(e->cmd_defns + idx))
            /* end-of-list */
            return 0;
        else
            return e->cmd_defns[idx].cmd_num;
    case ENGINE_CTRL_GET_NAME_LEN_FROM_CMD:
        return strlen(e->cmd_defns[idx].cmd_name);
    case ENGINE_CTRL_GET_NAME_FROM_CMD:
        return BIO_snprintf(s, strlen(e->cmd_defns[idx].cmd_name) + 1,
                            "%s", e->cmd_defns[idx].cmd_name);
    case ENGINE_CTRL_GET_DESC_LEN_FROM_CMD:
        if (e->cmd_defns[idx].cmd_desc)
            return strlen(e->cmd_defns[idx].cmd_desc);
        return strlen(int_no_description);
    case ENGINE_CTRL_GET_DESC_FROM_CMD:
        if (e->cmd_defns[idx].cmd_desc)
            return BIO_snprintf(s,
                                strlen(e->cmd_defns[idx].cmd_desc) + 1,
                                "%s", e->cmd_defns[idx].cmd_desc);
        return BIO_snprintf(s, strlen(int_no_description) + 1, "%s",
                            int_no_description);
    case ENGINE_CTRL_GET_CMD_FLAGS:
        return e->cmd_defns[idx].cmd_flags;
    }
    /* Shouldn't really be here ... */
    ENGINEerr(ENGINE_F_INT_CTRL_HELPER, ENGINE_R_INTERNAL_LIST_ERROR);
    return -1;
}

int ENGINE_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f) (void))
{
    int ctrl_exists, ref_exists;
    if (e == NULL) {
        ENGINEerr(ENGINE_F_ENGINE_CTRL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
    ref_exists = ((e->struct_ref > 0) ? 1 : 0);
    CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
    ctrl_exists = ((e->ctrl == NULL) ? 0 : 1);
    if (!ref_exists) {
        ENGINEerr(ENGINE_F_ENGINE_CTRL, ENGINE_R_NO_REFERENCE);
        return 0;
    }
    /*
     * Intercept any "root-level" commands before trying to hand them on to
     * ctrl() handlers.
     */
    switch (cmd) {
    case ENGINE_CTRL_HAS_CTRL_FUNCTION:
        return ctrl_exists;
    case ENGINE_CTRL_GET_FIRST_CMD_TYPE:
    case ENGINE_CTRL_GET_NEXT_CMD_TYPE:
    case ENGINE_CTRL_GET_CMD_FROM_NAME:
    case ENGINE_CTRL_GET_NAME_LEN_FROM_CMD:
    case ENGINE_CTRL_GET_NAME_FROM_CMD:
    case ENGINE_CTRL_GET_DESC_LEN_FROM_CMD:
    case ENGINE_CTRL_GET_DESC_FROM_CMD:
    case ENGINE_CTRL_GET_CMD_FLAGS:
        if (ctrl_exists && !(e->flags & ENGINE_FLAGS_MANUAL_CMD_CTRL))
            return int_ctrl_helper(e, cmd, i, p, f);
        if (!ctrl_exists) {
            ENGINEerr(ENGINE_F_ENGINE_CTRL, ENGINE_R_NO_CONTROL_FUNCTION);
            /*
             * For these cmd-related functions, failure is indicated by a -1
             * return value (because 0 is used as a valid return in some
             * places).
             */
            return -1;
        }
    default:
        break;
    }
    /* Anything else requires a ctrl() handler to exist. */
    if (!ctrl_exists) {
        ENGINEerr(ENGINE_F_ENGINE_CTRL, ENGINE_R_NO_CONTROL_FUNCTION);
        return 0;
    }
    return e->ctrl(e, cmd, i, p, f);
}

int ENGINE_cmd_is_executable(ENGINE *e, int cmd)
{
    int flags;
    if ((flags =
         ENGINE_ctrl(e, ENGINE_CTRL_GET_CMD_FLAGS, cmd, NULL, NULL)) < 0) {
        ENGINEerr(ENGINE_F_ENGINE_CMD_IS_EXECUTABLE,
                  ENGINE_R_INVALID_CMD_NUMBER);
        return 0;
    }
    if (!(flags & ENGINE_CMD_FLAG_NO_INPUT) &&
        !(flags & ENGINE_CMD_FLAG_NUMERIC) &&
        !(flags & ENGINE_CMD_FLAG_STRING))
        return 0;
    return 1;
}

int ENGINE_ctrl_cmd(ENGINE *e, const char *cmd_name,
                    long i, void *p, void (*f) (void), int cmd_optional)
{
    int num;

    if ((e == NULL) || (cmd_name == NULL)) {
        ENGINEerr(ENGINE_F_ENGINE_CTRL_CMD, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if ((e->ctrl == NULL) || ((num = ENGINE_ctrl(e,
                                                 ENGINE_CTRL_GET_CMD_FROM_NAME,
                                                 0, (void *)cmd_name,
                                                 NULL)) <= 0)) {
        /*
         * If the command didn't *have* to be supported, we fake success.
         * This allows certain settings to be specified for multiple ENGINEs
         * and only require a change of ENGINE id (without having to
         * selectively apply settings). Eg. changing from a hardware device
         * back to the regular software ENGINE without editing the config
         * file, etc.
         */
        if (cmd_optional) {
            ERR_clear_error();
            return 1;
        }
        ENGINEerr(ENGINE_F_ENGINE_CTRL_CMD, ENGINE_R_INVALID_CMD_NAME);
        return 0;
    }
    /*
     * Force the result of the control command to 0 or 1, for the reasons
     * mentioned before.
     */
    if (ENGINE_ctrl(e, num, i, p, f) > 0)
        return 1;
    return 0;
}

int ENGINE_ctrl_cmd_string(ENGINE *e, const char *cmd_name, const char *arg,
                           int cmd_optional)
{
    int num, flags;
    long l;
    char *ptr;
    if ((e == NULL) || (cmd_name == NULL)) {
        ENGINEerr(ENGINE_F_ENGINE_CTRL_CMD_STRING,
                  ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if ((e->ctrl == NULL) || ((num = ENGINE_ctrl(e,
                                                 ENGINE_CTRL_GET_CMD_FROM_NAME,
                                                 0, (void *)cmd_name,
                                                 NULL)) <= 0)) {
        /*
         * If the command didn't *have* to be supported, we fake success.
         * This allows certain settings to be specified for multiple ENGINEs
         * and only require a change of ENGINE id (without having to
         * selectively apply settings). Eg. changing from a hardware device
         * back to the regular software ENGINE without editing the config
         * file, etc.
         */
        if (cmd_optional) {
            ERR_clear_error();
            return 1;
        }
        ENGINEerr(ENGINE_F_ENGINE_CTRL_CMD_STRING, ENGINE_R_INVALID_CMD_NAME);
        return 0;
    }
    if (!ENGINE_cmd_is_executable(e, num)) {
        ENGINEerr(ENGINE_F_ENGINE_CTRL_CMD_STRING,
                  ENGINE_R_CMD_NOT_EXECUTABLE);
        return 0;
    }
    if ((flags =
         ENGINE_ctrl(e, ENGINE_CTRL_GET_CMD_FLAGS, num, NULL, NULL)) < 0) {
        /*
         * Shouldn't happen, given that ENGINE_cmd_is_executable() returned
         * success.
         */
        ENGINEerr(ENGINE_F_ENGINE_CTRL_CMD_STRING,
                  ENGINE_R_INTERNAL_LIST_ERROR);
        return 0;
    }
    /*
     * If the command takes no input, there must be no input. And vice versa.
     */
    if (flags & ENGINE_CMD_FLAG_NO_INPUT) {
        if (arg != NULL) {
            ENGINEerr(ENGINE_F_ENGINE_CTRL_CMD_STRING,
                      ENGINE_R_COMMAND_TAKES_NO_INPUT);
            return 0;
        }
        /*
         * We deliberately force the result of ENGINE_ctrl() to 0 or 1 rather
         * than returning it as "return data". This is to ensure usage of
         * these commands is consistent across applications and that certain
         * applications don't understand it one way, and others another.
         */
        if (ENGINE_ctrl(e, num, 0, (void *)arg, NULL) > 0)
            return 1;
        return 0;
    }
    /* So, we require input */
    if (arg == NULL) {
        ENGINEerr(ENGINE_F_ENGINE_CTRL_CMD_STRING,
                  ENGINE_R_COMMAND_TAKES_INPUT);
        return 0;
    }
    /* If it takes string input, that's easy */
    if (flags & ENGINE_CMD_FLAG_STRING) {
        /* Same explanation as above */
        if (ENGINE_ctrl(e, num, 0, (void *)arg, NULL) > 0)
            return 1;
        return 0;
    }
    /*
     * If it doesn't take numeric either, then it is unsupported for use in a
     * config-setting situation, which is what this function is for. This
     * should never happen though, because ENGINE_cmd_is_executable() was
     * used.
     */
    if (!(flags & ENGINE_CMD_FLAG_NUMERIC)) {
        ENGINEerr(ENGINE_F_ENGINE_CTRL_CMD_STRING,
                  ENGINE_R_INTERNAL_LIST_ERROR);
        return 0;
    }
    l = strtol(arg, &ptr, 10);
    if ((arg == ptr) || (*ptr != '\0')) {
        ENGINEerr(ENGINE_F_ENGINE_CTRL_CMD_STRING,
                  ENGINE_R_ARGUMENT_IS_NOT_A_NUMBER);
        return 0;
    }
    /*
     * Force the result of the control command to 0 or 1, for the reasons
     * mentioned before.
     */
    if (ENGINE_ctrl(e, num, l, NULL, NULL) > 0)
        return 1;
    return 0;
}
/* crypto/engine/eng_dyn.c */
/*
 * Written by Geoff Thorpe (geoff@geoffthorpe.net) for the OpenSSL project
 * 2001.
 */
/* ====================================================================
 * Copyright (c) 1999-2001 The OpenSSL Project.  All rights reserved.
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

// #include "eng_int.h"
#include "dso.h"

/*
 * Shared libraries implementing ENGINEs for use by the "dynamic" ENGINE
 * loader should implement the hook-up functions with the following
 * prototypes.
 */

/* Our ENGINE handlers */
static int dynamic_init(ENGINE *e);
static int dynamic_finish(ENGINE *e);
static int dynamic_ctrl(ENGINE *e, int cmd, long i, void *p,
                        void (*f) (void));
/* Predeclare our context type */
typedef struct st_dynamic_data_ctx dynamic_data_ctx;
/* The implementation for the important control command */
static int dynamic_load(ENGINE *e, dynamic_data_ctx *ctx);

#define DYNAMIC_CMD_SO_PATH             ENGINE_CMD_BASE
#define DYNAMIC_CMD_NO_VCHECK           (ENGINE_CMD_BASE + 1)
#define DYNAMIC_CMD_ID                  (ENGINE_CMD_BASE + 2)
#define DYNAMIC_CMD_LIST_ADD            (ENGINE_CMD_BASE + 3)
#define DYNAMIC_CMD_DIR_LOAD            (ENGINE_CMD_BASE + 4)
#define DYNAMIC_CMD_DIR_ADD             (ENGINE_CMD_BASE + 5)
#define DYNAMIC_CMD_LOAD                (ENGINE_CMD_BASE + 6)

/* The constants used when creating the ENGINE */
static const char *engine_dynamic_id = "dynamic";
static const char *engine_dynamic_name = "Dynamic engine loading support";
static const ENGINE_CMD_DEFN dynamic_cmd_defns[] = {
    {DYNAMIC_CMD_SO_PATH,
     "SO_PATH",
     "Specifies the path to the new ENGINE shared library",
     ENGINE_CMD_FLAG_STRING},
    {DYNAMIC_CMD_NO_VCHECK,
     "NO_VCHECK",
     "Specifies to continue even if version checking fails (boolean)",
     ENGINE_CMD_FLAG_NUMERIC},
    {DYNAMIC_CMD_ID,
     "ID",
     "Specifies an ENGINE id name for loading",
     ENGINE_CMD_FLAG_STRING},
    {DYNAMIC_CMD_LIST_ADD,
     "LIST_ADD",
     "Whether to add a loaded ENGINE to the internal list (0=no,1=yes,2=mandatory)",
     ENGINE_CMD_FLAG_NUMERIC},
    {DYNAMIC_CMD_DIR_LOAD,
     "DIR_LOAD",
     "Specifies whether to load from 'DIR_ADD' directories (0=no,1=yes,2=mandatory)",
     ENGINE_CMD_FLAG_NUMERIC},
    {DYNAMIC_CMD_DIR_ADD,
     "DIR_ADD",
     "Adds a directory from which ENGINEs can be loaded",
     ENGINE_CMD_FLAG_STRING},
    {DYNAMIC_CMD_LOAD,
     "LOAD",
     "Load up the ENGINE specified by other settings",
     ENGINE_CMD_FLAG_NO_INPUT},
    {0, NULL, NULL, 0}
};

/*
 * Loading code stores state inside the ENGINE structure via the "ex_data"
 * element. We load all our state into a single structure and use that as a
 * single context in the "ex_data" stack.
 */
struct st_dynamic_data_ctx {
    /* The DSO object we load that supplies the ENGINE code */
    DSO *dynamic_dso;
    /*
     * The function pointer to the version checking shared library function
     */
    dynamic_v_check_fn v_check;
    /*
     * The function pointer to the engine-binding shared library function
     */
    dynamic_bind_engine bind_engine;
    /* The default name/path for loading the shared library */
    const char *DYNAMIC_LIBNAME;
    /* Whether to continue loading on a version check failure */
    int no_vcheck;
    /* If non-NULL, stipulates the 'id' of the ENGINE to be loaded */
    const char *engine_id;
    /*
     * If non-zero, a successfully loaded ENGINE should be added to the
     * internal ENGINE list. If 2, the add must succeed or the entire load
     * should fail.
     */
    int list_add_value;
    /* The symbol name for the version checking function */
    const char *DYNAMIC_F1;
    /* The symbol name for the "initialise ENGINE structure" function */
    const char *DYNAMIC_F2;
    /*
     * Whether to never use 'dirs', use 'dirs' as a fallback, or only use
     * 'dirs' for loading. Default is to use 'dirs' as a fallback.
     */
    int dir_load;
    /* A stack of directories from which ENGINEs could be loaded */
    STACK_OF(OPENSSL_STRING) *dirs;
};

/*
 * This is the "ex_data" index we obtain and reserve for use with our context
 * structure.
 */
static int dynamic_ex_data_idx = -1;

static void int_free_str(char *s)
{
    OPENSSL_free(s);
}

/*
 * Because our ex_data element may or may not get allocated depending on
 * whether a "first-use" occurs before the ENGINE is freed, we have a memory
 * leak problem to solve. We can't declare a "new" handler for the ex_data as
 * we don't want a dynamic_data_ctx in *all* ENGINE structures of all types
 * (this is a bug in the design of CRYPTO_EX_DATA). As such, we just declare
 * a "free" handler and that will get called if an ENGINE is being destroyed
 * and there was an ex_data element corresponding to our context type.
 */
static void dynamic_data_ctx_free_func(void *parent, void *ptr,
                                       CRYPTO_EX_DATA *ad, int idx, long argl,
                                       void *argp)
{
    if (ptr) {
        dynamic_data_ctx *ctx = (dynamic_data_ctx *)ptr;
        if (ctx->dynamic_dso)
            DSO_free(ctx->dynamic_dso);
        if (ctx->DYNAMIC_LIBNAME)
            OPENSSL_free((void *)ctx->DYNAMIC_LIBNAME);
        if (ctx->engine_id)
            OPENSSL_free((void *)ctx->engine_id);
        if (ctx->dirs)
            sk_OPENSSL_STRING_pop_free(ctx->dirs, int_free_str);
        OPENSSL_free(ctx);
    }
}

/*
 * Construct the per-ENGINE context. We create it blindly and then use a lock
 * to check for a race - if so, all but one of the threads "racing" will have
 * wasted their time. The alternative involves creating everything inside the
 * lock which is far worse.
 */
static int dynamic_set_data_ctx(ENGINE *e, dynamic_data_ctx **ctx)
{
    dynamic_data_ctx *c;
    c = OPENSSL_malloc(sizeof(dynamic_data_ctx));
    if (!c) {
        ENGINEerr(ENGINE_F_DYNAMIC_SET_DATA_CTX, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    memset(c, 0, sizeof(dynamic_data_ctx));
    c->dynamic_dso = NULL;
    c->v_check = NULL;
    c->bind_engine = NULL;
    c->DYNAMIC_LIBNAME = NULL;
    c->no_vcheck = 0;
    c->engine_id = NULL;
    c->list_add_value = 0;
    c->DYNAMIC_F1 = "v_check";
    c->DYNAMIC_F2 = "bind_engine";
    c->dir_load = 1;
    c->dirs = sk_OPENSSL_STRING_new_null();
    if (!c->dirs) {
        ENGINEerr(ENGINE_F_DYNAMIC_SET_DATA_CTX, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(c);
        return 0;
    }
    CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
    if ((*ctx = (dynamic_data_ctx *)ENGINE_get_ex_data(e,
                                                       dynamic_ex_data_idx))
        == NULL) {
        /* Good, we're the first */
        ENGINE_set_ex_data(e, dynamic_ex_data_idx, c);
        *ctx = c;
        c = NULL;
    }
    CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
    /*
     * If we lost the race to set the context, c is non-NULL and *ctx is the
     * context of the thread that won.
     */
    if (c) {
        sk_OPENSSL_STRING_free(c->dirs);
        OPENSSL_free(c);
    }
    return 1;
}

/*
 * This function retrieves the context structure from an ENGINE's "ex_data",
 * or if it doesn't exist yet, sets it up.
 */
static dynamic_data_ctx *dynamic_get_data_ctx(ENGINE *e)
{
    dynamic_data_ctx *ctx;
    if (dynamic_ex_data_idx < 0) {
        /*
         * Create and register the ENGINE ex_data, and associate our "free"
         * function with it to ensure any allocated contexts get freed when
         * an ENGINE goes underground.
         */
        int new_idx = ENGINE_get_ex_new_index(0, NULL, NULL, NULL,
                                              dynamic_data_ctx_free_func);
        if (new_idx == -1) {
            ENGINEerr(ENGINE_F_DYNAMIC_GET_DATA_CTX, ENGINE_R_NO_INDEX);
            return NULL;
        }
        CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
        /* Avoid a race by checking again inside this lock */
        if (dynamic_ex_data_idx < 0) {
            /* Good, someone didn't beat us to it */
            dynamic_ex_data_idx = new_idx;
            new_idx = -1;
        }
        CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
        /*
         * In theory we could "give back" the index here if (new_idx>-1), but
         * it's not possible and wouldn't gain us much if it were.
         */
    }
    ctx = (dynamic_data_ctx *)ENGINE_get_ex_data(e, dynamic_ex_data_idx);
    /* Check if the context needs to be created */
    if ((ctx == NULL) && !dynamic_set_data_ctx(e, &ctx))
        /* "set_data" will set errors if necessary */
        return NULL;
    return ctx;
}

static ENGINE *engine_dynamic(void)
{
    ENGINE *ret = ENGINE_new();
    if (!ret)
        return NULL;
    if (!ENGINE_set_id(ret, engine_dynamic_id) ||
        !ENGINE_set_name(ret, engine_dynamic_name) ||
        !ENGINE_set_init_function(ret, dynamic_init) ||
        !ENGINE_set_finish_function(ret, dynamic_finish) ||
        !ENGINE_set_ctrl_function(ret, dynamic_ctrl) ||
        !ENGINE_set_flags(ret, ENGINE_FLAGS_BY_ID_COPY) ||
        !ENGINE_set_cmd_defns(ret, dynamic_cmd_defns)) {
        ENGINE_free(ret);
        return NULL;
    }
    return ret;
}

void ENGINE_load_dynamic(void)
{
    ENGINE *toadd = engine_dynamic();
    if (!toadd)
        return;
    ENGINE_add(toadd);
    /*
     * If the "add" worked, it gets a structural reference. So either way, we
     * release our just-created reference.
     */
    ENGINE_free(toadd);
    /*
     * If the "add" didn't work, it was probably a conflict because it was
     * already added (eg. someone calling ENGINE_load_blah then calling
     * ENGINE_load_builtin_engines() perhaps).
     */
    ERR_clear_error();
}

static int dynamic_init(ENGINE *e)
{
    /*
     * We always return failure - the "dyanamic" engine itself can't be used
     * for anything.
     */
    return 0;
}

static int dynamic_finish(ENGINE *e)
{
    /*
     * This should never be called on account of "dynamic_init" always
     * failing.
     */
    return 0;
}

static int dynamic_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f) (void))
{
    dynamic_data_ctx *ctx = dynamic_get_data_ctx(e);
    int initialised;

    if (!ctx) {
        ENGINEerr(ENGINE_F_DYNAMIC_CTRL, ENGINE_R_NOT_LOADED);
        return 0;
    }
    initialised = ((ctx->dynamic_dso == NULL) ? 0 : 1);
    /* All our control commands require the ENGINE to be uninitialised */
    if (initialised) {
        ENGINEerr(ENGINE_F_DYNAMIC_CTRL, ENGINE_R_ALREADY_LOADED);
        return 0;
    }
    switch (cmd) {
    case DYNAMIC_CMD_SO_PATH:
        /* a NULL 'p' or a string of zero-length is the same thing */
        if (p && (strlen((const char *)p) < 1))
            p = NULL;
        if (ctx->DYNAMIC_LIBNAME)
            OPENSSL_free((void *)ctx->DYNAMIC_LIBNAME);
        if (p)
            ctx->DYNAMIC_LIBNAME = BUF_strdup(p);
        else
            ctx->DYNAMIC_LIBNAME = NULL;
        return (ctx->DYNAMIC_LIBNAME ? 1 : 0);
    case DYNAMIC_CMD_NO_VCHECK:
        ctx->no_vcheck = ((i == 0) ? 0 : 1);
        return 1;
    case DYNAMIC_CMD_ID:
        /* a NULL 'p' or a string of zero-length is the same thing */
        if (p && (strlen((const char *)p) < 1))
            p = NULL;
        if (ctx->engine_id)
            OPENSSL_free((void *)ctx->engine_id);
        if (p)
            ctx->engine_id = BUF_strdup(p);
        else
            ctx->engine_id = NULL;
        return (ctx->engine_id ? 1 : 0);
    case DYNAMIC_CMD_LIST_ADD:
        if ((i < 0) || (i > 2)) {
            ENGINEerr(ENGINE_F_DYNAMIC_CTRL, ENGINE_R_INVALID_ARGUMENT);
            return 0;
        }
        ctx->list_add_value = (int)i;
        return 1;
    case DYNAMIC_CMD_LOAD:
        return dynamic_load(e, ctx);
    case DYNAMIC_CMD_DIR_LOAD:
        if ((i < 0) || (i > 2)) {
            ENGINEerr(ENGINE_F_DYNAMIC_CTRL, ENGINE_R_INVALID_ARGUMENT);
            return 0;
        }
        ctx->dir_load = (int)i;
        return 1;
    case DYNAMIC_CMD_DIR_ADD:
        /* a NULL 'p' or a string of zero-length is the same thing */
        if (!p || (strlen((const char *)p) < 1)) {
            ENGINEerr(ENGINE_F_DYNAMIC_CTRL, ENGINE_R_INVALID_ARGUMENT);
            return 0;
        }
        {
            char *tmp_str = BUF_strdup(p);
            if (!tmp_str) {
                ENGINEerr(ENGINE_F_DYNAMIC_CTRL, ERR_R_MALLOC_FAILURE);
                return 0;
            }
            sk_OPENSSL_STRING_insert(ctx->dirs, tmp_str, -1);
        }
        return 1;
    default:
        break;
    }
    ENGINEerr(ENGINE_F_DYNAMIC_CTRL, ENGINE_R_CTRL_COMMAND_NOT_IMPLEMENTED);
    return 0;
}

static int int_load(dynamic_data_ctx *ctx)
{
    int num, loop;
    /* Unless told not to, try a direct load */
    if ((ctx->dir_load != 2) && (DSO_load(ctx->dynamic_dso,
                                          ctx->DYNAMIC_LIBNAME, NULL,
                                          0)) != NULL)
        return 1;
    /* If we're not allowed to use 'dirs' or we have none, fail */
    if (!ctx->dir_load || (num = sk_OPENSSL_STRING_num(ctx->dirs)) < 1)
        return 0;
    for (loop = 0; loop < num; loop++) {
        const char *s = sk_OPENSSL_STRING_value(ctx->dirs, loop);
        char *merge = DSO_merge(ctx->dynamic_dso, ctx->DYNAMIC_LIBNAME, s);
        if (!merge)
            return 0;
        if (DSO_load(ctx->dynamic_dso, merge, NULL, 0)) {
            /* Found what we're looking for */
            OPENSSL_free(merge);
            return 1;
        }
        OPENSSL_free(merge);
    }
    return 0;
}

static int dynamic_load(ENGINE *e, dynamic_data_ctx *ctx)
{
    ENGINE cpy;
    dynamic_fns fns;

    if (!ctx->dynamic_dso)
        ctx->dynamic_dso = DSO_new();
    if (!ctx->DYNAMIC_LIBNAME) {
        if (!ctx->engine_id)
            return 0;
        ctx->DYNAMIC_LIBNAME =
            DSO_convert_filename(ctx->dynamic_dso, ctx->engine_id);
    }
    if (!int_load(ctx)) {
        ENGINEerr(ENGINE_F_DYNAMIC_LOAD, ENGINE_R_DSO_NOT_FOUND);
        DSO_free(ctx->dynamic_dso);
        ctx->dynamic_dso = NULL;
        return 0;
    }
    /* We have to find a bind function otherwise it'll always end badly */
    if (!
        (ctx->bind_engine =
         (dynamic_bind_engine) DSO_bind_func(ctx->dynamic_dso,
                                             ctx->DYNAMIC_F2))) {
        ctx->bind_engine = NULL;
        DSO_free(ctx->dynamic_dso);
        ctx->dynamic_dso = NULL;
        ENGINEerr(ENGINE_F_DYNAMIC_LOAD, ENGINE_R_DSO_FAILURE);
        return 0;
    }
    /* Do we perform version checking? */
    if (!ctx->no_vcheck) {
        unsigned long vcheck_res = 0;
        /*
         * Now we try to find a version checking function and decide how to
         * cope with failure if/when it fails.
         */
        ctx->v_check =
            (dynamic_v_check_fn) DSO_bind_func(ctx->dynamic_dso,
                                               ctx->DYNAMIC_F1);
        if (ctx->v_check)
            vcheck_res = ctx->v_check(OSSL_DYNAMIC_VERSION);
        /*
         * We fail if the version checker veto'd the load *or* if it is
         * deferring to us (by returning its version) and we think it is too
         * old.
         */
        if (vcheck_res < OSSL_DYNAMIC_OLDEST) {
            /* Fail */
            ctx->bind_engine = NULL;
            ctx->v_check = NULL;
            DSO_free(ctx->dynamic_dso);
            ctx->dynamic_dso = NULL;
            ENGINEerr(ENGINE_F_DYNAMIC_LOAD,
                      ENGINE_R_VERSION_INCOMPATIBILITY);
            return 0;
        }
    }
    /*
     * First binary copy the ENGINE structure so that we can roll back if the
     * hand-over fails
     */
    memcpy(&cpy, e, sizeof(ENGINE));
    /*
     * Provide the ERR, "ex_data", memory, and locking callbacks so the
     * loaded library uses our state rather than its own. FIXME: As noted in
     * engine.h, much of this would be simplified if each area of code
     * provided its own "summary" structure of all related callbacks. It
     * would also increase opaqueness.
     */
    fns.static_state = ENGINE_get_static_state();
    fns.err_fns = ERR_get_implementation();
    fns.ex_data_fns = CRYPTO_get_ex_data_implementation();
    CRYPTO_get_mem_functions(&fns.mem_fns.malloc_cb,
                             &fns.mem_fns.realloc_cb, &fns.mem_fns.free_cb);
    fns.lock_fns.lock_locking_cb = CRYPTO_get_locking_callback();
    fns.lock_fns.lock_add_lock_cb = CRYPTO_get_add_lock_callback();
    fns.lock_fns.dynlock_create_cb = CRYPTO_get_dynlock_create_callback();
    fns.lock_fns.dynlock_lock_cb = CRYPTO_get_dynlock_lock_callback();
    fns.lock_fns.dynlock_destroy_cb = CRYPTO_get_dynlock_destroy_callback();
    /*
     * Now that we've loaded the dynamic engine, make sure no "dynamic"
     * ENGINE elements will show through.
     */
    engine_set_all_null(e);

    /* Try to bind the ENGINE onto our own ENGINE structure */
    if (!ctx->bind_engine(e, ctx->engine_id, &fns)) {
        ctx->bind_engine = NULL;
        ctx->v_check = NULL;
        DSO_free(ctx->dynamic_dso);
        ctx->dynamic_dso = NULL;
        ENGINEerr(ENGINE_F_DYNAMIC_LOAD, ENGINE_R_INIT_FAILED);
        /* Copy the original ENGINE structure back */
        memcpy(e, &cpy, sizeof(ENGINE));
        return 0;
    }
    /* Do we try to add this ENGINE to the internal list too? */
    if (ctx->list_add_value > 0) {
        if (!ENGINE_add(e)) {
            /* Do we tolerate this or fail? */
            if (ctx->list_add_value > 1) {
                /*
                 * Fail - NB: By this time, it's too late to rollback, and
                 * trying to do so allows the bind_engine() code to have
                 * created leaks. We just have to fail where we are, after
                 * the ENGINE has changed.
                 */
                ENGINEerr(ENGINE_F_DYNAMIC_LOAD,
                          ENGINE_R_CONFLICTING_ENGINE_ID);
                return 0;
            }
            /* Tolerate */
            ERR_clear_error();
        }
    }
    return 1;
}
/* crypto/engine/eng_err.c */
/* ====================================================================
 * Copyright (c) 1999-2010 The OpenSSL Project.  All rights reserved.
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
// #include "engine.h"

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

# define ERR_FUNC(func) ERR_PACK(ERR_LIB_ENGINE,func,0)
# define ERR_REASON(reason) ERR_PACK(ERR_LIB_ENGINE,0,reason)

static ERR_STRING_DATA ENGINE_str_functs[] = {
    {ERR_FUNC(ENGINE_F_DYNAMIC_CTRL), "DYNAMIC_CTRL"},
    {ERR_FUNC(ENGINE_F_DYNAMIC_GET_DATA_CTX), "DYNAMIC_GET_DATA_CTX"},
    {ERR_FUNC(ENGINE_F_DYNAMIC_LOAD), "DYNAMIC_LOAD"},
    {ERR_FUNC(ENGINE_F_DYNAMIC_SET_DATA_CTX), "DYNAMIC_SET_DATA_CTX"},
    {ERR_FUNC(ENGINE_F_ENGINE_ADD), "ENGINE_add"},
    {ERR_FUNC(ENGINE_F_ENGINE_BY_ID), "ENGINE_by_id"},
    {ERR_FUNC(ENGINE_F_ENGINE_CMD_IS_EXECUTABLE), "ENGINE_cmd_is_executable"},
    {ERR_FUNC(ENGINE_F_ENGINE_CTRL), "ENGINE_ctrl"},
    {ERR_FUNC(ENGINE_F_ENGINE_CTRL_CMD), "ENGINE_ctrl_cmd"},
    {ERR_FUNC(ENGINE_F_ENGINE_CTRL_CMD_STRING), "ENGINE_ctrl_cmd_string"},
    {ERR_FUNC(ENGINE_F_ENGINE_FINISH), "ENGINE_finish"},
    {ERR_FUNC(ENGINE_F_ENGINE_FREE_UTIL), "ENGINE_FREE_UTIL"},
    {ERR_FUNC(ENGINE_F_ENGINE_GET_CIPHER), "ENGINE_get_cipher"},
    {ERR_FUNC(ENGINE_F_ENGINE_GET_DEFAULT_TYPE), "ENGINE_GET_DEFAULT_TYPE"},
    {ERR_FUNC(ENGINE_F_ENGINE_GET_DIGEST), "ENGINE_get_digest"},
    {ERR_FUNC(ENGINE_F_ENGINE_GET_NEXT), "ENGINE_get_next"},
    {ERR_FUNC(ENGINE_F_ENGINE_GET_PKEY_ASN1_METH),
     "ENGINE_get_pkey_asn1_meth"},
    {ERR_FUNC(ENGINE_F_ENGINE_GET_PKEY_METH), "ENGINE_get_pkey_meth"},
    {ERR_FUNC(ENGINE_F_ENGINE_GET_PREV), "ENGINE_get_prev"},
    {ERR_FUNC(ENGINE_F_ENGINE_INIT), "ENGINE_init"},
    {ERR_FUNC(ENGINE_F_ENGINE_LIST_ADD), "ENGINE_LIST_ADD"},
    {ERR_FUNC(ENGINE_F_ENGINE_LIST_REMOVE), "ENGINE_LIST_REMOVE"},
    {ERR_FUNC(ENGINE_F_ENGINE_LOAD_PRIVATE_KEY), "ENGINE_load_private_key"},
    {ERR_FUNC(ENGINE_F_ENGINE_LOAD_PUBLIC_KEY), "ENGINE_load_public_key"},
    {ERR_FUNC(ENGINE_F_ENGINE_LOAD_SSL_CLIENT_CERT),
     "ENGINE_load_ssl_client_cert"},
    {ERR_FUNC(ENGINE_F_ENGINE_NEW), "ENGINE_new"},
    {ERR_FUNC(ENGINE_F_ENGINE_REMOVE), "ENGINE_remove"},
    {ERR_FUNC(ENGINE_F_ENGINE_SET_DEFAULT_STRING),
     "ENGINE_set_default_string"},
    {ERR_FUNC(ENGINE_F_ENGINE_SET_DEFAULT_TYPE), "ENGINE_SET_DEFAULT_TYPE"},
    {ERR_FUNC(ENGINE_F_ENGINE_SET_ID), "ENGINE_set_id"},
    {ERR_FUNC(ENGINE_F_ENGINE_SET_NAME), "ENGINE_set_name"},
    {ERR_FUNC(ENGINE_F_ENGINE_TABLE_REGISTER), "ENGINE_TABLE_REGISTER"},
    {ERR_FUNC(ENGINE_F_ENGINE_UNLOAD_KEY), "ENGINE_UNLOAD_KEY"},
    {ERR_FUNC(ENGINE_F_ENGINE_UNLOCKED_FINISH), "ENGINE_UNLOCKED_FINISH"},
    {ERR_FUNC(ENGINE_F_ENGINE_UP_REF), "ENGINE_up_ref"},
    {ERR_FUNC(ENGINE_F_INT_CTRL_HELPER), "INT_CTRL_HELPER"},
    {ERR_FUNC(ENGINE_F_INT_ENGINE_CONFIGURE), "INT_ENGINE_CONFIGURE"},
    {ERR_FUNC(ENGINE_F_INT_ENGINE_MODULE_INIT), "INT_ENGINE_MODULE_INIT"},
    {ERR_FUNC(ENGINE_F_LOG_MESSAGE), "LOG_MESSAGE"},
    {0, NULL}
};

static ERR_STRING_DATA ENGINE_str_reasons[] = {
    {ERR_REASON(ENGINE_R_ALREADY_LOADED), "already loaded"},
    {ERR_REASON(ENGINE_R_ARGUMENT_IS_NOT_A_NUMBER),
     "argument is not a number"},
    {ERR_REASON(ENGINE_R_CMD_NOT_EXECUTABLE), "cmd not executable"},
    {ERR_REASON(ENGINE_R_COMMAND_TAKES_INPUT), "command takes input"},
    {ERR_REASON(ENGINE_R_COMMAND_TAKES_NO_INPUT), "command takes no input"},
    {ERR_REASON(ENGINE_R_CONFLICTING_ENGINE_ID), "conflicting engine id"},
    {ERR_REASON(ENGINE_R_CTRL_COMMAND_NOT_IMPLEMENTED),
     "ctrl command not implemented"},
    {ERR_REASON(ENGINE_R_DH_NOT_IMPLEMENTED), "dh not implemented"},
    {ERR_REASON(ENGINE_R_DSA_NOT_IMPLEMENTED), "dsa not implemented"},
    {ERR_REASON(ENGINE_R_DSO_FAILURE), "DSO failure"},
    {ERR_REASON(ENGINE_R_DSO_NOT_FOUND), "dso not found"},
    {ERR_REASON(ENGINE_R_ENGINES_SECTION_ERROR), "engines section error"},
    {ERR_REASON(ENGINE_R_ENGINE_CONFIGURATION_ERROR),
     "engine configuration error"},
    {ERR_REASON(ENGINE_R_ENGINE_IS_NOT_IN_LIST), "engine is not in the list"},
    {ERR_REASON(ENGINE_R_ENGINE_SECTION_ERROR), "engine section error"},
    {ERR_REASON(ENGINE_R_FAILED_LOADING_PRIVATE_KEY),
     "failed loading private key"},
    {ERR_REASON(ENGINE_R_FAILED_LOADING_PUBLIC_KEY),
     "failed loading public key"},
    {ERR_REASON(ENGINE_R_FINISH_FAILED), "finish failed"},
    {ERR_REASON(ENGINE_R_GET_HANDLE_FAILED),
     "could not obtain hardware handle"},
    {ERR_REASON(ENGINE_R_ID_OR_NAME_MISSING), "'id' or 'name' missing"},
    {ERR_REASON(ENGINE_R_INIT_FAILED), "init failed"},
    {ERR_REASON(ENGINE_R_INTERNAL_LIST_ERROR), "internal list error"},
    {ERR_REASON(ENGINE_R_INVALID_ARGUMENT), "invalid argument"},
    {ERR_REASON(ENGINE_R_INVALID_CMD_NAME), "invalid cmd name"},
    {ERR_REASON(ENGINE_R_INVALID_CMD_NUMBER), "invalid cmd number"},
    {ERR_REASON(ENGINE_R_INVALID_INIT_VALUE), "invalid init value"},
    {ERR_REASON(ENGINE_R_INVALID_STRING), "invalid string"},
    {ERR_REASON(ENGINE_R_NOT_INITIALISED), "not initialised"},
    {ERR_REASON(ENGINE_R_NOT_LOADED), "not loaded"},
    {ERR_REASON(ENGINE_R_NO_CONTROL_FUNCTION), "no control function"},
    {ERR_REASON(ENGINE_R_NO_INDEX), "no index"},
    {ERR_REASON(ENGINE_R_NO_LOAD_FUNCTION), "no load function"},
    {ERR_REASON(ENGINE_R_NO_REFERENCE), "no reference"},
    {ERR_REASON(ENGINE_R_NO_SUCH_ENGINE), "no such engine"},
    {ERR_REASON(ENGINE_R_NO_UNLOAD_FUNCTION), "no unload function"},
    {ERR_REASON(ENGINE_R_PROVIDE_PARAMETERS), "provide parameters"},
    {ERR_REASON(ENGINE_R_RSA_NOT_IMPLEMENTED), "rsa not implemented"},
    {ERR_REASON(ENGINE_R_UNIMPLEMENTED_CIPHER), "unimplemented cipher"},
    {ERR_REASON(ENGINE_R_UNIMPLEMENTED_DIGEST), "unimplemented digest"},
    {ERR_REASON(ENGINE_R_UNIMPLEMENTED_PUBLIC_KEY_METHOD),
     "unimplemented public key method"},
    {ERR_REASON(ENGINE_R_VERSION_INCOMPATIBILITY), "version incompatibility"},
    {0, NULL}
};

#endif

void ERR_load_ENGINE_strings(void)
{
#ifndef OPENSSL_NO_ERR

    if (ERR_func_error_string(ENGINE_str_functs[0].error) == NULL) {
        ERR_load_strings(0, ENGINE_str_functs);
        ERR_load_strings(0, ENGINE_str_reasons);
    }
#endif
}
/* crypto/engine/eng_fat.c */
/* ====================================================================
 * Copyright (c) 1999-2001 The OpenSSL Project.  All rights reserved.
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
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * ECDH support in OpenSSL originally developed by
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
 */

// #include "eng_int.h"
// #include "conf.h"

int ENGINE_set_default(ENGINE *e, unsigned int flags)
{
    if ((flags & ENGINE_METHOD_CIPHERS) && !ENGINE_set_default_ciphers(e))
        return 0;
    if ((flags & ENGINE_METHOD_DIGESTS) && !ENGINE_set_default_digests(e))
        return 0;
#ifndef OPENSSL_NO_RSA
    if ((flags & ENGINE_METHOD_RSA) && !ENGINE_set_default_RSA(e))
        return 0;
#endif
#ifndef OPENSSL_NO_DSA
    if ((flags & ENGINE_METHOD_DSA) && !ENGINE_set_default_DSA(e))
        return 0;
#endif
#ifndef OPENSSL_NO_DH
    if ((flags & ENGINE_METHOD_DH) && !ENGINE_set_default_DH(e))
        return 0;
#endif
#ifndef OPENSSL_NO_ECDH
    if ((flags & ENGINE_METHOD_ECDH) && !ENGINE_set_default_ECDH(e))
        return 0;
#endif
#ifndef OPENSSL_NO_ECDSA
    if ((flags & ENGINE_METHOD_ECDSA) && !ENGINE_set_default_ECDSA(e))
        return 0;
#endif
    if ((flags & ENGINE_METHOD_RAND) && !ENGINE_set_default_RAND(e))
        return 0;
    if ((flags & ENGINE_METHOD_PKEY_METHS)
        && !ENGINE_set_default_pkey_meths(e))
        return 0;
    if ((flags & ENGINE_METHOD_PKEY_ASN1_METHS)
        && !ENGINE_set_default_pkey_asn1_meths(e))
        return 0;
    return 1;
}

/* Set default algorithms using a string */

static int int_def_cb(const char *alg, int len, void *arg)
{
    unsigned int *pflags = arg;
    if (alg == NULL)
        return 0;
    if (!strncmp(alg, "ALL", len))
        *pflags |= ENGINE_METHOD_ALL;
    else if (!strncmp(alg, "RSA", len))
        *pflags |= ENGINE_METHOD_RSA;
    else if (!strncmp(alg, "DSA", len))
        *pflags |= ENGINE_METHOD_DSA;
    else if (!strncmp(alg, "ECDH", len))
        *pflags |= ENGINE_METHOD_ECDH;
    else if (!strncmp(alg, "ECDSA", len))
        *pflags |= ENGINE_METHOD_ECDSA;
    else if (!strncmp(alg, "DH", len))
        *pflags |= ENGINE_METHOD_DH;
    else if (!strncmp(alg, "RAND", len))
        *pflags |= ENGINE_METHOD_RAND;
    else if (!strncmp(alg, "CIPHERS", len))
        *pflags |= ENGINE_METHOD_CIPHERS;
    else if (!strncmp(alg, "DIGESTS", len))
        *pflags |= ENGINE_METHOD_DIGESTS;
    else if (!strncmp(alg, "PKEY", len))
        *pflags |= ENGINE_METHOD_PKEY_METHS | ENGINE_METHOD_PKEY_ASN1_METHS;
    else if (!strncmp(alg, "PKEY_CRYPTO", len))
        *pflags |= ENGINE_METHOD_PKEY_METHS;
    else if (!strncmp(alg, "PKEY_ASN1", len))
        *pflags |= ENGINE_METHOD_PKEY_ASN1_METHS;
    else
        return 0;
    return 1;
}

int ENGINE_set_default_string(ENGINE *e, const char *def_list)
{
    unsigned int flags = 0;
    if (!CONF_parse_list(def_list, ',', 1, int_def_cb, &flags)) {
        ENGINEerr(ENGINE_F_ENGINE_SET_DEFAULT_STRING,
                  ENGINE_R_INVALID_STRING);
        ERR_add_error_data(2, "str=", def_list);
        return 0;
    }
    return ENGINE_set_default(e, flags);
}

int ENGINE_register_complete(ENGINE *e)
{
    ENGINE_register_ciphers(e);
    ENGINE_register_digests(e);
#ifndef OPENSSL_NO_RSA
    ENGINE_register_RSA(e);
#endif
#ifndef OPENSSL_NO_DSA
    ENGINE_register_DSA(e);
#endif
#ifndef OPENSSL_NO_DH
    ENGINE_register_DH(e);
#endif
#ifndef OPENSSL_NO_ECDH
    ENGINE_register_ECDH(e);
#endif
#ifndef OPENSSL_NO_ECDSA
    ENGINE_register_ECDSA(e);
#endif
    ENGINE_register_RAND(e);
    ENGINE_register_pkey_meths(e);
    ENGINE_register_pkey_asn1_meths(e);
    return 1;
}

int ENGINE_register_all_complete(void)
{
    ENGINE *e;

    for (e = ENGINE_get_first(); e; e = ENGINE_get_next(e))
        if (!(e->flags & ENGINE_FLAGS_NO_REGISTER_ALL))
            ENGINE_register_complete(e);
    return 1;
}
/* crypto/engine/eng_init.c */
/* ====================================================================
 * Copyright (c) 1999-2001 The OpenSSL Project.  All rights reserved.
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

// #include "eng_int.h"

/*
 * Initialise a engine type for use (or up its functional reference count if
 * it's already in use). This version is only used internally.
 */
int engine_unlocked_init(ENGINE *e)
{
    int to_return = 1;

    if ((e->funct_ref == 0) && e->init)
        /*
         * This is the first functional reference and the engine requires
         * initialisation so we do it now.
         */
        to_return = e->init(e);
    if (to_return) {
        /*
         * OK, we return a functional reference which is also a structural
         * reference.
         */
        e->struct_ref++;
        e->funct_ref++;
        engine_ref_debug(e, 0, 1)
            engine_ref_debug(e, 1, 1)
    }
    return to_return;
}

/*
 * Free a functional reference to a engine type. This version is only used
 * internally.
 */
int engine_unlocked_finish(ENGINE *e, int unlock_for_handlers)
{
    int to_return = 1;

    /*
     * Reduce the functional reference count here so if it's the terminating
     * case, we can release the lock safely and call the finish() handler
     * without risk of a race. We get a race if we leave the count until
     * after and something else is calling "finish" at the same time -
     * there's a chance that both threads will together take the count from 2
     * to 0 without either calling finish().
     */
    e->funct_ref--;
    engine_ref_debug(e, 1, -1);
    if ((e->funct_ref == 0) && e->finish) {
        if (unlock_for_handlers)
            CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
        to_return = e->finish(e);
        if (unlock_for_handlers)
            CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
        if (!to_return)
            return 0;
    }
#ifdef REF_CHECK
    if (e->funct_ref < 0) {
        fprintf(stderr, "ENGINE_finish, bad functional reference count\n");
        abort();
    }
#endif
    /* Release the structural reference too */
    if (!engine_free_util(e, 0)) {
        ENGINEerr(ENGINE_F_ENGINE_UNLOCKED_FINISH, ENGINE_R_FINISH_FAILED);
        return 0;
    }
    return to_return;
}

/* The API (locked) version of "init" */
int ENGINE_init(ENGINE *e)
{
    int ret;
    if (e == NULL) {
        ENGINEerr(ENGINE_F_ENGINE_INIT, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
    ret = engine_unlocked_init(e);
    CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
    return ret;
}

/* The API (locked) version of "finish" */
int ENGINE_finish(ENGINE *e)
{
    int to_return = 1;

    if (e == NULL) {
        ENGINEerr(ENGINE_F_ENGINE_FINISH, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
    to_return = engine_unlocked_finish(e, 1);
    CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
    if (!to_return) {
        ENGINEerr(ENGINE_F_ENGINE_FINISH, ENGINE_R_FINISH_FAILED);
        return 0;
    }
    return to_return;
}
/* crypto/engine/eng_lib.c */
/*
 * Written by Geoff Thorpe (geoff@geoffthorpe.net) for the OpenSSL project
 * 2000.
 */
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

// #include "eng_int.h"
#include "rand.h"

/* The "new"/"free" stuff first */

ENGINE *ENGINE_new(void)
{
    ENGINE *ret;

    ret = (ENGINE *)OPENSSL_malloc(sizeof(ENGINE));
    if (ret == NULL) {
        ENGINEerr(ENGINE_F_ENGINE_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    memset(ret, 0, sizeof(ENGINE));
    ret->struct_ref = 1;
    engine_ref_debug(ret, 0, 1)
        CRYPTO_new_ex_data(CRYPTO_EX_INDEX_ENGINE, ret, &ret->ex_data);
    return ret;
}

/*
 * Placed here (close proximity to ENGINE_new) so that modifications to the
 * elements of the ENGINE structure are more likely to be caught and changed
 * here.
 */
void engine_set_all_null(ENGINE *e)
{
    e->id = NULL;
    e->name = NULL;
    e->rsa_meth = NULL;
    e->dsa_meth = NULL;
    e->dh_meth = NULL;
    e->rand_meth = NULL;
    e->store_meth = NULL;
    e->ciphers = NULL;
    e->digests = NULL;
    e->destroy = NULL;
    e->init = NULL;
    e->finish = NULL;
    e->ctrl = NULL;
    e->load_privkey = NULL;
    e->load_pubkey = NULL;
    e->cmd_defns = NULL;
    e->flags = 0;
}

int engine_free_util(ENGINE *e, int locked)
{
    int i;

    if (e == NULL) {
        ENGINEerr(ENGINE_F_ENGINE_FREE_UTIL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (locked)
        i = CRYPTO_add(&e->struct_ref, -1, CRYPTO_LOCK_ENGINE);
    else
        i = --e->struct_ref;
    engine_ref_debug(e, 0, -1)
        if (i > 0)
        return 1;
#ifdef REF_CHECK
    if (i < 0) {
        fprintf(stderr, "ENGINE_free, bad structural reference count\n");
        abort();
    }
#endif
    /* Free up any dynamically allocated public key methods */
    engine_pkey_meths_free(e);
    engine_pkey_asn1_meths_free(e);
    /*
     * Give the ENGINE a chance to do any structural cleanup corresponding to
     * allocation it did in its constructor (eg. unload error strings)
     */
    if (e->destroy)
        e->destroy(e);
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_ENGINE, e, &e->ex_data);
    OPENSSL_free(e);
    return 1;
}

int ENGINE_free(ENGINE *e)
{
    return engine_free_util(e, 1);
}

/* Cleanup stuff */

/*
 * ENGINE_cleanup() is coded such that anything that does work that will need
 * cleanup can register a "cleanup" callback here. That way we don't get
 * linker bloat by referring to all *possible* cleanups, but any linker bloat
 * into code "X" will cause X's cleanup function to end up here.
 */
static STACK_OF(ENGINE_CLEANUP_ITEM) *cleanup_stack = NULL;
static int int_cleanup_check(int create)
{
    if (cleanup_stack)
        return 1;
    if (!create)
        return 0;
    cleanup_stack = sk_ENGINE_CLEANUP_ITEM_new_null();
    return (cleanup_stack ? 1 : 0);
}

static ENGINE_CLEANUP_ITEM *int_cleanup_item(ENGINE_CLEANUP_CB *cb)
{
    ENGINE_CLEANUP_ITEM *item = OPENSSL_malloc(sizeof(ENGINE_CLEANUP_ITEM));
    if (!item)
        return NULL;
    item->cb = cb;
    return item;
}

void engine_cleanup_add_first(ENGINE_CLEANUP_CB *cb)
{
    ENGINE_CLEANUP_ITEM *item;
    if (!int_cleanup_check(1))
        return;
    item = int_cleanup_item(cb);
    if (item)
        sk_ENGINE_CLEANUP_ITEM_insert(cleanup_stack, item, 0);
}

void engine_cleanup_add_last(ENGINE_CLEANUP_CB *cb)
{
    ENGINE_CLEANUP_ITEM *item;
    if (!int_cleanup_check(1))
        return;
    item = int_cleanup_item(cb);
    if (item != NULL) {
        if (sk_ENGINE_CLEANUP_ITEM_push(cleanup_stack, item) <= 0)
            OPENSSL_free(item);
    }
}

/* The API function that performs all cleanup */
static void engine_cleanup_cb_free(ENGINE_CLEANUP_ITEM *item)
{
    (*(item->cb)) ();
    OPENSSL_free(item);
}

void ENGINE_cleanup(void)
{
    if (int_cleanup_check(0)) {
        sk_ENGINE_CLEANUP_ITEM_pop_free(cleanup_stack,
                                        engine_cleanup_cb_free);
        cleanup_stack = NULL;
    }
    /*
     * FIXME: This should be handled (somehow) through RAND, eg. by it
     * registering a cleanup callback.
     */
    RAND_set_rand_method(NULL);
}

/* Now the "ex_data" support */

int ENGINE_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
                            CRYPTO_EX_dup *dup_func,
                            CRYPTO_EX_free *free_func)
{
    return CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_ENGINE, argl, argp,
                                   new_func, dup_func, free_func);
}

int ENGINE_set_ex_data(ENGINE *e, int idx, void *arg)
{
    return (CRYPTO_set_ex_data(&e->ex_data, idx, arg));
}

void *ENGINE_get_ex_data(const ENGINE *e, int idx)
{
    return (CRYPTO_get_ex_data(&e->ex_data, idx));
}

/*
 * Functions to get/set an ENGINE's elements - mainly to avoid exposing the
 * ENGINE structure itself.
 */

int ENGINE_set_id(ENGINE *e, const char *id)
{
    if (id == NULL) {
        ENGINEerr(ENGINE_F_ENGINE_SET_ID, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    e->id = id;
    return 1;
}

int ENGINE_set_name(ENGINE *e, const char *name)
{
    if (name == NULL) {
        ENGINEerr(ENGINE_F_ENGINE_SET_NAME, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    e->name = name;
    return 1;
}

int ENGINE_set_destroy_function(ENGINE *e, ENGINE_GEN_INT_FUNC_PTR destroy_f)
{
    e->destroy = destroy_f;
    return 1;
}

int ENGINE_set_init_function(ENGINE *e, ENGINE_GEN_INT_FUNC_PTR init_f)
{
    e->init = init_f;
    return 1;
}

int ENGINE_set_finish_function(ENGINE *e, ENGINE_GEN_INT_FUNC_PTR finish_f)
{
    e->finish = finish_f;
    return 1;
}

int ENGINE_set_ctrl_function(ENGINE *e, ENGINE_CTRL_FUNC_PTR ctrl_f)
{
    e->ctrl = ctrl_f;
    return 1;
}

int ENGINE_set_flags(ENGINE *e, int flags)
{
    e->flags = flags;
    return 1;
}

int ENGINE_set_cmd_defns(ENGINE *e, const ENGINE_CMD_DEFN *defns)
{
    e->cmd_defns = defns;
    return 1;
}

const char *ENGINE_get_id(const ENGINE *e)
{
    return e->id;
}

const char *ENGINE_get_name(const ENGINE *e)
{
    return e->name;
}

ENGINE_GEN_INT_FUNC_PTR ENGINE_get_destroy_function(const ENGINE *e)
{
    return e->destroy;
}

ENGINE_GEN_INT_FUNC_PTR ENGINE_get_init_function(const ENGINE *e)
{
    return e->init;
}

ENGINE_GEN_INT_FUNC_PTR ENGINE_get_finish_function(const ENGINE *e)
{
    return e->finish;
}

ENGINE_CTRL_FUNC_PTR ENGINE_get_ctrl_function(const ENGINE *e)
{
    return e->ctrl;
}

int ENGINE_get_flags(const ENGINE *e)
{
    return e->flags;
}

const ENGINE_CMD_DEFN *ENGINE_get_cmd_defns(const ENGINE *e)
{
    return e->cmd_defns;
}

/*
 * eng_lib.o is pretty much linked into anything that touches ENGINE already,
 * so put the "static_state" hack here.
 */

static int internal_static_hack = 0;

void *ENGINE_get_static_state(void)
{
    return &internal_static_hack;
}
/* crypto/engine/eng_list.c */
/*
 * Written by Geoff Thorpe (geoff@geoffthorpe.net) for the OpenSSL project
 * 2000.
 */
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
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * ECDH support in OpenSSL originally developed by
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
 */

// #include "cryptlib.h"
// #include "eng_int.h"

/*
 * The linked-list of pointers to engine types. engine_list_head incorporates
 * an implicit structural reference but engine_list_tail does not - the
 * latter is a computational niceity and only points to something that is
 * already pointed to by its predecessor in the list (or engine_list_head
 * itself). In the same way, the use of the "prev" pointer in each ENGINE is
 * to save excessive list iteration, it doesn't correspond to an extra
 * structural reference. Hence, engine_list_head, and each non-null "next"
 * pointer account for the list itself assuming exactly 1 structural
 * reference on each list member.
 */
static ENGINE *engine_list_head = NULL;
static ENGINE *engine_list_tail = NULL;

/*
 * This cleanup function is only needed internally. If it should be called,
 * we register it with the "ENGINE_cleanup()" stack to be called during
 * cleanup.
 */

static void engine_list_cleanup(void)
{
    ENGINE *iterator = engine_list_head;

    while (iterator != NULL) {
        ENGINE_remove(iterator);
        iterator = engine_list_head;
    }
    return;
}

/*
 * These static functions starting with a lower case "engine_" always take
 * place when CRYPTO_LOCK_ENGINE has been locked up.
 */
static int engine_list_add(ENGINE *e)
{
    int conflict = 0;
    ENGINE *iterator = NULL;

    if (e == NULL) {
        ENGINEerr(ENGINE_F_ENGINE_LIST_ADD, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    iterator = engine_list_head;
    while (iterator && !conflict) {
        conflict = (strcmp(iterator->id, e->id) == 0);
        iterator = iterator->next;
    }
    if (conflict) {
        ENGINEerr(ENGINE_F_ENGINE_LIST_ADD, ENGINE_R_CONFLICTING_ENGINE_ID);
        return 0;
    }
    if (engine_list_head == NULL) {
        /* We are adding to an empty list. */
        if (engine_list_tail) {
            ENGINEerr(ENGINE_F_ENGINE_LIST_ADD, ENGINE_R_INTERNAL_LIST_ERROR);
            return 0;
        }
        engine_list_head = e;
        e->prev = NULL;
        /*
         * The first time the list allocates, we should register the cleanup.
         */
        engine_cleanup_add_last(engine_list_cleanup);
    } else {
        /* We are adding to the tail of an existing list. */
        if ((engine_list_tail == NULL) || (engine_list_tail->next != NULL)) {
            ENGINEerr(ENGINE_F_ENGINE_LIST_ADD, ENGINE_R_INTERNAL_LIST_ERROR);
            return 0;
        }
        engine_list_tail->next = e;
        e->prev = engine_list_tail;
    }
    /*
     * Having the engine in the list assumes a structural reference.
     */
    e->struct_ref++;
    engine_ref_debug(e, 0, 1)
        /* However it came to be, e is the last item in the list. */
        engine_list_tail = e;
    e->next = NULL;
    return 1;
}

static int engine_list_remove(ENGINE *e)
{
    ENGINE *iterator;

    if (e == NULL) {
        ENGINEerr(ENGINE_F_ENGINE_LIST_REMOVE, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    /* We need to check that e is in our linked list! */
    iterator = engine_list_head;
    while (iterator && (iterator != e))
        iterator = iterator->next;
    if (iterator == NULL) {
        ENGINEerr(ENGINE_F_ENGINE_LIST_REMOVE,
                  ENGINE_R_ENGINE_IS_NOT_IN_LIST);
        return 0;
    }
    /* un-link e from the chain. */
    if (e->next)
        e->next->prev = e->prev;
    if (e->prev)
        e->prev->next = e->next;
    /* Correct our head/tail if necessary. */
    if (engine_list_head == e)
        engine_list_head = e->next;
    if (engine_list_tail == e)
        engine_list_tail = e->prev;
    engine_free_util(e, 0);
    return 1;
}

/* Get the first/last "ENGINE" type available. */
ENGINE *ENGINE_get_first(void)
{
    ENGINE *ret;

    CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
    ret = engine_list_head;
    if (ret) {
        ret->struct_ref++;
        engine_ref_debug(ret, 0, 1)
    }
    CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
    return ret;
}

ENGINE *ENGINE_get_last(void)
{
    ENGINE *ret;

    CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
    ret = engine_list_tail;
    if (ret) {
        ret->struct_ref++;
        engine_ref_debug(ret, 0, 1)
    }
    CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
    return ret;
}

/* Iterate to the next/previous "ENGINE" type (NULL = end of the list). */
ENGINE *ENGINE_get_next(ENGINE *e)
{
    ENGINE *ret = NULL;
    if (e == NULL) {
        ENGINEerr(ENGINE_F_ENGINE_GET_NEXT, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
    ret = e->next;
    if (ret) {
        /* Return a valid structural refernce to the next ENGINE */
        ret->struct_ref++;
        engine_ref_debug(ret, 0, 1)
    }
    CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
    /* Release the structural reference to the previous ENGINE */
    ENGINE_free(e);
    return ret;
}

ENGINE *ENGINE_get_prev(ENGINE *e)
{
    ENGINE *ret = NULL;
    if (e == NULL) {
        ENGINEerr(ENGINE_F_ENGINE_GET_PREV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
    ret = e->prev;
    if (ret) {
        /* Return a valid structural reference to the next ENGINE */
        ret->struct_ref++;
        engine_ref_debug(ret, 0, 1)
    }
    CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
    /* Release the structural reference to the previous ENGINE */
    ENGINE_free(e);
    return ret;
}

/* Add another "ENGINE" type into the list. */
int ENGINE_add(ENGINE *e)
{
    int to_return = 1;
    if (e == NULL) {
        ENGINEerr(ENGINE_F_ENGINE_ADD, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if ((e->id == NULL) || (e->name == NULL)) {
        ENGINEerr(ENGINE_F_ENGINE_ADD, ENGINE_R_ID_OR_NAME_MISSING);
        return 0;
    }
    CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
    if (!engine_list_add(e)) {
        ENGINEerr(ENGINE_F_ENGINE_ADD, ENGINE_R_INTERNAL_LIST_ERROR);
        to_return = 0;
    }
    CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
    return to_return;
}

/* Remove an existing "ENGINE" type from the array. */
int ENGINE_remove(ENGINE *e)
{
    int to_return = 1;
    if (e == NULL) {
        ENGINEerr(ENGINE_F_ENGINE_REMOVE, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
    if (!engine_list_remove(e)) {
        ENGINEerr(ENGINE_F_ENGINE_REMOVE, ENGINE_R_INTERNAL_LIST_ERROR);
        to_return = 0;
    }
    CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
    return to_return;
}

static void engine_cpy(ENGINE *dest, const ENGINE *src)
{
    dest->id = src->id;
    dest->name = src->name;
#ifndef OPENSSL_NO_RSA
    dest->rsa_meth = src->rsa_meth;
#endif
#ifndef OPENSSL_NO_DSA
    dest->dsa_meth = src->dsa_meth;
#endif
#ifndef OPENSSL_NO_DH
    dest->dh_meth = src->dh_meth;
#endif
#ifndef OPENSSL_NO_ECDH
    dest->ecdh_meth = src->ecdh_meth;
#endif
#ifndef OPENSSL_NO_ECDSA
    dest->ecdsa_meth = src->ecdsa_meth;
#endif
    dest->rand_meth = src->rand_meth;
    dest->store_meth = src->store_meth;
    dest->ciphers = src->ciphers;
    dest->digests = src->digests;
    dest->pkey_meths = src->pkey_meths;
    dest->destroy = src->destroy;
    dest->init = src->init;
    dest->finish = src->finish;
    dest->ctrl = src->ctrl;
    dest->load_privkey = src->load_privkey;
    dest->load_pubkey = src->load_pubkey;
    dest->cmd_defns = src->cmd_defns;
    dest->flags = src->flags;
}

ENGINE *ENGINE_by_id(const char *id)
{
    ENGINE *iterator;
    char *load_dir = NULL;
    if (id == NULL) {
        ENGINEerr(ENGINE_F_ENGINE_BY_ID, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }
    CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
    iterator = engine_list_head;
    while (iterator && (strcmp(id, iterator->id) != 0))
        iterator = iterator->next;
    if (iterator) {
        /*
         * We need to return a structural reference. If this is an ENGINE
         * type that returns copies, make a duplicate - otherwise increment
         * the existing ENGINE's reference count.
         */
        if (iterator->flags & ENGINE_FLAGS_BY_ID_COPY) {
            ENGINE *cp = ENGINE_new();
            if (!cp)
                iterator = NULL;
            else {
                engine_cpy(cp, iterator);
                iterator = cp;
            }
        } else {
            iterator->struct_ref++;
            engine_ref_debug(iterator, 0, 1)
        }
    }
    CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
#if 0
    if (iterator == NULL) {
        ENGINEerr(ENGINE_F_ENGINE_BY_ID, ENGINE_R_NO_SUCH_ENGINE);
        ERR_add_error_data(2, "id=", id);
    }
    return iterator;
#else
    /* EEK! Experimental code starts */
    if (iterator)
        return iterator;
    /*
     * Prevent infinite recusrion if we're looking for the dynamic engine.
     */
    if (strcmp(id, "dynamic")) {
# ifdef OPENSSL_SYS_VMS
        if ((load_dir = ossl_safe_getenv("OPENSSL_ENGINES")) == 0)
            load_dir = "SSLROOT:[ENGINES]";
# else
        if ((load_dir = ossl_safe_getenv("OPENSSL_ENGINES")) == 0)
            load_dir = ENGINESDIR;
# endif
        iterator = ENGINE_by_id("dynamic");
        if (!iterator || !ENGINE_ctrl_cmd_string(iterator, "ID", id, 0) ||
            !ENGINE_ctrl_cmd_string(iterator, "DIR_LOAD", "2", 0) ||
            !ENGINE_ctrl_cmd_string(iterator, "DIR_ADD",
                                    load_dir, 0) ||
            !ENGINE_ctrl_cmd_string(iterator, "LIST_ADD", "1", 0) ||
            !ENGINE_ctrl_cmd_string(iterator, "LOAD", NULL, 0))
            goto notfound;
        return iterator;
    }
 notfound:
    ENGINE_free(iterator);
    ENGINEerr(ENGINE_F_ENGINE_BY_ID, ENGINE_R_NO_SUCH_ENGINE);
    ERR_add_error_data(2, "id=", id);
    return NULL;
    /* EEK! Experimental code ends */
#endif
}

int ENGINE_up_ref(ENGINE *e)
{
    if (e == NULL) {
        ENGINEerr(ENGINE_F_ENGINE_UP_REF, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    CRYPTO_add(&e->struct_ref, 1, CRYPTO_LOCK_ENGINE);
    return 1;
}
/* crypto/engine/eng_openssl.c */
/*
 * Written by Geoff Thorpe (geoff@geoffthorpe.net) for the OpenSSL project
 * 2000.
 */
/* ====================================================================
 * Copyright (c) 1999-2001 The OpenSSL Project.  All rights reserved.
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
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * ECDH support in OpenSSL originally developed by
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
 */

#include <stdio.h>
#include "crypto.h"
// #include "cryptlib.h"
// #include "engine.h"
// #include "dso.h"
#include "pem.h"
// #include "evp.h"
// #include "rand.h"
#ifndef OPENSSL_NO_RSA
# include "rsa.h"
#endif
#ifndef OPENSSL_NO_DSA
# include "dsa.h"
#endif
#ifndef OPENSSL_NO_DH
# include "dh.h"
#endif

/*
 * This testing gunk is implemented (and explained) lower down. It also
 * assumes the application explicitly calls "ENGINE_load_openssl()" because
 * this is no longer automatic in ENGINE_load_builtin_engines().
 */
#define TEST_ENG_OPENSSL_RC4
#define TEST_ENG_OPENSSL_PKEY
/* #define TEST_ENG_OPENSSL_RC4_OTHERS */
#define TEST_ENG_OPENSSL_RC4_P_INIT
/* #define TEST_ENG_OPENSSL_RC4_P_CIPHER */
#define TEST_ENG_OPENSSL_SHA
/* #define TEST_ENG_OPENSSL_SHA_OTHERS */
/* #define TEST_ENG_OPENSSL_SHA_P_INIT */
/* #define TEST_ENG_OPENSSL_SHA_P_UPDATE */
/* #define TEST_ENG_OPENSSL_SHA_P_FINAL */

/* Now check what of those algorithms are actually enabled */
#ifdef OPENSSL_NO_RC4
# undef TEST_ENG_OPENSSL_RC4
# undef TEST_ENG_OPENSSL_RC4_OTHERS
# undef TEST_ENG_OPENSSL_RC4_P_INIT
# undef TEST_ENG_OPENSSL_RC4_P_CIPHER
#endif
#if defined(OPENSSL_NO_SHA) || defined(OPENSSL_NO_SHA0) || defined(OPENSSL_NO_SHA1)
# undef TEST_ENG_OPENSSL_SHA
# undef TEST_ENG_OPENSSL_SHA_OTHERS
# undef TEST_ENG_OPENSSL_SHA_P_INIT
# undef TEST_ENG_OPENSSL_SHA_P_UPDATE
# undef TEST_ENG_OPENSSL_SHA_P_FINAL
#endif

#ifdef TEST_ENG_OPENSSL_RC4
static int openssl_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                           const int **nids, int nid);
#endif
#ifdef TEST_ENG_OPENSSL_SHA
static int openssl_digests(ENGINE *e, const EVP_MD **digest,
                           const int **nids, int nid);
#endif

#ifdef TEST_ENG_OPENSSL_PKEY
static EVP_PKEY *openssl_load_privkey(ENGINE *eng, const char *key_id,
                                      UI_METHOD *ui_method,
                                      void *callback_data);
#endif

/* The constants used when creating the ENGINE */
static const char *engine_openssl_id = "openssl";
static const char *engine_openssl_name = "Software engine support";

/*
 * This internal function is used by ENGINE_openssl() and possibly by the
 * "dynamic" ENGINE support too
 */
static int bind_helper(ENGINE *e)
{
    if (!ENGINE_set_id(e, engine_openssl_id)
        || !ENGINE_set_name(e, engine_openssl_name)
#ifndef TEST_ENG_OPENSSL_NO_ALGORITHMS
# ifndef OPENSSL_NO_RSA
        || !ENGINE_set_RSA(e, RSA_get_default_method())
# endif
# ifndef OPENSSL_NO_DSA
        || !ENGINE_set_DSA(e, DSA_get_default_method())
# endif
# ifndef OPENSSL_NO_ECDH
        || !ENGINE_set_ECDH(e, ECDH_OpenSSL())
# endif
# ifndef OPENSSL_NO_ECDSA
        || !ENGINE_set_ECDSA(e, ECDSA_OpenSSL())
# endif
# ifndef OPENSSL_NO_DH
        || !ENGINE_set_DH(e, DH_get_default_method())
# endif
        || !ENGINE_set_RAND(e, RAND_SSLeay())
# ifdef TEST_ENG_OPENSSL_RC4
        || !ENGINE_set_ciphers(e, openssl_ciphers)
# endif
# ifdef TEST_ENG_OPENSSL_SHA
        || !ENGINE_set_digests(e, openssl_digests)
# endif
#endif
#ifdef TEST_ENG_OPENSSL_PKEY
        || !ENGINE_set_load_privkey_function(e, openssl_load_privkey)
#endif
        )
        return 0;
    /*
     * If we add errors to this ENGINE, ensure the error handling is setup
     * here
     */
    /* openssl_load_error_strings(); */
    return 1;
}

static ENGINE *engine_openssl(void)
{
    ENGINE *ret = ENGINE_new();
    if (!ret)
        return NULL;
    if (!bind_helper(ret)) {
        ENGINE_free(ret);
        return NULL;
    }
    return ret;
}

void ENGINE_load_openssl(void)
{
    ENGINE *toadd = engine_openssl();
    if (!toadd)
        return;
    ENGINE_add(toadd);
    /*
     * If the "add" worked, it gets a structural reference. So either way, we
     * release our just-created reference.
     */
    ENGINE_free(toadd);
    ERR_clear_error();
}

/*
 * This stuff is needed if this ENGINE is being compiled into a
 * self-contained shared-library.
 */
#ifdef ENGINE_DYNAMIC_SUPPORT
static int bind_fn(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, engine_openssl_id) != 0))
        return 0;
    if (!bind_helper(e))
        return 0;
    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
    IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)
#endif                          /* ENGINE_DYNAMIC_SUPPORT */
#ifdef TEST_ENG_OPENSSL_RC4
/*-
 * This section of code compiles an "alternative implementation" of two modes of
 * RC4 into this ENGINE. The result is that EVP_CIPHER operation for "rc4"
 * should under normal circumstances go via this support rather than the default
 * EVP support. There are other symbols to tweak the testing;
 *    TEST_ENC_OPENSSL_RC4_OTHERS - print a one line message to stderr each time
 *        we're asked for a cipher we don't support (should not happen).
 *    TEST_ENG_OPENSSL_RC4_P_INIT - print a one line message to stderr each time
 *        the "init_key" handler is called.
 *    TEST_ENG_OPENSSL_RC4_P_CIPHER - ditto for the "cipher" handler.
 */
# include "rc4.h"
# define TEST_RC4_KEY_SIZE               16
static int test_cipher_nids[] = { NID_rc4, NID_rc4_40 };

static int test_cipher_nids_number = 2;
typedef struct {
    unsigned char key[TEST_RC4_KEY_SIZE];
    RC4_KEY ks;
} TEST_RC4_KEY;
# define test(ctx) ((TEST_RC4_KEY *)(ctx)->cipher_data)
static int test_rc4_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc)
{
# ifdef TEST_ENG_OPENSSL_RC4_P_INIT
    fprintf(stderr, "(TEST_ENG_OPENSSL_RC4) test_init_key() called\n");
# endif
    memcpy(&test(ctx)->key[0], key, EVP_CIPHER_CTX_key_length(ctx));
    RC4_set_key(&test(ctx)->ks, EVP_CIPHER_CTX_key_length(ctx),
                test(ctx)->key);
    return 1;
}

static int test_rc4_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                           const unsigned char *in, size_t inl)
{
# ifdef TEST_ENG_OPENSSL_RC4_P_CIPHER
    fprintf(stderr, "(TEST_ENG_OPENSSL_RC4) test_cipher() called\n");
# endif
    RC4(&test(ctx)->ks, inl, in, out);
    return 1;
}

static const EVP_CIPHER test_r4_cipher = {
    NID_rc4,
    1, TEST_RC4_KEY_SIZE, 0,
    EVP_CIPH_VARIABLE_LENGTH,
    test_rc4_init_key,
    test_rc4_cipher,
    NULL,
    sizeof(TEST_RC4_KEY),
    NULL,
    NULL,
    NULL,
    NULL
};

static const EVP_CIPHER test_r4_40_cipher = {
    NID_rc4_40,
    1, 5 /* 40 bit */ , 0,
    EVP_CIPH_VARIABLE_LENGTH,
    test_rc4_init_key,
    test_rc4_cipher,
    NULL,
    sizeof(TEST_RC4_KEY),
    NULL,
    NULL,
    NULL,
    NULL
};

static int openssl_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                           const int **nids, int nid)
{
    if (!cipher) {
        /* We are returning a list of supported nids */
        *nids = test_cipher_nids;
        return test_cipher_nids_number;
    }
    /* We are being asked for a specific cipher */
    if (nid == NID_rc4)
        *cipher = &test_r4_cipher;
    else if (nid == NID_rc4_40)
        *cipher = &test_r4_40_cipher;
    else {
# ifdef TEST_ENG_OPENSSL_RC4_OTHERS
        fprintf(stderr, "(TEST_ENG_OPENSSL_RC4) returning NULL for "
                "nid %d\n", nid);
# endif
        *cipher = NULL;
        return 0;
    }
    return 1;
}
#endif

#ifdef TEST_ENG_OPENSSL_SHA
/* Much the same sort of comment as for TEST_ENG_OPENSSL_RC4 */
# include "sha.h"
static int test_digest_nids[] = { NID_sha1 };

static int test_digest_nids_number = 1;
static int test_sha1_init(EVP_MD_CTX *ctx)
{
# ifdef TEST_ENG_OPENSSL_SHA_P_INIT
    fprintf(stderr, "(TEST_ENG_OPENSSL_SHA) test_sha1_init() called\n");
# endif
    return SHA1_Init(ctx->md_data);
}

static int test_sha1_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
# ifdef TEST_ENG_OPENSSL_SHA_P_UPDATE
    fprintf(stderr, "(TEST_ENG_OPENSSL_SHA) test_sha1_update() called\n");
# endif
    return SHA1_Update(ctx->md_data, data, count);
}

static int test_sha1_final(EVP_MD_CTX *ctx, unsigned char *md)
{
# ifdef TEST_ENG_OPENSSL_SHA_P_FINAL
    fprintf(stderr, "(TEST_ENG_OPENSSL_SHA) test_sha1_final() called\n");
# endif
    return SHA1_Final(md, ctx->md_data);
}

static const EVP_MD test_sha_md = {
    NID_sha1,
    NID_sha1WithRSAEncryption,
    SHA_DIGEST_LENGTH,
    0,
    test_sha1_init,
    test_sha1_update,
    test_sha1_final,
    NULL,
    NULL,
    EVP_PKEY_RSA_method,
    SHA_CBLOCK,
    sizeof(EVP_MD *) + sizeof(SHA_CTX),
};

static int openssl_digests(ENGINE *e, const EVP_MD **digest,
                           const int **nids, int nid)
{
    if (!digest) {
        /* We are returning a list of supported nids */
        *nids = test_digest_nids;
        return test_digest_nids_number;
    }
    /* We are being asked for a specific digest */
    if (nid == NID_sha1)
        *digest = &test_sha_md;
    else {
# ifdef TEST_ENG_OPENSSL_SHA_OTHERS
        fprintf(stderr, "(TEST_ENG_OPENSSL_SHA) returning NULL for "
                "nid %d\n", nid);
# endif
        *digest = NULL;
        return 0;
    }
    return 1;
}
#endif

#ifdef TEST_ENG_OPENSSL_PKEY
static EVP_PKEY *openssl_load_privkey(ENGINE *eng, const char *key_id,
                                      UI_METHOD *ui_method,
                                      void *callback_data)
{
    BIO *in;
    EVP_PKEY *key;
    fprintf(stderr, "(TEST_ENG_OPENSSL_PKEY)Loading Private key %s\n",
            key_id);
    in = BIO_new_file(key_id, "r");
    if (!in)
        return NULL;
    key = PEM_read_bio_PrivateKey(in, NULL, 0, NULL);
    BIO_free(in);
    return key;
}
#endif
/* crypto/engine/eng_pkey.c */
/* ====================================================================
 * Copyright (c) 1999-2001 The OpenSSL Project.  All rights reserved.
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

// #include "eng_int.h"

/* Basic get/set stuff */

int ENGINE_set_load_privkey_function(ENGINE *e,
                                     ENGINE_LOAD_KEY_PTR loadpriv_f)
{
    e->load_privkey = loadpriv_f;
    return 1;
}

int ENGINE_set_load_pubkey_function(ENGINE *e, ENGINE_LOAD_KEY_PTR loadpub_f)
{
    e->load_pubkey = loadpub_f;
    return 1;
}

int ENGINE_set_load_ssl_client_cert_function(ENGINE *e,
                                             ENGINE_SSL_CLIENT_CERT_PTR
                                             loadssl_f)
{
    e->load_ssl_client_cert = loadssl_f;
    return 1;
}

ENGINE_LOAD_KEY_PTR ENGINE_get_load_privkey_function(const ENGINE *e)
{
    return e->load_privkey;
}

ENGINE_LOAD_KEY_PTR ENGINE_get_load_pubkey_function(const ENGINE *e)
{
    return e->load_pubkey;
}

ENGINE_SSL_CLIENT_CERT_PTR ENGINE_get_ssl_client_cert_function(const ENGINE
                                                               *e)
{
    return e->load_ssl_client_cert;
}

/* API functions to load public/private keys */

EVP_PKEY *ENGINE_load_private_key(ENGINE *e, const char *key_id,
                                  UI_METHOD *ui_method, void *callback_data)
{
    EVP_PKEY *pkey;

    if (e == NULL) {
        ENGINEerr(ENGINE_F_ENGINE_LOAD_PRIVATE_KEY,
                  ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
    if (e->funct_ref == 0) {
        CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
        ENGINEerr(ENGINE_F_ENGINE_LOAD_PRIVATE_KEY, ENGINE_R_NOT_INITIALISED);
        return 0;
    }
    CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
    if (!e->load_privkey) {
        ENGINEerr(ENGINE_F_ENGINE_LOAD_PRIVATE_KEY,
                  ENGINE_R_NO_LOAD_FUNCTION);
        return 0;
    }
    pkey = e->load_privkey(e, key_id, ui_method, callback_data);
    if (!pkey) {
        ENGINEerr(ENGINE_F_ENGINE_LOAD_PRIVATE_KEY,
                  ENGINE_R_FAILED_LOADING_PRIVATE_KEY);
        return 0;
    }
    return pkey;
}

EVP_PKEY *ENGINE_load_public_key(ENGINE *e, const char *key_id,
                                 UI_METHOD *ui_method, void *callback_data)
{
    EVP_PKEY *pkey;

    if (e == NULL) {
        ENGINEerr(ENGINE_F_ENGINE_LOAD_PUBLIC_KEY,
                  ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
    if (e->funct_ref == 0) {
        CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
        ENGINEerr(ENGINE_F_ENGINE_LOAD_PUBLIC_KEY, ENGINE_R_NOT_INITIALISED);
        return 0;
    }
    CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
    if (!e->load_pubkey) {
        ENGINEerr(ENGINE_F_ENGINE_LOAD_PUBLIC_KEY, ENGINE_R_NO_LOAD_FUNCTION);
        return 0;
    }
    pkey = e->load_pubkey(e, key_id, ui_method, callback_data);
    if (!pkey) {
        ENGINEerr(ENGINE_F_ENGINE_LOAD_PUBLIC_KEY,
                  ENGINE_R_FAILED_LOADING_PUBLIC_KEY);
        return 0;
    }
    return pkey;
}

int ENGINE_load_ssl_client_cert(ENGINE *e, SSL *s,
                                STACK_OF(X509_NAME) *ca_dn, X509 **pcert,
                                EVP_PKEY **ppkey, STACK_OF(X509) **pother,
                                UI_METHOD *ui_method, void *callback_data)
{

    if (e == NULL) {
        ENGINEerr(ENGINE_F_ENGINE_LOAD_SSL_CLIENT_CERT,
                  ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
    if (e->funct_ref == 0) {
        CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
        ENGINEerr(ENGINE_F_ENGINE_LOAD_SSL_CLIENT_CERT,
                  ENGINE_R_NOT_INITIALISED);
        return 0;
    }
    CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
    if (!e->load_ssl_client_cert) {
        ENGINEerr(ENGINE_F_ENGINE_LOAD_SSL_CLIENT_CERT,
                  ENGINE_R_NO_LOAD_FUNCTION);
        return 0;
    }
    return e->load_ssl_client_cert(e, s, ca_dn, pcert, ppkey, pother,
                                   ui_method, callback_data);
}
/* ====================================================================
 * Copyright (c) 2011 The OpenSSL Project.  All rights reserved.
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
 */

#include "opensslconf.h"

#include <stdio.h>
#include <string.h>
// #include "engine.h"
// #include "rand.h"
// #include "err.h"

#if (defined(__i386)   || defined(__i386__)   || defined(_M_IX86) || \
     defined(__x86_64) || defined(__x86_64__) || \
     defined(_M_AMD64) || defined (_M_X64)) && defined(OPENSSL_CPUID_OBJ)

size_t OPENSSL_ia32_rdrand(void);

static int get_random_bytes(unsigned char *buf, int num)
{
    size_t rnd;

    while (num >= (int)sizeof(size_t)) {
        if ((rnd = OPENSSL_ia32_rdrand()) == 0)
            return 0;

        *((size_t *)buf) = rnd;
        buf += sizeof(size_t);
        num -= sizeof(size_t);
    }
    if (num) {
        if ((rnd = OPENSSL_ia32_rdrand()) == 0)
            return 0;

        memcpy(buf, &rnd, num);
    }

    return 1;
}

static int random_status(void)
{
    return 1;
}

static RAND_METHOD rdrand_meth = {
    NULL,                       /* seed */
    get_random_bytes,
    NULL,                       /* cleanup */
    NULL,                       /* add */
    get_random_bytes,
    random_status,
};

static int rdrand_init(ENGINE *e)
{
    return 1;
}

static const char *engine_e_rdrand_id = "rdrand";
static const char *engine_e_rdrand_name = "Intel RDRAND engine";

static int bind_helper(ENGINE *e)
{
    if (!ENGINE_set_id(e, engine_e_rdrand_id) ||
        !ENGINE_set_name(e, engine_e_rdrand_name) ||
        !ENGINE_set_flags(e, ENGINE_FLAGS_NO_REGISTER_ALL) ||
        !ENGINE_set_init_function(e, rdrand_init) ||
        !ENGINE_set_RAND(e, &rdrand_meth))
        return 0;

    return 1;
}

static ENGINE *ENGINE_rdrand(void)
{
    ENGINE *ret = ENGINE_new();
    if (!ret)
        return NULL;
    if (!bind_helper(ret)) {
        ENGINE_free(ret);
        return NULL;
    }
    return ret;
}

void ENGINE_load_rdrand(void)
{
    extern unsigned int OPENSSL_ia32cap_P[];

    if (OPENSSL_ia32cap_P[1] & (1 << (62 - 32))) {
        ENGINE *toadd = ENGINE_rdrand();
        if (!toadd)
            return;
        ENGINE_add(toadd);
        ENGINE_free(toadd);
        ERR_clear_error();
    }
}
#else
void ENGINE_load_rdrand(void)
{
}
#endif
/* ====================================================================
 * Copyright (c) 2001-2018 The OpenSSL Project.  All rights reserved.
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

// #include "cryptlib.h"
// #include "evp.h"
#include "lhash.h"
// #include "eng_int.h"

/* The type of the items in the table */
typedef struct st_engine_pile {
    /* The 'nid' of this algorithm/mode */
    int nid;
    /* ENGINEs that implement this algorithm/mode. */
    STACK_OF(ENGINE) *sk;
    /* The default ENGINE to perform this algorithm/mode. */
    ENGINE *funct;
    /*
     * Zero if 'sk' is newer than the cached 'funct', non-zero otherwise
     */
    int uptodate;
} ENGINE_PILE;

DECLARE_LHASH_OF(ENGINE_PILE);

/* The type exposed in eng_int.h */
struct st_engine_table {
    LHASH_OF(ENGINE_PILE) piles;
};                              /* ENGINE_TABLE */

typedef struct st_engine_pile_doall {
    engine_table_doall_cb *cb;
    void *arg;
} ENGINE_PILE_DOALL;

/* Global flags (ENGINE_TABLE_FLAG_***). */
static unsigned int table_flags = 0;

/* API function manipulating 'table_flags' */
unsigned int ENGINE_get_table_flags(void)
{
    return table_flags;
}

void ENGINE_set_table_flags(unsigned int flags)
{
    table_flags = flags;
}

/* Internal functions for the "piles" hash table */
static unsigned long engine_pile_hash(const ENGINE_PILE *c)
{
    return c->nid;
}

static int engine_pile_cmp(const ENGINE_PILE *a, const ENGINE_PILE *b)
{
    return a->nid - b->nid;
}

static IMPLEMENT_LHASH_HASH_FN(engine_pile, ENGINE_PILE)
static IMPLEMENT_LHASH_COMP_FN(engine_pile, ENGINE_PILE)

static int int_table_check(ENGINE_TABLE **t, int create)
{
    LHASH_OF(ENGINE_PILE) *lh;

    if (*t)
        return 1;
    if (!create)
        return 0;
    if ((lh = lh_ENGINE_PILE_new()) == NULL)
        return 0;
    *t = (ENGINE_TABLE *)lh;
    return 1;
}

/*
 * Privately exposed (via eng_int.h) functions for adding and/or removing
 * ENGINEs from the implementation table
 */
int engine_table_register(ENGINE_TABLE **table, ENGINE_CLEANUP_CB *cleanup,
                          ENGINE *e, const int *nids, int num_nids,
                          int setdefault)
{
    int ret = 0, added = 0;
    ENGINE_PILE tmplate, *fnd;
    CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
    if (!(*table))
        added = 1;
    if (!int_table_check(table, 1))
        goto end;
    if (added)
        /* The cleanup callback needs to be added */
        engine_cleanup_add_first(cleanup);
    while (num_nids--) {
        tmplate.nid = *nids;
        fnd = lh_ENGINE_PILE_retrieve(&(*table)->piles, &tmplate);
        if (!fnd) {
            fnd = OPENSSL_malloc(sizeof(ENGINE_PILE));
            if (!fnd)
                goto end;
            fnd->uptodate = 1;
            fnd->nid = *nids;
            fnd->sk = sk_ENGINE_new_null();
            if (!fnd->sk) {
                OPENSSL_free(fnd);
                goto end;
            }
            fnd->funct = NULL;
            (void)lh_ENGINE_PILE_insert(&(*table)->piles, fnd);
            if (lh_ENGINE_PILE_retrieve(&(*table)->piles, &tmplate) != fnd) {
                sk_ENGINE_free(fnd->sk);
                OPENSSL_free(fnd);
                goto end;
            }
        }
        /* A registration shouldn't add duplciate entries */
        (void)sk_ENGINE_delete_ptr(fnd->sk, e);
        /*
         * if 'setdefault', this ENGINE goes to the head of the list
         */
        if (!sk_ENGINE_push(fnd->sk, e))
            goto end;
        /* "touch" this ENGINE_PILE */
        fnd->uptodate = 0;
        if (setdefault) {
            if (!engine_unlocked_init(e)) {
                ENGINEerr(ENGINE_F_ENGINE_TABLE_REGISTER,
                          ENGINE_R_INIT_FAILED);
                goto end;
            }
            if (fnd->funct)
                engine_unlocked_finish(fnd->funct, 0);
            fnd->funct = e;
            fnd->uptodate = 1;
        }
        nids++;
    }
    ret = 1;
 end:
    CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
    return ret;
}

static void int_unregister_cb_doall_arg(ENGINE_PILE *pile, ENGINE *e)
{
    int n;
    /* Iterate the 'c->sk' stack removing any occurance of 'e' */
    while ((n = sk_ENGINE_find(pile->sk, e)) >= 0) {
        (void)sk_ENGINE_delete(pile->sk, n);
        pile->uptodate = 0;
    }
    if (pile->funct == e) {
        engine_unlocked_finish(e, 0);
        pile->funct = NULL;
    }
}

static IMPLEMENT_LHASH_DOALL_ARG_FN(int_unregister_cb, ENGINE_PILE, ENGINE)

void engine_table_unregister(ENGINE_TABLE **table, ENGINE *e)
{
    CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
    if (int_table_check(table, 0))
        lh_ENGINE_PILE_doall_arg(&(*table)->piles,
                                 LHASH_DOALL_ARG_FN(int_unregister_cb),
                                 ENGINE, e);
    CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
}

static void int_cleanup_cb_doall(ENGINE_PILE *p)
{
    sk_ENGINE_free(p->sk);
    if (p->funct)
        engine_unlocked_finish(p->funct, 0);
    OPENSSL_free(p);
}

static IMPLEMENT_LHASH_DOALL_FN(int_cleanup_cb, ENGINE_PILE)

void engine_table_cleanup(ENGINE_TABLE **table)
{
    CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
    if (*table) {
        lh_ENGINE_PILE_doall(&(*table)->piles,
                             LHASH_DOALL_FN(int_cleanup_cb));
        lh_ENGINE_PILE_free(&(*table)->piles);
        *table = NULL;
    }
    CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
}

/* return a functional reference for a given 'nid' */
#ifndef ENGINE_TABLE_DEBUG
ENGINE *engine_table_select(ENGINE_TABLE **table, int nid)
#else
ENGINE *engine_table_select_tmp(ENGINE_TABLE **table, int nid, const char *f,
                                int l)
#endif
{
    ENGINE *ret = NULL;
    ENGINE_PILE tmplate, *fnd = NULL;
    int initres, loop = 0;

    if (!(*table)) {
#ifdef ENGINE_TABLE_DEBUG
        fprintf(stderr, "engine_table_dbg: %s:%d, nid=%d, nothing "
                "registered!\n", f, l, nid);
#endif
        return NULL;
    }
    ERR_set_mark();
    CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
    /*
     * Check again inside the lock otherwise we could race against cleanup
     * operations. But don't worry about a fprintf(stderr).
     */
    if (!int_table_check(table, 0))
        goto end;
    tmplate.nid = nid;
    fnd = lh_ENGINE_PILE_retrieve(&(*table)->piles, &tmplate);
    if (!fnd)
        goto end;
    if (fnd->funct && engine_unlocked_init(fnd->funct)) {
#ifdef ENGINE_TABLE_DEBUG
        fprintf(stderr, "engine_table_dbg: %s:%d, nid=%d, using "
                "ENGINE '%s' cached\n", f, l, nid, fnd->funct->id);
#endif
        ret = fnd->funct;
        goto end;
    }
    if (fnd->uptodate) {
        ret = fnd->funct;
        goto end;
    }
 trynext:
    ret = sk_ENGINE_value(fnd->sk, loop++);
    if (!ret) {
#ifdef ENGINE_TABLE_DEBUG
        fprintf(stderr, "engine_table_dbg: %s:%d, nid=%d, no "
                "registered implementations would initialise\n", f, l, nid);
#endif
        goto end;
    }
    /* Try to initialise the ENGINE? */
    if ((ret->funct_ref > 0) || !(table_flags & ENGINE_TABLE_FLAG_NOINIT))
        initres = engine_unlocked_init(ret);
    else
        initres = 0;
    if (initres) {
        /* Update 'funct' */
        if ((fnd->funct != ret) && engine_unlocked_init(ret)) {
            /* If there was a previous default we release it. */
            if (fnd->funct)
                engine_unlocked_finish(fnd->funct, 0);
            fnd->funct = ret;
#ifdef ENGINE_TABLE_DEBUG
            fprintf(stderr, "engine_table_dbg: %s:%d, nid=%d, "
                    "setting default to '%s'\n", f, l, nid, ret->id);
#endif
        }
#ifdef ENGINE_TABLE_DEBUG
        fprintf(stderr, "engine_table_dbg: %s:%d, nid=%d, using "
                "newly initialised '%s'\n", f, l, nid, ret->id);
#endif
        goto end;
    }
    goto trynext;
 end:
    /*
     * If it failed, it is unlikely to succeed again until some future
     * registrations have taken place. In all cases, we cache.
     */
    if (fnd)
        fnd->uptodate = 1;
#ifdef ENGINE_TABLE_DEBUG
    if (ret)
        fprintf(stderr, "engine_table_dbg: %s:%d, nid=%d, caching "
                "ENGINE '%s'\n", f, l, nid, ret->id);
    else
        fprintf(stderr, "engine_table_dbg: %s:%d, nid=%d, caching "
                "'no matching ENGINE'\n", f, l, nid);
#endif
    CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
    /*
     * Whatever happened, any failed init()s are not failures in this
     * context, so clear our error state.
     */
    ERR_pop_to_mark();
    return ret;
}

/* Table enumeration */

static void int_cb_doall_arg(ENGINE_PILE *pile, ENGINE_PILE_DOALL *dall)
{
    dall->cb(pile->nid, pile->sk, pile->funct, dall->arg);
}

static IMPLEMENT_LHASH_DOALL_ARG_FN(int_cb, ENGINE_PILE, ENGINE_PILE_DOALL)

void engine_table_doall(ENGINE_TABLE *table, engine_table_doall_cb *cb,
                        void *arg)
{
    ENGINE_PILE_DOALL dall;
    dall.cb = cb;
    dall.arg = arg;
    if (table)
        lh_ENGINE_PILE_doall_arg(&table->piles,
                                 LHASH_DOALL_ARG_FN(int_cb),
                                 ENGINE_PILE_DOALL, &dall);
}
