/* crypto/x509/by_dir.c */
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
#include <errno.h>

#include "cryptlib.h"

#ifndef NO_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifndef OPENSSL_NO_POSIX_IO
# include <sys/stat.h>
#endif

#include "lhash.h"
#include "x509.h"

typedef struct lookup_dir_hashes_st {
    unsigned long hash;
    int suffix;
} BY_DIR_HASH;

typedef struct lookup_dir_entry_st {
    char *dir;
    int dir_type;
    STACK_OF(BY_DIR_HASH) *hashes;
} BY_DIR_ENTRY;

typedef struct lookup_dir_st {
    BUF_MEM *buffer;
    STACK_OF(BY_DIR_ENTRY) *dirs;
} BY_DIR;

DECLARE_STACK_OF(BY_DIR_HASH)
DECLARE_STACK_OF(BY_DIR_ENTRY)

static int dir_ctrl(X509_LOOKUP *ctx, int cmd, const char *argp, long argl,
                    char **ret);
static int new_dir(X509_LOOKUP *lu);
static void free_dir(X509_LOOKUP *lu);
static int add_cert_dir(BY_DIR *ctx, const char *dir, int type);
static int get_cert_by_subject(X509_LOOKUP *xl, int type, X509_NAME *name,
                               X509_OBJECT *ret);
X509_LOOKUP_METHOD x509_dir_lookup = {
    "Load certs from files in a directory",
    new_dir,                    /* new */
    free_dir,                   /* free */
    NULL,                       /* init */
    NULL,                       /* shutdown */
    dir_ctrl,                   /* ctrl */
    get_cert_by_subject,        /* get_by_subject */
    NULL,                       /* get_by_issuer_serial */
    NULL,                       /* get_by_fingerprint */
    NULL,                       /* get_by_alias */
};

X509_LOOKUP_METHOD *X509_LOOKUP_hash_dir(void)
{
    return (&x509_dir_lookup);
}

static int dir_ctrl(X509_LOOKUP *ctx, int cmd, const char *argp, long argl,
                    char **retp)
{
    int ret = 0;
    BY_DIR *ld;
    char *dir = NULL;

    ld = (BY_DIR *)ctx->method_data;

    switch (cmd) {
    case X509_L_ADD_DIR:
        if (argl == X509_FILETYPE_DEFAULT) {
            dir = (char *)ossl_safe_getenv(X509_get_default_cert_dir_env());
            if (dir)
                ret = add_cert_dir(ld, dir, X509_FILETYPE_PEM);
            else
                ret = add_cert_dir(ld, X509_get_default_cert_dir(),
                                   X509_FILETYPE_PEM);
            if (!ret) {
                X509err(X509_F_DIR_CTRL, X509_R_LOADING_CERT_DIR);
            }
        } else
            ret = add_cert_dir(ld, argp, (int)argl);
        break;
    }
    return (ret);
}

static int new_dir(X509_LOOKUP *lu)
{
    BY_DIR *a;

    if ((a = (BY_DIR *)OPENSSL_malloc(sizeof(BY_DIR))) == NULL)
        return (0);
    if ((a->buffer = BUF_MEM_new()) == NULL) {
        OPENSSL_free(a);
        return (0);
    }
    a->dirs = NULL;
    lu->method_data = (char *)a;
    return (1);
}

static void by_dir_hash_free(BY_DIR_HASH *hash)
{
    OPENSSL_free(hash);
}

static int by_dir_hash_cmp(const BY_DIR_HASH *const *a,
                           const BY_DIR_HASH *const *b)
{
    if ((*a)->hash > (*b)->hash)
        return 1;
    if ((*a)->hash < (*b)->hash)
        return -1;
    return 0;
}

static void by_dir_entry_free(BY_DIR_ENTRY *ent)
{
    if (ent->dir)
        OPENSSL_free(ent->dir);
    if (ent->hashes)
        sk_BY_DIR_HASH_pop_free(ent->hashes, by_dir_hash_free);
    OPENSSL_free(ent);
}

static void free_dir(X509_LOOKUP *lu)
{
    BY_DIR *a;

    a = (BY_DIR *)lu->method_data;
    if (a->dirs != NULL)
        sk_BY_DIR_ENTRY_pop_free(a->dirs, by_dir_entry_free);
    if (a->buffer != NULL)
        BUF_MEM_free(a->buffer);
    OPENSSL_free(a);
}

static int add_cert_dir(BY_DIR *ctx, const char *dir, int type)
{
    int j, len;
    const char *s, *ss, *p;

    if (dir == NULL || !*dir) {
        X509err(X509_F_ADD_CERT_DIR, X509_R_INVALID_DIRECTORY);
        return 0;
    }

    s = dir;
    p = s;
    do {
        if ((*p == LIST_SEPARATOR_CHAR) || (*p == '\0')) {
            BY_DIR_ENTRY *ent;
            ss = s;
            s = p + 1;
            len = (int)(p - ss);
            if (len == 0)
                continue;
            for (j = 0; j < sk_BY_DIR_ENTRY_num(ctx->dirs); j++) {
                ent = sk_BY_DIR_ENTRY_value(ctx->dirs, j);
                if (strlen(ent->dir) == (size_t)len &&
                    strncmp(ent->dir, ss, (unsigned int)len) == 0)
                    break;
            }
            if (j < sk_BY_DIR_ENTRY_num(ctx->dirs))
                continue;
            if (ctx->dirs == NULL) {
                ctx->dirs = sk_BY_DIR_ENTRY_new_null();
                if (!ctx->dirs) {
                    X509err(X509_F_ADD_CERT_DIR, ERR_R_MALLOC_FAILURE);
                    return 0;
                }
            }
            ent = OPENSSL_malloc(sizeof(BY_DIR_ENTRY));
            if (!ent)
                return 0;
            ent->dir_type = type;
            ent->hashes = sk_BY_DIR_HASH_new(by_dir_hash_cmp);
            ent->dir = OPENSSL_malloc((unsigned int)len + 1);
            if (!ent->dir || !ent->hashes) {
                by_dir_entry_free(ent);
                return 0;
            }
            strncpy(ent->dir, ss, (unsigned int)len);
            ent->dir[len] = '\0';
            if (!sk_BY_DIR_ENTRY_push(ctx->dirs, ent)) {
                by_dir_entry_free(ent);
                return 0;
            }
        }
    } while (*p++ != '\0');
    return 1;
}

static int get_cert_by_subject(X509_LOOKUP *xl, int type, X509_NAME *name,
                               X509_OBJECT *ret)
{
    BY_DIR *ctx;
    union {
        struct {
            X509 st_x509;
            X509_CINF st_x509_cinf;
        } x509;
        struct {
            X509_CRL st_crl;
            X509_CRL_INFO st_crl_info;
        } crl;
    } data;
    int ok = 0;
    int i, j, k;
    unsigned long h;
    BUF_MEM *b = NULL;
    X509_OBJECT stmp, *tmp;
    const char *postfix = "";

    if (name == NULL)
        return (0);

    stmp.type = type;
    if (type == X509_LU_X509) {
        data.x509.st_x509.cert_info = &data.x509.st_x509_cinf;
        data.x509.st_x509_cinf.subject = name;
        stmp.data.x509 = &data.x509.st_x509;
        postfix = "";
    } else if (type == X509_LU_CRL) {
        data.crl.st_crl.crl = &data.crl.st_crl_info;
        data.crl.st_crl_info.issuer = name;
        stmp.data.crl = &data.crl.st_crl;
        postfix = "r";
    } else {
        X509err(X509_F_GET_CERT_BY_SUBJECT, X509_R_WRONG_LOOKUP_TYPE);
        goto finish;
    }

    if ((b = BUF_MEM_new()) == NULL) {
        X509err(X509_F_GET_CERT_BY_SUBJECT, ERR_R_BUF_LIB);
        goto finish;
    }

    ctx = (BY_DIR *)xl->method_data;

    h = X509_NAME_hash(name);
    for (i = 0; i < sk_BY_DIR_ENTRY_num(ctx->dirs); i++) {
        BY_DIR_ENTRY *ent;
        int idx;
        BY_DIR_HASH htmp, *hent;
        ent = sk_BY_DIR_ENTRY_value(ctx->dirs, i);
        j = strlen(ent->dir) + 1 + 8 + 6 + 1 + 1;
        if (!BUF_MEM_grow(b, j)) {
            X509err(X509_F_GET_CERT_BY_SUBJECT, ERR_R_MALLOC_FAILURE);
            goto finish;
        }
        if (type == X509_LU_CRL && ent->hashes) {
            htmp.hash = h;
            CRYPTO_r_lock(CRYPTO_LOCK_X509_STORE);
            idx = sk_BY_DIR_HASH_find(ent->hashes, &htmp);
            if (idx >= 0) {
                hent = sk_BY_DIR_HASH_value(ent->hashes, idx);
                k = hent->suffix;
            } else {
                hent = NULL;
                k = 0;
            }
            CRYPTO_r_unlock(CRYPTO_LOCK_X509_STORE);
        } else {
            k = 0;
            hent = NULL;
        }
        for (;;) {
            char c = '/';
#ifdef OPENSSL_SYS_VMS
            c = ent->dir[strlen(ent->dir) - 1];
            if (c != ':' && c != '>' && c != ']') {
                /*
                 * If no separator is present, we assume the directory
                 * specifier is a logical name, and add a colon.  We really
                 * should use better VMS routines for merging things like
                 * this, but this will do for now... -- Richard Levitte
                 */
                c = ':';
            } else {
                c = '\0';
            }
#endif
            if (c == '\0') {
                /*
                 * This is special.  When c == '\0', no directory separator
                 * should be added.
                 */
                BIO_snprintf(b->data, b->max,
                             "%s%08lx.%s%d", ent->dir, h, postfix, k);
            } else {
                BIO_snprintf(b->data, b->max,
                             "%s%c%08lx.%s%d", ent->dir, c, h, postfix, k);
            }
#ifndef OPENSSL_NO_POSIX_IO
# ifdef _WIN32
#  define stat _stat
# endif
            {
                struct stat st;
                if (stat(b->data, &st) < 0)
                    break;
            }
#endif
            /* found one. */
            if (type == X509_LU_X509) {
                if ((X509_load_cert_file(xl, b->data, ent->dir_type)) == 0)
                    break;
            } else if (type == X509_LU_CRL) {
                if ((X509_load_crl_file(xl, b->data, ent->dir_type)) == 0)
                    break;
            }
            /* else case will caught higher up */
            k++;
        }

        /*
         * we have added it to the cache so now pull it out again
         */
        CRYPTO_w_lock(CRYPTO_LOCK_X509_STORE);
        j = sk_X509_OBJECT_find(xl->store_ctx->objs, &stmp);
        if (j != -1)
            tmp = sk_X509_OBJECT_value(xl->store_ctx->objs, j);
        else
            tmp = NULL;
        CRYPTO_w_unlock(CRYPTO_LOCK_X509_STORE);

        /* If a CRL, update the last file suffix added for this */

        if (type == X509_LU_CRL) {
            CRYPTO_w_lock(CRYPTO_LOCK_X509_STORE);
            /*
             * Look for entry again in case another thread added an entry
             * first.
             */
            if (!hent) {
                htmp.hash = h;
                idx = sk_BY_DIR_HASH_find(ent->hashes, &htmp);
                if (idx >= 0)
                    hent = sk_BY_DIR_HASH_value(ent->hashes, idx);
            }
            if (!hent) {
                hent = OPENSSL_malloc(sizeof(BY_DIR_HASH));
                if (hent == NULL) {
                    CRYPTO_w_unlock(CRYPTO_LOCK_X509_STORE);
                    X509err(X509_F_GET_CERT_BY_SUBJECT, ERR_R_MALLOC_FAILURE);
                    goto finish;
                }
                hent->hash = h;
                hent->suffix = k;
                if (!sk_BY_DIR_HASH_push(ent->hashes, hent)) {
                    CRYPTO_w_unlock(CRYPTO_LOCK_X509_STORE);
                    OPENSSL_free(hent);
                    ok = 0;
                    goto finish;
                }
            } else if (hent->suffix < k)
                hent->suffix = k;

            CRYPTO_w_unlock(CRYPTO_LOCK_X509_STORE);

        }

        if (tmp != NULL) {
            ok = 1;
            ret->type = tmp->type;
            memcpy(&ret->data, &tmp->data, sizeof(ret->data));
            /*
             * If we were going to up the reference count, we would need to
             * do it on a perl 'type' basis
             */
        /*- CRYPTO_add(&tmp->data.x509->references,1,
                    CRYPTO_LOCK_X509);*/
            goto finish;
        }
    }
 finish:
    if (b != NULL)
        BUF_MEM_free(b);
    return (ok);
}
/* crypto/x509/by_file.c */
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
#include <errno.h>

// #include "cryptlib.h"
// #include "lhash.h"
#include "buffer.h"
// #include "x509.h"
#include "pem.h"

#ifndef OPENSSL_NO_STDIO

static int by_file_ctrl(X509_LOOKUP *ctx, int cmd, const char *argc,
                        long argl, char **ret);
X509_LOOKUP_METHOD x509_file_lookup = {
    "Load file into cache",
    NULL,                       /* new */
    NULL,                       /* free */
    NULL,                       /* init */
    NULL,                       /* shutdown */
    by_file_ctrl,               /* ctrl */
    NULL,                       /* get_by_subject */
    NULL,                       /* get_by_issuer_serial */
    NULL,                       /* get_by_fingerprint */
    NULL,                       /* get_by_alias */
};

X509_LOOKUP_METHOD *X509_LOOKUP_file(void)
{
    return (&x509_file_lookup);
}

static int by_file_ctrl(X509_LOOKUP *ctx, int cmd, const char *argp,
                        long argl, char **ret)
{
    int ok = 0;
    const char *file;

    switch (cmd) {
    case X509_L_FILE_LOAD:
        if (argl == X509_FILETYPE_DEFAULT) {
            file = ossl_safe_getenv(X509_get_default_cert_file_env());

            if (file)
                ok = (X509_load_cert_crl_file(ctx, file,
                                              X509_FILETYPE_PEM) != 0);

            else
                ok = (X509_load_cert_crl_file
                      (ctx, X509_get_default_cert_file(),
                       X509_FILETYPE_PEM) != 0);

            if (!ok) {
                X509err(X509_F_BY_FILE_CTRL, X509_R_LOADING_DEFAULTS);
            }
        } else {
            if (argl == X509_FILETYPE_PEM)
                ok = (X509_load_cert_crl_file(ctx, argp,
                                              X509_FILETYPE_PEM) != 0);
            else
                ok = (X509_load_cert_file(ctx, argp, (int)argl) != 0);
        }
        break;
    }
    return (ok);
}

int X509_load_cert_file(X509_LOOKUP *ctx, const char *file, int type)
{
    int ret = 0;
    BIO *in = NULL;
    int i, count = 0;
    X509 *x = NULL;

    if (file == NULL)
        return (1);
    in = BIO_new(BIO_s_file_internal());

    if ((in == NULL) || (BIO_read_filename(in, file) <= 0)) {
        X509err(X509_F_X509_LOAD_CERT_FILE, ERR_R_SYS_LIB);
        goto err;
    }

    if (type == X509_FILETYPE_PEM) {
        for (;;) {
            x = PEM_read_bio_X509_AUX(in, NULL, NULL, "");
            if (x == NULL) {
                if ((ERR_GET_REASON(ERR_peek_last_error()) ==
                     PEM_R_NO_START_LINE) && (count > 0)) {
                    ERR_clear_error();
                    break;
                } else {
                    X509err(X509_F_X509_LOAD_CERT_FILE, ERR_R_PEM_LIB);
                    goto err;
                }
            }
            i = X509_STORE_add_cert(ctx->store_ctx, x);
            if (!i)
                goto err;
            count++;
            X509_free(x);
            x = NULL;
        }
        ret = count;
    } else if (type == X509_FILETYPE_ASN1) {
        x = d2i_X509_bio(in, NULL);
        if (x == NULL) {
            X509err(X509_F_X509_LOAD_CERT_FILE, ERR_R_ASN1_LIB);
            goto err;
        }
        i = X509_STORE_add_cert(ctx->store_ctx, x);
        if (!i)
            goto err;
        ret = i;
    } else {
        X509err(X509_F_X509_LOAD_CERT_FILE, X509_R_BAD_X509_FILETYPE);
        goto err;
    }
 err:
    if (x != NULL)
        X509_free(x);
    if (in != NULL)
        BIO_free(in);
    return (ret);
}

int X509_load_crl_file(X509_LOOKUP *ctx, const char *file, int type)
{
    int ret = 0;
    BIO *in = NULL;
    int i, count = 0;
    X509_CRL *x = NULL;

    if (file == NULL)
        return (1);
    in = BIO_new(BIO_s_file_internal());

    if ((in == NULL) || (BIO_read_filename(in, file) <= 0)) {
        X509err(X509_F_X509_LOAD_CRL_FILE, ERR_R_SYS_LIB);
        goto err;
    }

    if (type == X509_FILETYPE_PEM) {
        for (;;) {
            x = PEM_read_bio_X509_CRL(in, NULL, NULL, "");
            if (x == NULL) {
                if ((ERR_GET_REASON(ERR_peek_last_error()) ==
                     PEM_R_NO_START_LINE) && (count > 0)) {
                    ERR_clear_error();
                    break;
                } else {
                    X509err(X509_F_X509_LOAD_CRL_FILE, ERR_R_PEM_LIB);
                    goto err;
                }
            }
            i = X509_STORE_add_crl(ctx->store_ctx, x);
            if (!i)
                goto err;
            count++;
            X509_CRL_free(x);
            x = NULL;
        }
        ret = count;
    } else if (type == X509_FILETYPE_ASN1) {
        x = d2i_X509_CRL_bio(in, NULL);
        if (x == NULL) {
            X509err(X509_F_X509_LOAD_CRL_FILE, ERR_R_ASN1_LIB);
            goto err;
        }
        i = X509_STORE_add_crl(ctx->store_ctx, x);
        if (!i)
            goto err;
        ret = i;
    } else {
        X509err(X509_F_X509_LOAD_CRL_FILE, X509_R_BAD_X509_FILETYPE);
        goto err;
    }
 err:
    if (x != NULL)
        X509_CRL_free(x);
    if (in != NULL)
        BIO_free(in);
    return (ret);
}

int X509_load_cert_crl_file(X509_LOOKUP *ctx, const char *file, int type)
{
    STACK_OF(X509_INFO) *inf;
    X509_INFO *itmp;
    BIO *in;
    int i, count = 0;
    if (type != X509_FILETYPE_PEM)
        return X509_load_cert_file(ctx, file, type);
    in = BIO_new_file(file, "r");
    if (!in) {
        X509err(X509_F_X509_LOAD_CERT_CRL_FILE, ERR_R_SYS_LIB);
        return 0;
    }
    inf = PEM_X509_INFO_read_bio(in, NULL, NULL, "");
    BIO_free(in);
    if (!inf) {
        X509err(X509_F_X509_LOAD_CERT_CRL_FILE, ERR_R_PEM_LIB);
        return 0;
    }
    for (i = 0; i < sk_X509_INFO_num(inf); i++) {
        itmp = sk_X509_INFO_value(inf, i);
        if (itmp->x509) {
            X509_STORE_add_cert(ctx->store_ctx, itmp->x509);
            count++;
        }
        if (itmp->crl) {
            X509_STORE_add_crl(ctx->store_ctx, itmp->crl);
            count++;
        }
    }
    sk_X509_INFO_pop_free(inf, X509_INFO_free);
    return count;
}

#endif                          /* OPENSSL_NO_STDIO */
