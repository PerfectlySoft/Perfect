/* conf_api.c */
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

/* Part of the code in here was originally in conf.c, which is now removed */

#ifndef CONF_DEBUG
# undef NDEBUG                  /* avoid conflicting definitions */
# define NDEBUG
#endif

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "cryptlib.h"
#include "conf.h"
#include "conf_api.h"
#include "e_os.h"

static void value_free_hash_doall_arg(CONF_VALUE *a,
                                      LHASH_OF(CONF_VALUE) *conf);
static void value_free_stack_doall(CONF_VALUE *a);
static IMPLEMENT_LHASH_DOALL_ARG_FN(value_free_hash, CONF_VALUE,
                                    LHASH_OF(CONF_VALUE))
static IMPLEMENT_LHASH_DOALL_FN(value_free_stack, CONF_VALUE)

/* Up until OpenSSL 0.9.5a, this was get_section */
CONF_VALUE *_CONF_get_section(const CONF *conf, const char *section)
{
    CONF_VALUE *v, vv;

    if ((conf == NULL) || (section == NULL))
        return (NULL);
    vv.name = NULL;
    vv.section = (char *)section;
    v = lh_CONF_VALUE_retrieve(conf->data, &vv);
    return (v);
}

/* Up until OpenSSL 0.9.5a, this was CONF_get_section */
STACK_OF(CONF_VALUE) *_CONF_get_section_values(const CONF *conf,
                                               const char *section)
{
    CONF_VALUE *v;

    v = _CONF_get_section(conf, section);
    if (v != NULL)
        return ((STACK_OF(CONF_VALUE) *)v->value);
    else
        return (NULL);
}

int _CONF_add_string(CONF *conf, CONF_VALUE *section, CONF_VALUE *value)
{
    CONF_VALUE *v = NULL;
    STACK_OF(CONF_VALUE) *ts;

    ts = (STACK_OF(CONF_VALUE) *)section->value;

    value->section = section->section;
    if (!sk_CONF_VALUE_push(ts, value)) {
        return 0;
    }

    v = lh_CONF_VALUE_insert(conf->data, value);
    if (v != NULL) {
        (void)sk_CONF_VALUE_delete_ptr(ts, v);
        OPENSSL_free(v->name);
        OPENSSL_free(v->value);
        OPENSSL_free(v);
    }
    return 1;
}

char *_CONF_get_string(const CONF *conf, const char *section,
                       const char *name)
{
    CONF_VALUE *v, vv;
    char *p;

    if (name == NULL)
        return (NULL);
    if (conf != NULL) {
        if (section != NULL) {
            vv.name = (char *)name;
            vv.section = (char *)section;
            v = lh_CONF_VALUE_retrieve(conf->data, &vv);
            if (v != NULL)
                return (v->value);
            if (strcmp(section, "ENV") == 0) {
                p = ossl_safe_getenv(name);
                if (p != NULL)
                    return (p);
            }
        }
        vv.section = "default";
        vv.name = (char *)name;
        v = lh_CONF_VALUE_retrieve(conf->data, &vv);
        if (v != NULL)
            return (v->value);
        else
            return (NULL);
    } else
        return (ossl_safe_getenv(name));
}

#if 0                           /* There's no way to provide error checking
                                 * with this function, so force implementors
                                 * of the higher levels to get a string and
                                 * read the number themselves. */
long _CONF_get_number(CONF *conf, char *section, char *name)
{
    char *str;
    long ret = 0;

    str = _CONF_get_string(conf, section, name);
    if (str == NULL)
        return (0);
    for (;;) {
        if (conf->meth->is_number(conf, *str))
            ret = ret * 10 + conf->meth->to_int(conf, *str);
        else
            return (ret);
        str++;
    }
}
#endif

static unsigned long conf_value_hash(const CONF_VALUE *v)
{
    return (lh_strhash(v->section) << 2) ^ lh_strhash(v->name);
}

static IMPLEMENT_LHASH_HASH_FN(conf_value, CONF_VALUE)

static int conf_value_cmp(const CONF_VALUE *a, const CONF_VALUE *b)
{
    int i;

    if (a->section != b->section) {
        i = strcmp(a->section, b->section);
        if (i)
            return (i);
    }

    if ((a->name != NULL) && (b->name != NULL)) {
        i = strcmp(a->name, b->name);
        return (i);
    } else if (a->name == b->name)
        return (0);
    else
        return ((a->name == NULL) ? -1 : 1);
}

static IMPLEMENT_LHASH_COMP_FN(conf_value, CONF_VALUE)

int _CONF_new_data(CONF *conf)
{
    if (conf == NULL) {
        return 0;
    }
    if (conf->data == NULL)
        if ((conf->data = lh_CONF_VALUE_new()) == NULL) {
            return 0;
        }
    return 1;
}

void _CONF_free_data(CONF *conf)
{
    if (conf == NULL || conf->data == NULL)
        return;

    lh_CONF_VALUE_down_load(conf->data) = 0; /* evil thing to make * sure the
                                              * 'OPENSSL_free()' works as *
                                              * expected */
    lh_CONF_VALUE_doall_arg(conf->data,
                            LHASH_DOALL_ARG_FN(value_free_hash),
                            LHASH_OF(CONF_VALUE), conf->data);

    /*
     * We now have only 'section' entries in the hash table. Due to problems
     * with
     */

    lh_CONF_VALUE_doall(conf->data, LHASH_DOALL_FN(value_free_stack));
    lh_CONF_VALUE_free(conf->data);
}

static void value_free_hash_doall_arg(CONF_VALUE *a,
                                      LHASH_OF(CONF_VALUE) *conf)
{
    if (a->name != NULL)
        (void)lh_CONF_VALUE_delete(conf, a);
}

static void value_free_stack_doall(CONF_VALUE *a)
{
    CONF_VALUE *vv;
    STACK_OF(CONF_VALUE) *sk;
    int i;

    if (a->name != NULL)
        return;

    sk = (STACK_OF(CONF_VALUE) *)a->value;
    for (i = sk_CONF_VALUE_num(sk) - 1; i >= 0; i--) {
        vv = sk_CONF_VALUE_value(sk, i);
        OPENSSL_free(vv->value);
        OPENSSL_free(vv->name);
        OPENSSL_free(vv);
    }
    if (sk != NULL)
        sk_CONF_VALUE_free(sk);
    OPENSSL_free(a->section);
    OPENSSL_free(a);
}

/* Up until OpenSSL 0.9.5a, this was new_section */
CONF_VALUE *_CONF_new_section(CONF *conf, const char *section)
{
    STACK_OF(CONF_VALUE) *sk = NULL;
    int ok = 0, i;
    CONF_VALUE *v = NULL, *vv;

    if ((sk = sk_CONF_VALUE_new_null()) == NULL)
        goto err;
    if ((v = OPENSSL_malloc(sizeof(CONF_VALUE))) == NULL)
        goto err;
    i = strlen(section) + 1;
    if ((v->section = OPENSSL_malloc(i)) == NULL)
        goto err;

    memcpy(v->section, section, i);
    v->name = NULL;
    v->value = (char *)sk;

    vv = lh_CONF_VALUE_insert(conf->data, v);
    OPENSSL_assert(vv == NULL);
    if (lh_CONF_VALUE_error(conf->data) > 0)
        goto err;
    ok = 1;
 err:
    if (!ok) {
        if (sk != NULL)
            sk_CONF_VALUE_free(sk);
        if (v != NULL)
            OPENSSL_free(v);
        v = NULL;
    }
    return (v);
}

IMPLEMENT_STACK_OF(CONF_VALUE)
/* crypto/conf/conf.c */
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

/* Part of the code in here was originally in conf.c, which is now removed */

#include <stdio.h>
#include <string.h>
// #include "cryptlib.h"
#include "stack.h"
#include "lhash.h"
// #include "conf.h"
// #include "conf_api.h"
#include "conf_def.h"
#include "buffer.h"
#include "err.h"

/*
 * The maximum length we can grow a value to after variable expansion. 64k
 * should be more than enough for all reasonable uses.
 */
#define MAX_CONF_VALUE_LENGTH       65536

static char *eat_ws(CONF *conf, char *p);
static char *eat_alpha_numeric(CONF *conf, char *p);
static void clear_comments(CONF *conf, char *p);
static int str_copy(CONF *conf, char *section, char **to, char *from);
static char *scan_quote(CONF *conf, char *p);
static char *scan_dquote(CONF *conf, char *p);
#define scan_esc(conf,p)        (((IS_EOF((conf),(p)[1]))?((p)+1):((p)+2)))

static CONF *def_create(CONF_METHOD *meth);
static int def_init_default(CONF *conf);
static int def_init_WIN32(CONF *conf);
static int def_destroy(CONF *conf);
static int def_destroy_data(CONF *conf);
static int def_load(CONF *conf, const char *name, long *eline);
static int def_load_bio(CONF *conf, BIO *bp, long *eline);
static int def_dump(const CONF *conf, BIO *bp);
static int def_is_number(const CONF *conf, char c);
static int def_to_int(const CONF *conf, char c);

const char CONF_def_version[] = "CONF_def" OPENSSL_VERSION_PTEXT;

static CONF_METHOD default_method = {
    "OpenSSL default",
    def_create,
    def_init_default,
    def_destroy,
    def_destroy_data,
    def_load_bio,
    def_dump,
    def_is_number,
    def_to_int,
    def_load
};

static CONF_METHOD WIN32_method = {
    "WIN32",
    def_create,
    def_init_WIN32,
    def_destroy,
    def_destroy_data,
    def_load_bio,
    def_dump,
    def_is_number,
    def_to_int,
    def_load
};

CONF_METHOD *NCONF_default()
{
    return &default_method;
}

CONF_METHOD *NCONF_WIN32()
{
    return &WIN32_method;
}

static CONF *def_create(CONF_METHOD *meth)
{
    CONF *ret;

    ret = OPENSSL_malloc(sizeof(CONF) + sizeof(unsigned short *));
    if (ret)
        if (meth->init(ret) == 0) {
            OPENSSL_free(ret);
            ret = NULL;
        }
    return ret;
}

static int def_init_default(CONF *conf)
{
    if (conf == NULL)
        return 0;

    conf->meth = &default_method;
    conf->meth_data = CONF_type_default;
    conf->data = NULL;

    return 1;
}

static int def_init_WIN32(CONF *conf)
{
    if (conf == NULL)
        return 0;

    conf->meth = &WIN32_method;
    conf->meth_data = (void *)CONF_type_win32;
    conf->data = NULL;

    return 1;
}

static int def_destroy(CONF *conf)
{
    if (def_destroy_data(conf)) {
        OPENSSL_free(conf);
        return 1;
    }
    return 0;
}

static int def_destroy_data(CONF *conf)
{
    if (conf == NULL)
        return 0;
    _CONF_free_data(conf);
    return 1;
}

static int def_load(CONF *conf, const char *name, long *line)
{
    int ret;
    BIO *in = NULL;

#ifdef OPENSSL_SYS_VMS
    in = BIO_new_file(name, "r");
#else
    in = BIO_new_file(name, "rb");
#endif
    if (in == NULL) {
        if (ERR_GET_REASON(ERR_peek_last_error()) == BIO_R_NO_SUCH_FILE)
            CONFerr(CONF_F_DEF_LOAD, CONF_R_NO_SUCH_FILE);
        else
            CONFerr(CONF_F_DEF_LOAD, ERR_R_SYS_LIB);
        return 0;
    }

    ret = def_load_bio(conf, in, line);
    BIO_free(in);

    return ret;
}

static int def_load_bio(CONF *conf, BIO *in, long *line)
{
/* The macro BUFSIZE conflicts with a system macro in VxWorks */
#define CONFBUFSIZE     512
    int bufnum = 0, i, ii;
    BUF_MEM *buff = NULL;
    char *s, *p, *end;
    int again;
    long eline = 0;
    char btmp[DECIMAL_SIZE(eline) + 1];
    CONF_VALUE *v = NULL, *tv;
    CONF_VALUE *sv = NULL;
    char *section = NULL, *buf;
    char *start, *psection, *pname;
    void *h = (void *)(conf->data);

    if ((buff = BUF_MEM_new()) == NULL) {
        CONFerr(CONF_F_DEF_LOAD_BIO, ERR_R_BUF_LIB);
        goto err;
    }

    section = BUF_strdup("default");
    if (section == NULL) {
        CONFerr(CONF_F_DEF_LOAD_BIO, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (_CONF_new_data(conf) == 0) {
        CONFerr(CONF_F_DEF_LOAD_BIO, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    sv = _CONF_new_section(conf, section);
    if (sv == NULL) {
        CONFerr(CONF_F_DEF_LOAD_BIO, CONF_R_UNABLE_TO_CREATE_NEW_SECTION);
        goto err;
    }

    bufnum = 0;
    again = 0;
    for (;;) {
        if (!BUF_MEM_grow(buff, bufnum + CONFBUFSIZE)) {
            CONFerr(CONF_F_DEF_LOAD_BIO, ERR_R_BUF_LIB);
            goto err;
        }
        p = &(buff->data[bufnum]);
        *p = '\0';
        BIO_gets(in, p, CONFBUFSIZE - 1);
        p[CONFBUFSIZE - 1] = '\0';
        ii = i = strlen(p);
        if (i == 0 && !again)
            break;
        again = 0;
        while (i > 0) {
            if ((p[i - 1] != '\r') && (p[i - 1] != '\n'))
                break;
            else
                i--;
        }
        /*
         * we removed some trailing stuff so there is a new line on the end.
         */
        if (ii && i == ii)
            again = 1;          /* long line */
        else {
            p[i] = '\0';
            eline++;            /* another input line */
        }

        /* we now have a line with trailing \r\n removed */

        /* i is the number of bytes */
        bufnum += i;

        v = NULL;
        /* check for line continuation */
        if (bufnum >= 1) {
            /*
             * If we have bytes and the last char '\\' and second last char
             * is not '\\'
             */
            p = &(buff->data[bufnum - 1]);
            if (IS_ESC(conf, p[0]) && ((bufnum <= 1) || !IS_ESC(conf, p[-1]))) {
                bufnum--;
                again = 1;
            }
        }
        if (again)
            continue;
        bufnum = 0;
        buf = buff->data;

        clear_comments(conf, buf);
        s = eat_ws(conf, buf);
        if (IS_EOF(conf, *s))
            continue;           /* blank line */
        if (*s == '[') {
            char *ss;

            s++;
            start = eat_ws(conf, s);
            ss = start;
 again:
            end = eat_alpha_numeric(conf, ss);
            p = eat_ws(conf, end);
            if (*p != ']') {
                if (*p != '\0' && ss != p) {
                    ss = p;
                    goto again;
                }
                CONFerr(CONF_F_DEF_LOAD_BIO,
                        CONF_R_MISSING_CLOSE_SQUARE_BRACKET);
                goto err;
            }
            *end = '\0';
            if (!str_copy(conf, NULL, &section, start))
                goto err;
            if ((sv = _CONF_get_section(conf, section)) == NULL)
                sv = _CONF_new_section(conf, section);
            if (sv == NULL) {
                CONFerr(CONF_F_DEF_LOAD_BIO,
                        CONF_R_UNABLE_TO_CREATE_NEW_SECTION);
                goto err;
            }
            continue;
        } else {
            pname = s;
            psection = NULL;
            end = eat_alpha_numeric(conf, s);
            if ((end[0] == ':') && (end[1] == ':')) {
                *end = '\0';
                end += 2;
                psection = pname;
                pname = end;
                end = eat_alpha_numeric(conf, end);
            }
            p = eat_ws(conf, end);
            if (*p != '=') {
                CONFerr(CONF_F_DEF_LOAD_BIO, CONF_R_MISSING_EQUAL_SIGN);
                goto err;
            }
            *end = '\0';
            p++;
            start = eat_ws(conf, p);
            while (!IS_EOF(conf, *p))
                p++;
            p--;
            while ((p != start) && (IS_WS(conf, *p)))
                p--;
            p++;
            *p = '\0';

            if (!(v = (CONF_VALUE *)OPENSSL_malloc(sizeof(CONF_VALUE)))) {
                CONFerr(CONF_F_DEF_LOAD_BIO, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            if (psection == NULL)
                psection = section;
            v->name = (char *)OPENSSL_malloc(strlen(pname) + 1);
            v->value = NULL;
            if (v->name == NULL) {
                CONFerr(CONF_F_DEF_LOAD_BIO, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            BUF_strlcpy(v->name, pname, strlen(pname) + 1);
            if (!str_copy(conf, psection, &(v->value), start))
                goto err;

            if (strcmp(psection, section) != 0) {
                if ((tv = _CONF_get_section(conf, psection))
                    == NULL)
                    tv = _CONF_new_section(conf, psection);
                if (tv == NULL) {
                    CONFerr(CONF_F_DEF_LOAD_BIO,
                            CONF_R_UNABLE_TO_CREATE_NEW_SECTION);
                    goto err;
                }
            } else
                tv = sv;
#if 1
            if (_CONF_add_string(conf, tv, v) == 0) {
                CONFerr(CONF_F_DEF_LOAD_BIO, ERR_R_MALLOC_FAILURE);
                goto err;
            }
#else
            v->section = tv->section;
            if (!sk_CONF_VALUE_push(ts, v)) {
                CONFerr(CONF_F_DEF_LOAD_BIO, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            vv = (CONF_VALUE *)lh_insert(conf->data, v);
            if (vv != NULL) {
                sk_CONF_VALUE_delete_ptr(ts, vv);
                OPENSSL_free(vv->name);
                OPENSSL_free(vv->value);
                OPENSSL_free(vv);
            }
#endif
            v = NULL;
        }
    }
    if (buff != NULL)
        BUF_MEM_free(buff);
    if (section != NULL)
        OPENSSL_free(section);
    return (1);
 err:
    if (buff != NULL)
        BUF_MEM_free(buff);
    if (section != NULL)
        OPENSSL_free(section);
    if (line != NULL)
        *line = eline;
    BIO_snprintf(btmp, sizeof(btmp), "%ld", eline);
    ERR_add_error_data(2, "line ", btmp);
    if ((h != conf->data) && (conf->data != NULL)) {
        CONF_free(conf->data);
        conf->data = NULL;
    }
    if (v != NULL) {
        if (v->name != NULL)
            OPENSSL_free(v->name);
        if (v->value != NULL)
            OPENSSL_free(v->value);
        if (v != NULL)
            OPENSSL_free(v);
    }
    return (0);
}

static void clear_comments(CONF *conf, char *p)
{
    for (;;) {
        if (IS_FCOMMENT(conf, *p)) {
            *p = '\0';
            return;
        }
        if (!IS_WS(conf, *p)) {
            break;
        }
        p++;
    }

    for (;;) {
        if (IS_COMMENT(conf, *p)) {
            *p = '\0';
            return;
        }
        if (IS_DQUOTE(conf, *p)) {
            p = scan_dquote(conf, p);
            continue;
        }
        if (IS_QUOTE(conf, *p)) {
            p = scan_quote(conf, p);
            continue;
        }
        if (IS_ESC(conf, *p)) {
            p = scan_esc(conf, p);
            continue;
        }
        if (IS_EOF(conf, *p))
            return;
        else
            p++;
    }
}

static int str_copy(CONF *conf, char *section, char **pto, char *from)
{
    int q, r, rr = 0, to = 0, len = 0;
    char *s, *e, *rp, *p, *rrp, *np, *cp, v;
    BUF_MEM *buf;

    if ((buf = BUF_MEM_new()) == NULL)
        return (0);

    len = strlen(from) + 1;
    if (!BUF_MEM_grow(buf, len))
        goto err;

    for (;;) {
        if (IS_QUOTE(conf, *from)) {
            q = *from;
            from++;
            while (!IS_EOF(conf, *from) && (*from != q)) {
                if (IS_ESC(conf, *from)) {
                    from++;
                    if (IS_EOF(conf, *from))
                        break;
                }
                buf->data[to++] = *(from++);
            }
            if (*from == q)
                from++;
        } else if (IS_DQUOTE(conf, *from)) {
            q = *from;
            from++;
            while (!IS_EOF(conf, *from)) {
                if (*from == q) {
                    if (*(from + 1) == q) {
                        from++;
                    } else {
                        break;
                    }
                }
                buf->data[to++] = *(from++);
            }
            if (*from == q)
                from++;
        } else if (IS_ESC(conf, *from)) {
            from++;
            v = *(from++);
            if (IS_EOF(conf, v))
                break;
            else if (v == 'r')
                v = '\r';
            else if (v == 'n')
                v = '\n';
            else if (v == 'b')
                v = '\b';
            else if (v == 't')
                v = '\t';
            buf->data[to++] = v;
        } else if (IS_EOF(conf, *from))
            break;
        else if (*from == '$') {
            size_t newsize;

            /* try to expand it */
            rrp = NULL;
            s = &(from[1]);
            if (*s == '{')
                q = '}';
            else if (*s == '(')
                q = ')';
            else
                q = 0;

            if (q)
                s++;
            cp = section;
            e = np = s;
            while (IS_ALPHA_NUMERIC(conf, *e))
                e++;
            if ((e[0] == ':') && (e[1] == ':')) {
                cp = np;
                rrp = e;
                rr = *e;
                *rrp = '\0';
                e += 2;
                np = e;
                while (IS_ALPHA_NUMERIC(conf, *e))
                    e++;
            }
            r = *e;
            *e = '\0';
            rp = e;
            if (q) {
                if (r != q) {
                    CONFerr(CONF_F_STR_COPY, CONF_R_NO_CLOSE_BRACE);
                    goto err;
                }
                e++;
            }
            /*-
             * So at this point we have
             * np which is the start of the name string which is
             *   '\0' terminated.
             * cp which is the start of the section string which is
             *   '\0' terminated.
             * e is the 'next point after'.
             * r and rr are the chars replaced by the '\0'
             * rp and rrp is where 'r' and 'rr' came from.
             */
            p = _CONF_get_string(conf, cp, np);
            if (rrp != NULL)
                *rrp = rr;
            *rp = r;
            if (p == NULL) {
                CONFerr(CONF_F_STR_COPY, CONF_R_VARIABLE_HAS_NO_VALUE);
                goto err;
            }
            newsize = strlen(p) + buf->length - (e - from);
            if (newsize > MAX_CONF_VALUE_LENGTH) {
                CONFerr(CONF_F_STR_COPY, CONF_R_VARIABLE_EXPANSION_TOO_LONG);
                goto err;
            }
            if (!BUF_MEM_grow_clean(buf, newsize)) {
                CONFerr(CONF_F_STR_COPY, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            while (*p)
                buf->data[to++] = *(p++);

            /*
             * Since we change the pointer 'from', we also have to change the
             * perceived length of the string it points at.  /RL
             */
            len -= e - from;
            from = e;

            /*
             * In case there were no braces or parenthesis around the
             * variable reference, we have to put back the character that was
             * replaced with a '\0'.  /RL
             */
            *rp = r;
        } else
            buf->data[to++] = *(from++);
    }
    buf->data[to] = '\0';
    if (*pto != NULL)
        OPENSSL_free(*pto);
    *pto = buf->data;
    OPENSSL_free(buf);
    return (1);
 err:
    if (buf != NULL)
        BUF_MEM_free(buf);
    return (0);
}

static char *eat_ws(CONF *conf, char *p)
{
    while (IS_WS(conf, *p) && (!IS_EOF(conf, *p)))
        p++;
    return (p);
}

static char *eat_alpha_numeric(CONF *conf, char *p)
{
    for (;;) {
        if (IS_ESC(conf, *p)) {
            p = scan_esc(conf, p);
            continue;
        }
        if (!IS_ALPHA_NUMERIC_PUNCT(conf, *p))
            return (p);
        p++;
    }
}

static char *scan_quote(CONF *conf, char *p)
{
    int q = *p;

    p++;
    while (!(IS_EOF(conf, *p)) && (*p != q)) {
        if (IS_ESC(conf, *p)) {
            p++;
            if (IS_EOF(conf, *p))
                return (p);
        }
        p++;
    }
    if (*p == q)
        p++;
    return (p);
}

static char *scan_dquote(CONF *conf, char *p)
{
    int q = *p;

    p++;
    while (!(IS_EOF(conf, *p))) {
        if (*p == q) {
            if (*(p + 1) == q) {
                p++;
            } else {
                break;
            }
        }
        p++;
    }
    if (*p == q)
        p++;
    return (p);
}

static void dump_value_doall_arg(CONF_VALUE *a, BIO *out)
{
    if (a->name)
        BIO_printf(out, "[%s] %s=%s\n", a->section, a->name, a->value);
    else
        BIO_printf(out, "[[%s]]\n", a->section);
}

static IMPLEMENT_LHASH_DOALL_ARG_FN(dump_value, CONF_VALUE, BIO)

static int def_dump(const CONF *conf, BIO *out)
{
    lh_CONF_VALUE_doall_arg(conf->data, LHASH_DOALL_ARG_FN(dump_value),
                            BIO, out);
    return 1;
}

static int def_is_number(const CONF *conf, char c)
{
    return IS_NUMBER(conf, c);
}

static int def_to_int(const CONF *conf, char c)
{
    return c - '0';
}
/* crypto/conf/conf_err.c */
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

/*
 * NOTE: this file was auto generated by the mkerr.pl script: any changes
 * made to it will be overwritten when the script next updates this file,
 * only reason strings will be preserved.
 */

#include <stdio.h>
// #include "err.h"
// #include "conf.h"

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

# define ERR_FUNC(func) ERR_PACK(ERR_LIB_CONF,func,0)
# define ERR_REASON(reason) ERR_PACK(ERR_LIB_CONF,0,reason)

static ERR_STRING_DATA CONF_str_functs[] = {
    {ERR_FUNC(CONF_F_CONF_DUMP_FP), "CONF_dump_fp"},
    {ERR_FUNC(CONF_F_CONF_LOAD), "CONF_load"},
    {ERR_FUNC(CONF_F_CONF_LOAD_BIO), "CONF_load_bio"},
    {ERR_FUNC(CONF_F_CONF_LOAD_FP), "CONF_load_fp"},
    {ERR_FUNC(CONF_F_CONF_MODULES_LOAD), "CONF_modules_load"},
    {ERR_FUNC(CONF_F_CONF_PARSE_LIST), "CONF_parse_list"},
    {ERR_FUNC(CONF_F_DEF_LOAD), "DEF_LOAD"},
    {ERR_FUNC(CONF_F_DEF_LOAD_BIO), "DEF_LOAD_BIO"},
    {ERR_FUNC(CONF_F_MODULE_INIT), "MODULE_INIT"},
    {ERR_FUNC(CONF_F_MODULE_LOAD_DSO), "MODULE_LOAD_DSO"},
    {ERR_FUNC(CONF_F_MODULE_RUN), "MODULE_RUN"},
    {ERR_FUNC(CONF_F_NCONF_DUMP_BIO), "NCONF_dump_bio"},
    {ERR_FUNC(CONF_F_NCONF_DUMP_FP), "NCONF_dump_fp"},
    {ERR_FUNC(CONF_F_NCONF_GET_NUMBER), "NCONF_get_number"},
    {ERR_FUNC(CONF_F_NCONF_GET_NUMBER_E), "NCONF_get_number_e"},
    {ERR_FUNC(CONF_F_NCONF_GET_SECTION), "NCONF_get_section"},
    {ERR_FUNC(CONF_F_NCONF_GET_STRING), "NCONF_get_string"},
    {ERR_FUNC(CONF_F_NCONF_LOAD), "NCONF_load"},
    {ERR_FUNC(CONF_F_NCONF_LOAD_BIO), "NCONF_load_bio"},
    {ERR_FUNC(CONF_F_NCONF_LOAD_FP), "NCONF_load_fp"},
    {ERR_FUNC(CONF_F_NCONF_NEW), "NCONF_new"},
    {ERR_FUNC(CONF_F_STR_COPY), "STR_COPY"},
    {0, NULL}
};

static ERR_STRING_DATA CONF_str_reasons[] = {
    {ERR_REASON(CONF_R_ERROR_LOADING_DSO), "error loading dso"},
    {ERR_REASON(CONF_R_LIST_CANNOT_BE_NULL), "list cannot be null"},
    {ERR_REASON(CONF_R_MISSING_CLOSE_SQUARE_BRACKET),
     "missing close square bracket"},
    {ERR_REASON(CONF_R_MISSING_EQUAL_SIGN), "missing equal sign"},
    {ERR_REASON(CONF_R_MISSING_FINISH_FUNCTION), "missing finish function"},
    {ERR_REASON(CONF_R_MISSING_INIT_FUNCTION), "missing init function"},
    {ERR_REASON(CONF_R_MODULE_INITIALIZATION_ERROR),
     "module initialization error"},
    {ERR_REASON(CONF_R_NO_CLOSE_BRACE), "no close brace"},
    {ERR_REASON(CONF_R_NO_CONF), "no conf"},
    {ERR_REASON(CONF_R_NO_CONF_OR_ENVIRONMENT_VARIABLE),
     "no conf or environment variable"},
    {ERR_REASON(CONF_R_NO_SECTION), "no section"},
    {ERR_REASON(CONF_R_NO_SUCH_FILE), "no such file"},
    {ERR_REASON(CONF_R_NO_VALUE), "no value"},
    {ERR_REASON(CONF_R_UNABLE_TO_CREATE_NEW_SECTION),
     "unable to create new section"},
    {ERR_REASON(CONF_R_UNKNOWN_MODULE_NAME), "unknown module name"},
    {ERR_REASON(CONF_R_VARIABLE_EXPANSION_TOO_LONG),
     "variable expansion too long"},
    {ERR_REASON(CONF_R_VARIABLE_HAS_NO_VALUE), "variable has no value"},
    {0, NULL}
};

#endif

void ERR_load_CONF_strings(void)
{
#ifndef OPENSSL_NO_ERR

    if (ERR_func_error_string(CONF_str_functs[0].error) == NULL) {
        ERR_load_strings(0, CONF_str_functs);
        ERR_load_strings(0, CONF_str_reasons);
    }
#endif
}
/* conf_lib.c */
/*
 * Written by Richard Levitte (richard@levitte.org) for the OpenSSL project
 * 2000.
 */
/* ====================================================================
 * Copyright (c) 2000 The OpenSSL Project.  All rights reserved.
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

#include <stdio.h>
#include "crypto.h"
// #include "err.h"
// #include "conf.h"
// #include "conf_api.h"
// #include "lhash.h"

const char CONF_version[] = "CONF" OPENSSL_VERSION_PTEXT;

static CONF_METHOD *default_CONF_method = NULL;

/* Init a 'CONF' structure from an old LHASH */

void CONF_set_nconf(CONF *conf, LHASH_OF(CONF_VALUE) *hash)
{
    if (default_CONF_method == NULL)
        default_CONF_method = NCONF_default();

    default_CONF_method->init(conf);
    conf->data = hash;
}

/*
 * The following section contains the "CONF classic" functions, rewritten in
 * terms of the new CONF interface.
 */

int CONF_set_default_method(CONF_METHOD *meth)
{
    default_CONF_method = meth;
    return 1;
}

LHASH_OF(CONF_VALUE) *CONF_load(LHASH_OF(CONF_VALUE) *conf, const char *file,
                                long *eline)
{
    LHASH_OF(CONF_VALUE) *ltmp;
    BIO *in = NULL;

#ifdef OPENSSL_SYS_VMS
    in = BIO_new_file(file, "r");
#else
    in = BIO_new_file(file, "rb");
#endif
    if (in == NULL) {
        CONFerr(CONF_F_CONF_LOAD, ERR_R_SYS_LIB);
        return NULL;
    }

    ltmp = CONF_load_bio(conf, in, eline);
    BIO_free(in);

    return ltmp;
}

#ifndef OPENSSL_NO_FP_API
LHASH_OF(CONF_VALUE) *CONF_load_fp(LHASH_OF(CONF_VALUE) *conf, FILE *fp,
                                   long *eline)
{
    BIO *btmp;
    LHASH_OF(CONF_VALUE) *ltmp;
    if (!(btmp = BIO_new_fp(fp, BIO_NOCLOSE))) {
        CONFerr(CONF_F_CONF_LOAD_FP, ERR_R_BUF_LIB);
        return NULL;
    }
    ltmp = CONF_load_bio(conf, btmp, eline);
    BIO_free(btmp);
    return ltmp;
}
#endif

LHASH_OF(CONF_VALUE) *CONF_load_bio(LHASH_OF(CONF_VALUE) *conf, BIO *bp,
                                    long *eline)
{
    CONF ctmp;
    int ret;

    CONF_set_nconf(&ctmp, conf);

    ret = NCONF_load_bio(&ctmp, bp, eline);
    if (ret)
        return ctmp.data;
    return NULL;
}

STACK_OF(CONF_VALUE) *CONF_get_section(LHASH_OF(CONF_VALUE) *conf,
                                       const char *section)
{
    if (conf == NULL) {
        return NULL;
    } else {
        CONF ctmp;
        CONF_set_nconf(&ctmp, conf);
        return NCONF_get_section(&ctmp, section);
    }
}

char *CONF_get_string(LHASH_OF(CONF_VALUE) *conf, const char *group,
                      const char *name)
{
    if (conf == NULL) {
        return NCONF_get_string(NULL, group, name);
    } else {
        CONF ctmp;
        CONF_set_nconf(&ctmp, conf);
        return NCONF_get_string(&ctmp, group, name);
    }
}

long CONF_get_number(LHASH_OF(CONF_VALUE) *conf, const char *group,
                     const char *name)
{
    int status;
    long result = 0;

    if (conf == NULL) {
        status = NCONF_get_number_e(NULL, group, name, &result);
    } else {
        CONF ctmp;
        CONF_set_nconf(&ctmp, conf);
        status = NCONF_get_number_e(&ctmp, group, name, &result);
    }

    if (status == 0) {
        /* This function does not believe in errors... */
        ERR_clear_error();
    }
    return result;
}

void CONF_free(LHASH_OF(CONF_VALUE) *conf)
{
    CONF ctmp;
    CONF_set_nconf(&ctmp, conf);
    NCONF_free_data(&ctmp);
}

#ifndef OPENSSL_NO_FP_API
int CONF_dump_fp(LHASH_OF(CONF_VALUE) *conf, FILE *out)
{
    BIO *btmp;
    int ret;

    if (!(btmp = BIO_new_fp(out, BIO_NOCLOSE))) {
        CONFerr(CONF_F_CONF_DUMP_FP, ERR_R_BUF_LIB);
        return 0;
    }
    ret = CONF_dump_bio(conf, btmp);
    BIO_free(btmp);
    return ret;
}
#endif

int CONF_dump_bio(LHASH_OF(CONF_VALUE) *conf, BIO *out)
{
    CONF ctmp;
    CONF_set_nconf(&ctmp, conf);
    return NCONF_dump_bio(&ctmp, out);
}

/*
 * The following section contains the "New CONF" functions.  They are
 * completely centralised around a new CONF structure that may contain
 * basically anything, but at least a method pointer and a table of data.
 * These functions are also written in terms of the bridge functions used by
 * the "CONF classic" functions, for consistency.
 */

CONF *NCONF_new(CONF_METHOD *meth)
{
    CONF *ret;

    if (meth == NULL)
        meth = NCONF_default();

    ret = meth->create(meth);
    if (ret == NULL) {
        CONFerr(CONF_F_NCONF_NEW, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }

    return ret;
}

void NCONF_free(CONF *conf)
{
    if (conf == NULL)
        return;
    conf->meth->destroy(conf);
}

void NCONF_free_data(CONF *conf)
{
    if (conf == NULL)
        return;
    conf->meth->destroy_data(conf);
}

int NCONF_load(CONF *conf, const char *file, long *eline)
{
    if (conf == NULL) {
        CONFerr(CONF_F_NCONF_LOAD, CONF_R_NO_CONF);
        return 0;
    }

    return conf->meth->load(conf, file, eline);
}

#ifndef OPENSSL_NO_FP_API
int NCONF_load_fp(CONF *conf, FILE *fp, long *eline)
{
    BIO *btmp;
    int ret;
    if (!(btmp = BIO_new_fp(fp, BIO_NOCLOSE))) {
        CONFerr(CONF_F_NCONF_LOAD_FP, ERR_R_BUF_LIB);
        return 0;
    }
    ret = NCONF_load_bio(conf, btmp, eline);
    BIO_free(btmp);
    return ret;
}
#endif

int NCONF_load_bio(CONF *conf, BIO *bp, long *eline)
{
    if (conf == NULL) {
        CONFerr(CONF_F_NCONF_LOAD_BIO, CONF_R_NO_CONF);
        return 0;
    }

    return conf->meth->load_bio(conf, bp, eline);
}

STACK_OF(CONF_VALUE) *NCONF_get_section(const CONF *conf, const char *section)
{
    if (conf == NULL) {
        CONFerr(CONF_F_NCONF_GET_SECTION, CONF_R_NO_CONF);
        return NULL;
    }

    if (section == NULL) {
        CONFerr(CONF_F_NCONF_GET_SECTION, CONF_R_NO_SECTION);
        return NULL;
    }

    return _CONF_get_section_values(conf, section);
}

char *NCONF_get_string(const CONF *conf, const char *group, const char *name)
{
    char *s = _CONF_get_string(conf, group, name);

    /*
     * Since we may get a value from an environment variable even if conf is
     * NULL, let's check the value first
     */
    if (s)
        return s;

    if (conf == NULL) {
        CONFerr(CONF_F_NCONF_GET_STRING,
                CONF_R_NO_CONF_OR_ENVIRONMENT_VARIABLE);
        return NULL;
    }
    CONFerr(CONF_F_NCONF_GET_STRING, CONF_R_NO_VALUE);
    ERR_add_error_data(4, "group=", group, " name=", name);
    return NULL;
}

int NCONF_get_number_e(const CONF *conf, const char *group, const char *name,
                       long *result)
{
    char *str;

    if (result == NULL) {
        CONFerr(CONF_F_NCONF_GET_NUMBER_E, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    str = NCONF_get_string(conf, group, name);

    if (str == NULL)
        return 0;

    for (*result = 0; conf->meth->is_number(conf, *str);) {
        *result = (*result) * 10 + conf->meth->to_int(conf, *str);
        str++;
    }

    return 1;
}

#ifndef OPENSSL_NO_FP_API
int NCONF_dump_fp(const CONF *conf, FILE *out)
{
    BIO *btmp;
    int ret;
    if (!(btmp = BIO_new_fp(out, BIO_NOCLOSE))) {
        CONFerr(CONF_F_NCONF_DUMP_FP, ERR_R_BUF_LIB);
        return 0;
    }
    ret = NCONF_dump_bio(conf, btmp);
    BIO_free(btmp);
    return ret;
}
#endif

int NCONF_dump_bio(const CONF *conf, BIO *out)
{
    if (conf == NULL) {
        CONFerr(CONF_F_NCONF_DUMP_BIO, CONF_R_NO_CONF);
        return 0;
    }

    return conf->meth->dump(conf, out);
}

/* This function should be avoided */
#if 0
long NCONF_get_number(CONF *conf, char *group, char *name)
{
    int status;
    long ret = 0;

    status = NCONF_get_number_e(conf, group, name, &ret);
    if (status == 0) {
        /* This function does not believe in errors... */
        ERR_get_error();
    }
    return ret;
}
#endif
/* conf_mall.c */
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

#include <stdio.h>
// #include "crypto.h"
// #include "cryptlib.h"
// #include "conf.h"
#include "dso.h"
#include "x509.h"
#include "asn1.h"
#ifndef OPENSSL_NO_ENGINE
# include "engine.h"
#endif

/* Load all OpenSSL builtin modules */

void OPENSSL_load_builtin_modules(void)
{
    /* Add builtin modules here */
    ASN1_add_oid_module();
#ifndef OPENSSL_NO_ENGINE
    ENGINE_add_conf_module();
#endif
    EVP_add_alg_module();
}
/* conf_mod.c */
/*
 * Written by Stephen Henson (steve@openssl.org) for the OpenSSL project
 * 2001.
 */
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

#include <stdio.h>
#include <ctype.h>
// #include "crypto.h"
// #include "cryptlib.h"
// #include "conf.h"
// #include "dso.h"
// #include "x509.h"

#define DSO_mod_init_name "OPENSSL_init"
#define DSO_mod_finish_name "OPENSSL_finish"

/*
 * This structure contains a data about supported modules. entries in this
 * table correspond to either dynamic or static modules.
 */

struct conf_module_st {
    /* DSO of this module or NULL if static */
    DSO *dso;
    /* Name of the module */
    char *name;
    /* Init function */
    conf_init_func *init;
    /* Finish function */
    conf_finish_func *finish;
    /* Number of successfully initialized modules */
    int links;
    void *usr_data;
};

/*
 * This structure contains information about modules that have been
 * successfully initialized. There may be more than one entry for a given
 * module.
 */

struct conf_imodule_st {
    CONF_MODULE *pmod;
    char *name;
    char *value;
    unsigned long flags;
    void *usr_data;
};

static STACK_OF(CONF_MODULE) *supported_modules = NULL;
static STACK_OF(CONF_IMODULE) *initialized_modules = NULL;

static void module_free(CONF_MODULE *md);
static void module_finish(CONF_IMODULE *imod);
static int module_run(const CONF *cnf, char *name, char *value,
                      unsigned long flags);
static CONF_MODULE *module_add(DSO *dso, const char *name,
                               conf_init_func *ifunc,
                               conf_finish_func *ffunc);
static CONF_MODULE *module_find(char *name);
static int module_init(CONF_MODULE *pmod, char *name, char *value,
                       const CONF *cnf);
static CONF_MODULE *module_load_dso(const CONF *cnf, char *name, char *value,
                                    unsigned long flags);

/* Main function: load modules from a CONF structure */

int CONF_modules_load(const CONF *cnf, const char *appname,
                      unsigned long flags)
{
    STACK_OF(CONF_VALUE) *values;
    CONF_VALUE *vl;
    char *vsection = NULL;

    int ret, i;

    if (!cnf)
        return 1;

    if (appname)
        vsection = NCONF_get_string(cnf, NULL, appname);

    if (!appname || (!vsection && (flags & CONF_MFLAGS_DEFAULT_SECTION)))
        vsection = NCONF_get_string(cnf, NULL, "openssl_conf");

    if (!vsection) {
        ERR_clear_error();
        return 1;
    }

    values = NCONF_get_section(cnf, vsection);

    if (!values)
        return 0;

    for (i = 0; i < sk_CONF_VALUE_num(values); i++) {
        vl = sk_CONF_VALUE_value(values, i);
        ret = module_run(cnf, vl->name, vl->value, flags);
        if (ret <= 0)
            if (!(flags & CONF_MFLAGS_IGNORE_ERRORS))
                return ret;
    }

    return 1;

}

int CONF_modules_load_file(const char *filename, const char *appname,
                           unsigned long flags)
{
    char *file = NULL;
    CONF *conf = NULL;
    int ret = 0;
    conf = NCONF_new(NULL);
    if (!conf)
        goto err;

    if (filename == NULL) {
        file = CONF_get1_default_config_file();
        if (!file)
            goto err;
    } else
        file = (char *)filename;

    if (NCONF_load(conf, file, NULL) <= 0) {
        if ((flags & CONF_MFLAGS_IGNORE_MISSING_FILE) &&
            (ERR_GET_REASON(ERR_peek_last_error()) == CONF_R_NO_SUCH_FILE)) {
            ERR_clear_error();
            ret = 1;
        }
        goto err;
    }

    ret = CONF_modules_load(conf, appname, flags);

 err:
    if (filename == NULL)
        OPENSSL_free(file);
    NCONF_free(conf);

    return ret;
}

static int module_run(const CONF *cnf, char *name, char *value,
                      unsigned long flags)
{
    CONF_MODULE *md;
    int ret;

    md = module_find(name);

    /* Module not found: try to load DSO */
    if (!md && !(flags & CONF_MFLAGS_NO_DSO))
        md = module_load_dso(cnf, name, value, flags);

    if (!md) {
        if (!(flags & CONF_MFLAGS_SILENT)) {
            CONFerr(CONF_F_MODULE_RUN, CONF_R_UNKNOWN_MODULE_NAME);
            ERR_add_error_data(2, "module=", name);
        }
        return -1;
    }

    ret = module_init(md, name, value, cnf);

    if (ret <= 0) {
        if (!(flags & CONF_MFLAGS_SILENT)) {
            char rcode[DECIMAL_SIZE(ret) + 1];
            CONFerr(CONF_F_MODULE_RUN, CONF_R_MODULE_INITIALIZATION_ERROR);
            BIO_snprintf(rcode, sizeof(rcode), "%-8d", ret);
            ERR_add_error_data(6, "module=", name, ", value=", value,
                               ", retcode=", rcode);
        }
    }

    return ret;
}

/* Load a module from a DSO */
static CONF_MODULE *module_load_dso(const CONF *cnf, char *name, char *value,
                                    unsigned long flags)
{
    DSO *dso = NULL;
    conf_init_func *ifunc;
    conf_finish_func *ffunc;
    char *path = NULL;
    int errcode = 0;
    CONF_MODULE *md;
    /* Look for alternative path in module section */
    path = NCONF_get_string(cnf, value, "path");
    if (!path) {
        ERR_clear_error();
        path = name;
    }
    dso = DSO_load(NULL, path, NULL, 0);
    if (!dso) {
        errcode = CONF_R_ERROR_LOADING_DSO;
        goto err;
    }
    ifunc = (conf_init_func *)DSO_bind_func(dso, DSO_mod_init_name);
    if (!ifunc) {
        errcode = CONF_R_MISSING_INIT_FUNCTION;
        goto err;
    }
    ffunc = (conf_finish_func *)DSO_bind_func(dso, DSO_mod_finish_name);
    /* All OK, add module */
    md = module_add(dso, name, ifunc, ffunc);

    if (!md)
        goto err;

    return md;

 err:
    if (dso)
        DSO_free(dso);
    CONFerr(CONF_F_MODULE_LOAD_DSO, errcode);
    ERR_add_error_data(4, "module=", name, ", path=", path);
    return NULL;
}

/* add module to list */
static CONF_MODULE *module_add(DSO *dso, const char *name,
                               conf_init_func *ifunc, conf_finish_func *ffunc)
{
    CONF_MODULE *tmod = NULL;
    if (supported_modules == NULL)
        supported_modules = sk_CONF_MODULE_new_null();
    if (supported_modules == NULL)
        return NULL;
    tmod = OPENSSL_malloc(sizeof(CONF_MODULE));
    if (tmod == NULL)
        return NULL;

    tmod->dso = dso;
    tmod->name = BUF_strdup(name);
    if (tmod->name == NULL) {
        OPENSSL_free(tmod);
        return NULL;
    }
    tmod->init = ifunc;
    tmod->finish = ffunc;
    tmod->links = 0;

    if (!sk_CONF_MODULE_push(supported_modules, tmod)) {
        OPENSSL_free(tmod);
        return NULL;
    }

    return tmod;
}

/*
 * Find a module from the list. We allow module names of the form
 * modname.XXXX to just search for modname to allow the same module to be
 * initialized more than once.
 */

static CONF_MODULE *module_find(char *name)
{
    CONF_MODULE *tmod;
    int i, nchar;
    char *p;
    p = strrchr(name, '.');

    if (p)
        nchar = p - name;
    else
        nchar = strlen(name);

    for (i = 0; i < sk_CONF_MODULE_num(supported_modules); i++) {
        tmod = sk_CONF_MODULE_value(supported_modules, i);
        if (!strncmp(tmod->name, name, nchar))
            return tmod;
    }

    return NULL;

}

/* initialize a module */
static int module_init(CONF_MODULE *pmod, char *name, char *value,
                       const CONF *cnf)
{
    int ret = 1;
    int init_called = 0;
    CONF_IMODULE *imod = NULL;

    /* Otherwise add initialized module to list */
    imod = OPENSSL_malloc(sizeof(CONF_IMODULE));
    if (!imod)
        goto err;

    imod->pmod = pmod;
    imod->name = BUF_strdup(name);
    imod->value = BUF_strdup(value);
    imod->usr_data = NULL;

    if (!imod->name || !imod->value)
        goto memerr;

    /* Try to initialize module */
    if (pmod->init) {
        ret = pmod->init(imod, cnf);
        init_called = 1;
        /* Error occurred, exit */
        if (ret <= 0)
            goto err;
    }

    if (initialized_modules == NULL) {
        initialized_modules = sk_CONF_IMODULE_new_null();
        if (!initialized_modules) {
            CONFerr(CONF_F_MODULE_INIT, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    }

    if (!sk_CONF_IMODULE_push(initialized_modules, imod)) {
        CONFerr(CONF_F_MODULE_INIT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    pmod->links++;

    return ret;

 err:

    /* We've started the module so we'd better finish it */
    if (pmod->finish && init_called)
        pmod->finish(imod);

 memerr:
    if (imod) {
        if (imod->name)
            OPENSSL_free(imod->name);
        if (imod->value)
            OPENSSL_free(imod->value);
        OPENSSL_free(imod);
    }

    return -1;

}

/*
 * Unload any dynamic modules that have a link count of zero: i.e. have no
 * active initialized modules. If 'all' is set then all modules are unloaded
 * including static ones.
 */

void CONF_modules_unload(int all)
{
    int i;
    CONF_MODULE *md;
    CONF_modules_finish();
    /* unload modules in reverse order */
    for (i = sk_CONF_MODULE_num(supported_modules) - 1; i >= 0; i--) {
        md = sk_CONF_MODULE_value(supported_modules, i);
        /* If static or in use and 'all' not set ignore it */
        if (((md->links > 0) || !md->dso) && !all)
            continue;
        /* Since we're working in reverse this is OK */
        (void)sk_CONF_MODULE_delete(supported_modules, i);
        module_free(md);
    }
    if (sk_CONF_MODULE_num(supported_modules) == 0) {
        sk_CONF_MODULE_free(supported_modules);
        supported_modules = NULL;
    }
}

/* unload a single module */
static void module_free(CONF_MODULE *md)
{
    if (md->dso)
        DSO_free(md->dso);
    OPENSSL_free(md->name);
    OPENSSL_free(md);
}

/* finish and free up all modules instances */

void CONF_modules_finish(void)
{
    CONF_IMODULE *imod;
    while (sk_CONF_IMODULE_num(initialized_modules) > 0) {
        imod = sk_CONF_IMODULE_pop(initialized_modules);
        module_finish(imod);
    }
    sk_CONF_IMODULE_free(initialized_modules);
    initialized_modules = NULL;
}

/* finish a module instance */

static void module_finish(CONF_IMODULE *imod)
{
    if (imod->pmod->finish)
        imod->pmod->finish(imod);
    imod->pmod->links--;
    OPENSSL_free(imod->name);
    OPENSSL_free(imod->value);
    OPENSSL_free(imod);
}

/* Add a static module to OpenSSL */

int CONF_module_add(const char *name, conf_init_func *ifunc,
                    conf_finish_func *ffunc)
{
    if (module_add(NULL, name, ifunc, ffunc))
        return 1;
    else
        return 0;
}

void CONF_modules_free(void)
{
    CONF_modules_finish();
    CONF_modules_unload(1);
}

/* Utility functions */

const char *CONF_imodule_get_name(const CONF_IMODULE *md)
{
    return md->name;
}

const char *CONF_imodule_get_value(const CONF_IMODULE *md)
{
    return md->value;
}

void *CONF_imodule_get_usr_data(const CONF_IMODULE *md)
{
    return md->usr_data;
}

void CONF_imodule_set_usr_data(CONF_IMODULE *md, void *usr_data)
{
    md->usr_data = usr_data;
}

CONF_MODULE *CONF_imodule_get_module(const CONF_IMODULE *md)
{
    return md->pmod;
}

unsigned long CONF_imodule_get_flags(const CONF_IMODULE *md)
{
    return md->flags;
}

void CONF_imodule_set_flags(CONF_IMODULE *md, unsigned long flags)
{
    md->flags = flags;
}

void *CONF_module_get_usr_data(CONF_MODULE *pmod)
{
    return pmod->usr_data;
}

void CONF_module_set_usr_data(CONF_MODULE *pmod, void *usr_data)
{
    pmod->usr_data = usr_data;
}

/* Return default config file name */

char *CONF_get1_default_config_file(void)
{
    char *file;
    int len;

    file = ossl_safe_getenv("OPENSSL_CONF");
    if (file)
        return BUF_strdup(file);

    len = strlen(X509_get_default_cert_area());
#ifndef OPENSSL_SYS_VMS
    len++;
#endif
    len += strlen(OPENSSL_CONF);

    file = OPENSSL_malloc(len + 1);

    if (!file)
        return NULL;
    BUF_strlcpy(file, X509_get_default_cert_area(), len + 1);
#ifndef OPENSSL_SYS_VMS
    BUF_strlcat(file, "/", len + 1);
#endif
    BUF_strlcat(file, OPENSSL_CONF, len + 1);

    return file;
}

/*
 * This function takes a list separated by 'sep' and calls the callback
 * function giving the start and length of each member optionally stripping
 * leading and trailing whitespace. This can be used to parse comma separated
 * lists for example.
 */

int CONF_parse_list(const char *list_, int sep, int nospc,
                    int (*list_cb) (const char *elem, int len, void *usr),
                    void *arg)
{
    int ret;
    const char *lstart, *tmpend, *p;

    if (list_ == NULL) {
        CONFerr(CONF_F_CONF_PARSE_LIST, CONF_R_LIST_CANNOT_BE_NULL);
        return 0;
    }

    lstart = list_;
    for (;;) {
        if (nospc) {
            while (*lstart && isspace((unsigned char)*lstart))
                lstart++;
        }
        p = strchr(lstart, sep);
        if (p == lstart || !*lstart)
            ret = list_cb(NULL, 0, arg);
        else {
            if (p)
                tmpend = p - 1;
            else
                tmpend = lstart + strlen(lstart) - 1;
            if (nospc) {
                while (isspace((unsigned char)*tmpend))
                    tmpend--;
            }
            ret = list_cb(lstart, tmpend - lstart + 1, arg);
        }
        if (ret <= 0)
            return ret;
        if (p == NULL)
            return 1;
        lstart = p + 1;
    }
}
/* conf_sap.c */
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

#include <stdio.h>
// #include "crypto.h"
// #include "cryptlib.h"
// #include "conf.h"
// #include "dso.h"
// #include "x509.h"
// #include "asn1.h"
#ifndef OPENSSL_NO_ENGINE
# include "engine.h"
#endif

/*
 * This is the automatic configuration loader: it is called automatically by
 * OpenSSL when any of a number of standard initialisation functions are
 * called, unless this is overridden by calling OPENSSL_no_config()
 */

static int openssl_configured = 0;

void OPENSSL_config(const char *config_name)
{
    if (openssl_configured)
        return;

    OPENSSL_load_builtin_modules();
#ifndef OPENSSL_NO_ENGINE
    /* Need to load ENGINEs */
    ENGINE_load_builtin_engines();
#endif
    ERR_clear_error();
    CONF_modules_load_file(NULL, config_name,
                               CONF_MFLAGS_DEFAULT_SECTION |
                               CONF_MFLAGS_IGNORE_MISSING_FILE);
    openssl_configured = 1;
}

void OPENSSL_no_config()
{
    openssl_configured = 1;
}
