/* crypto/o_dir.c */
/*
 * Written by Richard Levitte (richard@levitte.org) for the OpenSSL project
 * 2004.
 */
/* ====================================================================
 * Copyright (c) 2004 The OpenSSL Project.  All rights reserved.
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

#include <errno.h>
#include "e_os.h"

/*
 * The routines really come from the Levitte Programming, so to make life
 * simple, let's just use the raw files and hack the symbols to fit our
 * namespace.
 */
#define LP_DIR_CTX OPENSSL_DIR_CTX
#define LP_dir_context_st OPENSSL_dir_context_st
#define LP_find_file OPENSSL_DIR_read
#define LP_find_file_end OPENSSL_DIR_end

#include "o_dir.h"

#define LPDIR_H
#if defined OPENSSL_SYS_UNIX || defined DJGPP \
    || (defined __VMS_VER && __VMS_VER >= 70000000)
# include "LPdir_unix.h"
#elif defined OPENSSL_SYS_VMS
# include "LPdir_vms.c"
#elif defined OPENSSL_SYS_WIN32
# include "LPdir_win32.c"
#elif defined OPENSSL_SYS_WINCE
# include "LPdir_wince.c"
#else
# include "LPdir_nyi.c"
#endif
/*
 * Written by Stephen henson (steve@openssl.org) for the OpenSSL project
 * 2011.
 */
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

#include "cryptlib.h"
#ifdef OPENSSL_FIPS
# include <fips.h>
# include <fips_rand.h>
# include "rand.h"
#endif

int FIPS_mode(void)
{
    OPENSSL_init();
#ifdef OPENSSL_FIPS
    return FIPS_module_mode();
#else
    return 0;
#endif
}

int FIPS_mode_set(int r)
{
    OPENSSL_init();
#ifdef OPENSSL_FIPS
# ifndef FIPS_AUTH_USER_PASS
#  define FIPS_AUTH_USER_PASS     "Default FIPS Crypto User Password"
# endif
    if (!FIPS_module_mode_set(r, FIPS_AUTH_USER_PASS))
        return 0;
    if (r)
        RAND_set_rand_method(FIPS_rand_get_method());
    else
        RAND_set_rand_method(NULL);
    return 1;
#else
    if (r == 0)
        return 1;
    CRYPTOerr(CRYPTO_F_FIPS_MODE_SET, CRYPTO_R_FIPS_MODE_NOT_SUPPORTED);
    return 0;
#endif
}
/* o_init.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
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

// #include "e_os.h"
#include "err.h"
#ifdef OPENSSL_FIPS
# include <fips.h>
# include "rand.h"

# ifndef OPENSSL_NO_DEPRECATED
/* the prototype is missing in <openssl/fips.h> */
void FIPS_crypto_set_id_callback(unsigned long (*func)(void));
# endif
#endif

/*
 * Perform any essential OpenSSL initialization operations. Currently only
 * sets FIPS callbacks
 */

void OPENSSL_init(void)
{
    static int done = 0;
    if (done)
        return;
    done = 1;
#ifdef OPENSSL_FIPS
    FIPS_set_locking_callbacks(CRYPTO_lock, CRYPTO_add_lock);
# ifndef OPENSSL_NO_DEPRECATED
    FIPS_crypto_set_id_callback(CRYPTO_thread_id);
# endif
    FIPS_set_error_callbacks(ERR_put_error, ERR_add_error_vdata);
    FIPS_set_malloc_callbacks(CRYPTO_malloc, CRYPTO_free);
    RAND_init_fips();
#endif
#if 0
    fprintf(stderr, "Called OPENSSL_init\n");
#endif
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// #include "err.h"
#include "lhash.h"
#include "objects.h"
#include "safestack.h"
#include "e_os2.h"

/*
 * Later versions of DEC C has started to add lnkage information to certain
 * functions, which makes it tricky to use them as values to regular function
 * pointers.  One way is to define a macro that takes care of casting them
 * correctly.
 */
#ifdef OPENSSL_SYS_VMS_DECC
# define OPENSSL_strcmp (int (*)(const char *,const char *))strcmp
#else
# define OPENSSL_strcmp strcmp
#endif

/*
 * I use the ex_data stuff to manage the identifiers for the obj_name_types
 * that applications may define.  I only really use the free function field.
 */
DECLARE_LHASH_OF(OBJ_NAME);
static LHASH_OF(OBJ_NAME) *names_lh = NULL;
static int names_type_num = OBJ_NAME_TYPE_NUM;

typedef struct name_funcs_st {
    unsigned long (*hash_func) (const char *name);
    int (*cmp_func) (const char *a, const char *b);
    void (*free_func) (const char *, int, const char *);
} NAME_FUNCS;

DECLARE_STACK_OF(NAME_FUNCS)
IMPLEMENT_STACK_OF(NAME_FUNCS)

static STACK_OF(NAME_FUNCS) *name_funcs_stack;

/*
 * The LHASH callbacks now use the raw "void *" prototypes and do
 * per-variable casting in the functions. This prevents function pointer
 * casting without the need for macro-generated wrapper functions.
 */

/* static unsigned long obj_name_hash(OBJ_NAME *a); */
static unsigned long obj_name_hash(const void *a_void);
/* static int obj_name_cmp(OBJ_NAME *a,OBJ_NAME *b); */
static int obj_name_cmp(const void *a_void, const void *b_void);

static IMPLEMENT_LHASH_HASH_FN(obj_name, OBJ_NAME)
static IMPLEMENT_LHASH_COMP_FN(obj_name, OBJ_NAME)

int OBJ_NAME_init(void)
{
    if (names_lh != NULL)
        return (1);
    MemCheck_off();
    names_lh = lh_OBJ_NAME_new();
    MemCheck_on();
    return (names_lh != NULL);
}

int OBJ_NAME_new_index(unsigned long (*hash_func) (const char *),
                       int (*cmp_func) (const char *, const char *),
                       void (*free_func) (const char *, int, const char *))
{
    int ret;
    int i;
    NAME_FUNCS *name_funcs;

    if (name_funcs_stack == NULL) {
        MemCheck_off();
        name_funcs_stack = sk_NAME_FUNCS_new_null();
        MemCheck_on();
    }
    if (name_funcs_stack == NULL) {
        /* ERROR */
        return (0);
    }
    ret = names_type_num;
    names_type_num++;
    for (i = sk_NAME_FUNCS_num(name_funcs_stack); i < names_type_num; i++) {
        MemCheck_off();
        name_funcs = OPENSSL_malloc(sizeof(NAME_FUNCS));
        MemCheck_on();
        if (!name_funcs) {
            OBJerr(OBJ_F_OBJ_NAME_NEW_INDEX, ERR_R_MALLOC_FAILURE);
            return (0);
        }
        name_funcs->hash_func = lh_strhash;
        name_funcs->cmp_func = OPENSSL_strcmp;
        name_funcs->free_func = 0; /* NULL is often declared to * ((void
                                    * *)0), which according * to Compaq C is
                                    * not really * compatible with a function
                                    * * pointer.  -- Richard Levitte */
        MemCheck_off();
        sk_NAME_FUNCS_push(name_funcs_stack, name_funcs);
        MemCheck_on();
    }
    name_funcs = sk_NAME_FUNCS_value(name_funcs_stack, ret);
    if (hash_func != NULL)
        name_funcs->hash_func = hash_func;
    if (cmp_func != NULL)
        name_funcs->cmp_func = cmp_func;
    if (free_func != NULL)
        name_funcs->free_func = free_func;
    return (ret);
}

/* static int obj_name_cmp(OBJ_NAME *a, OBJ_NAME *b) */
static int obj_name_cmp(const void *a_void, const void *b_void)
{
    int ret;
    const OBJ_NAME *a = (const OBJ_NAME *)a_void;
    const OBJ_NAME *b = (const OBJ_NAME *)b_void;

    ret = a->type - b->type;
    if (ret == 0) {
        if ((name_funcs_stack != NULL)
            && (sk_NAME_FUNCS_num(name_funcs_stack) > a->type)) {
            ret = sk_NAME_FUNCS_value(name_funcs_stack,
                                      a->type)->cmp_func(a->name, b->name);
        } else
            ret = strcmp(a->name, b->name);
    }
    return (ret);
}

/* static unsigned long obj_name_hash(OBJ_NAME *a) */
static unsigned long obj_name_hash(const void *a_void)
{
    unsigned long ret;
    const OBJ_NAME *a = (const OBJ_NAME *)a_void;

    if ((name_funcs_stack != NULL)
        && (sk_NAME_FUNCS_num(name_funcs_stack) > a->type)) {
        ret =
            sk_NAME_FUNCS_value(name_funcs_stack,
                                a->type)->hash_func(a->name);
    } else {
        ret = lh_strhash(a->name);
    }
    ret ^= a->type;
    return (ret);
}

const char *OBJ_NAME_get(const char *name, int type)
{
    OBJ_NAME on, *ret;
    int num = 0, alias;

    if (name == NULL)
        return (NULL);
    if ((names_lh == NULL) && !OBJ_NAME_init())
        return (NULL);

    alias = type & OBJ_NAME_ALIAS;
    type &= ~OBJ_NAME_ALIAS;

    on.name = name;
    on.type = type;

    for (;;) {
        ret = lh_OBJ_NAME_retrieve(names_lh, &on);
        if (ret == NULL)
            return (NULL);
        if ((ret->alias) && !alias) {
            if (++num > 10)
                return (NULL);
            on.name = ret->data;
        } else {
            return (ret->data);
        }
    }
}

int OBJ_NAME_add(const char *name, int type, const char *data)
{
    OBJ_NAME *onp, *ret;
    int alias;

    if ((names_lh == NULL) && !OBJ_NAME_init())
        return (0);

    alias = type & OBJ_NAME_ALIAS;
    type &= ~OBJ_NAME_ALIAS;

    onp = (OBJ_NAME *)OPENSSL_malloc(sizeof(OBJ_NAME));
    if (onp == NULL) {
        /* ERROR */
        return 0;
    }

    onp->name = name;
    onp->alias = alias;
    onp->type = type;
    onp->data = data;

    ret = lh_OBJ_NAME_insert(names_lh, onp);
    if (ret != NULL) {
        /* free things */
        if ((name_funcs_stack != NULL)
            && (sk_NAME_FUNCS_num(name_funcs_stack) > ret->type)) {
            /*
             * XXX: I'm not sure I understand why the free function should
             * get three arguments... -- Richard Levitte
             */
            sk_NAME_FUNCS_value(name_funcs_stack,
                                ret->type)->free_func(ret->name, ret->type,
                                                      ret->data);
        }
        OPENSSL_free(ret);
    } else {
        if (lh_OBJ_NAME_error(names_lh)) {
            /* ERROR */
            OPENSSL_free(onp);
            return 0;
        }
    }
    return 1;
}

int OBJ_NAME_remove(const char *name, int type)
{
    OBJ_NAME on, *ret;

    if (names_lh == NULL)
        return (0);

    type &= ~OBJ_NAME_ALIAS;
    on.name = name;
    on.type = type;
    ret = lh_OBJ_NAME_delete(names_lh, &on);
    if (ret != NULL) {
        /* free things */
        if ((name_funcs_stack != NULL)
            && (sk_NAME_FUNCS_num(name_funcs_stack) > ret->type)) {
            /*
             * XXX: I'm not sure I understand why the free function should
             * get three arguments... -- Richard Levitte
             */
            sk_NAME_FUNCS_value(name_funcs_stack,
                                ret->type)->free_func(ret->name, ret->type,
                                                      ret->data);
        }
        OPENSSL_free(ret);
        return (1);
    } else
        return (0);
}

struct doall {
    int type;
    void (*fn) (const OBJ_NAME *, void *arg);
    void *arg;
};

static void do_all_fn_doall_arg(const OBJ_NAME *name, struct doall *d)
{
    if (name->type == d->type)
        d->fn(name, d->arg);
}

static IMPLEMENT_LHASH_DOALL_ARG_FN(do_all_fn, const OBJ_NAME, struct doall)

void OBJ_NAME_do_all(int type, void (*fn) (const OBJ_NAME *, void *arg),
                     void *arg)
{
    struct doall d;

    d.type = type;
    d.fn = fn;
    d.arg = arg;

    lh_OBJ_NAME_doall_arg(names_lh, LHASH_DOALL_ARG_FN(do_all_fn),
                          struct doall, &d);
}

struct doall_sorted {
    int type;
    int n;
    const OBJ_NAME **names;
};

static void do_all_sorted_fn(const OBJ_NAME *name, void *d_)
{
    struct doall_sorted *d = d_;

    if (name->type != d->type)
        return;

    d->names[d->n++] = name;
}

static int do_all_sorted_cmp(const void *n1_, const void *n2_)
{
    const OBJ_NAME *const *n1 = n1_;
    const OBJ_NAME *const *n2 = n2_;

    return strcmp((*n1)->name, (*n2)->name);
}

void OBJ_NAME_do_all_sorted(int type,
                            void (*fn) (const OBJ_NAME *, void *arg),
                            void *arg)
{
    struct doall_sorted d;
    int n;

    d.type = type;
    d.names =
        OPENSSL_malloc(lh_OBJ_NAME_num_items(names_lh) * sizeof(*d.names));
    /* Really should return an error if !d.names...but its a void function! */
    if (d.names) {
        d.n = 0;
        OBJ_NAME_do_all(type, do_all_sorted_fn, &d);

        qsort((void *)d.names, d.n, sizeof(*d.names), do_all_sorted_cmp);

        for (n = 0; n < d.n; ++n)
            fn(d.names[n], arg);

        OPENSSL_free((void *)d.names);
    }
}

static int free_type;

static void names_lh_free_doall(OBJ_NAME *onp)
{
    if (onp == NULL)
        return;

    if (free_type < 0 || free_type == onp->type)
        OBJ_NAME_remove(onp->name, onp->type);
}

static IMPLEMENT_LHASH_DOALL_FN(names_lh_free, OBJ_NAME)

static void name_funcs_free(NAME_FUNCS *ptr)
{
    OPENSSL_free(ptr);
}

void OBJ_NAME_cleanup(int type)
{
    unsigned long down_load;

    if (names_lh == NULL)
        return;

    free_type = type;
    down_load = lh_OBJ_NAME_down_load(names_lh);
    lh_OBJ_NAME_down_load(names_lh) = 0;

    lh_OBJ_NAME_doall(names_lh, LHASH_DOALL_FN(names_lh_free));
    if (type < 0) {
        lh_OBJ_NAME_free(names_lh);
        sk_NAME_FUNCS_pop_free(name_funcs_stack, name_funcs_free);
        names_lh = NULL;
        name_funcs_stack = NULL;
    } else
        lh_OBJ_NAME_down_load(names_lh) = down_load;
}
/* crypto/o_str.c */
/*
 * Written by Richard Levitte (richard@levitte.org) for the OpenSSL project
 * 2003.
 */
/* ====================================================================
 * Copyright (c) 2003 The OpenSSL Project.  All rights reserved.
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

#include <ctype.h>
// #include "e_os.h"
#include "o_str.h"

#if !defined(OPENSSL_IMPLEMENTS_strncasecmp) && \
    !defined(OPENSSL_SYSNAME_WIN32) && !defined(OPENSSL_SYSNAME_WINCE) && \
    !defined(NETWARE_CLIB)
# include <strings.h>
#endif

int OPENSSL_strncasecmp(const char *str1, const char *str2, size_t n)
{
#if defined(OPENSSL_IMPLEMENTS_strncasecmp)
    while (*str1 && *str2 && n) {
        int res = toupper(*str1) - toupper(*str2);
        if (res)
            return res < 0 ? -1 : 1;
        str1++;
        str2++;
        n--;
    }
    if (n == 0)
        return 0;
    if (*str1)
        return 1;
    if (*str2)
        return -1;
    return 0;
#else
    /*
     * Recursion hazard warning! Whenever strncasecmp is #defined as
     * OPENSSL_strncasecmp, OPENSSL_IMPLEMENTS_strncasecmp must be defined as
     * well.
     */
    return strncasecmp(str1, str2, n);
#endif
}

int OPENSSL_strcasecmp(const char *str1, const char *str2)
{
#if defined(OPENSSL_IMPLEMENTS_strncasecmp)
    return OPENSSL_strncasecmp(str1, str2, (size_t)-1);
#else
    return strcasecmp(str1, str2);
#endif
}

int OPENSSL_memcmp(const void *v1, const void *v2, size_t n)
{
    const unsigned char *c1 = v1, *c2 = v2;
    int ret = 0;

    while (n && (ret = *c1 - *c2) == 0)
        n--, c1++, c2++;

    return ret;
}
/* crypto/o_time.c */
/*
 * Written by Richard Levitte (richard@levitte.org) for the OpenSSL project
 * 2001.
 */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2008.
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

// #include "e_os2.h"
#include <string.h>
#include "o_time.h"

#ifdef OPENSSL_SYS_VMS
# if __CRTL_VER >= 70000000 && \
     (defined _POSIX_C_SOURCE || !defined _ANSI_C_SOURCE)
#  define VMS_GMTIME_OK
# endif
# ifndef VMS_GMTIME_OK
#  include <libdtdef.h>
#  include <lib$routines.h>
#  include <lnmdef.h>
#  include <starlet.h>
#  include <descrip.h>
#  include <stdlib.h>
# endif                         /* ndef VMS_GMTIME_OK */


/*
 * Needed to pick up the correct definitions and declarations in some of the
 * DEC C Header Files (*.H).
 */
# define __NEW_STARLET 1

# if (defined(__alpha) || defined(__ia64))
#  include <iledef.h>
# else

/* VAX */
typedef struct _ile3 {          /* Copied from ILEDEF.H for Alpha   */
#  pragma __nomember_alignment
    unsigned short int ile3$w_length;        /* Length of buffer in bytes */
    unsigned short int ile3$w_code;          /* Item code value */
    void *ile3$ps_bufaddr;                   /* Buffer address */
    unsigned short int *ile3$ps_retlen_addr; /* Address of word for returned length */
} ILE3;
# endif   /* alpha || ia64    */
#endif    /* OPENSSL_SYS_VMS  */

struct tm *OPENSSL_gmtime(const time_t *timer, struct tm *result)
{
    struct tm *ts = NULL;

#if defined(OPENSSL_THREADS) && !defined(OPENSSL_SYS_WIN32) && !defined(OPENSSL_SYS_OS2) && (!defined(OPENSSL_SYS_VMS) || defined(gmtime_r)) && !defined(OPENSSL_SYS_SUNOS)
    if (gmtime_r(timer, result) == NULL)
        return NULL;
    ts = result;
#elif defined (OPENSSL_SYS_WINDOWS) && defined(_MSC_VER) && _MSC_VER >= 1400
    if (gmtime_s(result, timer))
        return NULL;
    ts = result;
#elif !defined(OPENSSL_SYS_VMS) || defined(VMS_GMTIME_OK)
    ts = gmtime(timer);
    if (ts == NULL)
        return NULL;

    memcpy(result, ts, sizeof(struct tm));
    ts = result;
#endif
#if defined( OPENSSL_SYS_VMS) && !defined( VMS_GMTIME_OK)
    if (ts == NULL) {
        static $DESCRIPTOR(tabnam, "LNM$DCL_LOGICAL");
        static $DESCRIPTOR(lognam, "SYS$TIMEZONE_DIFFERENTIAL");
        char logvalue[256];
        unsigned int reslen = 0;
# if __INITIAL_POINTER_SIZE == 64
        ILEB_64 itemlist[2], *pitem;
# else
        ILE3 itemlist[2], *pitem;
# endif
        int status;
        time_t t;


        /*
         * Setup an itemlist for the call to $TRNLNM - Translate Logical Name.
         */
        pitem = itemlist;

# if __INITIAL_POINTER_SIZE == 64
        pitem->ileb_64$w_mbo = 1;
        pitem->ileb_64$w_code = LNM$_STRING;
        pitem->ileb_64$l_mbmo = -1;
        pitem->ileb_64$q_length = sizeof(logvalue);
        pitem->ileb_64$pq_bufaddr = logvalue;
        pitem->ileb_64$pq_retlen_addr = (unsigned __int64 *) &reslen;
        pitem++;
        /* Last item of the item list is null terminated */
        pitem->ileb_64$q_length = pitem->ileb_64$w_code = 0;
# else
        pitem->ile3$w_length = sizeof(logvalue);
        pitem->ile3$w_code = LNM$_STRING;
        pitem->ile3$ps_bufaddr = logvalue;
        pitem->ile3$ps_retlen_addr = (unsigned short int *) &reslen;
        pitem++;
        /* Last item of the item list is null terminated */
        pitem->ile3$w_length = pitem->ile3$w_code = 0;
# endif


        /* Get the value for SYS$TIMEZONE_DIFFERENTIAL */
        status = sys$trnlnm(0, &tabnam, &lognam, 0, itemlist);
        if (!(status & 1))
            return NULL;
        logvalue[reslen] = '\0';

        t = *timer;

        /* The following is extracted from the DEC C header time.h */
        /*
         **  Beginning in OpenVMS Version 7.0 mktime, time, ctime, strftime
         **  have two implementations.  One implementation is provided
         **  for compatibility and deals with time in terms of local time,
         **  the other __utc_* deals with time in terms of UTC.
         */
        /*
         * We use the same conditions as in said time.h to check if we should
         * assume that t contains local time (and should therefore be
         * adjusted) or UTC (and should therefore be left untouched).
         */
# if __CRTL_VER < 70000000 || defined _VMS_V6_SOURCE
        /* Get the numerical value of the equivalence string */
        status = atoi(logvalue);

        /* and use it to move time to GMT */
        t -= status;
# endif

        /* then convert the result to the time structure */

        /*
         * Since there was no gmtime_r() to do this stuff for us, we have to
         * do it the hard way.
         */
        {
            /*-
             * The VMS epoch is the astronomical Smithsonian date,
               if I remember correctly, which is November 17, 1858.
               Furthermore, time is measure in thenths of microseconds
               and stored in quadwords (64 bit integers).  unix_epoch
               below is January 1st 1970 expressed as a VMS time.  The
               following code was used to get this number:

               #include <stdio.h>
               #include <stdlib.h>
               #include <lib$routines.h>
               #include <starlet.h>

               main()
               {
                 unsigned long systime[2];
                 unsigned short epoch_values[7] =
                   { 1970, 1, 1, 0, 0, 0, 0 };

                 lib$cvt_vectim(epoch_values, systime);

                 printf("%u %u", systime[0], systime[1]);
               }
            */
            unsigned long unix_epoch[2] = { 1273708544, 8164711 };
            unsigned long deltatime[2];
            unsigned long systime[2];
            struct vms_vectime {
                short year, month, day, hour, minute, second, centi_second;
            } time_values;
            long operation;

            /*
             * Turn the number of seconds since January 1st 1970 to an
             * internal delta time. Note that lib$cvt_to_internal_time() will
             * assume that t is signed, and will therefore break on 32-bit
             * systems some time in 2038.
             */
            operation = LIB$K_DELTA_SECONDS;
            status = lib$cvt_to_internal_time(&operation, &t, deltatime);

            /*
             * Add the delta time with the Unix epoch and we have the current
             * UTC time in internal format
             */
            status = lib$add_times(unix_epoch, deltatime, systime);

            /* Turn the internal time into a time vector */
            status = sys$numtim(&time_values, systime);

            /* Fill in the struct tm with the result */
            result->tm_sec = time_values.second;
            result->tm_min = time_values.minute;
            result->tm_hour = time_values.hour;
            result->tm_mday = time_values.day;
            result->tm_mon = time_values.month - 1;
            result->tm_year = time_values.year - 1900;

            operation = LIB$K_DAY_OF_WEEK;
            status = lib$cvt_from_internal_time(&operation,
                                                &result->tm_wday, systime);
            result->tm_wday %= 7;

            operation = LIB$K_DAY_OF_YEAR;
            status = lib$cvt_from_internal_time(&operation,
                                                &result->tm_yday, systime);
            result->tm_yday--;

            result->tm_isdst = 0; /* There's no way to know... */

            ts = result;
        }
    }
#endif
    return ts;
}

/*
 * Take a tm structure and add an offset to it. This avoids any OS issues
 * with restricted date types and overflows which cause the year 2038
 * problem.
 */

#define SECS_PER_DAY (24 * 60 * 60)

static long date_to_julian(int y, int m, int d);
static void julian_to_date(long jd, int *y, int *m, int *d);
static int julian_adj(const struct tm *tm, int off_day, long offset_sec,
                      long *pday, int *psec);

int OPENSSL_gmtime_adj(struct tm *tm, int off_day, long offset_sec)
{
    int time_sec, time_year, time_month, time_day;
    long time_jd;

    /* Convert time and offset into julian day and seconds */
    if (!julian_adj(tm, off_day, offset_sec, &time_jd, &time_sec))
        return 0;

    /* Convert Julian day back to date */

    julian_to_date(time_jd, &time_year, &time_month, &time_day);

    if (time_year < 1900 || time_year > 9999)
        return 0;

    /* Update tm structure */

    tm->tm_year = time_year - 1900;
    tm->tm_mon = time_month - 1;
    tm->tm_mday = time_day;

    tm->tm_hour = time_sec / 3600;
    tm->tm_min = (time_sec / 60) % 60;
    tm->tm_sec = time_sec % 60;

    return 1;

}

int OPENSSL_gmtime_diff(int *pday, int *psec,
                        const struct tm *from, const struct tm *to)
{
    int from_sec, to_sec, diff_sec;
    long from_jd, to_jd, diff_day;
    if (!julian_adj(from, 0, 0, &from_jd, &from_sec))
        return 0;
    if (!julian_adj(to, 0, 0, &to_jd, &to_sec))
        return 0;
    diff_day = to_jd - from_jd;
    diff_sec = to_sec - from_sec;
    /* Adjust differences so both positive or both negative */
    if (diff_day > 0 && diff_sec < 0) {
        diff_day--;
        diff_sec += SECS_PER_DAY;
    }
    if (diff_day < 0 && diff_sec > 0) {
        diff_day++;
        diff_sec -= SECS_PER_DAY;
    }

    if (pday)
        *pday = (int)diff_day;
    if (psec)
        *psec = diff_sec;

    return 1;

}

/* Convert tm structure and offset into julian day and seconds */
static int julian_adj(const struct tm *tm, int off_day, long offset_sec,
                      long *pday, int *psec)
{
    int offset_hms, offset_day;
    long time_jd;
    int time_year, time_month, time_day;
    /* split offset into days and day seconds */
    offset_day = offset_sec / SECS_PER_DAY;
    /* Avoid sign issues with % operator */
    offset_hms = offset_sec - (offset_day * SECS_PER_DAY);
    offset_day += off_day;
    /* Add current time seconds to offset */
    offset_hms += tm->tm_hour * 3600 + tm->tm_min * 60 + tm->tm_sec;
    /* Adjust day seconds if overflow */
    if (offset_hms >= SECS_PER_DAY) {
        offset_day++;
        offset_hms -= SECS_PER_DAY;
    } else if (offset_hms < 0) {
        offset_day--;
        offset_hms += SECS_PER_DAY;
    }

    /*
     * Convert date of time structure into a Julian day number.
     */

    time_year = tm->tm_year + 1900;
    time_month = tm->tm_mon + 1;
    time_day = tm->tm_mday;

    time_jd = date_to_julian(time_year, time_month, time_day);

    /* Work out Julian day of new date */
    time_jd += offset_day;

    if (time_jd < 0)
        return 0;

    *pday = time_jd;
    *psec = offset_hms;
    return 1;
}

/*
 * Convert date to and from julian day Uses Fliegel & Van Flandern algorithm
 */
static long date_to_julian(int y, int m, int d)
{
    return (1461 * (y + 4800 + (m - 14) / 12)) / 4 +
        (367 * (m - 2 - 12 * ((m - 14) / 12))) / 12 -
        (3 * ((y + 4900 + (m - 14) / 12) / 100)) / 4 + d - 32075;
}

static void julian_to_date(long jd, int *y, int *m, int *d)
{
    long L = jd + 68569;
    long n = (4 * L) / 146097;
    long i, j;

    L = L - (146097 * n + 3) / 4;
    i = (4000 * (L + 1)) / 1461001;
    L = L - (1461 * i) / 4 + 31;
    j = (80 * L) / 2447;
    *d = L - (2447 * j) / 80;
    L = j / 11;
    *m = j + 2 - (12 * L);
    *y = 100 * (n - 49) + i + L;
}

#ifdef OPENSSL_TIME_TEST

# include <stdio.h>

/*
 * Time checking test code. Check times are identical for a wide range of
 * offsets. This should be run on a machine with 64 bit time_t or it will
 * trigger the very errors the routines fix.
 */

int main(int argc, char **argv)
{
    long offset;
    for (offset = 0; offset < 1000000; offset++) {
        check_time(offset);
        check_time(-offset);
        check_time(offset * 1000);
        check_time(-offset * 1000);
    }
}

int check_time(long offset)
{
    struct tm tm1, tm2, o1;
    int off_day, off_sec;
    long toffset;
    time_t t1, t2;
    time(&t1);
    t2 = t1 + offset;
    OPENSSL_gmtime(&t2, &tm2);
    OPENSSL_gmtime(&t1, &tm1);
    o1 = tm1;
    OPENSSL_gmtime_adj(&tm1, 0, offset);
    if ((tm1.tm_year != tm2.tm_year) ||
        (tm1.tm_mon != tm2.tm_mon) ||
        (tm1.tm_mday != tm2.tm_mday) ||
        (tm1.tm_hour != tm2.tm_hour) ||
        (tm1.tm_min != tm2.tm_min) || (tm1.tm_sec != tm2.tm_sec)) {
        fprintf(stderr, "TIME ERROR!!\n");
        fprintf(stderr, "Time1: %d/%d/%d, %d:%02d:%02d\n",
                tm2.tm_mday, tm2.tm_mon + 1, tm2.tm_year + 1900,
                tm2.tm_hour, tm2.tm_min, tm2.tm_sec);
        fprintf(stderr, "Time2: %d/%d/%d, %d:%02d:%02d\n",
                tm1.tm_mday, tm1.tm_mon + 1, tm1.tm_year + 1900,
                tm1.tm_hour, tm1.tm_min, tm1.tm_sec);
        return 0;
    }
    OPENSSL_gmtime_diff(&o1, &tm1, &off_day, &off_sec);
    toffset = (long)off_day *SECS_PER_DAY + off_sec;
    if (offset != toffset) {
        fprintf(stderr, "TIME OFFSET ERROR!!\n");
        fprintf(stderr, "Expected %ld, Got %ld (%d:%d)\n",
                offset, toffset, off_day, off_sec);
        return 0;
    }
    return 1;
}

#endif
