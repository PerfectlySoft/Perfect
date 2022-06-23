/* dso_beos.c */
/*
 * Written by Marcin Konicki (ahwayakchih@neoni.net) for the OpenSSL project
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
#include <string.h>
#include "cryptlib.h"
#include "dso.h"

#if !defined(OPENSSL_SYS_BEOS)
DSO_METHOD *DSO_METHOD_beos(void)
{
    return NULL;
}
#else

# include <kernel/image.h>

static int beos_load(DSO *dso);
static int beos_unload(DSO *dso);
static void *beos_bind_var(DSO *dso, const char *symname);
static DSO_FUNC_TYPE beos_bind_func(DSO *dso, const char *symname);
# if 0
static int beos_unbind_var(DSO *dso, char *symname, void *symptr);
static int beos_unbind_func(DSO *dso, char *symname, DSO_FUNC_TYPE symptr);
static int beos_init(DSO *dso);
static int beos_finish(DSO *dso);
static long beos_ctrl(DSO *dso, int cmd, long larg, void *parg);
# endif
static char *beos_name_converter(DSO *dso, const char *filename);

static DSO_METHOD dso_meth_beos = {
    "OpenSSL 'beos' shared library method",
    beos_load,
    beos_unload,
    beos_bind_var,
    beos_bind_func,
/* For now, "unbind" doesn't exist */
# if 0
    NULL,                       /* unbind_var */
    NULL,                       /* unbind_func */
# endif
    NULL,                       /* ctrl */
    beos_name_converter,
    NULL,                       /* init */
    NULL                        /* finish */
};

DSO_METHOD *DSO_METHOD_beos(void)
{
    return (&dso_meth_beos);
}

/*
 * For this DSO_METHOD, our meth_data STACK will contain; (i) a pointer to
 * the handle (image_id) returned from load_add_on().
 */

static int beos_load(DSO *dso)
{
    image_id id;
    /* See applicable comments from dso_dl.c */
    char *filename = DSO_convert_filename(dso, NULL);

    if (filename == NULL) {
        DSOerr(DSO_F_BEOS_LOAD, DSO_R_NO_FILENAME);
        goto err;
    }
    id = load_add_on(filename);
    if (id < 1) {
        DSOerr(DSO_F_BEOS_LOAD, DSO_R_LOAD_FAILED);
        ERR_add_error_data(3, "filename(", filename, ")");
        goto err;
    }
    if (!sk_push(dso->meth_data, (char *)id)) {
        DSOerr(DSO_F_BEOS_LOAD, DSO_R_STACK_ERROR);
        goto err;
    }
    /* Success */
    dso->loaded_filename = filename;
    return (1);
 err:
    /* Cleanup ! */
    if (filename != NULL)
        OPENSSL_free(filename);
    if (id > 0)
        unload_add_on(id);
    return (0);
}

static int beos_unload(DSO *dso)
{
    image_id id;
    if (dso == NULL) {
        DSOerr(DSO_F_BEOS_UNLOAD, ERR_R_PASSED_NULL_PARAMETER);
        return (0);
    }
    if (sk_num(dso->meth_data) < 1)
        return (1);
    id = (image_id) sk_pop(dso->meth_data);
    if (id < 1) {
        DSOerr(DSO_F_BEOS_UNLOAD, DSO_R_NULL_HANDLE);
        return (0);
    }
    if (unload_add_on(id) != B_OK) {
        DSOerr(DSO_F_BEOS_UNLOAD, DSO_R_UNLOAD_FAILED);
        /*
         * We should push the value back onto the stack in case of a retry.
         */
        sk_push(dso->meth_data, (char *)id);
        return (0);
    }
    return (1);
}

static void *beos_bind_var(DSO *dso, const char *symname)
{
    image_id id;
    void *sym;

    if ((dso == NULL) || (symname == NULL)) {
        DSOerr(DSO_F_BEOS_BIND_VAR, ERR_R_PASSED_NULL_PARAMETER);
        return (NULL);
    }
    if (sk_num(dso->meth_data) < 1) {
        DSOerr(DSO_F_BEOS_BIND_VAR, DSO_R_STACK_ERROR);
        return (NULL);
    }
    id = (image_id) sk_value(dso->meth_data, sk_num(dso->meth_data) - 1);
    if (id < 1) {
        DSOerr(DSO_F_BEOS_BIND_VAR, DSO_R_NULL_HANDLE);
        return (NULL);
    }
    if (get_image_symbol(id, symname, B_SYMBOL_TYPE_DATA, &sym) != B_OK) {
        DSOerr(DSO_F_BEOS_BIND_VAR, DSO_R_SYM_FAILURE);
        ERR_add_error_data(3, "symname(", symname, ")");
        return (NULL);
    }
    return (sym);
}

static DSO_FUNC_TYPE beos_bind_func(DSO *dso, const char *symname)
{
    image_id id;
    void *sym;

    if ((dso == NULL) || (symname == NULL)) {
        DSOerr(DSO_F_BEOS_BIND_FUNC, ERR_R_PASSED_NULL_PARAMETER);
        return (NULL);
    }
    if (sk_num(dso->meth_data) < 1) {
        DSOerr(DSO_F_BEOS_BIND_FUNC, DSO_R_STACK_ERROR);
        return (NULL);
    }
    id = (image_id) sk_value(dso->meth_data, sk_num(dso->meth_data) - 1);
    if (id < 1) {
        DSOerr(DSO_F_BEOS_BIND_FUNC, DSO_R_NULL_HANDLE);
        return (NULL);
    }
    if (get_image_symbol(id, symname, B_SYMBOL_TYPE_TEXT, &sym) != B_OK) {
        DSOerr(DSO_F_BEOS_BIND_FUNC, DSO_R_SYM_FAILURE);
        ERR_add_error_data(3, "symname(", symname, ")");
        return (NULL);
    }
    return ((DSO_FUNC_TYPE)sym);
}

/* This one is the same as the one in dlfcn */
static char *beos_name_converter(DSO *dso, const char *filename)
{
    char *translated;
    int len, rsize, transform;

    len = strlen(filename);
    rsize = len + 1;
    transform = (strstr(filename, "/") == NULL);
    if (transform) {
        /* We will convert this to "%s.so" or "lib%s.so" */
        rsize += 3;             /* The length of ".so" */
        if ((DSO_flags(dso) & DSO_FLAG_NAME_TRANSLATION_EXT_ONLY) == 0)
            rsize += 3;         /* The length of "lib" */
    }
    translated = OPENSSL_malloc(rsize);
    if (translated == NULL) {
        DSOerr(DSO_F_BEOS_NAME_CONVERTER, DSO_R_NAME_TRANSLATION_FAILED);
        return (NULL);
    }
    if (transform) {
        if ((DSO_flags(dso) & DSO_FLAG_NAME_TRANSLATION_EXT_ONLY) == 0)
            sprintf(translated, "lib%s.so", filename);
        else
            sprintf(translated, "%s.so", filename);
    } else
        sprintf(translated, "%s", filename);
    return (translated);
}

#endif
/* dso_dl.c */
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
// #include "cryptlib.h"
// #include "dso.h"

#ifndef DSO_DL
DSO_METHOD *DSO_METHOD_dl(void)
{
    return NULL;
}
#else

# include <dl.h>

/* Part of the hack in "dl_load" ... */
# define DSO_MAX_TRANSLATED_SIZE 256

static int dl_load(DSO *dso);
static int dl_unload(DSO *dso);
static void *dl_bind_var(DSO *dso, const char *symname);
static DSO_FUNC_TYPE dl_bind_func(DSO *dso, const char *symname);
# if 0
static int dl_unbind_var(DSO *dso, char *symname, void *symptr);
static int dl_unbind_func(DSO *dso, char *symname, DSO_FUNC_TYPE symptr);
static int dl_init(DSO *dso);
static int dl_finish(DSO *dso);
static int dl_ctrl(DSO *dso, int cmd, long larg, void *parg);
# endif
static char *dl_name_converter(DSO *dso, const char *filename);
static char *dl_merger(DSO *dso, const char *filespec1,
                       const char *filespec2);
static int dl_pathbyaddr(void *addr, char *path, int sz);
static void *dl_globallookup(const char *name);

static DSO_METHOD dso_meth_dl = {
    "OpenSSL 'dl' shared library method",
    dl_load,
    dl_unload,
    dl_bind_var,
    dl_bind_func,
/* For now, "unbind" doesn't exist */
# if 0
    NULL,                       /* unbind_var */
    NULL,                       /* unbind_func */
# endif
    NULL,                       /* ctrl */
    dl_name_converter,
    dl_merger,
    NULL,                       /* init */
    NULL,                       /* finish */
    dl_pathbyaddr,
    dl_globallookup
};

DSO_METHOD *DSO_METHOD_dl(void)
{
    return (&dso_meth_dl);
}

/*
 * For this DSO_METHOD, our meth_data STACK will contain; (i) the handle
 * (shl_t) returned from shl_load(). NB: I checked on HPUX11 and shl_t is
 * itself a pointer type so the cast is safe.
 */

static int dl_load(DSO *dso)
{
    shl_t ptr = NULL;
    /*
     * We don't do any fancy retries or anything, just take the method's (or
     * DSO's if it has the callback set) best translation of the
     * platform-independant filename and try once with that.
     */
    char *filename = DSO_convert_filename(dso, NULL);

    if (filename == NULL) {
        DSOerr(DSO_F_DL_LOAD, DSO_R_NO_FILENAME);
        goto err;
    }
    ptr = shl_load(filename, BIND_IMMEDIATE |
                   (dso->flags & DSO_FLAG_NO_NAME_TRANSLATION ? 0 :
                    DYNAMIC_PATH), 0L);
    if (ptr == NULL) {
        DSOerr(DSO_F_DL_LOAD, DSO_R_LOAD_FAILED);
        ERR_add_error_data(4, "filename(", filename, "): ", strerror(errno));
        goto err;
    }
    if (!sk_push(dso->meth_data, (char *)ptr)) {
        DSOerr(DSO_F_DL_LOAD, DSO_R_STACK_ERROR);
        goto err;
    }
    /*
     * Success, stick the converted filename we've loaded under into the DSO
     * (it also serves as the indicator that we are currently loaded).
     */
    dso->loaded_filename = filename;
    return (1);
 err:
    /* Cleanup! */
    if (filename != NULL)
        OPENSSL_free(filename);
    if (ptr != NULL)
        shl_unload(ptr);
    return (0);
}

static int dl_unload(DSO *dso)
{
    shl_t ptr;
    if (dso == NULL) {
        DSOerr(DSO_F_DL_UNLOAD, ERR_R_PASSED_NULL_PARAMETER);
        return (0);
    }
    if (sk_num(dso->meth_data) < 1)
        return (1);
    /* Is this statement legal? */
    ptr = (shl_t) sk_pop(dso->meth_data);
    if (ptr == NULL) {
        DSOerr(DSO_F_DL_UNLOAD, DSO_R_NULL_HANDLE);
        /*
         * Should push the value back onto the stack in case of a retry.
         */
        sk_push(dso->meth_data, (char *)ptr);
        return (0);
    }
    shl_unload(ptr);
    return (1);
}

static void *dl_bind_var(DSO *dso, const char *symname)
{
    shl_t ptr;
    void *sym;

    if ((dso == NULL) || (symname == NULL)) {
        DSOerr(DSO_F_DL_BIND_VAR, ERR_R_PASSED_NULL_PARAMETER);
        return (NULL);
    }
    if (sk_num(dso->meth_data) < 1) {
        DSOerr(DSO_F_DL_BIND_VAR, DSO_R_STACK_ERROR);
        return (NULL);
    }
    ptr = (shl_t) sk_value(dso->meth_data, sk_num(dso->meth_data) - 1);
    if (ptr == NULL) {
        DSOerr(DSO_F_DL_BIND_VAR, DSO_R_NULL_HANDLE);
        return (NULL);
    }
    if (shl_findsym(&ptr, symname, TYPE_UNDEFINED, &sym) < 0) {
        DSOerr(DSO_F_DL_BIND_VAR, DSO_R_SYM_FAILURE);
        ERR_add_error_data(4, "symname(", symname, "): ", strerror(errno));
        return (NULL);
    }
    return (sym);
}

static DSO_FUNC_TYPE dl_bind_func(DSO *dso, const char *symname)
{
    shl_t ptr;
    void *sym;

    if ((dso == NULL) || (symname == NULL)) {
        DSOerr(DSO_F_DL_BIND_FUNC, ERR_R_PASSED_NULL_PARAMETER);
        return (NULL);
    }
    if (sk_num(dso->meth_data) < 1) {
        DSOerr(DSO_F_DL_BIND_FUNC, DSO_R_STACK_ERROR);
        return (NULL);
    }
    ptr = (shl_t) sk_value(dso->meth_data, sk_num(dso->meth_data) - 1);
    if (ptr == NULL) {
        DSOerr(DSO_F_DL_BIND_FUNC, DSO_R_NULL_HANDLE);
        return (NULL);
    }
    if (shl_findsym(&ptr, symname, TYPE_UNDEFINED, &sym) < 0) {
        DSOerr(DSO_F_DL_BIND_FUNC, DSO_R_SYM_FAILURE);
        ERR_add_error_data(4, "symname(", symname, "): ", strerror(errno));
        return (NULL);
    }
    return ((DSO_FUNC_TYPE)sym);
}

static char *dl_merger(DSO *dso, const char *filespec1, const char *filespec2)
{
    char *merged;

    if (!filespec1 && !filespec2) {
        DSOerr(DSO_F_DL_MERGER, ERR_R_PASSED_NULL_PARAMETER);
        return (NULL);
    }
    /*
     * If the first file specification is a rooted path, it rules. same goes
     * if the second file specification is missing.
     */
    if (!filespec2 || filespec1[0] == '/') {
        merged = OPENSSL_malloc(strlen(filespec1) + 1);
        if (!merged) {
            DSOerr(DSO_F_DL_MERGER, ERR_R_MALLOC_FAILURE);
            return (NULL);
        }
        strcpy(merged, filespec1);
    }
    /*
     * If the first file specification is missing, the second one rules.
     */
    else if (!filespec1) {
        merged = OPENSSL_malloc(strlen(filespec2) + 1);
        if (!merged) {
            DSOerr(DSO_F_DL_MERGER, ERR_R_MALLOC_FAILURE);
            return (NULL);
        }
        strcpy(merged, filespec2);
    } else
        /*
         * This part isn't as trivial as it looks.  It assumes that the
         * second file specification really is a directory, and makes no
         * checks whatsoever.  Therefore, the result becomes the
         * concatenation of filespec2 followed by a slash followed by
         * filespec1.
         */
    {
        int spec2len, len;

        spec2len = (filespec2 ? strlen(filespec2) : 0);
        len = spec2len + (filespec1 ? strlen(filespec1) : 0);

        if (filespec2 && filespec2[spec2len - 1] == '/') {
            spec2len--;
            len--;
        }
        merged = OPENSSL_malloc(len + 2);
        if (!merged) {
            DSOerr(DSO_F_DL_MERGER, ERR_R_MALLOC_FAILURE);
            return (NULL);
        }
        strcpy(merged, filespec2);
        merged[spec2len] = '/';
        strcpy(&merged[spec2len + 1], filespec1);
    }
    return (merged);
}

/*
 * This function is identical to the one in dso_dlfcn.c, but as it is highly
 * unlikely that both the "dl" *and* "dlfcn" variants are being compiled at
 * the same time, there's no great duplicating the code. Figuring out an
 * elegant way to share one copy of the code would be more difficult and
 * would not leave the implementations independant.
 */
# if defined(__hpux)
static const char extension[] = ".sl";
# else
static const char extension[] = ".so";
# endif
static char *dl_name_converter(DSO *dso, const char *filename)
{
    char *translated;
    int len, rsize, transform;

    len = strlen(filename);
    rsize = len + 1;
    transform = (strstr(filename, "/") == NULL);
    {
        /* We will convert this to "%s.s?" or "lib%s.s?" */
        rsize += strlen(extension); /* The length of ".s?" */
        if ((DSO_flags(dso) & DSO_FLAG_NAME_TRANSLATION_EXT_ONLY) == 0)
            rsize += 3;         /* The length of "lib" */
    }
    translated = OPENSSL_malloc(rsize);
    if (translated == NULL) {
        DSOerr(DSO_F_DL_NAME_CONVERTER, DSO_R_NAME_TRANSLATION_FAILED);
        return (NULL);
    }
    if (transform) {
        if ((DSO_flags(dso) & DSO_FLAG_NAME_TRANSLATION_EXT_ONLY) == 0)
            sprintf(translated, "lib%s%s", filename, extension);
        else
            sprintf(translated, "%s%s", filename, extension);
    } else
        sprintf(translated, "%s", filename);
    return (translated);
}

static int dl_pathbyaddr(void *addr, char *path, int sz)
{
    struct shl_descriptor inf;
    int i, len;

    if (addr == NULL) {
        union {
            int (*f) (void *, char *, int);
            void *p;
        } t = {
            dl_pathbyaddr
        };
        addr = t.p;
    }

    for (i = -1; shl_get_r(i, &inf) == 0; i++) {
        if (((size_t)addr >= inf.tstart && (size_t)addr < inf.tend) ||
            ((size_t)addr >= inf.dstart && (size_t)addr < inf.dend)) {
            len = (int)strlen(inf.filename);
            if (sz <= 0)
                return len + 1;
            if (len >= sz)
                len = sz - 1;
            memcpy(path, inf.filename, len);
            path[len++] = 0;
            return len;
        }
    }

    return -1;
}

static void *dl_globallookup(const char *name)
{
    void *ret;
    shl_t h = NULL;

    return shl_findsym(&h, name, TYPE_UNDEFINED, &ret) ? NULL : ret;
}
#endif                          /* DSO_DL */
/* dso_dlfcn.c */
/*
 * Written by Geoff Thorpe (geoff@geoffthorpe.net) for the OpenSSL project
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

/*
 * We need to do this early, because stdio.h includes the header files that
 * handle _GNU_SOURCE and other similar macros.  Defining it later is simply
 * too late, because those headers are protected from re- inclusion.
 */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE            /* make sure dladdr is declared */
#endif

#include <stdio.h>
// #include "cryptlib.h"
// #include "dso.h"

#ifndef DSO_DLFCN
DSO_METHOD *DSO_METHOD_dlfcn(void)
{
    return NULL;
}
#else

# ifdef HAVE_DLFCN_H
#  ifdef __osf__
#   define __EXTENSIONS__
#  endif
#  include <dlfcn.h>
#  define HAVE_DLINFO 1
#  if defined(_AIX) || defined(__CYGWIN__) || \
     defined(__SCO_VERSION__) || defined(_SCO_ELF) || \
     (defined(__osf__) && !defined(RTLD_NEXT))     || \
     (defined(__OpenBSD__) && !defined(RTLD_SELF)) || \
        defined(__ANDROID__)
#   undef HAVE_DLINFO
#  endif
# endif

/* Part of the hack in "dlfcn_load" ... */
# define DSO_MAX_TRANSLATED_SIZE 256

static int dlfcn_load(DSO *dso);
static int dlfcn_unload(DSO *dso);
static void *dlfcn_bind_var(DSO *dso, const char *symname);
static DSO_FUNC_TYPE dlfcn_bind_func(DSO *dso, const char *symname);
# if 0
static int dlfcn_unbind(DSO *dso, char *symname, void *symptr);
static int dlfcn_init(DSO *dso);
static int dlfcn_finish(DSO *dso);
static long dlfcn_ctrl(DSO *dso, int cmd, long larg, void *parg);
# endif
static char *dlfcn_name_converter(DSO *dso, const char *filename);
static char *dlfcn_merger(DSO *dso, const char *filespec1,
                          const char *filespec2);
static int dlfcn_pathbyaddr(void *addr, char *path, int sz);
static void *dlfcn_globallookup(const char *name);

static DSO_METHOD dso_meth_dlfcn = {
    "OpenSSL 'dlfcn' shared library method",
    dlfcn_load,
    dlfcn_unload,
    dlfcn_bind_var,
    dlfcn_bind_func,
/* For now, "unbind" doesn't exist */
# if 0
    NULL,                       /* unbind_var */
    NULL,                       /* unbind_func */
# endif
    NULL,                       /* ctrl */
    dlfcn_name_converter,
    dlfcn_merger,
    NULL,                       /* init */
    NULL,                       /* finish */
    dlfcn_pathbyaddr,
    dlfcn_globallookup
};

DSO_METHOD *DSO_METHOD_dlfcn(void)
{
    return (&dso_meth_dlfcn);
}

/*
 * Prior to using the dlopen() function, we should decide on the flag we
 * send. There's a few different ways of doing this and it's a messy
 * venn-diagram to match up which platforms support what. So as we don't have
 * autoconf yet, I'm implementing a hack that could be hacked further
 * relatively easily to deal with cases as we find them. Initially this is to
 * cope with OpenBSD.
 */
# if defined(__OpenBSD__) || defined(__NetBSD__)
#  ifdef DL_LAZY
#   define DLOPEN_FLAG DL_LAZY
#  else
#   ifdef RTLD_NOW
#    define DLOPEN_FLAG RTLD_NOW
#   else
#    define DLOPEN_FLAG 0
#   endif
#  endif
# else
#  ifdef OPENSSL_SYS_SUNOS
#   define DLOPEN_FLAG 1
#  else
#   define DLOPEN_FLAG RTLD_NOW /* Hope this works everywhere else */
#  endif
# endif

/*
 * For this DSO_METHOD, our meth_data STACK will contain; (i) the handle
 * (void*) returned from dlopen().
 */

static int dlfcn_load(DSO *dso)
{
    void *ptr = NULL;
    /* See applicable comments in dso_dl.c */
    char *filename = DSO_convert_filename(dso, NULL);
    int flags = DLOPEN_FLAG;

    if (filename == NULL) {
        DSOerr(DSO_F_DLFCN_LOAD, DSO_R_NO_FILENAME);
        goto err;
    }
# ifdef RTLD_GLOBAL
    if (dso->flags & DSO_FLAG_GLOBAL_SYMBOLS)
        flags |= RTLD_GLOBAL;
# endif
    ptr = dlopen(filename, flags);
    if (ptr == NULL) {
        DSOerr(DSO_F_DLFCN_LOAD, DSO_R_LOAD_FAILED);
        ERR_add_error_data(4, "filename(", filename, "): ", dlerror());
        goto err;
    }
    if (!sk_void_push(dso->meth_data, (char *)ptr)) {
        DSOerr(DSO_F_DLFCN_LOAD, DSO_R_STACK_ERROR);
        goto err;
    }
    /* Success */
    dso->loaded_filename = filename;
    return (1);
 err:
    /* Cleanup! */
    if (filename != NULL)
        OPENSSL_free(filename);
    if (ptr != NULL)
        dlclose(ptr);
    return (0);
}

static int dlfcn_unload(DSO *dso)
{
    void *ptr;
    if (dso == NULL) {
        DSOerr(DSO_F_DLFCN_UNLOAD, ERR_R_PASSED_NULL_PARAMETER);
        return (0);
    }
    if (sk_void_num(dso->meth_data) < 1)
        return (1);
    ptr = sk_void_pop(dso->meth_data);
    if (ptr == NULL) {
        DSOerr(DSO_F_DLFCN_UNLOAD, DSO_R_NULL_HANDLE);
        /*
         * Should push the value back onto the stack in case of a retry.
         */
        sk_void_push(dso->meth_data, ptr);
        return (0);
    }
    /* For now I'm not aware of any errors associated with dlclose() */
    dlclose(ptr);
    return (1);
}

static void *dlfcn_bind_var(DSO *dso, const char *symname)
{
    void *ptr, *sym;

    if ((dso == NULL) || (symname == NULL)) {
        DSOerr(DSO_F_DLFCN_BIND_VAR, ERR_R_PASSED_NULL_PARAMETER);
        return (NULL);
    }
    if (sk_void_num(dso->meth_data) < 1) {
        DSOerr(DSO_F_DLFCN_BIND_VAR, DSO_R_STACK_ERROR);
        return (NULL);
    }
    ptr = sk_void_value(dso->meth_data, sk_void_num(dso->meth_data) - 1);
    if (ptr == NULL) {
        DSOerr(DSO_F_DLFCN_BIND_VAR, DSO_R_NULL_HANDLE);
        return (NULL);
    }
    sym = dlsym(ptr, symname);
    if (sym == NULL) {
        DSOerr(DSO_F_DLFCN_BIND_VAR, DSO_R_SYM_FAILURE);
        ERR_add_error_data(4, "symname(", symname, "): ", dlerror());
        return (NULL);
    }
    return (sym);
}

static DSO_FUNC_TYPE dlfcn_bind_func(DSO *dso, const char *symname)
{
    void *ptr;
    union {
        DSO_FUNC_TYPE sym;
        void *dlret;
    } u;

    if ((dso == NULL) || (symname == NULL)) {
        DSOerr(DSO_F_DLFCN_BIND_FUNC, ERR_R_PASSED_NULL_PARAMETER);
        return (NULL);
    }
    if (sk_void_num(dso->meth_data) < 1) {
        DSOerr(DSO_F_DLFCN_BIND_FUNC, DSO_R_STACK_ERROR);
        return (NULL);
    }
    ptr = sk_void_value(dso->meth_data, sk_void_num(dso->meth_data) - 1);
    if (ptr == NULL) {
        DSOerr(DSO_F_DLFCN_BIND_FUNC, DSO_R_NULL_HANDLE);
        return (NULL);
    }
    u.dlret = dlsym(ptr, symname);
    if (u.dlret == NULL) {
        DSOerr(DSO_F_DLFCN_BIND_FUNC, DSO_R_SYM_FAILURE);
        ERR_add_error_data(4, "symname(", symname, "): ", dlerror());
        return (NULL);
    }
    return u.sym;
}

static char *dlfcn_merger(DSO *dso, const char *filespec1,
                          const char *filespec2)
{
    char *merged;

    if (!filespec1 && !filespec2) {
        DSOerr(DSO_F_DLFCN_MERGER, ERR_R_PASSED_NULL_PARAMETER);
        return (NULL);
    }
    /*
     * If the first file specification is a rooted path, it rules. same goes
     * if the second file specification is missing.
     */
    if (!filespec2 || (filespec1 != NULL && filespec1[0] == '/')) {
        merged = OPENSSL_malloc(strlen(filespec1) + 1);
        if (!merged) {
            DSOerr(DSO_F_DLFCN_MERGER, ERR_R_MALLOC_FAILURE);
            return (NULL);
        }
        strcpy(merged, filespec1);
    }
    /*
     * If the first file specification is missing, the second one rules.
     */
    else if (!filespec1) {
        merged = OPENSSL_malloc(strlen(filespec2) + 1);
        if (!merged) {
            DSOerr(DSO_F_DLFCN_MERGER, ERR_R_MALLOC_FAILURE);
            return (NULL);
        }
        strcpy(merged, filespec2);
    } else {
        /*
         * This part isn't as trivial as it looks.  It assumes that the
         * second file specification really is a directory, and makes no
         * checks whatsoever.  Therefore, the result becomes the
         * concatenation of filespec2 followed by a slash followed by
         * filespec1.
         */
        int spec2len, len;

        spec2len = strlen(filespec2);
        len = spec2len + strlen(filespec1);

        if (spec2len && filespec2[spec2len - 1] == '/') {
            spec2len--;
            len--;
        }
        merged = OPENSSL_malloc(len + 2);
        if (!merged) {
            DSOerr(DSO_F_DLFCN_MERGER, ERR_R_MALLOC_FAILURE);
            return (NULL);
        }
        strcpy(merged, filespec2);
        merged[spec2len] = '/';
        strcpy(&merged[spec2len + 1], filespec1);
    }
    return (merged);
}

# ifdef OPENSSL_SYS_MACOSX
#  define DSO_ext ".dylib"
#  define DSO_extlen 6
# else
#  define DSO_ext ".so"
#  define DSO_extlen 3
# endif

static char *dlfcn_name_converter(DSO *dso, const char *filename)
{
    char *translated;
    int len, rsize, transform;

    len = strlen(filename);
    rsize = len + 1;
    transform = (strstr(filename, "/") == NULL);
    if (transform) {
        /* We will convert this to "%s.so" or "lib%s.so" etc */
        rsize += DSO_extlen;    /* The length of ".so" */
        if ((DSO_flags(dso) & DSO_FLAG_NAME_TRANSLATION_EXT_ONLY) == 0)
            rsize += 3;         /* The length of "lib" */
    }
    translated = OPENSSL_malloc(rsize);
    if (translated == NULL) {
        DSOerr(DSO_F_DLFCN_NAME_CONVERTER, DSO_R_NAME_TRANSLATION_FAILED);
        return (NULL);
    }
    if (transform) {
        if ((DSO_flags(dso) & DSO_FLAG_NAME_TRANSLATION_EXT_ONLY) == 0)
            sprintf(translated, "lib%s" DSO_ext, filename);
        else
            sprintf(translated, "%s" DSO_ext, filename);
    } else
        sprintf(translated, "%s", filename);
    return (translated);
}

# ifdef __sgi
/*-
This is a quote from IRIX manual for dladdr(3c):

     <dlfcn.h> does not contain a prototype for dladdr or definition of
     Dl_info.  The #include <dlfcn.h>  in the SYNOPSIS line is traditional,
     but contains no dladdr prototype and no IRIX library contains an
     implementation.  Write your own declaration based on the code below.

     The following code is dependent on internal interfaces that are not
     part of the IRIX compatibility guarantee; however, there is no future
     intention to change this interface, so on a practical level, the code
     below is safe to use on IRIX.
*/
#  include <rld_interface.h>
#  ifndef _RLD_INTERFACE_DLFCN_H_DLADDR
#   define _RLD_INTERFACE_DLFCN_H_DLADDR
typedef struct Dl_info {
    const char *dli_fname;
    void *dli_fbase;
    const char *dli_sname;
    void *dli_saddr;
    int dli_version;
    int dli_reserved1;
    long dli_reserved[4];
} Dl_info;
#  else
typedef struct Dl_info Dl_info;
#  endif
#  define _RLD_DLADDR             14

static int dladdr(void *address, Dl_info *dl)
{
    void *v;
    v = _rld_new_interface(_RLD_DLADDR, address, dl);
    return (int)v;
}
# endif                         /* __sgi */

static int dlfcn_pathbyaddr(void *addr, char *path, int sz)
{
# ifdef HAVE_DLINFO
    Dl_info dli;
    int len;

    if (addr == NULL) {
        union {
            int (*f) (void *, char *, int);
            void *p;
        } t = {
            dlfcn_pathbyaddr
        };
        addr = t.p;
    }

    if (dladdr(addr, &dli)) {
        len = (int)strlen(dli.dli_fname);
        if (sz <= 0)
            return len + 1;
        if (len >= sz)
            len = sz - 1;
        memcpy(path, dli.dli_fname, len);
        path[len++] = 0;
        return len;
    }

    ERR_add_error_data(2, "dlfcn_pathbyaddr(): ", dlerror());
# endif
    return -1;
}

static void *dlfcn_globallookup(const char *name)
{
    void *ret = NULL, *handle = dlopen(NULL, RTLD_LAZY);

    if (handle) {
        ret = dlsym(handle, name);
        dlclose(handle);
    }

    return ret;
}
#endif                          /* DSO_DLFCN */
/* crypto/dso/dso_err.c */
/* ====================================================================
 * Copyright (c) 1999-2006 The OpenSSL Project.  All rights reserved.
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
// #include "dso.h"

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

# define ERR_FUNC(func) ERR_PACK(ERR_LIB_DSO,func,0)
# define ERR_REASON(reason) ERR_PACK(ERR_LIB_DSO,0,reason)

static ERR_STRING_DATA DSO_str_functs[] = {
    {ERR_FUNC(DSO_F_BEOS_BIND_FUNC), "BEOS_BIND_FUNC"},
    {ERR_FUNC(DSO_F_BEOS_BIND_VAR), "BEOS_BIND_VAR"},
    {ERR_FUNC(DSO_F_BEOS_LOAD), "BEOS_LOAD"},
    {ERR_FUNC(DSO_F_BEOS_NAME_CONVERTER), "BEOS_NAME_CONVERTER"},
    {ERR_FUNC(DSO_F_BEOS_UNLOAD), "BEOS_UNLOAD"},
    {ERR_FUNC(DSO_F_DLFCN_BIND_FUNC), "DLFCN_BIND_FUNC"},
    {ERR_FUNC(DSO_F_DLFCN_BIND_VAR), "DLFCN_BIND_VAR"},
    {ERR_FUNC(DSO_F_DLFCN_LOAD), "DLFCN_LOAD"},
    {ERR_FUNC(DSO_F_DLFCN_MERGER), "DLFCN_MERGER"},
    {ERR_FUNC(DSO_F_DLFCN_NAME_CONVERTER), "DLFCN_NAME_CONVERTER"},
    {ERR_FUNC(DSO_F_DLFCN_UNLOAD), "DLFCN_UNLOAD"},
    {ERR_FUNC(DSO_F_DL_BIND_FUNC), "DL_BIND_FUNC"},
    {ERR_FUNC(DSO_F_DL_BIND_VAR), "DL_BIND_VAR"},
    {ERR_FUNC(DSO_F_DL_LOAD), "DL_LOAD"},
    {ERR_FUNC(DSO_F_DL_MERGER), "DL_MERGER"},
    {ERR_FUNC(DSO_F_DL_NAME_CONVERTER), "DL_NAME_CONVERTER"},
    {ERR_FUNC(DSO_F_DL_UNLOAD), "DL_UNLOAD"},
    {ERR_FUNC(DSO_F_DSO_BIND_FUNC), "DSO_bind_func"},
    {ERR_FUNC(DSO_F_DSO_BIND_VAR), "DSO_bind_var"},
    {ERR_FUNC(DSO_F_DSO_CONVERT_FILENAME), "DSO_convert_filename"},
    {ERR_FUNC(DSO_F_DSO_CTRL), "DSO_ctrl"},
    {ERR_FUNC(DSO_F_DSO_FREE), "DSO_free"},
    {ERR_FUNC(DSO_F_DSO_GET_FILENAME), "DSO_get_filename"},
    {ERR_FUNC(DSO_F_DSO_GET_LOADED_FILENAME), "DSO_get_loaded_filename"},
    {ERR_FUNC(DSO_F_DSO_GLOBAL_LOOKUP), "DSO_global_lookup"},
    {ERR_FUNC(DSO_F_DSO_LOAD), "DSO_load"},
    {ERR_FUNC(DSO_F_DSO_MERGE), "DSO_merge"},
    {ERR_FUNC(DSO_F_DSO_NEW_METHOD), "DSO_new_method"},
    {ERR_FUNC(DSO_F_DSO_PATHBYADDR), "DSO_pathbyaddr"},
    {ERR_FUNC(DSO_F_DSO_SET_FILENAME), "DSO_set_filename"},
    {ERR_FUNC(DSO_F_DSO_SET_NAME_CONVERTER), "DSO_set_name_converter"},
    {ERR_FUNC(DSO_F_DSO_UP_REF), "DSO_up_ref"},
    {ERR_FUNC(DSO_F_GLOBAL_LOOKUP_FUNC), "GLOBAL_LOOKUP_FUNC"},
    {ERR_FUNC(DSO_F_PATHBYADDR), "PATHBYADDR"},
    {ERR_FUNC(DSO_F_VMS_BIND_SYM), "VMS_BIND_SYM"},
    {ERR_FUNC(DSO_F_VMS_LOAD), "VMS_LOAD"},
    {ERR_FUNC(DSO_F_VMS_MERGER), "VMS_MERGER"},
    {ERR_FUNC(DSO_F_VMS_UNLOAD), "VMS_UNLOAD"},
    {ERR_FUNC(DSO_F_WIN32_BIND_FUNC), "WIN32_BIND_FUNC"},
    {ERR_FUNC(DSO_F_WIN32_BIND_VAR), "WIN32_BIND_VAR"},
    {ERR_FUNC(DSO_F_WIN32_GLOBALLOOKUP), "WIN32_GLOBALLOOKUP"},
    {ERR_FUNC(DSO_F_WIN32_GLOBALLOOKUP_FUNC), "WIN32_GLOBALLOOKUP_FUNC"},
    {ERR_FUNC(DSO_F_WIN32_JOINER), "WIN32_JOINER"},
    {ERR_FUNC(DSO_F_WIN32_LOAD), "WIN32_LOAD"},
    {ERR_FUNC(DSO_F_WIN32_MERGER), "WIN32_MERGER"},
    {ERR_FUNC(DSO_F_WIN32_NAME_CONVERTER), "WIN32_NAME_CONVERTER"},
    {ERR_FUNC(DSO_F_WIN32_PATHBYADDR), "WIN32_PATHBYADDR"},
    {ERR_FUNC(DSO_F_WIN32_SPLITTER), "WIN32_SPLITTER"},
    {ERR_FUNC(DSO_F_WIN32_UNLOAD), "WIN32_UNLOAD"},
    {0, NULL}
};

static ERR_STRING_DATA DSO_str_reasons[] = {
    {ERR_REASON(DSO_R_CTRL_FAILED), "control command failed"},
    {ERR_REASON(DSO_R_DSO_ALREADY_LOADED), "dso already loaded"},
    {ERR_REASON(DSO_R_EMPTY_FILE_STRUCTURE), "empty file structure"},
    {ERR_REASON(DSO_R_FAILURE), "failure"},
    {ERR_REASON(DSO_R_FILENAME_TOO_BIG), "filename too big"},
    {ERR_REASON(DSO_R_FINISH_FAILED), "cleanup method function failed"},
    {ERR_REASON(DSO_R_INCORRECT_FILE_SYNTAX), "incorrect file syntax"},
    {ERR_REASON(DSO_R_LOAD_FAILED), "could not load the shared library"},
    {ERR_REASON(DSO_R_NAME_TRANSLATION_FAILED), "name translation failed"},
    {ERR_REASON(DSO_R_NO_FILENAME), "no filename"},
    {ERR_REASON(DSO_R_NO_FILE_SPECIFICATION), "no file specification"},
    {ERR_REASON(DSO_R_NULL_HANDLE), "a null shared library handle was used"},
    {ERR_REASON(DSO_R_SET_FILENAME_FAILED), "set filename failed"},
    {ERR_REASON(DSO_R_STACK_ERROR), "the meth_data stack is corrupt"},
    {ERR_REASON(DSO_R_SYM_FAILURE),
     "could not bind to the requested symbol name"},
    {ERR_REASON(DSO_R_UNLOAD_FAILED), "could not unload the shared library"},
    {ERR_REASON(DSO_R_UNSUPPORTED), "functionality not supported"},
    {0, NULL}
};

#endif

void ERR_load_DSO_strings(void)
{
#ifndef OPENSSL_NO_ERR

    if (ERR_func_error_string(DSO_str_functs[0].error) == NULL) {
        ERR_load_strings(0, DSO_str_functs);
        ERR_load_strings(0, DSO_str_reasons);
    }
#endif
}
/* dso_lib.c */
/*
 * Written by Geoff Thorpe (geoff@geoffthorpe.net) for the OpenSSL project
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
// #include "cryptlib.h"
// #include "dso.h"

static DSO_METHOD *default_DSO_meth = NULL;

DSO *DSO_new(void)
{
    return (DSO_new_method(NULL));
}

void DSO_set_default_method(DSO_METHOD *meth)
{
    default_DSO_meth = meth;
}

DSO_METHOD *DSO_get_default_method(void)
{
    return (default_DSO_meth);
}

DSO_METHOD *DSO_get_method(DSO *dso)
{
    return (dso->meth);
}

DSO_METHOD *DSO_set_method(DSO *dso, DSO_METHOD *meth)
{
    DSO_METHOD *mtmp;
    mtmp = dso->meth;
    dso->meth = meth;
    return (mtmp);
}

DSO *DSO_new_method(DSO_METHOD *meth)
{
    DSO *ret;

    if (default_DSO_meth == NULL)
        /*
         * We default to DSO_METH_openssl() which in turn defaults to
         * stealing the "best available" method. Will fallback to
         * DSO_METH_null() in the worst case.
         */
        default_DSO_meth = DSO_METHOD_openssl();
    ret = (DSO *)OPENSSL_malloc(sizeof(DSO));
    if (ret == NULL) {
        DSOerr(DSO_F_DSO_NEW_METHOD, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }
    memset(ret, 0, sizeof(DSO));
    ret->meth_data = sk_void_new_null();
    if (ret->meth_data == NULL) {
        /* sk_new doesn't generate any errors so we do */
        DSOerr(DSO_F_DSO_NEW_METHOD, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(ret);
        return (NULL);
    }
    if (meth == NULL)
        ret->meth = default_DSO_meth;
    else
        ret->meth = meth;
    ret->references = 1;
    if ((ret->meth->init != NULL) && !ret->meth->init(ret)) {
        sk_void_free(ret->meth_data);
        OPENSSL_free(ret);
        ret = NULL;
    }
    return (ret);
}

int DSO_free(DSO *dso)
{
    int i;

    if (dso == NULL) {
        DSOerr(DSO_F_DSO_FREE, ERR_R_PASSED_NULL_PARAMETER);
        return (0);
    }

    i = CRYPTO_add(&dso->references, -1, CRYPTO_LOCK_DSO);
#ifdef REF_PRINT
    REF_PRINT("DSO", dso);
#endif
    if (i > 0)
        return (1);
#ifdef REF_CHECK
    if (i < 0) {
        fprintf(stderr, "DSO_free, bad reference count\n");
        abort();
    }
#endif

    if ((dso->meth->dso_unload != NULL) && !dso->meth->dso_unload(dso)) {
        DSOerr(DSO_F_DSO_FREE, DSO_R_UNLOAD_FAILED);
        return (0);
    }

    if ((dso->meth->finish != NULL) && !dso->meth->finish(dso)) {
        DSOerr(DSO_F_DSO_FREE, DSO_R_FINISH_FAILED);
        return (0);
    }

    sk_void_free(dso->meth_data);
    if (dso->filename != NULL)
        OPENSSL_free(dso->filename);
    if (dso->loaded_filename != NULL)
        OPENSSL_free(dso->loaded_filename);

    OPENSSL_free(dso);
    return (1);
}

int DSO_flags(DSO *dso)
{
    return ((dso == NULL) ? 0 : dso->flags);
}

int DSO_up_ref(DSO *dso)
{
    if (dso == NULL) {
        DSOerr(DSO_F_DSO_UP_REF, ERR_R_PASSED_NULL_PARAMETER);
        return (0);
    }

    CRYPTO_add(&dso->references, 1, CRYPTO_LOCK_DSO);
    return (1);
}

DSO *DSO_load(DSO *dso, const char *filename, DSO_METHOD *meth, int flags)
{
    DSO *ret;
    int allocated = 0;

    if (dso == NULL) {
        ret = DSO_new_method(meth);
        if (ret == NULL) {
            DSOerr(DSO_F_DSO_LOAD, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        allocated = 1;
        /* Pass the provided flags to the new DSO object */
        if (DSO_ctrl(ret, DSO_CTRL_SET_FLAGS, flags, NULL) < 0) {
            DSOerr(DSO_F_DSO_LOAD, DSO_R_CTRL_FAILED);
            goto err;
        }
    } else
        ret = dso;
    /* Don't load if we're currently already loaded */
    if (ret->filename != NULL) {
        DSOerr(DSO_F_DSO_LOAD, DSO_R_DSO_ALREADY_LOADED);
        goto err;
    }
    /*
     * filename can only be NULL if we were passed a dso that already has one
     * set.
     */
    if (filename != NULL)
        if (!DSO_set_filename(ret, filename)) {
            DSOerr(DSO_F_DSO_LOAD, DSO_R_SET_FILENAME_FAILED);
            goto err;
        }
    filename = ret->filename;
    if (filename == NULL) {
        DSOerr(DSO_F_DSO_LOAD, DSO_R_NO_FILENAME);
        goto err;
    }
    if (ret->meth->dso_load == NULL) {
        DSOerr(DSO_F_DSO_LOAD, DSO_R_UNSUPPORTED);
        goto err;
    }
    if (!ret->meth->dso_load(ret)) {
        DSOerr(DSO_F_DSO_LOAD, DSO_R_LOAD_FAILED);
        goto err;
    }
    /* Load succeeded */
    return (ret);
 err:
    if (allocated)
        DSO_free(ret);
    return (NULL);
}

void *DSO_bind_var(DSO *dso, const char *symname)
{
    void *ret = NULL;

    if ((dso == NULL) || (symname == NULL)) {
        DSOerr(DSO_F_DSO_BIND_VAR, ERR_R_PASSED_NULL_PARAMETER);
        return (NULL);
    }
    if (dso->meth->dso_bind_var == NULL) {
        DSOerr(DSO_F_DSO_BIND_VAR, DSO_R_UNSUPPORTED);
        return (NULL);
    }
    if ((ret = dso->meth->dso_bind_var(dso, symname)) == NULL) {
        DSOerr(DSO_F_DSO_BIND_VAR, DSO_R_SYM_FAILURE);
        return (NULL);
    }
    /* Success */
    return (ret);
}

DSO_FUNC_TYPE DSO_bind_func(DSO *dso, const char *symname)
{
    DSO_FUNC_TYPE ret = NULL;

    if ((dso == NULL) || (symname == NULL)) {
        DSOerr(DSO_F_DSO_BIND_FUNC, ERR_R_PASSED_NULL_PARAMETER);
        return (NULL);
    }
    if (dso->meth->dso_bind_func == NULL) {
        DSOerr(DSO_F_DSO_BIND_FUNC, DSO_R_UNSUPPORTED);
        return (NULL);
    }
    if ((ret = dso->meth->dso_bind_func(dso, symname)) == NULL) {
        DSOerr(DSO_F_DSO_BIND_FUNC, DSO_R_SYM_FAILURE);
        return (NULL);
    }
    /* Success */
    return (ret);
}

/*
 * I don't really like these *_ctrl functions very much to be perfectly
 * honest. For one thing, I think I have to return a negative value for any
 * error because possible DSO_ctrl() commands may return values such as
 * "size"s that can legitimately be zero (making the standard
 * "if (DSO_cmd(...))" form that works almost everywhere else fail at odd
 * times. I'd prefer "output" values to be passed by reference and the return
 * value as success/failure like usual ... but we conform when we must... :-)
 */
long DSO_ctrl(DSO *dso, int cmd, long larg, void *parg)
{
    if (dso == NULL) {
        DSOerr(DSO_F_DSO_CTRL, ERR_R_PASSED_NULL_PARAMETER);
        return (-1);
    }
    /*
     * We should intercept certain generic commands and only pass control to
     * the method-specific ctrl() function if it's something we don't handle.
     */
    switch (cmd) {
    case DSO_CTRL_GET_FLAGS:
        return dso->flags;
    case DSO_CTRL_SET_FLAGS:
        dso->flags = (int)larg;
        return (0);
    case DSO_CTRL_OR_FLAGS:
        dso->flags |= (int)larg;
        return (0);
    default:
        break;
    }
    if ((dso->meth == NULL) || (dso->meth->dso_ctrl == NULL)) {
        DSOerr(DSO_F_DSO_CTRL, DSO_R_UNSUPPORTED);
        return (-1);
    }
    return (dso->meth->dso_ctrl(dso, cmd, larg, parg));
}

int DSO_set_name_converter(DSO *dso, DSO_NAME_CONVERTER_FUNC cb,
                           DSO_NAME_CONVERTER_FUNC *oldcb)
{
    if (dso == NULL) {
        DSOerr(DSO_F_DSO_SET_NAME_CONVERTER, ERR_R_PASSED_NULL_PARAMETER);
        return (0);
    }
    if (oldcb)
        *oldcb = dso->name_converter;
    dso->name_converter = cb;
    return (1);
}

const char *DSO_get_filename(DSO *dso)
{
    if (dso == NULL) {
        DSOerr(DSO_F_DSO_GET_FILENAME, ERR_R_PASSED_NULL_PARAMETER);
        return (NULL);
    }
    return (dso->filename);
}

int DSO_set_filename(DSO *dso, const char *filename)
{
    char *copied;

    if ((dso == NULL) || (filename == NULL)) {
        DSOerr(DSO_F_DSO_SET_FILENAME, ERR_R_PASSED_NULL_PARAMETER);
        return (0);
    }
    if (dso->loaded_filename) {
        DSOerr(DSO_F_DSO_SET_FILENAME, DSO_R_DSO_ALREADY_LOADED);
        return (0);
    }
    /* We'll duplicate filename */
    copied = OPENSSL_malloc(strlen(filename) + 1);
    if (copied == NULL) {
        DSOerr(DSO_F_DSO_SET_FILENAME, ERR_R_MALLOC_FAILURE);
        return (0);
    }
    BUF_strlcpy(copied, filename, strlen(filename) + 1);
    if (dso->filename)
        OPENSSL_free(dso->filename);
    dso->filename = copied;
    return (1);
}

char *DSO_merge(DSO *dso, const char *filespec1, const char *filespec2)
{
    char *result = NULL;

    if (dso == NULL || filespec1 == NULL) {
        DSOerr(DSO_F_DSO_MERGE, ERR_R_PASSED_NULL_PARAMETER);
        return (NULL);
    }
    if ((dso->flags & DSO_FLAG_NO_NAME_TRANSLATION) == 0) {
        if (dso->merger != NULL)
            result = dso->merger(dso, filespec1, filespec2);
        else if (dso->meth->dso_merger != NULL)
            result = dso->meth->dso_merger(dso, filespec1, filespec2);
    }
    return (result);
}

char *DSO_convert_filename(DSO *dso, const char *filename)
{
    char *result = NULL;

    if (dso == NULL) {
        DSOerr(DSO_F_DSO_CONVERT_FILENAME, ERR_R_PASSED_NULL_PARAMETER);
        return (NULL);
    }
    if (filename == NULL)
        filename = dso->filename;
    if (filename == NULL) {
        DSOerr(DSO_F_DSO_CONVERT_FILENAME, DSO_R_NO_FILENAME);
        return (NULL);
    }
    if ((dso->flags & DSO_FLAG_NO_NAME_TRANSLATION) == 0) {
        if (dso->name_converter != NULL)
            result = dso->name_converter(dso, filename);
        else if (dso->meth->dso_name_converter != NULL)
            result = dso->meth->dso_name_converter(dso, filename);
    }
    if (result == NULL) {
        result = OPENSSL_malloc(strlen(filename) + 1);
        if (result == NULL) {
            DSOerr(DSO_F_DSO_CONVERT_FILENAME, ERR_R_MALLOC_FAILURE);
            return (NULL);
        }
        BUF_strlcpy(result, filename, strlen(filename) + 1);
    }
    return (result);
}

const char *DSO_get_loaded_filename(DSO *dso)
{
    if (dso == NULL) {
        DSOerr(DSO_F_DSO_GET_LOADED_FILENAME, ERR_R_PASSED_NULL_PARAMETER);
        return (NULL);
    }
    return (dso->loaded_filename);
}

int DSO_pathbyaddr(void *addr, char *path, int sz)
{
    DSO_METHOD *meth = default_DSO_meth;
    if (meth == NULL)
        meth = DSO_METHOD_openssl();
    if (meth->pathbyaddr == NULL) {
        DSOerr(DSO_F_DSO_PATHBYADDR, DSO_R_UNSUPPORTED);
        return -1;
    }
    return (*meth->pathbyaddr) (addr, path, sz);
}

void *DSO_global_lookup(const char *name)
{
    DSO_METHOD *meth = default_DSO_meth;
    if (meth == NULL)
        meth = DSO_METHOD_openssl();
    if (meth->globallookup == NULL) {
        DSOerr(DSO_F_DSO_GLOBAL_LOOKUP, DSO_R_UNSUPPORTED);
        return NULL;
    }
    return (*meth->globallookup) (name);
}
/* dso_null.c */
/*
 * Written by Geoff Thorpe (geoff@geoffthorpe.net) for the OpenSSL project
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

/*
 * This "NULL" method is provided as the fallback for systems that have no
 * appropriate support for "shared-libraries".
 */

#include <stdio.h>
// #include "cryptlib.h"
// #include "dso.h"

static DSO_METHOD dso_meth_null = {
    "NULL shared library method",
    NULL,                       /* load */
    NULL,                       /* unload */
    NULL,                       /* bind_var */
    NULL,                       /* bind_func */
/* For now, "unbind" doesn't exist */
#if 0
    NULL,                       /* unbind_var */
    NULL,                       /* unbind_func */
#endif
    NULL,                       /* ctrl */
    NULL,                       /* dso_name_converter */
    NULL,                       /* dso_merger */
    NULL,                       /* init */
    NULL,                       /* finish */
    NULL,                       /* pathbyaddr */
    NULL                        /* globallookup */
};

DSO_METHOD *DSO_METHOD_null(void)
{
    return (&dso_meth_null);
}
/* dso_openssl.c */
/*
 * Written by Geoff Thorpe (geoff@geoffthorpe.net) for the OpenSSL project
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
// #include "cryptlib.h"
// #include "dso.h"

/* We just pinch the method from an appropriate "default" method. */

DSO_METHOD *DSO_METHOD_openssl(void)
{
#ifdef DEF_DSO_METHOD
    return (DEF_DSO_METHOD());
#elif defined(DSO_DLFCN)
    return (DSO_METHOD_dlfcn());
#elif defined(DSO_DL)
    return (DSO_METHOD_dl());
#elif defined(DSO_WIN32)
    return (DSO_METHOD_win32());
#elif defined(DSO_VMS)
    return (DSO_METHOD_vms());
#elif defined(DSO_BEOS)
    return (DSO_METHOD_beos());
#else
    return (DSO_METHOD_null());
#endif
}
/* dso_vms.c */
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
#include <string.h>
#include <errno.h>
// #include "cryptlib.h"
// #include "dso.h"

#ifndef OPENSSL_SYS_VMS
DSO_METHOD *DSO_METHOD_vms(void)
{
    return NULL;
}
#else

# pragma message disable DOLLARID
# include <rms.h>
# include <lib$routines.h>
# include <stsdef.h>
# include <descrip.h>
# include <starlet.h>
# include "vms_rms.h"

/* Some compiler options may mask the declaration of "_malloc32". */
# if __INITIAL_POINTER_SIZE && defined _ANSI_C_SOURCE
#  if __INITIAL_POINTER_SIZE == 64
#   pragma pointer_size save
#   pragma pointer_size 32
void *_malloc32(__size_t);
#   pragma pointer_size restore
#  endif                        /* __INITIAL_POINTER_SIZE == 64 */
# endif                         /* __INITIAL_POINTER_SIZE && defined
                                 * _ANSI_C_SOURCE */

# pragma message disable DOLLARID

static int vms_load(DSO *dso);
static int vms_unload(DSO *dso);
static void *vms_bind_var(DSO *dso, const char *symname);
static DSO_FUNC_TYPE vms_bind_func(DSO *dso, const char *symname);
# if 0
static int vms_unbind_var(DSO *dso, char *symname, void *symptr);
static int vms_unbind_func(DSO *dso, char *symname, DSO_FUNC_TYPE symptr);
static int vms_init(DSO *dso);
static int vms_finish(DSO *dso);
static long vms_ctrl(DSO *dso, int cmd, long larg, void *parg);
# endif
static char *vms_name_converter(DSO *dso, const char *filename);
static char *vms_merger(DSO *dso, const char *filespec1,
                        const char *filespec2);

static DSO_METHOD dso_meth_vms = {
    "OpenSSL 'VMS' shared library method",
    vms_load,
    NULL,                       /* unload */
    vms_bind_var,
    vms_bind_func,
/* For now, "unbind" doesn't exist */
# if 0
    NULL,                       /* unbind_var */
    NULL,                       /* unbind_func */
# endif
    NULL,                       /* ctrl */
    vms_name_converter,
    vms_merger,
    NULL,                       /* init */
    NULL                        /* finish */
};

/*
 * On VMS, the only "handle" is the file name.  LIB$FIND_IMAGE_SYMBOL depends
 * on the reference to the file name being the same for all calls regarding
 * one shared image, so we'll just store it in an instance of the following
 * structure and put a pointer to that instance in the meth_data stack.
 */
typedef struct dso_internal_st {
    /*
     * This should contain the name only, no directory, no extension, nothing
     * but a name.
     */
    struct dsc$descriptor_s filename_dsc;
    char filename[NAMX_MAXRSS + 1];
    /*
     * This contains whatever is not in filename, if needed. Normally not
     * defined.
     */
    struct dsc$descriptor_s imagename_dsc;
    char imagename[NAMX_MAXRSS + 1];
} DSO_VMS_INTERNAL;

DSO_METHOD *DSO_METHOD_vms(void)
{
    return (&dso_meth_vms);
}

static int vms_load(DSO *dso)
{
    void *ptr = NULL;
    /* See applicable comments in dso_dl.c */
    char *filename = DSO_convert_filename(dso, NULL);

/* Ensure 32-bit pointer for "p", and appropriate malloc() function. */
# if __INITIAL_POINTER_SIZE == 64
#  define DSO_MALLOC _malloc32
#  pragma pointer_size save
#  pragma pointer_size 32
# else                          /* __INITIAL_POINTER_SIZE == 64 */
#  define DSO_MALLOC OPENSSL_malloc
# endif                         /* __INITIAL_POINTER_SIZE == 64 [else] */

    DSO_VMS_INTERNAL *p = NULL;

# if __INITIAL_POINTER_SIZE == 64
#  pragma pointer_size restore
# endif                         /* __INITIAL_POINTER_SIZE == 64 */

    const char *sp1, *sp2;      /* Search result */
    const char *ext = NULL;	/* possible extension to add */

    if (filename == NULL) {
        DSOerr(DSO_F_VMS_LOAD, DSO_R_NO_FILENAME);
        goto err;
    }

    /*-
     * A file specification may look like this:
     *
     *      node::dev:[dir-spec]name.type;ver
     *
     * or (for compatibility with TOPS-20):
     *
     *      node::dev:<dir-spec>name.type;ver
     *
     * and the dir-spec uses '.' as separator.  Also, a dir-spec
     * may consist of several parts, with mixed use of [] and <>:
     *
     *      [dir1.]<dir2>
     *
     * We need to split the file specification into the name and
     * the rest (both before and after the name itself).
     */
    /*
     * Start with trying to find the end of a dir-spec, and save the position
     * of the byte after in sp1
     */
    sp1 = strrchr(filename, ']');
    sp2 = strrchr(filename, '>');
    if (sp1 == NULL)
        sp1 = sp2;
    if (sp2 != NULL && sp2 > sp1)
        sp1 = sp2;
    if (sp1 == NULL)
        sp1 = strrchr(filename, ':');
    if (sp1 == NULL)
        sp1 = filename;
    else
        sp1++;                  /* The byte after the found character */
    /* Now, let's see if there's a type, and save the position in sp2 */
    sp2 = strchr(sp1, '.');
    /*
     * If there is a period and the next character is a semi-colon,
     * we need to add an extension
     */
    if (sp2 != NULL && sp2[1] == ';')
        ext = ".EXE";
    /*
     * If we found it, that's where we'll cut.  Otherwise, look for a version
     * number and save the position in sp2
     */
    if (sp2 == NULL) {
        sp2 = strchr(sp1, ';');
        ext = ".EXE";
    }
    /*
     * If there was still nothing to find, set sp2 to point at the end of the
     * string
     */
    if (sp2 == NULL)
        sp2 = sp1 + strlen(sp1);

    /* Check that we won't get buffer overflows */
    if (sp2 - sp1 > FILENAME_MAX
        || (sp1 - filename) + strlen(sp2) > FILENAME_MAX) {
        DSOerr(DSO_F_VMS_LOAD, DSO_R_FILENAME_TOO_BIG);
        goto err;
    }

    p = DSO_MALLOC(sizeof(DSO_VMS_INTERNAL));
    if (p == NULL) {
        DSOerr(DSO_F_VMS_LOAD, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    strncpy(p->filename, sp1, sp2 - sp1);
    p->filename[sp2 - sp1] = '\0';

    strncpy(p->imagename, filename, sp1 - filename);
    p->imagename[sp1 - filename] = '\0';
    if (ext) {
        strcat(p->imagename, ext);
        if (*sp2 == '.')
            sp2++;
    }
    strcat(p->imagename, sp2);

    p->filename_dsc.dsc$w_length = strlen(p->filename);
    p->filename_dsc.dsc$b_dtype = DSC$K_DTYPE_T;
    p->filename_dsc.dsc$b_class = DSC$K_CLASS_S;
    p->filename_dsc.dsc$a_pointer = p->filename;
    p->imagename_dsc.dsc$w_length = strlen(p->imagename);
    p->imagename_dsc.dsc$b_dtype = DSC$K_DTYPE_T;
    p->imagename_dsc.dsc$b_class = DSC$K_CLASS_S;
    p->imagename_dsc.dsc$a_pointer = p->imagename;

    if (!sk_void_push(dso->meth_data, (char *)p)) {
        DSOerr(DSO_F_VMS_LOAD, DSO_R_STACK_ERROR);
        goto err;
    }

    /* Success (for now, we lie.  We actually do not know...) */
    dso->loaded_filename = filename;
    return (1);
 err:
    /* Cleanup! */
    if (p != NULL)
        OPENSSL_free(p);
    if (filename != NULL)
        OPENSSL_free(filename);
    return (0);
}

/*
 * Note that this doesn't actually unload the shared image, as there is no
 * such thing in VMS.  Next time it get loaded again, a new copy will
 * actually be loaded.
 */
static int vms_unload(DSO *dso)
{
    DSO_VMS_INTERNAL *p;
    if (dso == NULL) {
        DSOerr(DSO_F_VMS_UNLOAD, ERR_R_PASSED_NULL_PARAMETER);
        return (0);
    }
    if (sk_void_num(dso->meth_data) < 1)
        return (1);
    p = (DSO_VMS_INTERNAL *)sk_void_pop(dso->meth_data);
    if (p == NULL) {
        DSOerr(DSO_F_VMS_UNLOAD, DSO_R_NULL_HANDLE);
        return (0);
    }
    /* Cleanup */
    OPENSSL_free(p);
    return (1);
}

/*
 * We must do this in a separate function because of the way the exception
 * handler works (it makes this function return
 */
static int do_find_symbol(DSO_VMS_INTERNAL *ptr,
                          struct dsc$descriptor_s *symname_dsc, void **sym,
                          unsigned long flags)
{
    /*
     * Make sure that signals are caught and returned instead of aborting the
     * program.  The exception handler gets unestablished automatically on
     * return from this function.
     */
    lib$establish(lib$sig_to_ret);

    if (ptr->imagename_dsc.dsc$w_length)
        return lib$find_image_symbol(&ptr->filename_dsc,
                                     symname_dsc, sym,
                                     &ptr->imagename_dsc, flags);
    else
        return lib$find_image_symbol(&ptr->filename_dsc,
                                     symname_dsc, sym, 0, flags);
}

void vms_bind_sym(DSO *dso, const char *symname, void **sym)
{
    DSO_VMS_INTERNAL *ptr;
    int status;
# if 0
    int flags = (1 << 4);       /* LIB$M_FIS_MIXEDCASE, but this symbol isn't
                                 * defined in VMS older than 7.0 or so */
# else
    int flags = 0;
# endif
    struct dsc$descriptor_s symname_dsc;

/* Arrange 32-bit pointer to (copied) string storage, if needed. */
# if __INITIAL_POINTER_SIZE == 64
#  define SYMNAME symname_32p
#  pragma pointer_size save
#  pragma pointer_size 32
    char *symname_32p;
#  pragma pointer_size restore
    char symname_32[NAMX_MAXRSS + 1];
# else                          /* __INITIAL_POINTER_SIZE == 64 */
#  define SYMNAME ((char *) symname)
# endif                         /* __INITIAL_POINTER_SIZE == 64 [else] */

    *sym = NULL;

    if ((dso == NULL) || (symname == NULL)) {
        DSOerr(DSO_F_VMS_BIND_SYM, ERR_R_PASSED_NULL_PARAMETER);
        return;
    }
# if __INITIAL_POINTER_SIZE == 64
    /* Copy the symbol name to storage with a 32-bit pointer. */
    symname_32p = symname_32;
    strcpy(symname_32p, symname);
# endif                         /* __INITIAL_POINTER_SIZE == 64 [else] */

    symname_dsc.dsc$w_length = strlen(SYMNAME);
    symname_dsc.dsc$b_dtype = DSC$K_DTYPE_T;
    symname_dsc.dsc$b_class = DSC$K_CLASS_S;
    symname_dsc.dsc$a_pointer = SYMNAME;

    if (sk_void_num(dso->meth_data) < 1) {
        DSOerr(DSO_F_VMS_BIND_SYM, DSO_R_STACK_ERROR);
        return;
    }
    ptr = (DSO_VMS_INTERNAL *)sk_void_value(dso->meth_data,
                                            sk_void_num(dso->meth_data) - 1);
    if (ptr == NULL) {
        DSOerr(DSO_F_VMS_BIND_SYM, DSO_R_NULL_HANDLE);
        return;
    }

    if (dso->flags & DSO_FLAG_UPCASE_SYMBOL)
        flags = 0;

    status = do_find_symbol(ptr, &symname_dsc, sym, flags);

    if (!$VMS_STATUS_SUCCESS(status)) {
        unsigned short length;
        char errstring[257];
        struct dsc$descriptor_s errstring_dsc;

        errstring_dsc.dsc$w_length = sizeof(errstring);
        errstring_dsc.dsc$b_dtype = DSC$K_DTYPE_T;
        errstring_dsc.dsc$b_class = DSC$K_CLASS_S;
        errstring_dsc.dsc$a_pointer = errstring;

        *sym = NULL;

        status = sys$getmsg(status, &length, &errstring_dsc, 1, 0);

        if (!$VMS_STATUS_SUCCESS(status))
            lib$signal(status); /* This is really bad.  Abort! */
        else {
            errstring[length] = '\0';

            DSOerr(DSO_F_VMS_BIND_SYM, DSO_R_SYM_FAILURE);
            if (ptr->imagename_dsc.dsc$w_length)
                ERR_add_error_data(9,
                                   "Symbol ", symname,
                                   " in ", ptr->filename,
                                   " (", ptr->imagename, ")",
                                   ": ", errstring);
            else
                ERR_add_error_data(6,
                                   "Symbol ", symname,
                                   " in ", ptr->filename, ": ", errstring);
        }
        return;
    }
    return;
}

static void *vms_bind_var(DSO *dso, const char *symname)
{
    void *sym = 0;
    vms_bind_sym(dso, symname, &sym);
    return sym;
}

static DSO_FUNC_TYPE vms_bind_func(DSO *dso, const char *symname)
{
    DSO_FUNC_TYPE sym = 0;
    vms_bind_sym(dso, symname, (void **)&sym);
    return sym;
}

static char *vms_merger(DSO *dso, const char *filespec1,
                        const char *filespec2)
{
    int status;
    int filespec1len, filespec2len;
    struct FAB fab;
    struct NAMX_STRUCT nam;
    char esa[NAMX_MAXRSS + 1];
    char *merged;

/* Arrange 32-bit pointer to (copied) string storage, if needed. */
# if __INITIAL_POINTER_SIZE == 64
#  define FILESPEC1 filespec1_32p;
#  define FILESPEC2 filespec2_32p;
#  pragma pointer_size save
#  pragma pointer_size 32
    char *filespec1_32p;
    char *filespec2_32p;
#  pragma pointer_size restore
    char filespec1_32[NAMX_MAXRSS + 1];
    char filespec2_32[NAMX_MAXRSS + 1];
# else                          /* __INITIAL_POINTER_SIZE == 64 */
#  define FILESPEC1 ((char *) filespec1)
#  define FILESPEC2 ((char *) filespec2)
# endif                         /* __INITIAL_POINTER_SIZE == 64 [else] */

    if (!filespec1)
        filespec1 = "";
    if (!filespec2)
        filespec2 = "";
    filespec1len = strlen(filespec1);
    filespec2len = strlen(filespec2);

# if __INITIAL_POINTER_SIZE == 64
    /* Copy the file names to storage with a 32-bit pointer. */
    filespec1_32p = filespec1_32;
    filespec2_32p = filespec2_32;
    strcpy(filespec1_32p, filespec1);
    strcpy(filespec2_32p, filespec2);
# endif                         /* __INITIAL_POINTER_SIZE == 64 [else] */

    fab = cc$rms_fab;
    nam = CC_RMS_NAMX;

    FAB_OR_NAML(fab, nam).FAB_OR_NAML_FNA = FILESPEC1;
    FAB_OR_NAML(fab, nam).FAB_OR_NAML_FNS = filespec1len;
    FAB_OR_NAML(fab, nam).FAB_OR_NAML_DNA = FILESPEC2;
    FAB_OR_NAML(fab, nam).FAB_OR_NAML_DNS = filespec2len;
    NAMX_DNA_FNA_SET(fab)

        nam.NAMX_ESA = esa;
    nam.NAMX_ESS = NAMX_MAXRSS;
    nam.NAMX_NOP = NAM$M_SYNCHK | NAM$M_PWD;
    SET_NAMX_NO_SHORT_UPCASE(nam);

    fab.FAB_NAMX = &nam;

    status = sys$parse(&fab, 0, 0);

    if (!$VMS_STATUS_SUCCESS(status)) {
        unsigned short length;
        char errstring[257];
        struct dsc$descriptor_s errstring_dsc;

        errstring_dsc.dsc$w_length = sizeof(errstring);
        errstring_dsc.dsc$b_dtype = DSC$K_DTYPE_T;
        errstring_dsc.dsc$b_class = DSC$K_CLASS_S;
        errstring_dsc.dsc$a_pointer = errstring;

        status = sys$getmsg(status, &length, &errstring_dsc, 1, 0);

        if (!$VMS_STATUS_SUCCESS(status))
            lib$signal(status); /* This is really bad.  Abort! */
        else {
            errstring[length] = '\0';

            DSOerr(DSO_F_VMS_MERGER, DSO_R_FAILURE);
            ERR_add_error_data(7,
                               "filespec \"", filespec1, "\", ",
                               "defaults \"", filespec2, "\": ", errstring);
        }
        return (NULL);
    }

    merged = OPENSSL_malloc(nam.NAMX_ESL + 1);
    if (!merged)
        goto malloc_err;
    strncpy(merged, nam.NAMX_ESA, nam.NAMX_ESL);
    merged[nam.NAMX_ESL] = '\0';
    return (merged);
 malloc_err:
    DSOerr(DSO_F_VMS_MERGER, ERR_R_MALLOC_FAILURE);
}

static char *vms_name_converter(DSO *dso, const char *filename)
{
    int len = strlen(filename);
    char *not_translated = OPENSSL_malloc(len + 1);
    if (not_translated)
        strcpy(not_translated, filename);
    return (not_translated);
}

#endif                          /* OPENSSL_SYS_VMS */
/* dso_win32.c */
/*
 * Written by Geoff Thorpe (geoff@geoffthorpe.net) for the OpenSSL project
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
#include <string.h>
// #include "cryptlib.h"
// #include "dso.h"

#if !defined(DSO_WIN32)
DSO_METHOD *DSO_METHOD_win32(void)
{
    return NULL;
}
#else

# ifdef _WIN32_WCE
#  if _WIN32_WCE < 300
static FARPROC GetProcAddressA(HMODULE hModule, LPCSTR lpProcName)
{
    WCHAR lpProcNameW[64];
    int i;

    for (i = 0; lpProcName[i] && i < 64; i++)
        lpProcNameW[i] = (WCHAR)lpProcName[i];
    if (i == 64)
        return NULL;
    lpProcNameW[i] = 0;

    return GetProcAddressW(hModule, lpProcNameW);
}
#  endif
#  undef GetProcAddress
#  define GetProcAddress GetProcAddressA

static HINSTANCE LoadLibraryA(LPCSTR lpLibFileName)
{
    WCHAR *fnamw;
    size_t len_0 = strlen(lpLibFileName) + 1, i;

#  ifdef _MSC_VER
    fnamw = (WCHAR *)_alloca(len_0 * sizeof(WCHAR));
#  else
    fnamw = (WCHAR *)alloca(len_0 * sizeof(WCHAR));
#  endif
    if (fnamw == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
#  if defined(_WIN32_WCE) && _WIN32_WCE>=101
    if (!MultiByteToWideChar(CP_ACP, 0, lpLibFileName, len_0, fnamw, len_0))
#  endif
        for (i = 0; i < len_0; i++)
            fnamw[i] = (WCHAR)lpLibFileName[i];

    return LoadLibraryW(fnamw);
}
# endif

/* Part of the hack in "win32_load" ... */
# define DSO_MAX_TRANSLATED_SIZE 256

static int win32_load(DSO *dso);
static int win32_unload(DSO *dso);
static void *win32_bind_var(DSO *dso, const char *symname);
static DSO_FUNC_TYPE win32_bind_func(DSO *dso, const char *symname);
# if 0
static int win32_unbind_var(DSO *dso, char *symname, void *symptr);
static int win32_unbind_func(DSO *dso, char *symname, DSO_FUNC_TYPE symptr);
static int win32_init(DSO *dso);
static int win32_finish(DSO *dso);
static long win32_ctrl(DSO *dso, int cmd, long larg, void *parg);
# endif
static char *win32_name_converter(DSO *dso, const char *filename);
static char *win32_merger(DSO *dso, const char *filespec1,
                          const char *filespec2);
static int win32_pathbyaddr(void *addr, char *path, int sz);
static void *win32_globallookup(const char *name);

static const char *openssl_strnchr(const char *string, int c, size_t len);

static DSO_METHOD dso_meth_win32 = {
    "OpenSSL 'win32' shared library method",
    win32_load,
    win32_unload,
    win32_bind_var,
    win32_bind_func,
/* For now, "unbind" doesn't exist */
# if 0
    NULL,                       /* unbind_var */
    NULL,                       /* unbind_func */
# endif
    NULL,                       /* ctrl */
    win32_name_converter,
    win32_merger,
    NULL,                       /* init */
    NULL,                       /* finish */
    win32_pathbyaddr,
    win32_globallookup
};

DSO_METHOD *DSO_METHOD_win32(void)
{
    return (&dso_meth_win32);
}

/*
 * For this DSO_METHOD, our meth_data STACK will contain; (i) a pointer to
 * the handle (HINSTANCE) returned from LoadLibrary(), and copied.
 */

static int win32_load(DSO *dso)
{
    HINSTANCE h = NULL, *p = NULL;
    /* See applicable comments from dso_dl.c */
    char *filename = DSO_convert_filename(dso, NULL);

    if (filename == NULL) {
        DSOerr(DSO_F_WIN32_LOAD, DSO_R_NO_FILENAME);
        goto err;
    }
    h = LoadLibraryA(filename);
    if (h == NULL) {
        DSOerr(DSO_F_WIN32_LOAD, DSO_R_LOAD_FAILED);
        ERR_add_error_data(3, "filename(", filename, ")");
        goto err;
    }
    p = (HINSTANCE *) OPENSSL_malloc(sizeof(HINSTANCE));
    if (p == NULL) {
        DSOerr(DSO_F_WIN32_LOAD, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    *p = h;
    if (!sk_void_push(dso->meth_data, p)) {
        DSOerr(DSO_F_WIN32_LOAD, DSO_R_STACK_ERROR);
        goto err;
    }
    /* Success */
    dso->loaded_filename = filename;
    return (1);
 err:
    /* Cleanup ! */
    if (filename != NULL)
        OPENSSL_free(filename);
    if (p != NULL)
        OPENSSL_free(p);
    if (h != NULL)
        FreeLibrary(h);
    return (0);
}

static int win32_unload(DSO *dso)
{
    HINSTANCE *p;
    if (dso == NULL) {
        DSOerr(DSO_F_WIN32_UNLOAD, ERR_R_PASSED_NULL_PARAMETER);
        return (0);
    }
    if (sk_void_num(dso->meth_data) < 1)
        return (1);
    p = sk_void_pop(dso->meth_data);
    if (p == NULL) {
        DSOerr(DSO_F_WIN32_UNLOAD, DSO_R_NULL_HANDLE);
        return (0);
    }
    if (!FreeLibrary(*p)) {
        DSOerr(DSO_F_WIN32_UNLOAD, DSO_R_UNLOAD_FAILED);
        /*
         * We should push the value back onto the stack in case of a retry.
         */
        sk_void_push(dso->meth_data, p);
        return (0);
    }
    /* Cleanup */
    OPENSSL_free(p);
    return (1);
}

/*
 * Using GetProcAddress for variables? TODO: Check this out in the Win32 API
 * docs, there's probably a variant for variables.
 */
static void *win32_bind_var(DSO *dso, const char *symname)
{
    HINSTANCE *ptr;
    void *sym;

    if ((dso == NULL) || (symname == NULL)) {
        DSOerr(DSO_F_WIN32_BIND_VAR, ERR_R_PASSED_NULL_PARAMETER);
        return (NULL);
    }
    if (sk_void_num(dso->meth_data) < 1) {
        DSOerr(DSO_F_WIN32_BIND_VAR, DSO_R_STACK_ERROR);
        return (NULL);
    }
    ptr = sk_void_value(dso->meth_data, sk_void_num(dso->meth_data) - 1);
    if (ptr == NULL) {
        DSOerr(DSO_F_WIN32_BIND_VAR, DSO_R_NULL_HANDLE);
        return (NULL);
    }
    sym = GetProcAddress(*ptr, symname);
    if (sym == NULL) {
        DSOerr(DSO_F_WIN32_BIND_VAR, DSO_R_SYM_FAILURE);
        ERR_add_error_data(3, "symname(", symname, ")");
        return (NULL);
    }
    return (sym);
}

static DSO_FUNC_TYPE win32_bind_func(DSO *dso, const char *symname)
{
    HINSTANCE *ptr;
    void *sym;

    if ((dso == NULL) || (symname == NULL)) {
        DSOerr(DSO_F_WIN32_BIND_FUNC, ERR_R_PASSED_NULL_PARAMETER);
        return (NULL);
    }
    if (sk_void_num(dso->meth_data) < 1) {
        DSOerr(DSO_F_WIN32_BIND_FUNC, DSO_R_STACK_ERROR);
        return (NULL);
    }
    ptr = sk_void_value(dso->meth_data, sk_void_num(dso->meth_data) - 1);
    if (ptr == NULL) {
        DSOerr(DSO_F_WIN32_BIND_FUNC, DSO_R_NULL_HANDLE);
        return (NULL);
    }
    sym = GetProcAddress(*ptr, symname);
    if (sym == NULL) {
        DSOerr(DSO_F_WIN32_BIND_FUNC, DSO_R_SYM_FAILURE);
        ERR_add_error_data(3, "symname(", symname, ")");
        return (NULL);
    }
    return ((DSO_FUNC_TYPE)sym);
}

struct file_st {
    const char *node;
    int nodelen;
    const char *device;
    int devicelen;
    const char *predir;
    int predirlen;
    const char *dir;
    int dirlen;
    const char *file;
    int filelen;
};

static struct file_st *win32_splitter(DSO *dso, const char *filename,
                                      int assume_last_is_dir)
{
    struct file_st *result = NULL;
    enum { IN_NODE, IN_DEVICE, IN_FILE } position;
    const char *start = filename;
    char last;

    if (!filename) {
        DSOerr(DSO_F_WIN32_SPLITTER, DSO_R_NO_FILENAME);
        /*
         * goto err;
         */
        return (NULL);
    }

    result = OPENSSL_malloc(sizeof(struct file_st));
    if (result == NULL) {
        DSOerr(DSO_F_WIN32_SPLITTER, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }

    memset(result, 0, sizeof(struct file_st));
    position = IN_DEVICE;

    if ((filename[0] == '\\' && filename[1] == '\\')
        || (filename[0] == '/' && filename[1] == '/')) {
        position = IN_NODE;
        filename += 2;
        start = filename;
        result->node = start;
    }

    do {
        last = filename[0];
        switch (last) {
        case ':':
            if (position != IN_DEVICE) {
                DSOerr(DSO_F_WIN32_SPLITTER, DSO_R_INCORRECT_FILE_SYNTAX);
                /*
                 * goto err;
                 */
                OPENSSL_free(result);
                return (NULL);
            }
            result->device = start;
            result->devicelen = (int)(filename - start);
            position = IN_FILE;
            start = ++filename;
            result->dir = start;
            break;
        case '\\':
        case '/':
            if (position == IN_NODE) {
                result->nodelen = (int)(filename - start);
                position = IN_FILE;
                start = ++filename;
                result->dir = start;
            } else if (position == IN_DEVICE) {
                position = IN_FILE;
                filename++;
                result->dir = start;
                result->dirlen = (int)(filename - start);
                start = filename;
            } else {
                filename++;
                result->dirlen += (int)(filename - start);
                start = filename;
            }
            break;
        case '\0':
            if (position == IN_NODE) {
                result->nodelen = (int)(filename - start);
            } else {
                if (filename - start > 0) {
                    if (assume_last_is_dir) {
                        if (position == IN_DEVICE) {
                            result->dir = start;
                            result->dirlen = 0;
                        }
                        result->dirlen += (int)(filename - start);
                    } else {
                        result->file = start;
                        result->filelen = (int)(filename - start);
                    }
                }
            }
            break;
        default:
            filename++;
            break;
        }
    }
    while (last);

    if (!result->nodelen)
        result->node = NULL;
    if (!result->devicelen)
        result->device = NULL;
    if (!result->dirlen)
        result->dir = NULL;
    if (!result->filelen)
        result->file = NULL;

    return (result);
}

static char *win32_joiner(DSO *dso, const struct file_st *file_split)
{
    int len = 0, offset = 0;
    char *result = NULL;
    const char *start;

    if (!file_split) {
        DSOerr(DSO_F_WIN32_JOINER, ERR_R_PASSED_NULL_PARAMETER);
        return (NULL);
    }
    if (file_split->node) {
        len += 2 + file_split->nodelen; /* 2 for starting \\ */
        if (file_split->predir || file_split->dir || file_split->file)
            len++;              /* 1 for ending \ */
    } else if (file_split->device) {
        len += file_split->devicelen + 1; /* 1 for ending : */
    }
    len += file_split->predirlen;
    if (file_split->predir && (file_split->dir || file_split->file)) {
        len++;                  /* 1 for ending \ */
    }
    len += file_split->dirlen;
    if (file_split->dir && file_split->file) {
        len++;                  /* 1 for ending \ */
    }
    len += file_split->filelen;

    if (!len) {
        DSOerr(DSO_F_WIN32_JOINER, DSO_R_EMPTY_FILE_STRUCTURE);
        return (NULL);
    }

    result = OPENSSL_malloc(len + 1);
    if (!result) {
        DSOerr(DSO_F_WIN32_JOINER, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }

    if (file_split->node) {
        strcpy(&result[offset], "\\\\");
        offset += 2;
        strncpy(&result[offset], file_split->node, file_split->nodelen);
        offset += file_split->nodelen;
        if (file_split->predir || file_split->dir || file_split->file) {
            result[offset] = '\\';
            offset++;
        }
    } else if (file_split->device) {
        strncpy(&result[offset], file_split->device, file_split->devicelen);
        offset += file_split->devicelen;
        result[offset] = ':';
        offset++;
    }
    start = file_split->predir;
    while (file_split->predirlen > (start - file_split->predir)) {
        const char *end = openssl_strnchr(start, '/',
                                          file_split->predirlen - (start -
                                                                   file_split->predir));
        if (!end)
            end = start
                + file_split->predirlen - (start - file_split->predir);
        strncpy(&result[offset], start, end - start);
        offset += (int)(end - start);
        result[offset] = '\\';
        offset++;
        start = end + 1;
    }
# if 0                          /* Not needed, since the directory converter
                                 * above already appeneded a backslash */
    if (file_split->predir && (file_split->dir || file_split->file)) {
        result[offset] = '\\';
        offset++;
    }
# endif
    start = file_split->dir;
    while (file_split->dirlen > (start - file_split->dir)) {
        const char *end = openssl_strnchr(start, '/',
                                          file_split->dirlen - (start -
                                                                file_split->dir));
        if (!end)
            end = start + file_split->dirlen - (start - file_split->dir);
        strncpy(&result[offset], start, end - start);
        offset += (int)(end - start);
        result[offset] = '\\';
        offset++;
        start = end + 1;
    }
# if 0                          /* Not needed, since the directory converter
                                 * above already appeneded a backslash */
    if (file_split->dir && file_split->file) {
        result[offset] = '\\';
        offset++;
    }
# endif
    strncpy(&result[offset], file_split->file, file_split->filelen);
    offset += file_split->filelen;
    result[offset] = '\0';
    return (result);
}

static char *win32_merger(DSO *dso, const char *filespec1,
                          const char *filespec2)
{
    char *merged = NULL;
    struct file_st *filespec1_split = NULL;
    struct file_st *filespec2_split = NULL;

    if (!filespec1 && !filespec2) {
        DSOerr(DSO_F_WIN32_MERGER, ERR_R_PASSED_NULL_PARAMETER);
        return (NULL);
    }
    if (!filespec2) {
        merged = OPENSSL_malloc(strlen(filespec1) + 1);
        if (!merged) {
            DSOerr(DSO_F_WIN32_MERGER, ERR_R_MALLOC_FAILURE);
            return (NULL);
        }
        strcpy(merged, filespec1);
    } else if (!filespec1) {
        merged = OPENSSL_malloc(strlen(filespec2) + 1);
        if (!merged) {
            DSOerr(DSO_F_WIN32_MERGER, ERR_R_MALLOC_FAILURE);
            return (NULL);
        }
        strcpy(merged, filespec2);
    } else {
        filespec1_split = win32_splitter(dso, filespec1, 0);
        if (!filespec1_split) {
            DSOerr(DSO_F_WIN32_MERGER, ERR_R_MALLOC_FAILURE);
            return (NULL);
        }
        filespec2_split = win32_splitter(dso, filespec2, 1);
        if (!filespec2_split) {
            DSOerr(DSO_F_WIN32_MERGER, ERR_R_MALLOC_FAILURE);
            OPENSSL_free(filespec1_split);
            return (NULL);
        }

        /* Fill in into filespec1_split */
        if (!filespec1_split->node && !filespec1_split->device) {
            filespec1_split->node = filespec2_split->node;
            filespec1_split->nodelen = filespec2_split->nodelen;
            filespec1_split->device = filespec2_split->device;
            filespec1_split->devicelen = filespec2_split->devicelen;
        }
        if (!filespec1_split->dir) {
            filespec1_split->dir = filespec2_split->dir;
            filespec1_split->dirlen = filespec2_split->dirlen;
        } else if (filespec1_split->dir[0] != '\\'
                   && filespec1_split->dir[0] != '/') {
            filespec1_split->predir = filespec2_split->dir;
            filespec1_split->predirlen = filespec2_split->dirlen;
        }
        if (!filespec1_split->file) {
            filespec1_split->file = filespec2_split->file;
            filespec1_split->filelen = filespec2_split->filelen;
        }

        merged = win32_joiner(dso, filespec1_split);
    }
    OPENSSL_free(filespec1_split);
    OPENSSL_free(filespec2_split);
    return (merged);
}

static char *win32_name_converter(DSO *dso, const char *filename)
{
    char *translated;
    int len, transform;

    len = strlen(filename);
    transform = ((strstr(filename, "/") == NULL) &&
                 (strstr(filename, "\\") == NULL) &&
                 (strstr(filename, ":") == NULL));
    if (transform)
        /* We will convert this to "%s.dll" */
        translated = OPENSSL_malloc(len + 5);
    else
        /* We will simply duplicate filename */
        translated = OPENSSL_malloc(len + 1);
    if (translated == NULL) {
        DSOerr(DSO_F_WIN32_NAME_CONVERTER, DSO_R_NAME_TRANSLATION_FAILED);
        return (NULL);
    }
    if (transform)
        sprintf(translated, "%s.dll", filename);
    else
        sprintf(translated, "%s", filename);
    return (translated);
}

static const char *openssl_strnchr(const char *string, int c, size_t len)
{
    size_t i;
    const char *p;
    for (i = 0, p = string; i < len && *p; i++, p++) {
        if (*p == c)
            return p;
    }
    return NULL;
}

# include <tlhelp32.h>
# ifdef _WIN32_WCE
#  define DLLNAME "TOOLHELP.DLL"
# else
#  ifdef MODULEENTRY32
#   undef MODULEENTRY32         /* unmask the ASCII version! */
#  endif
#  define DLLNAME "KERNEL32.DLL"
# endif

typedef HANDLE(WINAPI *CREATETOOLHELP32SNAPSHOT) (DWORD, DWORD);
typedef BOOL(WINAPI *CLOSETOOLHELP32SNAPSHOT) (HANDLE);
typedef BOOL(WINAPI *MODULE32) (HANDLE, MODULEENTRY32 *);

static int win32_pathbyaddr(void *addr, char *path, int sz)
{
    HMODULE dll;
    HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
    MODULEENTRY32 me32;
    CREATETOOLHELP32SNAPSHOT create_snap;
    CLOSETOOLHELP32SNAPSHOT close_snap;
    MODULE32 module_first, module_next;

    if (addr == NULL) {
        union {
            int (*f) (void *, char *, int);
            void *p;
        } t = {
            win32_pathbyaddr
        };
        addr = t.p;
    }

    dll = LoadLibrary(TEXT(DLLNAME));
    if (dll == NULL) {
        DSOerr(DSO_F_WIN32_PATHBYADDR, DSO_R_UNSUPPORTED);
        return -1;
    }

    create_snap = (CREATETOOLHELP32SNAPSHOT)
        GetProcAddress(dll, "CreateToolhelp32Snapshot");
    if (create_snap == NULL) {
        FreeLibrary(dll);
        DSOerr(DSO_F_WIN32_PATHBYADDR, DSO_R_UNSUPPORTED);
        return -1;
    }
    /* We take the rest for granted... */
# ifdef _WIN32_WCE
    close_snap = (CLOSETOOLHELP32SNAPSHOT)
        GetProcAddress(dll, "CloseToolhelp32Snapshot");
# else
    close_snap = (CLOSETOOLHELP32SNAPSHOT) CloseHandle;
# endif
    module_first = (MODULE32) GetProcAddress(dll, "Module32First");
    module_next = (MODULE32) GetProcAddress(dll, "Module32Next");

    hModuleSnap = (*create_snap) (TH32CS_SNAPMODULE, 0);
    if (hModuleSnap == INVALID_HANDLE_VALUE) {
        FreeLibrary(dll);
        DSOerr(DSO_F_WIN32_PATHBYADDR, DSO_R_UNSUPPORTED);
        return -1;
    }

    me32.dwSize = sizeof(me32);

    if (!(*module_first) (hModuleSnap, &me32)) {
        (*close_snap) (hModuleSnap);
        FreeLibrary(dll);
        DSOerr(DSO_F_WIN32_PATHBYADDR, DSO_R_FAILURE);
        return -1;
    }

    do {
        if ((BYTE *) addr >= me32.modBaseAddr &&
            (BYTE *) addr < me32.modBaseAddr + me32.modBaseSize) {
            (*close_snap) (hModuleSnap);
            FreeLibrary(dll);
# ifdef _WIN32_WCE
#  if _WIN32_WCE >= 101
            return WideCharToMultiByte(CP_ACP, 0, me32.szExePath, -1,
                                       path, sz, NULL, NULL);
#  else
            {
                int i, len = (int)wcslen(me32.szExePath);
                if (sz <= 0)
                    return len + 1;
                if (len >= sz)
                    len = sz - 1;
                for (i = 0; i < len; i++)
                    path[i] = (char)me32.szExePath[i];
                path[len++] = 0;
                return len;
            }
#  endif
# else
            {
                int len = (int)strlen(me32.szExePath);
                if (sz <= 0)
                    return len + 1;
                if (len >= sz)
                    len = sz - 1;
                memcpy(path, me32.szExePath, len);
                path[len++] = 0;
                return len;
            }
# endif
        }
    } while ((*module_next) (hModuleSnap, &me32));

    (*close_snap) (hModuleSnap);
    FreeLibrary(dll);
    return 0;
}

static void *win32_globallookup(const char *name)
{
    HMODULE dll;
    HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
    MODULEENTRY32 me32;
    CREATETOOLHELP32SNAPSHOT create_snap;
    CLOSETOOLHELP32SNAPSHOT close_snap;
    MODULE32 module_first, module_next;
    FARPROC ret = NULL;

    dll = LoadLibrary(TEXT(DLLNAME));
    if (dll == NULL) {
        DSOerr(DSO_F_WIN32_GLOBALLOOKUP, DSO_R_UNSUPPORTED);
        return NULL;
    }

    create_snap = (CREATETOOLHELP32SNAPSHOT)
        GetProcAddress(dll, "CreateToolhelp32Snapshot");
    if (create_snap == NULL) {
        FreeLibrary(dll);
        DSOerr(DSO_F_WIN32_GLOBALLOOKUP, DSO_R_UNSUPPORTED);
        return NULL;
    }
    /* We take the rest for granted... */
# ifdef _WIN32_WCE
    close_snap = (CLOSETOOLHELP32SNAPSHOT)
        GetProcAddress(dll, "CloseToolhelp32Snapshot");
# else
    close_snap = (CLOSETOOLHELP32SNAPSHOT) CloseHandle;
# endif
    module_first = (MODULE32) GetProcAddress(dll, "Module32First");
    module_next = (MODULE32) GetProcAddress(dll, "Module32Next");

    hModuleSnap = (*create_snap) (TH32CS_SNAPMODULE, 0);
    if (hModuleSnap == INVALID_HANDLE_VALUE) {
        FreeLibrary(dll);
        DSOerr(DSO_F_WIN32_GLOBALLOOKUP, DSO_R_UNSUPPORTED);
        return NULL;
    }

    me32.dwSize = sizeof(me32);

    if (!(*module_first) (hModuleSnap, &me32)) {
        (*close_snap) (hModuleSnap);
        FreeLibrary(dll);
        return NULL;
    }

    do {
        if ((ret = GetProcAddress(me32.hModule, name))) {
            (*close_snap) (hModuleSnap);
            FreeLibrary(dll);
            return ret;
        }
    } while ((*module_next) (hModuleSnap, &me32));

    (*close_snap) (hModuleSnap);
    FreeLibrary(dll);
    return NULL;
}
#endif                          /* DSO_WIN32 */
