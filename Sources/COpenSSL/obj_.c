/* crypto/objects/obj_dat.c */
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
#include <ctype.h>
#include <limits.h>
#include "cryptlib.h"
#include "lhash.h"
#include "asn1.h"
#include "objects.h"
#include "bn.h"

/* obj_dat.h is generated from objects.h by obj_dat.pl */
#ifndef OPENSSL_NO_OBJECT
# include "obj_dat.h"
#else
/* You will have to load all the objects needed manually in the application */
# define NUM_NID 0
# define NUM_SN 0
# define NUM_LN 0
# define NUM_OBJ 0
static const unsigned char lvalues[1];
static const ASN1_OBJECT nid_objs[1];
static const unsigned int sn_objs[1];
static const unsigned int ln_objs[1];
static const unsigned int obj_objs[1];
#endif

DECLARE_OBJ_BSEARCH_CMP_FN(const ASN1_OBJECT *, unsigned int, sn);
DECLARE_OBJ_BSEARCH_CMP_FN(const ASN1_OBJECT *, unsigned int, ln);
DECLARE_OBJ_BSEARCH_CMP_FN(const ASN1_OBJECT *, unsigned int, obj);

#define ADDED_DATA      0
#define ADDED_SNAME     1
#define ADDED_LNAME     2
#define ADDED_NID       3

typedef struct added_obj_st {
    int type;
    ASN1_OBJECT *obj;
} ADDED_OBJ;
DECLARE_LHASH_OF(ADDED_OBJ);

static int new_nid = NUM_NID;
static LHASH_OF(ADDED_OBJ) *added = NULL;

static int sn_cmp(const ASN1_OBJECT *const *a, const unsigned int *b)
{
    return (strcmp((*a)->sn, nid_objs[*b].sn));
}

IMPLEMENT_OBJ_BSEARCH_CMP_FN(const ASN1_OBJECT *, unsigned int, sn);

static int ln_cmp(const ASN1_OBJECT *const *a, const unsigned int *b)
{
    return (strcmp((*a)->ln, nid_objs[*b].ln));
}

IMPLEMENT_OBJ_BSEARCH_CMP_FN(const ASN1_OBJECT *, unsigned int, ln);

static unsigned long added_obj_hash(const ADDED_OBJ *ca)
{
    const ASN1_OBJECT *a;
    int i;
    unsigned long ret = 0;
    unsigned char *p;

    a = ca->obj;
    switch (ca->type) {
    case ADDED_DATA:
        ret = a->length << 20L;
        p = (unsigned char *)a->data;
        for (i = 0; i < a->length; i++)
            ret ^= p[i] << ((i * 3) % 24);
        break;
    case ADDED_SNAME:
        ret = lh_strhash(a->sn);
        break;
    case ADDED_LNAME:
        ret = lh_strhash(a->ln);
        break;
    case ADDED_NID:
        ret = a->nid;
        break;
    default:
        /* abort(); */
        return 0;
    }
    ret &= 0x3fffffffL;
    ret |= ((unsigned long)ca->type) << 30L;
    return (ret);
}

static IMPLEMENT_LHASH_HASH_FN(added_obj, ADDED_OBJ)

static int added_obj_cmp(const ADDED_OBJ *ca, const ADDED_OBJ *cb)
{
    ASN1_OBJECT *a, *b;
    int i;

    i = ca->type - cb->type;
    if (i)
        return (i);
    a = ca->obj;
    b = cb->obj;
    switch (ca->type) {
    case ADDED_DATA:
        i = (a->length - b->length);
        if (i)
            return (i);
        return (memcmp(a->data, b->data, (size_t)a->length));
    case ADDED_SNAME:
        if (a->sn == NULL)
            return (-1);
        else if (b->sn == NULL)
            return (1);
        else
            return (strcmp(a->sn, b->sn));
    case ADDED_LNAME:
        if (a->ln == NULL)
            return (-1);
        else if (b->ln == NULL)
            return (1);
        else
            return (strcmp(a->ln, b->ln));
    case ADDED_NID:
        return (a->nid - b->nid);
    default:
        /* abort(); */
        return 0;
    }
}

static IMPLEMENT_LHASH_COMP_FN(added_obj, ADDED_OBJ)

static int init_added(void)
{
    if (added != NULL)
        return (1);
    added = lh_ADDED_OBJ_new();
    return (added != NULL);
}

static void cleanup1_doall(ADDED_OBJ *a)
{
    a->obj->nid = 0;
    a->obj->flags |= ASN1_OBJECT_FLAG_DYNAMIC |
        ASN1_OBJECT_FLAG_DYNAMIC_STRINGS | ASN1_OBJECT_FLAG_DYNAMIC_DATA;
}

static void cleanup2_doall(ADDED_OBJ *a)
{
    a->obj->nid++;
}

static void cleanup3_doall(ADDED_OBJ *a)
{
    if (--a->obj->nid == 0)
        ASN1_OBJECT_free(a->obj);
    OPENSSL_free(a);
}

static IMPLEMENT_LHASH_DOALL_FN(cleanup1, ADDED_OBJ)
static IMPLEMENT_LHASH_DOALL_FN(cleanup2, ADDED_OBJ)
static IMPLEMENT_LHASH_DOALL_FN(cleanup3, ADDED_OBJ)

/*
 * The purpose of obj_cleanup_defer is to avoid EVP_cleanup() attempting to
 * use freed up OIDs. If neccessary the actual freeing up of OIDs is delayed.
 */
int obj_cleanup_defer = 0;

void check_defer(int nid)
{
    if (!obj_cleanup_defer && nid >= NUM_NID)
        obj_cleanup_defer = 1;
}

void OBJ_cleanup(void)
{
    if (obj_cleanup_defer) {
        obj_cleanup_defer = 2;
        return;
    }
    if (added == NULL)
        return;
    lh_ADDED_OBJ_down_load(added) = 0;
    lh_ADDED_OBJ_doall(added, LHASH_DOALL_FN(cleanup1)); /* zero counters */
    lh_ADDED_OBJ_doall(added, LHASH_DOALL_FN(cleanup2)); /* set counters */
    lh_ADDED_OBJ_doall(added, LHASH_DOALL_FN(cleanup3)); /* free objects */
    lh_ADDED_OBJ_free(added);
    added = NULL;
}

int OBJ_new_nid(int num)
{
    int i;

    i = new_nid;
    new_nid += num;
    return (i);
}

int OBJ_add_object(const ASN1_OBJECT *obj)
{
    ASN1_OBJECT *o;
    ADDED_OBJ *ao[4] = { NULL, NULL, NULL, NULL }, *aop;
    int i;

    if (added == NULL)
        if (!init_added())
            return (0);
    if ((o = OBJ_dup(obj)) == NULL)
        goto err;
    if (!(ao[ADDED_NID] = (ADDED_OBJ *)OPENSSL_malloc(sizeof(ADDED_OBJ))))
        goto err2;
    if ((o->length != 0) && (obj->data != NULL))
        if (!
            (ao[ADDED_DATA] = (ADDED_OBJ *)OPENSSL_malloc(sizeof(ADDED_OBJ))))
            goto err2;
    if (o->sn != NULL)
        if (!
            (ao[ADDED_SNAME] =
             (ADDED_OBJ *)OPENSSL_malloc(sizeof(ADDED_OBJ))))
            goto err2;
    if (o->ln != NULL)
        if (!
            (ao[ADDED_LNAME] =
             (ADDED_OBJ *)OPENSSL_malloc(sizeof(ADDED_OBJ))))
            goto err2;

    for (i = ADDED_DATA; i <= ADDED_NID; i++) {
        if (ao[i] != NULL) {
            ao[i]->type = i;
            ao[i]->obj = o;
            aop = lh_ADDED_OBJ_insert(added, ao[i]);
            /* memory leak, buit should not normally matter */
            if (aop != NULL)
                OPENSSL_free(aop);
        }
    }
    o->flags &=
        ~(ASN1_OBJECT_FLAG_DYNAMIC | ASN1_OBJECT_FLAG_DYNAMIC_STRINGS |
          ASN1_OBJECT_FLAG_DYNAMIC_DATA);

    return (o->nid);
 err2:
    OBJerr(OBJ_F_OBJ_ADD_OBJECT, ERR_R_MALLOC_FAILURE);
 err:
    for (i = ADDED_DATA; i <= ADDED_NID; i++)
        if (ao[i] != NULL)
            OPENSSL_free(ao[i]);
    ASN1_OBJECT_free(o);
    return NID_undef;
}

ASN1_OBJECT *OBJ_nid2obj(int n)
{
    ADDED_OBJ ad, *adp;
    ASN1_OBJECT ob;

    if ((n >= 0) && (n < NUM_NID)) {
        if ((n != NID_undef) && (nid_objs[n].nid == NID_undef)) {
            OBJerr(OBJ_F_OBJ_NID2OBJ, OBJ_R_UNKNOWN_NID);
            return (NULL);
        }
        return ((ASN1_OBJECT *)&(nid_objs[n]));
    } else if (added == NULL)
        return (NULL);
    else {
        ad.type = ADDED_NID;
        ad.obj = &ob;
        ob.nid = n;
        adp = lh_ADDED_OBJ_retrieve(added, &ad);
        if (adp != NULL)
            return (adp->obj);
        else {
            OBJerr(OBJ_F_OBJ_NID2OBJ, OBJ_R_UNKNOWN_NID);
            return (NULL);
        }
    }
}

const char *OBJ_nid2sn(int n)
{
    ADDED_OBJ ad, *adp;
    ASN1_OBJECT ob;

    if ((n >= 0) && (n < NUM_NID)) {
        if ((n != NID_undef) && (nid_objs[n].nid == NID_undef)) {
            OBJerr(OBJ_F_OBJ_NID2SN, OBJ_R_UNKNOWN_NID);
            return (NULL);
        }
        return (nid_objs[n].sn);
    } else if (added == NULL)
        return (NULL);
    else {
        ad.type = ADDED_NID;
        ad.obj = &ob;
        ob.nid = n;
        adp = lh_ADDED_OBJ_retrieve(added, &ad);
        if (adp != NULL)
            return (adp->obj->sn);
        else {
            OBJerr(OBJ_F_OBJ_NID2SN, OBJ_R_UNKNOWN_NID);
            return (NULL);
        }
    }
}

const char *OBJ_nid2ln(int n)
{
    ADDED_OBJ ad, *adp;
    ASN1_OBJECT ob;

    if ((n >= 0) && (n < NUM_NID)) {
        if ((n != NID_undef) && (nid_objs[n].nid == NID_undef)) {
            OBJerr(OBJ_F_OBJ_NID2LN, OBJ_R_UNKNOWN_NID);
            return (NULL);
        }
        return (nid_objs[n].ln);
    } else if (added == NULL)
        return (NULL);
    else {
        ad.type = ADDED_NID;
        ad.obj = &ob;
        ob.nid = n;
        adp = lh_ADDED_OBJ_retrieve(added, &ad);
        if (adp != NULL)
            return (adp->obj->ln);
        else {
            OBJerr(OBJ_F_OBJ_NID2LN, OBJ_R_UNKNOWN_NID);
            return (NULL);
        }
    }
}

static int obj_cmp(const ASN1_OBJECT *const *ap, const unsigned int *bp)
{
    int j;
    const ASN1_OBJECT *a = *ap;
    const ASN1_OBJECT *b = &nid_objs[*bp];

    j = (a->length - b->length);
    if (j)
        return (j);
    if (a->length == 0)
        return 0;
    return (memcmp(a->data, b->data, a->length));
}

IMPLEMENT_OBJ_BSEARCH_CMP_FN(const ASN1_OBJECT *, unsigned int, obj);

int OBJ_obj2nid(const ASN1_OBJECT *a)
{
    const unsigned int *op;
    ADDED_OBJ ad, *adp;

    if (a == NULL)
        return (NID_undef);
    if (a->nid != 0)
        return (a->nid);

    if (a->length == 0)
        return NID_undef;

    if (added != NULL) {
        ad.type = ADDED_DATA;
        ad.obj = (ASN1_OBJECT *)a; /* XXX: ugly but harmless */
        adp = lh_ADDED_OBJ_retrieve(added, &ad);
        if (adp != NULL)
            return (adp->obj->nid);
    }
    op = OBJ_bsearch_obj(&a, obj_objs, NUM_OBJ);
    if (op == NULL)
        return (NID_undef);
    return (nid_objs[*op].nid);
}

/*
 * Convert an object name into an ASN1_OBJECT if "noname" is not set then
 * search for short and long names first. This will convert the "dotted" form
 * into an object: unlike OBJ_txt2nid it can be used with any objects, not
 * just registered ones.
 */

ASN1_OBJECT *OBJ_txt2obj(const char *s, int no_name)
{
    int nid = NID_undef;
    ASN1_OBJECT *op = NULL;
    unsigned char *buf;
    unsigned char *p;
    const unsigned char *cp;
    int i, j;

    if (!no_name) {
        if (((nid = OBJ_sn2nid(s)) != NID_undef) ||
            ((nid = OBJ_ln2nid(s)) != NID_undef))
            return OBJ_nid2obj(nid);
    }

    /* Work out size of content octets */
    i = a2d_ASN1_OBJECT(NULL, 0, s, -1);
    if (i <= 0) {
        /* Don't clear the error */
        /*
         * ERR_clear_error();
         */
        return NULL;
    }
    /* Work out total size */
    j = ASN1_object_size(0, i, V_ASN1_OBJECT);

    if ((buf = (unsigned char *)OPENSSL_malloc(j)) == NULL)
        return NULL;

    p = buf;
    /* Write out tag+length */
    ASN1_put_object(&p, 0, i, V_ASN1_OBJECT, V_ASN1_UNIVERSAL);
    /* Write out contents */
    a2d_ASN1_OBJECT(p, i, s, -1);

    cp = buf;
    op = d2i_ASN1_OBJECT(NULL, &cp, j);
    OPENSSL_free(buf);
    return op;
}

int OBJ_obj2txt(char *buf, int buf_len, const ASN1_OBJECT *a, int no_name)
{
    int i, n = 0, len, nid, first, use_bn;
    BIGNUM *bl;
    unsigned long l;
    const unsigned char *p;
    char tbuf[DECIMAL_SIZE(i) + DECIMAL_SIZE(l) + 2];

    /* Ensure that, at every state, |buf| is NUL-terminated. */
    if (buf && buf_len > 0)
        buf[0] = '\0';

    if ((a == NULL) || (a->data == NULL))
        return (0);

    if (!no_name && (nid = OBJ_obj2nid(a)) != NID_undef) {
        const char *s;
        s = OBJ_nid2ln(nid);
        if (s == NULL)
            s = OBJ_nid2sn(nid);
        if (s) {
            if (buf)
                BUF_strlcpy(buf, s, buf_len);
            n = strlen(s);
            return n;
        }
    }

    len = a->length;
    p = a->data;

    first = 1;
    bl = NULL;

    while (len > 0) {
        l = 0;
        use_bn = 0;
        for (;;) {
            unsigned char c = *p++;
            len--;
            if ((len == 0) && (c & 0x80))
                goto err;
            if (use_bn) {
                if (!BN_add_word(bl, c & 0x7f))
                    goto err;
            } else
                l |= c & 0x7f;
            if (!(c & 0x80))
                break;
            if (!use_bn && (l > (ULONG_MAX >> 7L))) {
                if (!bl && !(bl = BN_new()))
                    goto err;
                if (!BN_set_word(bl, l))
                    goto err;
                use_bn = 1;
            }
            if (use_bn) {
                if (!BN_lshift(bl, bl, 7))
                    goto err;
            } else
                l <<= 7L;
        }

        if (first) {
            first = 0;
            if (l >= 80) {
                i = 2;
                if (use_bn) {
                    if (!BN_sub_word(bl, 80))
                        goto err;
                } else
                    l -= 80;
            } else {
                i = (int)(l / 40);
                l -= (long)(i * 40);
            }
            if (buf && (buf_len > 1)) {
                *buf++ = i + '0';
                *buf = '\0';
                buf_len--;
            }
            n++;
        }

        if (use_bn) {
            char *bndec;
            bndec = BN_bn2dec(bl);
            if (!bndec)
                goto err;
            i = strlen(bndec);
            if (buf) {
                if (buf_len > 1) {
                    *buf++ = '.';
                    *buf = '\0';
                    buf_len--;
                }
                BUF_strlcpy(buf, bndec, buf_len);
                if (i > buf_len) {
                    buf += buf_len;
                    buf_len = 0;
                } else {
                    buf += i;
                    buf_len -= i;
                }
            }
            n++;
            n += i;
            OPENSSL_free(bndec);
        } else {
            BIO_snprintf(tbuf, sizeof(tbuf), ".%lu", l);
            i = strlen(tbuf);
            if (buf && (buf_len > 0)) {
                BUF_strlcpy(buf, tbuf, buf_len);
                if (i > buf_len) {
                    buf += buf_len;
                    buf_len = 0;
                } else {
                    buf += i;
                    buf_len -= i;
                }
            }
            n += i;
            l = 0;
        }
    }

    if (bl)
        BN_free(bl);
    return n;

 err:
    if (bl)
        BN_free(bl);
    return -1;
}

int OBJ_txt2nid(const char *s)
{
    ASN1_OBJECT *obj;
    int nid;
    obj = OBJ_txt2obj(s, 0);
    nid = OBJ_obj2nid(obj);
    ASN1_OBJECT_free(obj);
    return nid;
}

int OBJ_ln2nid(const char *s)
{
    ASN1_OBJECT o;
    const ASN1_OBJECT *oo = &o;
    ADDED_OBJ ad, *adp;
    const unsigned int *op;

    o.ln = s;
    if (added != NULL) {
        ad.type = ADDED_LNAME;
        ad.obj = &o;
        adp = lh_ADDED_OBJ_retrieve(added, &ad);
        if (adp != NULL)
            return (adp->obj->nid);
    }
    op = OBJ_bsearch_ln(&oo, ln_objs, NUM_LN);
    if (op == NULL)
        return (NID_undef);
    return (nid_objs[*op].nid);
}

int OBJ_sn2nid(const char *s)
{
    ASN1_OBJECT o;
    const ASN1_OBJECT *oo = &o;
    ADDED_OBJ ad, *adp;
    const unsigned int *op;

    o.sn = s;
    if (added != NULL) {
        ad.type = ADDED_SNAME;
        ad.obj = &o;
        adp = lh_ADDED_OBJ_retrieve(added, &ad);
        if (adp != NULL)
            return (adp->obj->nid);
    }
    op = OBJ_bsearch_sn(&oo, sn_objs, NUM_SN);
    if (op == NULL)
        return (NID_undef);
    return (nid_objs[*op].nid);
}

const void *OBJ_bsearch_(const void *key, const void *base, int num, int size,
                         int (*cmp) (const void *, const void *))
{
    return OBJ_bsearch_ex_(key, base, num, size, cmp, 0);
}

const void *OBJ_bsearch_ex_(const void *key, const void *base_, int num,
                            int size,
                            int (*cmp) (const void *, const void *),
                            int flags)
{
    const char *base = base_;
    int l, h, i = 0, c = 0;
    const char *p = NULL;

    if (num == 0)
        return (NULL);
    l = 0;
    h = num;
    while (l < h) {
        i = (l + h) / 2;
        p = &(base[i * size]);
        c = (*cmp) (key, p);
        if (c < 0)
            h = i;
        else if (c > 0)
            l = i + 1;
        else
            break;
    }
#ifdef CHARSET_EBCDIC
    /*
     * THIS IS A KLUDGE - Because the *_obj is sorted in ASCII order, and I
     * don't have perl (yet), we revert to a *LINEAR* search when the object
     * wasn't found in the binary search.
     */
    if (c != 0) {
        for (i = 0; i < num; ++i) {
            p = &(base[i * size]);
            c = (*cmp) (key, p);
            if (c == 0 || (c < 0 && (flags & OBJ_BSEARCH_VALUE_ON_NOMATCH)))
                return p;
        }
    }
#endif
    if (c != 0 && !(flags & OBJ_BSEARCH_VALUE_ON_NOMATCH))
        p = NULL;
    else if (c == 0 && (flags & OBJ_BSEARCH_FIRST_VALUE_ON_MATCH)) {
        while (i > 0 && (*cmp) (key, &(base[(i - 1) * size])) == 0)
            i--;
        p = &(base[i * size]);
    }
    return (p);
}

/*
 * Parse a BIO sink to create some extra oid's objects.
 * Line format:<OID:isdigit or '.']><isspace><SN><isspace><LN>
 */
int OBJ_create_objects(BIO *in)
{
    MS_STATIC char buf[512];
    int i, num = 0;
    char *o, *s, *l = NULL;

    for (;;) {
        s = o = NULL;
        i = BIO_gets(in, buf, 512);
        if (i <= 0)
            return (num);
        buf[i - 1] = '\0';
        if (!isalnum((unsigned char)buf[0]))
            return (num);
        o = s = buf;
        while (isdigit((unsigned char)*s) || (*s == '.'))
            s++;
        if (*s != '\0') {
            *(s++) = '\0';
            while (isspace((unsigned char)*s))
                s++;
            if (*s == '\0') {
                s = NULL;
            } else {
                l = s;
                while ((*l != '\0') && !isspace((unsigned char)*l))
                    l++;
                if (*l != '\0') {
                    *(l++) = '\0';
                    while (isspace((unsigned char)*l))
                        l++;
                    if (*l == '\0') {
                        l = NULL;
                    }
                } else {
                    l = NULL;
                }
            }
        } else {
            s = NULL;
        }
        if (*o == '\0')
            return num;
        if (!OBJ_create(o, s, l))
            return (num);
        num++;
    }
    /* return(num); */
}

int OBJ_create(const char *oid, const char *sn, const char *ln)
{
    int ok = 0;
    ASN1_OBJECT *op = NULL;
    unsigned char *buf;
    int i;

    i = a2d_ASN1_OBJECT(NULL, 0, oid, -1);
    if (i <= 0)
        return (0);

    if ((buf = (unsigned char *)OPENSSL_malloc(i)) == NULL) {
        OBJerr(OBJ_F_OBJ_CREATE, ERR_R_MALLOC_FAILURE);
        return (0);
    }
    i = a2d_ASN1_OBJECT(buf, i, oid, -1);
    if (i == 0)
        goto err;
    op = (ASN1_OBJECT *)ASN1_OBJECT_create(OBJ_new_nid(1), buf, i, sn, ln);
    if (op == NULL)
        goto err;
    ok = OBJ_add_object(op);
 err:
    ASN1_OBJECT_free(op);
    OPENSSL_free(buf);
    return (ok);
}
/* crypto/objects/obj_err.c */
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
// #include "objects.h"

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

# define ERR_FUNC(func) ERR_PACK(ERR_LIB_OBJ,func,0)
# define ERR_REASON(reason) ERR_PACK(ERR_LIB_OBJ,0,reason)

static ERR_STRING_DATA OBJ_str_functs[] = {
    {ERR_FUNC(OBJ_F_OBJ_ADD_OBJECT), "OBJ_add_object"},
    {ERR_FUNC(OBJ_F_OBJ_CREATE), "OBJ_create"},
    {ERR_FUNC(OBJ_F_OBJ_DUP), "OBJ_dup"},
    {ERR_FUNC(OBJ_F_OBJ_NAME_NEW_INDEX), "OBJ_NAME_new_index"},
    {ERR_FUNC(OBJ_F_OBJ_NID2LN), "OBJ_nid2ln"},
    {ERR_FUNC(OBJ_F_OBJ_NID2OBJ), "OBJ_nid2obj"},
    {ERR_FUNC(OBJ_F_OBJ_NID2SN), "OBJ_nid2sn"},
    {0, NULL}
};

static ERR_STRING_DATA OBJ_str_reasons[] = {
    {ERR_REASON(OBJ_R_MALLOC_FAILURE), "malloc failure"},
    {ERR_REASON(OBJ_R_UNKNOWN_NID), "unknown nid"},
    {0, NULL}
};

#endif

void ERR_load_OBJ_strings(void)
{
#ifndef OPENSSL_NO_ERR

    if (ERR_func_error_string(OBJ_str_functs[0].error) == NULL) {
        ERR_load_strings(0, OBJ_str_functs);
        ERR_load_strings(0, OBJ_str_reasons);
    }
#endif
}
/* crypto/objects/obj_lib.c */
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
// #include "lhash.h"
// #include "objects.h"
#include "buffer.h"

ASN1_OBJECT *OBJ_dup(const ASN1_OBJECT *o)
{
    ASN1_OBJECT *r;
    int i;
    char *ln = NULL, *sn = NULL;
    unsigned char *data = NULL;

    if (o == NULL)
        return (NULL);
    if (!(o->flags & ASN1_OBJECT_FLAG_DYNAMIC))
        return ((ASN1_OBJECT *)o); /* XXX: ugh! Why? What kind of duplication
                                    * is this??? */

    r = ASN1_OBJECT_new();
    if (r == NULL) {
        OBJerr(OBJ_F_OBJ_DUP, ERR_R_ASN1_LIB);
        return (NULL);
    }
    data = OPENSSL_malloc(o->length);
    if (data == NULL)
        goto err;
    if (o->data != NULL)
        memcpy(data, o->data, o->length);
    /* once data attached to object it remains const */
    r->data = data;
    r->length = o->length;
    r->nid = o->nid;
    r->ln = r->sn = NULL;
    if (o->ln != NULL) {
        i = strlen(o->ln) + 1;
        ln = OPENSSL_malloc(i);
        if (ln == NULL)
            goto err;
        memcpy(ln, o->ln, i);
        r->ln = ln;
    }

    if (o->sn != NULL) {
        i = strlen(o->sn) + 1;
        sn = OPENSSL_malloc(i);
        if (sn == NULL)
            goto err;
        memcpy(sn, o->sn, i);
        r->sn = sn;
    }
    r->flags = o->flags | (ASN1_OBJECT_FLAG_DYNAMIC |
                           ASN1_OBJECT_FLAG_DYNAMIC_STRINGS |
                           ASN1_OBJECT_FLAG_DYNAMIC_DATA);
    return (r);
 err:
    OBJerr(OBJ_F_OBJ_DUP, ERR_R_MALLOC_FAILURE);
    if (ln != NULL)
        OPENSSL_free(ln);
    if (sn != NULL)
        OPENSSL_free(sn);
    if (data != NULL)
        OPENSSL_free(data);
    if (r != NULL)
        OPENSSL_free(r);
    return (NULL);
}

int OBJ_cmp(const ASN1_OBJECT *a, const ASN1_OBJECT *b)
{
    int ret;

    ret = (a->length - b->length);
    if (ret)
        return (ret);
    return (memcmp(a->data, b->data, a->length));
}
/* crypto/objects/obj_xref.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2006.
 */
/* ====================================================================
 * Copyright (c) 2006 The OpenSSL Project.  All rights reserved.
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

// #include "objects.h"
#include "obj_xref.h"

DECLARE_STACK_OF(nid_triple)
STACK_OF(nid_triple) *sig_app, *sigx_app;

static int sig_cmp(const nid_triple *a, const nid_triple *b)
{
    return a->sign_id - b->sign_id;
}

DECLARE_OBJ_BSEARCH_CMP_FN(nid_triple, nid_triple, sig);
IMPLEMENT_OBJ_BSEARCH_CMP_FN(nid_triple, nid_triple, sig);

static int sig_sk_cmp(const nid_triple *const *a, const nid_triple *const *b)
{
    return (*a)->sign_id - (*b)->sign_id;
}

DECLARE_OBJ_BSEARCH_CMP_FN(const nid_triple *, const nid_triple *, sigx);

static int sigx_cmp(const nid_triple *const *a, const nid_triple *const *b)
{
    int ret;
    ret = (*a)->hash_id - (*b)->hash_id;
    if (ret)
        return ret;
    return (*a)->pkey_id - (*b)->pkey_id;
}

IMPLEMENT_OBJ_BSEARCH_CMP_FN(const nid_triple *, const nid_triple *, sigx);

int OBJ_find_sigid_algs(int signid, int *pdig_nid, int *ppkey_nid)
{
    nid_triple tmp;
    const nid_triple *rv = NULL;
    tmp.sign_id = signid;

    if (sig_app) {
        int idx = sk_nid_triple_find(sig_app, &tmp);
        if (idx >= 0)
            rv = sk_nid_triple_value(sig_app, idx);
    }
#ifndef OBJ_XREF_TEST2
    if (rv == NULL) {
        rv = OBJ_bsearch_sig(&tmp, sigoid_srt,
                             sizeof(sigoid_srt) / sizeof(nid_triple));
    }
#endif
    if (rv == NULL)
        return 0;
    if (pdig_nid)
        *pdig_nid = rv->hash_id;
    if (ppkey_nid)
        *ppkey_nid = rv->pkey_id;
    return 1;
}

int OBJ_find_sigid_by_algs(int *psignid, int dig_nid, int pkey_nid)
{
    nid_triple tmp;
    const nid_triple *t = &tmp;
    const nid_triple **rv = NULL;

    tmp.hash_id = dig_nid;
    tmp.pkey_id = pkey_nid;

    if (sigx_app) {
        int idx = sk_nid_triple_find(sigx_app, &tmp);
        if (idx >= 0) {
            t = sk_nid_triple_value(sigx_app, idx);
            rv = &t;
        }
    }
#ifndef OBJ_XREF_TEST2
    if (rv == NULL) {
        rv = OBJ_bsearch_sigx(&t, sigoid_srt_xref,
                              sizeof(sigoid_srt_xref) / sizeof(nid_triple *)
            );
    }
#endif
    if (rv == NULL)
        return 0;
    if (psignid)
        *psignid = (*rv)->sign_id;
    return 1;
}

int OBJ_add_sigid(int signid, int dig_id, int pkey_id)
{
    nid_triple *ntr;
    if (!sig_app)
        sig_app = sk_nid_triple_new(sig_sk_cmp);
    if (!sig_app)
        return 0;
    if (!sigx_app)
        sigx_app = sk_nid_triple_new(sigx_cmp);
    if (!sigx_app)
        return 0;
    ntr = OPENSSL_malloc(sizeof(int) * 3);
    if (!ntr)
        return 0;
    ntr->sign_id = signid;
    ntr->hash_id = dig_id;
    ntr->pkey_id = pkey_id;

    if (!sk_nid_triple_push(sig_app, ntr)) {
        OPENSSL_free(ntr);
        return 0;
    }

    if (!sk_nid_triple_push(sigx_app, ntr))
        return 0;

    sk_nid_triple_sort(sig_app);
    sk_nid_triple_sort(sigx_app);

    return 1;
}

static void sid_free(nid_triple *tt)
{
    OPENSSL_free(tt);
}

void OBJ_sigid_free(void)
{
    if (sig_app) {
        sk_nid_triple_pop_free(sig_app, sid_free);
        sig_app = NULL;
    }
    if (sigx_app) {
        sk_nid_triple_free(sigx_app);
        sigx_app = NULL;
    }
}

#ifdef OBJ_XREF_TEST

main()
{
    int n1, n2, n3;

    int i, rv;
# ifdef OBJ_XREF_TEST2
    for (i = 0; i < sizeof(sigoid_srt) / sizeof(nid_triple); i++) {
        OBJ_add_sigid(sigoid_srt[i][0], sigoid_srt[i][1], sigoid_srt[i][2]);
    }
# endif

    for (i = 0; i < sizeof(sigoid_srt) / sizeof(nid_triple); i++) {
        n1 = sigoid_srt[i][0];
        rv = OBJ_find_sigid_algs(n1, &n2, &n3);
        printf("Forward: %d, %s %s %s\n", rv,
               OBJ_nid2ln(n1), OBJ_nid2ln(n2), OBJ_nid2ln(n3));
        n1 = 0;
        rv = OBJ_find_sigid_by_algs(&n1, n2, n3);
        printf("Reverse: %d, %s %s %s\n", rv,
               OBJ_nid2ln(n1), OBJ_nid2ln(n2), OBJ_nid2ln(n3));
    }
}

#endif
