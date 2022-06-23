/* tasn_dec.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2000.
 */
/* ====================================================================
 * Copyright (c) 2000-2018 The OpenSSL Project.  All rights reserved.
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

#include <stddef.h>
#include <string.h>
#include "asn1.h"
#include "asn1t.h"
#include "objects.h"
#include "buffer.h"
#include "err.h"

/*
 * Constructed types with a recursive definition (such as can be found in PKCS7)
 * could eventually exceed the stack given malicious input with excessive
 * recursion. Therefore we limit the stack depth. This is the maximum number of
 * recursive invocations of asn1_item_embed_d2i().
 */
#define ASN1_MAX_CONSTRUCTED_NEST 30

static int asn1_check_eoc(const unsigned char **in, long len);
static int asn1_find_end(const unsigned char **in, long len, char inf);

static int asn1_collect(BUF_MEM *buf, const unsigned char **in, long len,
                        char inf, int tag, int aclass, int depth);

static int collect_data(BUF_MEM *buf, const unsigned char **p, long plen);

static int asn1_check_tlen(long *olen, int *otag, unsigned char *oclass,
                           char *inf, char *cst,
                           const unsigned char **in, long len,
                           int exptag, int expclass, char opt, ASN1_TLC *ctx);

static int asn1_template_ex_d2i(ASN1_VALUE **pval,
                                const unsigned char **in, long len,
                                const ASN1_TEMPLATE *tt, char opt,
                                ASN1_TLC *ctx, int depth);
static int asn1_template_noexp_d2i(ASN1_VALUE **val,
                                   const unsigned char **in, long len,
                                   const ASN1_TEMPLATE *tt, char opt,
                                   ASN1_TLC *ctx, int depth);
static int asn1_d2i_ex_primitive(ASN1_VALUE **pval,
                                 const unsigned char **in, long len,
                                 const ASN1_ITEM *it,
                                 int tag, int aclass, char opt,
                                 ASN1_TLC *ctx);

/* Table to convert tags to bit values, used for MSTRING type */
static const unsigned long tag2bit[32] = {
    /* tags  0 -  3 */
    0, 0, 0, B_ASN1_BIT_STRING,
    /* tags  4- 7 */
    B_ASN1_OCTET_STRING, 0, 0, B_ASN1_UNKNOWN,
    /* tags  8-11 */
    B_ASN1_UNKNOWN, B_ASN1_UNKNOWN, B_ASN1_UNKNOWN, B_ASN1_UNKNOWN,
    /* tags 12-15 */
    B_ASN1_UTF8STRING, B_ASN1_UNKNOWN, B_ASN1_UNKNOWN, B_ASN1_UNKNOWN,
    /* tags 16-19 */
    B_ASN1_SEQUENCE, 0, B_ASN1_NUMERICSTRING, B_ASN1_PRINTABLESTRING,
    /* tags 20-22 */
    B_ASN1_T61STRING, B_ASN1_VIDEOTEXSTRING, B_ASN1_IA5STRING,
    /* tags 23-24 */
    B_ASN1_UTCTIME, B_ASN1_GENERALIZEDTIME,
    /* tags 25-27 */
    B_ASN1_GRAPHICSTRING, B_ASN1_ISO64STRING, B_ASN1_GENERALSTRING,
    /* tags 28-31 */
    B_ASN1_UNIVERSALSTRING, B_ASN1_UNKNOWN, B_ASN1_BMPSTRING, B_ASN1_UNKNOWN,
};

unsigned long ASN1_tag2bit(int tag)
{
    if ((tag < 0) || (tag > 30))
        return 0;
    return tag2bit[tag];
}

/* Macro to initialize and invalidate the cache */

#define asn1_tlc_clear(c)       if (c) (c)->valid = 0
/* Version to avoid compiler warning about 'c' always non-NULL */
#define asn1_tlc_clear_nc(c)    (c)->valid = 0

/*
 * Decode an ASN1 item, this currently behaves just like a standard 'd2i'
 * function. 'in' points to a buffer to read the data from, in future we
 * will have more advanced versions that can input data a piece at a time and
 * this will simply be a special case.
 */

ASN1_VALUE *ASN1_item_d2i(ASN1_VALUE **pval,
                          const unsigned char **in, long len,
                          const ASN1_ITEM *it)
{
    ASN1_TLC c;
    ASN1_VALUE *ptmpval = NULL;
    if (!pval)
        pval = &ptmpval;
    asn1_tlc_clear_nc(&c);
    if (ASN1_item_ex_d2i(pval, in, len, it, -1, 0, 0, &c) > 0)
        return *pval;
    return NULL;
}

int ASN1_template_d2i(ASN1_VALUE **pval,
                      const unsigned char **in, long len,
                      const ASN1_TEMPLATE *tt)
{
    ASN1_TLC c;
    asn1_tlc_clear_nc(&c);
    return asn1_template_ex_d2i(pval, in, len, tt, 0, &c, 0);
}

/*
 * Decode an item, taking care of IMPLICIT tagging, if any. If 'opt' set and
 * tag mismatch return -1 to handle OPTIONAL
 */
static int asn1_item_ex_d2i(ASN1_VALUE **pval, const unsigned char **in,
                            long len, const ASN1_ITEM *it, int tag, int aclass,
                            char opt, ASN1_TLC *ctx, int depth)
{
    const ASN1_TEMPLATE *tt, *errtt = NULL;
    const ASN1_COMPAT_FUNCS *cf;
    const ASN1_EXTERN_FUNCS *ef;
    const ASN1_AUX *aux = it->funcs;
    ASN1_aux_cb *asn1_cb;
    const unsigned char *p = NULL, *q;
    unsigned char *wp = NULL;   /* BIG FAT WARNING! BREAKS CONST WHERE USED */
    unsigned char imphack = 0, oclass;
    char seq_eoc, seq_nolen, cst, isopt;
    long tmplen;
    int i;
    int otag;
    int ret = 0;
    ASN1_VALUE **pchptr, *ptmpval;
    int combine = aclass & ASN1_TFLG_COMBINE;
    aclass &= ~ASN1_TFLG_COMBINE;
    if (!pval)
        return 0;
    if (aux && aux->asn1_cb)
        asn1_cb = aux->asn1_cb;
    else
        asn1_cb = 0;

    if (++depth > ASN1_MAX_CONSTRUCTED_NEST) {
        ASN1err(ASN1_F_ASN1_ITEM_EX_D2I, ASN1_R_NESTED_TOO_DEEP);
        goto err;
    }

    switch (it->itype) {
    case ASN1_ITYPE_PRIMITIVE:
        if (it->templates) {
            /*
             * tagging or OPTIONAL is currently illegal on an item template
             * because the flags can't get passed down. In practice this
             * isn't a problem: we include the relevant flags from the item
             * template in the template itself.
             */
            if ((tag != -1) || opt) {
                ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
                        ASN1_R_ILLEGAL_OPTIONS_ON_ITEM_TEMPLATE);
                goto err;
            }
            return asn1_template_ex_d2i(pval, in, len,
                                        it->templates, opt, ctx, depth);
        }
        return asn1_d2i_ex_primitive(pval, in, len, it,
                                     tag, aclass, opt, ctx);
        break;

    case ASN1_ITYPE_MSTRING:
        p = *in;
        /* Just read in tag and class */
        ret = asn1_check_tlen(NULL, &otag, &oclass, NULL, NULL,
                              &p, len, -1, 0, 1, ctx);
        if (!ret) {
            ASN1err(ASN1_F_ASN1_ITEM_EX_D2I, ERR_R_NESTED_ASN1_ERROR);
            goto err;
        }

        /* Must be UNIVERSAL class */
        if (oclass != V_ASN1_UNIVERSAL) {
            /* If OPTIONAL, assume this is OK */
            if (opt)
                return -1;
            ASN1err(ASN1_F_ASN1_ITEM_EX_D2I, ASN1_R_MSTRING_NOT_UNIVERSAL);
            goto err;
        }
        /* Check tag matches bit map */
        if (!(ASN1_tag2bit(otag) & it->utype)) {
            /* If OPTIONAL, assume this is OK */
            if (opt)
                return -1;
            ASN1err(ASN1_F_ASN1_ITEM_EX_D2I, ASN1_R_MSTRING_WRONG_TAG);
            goto err;
        }
        return asn1_d2i_ex_primitive(pval, in, len, it, otag, 0, 0, ctx);

    case ASN1_ITYPE_EXTERN:
        /* Use new style d2i */
        ef = it->funcs;
        return ef->asn1_ex_d2i(pval, in, len, it, tag, aclass, opt, ctx);

    case ASN1_ITYPE_COMPAT:
        /* we must resort to old style evil hackery */
        cf = it->funcs;

        /* If OPTIONAL see if it is there */
        if (opt) {
            int exptag;
            p = *in;
            if (tag == -1)
                exptag = it->utype;
            else
                exptag = tag;
            /*
             * Don't care about anything other than presence of expected tag
             */

            ret = asn1_check_tlen(NULL, NULL, NULL, NULL, NULL,
                                  &p, len, exptag, aclass, 1, ctx);
            if (!ret) {
                ASN1err(ASN1_F_ASN1_ITEM_EX_D2I, ERR_R_NESTED_ASN1_ERROR);
                goto err;
            }
            if (ret == -1)
                return -1;
        }

        /*
         * This is the old style evil hack IMPLICIT handling: since the
         * underlying code is expecting a tag and class other than the one
         * present we change the buffer temporarily then change it back
         * afterwards. This doesn't and never did work for tags > 30. Yes
         * this is *horrible* but it is only needed for old style d2i which
         * will hopefully not be around for much longer. FIXME: should copy
         * the buffer then modify it so the input buffer can be const: we
         * should *always* copy because the old style d2i might modify the
         * buffer.
         */

        if (tag != -1) {
            wp = *(unsigned char **)in;
            imphack = *wp;
            if (p == NULL) {
                ASN1err(ASN1_F_ASN1_ITEM_EX_D2I, ERR_R_NESTED_ASN1_ERROR);
                goto err;
            }
            *wp = (unsigned char)((*p & V_ASN1_CONSTRUCTED)
                                  | it->utype);
        }

        ptmpval = cf->asn1_d2i(pval, in, len);

        if (tag != -1)
            *wp = imphack;

        if (ptmpval)
            return 1;

        ASN1err(ASN1_F_ASN1_ITEM_EX_D2I, ERR_R_NESTED_ASN1_ERROR);
        goto err;

    case ASN1_ITYPE_CHOICE:
        if (asn1_cb && !asn1_cb(ASN1_OP_D2I_PRE, pval, it, NULL))
            goto auxerr;
        if (*pval) {
            /* Free up and zero CHOICE value if initialised */
            i = asn1_get_choice_selector(pval, it);
            if ((i >= 0) && (i < it->tcount)) {
                tt = it->templates + i;
                pchptr = asn1_get_field_ptr(pval, tt);
                ASN1_template_free(pchptr, tt);
                asn1_set_choice_selector(pval, -1, it);
            }
        } else if (!ASN1_item_ex_new(pval, it)) {
            ASN1err(ASN1_F_ASN1_ITEM_EX_D2I, ERR_R_NESTED_ASN1_ERROR);
            goto err;
        }
        /* CHOICE type, try each possibility in turn */
        p = *in;
        for (i = 0, tt = it->templates; i < it->tcount; i++, tt++) {
            pchptr = asn1_get_field_ptr(pval, tt);
            /*
             * We mark field as OPTIONAL so its absence can be recognised.
             */
            ret = asn1_template_ex_d2i(pchptr, &p, len, tt, 1, ctx, depth);
            /* If field not present, try the next one */
            if (ret == -1)
                continue;
            /* If positive return, read OK, break loop */
            if (ret > 0)
                break;
            /* Otherwise must be an ASN1 parsing error */
            errtt = tt;
            ASN1err(ASN1_F_ASN1_ITEM_EX_D2I, ERR_R_NESTED_ASN1_ERROR);
            goto err;
        }

        /* Did we fall off the end without reading anything? */
        if (i == it->tcount) {
            /* If OPTIONAL, this is OK */
            if (opt) {
                /* Free and zero it */
                ASN1_item_ex_free(pval, it);
                return -1;
            }
            ASN1err(ASN1_F_ASN1_ITEM_EX_D2I, ASN1_R_NO_MATCHING_CHOICE_TYPE);
            goto err;
        }

        asn1_set_choice_selector(pval, i, it);
        if (asn1_cb && !asn1_cb(ASN1_OP_D2I_POST, pval, it, NULL))
            goto auxerr;
        *in = p;
        return 1;

    case ASN1_ITYPE_NDEF_SEQUENCE:
    case ASN1_ITYPE_SEQUENCE:
        p = *in;
        tmplen = len;

        /* If no IMPLICIT tagging set to SEQUENCE, UNIVERSAL */
        if (tag == -1) {
            tag = V_ASN1_SEQUENCE;
            aclass = V_ASN1_UNIVERSAL;
        }
        /* Get SEQUENCE length and update len, p */
        ret = asn1_check_tlen(&len, NULL, NULL, &seq_eoc, &cst,
                              &p, len, tag, aclass, opt, ctx);
        if (!ret) {
            ASN1err(ASN1_F_ASN1_ITEM_EX_D2I, ERR_R_NESTED_ASN1_ERROR);
            goto err;
        } else if (ret == -1)
            return -1;
        if (aux && (aux->flags & ASN1_AFLG_BROKEN)) {
            len = tmplen - (p - *in);
            seq_nolen = 1;
        }
        /* If indefinite we don't do a length check */
        else
            seq_nolen = seq_eoc;
        if (!cst) {
            ASN1err(ASN1_F_ASN1_ITEM_EX_D2I, ASN1_R_SEQUENCE_NOT_CONSTRUCTED);
            goto err;
        }

        if (!*pval && !ASN1_item_ex_new(pval, it)) {
            ASN1err(ASN1_F_ASN1_ITEM_EX_D2I, ERR_R_NESTED_ASN1_ERROR);
            goto err;
        }

        if (asn1_cb && !asn1_cb(ASN1_OP_D2I_PRE, pval, it, NULL))
            goto auxerr;

        /* Free up and zero any ADB found */
        for (i = 0, tt = it->templates; i < it->tcount; i++, tt++) {
            if (tt->flags & ASN1_TFLG_ADB_MASK) {
                const ASN1_TEMPLATE *seqtt;
                ASN1_VALUE **pseqval;
                seqtt = asn1_do_adb(pval, tt, 0);
                if (seqtt == NULL)
                    continue;
                pseqval = asn1_get_field_ptr(pval, seqtt);
                ASN1_template_free(pseqval, seqtt);
            }
        }

        /* Get each field entry */
        for (i = 0, tt = it->templates; i < it->tcount; i++, tt++) {
            const ASN1_TEMPLATE *seqtt;
            ASN1_VALUE **pseqval;
            seqtt = asn1_do_adb(pval, tt, 1);
            if (seqtt == NULL)
                goto err;
            pseqval = asn1_get_field_ptr(pval, seqtt);
            /* Have we ran out of data? */
            if (!len)
                break;
            q = p;
            if (asn1_check_eoc(&p, len)) {
                if (!seq_eoc) {
                    ASN1err(ASN1_F_ASN1_ITEM_EX_D2I, ASN1_R_UNEXPECTED_EOC);
                    goto err;
                }
                len -= p - q;
                seq_eoc = 0;
                q = p;
                break;
            }
            /*
             * This determines the OPTIONAL flag value. The field cannot be
             * omitted if it is the last of a SEQUENCE and there is still
             * data to be read. This isn't strictly necessary but it
             * increases efficiency in some cases.
             */
            if (i == (it->tcount - 1))
                isopt = 0;
            else
                isopt = (char)(seqtt->flags & ASN1_TFLG_OPTIONAL);
            /*
             * attempt to read in field, allowing each to be OPTIONAL
             */

            ret = asn1_template_ex_d2i(pseqval, &p, len, seqtt, isopt, ctx,
                                       depth);
            if (!ret) {
                errtt = seqtt;
                goto err;
            } else if (ret == -1) {
                /*
                 * OPTIONAL component absent. Free and zero the field.
                 */
                ASN1_template_free(pseqval, seqtt);
                continue;
            }
            /* Update length */
            len -= p - q;
        }

        /* Check for EOC if expecting one */
        if (seq_eoc && !asn1_check_eoc(&p, len)) {
            ASN1err(ASN1_F_ASN1_ITEM_EX_D2I, ASN1_R_MISSING_EOC);
            goto err;
        }
        /* Check all data read */
        if (!seq_nolen && len) {
            ASN1err(ASN1_F_ASN1_ITEM_EX_D2I, ASN1_R_SEQUENCE_LENGTH_MISMATCH);
            goto err;
        }

        /*
         * If we get here we've got no more data in the SEQUENCE, however we
         * may not have read all fields so check all remaining are OPTIONAL
         * and clear any that are.
         */
        for (; i < it->tcount; tt++, i++) {
            const ASN1_TEMPLATE *seqtt;
            seqtt = asn1_do_adb(pval, tt, 1);
            if (seqtt == NULL)
                goto err;
            if (seqtt->flags & ASN1_TFLG_OPTIONAL) {
                ASN1_VALUE **pseqval;
                pseqval = asn1_get_field_ptr(pval, seqtt);
                ASN1_template_free(pseqval, seqtt);
            } else {
                errtt = seqtt;
                ASN1err(ASN1_F_ASN1_ITEM_EX_D2I, ASN1_R_FIELD_MISSING);
                goto err;
            }
        }
        /* Save encoding */
        if (!asn1_enc_save(pval, *in, p - *in, it))
            goto auxerr;
        if (asn1_cb && !asn1_cb(ASN1_OP_D2I_POST, pval, it, NULL))
            goto auxerr;
        *in = p;
        return 1;

    default:
        return 0;
    }
 auxerr:
    ASN1err(ASN1_F_ASN1_ITEM_EX_D2I, ASN1_R_AUX_ERROR);
 err:
    if (combine == 0)
        ASN1_item_ex_free(pval, it);
    if (errtt)
        ERR_add_error_data(4, "Field=", errtt->field_name,
                           ", Type=", it->sname);
    else
        ERR_add_error_data(2, "Type=", it->sname);
    return 0;
}

int ASN1_item_ex_d2i(ASN1_VALUE **pval, const unsigned char **in, long len,
                     const ASN1_ITEM *it,
                     int tag, int aclass, char opt, ASN1_TLC *ctx)
{
    return asn1_item_ex_d2i(pval, in, len, it, tag, aclass, opt, ctx, 0);
}

/*
 * Templates are handled with two separate functions. One handles any
 * EXPLICIT tag and the other handles the rest.
 */

static int asn1_template_ex_d2i(ASN1_VALUE **val,
                                const unsigned char **in, long inlen,
                                const ASN1_TEMPLATE *tt, char opt,
                                ASN1_TLC *ctx, int depth)
{
    int flags, aclass;
    int ret;
    long len;
    const unsigned char *p, *q;
    char exp_eoc;
    if (!val)
        return 0;
    flags = tt->flags;
    aclass = flags & ASN1_TFLG_TAG_CLASS;

    p = *in;

    /* Check if EXPLICIT tag expected */
    if (flags & ASN1_TFLG_EXPTAG) {
        char cst;
        /*
         * Need to work out amount of data available to the inner content and
         * where it starts: so read in EXPLICIT header to get the info.
         */
        ret = asn1_check_tlen(&len, NULL, NULL, &exp_eoc, &cst,
                              &p, inlen, tt->tag, aclass, opt, ctx);
        q = p;
        if (!ret) {
            ASN1err(ASN1_F_ASN1_TEMPLATE_EX_D2I, ERR_R_NESTED_ASN1_ERROR);
            return 0;
        } else if (ret == -1)
            return -1;
        if (!cst) {
            ASN1err(ASN1_F_ASN1_TEMPLATE_EX_D2I,
                    ASN1_R_EXPLICIT_TAG_NOT_CONSTRUCTED);
            return 0;
        }
        /* We've found the field so it can't be OPTIONAL now */
        ret = asn1_template_noexp_d2i(val, &p, len, tt, 0, ctx, depth);
        if (!ret) {
            ASN1err(ASN1_F_ASN1_TEMPLATE_EX_D2I, ERR_R_NESTED_ASN1_ERROR);
            return 0;
        }
        /* We read the field in OK so update length */
        len -= p - q;
        if (exp_eoc) {
            /* If NDEF we must have an EOC here */
            if (!asn1_check_eoc(&p, len)) {
                ASN1err(ASN1_F_ASN1_TEMPLATE_EX_D2I, ASN1_R_MISSING_EOC);
                goto err;
            }
        } else {
            /*
             * Otherwise we must hit the EXPLICIT tag end or its an error
             */
            if (len) {
                ASN1err(ASN1_F_ASN1_TEMPLATE_EX_D2I,
                        ASN1_R_EXPLICIT_LENGTH_MISMATCH);
                goto err;
            }
        }
    } else
        return asn1_template_noexp_d2i(val, in, inlen, tt, opt, ctx, depth);

    *in = p;
    return 1;

 err:
    ASN1_template_free(val, tt);
    return 0;
}

static int asn1_template_noexp_d2i(ASN1_VALUE **val,
                                   const unsigned char **in, long len,
                                   const ASN1_TEMPLATE *tt, char opt,
                                   ASN1_TLC *ctx, int depth)
{
    int flags, aclass;
    int ret;
    const unsigned char *p, *q;
    if (!val)
        return 0;
    flags = tt->flags;
    aclass = flags & ASN1_TFLG_TAG_CLASS;

    p = *in;
    q = p;

    if (flags & ASN1_TFLG_SK_MASK) {
        /* SET OF, SEQUENCE OF */
        int sktag, skaclass;
        char sk_eoc;
        /* First work out expected inner tag value */
        if (flags & ASN1_TFLG_IMPTAG) {
            sktag = tt->tag;
            skaclass = aclass;
        } else {
            skaclass = V_ASN1_UNIVERSAL;
            if (flags & ASN1_TFLG_SET_OF)
                sktag = V_ASN1_SET;
            else
                sktag = V_ASN1_SEQUENCE;
        }
        /* Get the tag */
        ret = asn1_check_tlen(&len, NULL, NULL, &sk_eoc, NULL,
                              &p, len, sktag, skaclass, opt, ctx);
        if (!ret) {
            ASN1err(ASN1_F_ASN1_TEMPLATE_NOEXP_D2I, ERR_R_NESTED_ASN1_ERROR);
            return 0;
        } else if (ret == -1)
            return -1;
        if (!*val)
            *val = (ASN1_VALUE *)sk_new_null();
        else {
            /*
             * We've got a valid STACK: free up any items present
             */
            STACK_OF(ASN1_VALUE) *sktmp = (STACK_OF(ASN1_VALUE) *)*val;
            ASN1_VALUE *vtmp;
            while (sk_ASN1_VALUE_num(sktmp) > 0) {
                vtmp = sk_ASN1_VALUE_pop(sktmp);
                ASN1_item_ex_free(&vtmp, ASN1_ITEM_ptr(tt->item));
            }
        }

        if (!*val) {
            ASN1err(ASN1_F_ASN1_TEMPLATE_NOEXP_D2I, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        /* Read as many items as we can */
        while (len > 0) {
            ASN1_VALUE *skfield;
            q = p;
            /* See if EOC found */
            if (asn1_check_eoc(&p, len)) {
                if (!sk_eoc) {
                    ASN1err(ASN1_F_ASN1_TEMPLATE_NOEXP_D2I,
                            ASN1_R_UNEXPECTED_EOC);
                    goto err;
                }
                len -= p - q;
                sk_eoc = 0;
                break;
            }
            skfield = NULL;
            if (!asn1_item_ex_d2i(&skfield, &p, len, ASN1_ITEM_ptr(tt->item),
                                  -1, 0, 0, ctx, depth)) {
                ASN1err(ASN1_F_ASN1_TEMPLATE_NOEXP_D2I,
                        ERR_R_NESTED_ASN1_ERROR);
                goto err;
            }
            len -= p - q;
            if (!sk_ASN1_VALUE_push((STACK_OF(ASN1_VALUE) *)*val, skfield)) {
                ASN1_item_ex_free(&skfield, ASN1_ITEM_ptr(tt->item));
                ASN1err(ASN1_F_ASN1_TEMPLATE_NOEXP_D2I, ERR_R_MALLOC_FAILURE);
                goto err;
            }
        }
        if (sk_eoc) {
            ASN1err(ASN1_F_ASN1_TEMPLATE_NOEXP_D2I, ASN1_R_MISSING_EOC);
            goto err;
        }
    } else if (flags & ASN1_TFLG_IMPTAG) {
        /* IMPLICIT tagging */
        ret = asn1_item_ex_d2i(val, &p, len, ASN1_ITEM_ptr(tt->item), tt->tag,
                               aclass, opt, ctx, depth);
        if (!ret) {
            ASN1err(ASN1_F_ASN1_TEMPLATE_NOEXP_D2I, ERR_R_NESTED_ASN1_ERROR);
            goto err;
        } else if (ret == -1)
            return -1;
    } else {
        /* Nothing special */
        ret = asn1_item_ex_d2i(val, &p, len, ASN1_ITEM_ptr(tt->item),
                               -1, tt->flags & ASN1_TFLG_COMBINE, opt, ctx,
                               depth);
        if (!ret) {
            ASN1err(ASN1_F_ASN1_TEMPLATE_NOEXP_D2I, ERR_R_NESTED_ASN1_ERROR);
            goto err;
        } else if (ret == -1)
            return -1;
    }

    *in = p;
    return 1;

 err:
    ASN1_template_free(val, tt);
    return 0;
}

static int asn1_d2i_ex_primitive(ASN1_VALUE **pval,
                                 const unsigned char **in, long inlen,
                                 const ASN1_ITEM *it,
                                 int tag, int aclass, char opt, ASN1_TLC *ctx)
{
    int ret = 0, utype;
    long plen;
    char cst, inf, free_cont = 0;
    const unsigned char *p;
    BUF_MEM buf = { 0, NULL, 0 };
    const unsigned char *cont = NULL;
    long len;
    if (!pval) {
        ASN1err(ASN1_F_ASN1_D2I_EX_PRIMITIVE, ASN1_R_ILLEGAL_NULL);
        return 0;               /* Should never happen */
    }

    if (it->itype == ASN1_ITYPE_MSTRING) {
        utype = tag;
        tag = -1;
    } else
        utype = it->utype;

    if (utype == V_ASN1_ANY) {
        /* If type is ANY need to figure out type from tag */
        unsigned char oclass;
        if (tag >= 0) {
            ASN1err(ASN1_F_ASN1_D2I_EX_PRIMITIVE, ASN1_R_ILLEGAL_TAGGED_ANY);
            return 0;
        }
        if (opt) {
            ASN1err(ASN1_F_ASN1_D2I_EX_PRIMITIVE,
                    ASN1_R_ILLEGAL_OPTIONAL_ANY);
            return 0;
        }
        p = *in;
        ret = asn1_check_tlen(NULL, &utype, &oclass, NULL, NULL,
                              &p, inlen, -1, 0, 0, ctx);
        if (!ret) {
            ASN1err(ASN1_F_ASN1_D2I_EX_PRIMITIVE, ERR_R_NESTED_ASN1_ERROR);
            return 0;
        }
        if (oclass != V_ASN1_UNIVERSAL)
            utype = V_ASN1_OTHER;
    }
    if (tag == -1) {
        tag = utype;
        aclass = V_ASN1_UNIVERSAL;
    }
    p = *in;
    /* Check header */
    ret = asn1_check_tlen(&plen, NULL, NULL, &inf, &cst,
                          &p, inlen, tag, aclass, opt, ctx);
    if (!ret) {
        ASN1err(ASN1_F_ASN1_D2I_EX_PRIMITIVE, ERR_R_NESTED_ASN1_ERROR);
        return 0;
    } else if (ret == -1)
        return -1;
    ret = 0;
    /* SEQUENCE, SET and "OTHER" are left in encoded form */
    if ((utype == V_ASN1_SEQUENCE)
        || (utype == V_ASN1_SET) || (utype == V_ASN1_OTHER)) {
        /*
         * Clear context cache for type OTHER because the auto clear when we
         * have a exact match wont work
         */
        if (utype == V_ASN1_OTHER) {
            asn1_tlc_clear(ctx);
        }
        /* SEQUENCE and SET must be constructed */
        else if (!cst) {
            ASN1err(ASN1_F_ASN1_D2I_EX_PRIMITIVE,
                    ASN1_R_TYPE_NOT_CONSTRUCTED);
            return 0;
        }

        cont = *in;
        /* If indefinite length constructed find the real end */
        if (inf) {
            if (!asn1_find_end(&p, plen, inf))
                goto err;
            len = p - cont;
        } else {
            len = p - cont + plen;
            p += plen;
        }
    } else if (cst) {
        if (utype == V_ASN1_NULL || utype == V_ASN1_BOOLEAN
            || utype == V_ASN1_OBJECT || utype == V_ASN1_INTEGER
            || utype == V_ASN1_ENUMERATED) {
            ASN1err(ASN1_F_ASN1_D2I_EX_PRIMITIVE, ASN1_R_TYPE_NOT_PRIMITIVE);
            return 0;
        }

        /* Free any returned 'buf' content */
        free_cont = 1;
        /*
         * Should really check the internal tags are correct but some things
         * may get this wrong. The relevant specs say that constructed string
         * types should be OCTET STRINGs internally irrespective of the type.
         * So instead just check for UNIVERSAL class and ignore the tag.
         */
        if (!asn1_collect(&buf, &p, plen, inf, -1, V_ASN1_UNIVERSAL, 0)) {
            goto err;
        }
        len = buf.length;
        /* Append a final null to string */
        if (!BUF_MEM_grow_clean(&buf, len + 1)) {
            ASN1err(ASN1_F_ASN1_D2I_EX_PRIMITIVE, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        buf.data[len] = 0;
        cont = (const unsigned char *)buf.data;
    } else {
        cont = p;
        len = plen;
        p += plen;
    }

    /* We now have content length and type: translate into a structure */
    /* asn1_ex_c2i may reuse allocated buffer, and so sets free_cont to 0 */
    if (!asn1_ex_c2i(pval, cont, len, utype, &free_cont, it))
        goto err;

    *in = p;
    ret = 1;
 err:
    if (free_cont && buf.data)
        OPENSSL_free(buf.data);
    return ret;
}

/* Translate ASN1 content octets into a structure */

int asn1_ex_c2i(ASN1_VALUE **pval, const unsigned char *cont, int len,
                int utype, char *free_cont, const ASN1_ITEM *it)
{
    ASN1_VALUE **opval = NULL;
    ASN1_STRING *stmp;
    ASN1_TYPE *typ = NULL;
    int ret = 0;
    const ASN1_PRIMITIVE_FUNCS *pf;
    ASN1_INTEGER **tint;
    pf = it->funcs;

    if (pf && pf->prim_c2i)
        return pf->prim_c2i(pval, cont, len, utype, free_cont, it);
    /* If ANY type clear type and set pointer to internal value */
    if (it->utype == V_ASN1_ANY) {
        if (!*pval) {
            typ = ASN1_TYPE_new();
            if (typ == NULL)
                goto err;
            *pval = (ASN1_VALUE *)typ;
        } else
            typ = (ASN1_TYPE *)*pval;

        if (utype != typ->type)
            ASN1_TYPE_set(typ, utype, NULL);
        opval = pval;
        pval = &typ->value.asn1_value;
    }
    switch (utype) {
    case V_ASN1_OBJECT:
        if (!c2i_ASN1_OBJECT((ASN1_OBJECT **)pval, &cont, len))
            goto err;
        break;

    case V_ASN1_NULL:
        if (len) {
            ASN1err(ASN1_F_ASN1_EX_C2I, ASN1_R_NULL_IS_WRONG_LENGTH);
            goto err;
        }
        *pval = (ASN1_VALUE *)1;
        break;

    case V_ASN1_BOOLEAN:
        if (len != 1) {
            ASN1err(ASN1_F_ASN1_EX_C2I, ASN1_R_BOOLEAN_IS_WRONG_LENGTH);
            goto err;
        } else {
            ASN1_BOOLEAN *tbool;
            tbool = (ASN1_BOOLEAN *)pval;
            *tbool = *cont;
        }
        break;

    case V_ASN1_BIT_STRING:
        if (!c2i_ASN1_BIT_STRING((ASN1_BIT_STRING **)pval, &cont, len))
            goto err;
        break;

    case V_ASN1_INTEGER:
    case V_ASN1_ENUMERATED:
        tint = (ASN1_INTEGER **)pval;
        if (!c2i_ASN1_INTEGER(tint, &cont, len))
            goto err;
        /* Fixup type to match the expected form */
        (*tint)->type = utype | ((*tint)->type & V_ASN1_NEG);
        break;

    case V_ASN1_OCTET_STRING:
    case V_ASN1_NUMERICSTRING:
    case V_ASN1_PRINTABLESTRING:
    case V_ASN1_T61STRING:
    case V_ASN1_VIDEOTEXSTRING:
    case V_ASN1_IA5STRING:
    case V_ASN1_UTCTIME:
    case V_ASN1_GENERALIZEDTIME:
    case V_ASN1_GRAPHICSTRING:
    case V_ASN1_VISIBLESTRING:
    case V_ASN1_GENERALSTRING:
    case V_ASN1_UNIVERSALSTRING:
    case V_ASN1_BMPSTRING:
    case V_ASN1_UTF8STRING:
    case V_ASN1_OTHER:
    case V_ASN1_SET:
    case V_ASN1_SEQUENCE:
    default:
        if (utype == V_ASN1_BMPSTRING && (len & 1)) {
            ASN1err(ASN1_F_ASN1_EX_C2I, ASN1_R_BMPSTRING_IS_WRONG_LENGTH);
            goto err;
        }
        if (utype == V_ASN1_UNIVERSALSTRING && (len & 3)) {
            ASN1err(ASN1_F_ASN1_EX_C2I,
                    ASN1_R_UNIVERSALSTRING_IS_WRONG_LENGTH);
            goto err;
        }
        /* All based on ASN1_STRING and handled the same */
        if (!*pval) {
            stmp = ASN1_STRING_type_new(utype);
            if (!stmp) {
                ASN1err(ASN1_F_ASN1_EX_C2I, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            *pval = (ASN1_VALUE *)stmp;
        } else {
            stmp = (ASN1_STRING *)*pval;
            stmp->type = utype;
        }
        /* If we've already allocated a buffer use it */
        if (*free_cont) {
            if (stmp->data)
                OPENSSL_free(stmp->data);
            stmp->data = (unsigned char *)cont; /* UGLY CAST! RL */
            stmp->length = len;
            *free_cont = 0;
        } else {
            if (!ASN1_STRING_set(stmp, cont, len)) {
                ASN1err(ASN1_F_ASN1_EX_C2I, ERR_R_MALLOC_FAILURE);
                ASN1_STRING_free(stmp);
                *pval = NULL;
                goto err;
            }
        }
        break;
    }
    /* If ASN1_ANY and NULL type fix up value */
    if (typ && (utype == V_ASN1_NULL))
        typ->value.ptr = NULL;

    ret = 1;
 err:
    if (!ret) {
        ASN1_TYPE_free(typ);
        if (opval)
            *opval = NULL;
    }
    return ret;
}

/*
 * This function finds the end of an ASN1 structure when passed its maximum
 * length, whether it is indefinite length and a pointer to the content. This
 * is more efficient than calling asn1_collect because it does not recurse on
 * each indefinite length header.
 */

static int asn1_find_end(const unsigned char **in, long len, char inf)
{
    int expected_eoc;
    long plen;
    const unsigned char *p = *in, *q;
    /* If not indefinite length constructed just add length */
    if (inf == 0) {
        *in += len;
        return 1;
    }
    expected_eoc = 1;
    /*
     * Indefinite length constructed form. Find the end when enough EOCs are
     * found. If more indefinite length constructed headers are encountered
     * increment the expected eoc count otherwise just skip to the end of the
     * data.
     */
    while (len > 0) {
        if (asn1_check_eoc(&p, len)) {
            expected_eoc--;
            if (expected_eoc == 0)
                break;
            len -= 2;
            continue;
        }
        q = p;
        /* Just read in a header: only care about the length */
        if (!asn1_check_tlen(&plen, NULL, NULL, &inf, NULL, &p, len,
                             -1, 0, 0, NULL)) {
            ASN1err(ASN1_F_ASN1_FIND_END, ERR_R_NESTED_ASN1_ERROR);
            return 0;
        }
        if (inf)
            expected_eoc++;
        else
            p += plen;
        len -= p - q;
    }
    if (expected_eoc) {
        ASN1err(ASN1_F_ASN1_FIND_END, ASN1_R_MISSING_EOC);
        return 0;
    }
    *in = p;
    return 1;
}

/*
 * This function collects the asn1 data from a constructred string type into
 * a buffer. The values of 'in' and 'len' should refer to the contents of the
 * constructed type and 'inf' should be set if it is indefinite length.
 */

#ifndef ASN1_MAX_STRING_NEST
/*
 * This determines how many levels of recursion are permitted in ASN1 string
 * types. If it is not limited stack overflows can occur. If set to zero no
 * recursion is allowed at all. Although zero should be adequate examples
 * exist that require a value of 1. So 5 should be more than enough.
 */
# define ASN1_MAX_STRING_NEST 5
#endif

static int asn1_collect(BUF_MEM *buf, const unsigned char **in, long len,
                        char inf, int tag, int aclass, int depth)
{
    const unsigned char *p, *q;
    long plen;
    char cst, ininf;
    p = *in;
    inf &= 1;
    /*
     * If no buffer and not indefinite length constructed just pass over the
     * encoded data
     */
    if (!buf && !inf) {
        *in += len;
        return 1;
    }
    while (len > 0) {
        q = p;
        /* Check for EOC */
        if (asn1_check_eoc(&p, len)) {
            /*
             * EOC is illegal outside indefinite length constructed form
             */
            if (!inf) {
                ASN1err(ASN1_F_ASN1_COLLECT, ASN1_R_UNEXPECTED_EOC);
                return 0;
            }
            inf = 0;
            break;
        }

        if (!asn1_check_tlen(&plen, NULL, NULL, &ininf, &cst, &p,
                             len, tag, aclass, 0, NULL)) {
            ASN1err(ASN1_F_ASN1_COLLECT, ERR_R_NESTED_ASN1_ERROR);
            return 0;
        }

        /* If indefinite length constructed update max length */
        if (cst) {
            if (depth >= ASN1_MAX_STRING_NEST) {
                ASN1err(ASN1_F_ASN1_COLLECT, ASN1_R_NESTED_ASN1_STRING);
                return 0;
            }
            if (!asn1_collect(buf, &p, plen, ininf, tag, aclass, depth + 1))
                return 0;
        } else if (plen && !collect_data(buf, &p, plen))
            return 0;
        len -= p - q;
    }
    if (inf) {
        ASN1err(ASN1_F_ASN1_COLLECT, ASN1_R_MISSING_EOC);
        return 0;
    }
    *in = p;
    return 1;
}

static int collect_data(BUF_MEM *buf, const unsigned char **p, long plen)
{
    int len;
    if (buf) {
        len = buf->length;
        if (!BUF_MEM_grow_clean(buf, len + plen)) {
            ASN1err(ASN1_F_COLLECT_DATA, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        memcpy(buf->data + len, *p, plen);
    }
    *p += plen;
    return 1;
}

/* Check for ASN1 EOC and swallow it if found */

static int asn1_check_eoc(const unsigned char **in, long len)
{
    const unsigned char *p;
    if (len < 2)
        return 0;
    p = *in;
    if (!p[0] && !p[1]) {
        *in += 2;
        return 1;
    }
    return 0;
}

/*
 * Check an ASN1 tag and length: a bit like ASN1_get_object but it sets the
 * length for indefinite length constructed form, we don't know the exact
 * length but we can set an upper bound to the amount of data available minus
 * the header length just read.
 */

static int asn1_check_tlen(long *olen, int *otag, unsigned char *oclass,
                           char *inf, char *cst,
                           const unsigned char **in, long len,
                           int exptag, int expclass, char opt, ASN1_TLC *ctx)
{
    int i;
    int ptag, pclass;
    long plen;
    const unsigned char *p, *q;
    p = *in;
    q = p;

    if (ctx && ctx->valid) {
        i = ctx->ret;
        plen = ctx->plen;
        pclass = ctx->pclass;
        ptag = ctx->ptag;
        p += ctx->hdrlen;
    } else {
        i = ASN1_get_object(&p, &plen, &ptag, &pclass, len);
        if (ctx) {
            ctx->ret = i;
            ctx->plen = plen;
            ctx->pclass = pclass;
            ctx->ptag = ptag;
            ctx->hdrlen = p - q;
            ctx->valid = 1;
            /*
             * If definite length, and no error, length + header can't exceed
             * total amount of data available.
             */
            if (!(i & 0x81) && ((plen + ctx->hdrlen) > len)) {
                ASN1err(ASN1_F_ASN1_CHECK_TLEN, ASN1_R_TOO_LONG);
                asn1_tlc_clear(ctx);
                return 0;
            }
        }
    }

    if (i & 0x80) {
        ASN1err(ASN1_F_ASN1_CHECK_TLEN, ASN1_R_BAD_OBJECT_HEADER);
        asn1_tlc_clear(ctx);
        return 0;
    }
    if (exptag >= 0) {
        if ((exptag != ptag) || (expclass != pclass)) {
            /*
             * If type is OPTIONAL, not an error: indicate missing type.
             */
            if (opt)
                return -1;
            asn1_tlc_clear(ctx);
            ASN1err(ASN1_F_ASN1_CHECK_TLEN, ASN1_R_WRONG_TAG);
            return 0;
        }
        /*
         * We have a tag and class match: assume we are going to do something
         * with it
         */
        asn1_tlc_clear(ctx);
    }

    if (i & 1)
        plen = len - (p - q);

    if (inf)
        *inf = i & 1;

    if (cst)
        *cst = i & V_ASN1_CONSTRUCTED;

    if (olen)
        *olen = plen;

    if (oclass)
        *oclass = pclass;

    if (otag)
        *otag = ptag;

    *in = p;
    return 1;
}
/* tasn_enc.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2000.
 */
/* ====================================================================
 * Copyright (c) 2000-2018 The OpenSSL Project.  All rights reserved.
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

#include <stddef.h>
#include <string.h>
#include <limits.h>
#include "cryptlib.h"
// #include "asn1.h"
// #include "asn1t.h"
// #include "objects.h"

static int asn1_i2d_ex_primitive(ASN1_VALUE **pval, unsigned char **out,
                                 const ASN1_ITEM *it, int tag, int aclass);
static int asn1_set_seq_out(STACK_OF(ASN1_VALUE) *sk, unsigned char **out,
                            int skcontlen, const ASN1_ITEM *item,
                            int do_sort, int iclass);
static int asn1_template_ex_i2d(ASN1_VALUE **pval, unsigned char **out,
                                const ASN1_TEMPLATE *tt, int tag, int aclass);
static int asn1_item_flags_i2d(ASN1_VALUE *val, unsigned char **out,
                               const ASN1_ITEM *it, int flags);

/*
 * Top level i2d equivalents: the 'ndef' variant instructs the encoder to use
 * indefinite length constructed encoding, where appropriate
 */

int ASN1_item_ndef_i2d(ASN1_VALUE *val, unsigned char **out,
                       const ASN1_ITEM *it)
{
    return asn1_item_flags_i2d(val, out, it, ASN1_TFLG_NDEF);
}

int ASN1_item_i2d(ASN1_VALUE *val, unsigned char **out, const ASN1_ITEM *it)
{
    return asn1_item_flags_i2d(val, out, it, 0);
}

/*
 * Encode an ASN1 item, this is use by the standard 'i2d' function. 'out'
 * points to a buffer to output the data to. The new i2d has one additional
 * feature. If the output buffer is NULL (i.e. *out == NULL) then a buffer is
 * allocated and populated with the encoding.
 */

static int asn1_item_flags_i2d(ASN1_VALUE *val, unsigned char **out,
                               const ASN1_ITEM *it, int flags)
{
    if (out && !*out) {
        unsigned char *p, *buf;
        int len;
        len = ASN1_item_ex_i2d(&val, NULL, it, -1, flags);
        if (len <= 0)
            return len;
        buf = OPENSSL_malloc(len);
        if (!buf)
            return -1;
        p = buf;
        ASN1_item_ex_i2d(&val, &p, it, -1, flags);
        *out = buf;
        return len;
    }

    return ASN1_item_ex_i2d(&val, out, it, -1, flags);
}

/*
 * Encode an item, taking care of IMPLICIT tagging (if any). This function
 * performs the normal item handling: it can be used in external types.
 */

int ASN1_item_ex_i2d(ASN1_VALUE **pval, unsigned char **out,
                     const ASN1_ITEM *it, int tag, int aclass)
{
    const ASN1_TEMPLATE *tt = NULL;
    unsigned char *p = NULL;
    int i, seqcontlen, seqlen, ndef = 1;
    const ASN1_COMPAT_FUNCS *cf;
    const ASN1_EXTERN_FUNCS *ef;
    const ASN1_AUX *aux = it->funcs;
    ASN1_aux_cb *asn1_cb = 0;

    if ((it->itype != ASN1_ITYPE_PRIMITIVE) && !*pval)
        return 0;

    if (aux && aux->asn1_cb)
        asn1_cb = aux->asn1_cb;

    switch (it->itype) {

    case ASN1_ITYPE_PRIMITIVE:
        if (it->templates)
            return asn1_template_ex_i2d(pval, out, it->templates,
                                        tag, aclass);
        return asn1_i2d_ex_primitive(pval, out, it, tag, aclass);
        break;

    case ASN1_ITYPE_MSTRING:
        return asn1_i2d_ex_primitive(pval, out, it, -1, aclass);

    case ASN1_ITYPE_CHOICE:
        if (asn1_cb && !asn1_cb(ASN1_OP_I2D_PRE, pval, it, NULL))
            return 0;
        i = asn1_get_choice_selector(pval, it);
        if ((i >= 0) && (i < it->tcount)) {
            ASN1_VALUE **pchval;
            const ASN1_TEMPLATE *chtt;
            chtt = it->templates + i;
            pchval = asn1_get_field_ptr(pval, chtt);
            return asn1_template_ex_i2d(pchval, out, chtt, -1, aclass);
        }
        /* Fixme: error condition if selector out of range */
        if (asn1_cb && !asn1_cb(ASN1_OP_I2D_POST, pval, it, NULL))
            return 0;
        break;

    case ASN1_ITYPE_EXTERN:
        /* If new style i2d it does all the work */
        ef = it->funcs;
        return ef->asn1_ex_i2d(pval, out, it, tag, aclass);

    case ASN1_ITYPE_COMPAT:
        /* old style hackery... */
        cf = it->funcs;
        if (out)
            p = *out;
        i = cf->asn1_i2d(*pval, out);
        /*
         * Fixup for IMPLICIT tag: note this messes up for tags > 30, but so
         * did the old code. Tags > 30 are very rare anyway.
         */
        if (out && (tag != -1))
            *p = aclass | tag | (*p & V_ASN1_CONSTRUCTED);
        return i;

    case ASN1_ITYPE_NDEF_SEQUENCE:
        /* Use indefinite length constructed if requested */
        if (aclass & ASN1_TFLG_NDEF)
            ndef = 2;
        /* fall through */

    case ASN1_ITYPE_SEQUENCE:
        i = asn1_enc_restore(&seqcontlen, out, pval, it);
        /* An error occurred */
        if (i < 0)
            return 0;
        /* We have a valid cached encoding... */
        if (i > 0)
            return seqcontlen;
        /* Otherwise carry on */
        seqcontlen = 0;
        /* If no IMPLICIT tagging set to SEQUENCE, UNIVERSAL */
        if (tag == -1) {
            tag = V_ASN1_SEQUENCE;
            /* Retain any other flags in aclass */
            aclass = (aclass & ~ASN1_TFLG_TAG_CLASS)
                | V_ASN1_UNIVERSAL;
        }
        if (asn1_cb && !asn1_cb(ASN1_OP_I2D_PRE, pval, it, NULL))
            return 0;
        /* First work out sequence content length */
        for (i = 0, tt = it->templates; i < it->tcount; tt++, i++) {
            const ASN1_TEMPLATE *seqtt;
            ASN1_VALUE **pseqval;
            int tmplen;
            seqtt = asn1_do_adb(pval, tt, 1);
            if (!seqtt)
                return 0;
            pseqval = asn1_get_field_ptr(pval, seqtt);
            tmplen = asn1_template_ex_i2d(pseqval, NULL, seqtt, -1, aclass);
            if (tmplen == -1 || (tmplen > INT_MAX - seqcontlen))
                return -1;
            seqcontlen += tmplen;
        }

        seqlen = ASN1_object_size(ndef, seqcontlen, tag);
        if (!out || seqlen == -1)
            return seqlen;
        /* Output SEQUENCE header */
        ASN1_put_object(out, ndef, seqcontlen, tag, aclass);
        for (i = 0, tt = it->templates; i < it->tcount; tt++, i++) {
            const ASN1_TEMPLATE *seqtt;
            ASN1_VALUE **pseqval;
            seqtt = asn1_do_adb(pval, tt, 1);
            if (!seqtt)
                return 0;
            pseqval = asn1_get_field_ptr(pval, seqtt);
            /* FIXME: check for errors in enhanced version */
            asn1_template_ex_i2d(pseqval, out, seqtt, -1, aclass);
        }
        if (ndef == 2)
            ASN1_put_eoc(out);
        if (asn1_cb && !asn1_cb(ASN1_OP_I2D_POST, pval, it, NULL))
            return 0;
        return seqlen;

    default:
        return 0;

    }
    return 0;
}

int ASN1_template_i2d(ASN1_VALUE **pval, unsigned char **out,
                      const ASN1_TEMPLATE *tt)
{
    return asn1_template_ex_i2d(pval, out, tt, -1, 0);
}

static int asn1_template_ex_i2d(ASN1_VALUE **pval, unsigned char **out,
                                const ASN1_TEMPLATE *tt, int tag, int iclass)
{
    int i, ret, flags, ttag, tclass, ndef;
    flags = tt->flags;
    /*
     * Work out tag and class to use: tagging may come either from the
     * template or the arguments, not both because this would create
     * ambiguity. Additionally the iclass argument may contain some
     * additional flags which should be noted and passed down to other
     * levels.
     */
    if (flags & ASN1_TFLG_TAG_MASK) {
        /* Error if argument and template tagging */
        if (tag != -1)
            /* FIXME: error code here */
            return -1;
        /* Get tagging from template */
        ttag = tt->tag;
        tclass = flags & ASN1_TFLG_TAG_CLASS;
    } else if (tag != -1) {
        /* No template tagging, get from arguments */
        ttag = tag;
        tclass = iclass & ASN1_TFLG_TAG_CLASS;
    } else {
        ttag = -1;
        tclass = 0;
    }
    /*
     * Remove any class mask from iflag.
     */
    iclass &= ~ASN1_TFLG_TAG_CLASS;

    /*
     * At this point 'ttag' contains the outer tag to use, 'tclass' is the
     * class and iclass is any flags passed to this function.
     */

    /* if template and arguments require ndef, use it */
    if ((flags & ASN1_TFLG_NDEF) && (iclass & ASN1_TFLG_NDEF))
        ndef = 2;
    else
        ndef = 1;

    if (flags & ASN1_TFLG_SK_MASK) {
        /* SET OF, SEQUENCE OF */
        STACK_OF(ASN1_VALUE) *sk = (STACK_OF(ASN1_VALUE) *)*pval;
        int isset, sktag, skaclass;
        int skcontlen, sklen;
        ASN1_VALUE *skitem;

        if (!*pval)
            return 0;

        if (flags & ASN1_TFLG_SET_OF) {
            isset = 1;
            /* 2 means we reorder */
            if (flags & ASN1_TFLG_SEQUENCE_OF)
                isset = 2;
        } else
            isset = 0;

        /*
         * Work out inner tag value: if EXPLICIT or no tagging use underlying
         * type.
         */
        if ((ttag != -1) && !(flags & ASN1_TFLG_EXPTAG)) {
            sktag = ttag;
            skaclass = tclass;
        } else {
            skaclass = V_ASN1_UNIVERSAL;
            if (isset)
                sktag = V_ASN1_SET;
            else
                sktag = V_ASN1_SEQUENCE;
        }

        /* Determine total length of items */
        skcontlen = 0;
        for (i = 0; i < sk_ASN1_VALUE_num(sk); i++) {
            int tmplen;
            skitem = sk_ASN1_VALUE_value(sk, i);
            tmplen = ASN1_item_ex_i2d(&skitem, NULL, ASN1_ITEM_ptr(tt->item),
                                      -1, iclass);
            if (tmplen == -1 || (skcontlen > INT_MAX - tmplen))
                return -1;
            skcontlen += tmplen;
        }
        sklen = ASN1_object_size(ndef, skcontlen, sktag);
        if (sklen == -1)
            return -1;
        /* If EXPLICIT need length of surrounding tag */
        if (flags & ASN1_TFLG_EXPTAG)
            ret = ASN1_object_size(ndef, sklen, ttag);
        else
            ret = sklen;

        if (!out || ret == -1)
            return ret;

        /* Now encode this lot... */
        /* EXPLICIT tag */
        if (flags & ASN1_TFLG_EXPTAG)
            ASN1_put_object(out, ndef, sklen, ttag, tclass);
        /* SET or SEQUENCE and IMPLICIT tag */
        ASN1_put_object(out, ndef, skcontlen, sktag, skaclass);
        /* And the stuff itself */
        asn1_set_seq_out(sk, out, skcontlen, ASN1_ITEM_ptr(tt->item),
                         isset, iclass);
        if (ndef == 2) {
            ASN1_put_eoc(out);
            if (flags & ASN1_TFLG_EXPTAG)
                ASN1_put_eoc(out);
        }

        return ret;
    }

    if (flags & ASN1_TFLG_EXPTAG) {
        /* EXPLICIT tagging */
        /* Find length of tagged item */
        i = ASN1_item_ex_i2d(pval, NULL, ASN1_ITEM_ptr(tt->item), -1, iclass);
        if (!i)
            return 0;
        /* Find length of EXPLICIT tag */
        ret = ASN1_object_size(ndef, i, ttag);
        if (out && ret != -1) {
            /* Output tag and item */
            ASN1_put_object(out, ndef, i, ttag, tclass);
            ASN1_item_ex_i2d(pval, out, ASN1_ITEM_ptr(tt->item), -1, iclass);
            if (ndef == 2)
                ASN1_put_eoc(out);
        }
        return ret;
    }

    /* Either normal or IMPLICIT tagging: combine class and flags */
    return ASN1_item_ex_i2d(pval, out, ASN1_ITEM_ptr(tt->item),
                            ttag, tclass | iclass);

}

/* Temporary structure used to hold DER encoding of items for SET OF */

typedef struct {
    unsigned char *data;
    int length;
    ASN1_VALUE *field;
} DER_ENC;

static int der_cmp(const void *a, const void *b)
{
    const DER_ENC *d1 = a, *d2 = b;
    int cmplen, i;
    cmplen = (d1->length < d2->length) ? d1->length : d2->length;
    i = memcmp(d1->data, d2->data, cmplen);
    if (i)
        return i;
    return d1->length - d2->length;
}

/* Output the content octets of SET OF or SEQUENCE OF */

static int asn1_set_seq_out(STACK_OF(ASN1_VALUE) *sk, unsigned char **out,
                            int skcontlen, const ASN1_ITEM *item,
                            int do_sort, int iclass)
{
    int i;
    ASN1_VALUE *skitem;
    unsigned char *tmpdat = NULL, *p = NULL;
    DER_ENC *derlst = NULL, *tder;
    if (do_sort) {
        /* Don't need to sort less than 2 items */
        if (sk_ASN1_VALUE_num(sk) < 2)
            do_sort = 0;
        else {
            derlst = OPENSSL_malloc(sk_ASN1_VALUE_num(sk)
                                    * sizeof(*derlst));
            if (!derlst)
                return 0;
            tmpdat = OPENSSL_malloc(skcontlen);
            if (!tmpdat) {
                OPENSSL_free(derlst);
                return 0;
            }
        }
    }
    /* If not sorting just output each item */
    if (!do_sort) {
        for (i = 0; i < sk_ASN1_VALUE_num(sk); i++) {
            skitem = sk_ASN1_VALUE_value(sk, i);
            ASN1_item_ex_i2d(&skitem, out, item, -1, iclass);
        }
        return 1;
    }
    p = tmpdat;

    /* Doing sort: build up a list of each member's DER encoding */
    for (i = 0, tder = derlst; i < sk_ASN1_VALUE_num(sk); i++, tder++) {
        skitem = sk_ASN1_VALUE_value(sk, i);
        tder->data = p;
        tder->length = ASN1_item_ex_i2d(&skitem, &p, item, -1, iclass);
        tder->field = skitem;
    }

    /* Now sort them */
    qsort(derlst, sk_ASN1_VALUE_num(sk), sizeof(*derlst), der_cmp);
    /* Output sorted DER encoding */
    p = *out;
    for (i = 0, tder = derlst; i < sk_ASN1_VALUE_num(sk); i++, tder++) {
        memcpy(p, tder->data, tder->length);
        p += tder->length;
    }
    *out = p;
    /* If do_sort is 2 then reorder the STACK */
    if (do_sort == 2) {
        for (i = 0, tder = derlst; i < sk_ASN1_VALUE_num(sk); i++, tder++)
            (void)sk_ASN1_VALUE_set(sk, i, tder->field);
    }
    OPENSSL_free(derlst);
    OPENSSL_free(tmpdat);
    return 1;
}

static int asn1_i2d_ex_primitive(ASN1_VALUE **pval, unsigned char **out,
                                 const ASN1_ITEM *it, int tag, int aclass)
{
    int len;
    int utype;
    int usetag;
    int ndef = 0;

    utype = it->utype;

    /*
     * Get length of content octets and maybe find out the underlying type.
     */

    len = asn1_ex_i2c(pval, NULL, &utype, it);

    /*
     * If SEQUENCE, SET or OTHER then header is included in pseudo content
     * octets so don't include tag+length. We need to check here because the
     * call to asn1_ex_i2c() could change utype.
     */
    if ((utype == V_ASN1_SEQUENCE) || (utype == V_ASN1_SET) ||
        (utype == V_ASN1_OTHER))
        usetag = 0;
    else
        usetag = 1;

    /* -1 means omit type */

    if (len == -1)
        return 0;

    /* -2 return is special meaning use ndef */
    if (len == -2) {
        ndef = 2;
        len = 0;
    }

    /* If not implicitly tagged get tag from underlying type */
    if (tag == -1)
        tag = utype;

    /* Output tag+length followed by content octets */
    if (out) {
        if (usetag)
            ASN1_put_object(out, ndef, len, tag, aclass);
        asn1_ex_i2c(pval, *out, &utype, it);
        if (ndef)
            ASN1_put_eoc(out);
        else
            *out += len;
    }

    if (usetag)
        return ASN1_object_size(ndef, len, tag);
    return len;
}

/* Produce content octets from a structure */

int asn1_ex_i2c(ASN1_VALUE **pval, unsigned char *cout, int *putype,
                const ASN1_ITEM *it)
{
    ASN1_BOOLEAN *tbool = NULL;
    ASN1_STRING *strtmp;
    ASN1_OBJECT *otmp;
    int utype;
    const unsigned char *cont;
    unsigned char c;
    int len;
    const ASN1_PRIMITIVE_FUNCS *pf;
    pf = it->funcs;
    if (pf && pf->prim_i2c)
        return pf->prim_i2c(pval, cout, putype, it);

    /* Should type be omitted? */
    if ((it->itype != ASN1_ITYPE_PRIMITIVE)
        || (it->utype != V_ASN1_BOOLEAN)) {
        if (!*pval)
            return -1;
    }

    if (it->itype == ASN1_ITYPE_MSTRING) {
        /* If MSTRING type set the underlying type */
        strtmp = (ASN1_STRING *)*pval;
        utype = strtmp->type;
        *putype = utype;
    } else if (it->utype == V_ASN1_ANY) {
        /* If ANY set type and pointer to value */
        ASN1_TYPE *typ;
        typ = (ASN1_TYPE *)*pval;
        utype = typ->type;
        *putype = utype;
        pval = &typ->value.asn1_value;
    } else
        utype = *putype;

    switch (utype) {
    case V_ASN1_OBJECT:
        otmp = (ASN1_OBJECT *)*pval;
        cont = otmp->data;
        len = otmp->length;
        if (cont == NULL || len == 0)
            return -1;
        break;

    case V_ASN1_NULL:
        cont = NULL;
        len = 0;
        break;

    case V_ASN1_BOOLEAN:
        tbool = (ASN1_BOOLEAN *)pval;
        if (*tbool == -1)
            return -1;
        if (it->utype != V_ASN1_ANY) {
            /*
             * Default handling if value == size field then omit
             */
            if (*tbool && (it->size > 0))
                return -1;
            if (!*tbool && !it->size)
                return -1;
        }
        c = (unsigned char)*tbool;
        cont = &c;
        len = 1;
        break;

    case V_ASN1_BIT_STRING:
        return i2c_ASN1_BIT_STRING((ASN1_BIT_STRING *)*pval,
                                   cout ? &cout : NULL);
        break;

    case V_ASN1_INTEGER:
    case V_ASN1_ENUMERATED:
        /*
         * These are all have the same content format as ASN1_INTEGER
         */
        return i2c_ASN1_INTEGER((ASN1_INTEGER *)*pval, cout ? &cout : NULL);
        break;

    case V_ASN1_OCTET_STRING:
    case V_ASN1_NUMERICSTRING:
    case V_ASN1_PRINTABLESTRING:
    case V_ASN1_T61STRING:
    case V_ASN1_VIDEOTEXSTRING:
    case V_ASN1_IA5STRING:
    case V_ASN1_UTCTIME:
    case V_ASN1_GENERALIZEDTIME:
    case V_ASN1_GRAPHICSTRING:
    case V_ASN1_VISIBLESTRING:
    case V_ASN1_GENERALSTRING:
    case V_ASN1_UNIVERSALSTRING:
    case V_ASN1_BMPSTRING:
    case V_ASN1_UTF8STRING:
    case V_ASN1_SEQUENCE:
    case V_ASN1_SET:
    default:
        /* All based on ASN1_STRING and handled the same */
        strtmp = (ASN1_STRING *)*pval;
        /* Special handling for NDEF */
        if ((it->size == ASN1_TFLG_NDEF)
            && (strtmp->flags & ASN1_STRING_FLAG_NDEF)) {
            if (cout) {
                strtmp->data = cout;
                strtmp->length = 0;
            }
            /* Special return code */
            return -2;
        }
        cont = strtmp->data;
        len = strtmp->length;

        break;

    }
    if (cout && len)
        memcpy(cout, cont, len);
    return len;
}
/* tasn_fre.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
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

#include <stddef.h>
// #include "asn1.h"
// #include "asn1t.h"
// #include "objects.h"
#include "asn1_int.h"

/* Free up an ASN1 structure */

void ASN1_item_free(ASN1_VALUE *val, const ASN1_ITEM *it)
{
    asn1_item_combine_free(&val, it, 0);
}

void ASN1_item_ex_free(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    asn1_item_combine_free(pval, it, 0);
}

void asn1_item_combine_free(ASN1_VALUE **pval, const ASN1_ITEM *it, int combine)
{
    const ASN1_TEMPLATE *tt = NULL, *seqtt;
    const ASN1_EXTERN_FUNCS *ef;
    const ASN1_COMPAT_FUNCS *cf;
    const ASN1_AUX *aux = it->funcs;
    ASN1_aux_cb *asn1_cb;
    int i;
    if (!pval)
        return;
    if ((it->itype != ASN1_ITYPE_PRIMITIVE) && !*pval)
        return;
    if (aux && aux->asn1_cb)
        asn1_cb = aux->asn1_cb;
    else
        asn1_cb = 0;

    switch (it->itype) {

    case ASN1_ITYPE_PRIMITIVE:
        if (it->templates)
            ASN1_template_free(pval, it->templates);
        else
            ASN1_primitive_free(pval, it);
        break;

    case ASN1_ITYPE_MSTRING:
        ASN1_primitive_free(pval, it);
        break;

    case ASN1_ITYPE_CHOICE:
        if (asn1_cb) {
            i = asn1_cb(ASN1_OP_FREE_PRE, pval, it, NULL);
            if (i == 2)
                return;
        }
        i = asn1_get_choice_selector(pval, it);
        if ((i >= 0) && (i < it->tcount)) {
            ASN1_VALUE **pchval;
            tt = it->templates + i;
            pchval = asn1_get_field_ptr(pval, tt);
            ASN1_template_free(pchval, tt);
        }
        if (asn1_cb)
            asn1_cb(ASN1_OP_FREE_POST, pval, it, NULL);
        if (!combine) {
            OPENSSL_free(*pval);
            *pval = NULL;
        }
        break;

    case ASN1_ITYPE_COMPAT:
        cf = it->funcs;
        if (cf && cf->asn1_free)
            cf->asn1_free(*pval);
        break;

    case ASN1_ITYPE_EXTERN:
        ef = it->funcs;
        if (ef && ef->asn1_ex_free)
            ef->asn1_ex_free(pval, it);
        break;

    case ASN1_ITYPE_NDEF_SEQUENCE:
    case ASN1_ITYPE_SEQUENCE:
        if (asn1_do_lock(pval, -1, it) > 0)
            return;
        if (asn1_cb) {
            i = asn1_cb(ASN1_OP_FREE_PRE, pval, it, NULL);
            if (i == 2)
                return;
        }
        asn1_enc_free(pval, it);
        /*
         * If we free up as normal we will invalidate any ANY DEFINED BY
         * field and we wont be able to determine the type of the field it
         * defines. So free up in reverse order.
         */
        tt = it->templates + it->tcount - 1;
        for (i = 0; i < it->tcount; tt--, i++) {
            ASN1_VALUE **pseqval;
            seqtt = asn1_do_adb(pval, tt, 0);
            if (!seqtt)
                continue;
            pseqval = asn1_get_field_ptr(pval, seqtt);
            ASN1_template_free(pseqval, seqtt);
        }
        if (asn1_cb)
            asn1_cb(ASN1_OP_FREE_POST, pval, it, NULL);
        if (!combine) {
            OPENSSL_free(*pval);
            *pval = NULL;
        }
        break;
    }
}

void ASN1_template_free(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt)
{
    int i;
    if (tt->flags & ASN1_TFLG_SK_MASK) {
        STACK_OF(ASN1_VALUE) *sk = (STACK_OF(ASN1_VALUE) *)*pval;
        for (i = 0; i < sk_ASN1_VALUE_num(sk); i++) {
            ASN1_VALUE *vtmp;
            vtmp = sk_ASN1_VALUE_value(sk, i);
            asn1_item_combine_free(&vtmp, ASN1_ITEM_ptr(tt->item), 0);
        }
        sk_ASN1_VALUE_free(sk);
        *pval = NULL;
    } else
        asn1_item_combine_free(pval, ASN1_ITEM_ptr(tt->item),
                               tt->flags & ASN1_TFLG_COMBINE);
}

void ASN1_primitive_free(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    int utype;
    if (it) {
        const ASN1_PRIMITIVE_FUNCS *pf;
        pf = it->funcs;
        if (pf && pf->prim_free) {
            pf->prim_free(pval, it);
            return;
        }
    }
    /* Special case: if 'it' is NULL free contents of ASN1_TYPE */
    if (!it) {
        ASN1_TYPE *typ = (ASN1_TYPE *)*pval;
        utype = typ->type;
        pval = &typ->value.asn1_value;
        if (!*pval)
            return;
    } else if (it->itype == ASN1_ITYPE_MSTRING) {
        utype = -1;
        if (!*pval)
            return;
    } else {
        utype = it->utype;
        if ((utype != V_ASN1_BOOLEAN) && !*pval)
            return;
    }

    switch (utype) {
    case V_ASN1_OBJECT:
        ASN1_OBJECT_free((ASN1_OBJECT *)*pval);
        break;

    case V_ASN1_BOOLEAN:
        if (it)
            *(ASN1_BOOLEAN *)pval = it->size;
        else
            *(ASN1_BOOLEAN *)pval = -1;
        return;

    case V_ASN1_NULL:
        break;

    case V_ASN1_ANY:
        ASN1_primitive_free(pval, NULL);
        OPENSSL_free(*pval);
        break;

    default:
        ASN1_STRING_free((ASN1_STRING *)*pval);
        *pval = NULL;
        break;
    }
    *pval = NULL;
}
/* tasn_new.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2000.
 */
/* ====================================================================
 * Copyright (c) 2000-2004 The OpenSSL Project.  All rights reserved.
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

#include <stddef.h>
// #include "asn1.h"
// #include "objects.h"
// #include "err.h"
// #include "asn1t.h"
#include <string.h>
// #include "asn1_int.h"

static int asn1_item_ex_combine_new(ASN1_VALUE **pval, const ASN1_ITEM *it,
                                    int combine);
static void asn1_item_clear(ASN1_VALUE **pval, const ASN1_ITEM *it);
static void asn1_template_clear(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt);
static void asn1_primitive_clear(ASN1_VALUE **pval, const ASN1_ITEM *it);

ASN1_VALUE *ASN1_item_new(const ASN1_ITEM *it)
{
    ASN1_VALUE *ret = NULL;
    if (ASN1_item_ex_new(&ret, it) > 0)
        return ret;
    return NULL;
}

/* Allocate an ASN1 structure */

int ASN1_item_ex_new(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    return asn1_item_ex_combine_new(pval, it, 0);
}

static int asn1_item_ex_combine_new(ASN1_VALUE **pval, const ASN1_ITEM *it,
                                    int combine)
{
    const ASN1_TEMPLATE *tt = NULL;
    const ASN1_COMPAT_FUNCS *cf;
    const ASN1_EXTERN_FUNCS *ef;
    const ASN1_AUX *aux = it->funcs;
    ASN1_aux_cb *asn1_cb;
    ASN1_VALUE **pseqval;
    int i;
    if (aux && aux->asn1_cb)
        asn1_cb = aux->asn1_cb;
    else
        asn1_cb = 0;

#ifdef CRYPTO_MDEBUG
    if (it->sname)
        CRYPTO_push_info(it->sname);
#endif

    switch (it->itype) {

    case ASN1_ITYPE_EXTERN:
        ef = it->funcs;
        if (ef && ef->asn1_ex_new) {
            if (!ef->asn1_ex_new(pval, it))
                goto memerr;
        }
        break;

    case ASN1_ITYPE_COMPAT:
        cf = it->funcs;
        if (cf && cf->asn1_new) {
            *pval = cf->asn1_new();
            if (!*pval)
                goto memerr;
        }
        break;

    case ASN1_ITYPE_PRIMITIVE:
        if (it->templates) {
            if (!ASN1_template_new(pval, it->templates))
                goto memerr;
        } else if (!ASN1_primitive_new(pval, it))
            goto memerr;
        break;

    case ASN1_ITYPE_MSTRING:
        if (!ASN1_primitive_new(pval, it))
            goto memerr;
        break;

    case ASN1_ITYPE_CHOICE:
        if (asn1_cb) {
            i = asn1_cb(ASN1_OP_NEW_PRE, pval, it, NULL);
            if (!i)
                goto auxerr;
            if (i == 2) {
#ifdef CRYPTO_MDEBUG
                if (it->sname)
                    CRYPTO_pop_info();
#endif
                return 1;
            }
        }
        if (!combine) {
            *pval = OPENSSL_malloc(it->size);
            if (!*pval)
                goto memerr;
            memset(*pval, 0, it->size);
        }
        asn1_set_choice_selector(pval, -1, it);
        if (asn1_cb && !asn1_cb(ASN1_OP_NEW_POST, pval, it, NULL))
            goto auxerr2;
        break;

    case ASN1_ITYPE_NDEF_SEQUENCE:
    case ASN1_ITYPE_SEQUENCE:
        if (asn1_cb) {
            i = asn1_cb(ASN1_OP_NEW_PRE, pval, it, NULL);
            if (!i)
                goto auxerr;
            if (i == 2) {
#ifdef CRYPTO_MDEBUG
                if (it->sname)
                    CRYPTO_pop_info();
#endif
                return 1;
            }
        }
        if (!combine) {
            *pval = OPENSSL_malloc(it->size);
            if (!*pval)
                goto memerr;
            memset(*pval, 0, it->size);
            asn1_do_lock(pval, 0, it);
            asn1_enc_init(pval, it);
        }
        for (i = 0, tt = it->templates; i < it->tcount; tt++, i++) {
            pseqval = asn1_get_field_ptr(pval, tt);
            if (!ASN1_template_new(pseqval, tt))
                goto memerr2;
        }
        if (asn1_cb && !asn1_cb(ASN1_OP_NEW_POST, pval, it, NULL))
            goto auxerr2;
        break;
    }
#ifdef CRYPTO_MDEBUG
    if (it->sname)
        CRYPTO_pop_info();
#endif
    return 1;

 memerr2:
    asn1_item_combine_free(pval, it, combine);
 memerr:
    ASN1err(ASN1_F_ASN1_ITEM_EX_COMBINE_NEW, ERR_R_MALLOC_FAILURE);
#ifdef CRYPTO_MDEBUG
    if (it->sname)
        CRYPTO_pop_info();
#endif
    return 0;

 auxerr2:
    asn1_item_combine_free(pval, it, combine);
 auxerr:
    ASN1err(ASN1_F_ASN1_ITEM_EX_COMBINE_NEW, ASN1_R_AUX_ERROR);
#ifdef CRYPTO_MDEBUG
    if (it->sname)
        CRYPTO_pop_info();
#endif
    return 0;

}

static void asn1_item_clear(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    const ASN1_EXTERN_FUNCS *ef;

    switch (it->itype) {

    case ASN1_ITYPE_EXTERN:
        ef = it->funcs;
        if (ef && ef->asn1_ex_clear)
            ef->asn1_ex_clear(pval, it);
        else
            *pval = NULL;
        break;

    case ASN1_ITYPE_PRIMITIVE:
        if (it->templates)
            asn1_template_clear(pval, it->templates);
        else
            asn1_primitive_clear(pval, it);
        break;

    case ASN1_ITYPE_MSTRING:
        asn1_primitive_clear(pval, it);
        break;

    case ASN1_ITYPE_COMPAT:
    case ASN1_ITYPE_CHOICE:
    case ASN1_ITYPE_SEQUENCE:
    case ASN1_ITYPE_NDEF_SEQUENCE:
        *pval = NULL;
        break;
    }
}

int ASN1_template_new(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt)
{
    const ASN1_ITEM *it = ASN1_ITEM_ptr(tt->item);
    int ret;
    if (tt->flags & ASN1_TFLG_OPTIONAL) {
        asn1_template_clear(pval, tt);
        return 1;
    }
    /* If ANY DEFINED BY nothing to do */

    if (tt->flags & ASN1_TFLG_ADB_MASK) {
        *pval = NULL;
        return 1;
    }
#ifdef CRYPTO_MDEBUG
    if (tt->field_name)
        CRYPTO_push_info(tt->field_name);
#endif
    /* If SET OF or SEQUENCE OF, its a STACK */
    if (tt->flags & ASN1_TFLG_SK_MASK) {
        STACK_OF(ASN1_VALUE) *skval;
        skval = sk_ASN1_VALUE_new_null();
        if (!skval) {
            ASN1err(ASN1_F_ASN1_TEMPLATE_NEW, ERR_R_MALLOC_FAILURE);
            ret = 0;
            goto done;
        }
        *pval = (ASN1_VALUE *)skval;
        ret = 1;
        goto done;
    }
    /* Otherwise pass it back to the item routine */
    ret = asn1_item_ex_combine_new(pval, it, tt->flags & ASN1_TFLG_COMBINE);
 done:
#ifdef CRYPTO_MDEBUG
    if (it->sname)
        CRYPTO_pop_info();
#endif
    return ret;
}

static void asn1_template_clear(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt)
{
    /* If ADB or STACK just NULL the field */
    if (tt->flags & (ASN1_TFLG_ADB_MASK | ASN1_TFLG_SK_MASK))
        *pval = NULL;
    else
        asn1_item_clear(pval, ASN1_ITEM_ptr(tt->item));
}

/*
 * NB: could probably combine most of the real XXX_new() behaviour and junk
 * all the old functions.
 */

int ASN1_primitive_new(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    ASN1_TYPE *typ;
    ASN1_STRING *str;
    int utype;

    if (!it)
        return 0;

    if (it->funcs) {
        const ASN1_PRIMITIVE_FUNCS *pf = it->funcs;
        if (pf->prim_new)
            return pf->prim_new(pval, it);
    }

    if (it->itype == ASN1_ITYPE_MSTRING)
        utype = -1;
    else
        utype = it->utype;
    switch (utype) {
    case V_ASN1_OBJECT:
        *pval = (ASN1_VALUE *)OBJ_nid2obj(NID_undef);
        return 1;

    case V_ASN1_BOOLEAN:
        *(ASN1_BOOLEAN *)pval = it->size;
        return 1;

    case V_ASN1_NULL:
        *pval = (ASN1_VALUE *)1;
        return 1;

    case V_ASN1_ANY:
        typ = OPENSSL_malloc(sizeof(ASN1_TYPE));
        if (!typ)
            return 0;
        typ->value.ptr = NULL;
        typ->type = -1;
        *pval = (ASN1_VALUE *)typ;
        break;

    default:
        str = ASN1_STRING_type_new(utype);
        if (it->itype == ASN1_ITYPE_MSTRING && str)
            str->flags |= ASN1_STRING_FLAG_MSTRING;
        *pval = (ASN1_VALUE *)str;
        break;
    }
    if (*pval)
        return 1;
    return 0;
}

static void asn1_primitive_clear(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    int utype;
    if (it && it->funcs) {
        const ASN1_PRIMITIVE_FUNCS *pf = it->funcs;
        if (pf->prim_clear)
            pf->prim_clear(pval, it);
        else
            *pval = NULL;
        return;
    }
    if (!it || (it->itype == ASN1_ITYPE_MSTRING))
        utype = -1;
    else
        utype = it->utype;
    if (utype == V_ASN1_BOOLEAN)
        *(ASN1_BOOLEAN *)pval = it->size;
    else
        *pval = NULL;
}
/* tasn_prn.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2000.
 */
/* ====================================================================
 * Copyright (c) 2000,2005 The OpenSSL Project.  All rights reserved.
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

#include <stddef.h>
// #include "cryptlib.h"
// #include "asn1.h"
// #include "asn1t.h"
// #include "objects.h"
// #include "buffer.h"
// #include "err.h"
#include "x509v3.h"
#include "asn1_locl.h"

/*
 * Print routines.
 */

/* ASN1_PCTX routines */

ASN1_PCTX default_pctx = {
    ASN1_PCTX_FLAGS_SHOW_ABSENT, /* flags */
    0,                          /* nm_flags */
    0,                          /* cert_flags */
    0,                          /* oid_flags */
    0                           /* str_flags */
};

ASN1_PCTX *ASN1_PCTX_new(void)
{
    ASN1_PCTX *ret;
    ret = OPENSSL_malloc(sizeof(ASN1_PCTX));
    if (ret == NULL) {
        ASN1err(ASN1_F_ASN1_PCTX_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    ret->flags = 0;
    ret->nm_flags = 0;
    ret->cert_flags = 0;
    ret->oid_flags = 0;
    ret->str_flags = 0;
    return ret;
}

void ASN1_PCTX_free(ASN1_PCTX *p)
{
    OPENSSL_free(p);
}

unsigned long ASN1_PCTX_get_flags(ASN1_PCTX *p)
{
    return p->flags;
}

void ASN1_PCTX_set_flags(ASN1_PCTX *p, unsigned long flags)
{
    p->flags = flags;
}

unsigned long ASN1_PCTX_get_nm_flags(ASN1_PCTX *p)
{
    return p->nm_flags;
}

void ASN1_PCTX_set_nm_flags(ASN1_PCTX *p, unsigned long flags)
{
    p->nm_flags = flags;
}

unsigned long ASN1_PCTX_get_cert_flags(ASN1_PCTX *p)
{
    return p->cert_flags;
}

void ASN1_PCTX_set_cert_flags(ASN1_PCTX *p, unsigned long flags)
{
    p->cert_flags = flags;
}

unsigned long ASN1_PCTX_get_oid_flags(ASN1_PCTX *p)
{
    return p->oid_flags;
}

void ASN1_PCTX_set_oid_flags(ASN1_PCTX *p, unsigned long flags)
{
    p->oid_flags = flags;
}

unsigned long ASN1_PCTX_get_str_flags(ASN1_PCTX *p)
{
    return p->str_flags;
}

void ASN1_PCTX_set_str_flags(ASN1_PCTX *p, unsigned long flags)
{
    p->str_flags = flags;
}

/* Main print routines */

static int asn1_item_print_ctx(BIO *out, ASN1_VALUE **fld, int indent,
                               const ASN1_ITEM *it,
                               const char *fname, const char *sname,
                               int nohdr, const ASN1_PCTX *pctx);

int asn1_template_print_ctx(BIO *out, ASN1_VALUE **fld, int indent,
                            const ASN1_TEMPLATE *tt, const ASN1_PCTX *pctx);

static int asn1_primitive_print(BIO *out, ASN1_VALUE **fld,
                                const ASN1_ITEM *it, int indent,
                                const char *fname, const char *sname,
                                const ASN1_PCTX *pctx);

static int asn1_print_fsname(BIO *out, int indent,
                             const char *fname, const char *sname,
                             const ASN1_PCTX *pctx);

int ASN1_item_print(BIO *out, ASN1_VALUE *ifld, int indent,
                    const ASN1_ITEM *it, const ASN1_PCTX *pctx)
{
    const char *sname;
    if (pctx == NULL)
        pctx = &default_pctx;
    if (pctx->flags & ASN1_PCTX_FLAGS_NO_STRUCT_NAME)
        sname = NULL;
    else
        sname = it->sname;
    return asn1_item_print_ctx(out, &ifld, indent, it, NULL, sname, 0, pctx);
}

static int asn1_item_print_ctx(BIO *out, ASN1_VALUE **fld, int indent,
                               const ASN1_ITEM *it,
                               const char *fname, const char *sname,
                               int nohdr, const ASN1_PCTX *pctx)
{
    const ASN1_TEMPLATE *tt;
    const ASN1_EXTERN_FUNCS *ef;
    ASN1_VALUE **tmpfld;
    const ASN1_AUX *aux = it->funcs;
    ASN1_aux_cb *asn1_cb;
    ASN1_PRINT_ARG parg;
    int i;
    if (aux && aux->asn1_cb) {
        parg.out = out;
        parg.indent = indent;
        parg.pctx = pctx;
        asn1_cb = aux->asn1_cb;
    } else
        asn1_cb = 0;

   if (((it->itype != ASN1_ITYPE_PRIMITIVE)
       || (it->utype != V_ASN1_BOOLEAN)) && *fld == NULL) {
        if (pctx->flags & ASN1_PCTX_FLAGS_SHOW_ABSENT) {
            if (!nohdr && !asn1_print_fsname(out, indent, fname, sname, pctx))
                return 0;
            if (BIO_puts(out, "<ABSENT>\n") <= 0)
                return 0;
        }
        return 1;
    }

    switch (it->itype) {
    case ASN1_ITYPE_PRIMITIVE:
        if (it->templates) {
            if (!asn1_template_print_ctx(out, fld, indent,
                                         it->templates, pctx))
                return 0;
            break;
        }
        /* fall thru */
    case ASN1_ITYPE_MSTRING:
        if (!asn1_primitive_print(out, fld, it, indent, fname, sname, pctx))
            return 0;
        break;

    case ASN1_ITYPE_EXTERN:
        if (!nohdr && !asn1_print_fsname(out, indent, fname, sname, pctx))
            return 0;
        /* Use new style print routine if possible */
        ef = it->funcs;
        if (ef && ef->asn1_ex_print) {
            i = ef->asn1_ex_print(out, fld, indent, "", pctx);
            if (!i)
                return 0;
            if ((i == 2) && (BIO_puts(out, "\n") <= 0))
                return 0;
            return 1;
        } else if (sname &&
                   BIO_printf(out, ":EXTERNAL TYPE %s\n", sname) <= 0)
            return 0;
        break;

    case ASN1_ITYPE_CHOICE:
#if 0
        if (!nohdr && !asn1_print_fsname(out, indent, fname, sname, pctx))
            return 0;
#endif
        /* CHOICE type, get selector */
        i = asn1_get_choice_selector(fld, it);
        /* This should never happen... */
        if ((i < 0) || (i >= it->tcount)) {
            if (BIO_printf(out, "ERROR: selector [%d] invalid\n", i) <= 0)
                return 0;
            return 1;
        }
        tt = it->templates + i;
        tmpfld = asn1_get_field_ptr(fld, tt);
        if (!asn1_template_print_ctx(out, tmpfld, indent, tt, pctx))
            return 0;
        break;

    case ASN1_ITYPE_SEQUENCE:
    case ASN1_ITYPE_NDEF_SEQUENCE:
        if (!nohdr && !asn1_print_fsname(out, indent, fname, sname, pctx))
            return 0;
        if (fname || sname) {
            if (pctx->flags & ASN1_PCTX_FLAGS_SHOW_SEQUENCE) {
                if (BIO_puts(out, " {\n") <= 0)
                    return 0;
            } else {
                if (BIO_puts(out, "\n") <= 0)
                    return 0;
            }
        }

        if (asn1_cb) {
            i = asn1_cb(ASN1_OP_PRINT_PRE, fld, it, &parg);
            if (i == 0)
                return 0;
            if (i == 2)
                return 1;
        }

        /* Print each field entry */
        for (i = 0, tt = it->templates; i < it->tcount; i++, tt++) {
            const ASN1_TEMPLATE *seqtt;
            seqtt = asn1_do_adb(fld, tt, 1);
            if (!seqtt)
                return 0;
            tmpfld = asn1_get_field_ptr(fld, seqtt);
            if (!asn1_template_print_ctx(out, tmpfld,
                                         indent + 2, seqtt, pctx))
                return 0;
        }
        if (pctx->flags & ASN1_PCTX_FLAGS_SHOW_SEQUENCE) {
            if (BIO_printf(out, "%*s}\n", indent, "") < 0)
                return 0;
        }

        if (asn1_cb) {
            i = asn1_cb(ASN1_OP_PRINT_POST, fld, it, &parg);
            if (i == 0)
                return 0;
        }
        break;

    default:
        BIO_printf(out, "Unprocessed type %d\n", it->itype);
        return 0;
    }

    return 1;
}

int asn1_template_print_ctx(BIO *out, ASN1_VALUE **fld, int indent,
                            const ASN1_TEMPLATE *tt, const ASN1_PCTX *pctx)
{
    int i, flags;
    const char *sname, *fname;
    flags = tt->flags;
    if (pctx->flags & ASN1_PCTX_FLAGS_SHOW_FIELD_STRUCT_NAME)
        sname = ASN1_ITEM_ptr(tt->item)->sname;
    else
        sname = NULL;
    if (pctx->flags & ASN1_PCTX_FLAGS_NO_FIELD_NAME)
        fname = NULL;
    else
        fname = tt->field_name;
    if (flags & ASN1_TFLG_SK_MASK) {
        char *tname;
        ASN1_VALUE *skitem;
        STACK_OF(ASN1_VALUE) *stack;

        /* SET OF, SEQUENCE OF */
        if (fname) {
            if (pctx->flags & ASN1_PCTX_FLAGS_SHOW_SSOF) {
                if (flags & ASN1_TFLG_SET_OF)
                    tname = "SET";
                else
                    tname = "SEQUENCE";
                if (BIO_printf(out, "%*s%s OF %s {\n",
                               indent, "", tname, tt->field_name) <= 0)
                    return 0;
            } else if (BIO_printf(out, "%*s%s:\n", indent, "", fname) <= 0)
                return 0;
        }
        stack = (STACK_OF(ASN1_VALUE) *)*fld;
        for (i = 0; i < sk_ASN1_VALUE_num(stack); i++) {
            if ((i > 0) && (BIO_puts(out, "\n") <= 0))
                return 0;

            skitem = sk_ASN1_VALUE_value(stack, i);
            if (!asn1_item_print_ctx(out, &skitem, indent + 2,
                                     ASN1_ITEM_ptr(tt->item), NULL, NULL, 1,
                                     pctx))
                return 0;
        }
        if (!i && BIO_printf(out, "%*s<EMPTY>\n", indent + 2, "") <= 0)
            return 0;
        if (pctx->flags & ASN1_PCTX_FLAGS_SHOW_SEQUENCE) {
            if (BIO_printf(out, "%*s}\n", indent, "") <= 0)
                return 0;
        }
        return 1;
    }
    return asn1_item_print_ctx(out, fld, indent, ASN1_ITEM_ptr(tt->item),
                               fname, sname, 0, pctx);
}

static int asn1_print_fsname(BIO *out, int indent,
                             const char *fname, const char *sname,
                             const ASN1_PCTX *pctx)
{
    static char spaces[] = "                    ";
    const int nspaces = sizeof(spaces) - 1;

#if 0
    if (!sname && !fname)
        return 1;
#endif

    while (indent > nspaces) {
        if (BIO_write(out, spaces, nspaces) != nspaces)
            return 0;
        indent -= nspaces;
    }
    if (BIO_write(out, spaces, indent) != indent)
        return 0;
    if (pctx->flags & ASN1_PCTX_FLAGS_NO_STRUCT_NAME)
        sname = NULL;
    if (pctx->flags & ASN1_PCTX_FLAGS_NO_FIELD_NAME)
        fname = NULL;
    if (!sname && !fname)
        return 1;
    if (fname) {
        if (BIO_puts(out, fname) <= 0)
            return 0;
    }
    if (sname) {
        if (fname) {
            if (BIO_printf(out, " (%s)", sname) <= 0)
                return 0;
        } else {
            if (BIO_puts(out, sname) <= 0)
                return 0;
        }
    }
    if (BIO_write(out, ": ", 2) != 2)
        return 0;
    return 1;
}

static int asn1_print_boolean_ctx(BIO *out, int boolval,
                                  const ASN1_PCTX *pctx)
{
    const char *str;
    switch (boolval) {
    case -1:
        str = "BOOL ABSENT";
        break;

    case 0:
        str = "FALSE";
        break;

    default:
        str = "TRUE";
        break;

    }

    if (BIO_puts(out, str) <= 0)
        return 0;
    return 1;

}

static int asn1_print_integer_ctx(BIO *out, ASN1_INTEGER *str,
                                  const ASN1_PCTX *pctx)
{
    char *s;
    int ret = 1;
    s = i2s_ASN1_INTEGER(NULL, str);
    if (s == NULL)
        return 0;
    if (BIO_puts(out, s) <= 0)
        ret = 0;
    OPENSSL_free(s);
    return ret;
}

static int asn1_print_oid_ctx(BIO *out, const ASN1_OBJECT *oid,
                              const ASN1_PCTX *pctx)
{
    char objbuf[80];
    const char *ln;
    ln = OBJ_nid2ln(OBJ_obj2nid(oid));
    if (!ln)
        ln = "";
    OBJ_obj2txt(objbuf, sizeof(objbuf), oid, 1);
    if (BIO_printf(out, "%s (%s)", ln, objbuf) <= 0)
        return 0;
    return 1;
}

static int asn1_print_obstring_ctx(BIO *out, ASN1_STRING *str, int indent,
                                   const ASN1_PCTX *pctx)
{
    if (str->type == V_ASN1_BIT_STRING) {
        if (BIO_printf(out, " (%ld unused bits)\n", str->flags & 0x7) <= 0)
            return 0;
    } else if (BIO_puts(out, "\n") <= 0)
        return 0;
    if ((str->length > 0)
        && BIO_dump_indent(out, (char *)str->data, str->length,
                           indent + 2) <= 0)
        return 0;
    return 1;
}

static int asn1_primitive_print(BIO *out, ASN1_VALUE **fld,
                                const ASN1_ITEM *it, int indent,
                                const char *fname, const char *sname,
                                const ASN1_PCTX *pctx)
{
    long utype;
    ASN1_STRING *str;
    int ret = 1, needlf = 1;
    const char *pname;
    const ASN1_PRIMITIVE_FUNCS *pf;
    pf = it->funcs;
    if (!asn1_print_fsname(out, indent, fname, sname, pctx))
        return 0;
    if (pf && pf->prim_print)
        return pf->prim_print(out, fld, it, indent, pctx);
    if (it->itype == ASN1_ITYPE_MSTRING) {
        str = (ASN1_STRING *)*fld;
        utype = str->type & ~V_ASN1_NEG;
    } else {
        utype = it->utype;
        if (utype == V_ASN1_BOOLEAN)
            str = NULL;
        else
            str = (ASN1_STRING *)*fld;
    }
    if (utype == V_ASN1_ANY) {
        ASN1_TYPE *atype = (ASN1_TYPE *)*fld;
        utype = atype->type;
        fld = &atype->value.asn1_value;
        str = (ASN1_STRING *)*fld;
        if (pctx->flags & ASN1_PCTX_FLAGS_NO_ANY_TYPE)
            pname = NULL;
        else
            pname = ASN1_tag2str(utype);
    } else {
        if (pctx->flags & ASN1_PCTX_FLAGS_SHOW_TYPE)
            pname = ASN1_tag2str(utype);
        else
            pname = NULL;
    }

    if (utype == V_ASN1_NULL) {
        if (BIO_puts(out, "NULL\n") <= 0)
            return 0;
        return 1;
    }

    if (pname) {
        if (BIO_puts(out, pname) <= 0)
            return 0;
        if (BIO_puts(out, ":") <= 0)
            return 0;
    }

    switch (utype) {
    case V_ASN1_BOOLEAN:
        {
            int boolval = *(int *)fld;
            if (boolval == -1)
                boolval = it->size;
            ret = asn1_print_boolean_ctx(out, boolval, pctx);
        }
        break;

    case V_ASN1_INTEGER:
    case V_ASN1_ENUMERATED:
        ret = asn1_print_integer_ctx(out, str, pctx);
        break;

    case V_ASN1_UTCTIME:
        ret = ASN1_UTCTIME_print(out, str);
        break;

    case V_ASN1_GENERALIZEDTIME:
        ret = ASN1_GENERALIZEDTIME_print(out, str);
        break;

    case V_ASN1_OBJECT:
        ret = asn1_print_oid_ctx(out, (const ASN1_OBJECT *)*fld, pctx);
        break;

    case V_ASN1_OCTET_STRING:
    case V_ASN1_BIT_STRING:
        ret = asn1_print_obstring_ctx(out, str, indent, pctx);
        needlf = 0;
        break;

    case V_ASN1_SEQUENCE:
    case V_ASN1_SET:
    case V_ASN1_OTHER:
        if (BIO_puts(out, "\n") <= 0)
            return 0;
        if (ASN1_parse_dump(out, str->data, str->length, indent, 0) <= 0)
            ret = 0;
        needlf = 0;
        break;

    default:
        ret = ASN1_STRING_print_ex(out, str, pctx->str_flags);

    }
    if (!ret)
        return 0;
    if (needlf && BIO_puts(out, "\n") <= 0)
        return 0;
    return 1;
}
/* tasn_typ.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
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
// #include "asn1.h"
// #include "asn1t.h"

/* Declarations for string types */


IMPLEMENT_ASN1_TYPE(ASN1_INTEGER)
IMPLEMENT_ASN1_FUNCTIONS(ASN1_INTEGER)

IMPLEMENT_ASN1_TYPE(ASN1_ENUMERATED)
IMPLEMENT_ASN1_FUNCTIONS(ASN1_ENUMERATED)

IMPLEMENT_ASN1_TYPE(ASN1_BIT_STRING)
IMPLEMENT_ASN1_FUNCTIONS(ASN1_BIT_STRING)

IMPLEMENT_ASN1_TYPE(ASN1_OCTET_STRING)
IMPLEMENT_ASN1_FUNCTIONS(ASN1_OCTET_STRING)

IMPLEMENT_ASN1_TYPE(ASN1_NULL)
IMPLEMENT_ASN1_FUNCTIONS(ASN1_NULL)

IMPLEMENT_ASN1_TYPE(ASN1_OBJECT)

IMPLEMENT_ASN1_TYPE(ASN1_UTF8STRING)
IMPLEMENT_ASN1_FUNCTIONS(ASN1_UTF8STRING)

IMPLEMENT_ASN1_TYPE(ASN1_PRINTABLESTRING)
IMPLEMENT_ASN1_FUNCTIONS(ASN1_PRINTABLESTRING)

IMPLEMENT_ASN1_TYPE(ASN1_T61STRING)
IMPLEMENT_ASN1_FUNCTIONS(ASN1_T61STRING)

IMPLEMENT_ASN1_TYPE(ASN1_IA5STRING)
IMPLEMENT_ASN1_FUNCTIONS(ASN1_IA5STRING)

IMPLEMENT_ASN1_TYPE(ASN1_GENERALSTRING)
IMPLEMENT_ASN1_FUNCTIONS(ASN1_GENERALSTRING)

IMPLEMENT_ASN1_TYPE(ASN1_UTCTIME)
IMPLEMENT_ASN1_FUNCTIONS(ASN1_UTCTIME)

IMPLEMENT_ASN1_TYPE(ASN1_GENERALIZEDTIME)
IMPLEMENT_ASN1_FUNCTIONS(ASN1_GENERALIZEDTIME)

IMPLEMENT_ASN1_TYPE(ASN1_VISIBLESTRING)
IMPLEMENT_ASN1_FUNCTIONS(ASN1_VISIBLESTRING)

IMPLEMENT_ASN1_TYPE(ASN1_UNIVERSALSTRING)
IMPLEMENT_ASN1_FUNCTIONS(ASN1_UNIVERSALSTRING)

IMPLEMENT_ASN1_TYPE(ASN1_BMPSTRING)
IMPLEMENT_ASN1_FUNCTIONS(ASN1_BMPSTRING)

IMPLEMENT_ASN1_TYPE(ASN1_ANY)

/* Just swallow an ASN1_SEQUENCE in an ASN1_STRING */
IMPLEMENT_ASN1_TYPE(ASN1_SEQUENCE)

IMPLEMENT_ASN1_FUNCTIONS_fname(ASN1_TYPE, ASN1_ANY, ASN1_TYPE)

/* Multistring types */

IMPLEMENT_ASN1_MSTRING(ASN1_PRINTABLE, B_ASN1_PRINTABLE)
IMPLEMENT_ASN1_FUNCTIONS_name(ASN1_STRING, ASN1_PRINTABLE)

IMPLEMENT_ASN1_MSTRING(DISPLAYTEXT, B_ASN1_DISPLAYTEXT)
IMPLEMENT_ASN1_FUNCTIONS_name(ASN1_STRING, DISPLAYTEXT)

IMPLEMENT_ASN1_MSTRING(DIRECTORYSTRING, B_ASN1_DIRECTORYSTRING)
IMPLEMENT_ASN1_FUNCTIONS_name(ASN1_STRING, DIRECTORYSTRING)

/* Three separate BOOLEAN type: normal, DEFAULT TRUE and DEFAULT FALSE */
IMPLEMENT_ASN1_TYPE_ex(ASN1_BOOLEAN, ASN1_BOOLEAN, -1)
IMPLEMENT_ASN1_TYPE_ex(ASN1_TBOOLEAN, ASN1_BOOLEAN, 1)
IMPLEMENT_ASN1_TYPE_ex(ASN1_FBOOLEAN, ASN1_BOOLEAN, 0)

/* Special, OCTET STRING with indefinite length constructed support */

IMPLEMENT_ASN1_TYPE_ex(ASN1_OCTET_STRING_NDEF, ASN1_OCTET_STRING, ASN1_TFLG_NDEF)

ASN1_ITEM_TEMPLATE(ASN1_SEQUENCE_ANY) =
        ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, ASN1_SEQUENCE_ANY, ASN1_ANY)
ASN1_ITEM_TEMPLATE_END(ASN1_SEQUENCE_ANY)

ASN1_ITEM_TEMPLATE(ASN1_SET_ANY) =
        ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SET_OF, 0, ASN1_SET_ANY, ASN1_ANY)
ASN1_ITEM_TEMPLATE_END(ASN1_SET_ANY)

IMPLEMENT_ASN1_ENCODE_FUNCTIONS_const_fname(ASN1_SEQUENCE_ANY, ASN1_SEQUENCE_ANY, ASN1_SEQUENCE_ANY)
IMPLEMENT_ASN1_ENCODE_FUNCTIONS_const_fname(ASN1_SEQUENCE_ANY, ASN1_SET_ANY, ASN1_SET_ANY)
/* tasn_utl.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2000.
 */
/* ====================================================================
 * Copyright (c) 2000-2004 The OpenSSL Project.  All rights reserved.
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

#include <stddef.h>
#include <string.h>
// #include "asn1.h"
// #include "asn1t.h"
// #include "objects.h"
// #include "err.h"

/* Utility functions for manipulating fields and offsets */

/* Add 'offset' to 'addr' */
#define offset2ptr(addr, offset) (void *)(((char *) addr) + offset)

/*
 * Given an ASN1_ITEM CHOICE type return the selector value
 */

int asn1_get_choice_selector(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    int *sel = offset2ptr(*pval, it->utype);
    return *sel;
}

/*
 * Given an ASN1_ITEM CHOICE type set the selector value, return old value.
 */

int asn1_set_choice_selector(ASN1_VALUE **pval, int value,
                             const ASN1_ITEM *it)
{
    int *sel, ret;
    sel = offset2ptr(*pval, it->utype);
    ret = *sel;
    *sel = value;
    return ret;
}

/*
 * Do reference counting. The value 'op' decides what to do. if it is +1
 * then the count is incremented. If op is 0 count is set to 1. If op is -1
 * count is decremented and the return value is the current refrence count or
 * 0 if no reference count exists.
 */

int asn1_do_lock(ASN1_VALUE **pval, int op, const ASN1_ITEM *it)
{
    const ASN1_AUX *aux;
    int *lck, ret;
    if ((it->itype != ASN1_ITYPE_SEQUENCE)
        && (it->itype != ASN1_ITYPE_NDEF_SEQUENCE))
        return 0;
    aux = it->funcs;
    if (!aux || !(aux->flags & ASN1_AFLG_REFCOUNT))
        return 0;
    lck = offset2ptr(*pval, aux->ref_offset);
    if (op == 0) {
        *lck = 1;
        return 1;
    }
    ret = CRYPTO_add(lck, op, aux->ref_lock);
#ifdef REF_PRINT
    fprintf(stderr, "%s: Reference Count: %d\n", it->sname, *lck);
#endif
#ifdef REF_CHECK
    if (ret < 0)
        fprintf(stderr, "%s, bad reference count\n", it->sname);
#endif
    return ret;
}

static ASN1_ENCODING *asn1_get_enc_ptr(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    const ASN1_AUX *aux;
    if (!pval || !*pval)
        return NULL;
    aux = it->funcs;
    if (!aux || !(aux->flags & ASN1_AFLG_ENCODING))
        return NULL;
    return offset2ptr(*pval, aux->enc_offset);
}

void asn1_enc_init(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    ASN1_ENCODING *enc;
    enc = asn1_get_enc_ptr(pval, it);
    if (enc) {
        enc->enc = NULL;
        enc->len = 0;
        enc->modified = 1;
    }
}

void asn1_enc_free(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    ASN1_ENCODING *enc;
    enc = asn1_get_enc_ptr(pval, it);
    if (enc) {
        if (enc->enc)
            OPENSSL_free(enc->enc);
        enc->enc = NULL;
        enc->len = 0;
        enc->modified = 1;
    }
}

int asn1_enc_save(ASN1_VALUE **pval, const unsigned char *in, int inlen,
                  const ASN1_ITEM *it)
{
    ASN1_ENCODING *enc;
    enc = asn1_get_enc_ptr(pval, it);
    if (!enc)
        return 1;

    if (enc->enc)
        OPENSSL_free(enc->enc);
    enc->enc = OPENSSL_malloc(inlen);
    if (!enc->enc)
        return 0;
    memcpy(enc->enc, in, inlen);
    enc->len = inlen;
    enc->modified = 0;

    return 1;
}

int asn1_enc_restore(int *len, unsigned char **out, ASN1_VALUE **pval,
                     const ASN1_ITEM *it)
{
    ASN1_ENCODING *enc;
    enc = asn1_get_enc_ptr(pval, it);
    if (!enc || enc->modified)
        return 0;
    if (out) {
        memcpy(*out, enc->enc, enc->len);
        *out += enc->len;
    }
    if (len)
        *len = enc->len;
    return 1;
}

/* Given an ASN1_TEMPLATE get a pointer to a field */
ASN1_VALUE **asn1_get_field_ptr(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt)
{
    ASN1_VALUE **pvaltmp;
    if (tt->flags & ASN1_TFLG_COMBINE)
        return pval;
    pvaltmp = offset2ptr(*pval, tt->offset);
    /*
     * NOTE for BOOLEAN types the field is just a plain int so we can't
     * return int **, so settle for (int *).
     */
    return pvaltmp;
}

/*
 * Handle ANY DEFINED BY template, find the selector, look up the relevant
 * ASN1_TEMPLATE in the table and return it.
 */

const ASN1_TEMPLATE *asn1_do_adb(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt,
                                 int nullerr)
{
    const ASN1_ADB *adb;
    const ASN1_ADB_TABLE *atbl;
    long selector;
    ASN1_VALUE **sfld;
    int i;
    if (!(tt->flags & ASN1_TFLG_ADB_MASK))
        return tt;

    /* Else ANY DEFINED BY ... get the table */
    adb = ASN1_ADB_ptr(tt->item);

    /* Get the selector field */
    sfld = offset2ptr(*pval, adb->offset);

    /* Check if NULL */
    if (*sfld == NULL) {
        if (!adb->null_tt)
            goto err;
        return adb->null_tt;
    }

    /*
     * Convert type to a long: NB: don't check for NID_undef here because it
     * might be a legitimate value in the table
     */
    if (tt->flags & ASN1_TFLG_ADB_OID)
        selector = OBJ_obj2nid((ASN1_OBJECT *)*sfld);
    else
        selector = ASN1_INTEGER_get((ASN1_INTEGER *)*sfld);

    /*
     * Try to find matching entry in table Maybe should check application
     * types first to allow application override? Might also be useful to
     * have a flag which indicates table is sorted and we can do a binary
     * search. For now stick to a linear search.
     */

    for (atbl = adb->tbl, i = 0; i < adb->tblcount; i++, atbl++)
        if (atbl->value == selector)
            return &atbl->tt;

    /* FIXME: need to search application table too */

    /* No match, return default type */
    if (!adb->default_tt)
        goto err;
    return adb->default_tt;

 err:
    /* FIXME: should log the value or OID of unsupported type */
    if (nullerr)
        ASN1err(ASN1_F_ASN1_DO_ADB, ASN1_R_UNSUPPORTED_ANY_DEFINED_BY_TYPE);
    return NULL;
}
