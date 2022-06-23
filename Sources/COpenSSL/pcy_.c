/* pcy_cache.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
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
#include "x509.h"
#include "x509v3.h"

#include "pcy_int.h"

static int policy_data_cmp(const X509_POLICY_DATA *const *a,
                           const X509_POLICY_DATA *const *b);
static int policy_cache_set_int(long *out, ASN1_INTEGER *value);

/*
 * Set cache entry according to CertificatePolicies extension. Note: this
 * destroys the passed CERTIFICATEPOLICIES structure.
 */

static int policy_cache_create(X509 *x,
                               CERTIFICATEPOLICIES *policies, int crit)
{
    int i;
    int ret = 0;
    X509_POLICY_CACHE *cache = x->policy_cache;
    X509_POLICY_DATA *data = NULL;
    POLICYINFO *policy;
    if (sk_POLICYINFO_num(policies) == 0)
        goto bad_policy;
    cache->data = sk_X509_POLICY_DATA_new(policy_data_cmp);
    if (!cache->data)
        goto bad_policy;
    for (i = 0; i < sk_POLICYINFO_num(policies); i++) {
        policy = sk_POLICYINFO_value(policies, i);
        data = policy_data_new(policy, NULL, crit);
        if (!data)
            goto bad_policy;
        /*
         * Duplicate policy OIDs are illegal: reject if matches found.
         */
        if (OBJ_obj2nid(data->valid_policy) == NID_any_policy) {
            if (cache->anyPolicy) {
                ret = -1;
                goto bad_policy;
            }
            cache->anyPolicy = data;
        } else if (sk_X509_POLICY_DATA_find(cache->data, data) != -1) {
            ret = -1;
            goto bad_policy;
        } else if (!sk_X509_POLICY_DATA_push(cache->data, data))
            goto bad_policy;
        data = NULL;
    }
    ret = 1;
 bad_policy:
    if (ret == -1)
        x->ex_flags |= EXFLAG_INVALID_POLICY;
    if (data)
        policy_data_free(data);
    sk_POLICYINFO_pop_free(policies, POLICYINFO_free);
    if (ret <= 0) {
        sk_X509_POLICY_DATA_pop_free(cache->data, policy_data_free);
        cache->data = NULL;
    }
    return ret;
}

static int policy_cache_new(X509 *x)
{
    X509_POLICY_CACHE *cache;
    ASN1_INTEGER *ext_any = NULL;
    POLICY_CONSTRAINTS *ext_pcons = NULL;
    CERTIFICATEPOLICIES *ext_cpols = NULL;
    POLICY_MAPPINGS *ext_pmaps = NULL;
    int i;
    cache = OPENSSL_malloc(sizeof(X509_POLICY_CACHE));
    if (!cache)
        return 0;
    cache->anyPolicy = NULL;
    cache->data = NULL;
    cache->any_skip = -1;
    cache->explicit_skip = -1;
    cache->map_skip = -1;

    x->policy_cache = cache;

    /*
     * Handle requireExplicitPolicy *first*. Need to process this even if we
     * don't have any policies.
     */
    ext_pcons = X509_get_ext_d2i(x, NID_policy_constraints, &i, NULL);

    if (!ext_pcons) {
        if (i != -1)
            goto bad_cache;
    } else {
        if (!ext_pcons->requireExplicitPolicy
            && !ext_pcons->inhibitPolicyMapping)
            goto bad_cache;
        if (!policy_cache_set_int(&cache->explicit_skip,
                                  ext_pcons->requireExplicitPolicy))
            goto bad_cache;
        if (!policy_cache_set_int(&cache->map_skip,
                                  ext_pcons->inhibitPolicyMapping))
            goto bad_cache;
    }

    /* Process CertificatePolicies */

    ext_cpols = X509_get_ext_d2i(x, NID_certificate_policies, &i, NULL);
    /*
     * If no CertificatePolicies extension or problem decoding then there is
     * no point continuing because the valid policies will be NULL.
     */
    if (!ext_cpols) {
        /* If not absent some problem with extension */
        if (i != -1)
            goto bad_cache;
        return 1;
    }

    i = policy_cache_create(x, ext_cpols, i);

    /* NB: ext_cpols freed by policy_cache_set_policies */

    if (i <= 0)
        return i;

    ext_pmaps = X509_get_ext_d2i(x, NID_policy_mappings, &i, NULL);

    if (!ext_pmaps) {
        /* If not absent some problem with extension */
        if (i != -1)
            goto bad_cache;
    } else {
        i = policy_cache_set_mapping(x, ext_pmaps);
        if (i <= 0)
            goto bad_cache;
    }

    ext_any = X509_get_ext_d2i(x, NID_inhibit_any_policy, &i, NULL);

    if (!ext_any) {
        if (i != -1)
            goto bad_cache;
    } else if (!policy_cache_set_int(&cache->any_skip, ext_any))
        goto bad_cache;

    if (0) {
 bad_cache:
        x->ex_flags |= EXFLAG_INVALID_POLICY;
    }

    if (ext_pcons)
        POLICY_CONSTRAINTS_free(ext_pcons);

    if (ext_any)
        ASN1_INTEGER_free(ext_any);

    return 1;

}

void policy_cache_free(X509_POLICY_CACHE *cache)
{
    if (!cache)
        return;
    if (cache->anyPolicy)
        policy_data_free(cache->anyPolicy);
    if (cache->data)
        sk_X509_POLICY_DATA_pop_free(cache->data, policy_data_free);
    OPENSSL_free(cache);
}

const X509_POLICY_CACHE *policy_cache_set(X509 *x)
{

    if (x->policy_cache == NULL) {
        CRYPTO_w_lock(CRYPTO_LOCK_X509);
        policy_cache_new(x);
        CRYPTO_w_unlock(CRYPTO_LOCK_X509);
    }

    return x->policy_cache;

}

X509_POLICY_DATA *policy_cache_find_data(const X509_POLICY_CACHE *cache,
                                         const ASN1_OBJECT *id)
{
    int idx;
    X509_POLICY_DATA tmp;
    tmp.valid_policy = (ASN1_OBJECT *)id;
    idx = sk_X509_POLICY_DATA_find(cache->data, &tmp);
    if (idx == -1)
        return NULL;
    return sk_X509_POLICY_DATA_value(cache->data, idx);
}

static int policy_data_cmp(const X509_POLICY_DATA *const *a,
                           const X509_POLICY_DATA *const *b)
{
    return OBJ_cmp((*a)->valid_policy, (*b)->valid_policy);
}

static int policy_cache_set_int(long *out, ASN1_INTEGER *value)
{
    if (value == NULL)
        return 1;
    if (value->type == V_ASN1_NEG_INTEGER)
        return 0;
    *out = ASN1_INTEGER_get(value);
    return 1;
}
/* pcy_data.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
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
// #include "x509.h"
// #include "x509v3.h"

// #include "pcy_int.h"

/* Policy Node routines */

void policy_data_free(X509_POLICY_DATA *data)
{
    ASN1_OBJECT_free(data->valid_policy);
    /* Don't free qualifiers if shared */
    if (!(data->flags & POLICY_DATA_FLAG_SHARED_QUALIFIERS))
        sk_POLICYQUALINFO_pop_free(data->qualifier_set, POLICYQUALINFO_free);
    sk_ASN1_OBJECT_pop_free(data->expected_policy_set, ASN1_OBJECT_free);
    OPENSSL_free(data);
}

/*
 * Create a data based on an existing policy. If 'id' is NULL use the oid in
 * the policy, otherwise use 'id'. This behaviour covers the two types of
 * data in RFC3280: data with from a CertificatePolcies extension and
 * additional data with just the qualifiers of anyPolicy and ID from another
 * source.
 */

X509_POLICY_DATA *policy_data_new(POLICYINFO *policy,
                                  const ASN1_OBJECT *cid, int crit)
{
    X509_POLICY_DATA *ret;
    ASN1_OBJECT *id;
    if (!policy && !cid)
        return NULL;
    if (cid) {
        id = OBJ_dup(cid);
        if (!id)
            return NULL;
    } else
        id = NULL;
    ret = OPENSSL_malloc(sizeof(X509_POLICY_DATA));
    if (!ret)
        return NULL;
    ret->expected_policy_set = sk_ASN1_OBJECT_new_null();
    if (!ret->expected_policy_set) {
        OPENSSL_free(ret);
        if (id)
            ASN1_OBJECT_free(id);
        return NULL;
    }

    if (crit)
        ret->flags = POLICY_DATA_FLAG_CRITICAL;
    else
        ret->flags = 0;

    if (id)
        ret->valid_policy = id;
    else {
        ret->valid_policy = policy->policyid;
        policy->policyid = NULL;
    }

    if (policy) {
        ret->qualifier_set = policy->qualifiers;
        policy->qualifiers = NULL;
    } else
        ret->qualifier_set = NULL;

    return ret;
}
/* pcy_lib.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
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
// #include "x509.h"
// #include "x509v3.h"

// #include "pcy_int.h"

/* accessor functions */

/* X509_POLICY_TREE stuff */

int X509_policy_tree_level_count(const X509_POLICY_TREE *tree)
{
    if (!tree)
        return 0;
    return tree->nlevel;
}

X509_POLICY_LEVEL *X509_policy_tree_get0_level(const X509_POLICY_TREE *tree,
                                               int i)
{
    if (!tree || (i < 0) || (i >= tree->nlevel))
        return NULL;
    return tree->levels + i;
}

STACK_OF(X509_POLICY_NODE) *X509_policy_tree_get0_policies(const
                                                           X509_POLICY_TREE
                                                           *tree)
{
    if (!tree)
        return NULL;
    return tree->auth_policies;
}

STACK_OF(X509_POLICY_NODE) *X509_policy_tree_get0_user_policies(const
                                                                X509_POLICY_TREE
                                                                *tree)
{
    if (!tree)
        return NULL;
    if (tree->flags & POLICY_FLAG_ANY_POLICY)
        return tree->auth_policies;
    else
        return tree->user_policies;
}

/* X509_POLICY_LEVEL stuff */

int X509_policy_level_node_count(X509_POLICY_LEVEL *level)
{
    int n;
    if (!level)
        return 0;
    if (level->anyPolicy)
        n = 1;
    else
        n = 0;
    if (level->nodes)
        n += sk_X509_POLICY_NODE_num(level->nodes);
    return n;
}

X509_POLICY_NODE *X509_policy_level_get0_node(X509_POLICY_LEVEL *level, int i)
{
    if (!level)
        return NULL;
    if (level->anyPolicy) {
        if (i == 0)
            return level->anyPolicy;
        i--;
    }
    return sk_X509_POLICY_NODE_value(level->nodes, i);
}

/* X509_POLICY_NODE stuff */

const ASN1_OBJECT *X509_policy_node_get0_policy(const X509_POLICY_NODE *node)
{
    if (!node)
        return NULL;
    return node->data->valid_policy;
}

#if 0
int X509_policy_node_get_critical(const X509_POLICY_NODE *node)
{
    if (node_critical(node))
        return 1;
    return 0;
}
#endif

STACK_OF(POLICYQUALINFO) *X509_policy_node_get0_qualifiers(const
                                                           X509_POLICY_NODE
                                                           *node)
{
    if (!node)
        return NULL;
    return node->data->qualifier_set;
}

const X509_POLICY_NODE *X509_policy_node_get0_parent(const X509_POLICY_NODE
                                                     *node)
{
    if (!node)
        return NULL;
    return node->parent;
}
/* pcy_map.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
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
// #include "x509.h"
// #include "x509v3.h"

// #include "pcy_int.h"

/*
 * Set policy mapping entries in cache. Note: this modifies the passed
 * POLICY_MAPPINGS structure
 */

int policy_cache_set_mapping(X509 *x, POLICY_MAPPINGS *maps)
{
    POLICY_MAPPING *map;
    X509_POLICY_DATA *data;
    X509_POLICY_CACHE *cache = x->policy_cache;
    int i;
    int ret = 0;
    if (sk_POLICY_MAPPING_num(maps) == 0) {
        ret = -1;
        goto bad_mapping;
    }
    for (i = 0; i < sk_POLICY_MAPPING_num(maps); i++) {
        map = sk_POLICY_MAPPING_value(maps, i);
        /* Reject if map to or from anyPolicy */
        if ((OBJ_obj2nid(map->subjectDomainPolicy) == NID_any_policy)
            || (OBJ_obj2nid(map->issuerDomainPolicy) == NID_any_policy)) {
            ret = -1;
            goto bad_mapping;
        }

        /* Attempt to find matching policy data */
        data = policy_cache_find_data(cache, map->issuerDomainPolicy);
        /* If we don't have anyPolicy can't map */
        if (!data && !cache->anyPolicy)
            continue;

        /* Create a NODE from anyPolicy */
        if (!data) {
            data = policy_data_new(NULL, map->issuerDomainPolicy,
                                   cache->anyPolicy->flags
                                   & POLICY_DATA_FLAG_CRITICAL);
            if (!data)
                goto bad_mapping;
            data->qualifier_set = cache->anyPolicy->qualifier_set;
            /*
             * map->issuerDomainPolicy = NULL;
             */
            data->flags |= POLICY_DATA_FLAG_MAPPED_ANY;
            data->flags |= POLICY_DATA_FLAG_SHARED_QUALIFIERS;
            if (!sk_X509_POLICY_DATA_push(cache->data, data)) {
                policy_data_free(data);
                goto bad_mapping;
            }
        } else
            data->flags |= POLICY_DATA_FLAG_MAPPED;
        if (!sk_ASN1_OBJECT_push(data->expected_policy_set,
                                 map->subjectDomainPolicy))
            goto bad_mapping;
        map->subjectDomainPolicy = NULL;

    }

    ret = 1;
 bad_mapping:
    if (ret == -1)
        x->ex_flags |= EXFLAG_INVALID_POLICY;
    sk_POLICY_MAPPING_pop_free(maps, POLICY_MAPPING_free);
    return ret;

}
/* pcy_node.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
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

#include "asn1.h"
// #include "x509.h"
// #include "x509v3.h"

// #include "pcy_int.h"

static int node_cmp(const X509_POLICY_NODE *const *a,
                    const X509_POLICY_NODE *const *b)
{
    return OBJ_cmp((*a)->data->valid_policy, (*b)->data->valid_policy);
}

STACK_OF(X509_POLICY_NODE) *policy_node_cmp_new(void)
{
    return sk_X509_POLICY_NODE_new(node_cmp);
}

X509_POLICY_NODE *tree_find_sk(STACK_OF(X509_POLICY_NODE) *nodes,
                               const ASN1_OBJECT *id)
{
    X509_POLICY_DATA n;
    X509_POLICY_NODE l;
    int idx;

    n.valid_policy = (ASN1_OBJECT *)id;
    l.data = &n;

    idx = sk_X509_POLICY_NODE_find(nodes, &l);
    if (idx == -1)
        return NULL;

    return sk_X509_POLICY_NODE_value(nodes, idx);

}

X509_POLICY_NODE *level_find_node(const X509_POLICY_LEVEL *level,
                                  const X509_POLICY_NODE *parent,
                                  const ASN1_OBJECT *id)
{
    X509_POLICY_NODE *node;
    int i;
    for (i = 0; i < sk_X509_POLICY_NODE_num(level->nodes); i++) {
        node = sk_X509_POLICY_NODE_value(level->nodes, i);
        if (node->parent == parent) {
            if (!OBJ_cmp(node->data->valid_policy, id))
                return node;
        }
    }
    return NULL;
}

X509_POLICY_NODE *level_add_node(X509_POLICY_LEVEL *level,
                                 const X509_POLICY_DATA *data,
                                 X509_POLICY_NODE *parent,
                                 X509_POLICY_TREE *tree)
{
    X509_POLICY_NODE *node;
    node = OPENSSL_malloc(sizeof(X509_POLICY_NODE));
    if (!node)
        return NULL;
    node->data = data;
    node->parent = parent;
    node->nchild = 0;
    if (level) {
        if (OBJ_obj2nid(data->valid_policy) == NID_any_policy) {
            if (level->anyPolicy)
                goto node_error;
            level->anyPolicy = node;
        } else {

            if (!level->nodes)
                level->nodes = policy_node_cmp_new();
            if (!level->nodes)
                goto node_error;
            if (!sk_X509_POLICY_NODE_push(level->nodes, node))
                goto node_error;
        }
    }

    if (tree) {
        if (!tree->extra_data)
            tree->extra_data = sk_X509_POLICY_DATA_new_null();
        if (!tree->extra_data)
            goto node_error;
        if (!sk_X509_POLICY_DATA_push(tree->extra_data, data))
            goto node_error;
    }

    if (parent)
        parent->nchild++;

    return node;

 node_error:
    policy_node_free(node);
    return 0;

}

void policy_node_free(X509_POLICY_NODE *node)
{
    OPENSSL_free(node);
}

/*
 * See if a policy node matches a policy OID. If mapping enabled look through
 * expected policy set otherwise just valid policy.
 */

int policy_node_match(const X509_POLICY_LEVEL *lvl,
                      const X509_POLICY_NODE *node, const ASN1_OBJECT *oid)
{
    int i;
    ASN1_OBJECT *policy_oid;
    const X509_POLICY_DATA *x = node->data;

    if ((lvl->flags & X509_V_FLAG_INHIBIT_MAP)
        || !(x->flags & POLICY_DATA_FLAG_MAP_MASK)) {
        if (!OBJ_cmp(x->valid_policy, oid))
            return 1;
        return 0;
    }

    for (i = 0; i < sk_ASN1_OBJECT_num(x->expected_policy_set); i++) {
        policy_oid = sk_ASN1_OBJECT_value(x->expected_policy_set, i);
        if (!OBJ_cmp(policy_oid, oid))
            return 1;
    }
    return 0;

}
/* pcy_tree.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
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
// #include "x509.h"
// #include "x509v3.h"

// #include "pcy_int.h"

/*
 * Enable this to print out the complete policy tree at various point during
 * evaluation.
 */

/*
 * #define OPENSSL_POLICY_DEBUG
 */

#ifdef OPENSSL_POLICY_DEBUG

static void expected_print(BIO *err, X509_POLICY_LEVEL *lev,
                           X509_POLICY_NODE *node, int indent)
{
    if ((lev->flags & X509_V_FLAG_INHIBIT_MAP)
        || !(node->data->flags & POLICY_DATA_FLAG_MAP_MASK))
        BIO_puts(err, "  Not Mapped\n");
    else {
        int i;
        STACK_OF(ASN1_OBJECT) *pset = node->data->expected_policy_set;
        ASN1_OBJECT *oid;
        BIO_puts(err, "  Expected: ");
        for (i = 0; i < sk_ASN1_OBJECT_num(pset); i++) {
            oid = sk_ASN1_OBJECT_value(pset, i);
            if (i)
                BIO_puts(err, ", ");
            i2a_ASN1_OBJECT(err, oid);
        }
        BIO_puts(err, "\n");
    }
}

static void tree_print(char *str, X509_POLICY_TREE *tree,
                       X509_POLICY_LEVEL *curr)
{
    X509_POLICY_LEVEL *plev;
    X509_POLICY_NODE *node;
    int i;
    BIO *err;
    err = BIO_new_fp(stderr, BIO_NOCLOSE);
    if (!curr)
        curr = tree->levels + tree->nlevel;
    else
        curr++;
    BIO_printf(err, "Level print after %s\n", str);
    BIO_printf(err, "Printing Up to Level %ld\n", curr - tree->levels);
    for (plev = tree->levels; plev != curr; plev++) {
        BIO_printf(err, "Level %ld, flags = %x\n",
                   plev - tree->levels, plev->flags);
        for (i = 0; i < sk_X509_POLICY_NODE_num(plev->nodes); i++) {
            node = sk_X509_POLICY_NODE_value(plev->nodes, i);
            X509_POLICY_NODE_print(err, node, 2);
            expected_print(err, plev, node, 2);
            BIO_printf(err, "  Flags: %x\n", node->data->flags);
        }
        if (plev->anyPolicy)
            X509_POLICY_NODE_print(err, plev->anyPolicy, 2);
    }

    BIO_free(err);

}
#else

# define tree_print(a,b,c)      /* */

#endif

/*-
 * Initialize policy tree. Return values:
 *  0 Some internal error occurred.
 * -1 Inconsistent or invalid extensions in certificates.
 *  1 Tree initialized OK.
 *  2 Policy tree is empty.
 *  5 Tree OK and requireExplicitPolicy true.
 *  6 Tree empty and requireExplicitPolicy true.
 */

static int tree_init(X509_POLICY_TREE **ptree, STACK_OF(X509) *certs,
                     unsigned int flags)
{
    X509_POLICY_TREE *tree;
    X509_POLICY_LEVEL *level;
    const X509_POLICY_CACHE *cache;
    X509_POLICY_DATA *data = NULL;
    X509 *x;
    int ret = 1;
    int i, n;
    int explicit_policy;
    int any_skip;
    int map_skip;
    *ptree = NULL;
    n = sk_X509_num(certs);

#if 0
    /* Disable policy mapping for now... */
    flags |= X509_V_FLAG_INHIBIT_MAP;
#endif

    if (flags & X509_V_FLAG_EXPLICIT_POLICY)
        explicit_policy = 0;
    else
        explicit_policy = n + 1;

    if (flags & X509_V_FLAG_INHIBIT_ANY)
        any_skip = 0;
    else
        any_skip = n + 1;

    if (flags & X509_V_FLAG_INHIBIT_MAP)
        map_skip = 0;
    else
        map_skip = n + 1;

    /* Can't do anything with just a trust anchor */
    if (n == 1)
        return 1;
    /*
     * First setup policy cache in all certificates apart from the trust
     * anchor. Note any bad cache results on the way. Also can calculate
     * explicit_policy value at this point.
     */
    for (i = n - 2; i >= 0; i--) {
        x = sk_X509_value(certs, i);
        X509_check_purpose(x, -1, -1);
        cache = policy_cache_set(x);
        /* If cache NULL something bad happened: return immediately */
        if (cache == NULL)
            return 0;
        /*
         * If inconsistent extensions keep a note of it but continue
         */
        if (x->ex_flags & EXFLAG_INVALID_POLICY)
            ret = -1;
        /*
         * Otherwise if we have no data (hence no CertificatePolicies) and
         * haven't already set an inconsistent code note it.
         */
        else if ((ret == 1) && !cache->data)
            ret = 2;
        if (explicit_policy > 0) {
            if (!(x->ex_flags & EXFLAG_SI))
                explicit_policy--;
            if ((cache->explicit_skip != -1)
                && (cache->explicit_skip < explicit_policy))
                explicit_policy = cache->explicit_skip;
        }
    }

    if (ret != 1) {
        if (ret == 2 && !explicit_policy)
            return 6;
        return ret;
    }

    /* If we get this far initialize the tree */

    tree = OPENSSL_malloc(sizeof(X509_POLICY_TREE));

    if (!tree)
        return 0;

    tree->flags = 0;
    tree->levels = OPENSSL_malloc(sizeof(X509_POLICY_LEVEL) * n);
    tree->nlevel = 0;
    tree->extra_data = NULL;
    tree->auth_policies = NULL;
    tree->user_policies = NULL;

    if (!tree->levels) {
        OPENSSL_free(tree);
        return 0;
    }

    memset(tree->levels, 0, n * sizeof(X509_POLICY_LEVEL));

    tree->nlevel = n;

    level = tree->levels;

    /* Root data: initialize to anyPolicy */

    data = policy_data_new(NULL, OBJ_nid2obj(NID_any_policy), 0);

    if (!data || !level_add_node(level, data, NULL, tree))
        goto bad_tree;

    for (i = n - 2; i >= 0; i--) {
        level++;
        x = sk_X509_value(certs, i);
        cache = policy_cache_set(x);
        CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509);
        level->cert = x;

        if (!cache->anyPolicy)
            level->flags |= X509_V_FLAG_INHIBIT_ANY;

        /* Determine inhibit any and inhibit map flags */
        if (any_skip == 0) {
            /*
             * Any matching allowed if certificate is self issued and not the
             * last in the chain.
             */
            if (!(x->ex_flags & EXFLAG_SI) || (i == 0))
                level->flags |= X509_V_FLAG_INHIBIT_ANY;
        } else {
            if (!(x->ex_flags & EXFLAG_SI))
                any_skip--;
            if ((cache->any_skip >= 0)
                && (cache->any_skip < any_skip))
                any_skip = cache->any_skip;
        }

        if (map_skip == 0)
            level->flags |= X509_V_FLAG_INHIBIT_MAP;
        else {
            if (!(x->ex_flags & EXFLAG_SI))
                map_skip--;
            if ((cache->map_skip >= 0)
                && (cache->map_skip < map_skip))
                map_skip = cache->map_skip;
        }

    }

    *ptree = tree;

    if (explicit_policy)
        return 1;
    else
        return 5;

 bad_tree:

    X509_policy_tree_free(tree);

    return 0;

}

static int tree_link_matching_nodes(X509_POLICY_LEVEL *curr,
                                    const X509_POLICY_DATA *data)
{
    X509_POLICY_LEVEL *last = curr - 1;
    X509_POLICY_NODE *node;
    int i, matched = 0;
    /* Iterate through all in nodes linking matches */
    for (i = 0; i < sk_X509_POLICY_NODE_num(last->nodes); i++) {
        node = sk_X509_POLICY_NODE_value(last->nodes, i);
        if (policy_node_match(last, node, data->valid_policy)) {
            if (!level_add_node(curr, data, node, NULL))
                return 0;
            matched = 1;
        }
    }
    if (!matched && last->anyPolicy) {
        if (!level_add_node(curr, data, last->anyPolicy, NULL))
            return 0;
    }
    return 1;
}

/*
 * This corresponds to RFC3280 6.1.3(d)(1): link any data from
 * CertificatePolicies onto matching parent or anyPolicy if no match.
 */

static int tree_link_nodes(X509_POLICY_LEVEL *curr,
                           const X509_POLICY_CACHE *cache)
{
    int i;
    X509_POLICY_DATA *data;

    for (i = 0; i < sk_X509_POLICY_DATA_num(cache->data); i++) {
        data = sk_X509_POLICY_DATA_value(cache->data, i);
        /*
         * If a node is mapped any it doesn't have a corresponding
         * CertificatePolicies entry. However such an identical node would
         * be created if anyPolicy matching is enabled because there would be
         * no match with the parent valid_policy_set. So we create link
         * because then it will have the mapping flags right and we can prune
         * it later.
         */
#if 0
        if ((data->flags & POLICY_DATA_FLAG_MAPPED_ANY)
            && !(curr->flags & X509_V_FLAG_INHIBIT_ANY))
            continue;
#endif
        /* Look for matching nodes in previous level */
        if (!tree_link_matching_nodes(curr, data))
            return 0;
    }
    return 1;
}

/*
 * This corresponds to RFC3280 6.1.3(d)(2): Create new data for any unmatched
 * policies in the parent and link to anyPolicy.
 */

static int tree_add_unmatched(X509_POLICY_LEVEL *curr,
                              const X509_POLICY_CACHE *cache,
                              const ASN1_OBJECT *id,
                              X509_POLICY_NODE *node, X509_POLICY_TREE *tree)
{
    X509_POLICY_DATA *data;
    if (id == NULL)
        id = node->data->valid_policy;
    /*
     * Create a new node with qualifiers from anyPolicy and id from unmatched
     * node.
     */
    data = policy_data_new(NULL, id, node_critical(node));

    if (data == NULL)
        return 0;
    /* Curr may not have anyPolicy */
    data->qualifier_set = cache->anyPolicy->qualifier_set;
    data->flags |= POLICY_DATA_FLAG_SHARED_QUALIFIERS;
    if (!level_add_node(curr, data, node, tree)) {
        policy_data_free(data);
        return 0;
    }

    return 1;
}

static int tree_link_unmatched(X509_POLICY_LEVEL *curr,
                               const X509_POLICY_CACHE *cache,
                               X509_POLICY_NODE *node, X509_POLICY_TREE *tree)
{
    const X509_POLICY_LEVEL *last = curr - 1;
    int i;

    if ((last->flags & X509_V_FLAG_INHIBIT_MAP)
        || !(node->data->flags & POLICY_DATA_FLAG_MAPPED)) {
        /* If no policy mapping: matched if one child present */
        if (node->nchild)
            return 1;
        if (!tree_add_unmatched(curr, cache, NULL, node, tree))
            return 0;
        /* Add it */
    } else {
        /* If mapping: matched if one child per expected policy set */
        STACK_OF(ASN1_OBJECT) *expset = node->data->expected_policy_set;
        if (node->nchild == sk_ASN1_OBJECT_num(expset))
            return 1;
        /* Locate unmatched nodes */
        for (i = 0; i < sk_ASN1_OBJECT_num(expset); i++) {
            ASN1_OBJECT *oid = sk_ASN1_OBJECT_value(expset, i);
            if (level_find_node(curr, node, oid))
                continue;
            if (!tree_add_unmatched(curr, cache, oid, node, tree))
                return 0;
        }

    }

    return 1;

}

static int tree_link_any(X509_POLICY_LEVEL *curr,
                         const X509_POLICY_CACHE *cache,
                         X509_POLICY_TREE *tree)
{
    int i;
    /*
     * X509_POLICY_DATA *data;
     */
    X509_POLICY_NODE *node;
    X509_POLICY_LEVEL *last = curr - 1;

    for (i = 0; i < sk_X509_POLICY_NODE_num(last->nodes); i++) {
        node = sk_X509_POLICY_NODE_value(last->nodes, i);

        if (!tree_link_unmatched(curr, cache, node, tree))
            return 0;

#if 0

        /*
         * Skip any node with any children: we only want unmathced nodes.
         * Note: need something better for policy mapping because each node
         * may have multiple children
         */
        if (node->nchild)
            continue;

        /*
         * Create a new node with qualifiers from anyPolicy and id from
         * unmatched node.
         */
        data = policy_data_new(NULL, node->data->valid_policy,
                               node_critical(node));

        if (data == NULL)
            return 0;
        /* Curr may not have anyPolicy */
        data->qualifier_set = cache->anyPolicy->qualifier_set;
        data->flags |= POLICY_DATA_FLAG_SHARED_QUALIFIERS;
        if (!level_add_node(curr, data, node, tree)) {
            policy_data_free(data);
            return 0;
        }
#endif

    }
    /* Finally add link to anyPolicy */
    if (last->anyPolicy) {
        if (!level_add_node(curr, cache->anyPolicy, last->anyPolicy, NULL))
            return 0;
    }
    return 1;
}

/*
 * Prune the tree: delete any child mapped child data on the current level
 * then proceed up the tree deleting any data with no children. If we ever
 * have no data on a level we can halt because the tree will be empty.
 */

static int tree_prune(X509_POLICY_TREE *tree, X509_POLICY_LEVEL *curr)
{
    STACK_OF(X509_POLICY_NODE) *nodes;
    X509_POLICY_NODE *node;
    int i;
    nodes = curr->nodes;
    if (curr->flags & X509_V_FLAG_INHIBIT_MAP) {
        for (i = sk_X509_POLICY_NODE_num(nodes) - 1; i >= 0; i--) {
            node = sk_X509_POLICY_NODE_value(nodes, i);
            /* Delete any mapped data: see RFC3280 XXXX */
            if (node->data->flags & POLICY_DATA_FLAG_MAP_MASK) {
                node->parent->nchild--;
                OPENSSL_free(node);
                (void)sk_X509_POLICY_NODE_delete(nodes, i);
            }
        }
    }

    for (;;) {
        --curr;
        nodes = curr->nodes;
        for (i = sk_X509_POLICY_NODE_num(nodes) - 1; i >= 0; i--) {
            node = sk_X509_POLICY_NODE_value(nodes, i);
            if (node->nchild == 0) {
                node->parent->nchild--;
                OPENSSL_free(node);
                (void)sk_X509_POLICY_NODE_delete(nodes, i);
            }
        }
        if (curr->anyPolicy && !curr->anyPolicy->nchild) {
            if (curr->anyPolicy->parent)
                curr->anyPolicy->parent->nchild--;
            OPENSSL_free(curr->anyPolicy);
            curr->anyPolicy = NULL;
        }
        if (curr == tree->levels) {
            /* If we zapped anyPolicy at top then tree is empty */
            if (!curr->anyPolicy)
                return 2;
            return 1;
        }
    }

    return 1;

}

static int tree_add_auth_node(STACK_OF(X509_POLICY_NODE) **pnodes,
                              X509_POLICY_NODE *pcy)
{
    if (!*pnodes) {
        *pnodes = policy_node_cmp_new();
        if (!*pnodes)
            return 0;
    } else if (sk_X509_POLICY_NODE_find(*pnodes, pcy) != -1)
        return 1;

    if (!sk_X509_POLICY_NODE_push(*pnodes, pcy))
        return 0;

    return 1;

}

/*
 * Calculate the authority set based on policy tree. The 'pnodes' parameter
 * is used as a store for the set of policy nodes used to calculate the user
 * set. If the authority set is not anyPolicy then pnodes will just point to
 * the authority set. If however the authority set is anyPolicy then the set
 * of valid policies (other than anyPolicy) is store in pnodes. The return
 * value of '2' is used in this case to indicate that pnodes should be freed.
 */

static int tree_calculate_authority_set(X509_POLICY_TREE *tree,
                                        STACK_OF(X509_POLICY_NODE) **pnodes)
{
    X509_POLICY_LEVEL *curr;
    X509_POLICY_NODE *node, *anyptr;
    STACK_OF(X509_POLICY_NODE) **addnodes;
    int i, j;
    curr = tree->levels + tree->nlevel - 1;

    /* If last level contains anyPolicy set is anyPolicy */
    if (curr->anyPolicy) {
        if (!tree_add_auth_node(&tree->auth_policies, curr->anyPolicy))
            return 0;
        addnodes = pnodes;
    } else
        /* Add policies to authority set */
        addnodes = &tree->auth_policies;

    curr = tree->levels;
    for (i = 1; i < tree->nlevel; i++) {
        /*
         * If no anyPolicy node on this this level it can't appear on lower
         * levels so end search.
         */
        if (!(anyptr = curr->anyPolicy))
            break;
        curr++;
        for (j = 0; j < sk_X509_POLICY_NODE_num(curr->nodes); j++) {
            node = sk_X509_POLICY_NODE_value(curr->nodes, j);
            if ((node->parent == anyptr)
                && !tree_add_auth_node(addnodes, node))
                return 0;
        }
    }

    if (addnodes == pnodes)
        return 2;

    *pnodes = tree->auth_policies;

    return 1;
}

static int tree_calculate_user_set(X509_POLICY_TREE *tree,
                                   STACK_OF(ASN1_OBJECT) *policy_oids,
                                   STACK_OF(X509_POLICY_NODE) *auth_nodes)
{
    int i;
    X509_POLICY_NODE *node;
    ASN1_OBJECT *oid;

    X509_POLICY_NODE *anyPolicy;
    X509_POLICY_DATA *extra;

    /*
     * Check if anyPolicy present in authority constrained policy set: this
     * will happen if it is a leaf node.
     */

    if (sk_ASN1_OBJECT_num(policy_oids) <= 0)
        return 1;

    anyPolicy = tree->levels[tree->nlevel - 1].anyPolicy;

    for (i = 0; i < sk_ASN1_OBJECT_num(policy_oids); i++) {
        oid = sk_ASN1_OBJECT_value(policy_oids, i);
        if (OBJ_obj2nid(oid) == NID_any_policy) {
            tree->flags |= POLICY_FLAG_ANY_POLICY;
            return 1;
        }
    }

    for (i = 0; i < sk_ASN1_OBJECT_num(policy_oids); i++) {
        oid = sk_ASN1_OBJECT_value(policy_oids, i);
        node = tree_find_sk(auth_nodes, oid);
        if (!node) {
            if (!anyPolicy)
                continue;
            /*
             * Create a new node with policy ID from user set and qualifiers
             * from anyPolicy.
             */
            extra = policy_data_new(NULL, oid, node_critical(anyPolicy));
            if (!extra)
                return 0;
            extra->qualifier_set = anyPolicy->data->qualifier_set;
            extra->flags = POLICY_DATA_FLAG_SHARED_QUALIFIERS
                | POLICY_DATA_FLAG_EXTRA_NODE;
            node = level_add_node(NULL, extra, anyPolicy->parent, tree);
        }
        if (!tree->user_policies) {
            tree->user_policies = sk_X509_POLICY_NODE_new_null();
            if (!tree->user_policies)
                return 1;
        }
        if (!sk_X509_POLICY_NODE_push(tree->user_policies, node))
            return 0;
    }
    return 1;

}

static int tree_evaluate(X509_POLICY_TREE *tree)
{
    int ret, i;
    X509_POLICY_LEVEL *curr = tree->levels + 1;
    const X509_POLICY_CACHE *cache;

    for (i = 1; i < tree->nlevel; i++, curr++) {
        cache = policy_cache_set(curr->cert);
        if (!tree_link_nodes(curr, cache))
            return 0;

        if (!(curr->flags & X509_V_FLAG_INHIBIT_ANY)
            && !tree_link_any(curr, cache, tree))
            return 0;
        tree_print("before tree_prune()", tree, curr);
        ret = tree_prune(tree, curr);
        if (ret != 1)
            return ret;
    }

    return 1;

}

static void exnode_free(X509_POLICY_NODE *node)
{
    if (node->data && (node->data->flags & POLICY_DATA_FLAG_EXTRA_NODE))
        OPENSSL_free(node);
}

void X509_policy_tree_free(X509_POLICY_TREE *tree)
{
    X509_POLICY_LEVEL *curr;
    int i;

    if (!tree)
        return;

    sk_X509_POLICY_NODE_free(tree->auth_policies);
    sk_X509_POLICY_NODE_pop_free(tree->user_policies, exnode_free);

    for (i = 0, curr = tree->levels; i < tree->nlevel; i++, curr++) {
        if (curr->cert)
            X509_free(curr->cert);
        if (curr->nodes)
            sk_X509_POLICY_NODE_pop_free(curr->nodes, policy_node_free);
        if (curr->anyPolicy)
            policy_node_free(curr->anyPolicy);
    }

    if (tree->extra_data)
        sk_X509_POLICY_DATA_pop_free(tree->extra_data, policy_data_free);

    OPENSSL_free(tree->levels);
    OPENSSL_free(tree);

}

/*-
 * Application policy checking function.
 * Return codes:
 *  0   Internal Error.
 *  1   Successful.
 * -1   One or more certificates contain invalid or inconsistent extensions
 * -2   User constrained policy set empty and requireExplicit true.
 */

int X509_policy_check(X509_POLICY_TREE **ptree, int *pexplicit_policy,
                      STACK_OF(X509) *certs,
                      STACK_OF(ASN1_OBJECT) *policy_oids, unsigned int flags)
{
    int ret;
    int calc_ret;
    X509_POLICY_TREE *tree = NULL;
    STACK_OF(X509_POLICY_NODE) *nodes, *auth_nodes = NULL;
    *ptree = NULL;

    *pexplicit_policy = 0;
    ret = tree_init(&tree, certs, flags);

    switch (ret) {

        /* Tree empty requireExplicit False: OK */
    case 2:
        return 1;

        /* Some internal error */
    case -1:
        return -1;

        /* Some internal error */
    case 0:
        return 0;

        /* Tree empty requireExplicit True: Error */

    case 6:
        *pexplicit_policy = 1;
        return -2;

        /* Tree OK requireExplicit True: OK and continue */
    case 5:
        *pexplicit_policy = 1;
        break;

        /* Tree OK: continue */

    case 1:
        if (!tree)
            /*
             * tree_init() returns success and a null tree
             * if it's just looking at a trust anchor.
             * I'm not sure that returning success here is
             * correct, but I'm sure that reporting this
             * as an internal error which our caller
             * interprets as a malloc failure is wrong.
             */
            return 1;
        break;
    }

    if (!tree)
        goto error;
    ret = tree_evaluate(tree);

    tree_print("tree_evaluate()", tree, NULL);

    if (ret <= 0)
        goto error;

    /* Return value 2 means tree empty */
    if (ret == 2) {
        X509_policy_tree_free(tree);
        if (*pexplicit_policy)
            return -2;
        else
            return 1;
    }

    /* Tree is not empty: continue */

    calc_ret = tree_calculate_authority_set(tree, &auth_nodes);

    if (!calc_ret)
        goto error;

    ret = tree_calculate_user_set(tree, policy_oids, auth_nodes);

    if (calc_ret == 2)
        sk_X509_POLICY_NODE_free(auth_nodes);

    if (!ret)
        goto error;


    if (tree)
        *ptree = tree;

    if (*pexplicit_policy) {
        nodes = X509_policy_tree_get0_user_policies(tree);
        if (sk_X509_POLICY_NODE_num(nodes) <= 0)
            return -2;
    }

    return 1;

 error:

    X509_policy_tree_free(tree);

    return 0;

}
