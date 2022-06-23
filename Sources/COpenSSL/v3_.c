/*
 * Contributed to the OpenSSL Project by the American Registry for
 * Internet Numbers ("ARIN").
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
 */

/*
 * Implementation of RFC 3779 section 2.2.
 */

#include <stdio.h>
#include <stdlib.h>

#include "cryptlib.h"
#include "conf.h"
#include "asn1.h"
#include "asn1t.h"
#include "buffer.h"
#include "x509v3.h"

#ifndef OPENSSL_NO_RFC3779

/*
 * OpenSSL ASN.1 template translation of RFC 3779 2.2.3.
 */

ASN1_SEQUENCE(IPAddressRange) = {
  ASN1_SIMPLE(IPAddressRange, min, ASN1_BIT_STRING),
  ASN1_SIMPLE(IPAddressRange, max, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(IPAddressRange)

ASN1_CHOICE(IPAddressOrRange) = {
  ASN1_SIMPLE(IPAddressOrRange, u.addressPrefix, ASN1_BIT_STRING),
  ASN1_SIMPLE(IPAddressOrRange, u.addressRange,  IPAddressRange)
} ASN1_CHOICE_END(IPAddressOrRange)

ASN1_CHOICE(IPAddressChoice) = {
  ASN1_SIMPLE(IPAddressChoice,      u.inherit,           ASN1_NULL),
  ASN1_SEQUENCE_OF(IPAddressChoice, u.addressesOrRanges, IPAddressOrRange)
} ASN1_CHOICE_END(IPAddressChoice)

ASN1_SEQUENCE(IPAddressFamily) = {
  ASN1_SIMPLE(IPAddressFamily, addressFamily,   ASN1_OCTET_STRING),
  ASN1_SIMPLE(IPAddressFamily, ipAddressChoice, IPAddressChoice)
} ASN1_SEQUENCE_END(IPAddressFamily)

ASN1_ITEM_TEMPLATE(IPAddrBlocks) =
  ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0,
                        IPAddrBlocks, IPAddressFamily)
ASN1_ITEM_TEMPLATE_END(IPAddrBlocks)

IMPLEMENT_ASN1_FUNCTIONS(IPAddressRange)
IMPLEMENT_ASN1_FUNCTIONS(IPAddressOrRange)
IMPLEMENT_ASN1_FUNCTIONS(IPAddressChoice)
IMPLEMENT_ASN1_FUNCTIONS(IPAddressFamily)

/*
 * How much buffer space do we need for a raw address?
 */
# define ADDR_RAW_BUF_LEN        16

/*
 * What's the address length associated with this AFI?
 */
static int length_from_afi(const unsigned afi)
{
    switch (afi) {
    case IANA_AFI_IPV4:
        return 4;
    case IANA_AFI_IPV6:
        return 16;
    default:
        return 0;
    }
}

/*
 * Extract the AFI from an IPAddressFamily.
 */
unsigned int v3_addr_get_afi(const IPAddressFamily *f)
{
    if (f == NULL
            || f->addressFamily == NULL
            || f->addressFamily->data == NULL
            || f->addressFamily->length < 2)
        return 0;
    return (f->addressFamily->data[0] << 8) | f->addressFamily->data[1];
}

/*
 * Expand the bitstring form of an address into a raw byte array.
 * At the moment this is coded for simplicity, not speed.
 */
static int addr_expand(unsigned char *addr,
                       const ASN1_BIT_STRING *bs,
                       const int length, const unsigned char fill)
{
    if (bs->length < 0 || bs->length > length)
        return 0;
    if (bs->length > 0) {
        memcpy(addr, bs->data, bs->length);
        if ((bs->flags & 7) != 0) {
            unsigned char mask = 0xFF >> (8 - (bs->flags & 7));
            if (fill == 0)
                addr[bs->length - 1] &= ~mask;
            else
                addr[bs->length - 1] |= mask;
        }
    }
    memset(addr + bs->length, fill, length - bs->length);
    return 1;
}

/*
 * Extract the prefix length from a bitstring.
 */
# define addr_prefixlen(bs) ((int) ((bs)->length * 8 - ((bs)->flags & 7)))

/*
 * i2r handler for one address bitstring.
 */
static int i2r_address(BIO *out,
                       const unsigned afi,
                       const unsigned char fill, const ASN1_BIT_STRING *bs)
{
    unsigned char addr[ADDR_RAW_BUF_LEN];
    int i, n;

    if (bs->length < 0)
        return 0;
    switch (afi) {
    case IANA_AFI_IPV4:
        if (!addr_expand(addr, bs, 4, fill))
            return 0;
        BIO_printf(out, "%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3]);
        break;
    case IANA_AFI_IPV6:
        if (!addr_expand(addr, bs, 16, fill))
            return 0;
        for (n = 16; n > 1 && addr[n - 1] == 0x00 && addr[n - 2] == 0x00;
             n -= 2) ;
        for (i = 0; i < n; i += 2)
            BIO_printf(out, "%x%s", (addr[i] << 8) | addr[i + 1],
                       (i < 14 ? ":" : ""));
        if (i < 16)
            BIO_puts(out, ":");
        if (i == 0)
            BIO_puts(out, ":");
        break;
    default:
        for (i = 0; i < bs->length; i++)
            BIO_printf(out, "%s%02x", (i > 0 ? ":" : ""), bs->data[i]);
        BIO_printf(out, "[%d]", (int)(bs->flags & 7));
        break;
    }
    return 1;
}

/*
 * i2r handler for a sequence of addresses and ranges.
 */
static int i2r_IPAddressOrRanges(BIO *out,
                                 const int indent,
                                 const IPAddressOrRanges *aors,
                                 const unsigned afi)
{
    int i;
    for (i = 0; i < sk_IPAddressOrRange_num(aors); i++) {
        const IPAddressOrRange *aor = sk_IPAddressOrRange_value(aors, i);
        BIO_printf(out, "%*s", indent, "");
        switch (aor->type) {
        case IPAddressOrRange_addressPrefix:
            if (!i2r_address(out, afi, 0x00, aor->u.addressPrefix))
                return 0;
            BIO_printf(out, "/%d\n", addr_prefixlen(aor->u.addressPrefix));
            continue;
        case IPAddressOrRange_addressRange:
            if (!i2r_address(out, afi, 0x00, aor->u.addressRange->min))
                return 0;
            BIO_puts(out, "-");
            if (!i2r_address(out, afi, 0xFF, aor->u.addressRange->max))
                return 0;
            BIO_puts(out, "\n");
            continue;
        }
    }
    return 1;
}

/*
 * i2r handler for an IPAddrBlocks extension.
 */
static int i2r_IPAddrBlocks(const X509V3_EXT_METHOD *method,
                            void *ext, BIO *out, int indent)
{
    const IPAddrBlocks *addr = ext;
    int i;
    for (i = 0; i < sk_IPAddressFamily_num(addr); i++) {
        IPAddressFamily *f = sk_IPAddressFamily_value(addr, i);
        const unsigned int afi = v3_addr_get_afi(f);
        switch (afi) {
        case IANA_AFI_IPV4:
            BIO_printf(out, "%*sIPv4", indent, "");
            break;
        case IANA_AFI_IPV6:
            BIO_printf(out, "%*sIPv6", indent, "");
            break;
        default:
            BIO_printf(out, "%*sUnknown AFI %u", indent, "", afi);
            break;
        }
        if (f->addressFamily->length > 2) {
            switch (f->addressFamily->data[2]) {
            case 1:
                BIO_puts(out, " (Unicast)");
                break;
            case 2:
                BIO_puts(out, " (Multicast)");
                break;
            case 3:
                BIO_puts(out, " (Unicast/Multicast)");
                break;
            case 4:
                BIO_puts(out, " (MPLS)");
                break;
            case 64:
                BIO_puts(out, " (Tunnel)");
                break;
            case 65:
                BIO_puts(out, " (VPLS)");
                break;
            case 66:
                BIO_puts(out, " (BGP MDT)");
                break;
            case 128:
                BIO_puts(out, " (MPLS-labeled VPN)");
                break;
            default:
                BIO_printf(out, " (Unknown SAFI %u)",
                           (unsigned)f->addressFamily->data[2]);
                break;
            }
        }
        switch (f->ipAddressChoice->type) {
        case IPAddressChoice_inherit:
            BIO_puts(out, ": inherit\n");
            break;
        case IPAddressChoice_addressesOrRanges:
            BIO_puts(out, ":\n");
            if (!i2r_IPAddressOrRanges(out,
                                       indent + 2,
                                       f->ipAddressChoice->
                                       u.addressesOrRanges, afi))
                return 0;
            break;
        }
    }
    return 1;
}

/*
 * Sort comparison function for a sequence of IPAddressOrRange
 * elements.
 *
 * There's no sane answer we can give if addr_expand() fails, and an
 * assertion failure on externally supplied data is seriously uncool,
 * so we just arbitrarily declare that if given invalid inputs this
 * function returns -1.  If this messes up your preferred sort order
 * for garbage input, tough noogies.
 */
static int IPAddressOrRange_cmp(const IPAddressOrRange *a,
                                const IPAddressOrRange *b, const int length)
{
    unsigned char addr_a[ADDR_RAW_BUF_LEN], addr_b[ADDR_RAW_BUF_LEN];
    int prefixlen_a = 0, prefixlen_b = 0;
    int r;

    switch (a->type) {
    case IPAddressOrRange_addressPrefix:
        if (!addr_expand(addr_a, a->u.addressPrefix, length, 0x00))
            return -1;
        prefixlen_a = addr_prefixlen(a->u.addressPrefix);
        break;
    case IPAddressOrRange_addressRange:
        if (!addr_expand(addr_a, a->u.addressRange->min, length, 0x00))
            return -1;
        prefixlen_a = length * 8;
        break;
    }

    switch (b->type) {
    case IPAddressOrRange_addressPrefix:
        if (!addr_expand(addr_b, b->u.addressPrefix, length, 0x00))
            return -1;
        prefixlen_b = addr_prefixlen(b->u.addressPrefix);
        break;
    case IPAddressOrRange_addressRange:
        if (!addr_expand(addr_b, b->u.addressRange->min, length, 0x00))
            return -1;
        prefixlen_b = length * 8;
        break;
    }

    if ((r = memcmp(addr_a, addr_b, length)) != 0)
        return r;
    else
        return prefixlen_a - prefixlen_b;
}

/*
 * IPv4-specific closure over IPAddressOrRange_cmp, since sk_sort()
 * comparision routines are only allowed two arguments.
 */
static int v4IPAddressOrRange_cmp(const IPAddressOrRange *const *a,
                                  const IPAddressOrRange *const *b)
{
    return IPAddressOrRange_cmp(*a, *b, 4);
}

/*
 * IPv6-specific closure over IPAddressOrRange_cmp, since sk_sort()
 * comparision routines are only allowed two arguments.
 */
static int v6IPAddressOrRange_cmp(const IPAddressOrRange *const *a,
                                  const IPAddressOrRange *const *b)
{
    return IPAddressOrRange_cmp(*a, *b, 16);
}

/*
 * Calculate whether a range collapses to a prefix.
 * See last paragraph of RFC 3779 2.2.3.7.
 */
static int range_should_be_prefix(const unsigned char *min,
                                  const unsigned char *max, const int length)
{
    unsigned char mask;
    int i, j;

    OPENSSL_assert(memcmp(min, max, length) <= 0);
    for (i = 0; i < length && min[i] == max[i]; i++) ;
    for (j = length - 1; j >= 0 && min[j] == 0x00 && max[j] == 0xFF; j--) ;
    if (i < j)
        return -1;
    if (i > j)
        return i * 8;
    mask = min[i] ^ max[i];
    switch (mask) {
    case 0x01:
        j = 7;
        break;
    case 0x03:
        j = 6;
        break;
    case 0x07:
        j = 5;
        break;
    case 0x0F:
        j = 4;
        break;
    case 0x1F:
        j = 3;
        break;
    case 0x3F:
        j = 2;
        break;
    case 0x7F:
        j = 1;
        break;
    default:
        return -1;
    }
    if ((min[i] & mask) != 0 || (max[i] & mask) != mask)
        return -1;
    else
        return i * 8 + j;
}

/*
 * Construct a prefix.
 */
static int make_addressPrefix(IPAddressOrRange **result,
                              unsigned char *addr, const int prefixlen)
{
    int bytelen = (prefixlen + 7) / 8, bitlen = prefixlen % 8;
    IPAddressOrRange *aor = IPAddressOrRange_new();

    if (aor == NULL)
        return 0;
    aor->type = IPAddressOrRange_addressPrefix;
    if (aor->u.addressPrefix == NULL &&
        (aor->u.addressPrefix = ASN1_BIT_STRING_new()) == NULL)
        goto err;
    if (!ASN1_BIT_STRING_set(aor->u.addressPrefix, addr, bytelen))
        goto err;
    aor->u.addressPrefix->flags &= ~7;
    aor->u.addressPrefix->flags |= ASN1_STRING_FLAG_BITS_LEFT;
    if (bitlen > 0) {
        aor->u.addressPrefix->data[bytelen - 1] &= ~(0xFF >> bitlen);
        aor->u.addressPrefix->flags |= 8 - bitlen;
    }

    *result = aor;
    return 1;

 err:
    IPAddressOrRange_free(aor);
    return 0;
}

/*
 * Construct a range.  If it can be expressed as a prefix,
 * return a prefix instead.  Doing this here simplifies
 * the rest of the code considerably.
 */
static int make_addressRange(IPAddressOrRange **result,
                             unsigned char *min,
                             unsigned char *max, const int length)
{
    IPAddressOrRange *aor;
    int i, prefixlen;

    if ((prefixlen = range_should_be_prefix(min, max, length)) >= 0)
        return make_addressPrefix(result, min, prefixlen);

    if ((aor = IPAddressOrRange_new()) == NULL)
        return 0;
    aor->type = IPAddressOrRange_addressRange;
    OPENSSL_assert(aor->u.addressRange == NULL);
    if ((aor->u.addressRange = IPAddressRange_new()) == NULL)
        goto err;
    if (aor->u.addressRange->min == NULL &&
        (aor->u.addressRange->min = ASN1_BIT_STRING_new()) == NULL)
        goto err;
    if (aor->u.addressRange->max == NULL &&
        (aor->u.addressRange->max = ASN1_BIT_STRING_new()) == NULL)
        goto err;

    for (i = length; i > 0 && min[i - 1] == 0x00; --i) ;
    if (!ASN1_BIT_STRING_set(aor->u.addressRange->min, min, i))
        goto err;
    aor->u.addressRange->min->flags &= ~7;
    aor->u.addressRange->min->flags |= ASN1_STRING_FLAG_BITS_LEFT;
    if (i > 0) {
        unsigned char b = min[i - 1];
        int j = 1;
        while ((b & (0xFFU >> j)) != 0)
            ++j;
        aor->u.addressRange->min->flags |= 8 - j;
    }

    for (i = length; i > 0 && max[i - 1] == 0xFF; --i) ;
    if (!ASN1_BIT_STRING_set(aor->u.addressRange->max, max, i))
        goto err;
    aor->u.addressRange->max->flags &= ~7;
    aor->u.addressRange->max->flags |= ASN1_STRING_FLAG_BITS_LEFT;
    if (i > 0) {
        unsigned char b = max[i - 1];
        int j = 1;
        while ((b & (0xFFU >> j)) != (0xFFU >> j))
            ++j;
        aor->u.addressRange->max->flags |= 8 - j;
    }

    *result = aor;
    return 1;

 err:
    IPAddressOrRange_free(aor);
    return 0;
}

/*
 * Construct a new address family or find an existing one.
 */
static IPAddressFamily *make_IPAddressFamily(IPAddrBlocks *addr,
                                             const unsigned afi,
                                             const unsigned *safi)
{
    IPAddressFamily *f;
    unsigned char key[3];
    unsigned keylen;
    int i;

    key[0] = (afi >> 8) & 0xFF;
    key[1] = afi & 0xFF;
    if (safi != NULL) {
        key[2] = *safi & 0xFF;
        keylen = 3;
    } else {
        keylen = 2;
    }

    for (i = 0; i < sk_IPAddressFamily_num(addr); i++) {
        f = sk_IPAddressFamily_value(addr, i);
        OPENSSL_assert(f->addressFamily->data != NULL);
        if (f->addressFamily->length == keylen &&
            !memcmp(f->addressFamily->data, key, keylen))
            return f;
    }

    if ((f = IPAddressFamily_new()) == NULL)
        goto err;
    if (f->ipAddressChoice == NULL &&
        (f->ipAddressChoice = IPAddressChoice_new()) == NULL)
        goto err;
    if (f->addressFamily == NULL &&
        (f->addressFamily = ASN1_OCTET_STRING_new()) == NULL)
        goto err;
    if (!ASN1_OCTET_STRING_set(f->addressFamily, key, keylen))
        goto err;
    if (!sk_IPAddressFamily_push(addr, f))
        goto err;

    return f;

 err:
    IPAddressFamily_free(f);
    return NULL;
}

/*
 * Add an inheritance element.
 */
int v3_addr_add_inherit(IPAddrBlocks *addr,
                        const unsigned afi, const unsigned *safi)
{
    IPAddressFamily *f = make_IPAddressFamily(addr, afi, safi);
    if (f == NULL ||
        f->ipAddressChoice == NULL ||
        (f->ipAddressChoice->type == IPAddressChoice_addressesOrRanges &&
         f->ipAddressChoice->u.addressesOrRanges != NULL))
        return 0;
    if (f->ipAddressChoice->type == IPAddressChoice_inherit &&
        f->ipAddressChoice->u.inherit != NULL)
        return 1;
    if (f->ipAddressChoice->u.inherit == NULL &&
        (f->ipAddressChoice->u.inherit = ASN1_NULL_new()) == NULL)
        return 0;
    f->ipAddressChoice->type = IPAddressChoice_inherit;
    return 1;
}

/*
 * Construct an IPAddressOrRange sequence, or return an existing one.
 */
static IPAddressOrRanges *make_prefix_or_range(IPAddrBlocks *addr,
                                               const unsigned afi,
                                               const unsigned *safi)
{
    IPAddressFamily *f = make_IPAddressFamily(addr, afi, safi);
    IPAddressOrRanges *aors = NULL;

    if (f == NULL ||
        f->ipAddressChoice == NULL ||
        (f->ipAddressChoice->type == IPAddressChoice_inherit &&
         f->ipAddressChoice->u.inherit != NULL))
        return NULL;
    if (f->ipAddressChoice->type == IPAddressChoice_addressesOrRanges)
        aors = f->ipAddressChoice->u.addressesOrRanges;
    if (aors != NULL)
        return aors;
    if ((aors = sk_IPAddressOrRange_new_null()) == NULL)
        return NULL;
    switch (afi) {
    case IANA_AFI_IPV4:
        (void)sk_IPAddressOrRange_set_cmp_func(aors, v4IPAddressOrRange_cmp);
        break;
    case IANA_AFI_IPV6:
        (void)sk_IPAddressOrRange_set_cmp_func(aors, v6IPAddressOrRange_cmp);
        break;
    }
    f->ipAddressChoice->type = IPAddressChoice_addressesOrRanges;
    f->ipAddressChoice->u.addressesOrRanges = aors;
    return aors;
}

/*
 * Add a prefix.
 */
int v3_addr_add_prefix(IPAddrBlocks *addr,
                       const unsigned afi,
                       const unsigned *safi,
                       unsigned char *a, const int prefixlen)
{
    IPAddressOrRanges *aors = make_prefix_or_range(addr, afi, safi);
    IPAddressOrRange *aor;
    if (aors == NULL || !make_addressPrefix(&aor, a, prefixlen))
        return 0;
    if (sk_IPAddressOrRange_push(aors, aor))
        return 1;
    IPAddressOrRange_free(aor);
    return 0;
}

/*
 * Add a range.
 */
int v3_addr_add_range(IPAddrBlocks *addr,
                      const unsigned afi,
                      const unsigned *safi,
                      unsigned char *min, unsigned char *max)
{
    IPAddressOrRanges *aors = make_prefix_or_range(addr, afi, safi);
    IPAddressOrRange *aor;
    int length = length_from_afi(afi);
    if (aors == NULL)
        return 0;
    if (!make_addressRange(&aor, min, max, length))
        return 0;
    if (sk_IPAddressOrRange_push(aors, aor))
        return 1;
    IPAddressOrRange_free(aor);
    return 0;
}

/*
 * Extract min and max values from an IPAddressOrRange.
 */
static int extract_min_max(IPAddressOrRange *aor,
                           unsigned char *min, unsigned char *max, int length)
{
    if (aor == NULL || min == NULL || max == NULL)
        return 0;
    switch (aor->type) {
    case IPAddressOrRange_addressPrefix:
        return (addr_expand(min, aor->u.addressPrefix, length, 0x00) &&
                addr_expand(max, aor->u.addressPrefix, length, 0xFF));
    case IPAddressOrRange_addressRange:
        return (addr_expand(min, aor->u.addressRange->min, length, 0x00) &&
                addr_expand(max, aor->u.addressRange->max, length, 0xFF));
    }
    return 0;
}

/*
 * Public wrapper for extract_min_max().
 */
int v3_addr_get_range(IPAddressOrRange *aor,
                      const unsigned afi,
                      unsigned char *min,
                      unsigned char *max, const int length)
{
    int afi_length = length_from_afi(afi);
    if (aor == NULL || min == NULL || max == NULL ||
        afi_length == 0 || length < afi_length ||
        (aor->type != IPAddressOrRange_addressPrefix &&
         aor->type != IPAddressOrRange_addressRange) ||
        !extract_min_max(aor, min, max, afi_length))
        return 0;

    return afi_length;
}

/*
 * Sort comparision function for a sequence of IPAddressFamily.
 *
 * The last paragraph of RFC 3779 2.2.3.3 is slightly ambiguous about
 * the ordering: I can read it as meaning that IPv6 without a SAFI
 * comes before IPv4 with a SAFI, which seems pretty weird.  The
 * examples in appendix B suggest that the author intended the
 * null-SAFI rule to apply only within a single AFI, which is what I
 * would have expected and is what the following code implements.
 */
static int IPAddressFamily_cmp(const IPAddressFamily *const *a_,
                               const IPAddressFamily *const *b_)
{
    const ASN1_OCTET_STRING *a = (*a_)->addressFamily;
    const ASN1_OCTET_STRING *b = (*b_)->addressFamily;
    int len = ((a->length <= b->length) ? a->length : b->length);
    int cmp = memcmp(a->data, b->data, len);
    return cmp ? cmp : a->length - b->length;
}

/*
 * Check whether an IPAddrBLocks is in canonical form.
 */
int v3_addr_is_canonical(IPAddrBlocks *addr)
{
    unsigned char a_min[ADDR_RAW_BUF_LEN], a_max[ADDR_RAW_BUF_LEN];
    unsigned char b_min[ADDR_RAW_BUF_LEN], b_max[ADDR_RAW_BUF_LEN];
    IPAddressOrRanges *aors;
    int i, j, k;

    /*
     * Empty extension is cannonical.
     */
    if (addr == NULL)
        return 1;

    /*
     * Check whether the top-level list is in order.
     */
    for (i = 0; i < sk_IPAddressFamily_num(addr) - 1; i++) {
        const IPAddressFamily *a = sk_IPAddressFamily_value(addr, i);
        const IPAddressFamily *b = sk_IPAddressFamily_value(addr, i + 1);
        if (IPAddressFamily_cmp(&a, &b) >= 0)
            return 0;
    }

    /*
     * Top level's ok, now check each address family.
     */
    for (i = 0; i < sk_IPAddressFamily_num(addr); i++) {
        IPAddressFamily *f = sk_IPAddressFamily_value(addr, i);
        int length = length_from_afi(v3_addr_get_afi(f));

        /*
         * Inheritance is canonical.  Anything other than inheritance or
         * a SEQUENCE OF IPAddressOrRange is an ASN.1 error or something.
         */
        if (f == NULL || f->ipAddressChoice == NULL)
            return 0;
        switch (f->ipAddressChoice->type) {
        case IPAddressChoice_inherit:
            continue;
        case IPAddressChoice_addressesOrRanges:
            break;
        default:
            return 0;
        }

        /*
         * It's an IPAddressOrRanges sequence, check it.
         */
        aors = f->ipAddressChoice->u.addressesOrRanges;
        if (sk_IPAddressOrRange_num(aors) == 0)
            return 0;
        for (j = 0; j < sk_IPAddressOrRange_num(aors) - 1; j++) {
            IPAddressOrRange *a = sk_IPAddressOrRange_value(aors, j);
            IPAddressOrRange *b = sk_IPAddressOrRange_value(aors, j + 1);

            if (!extract_min_max(a, a_min, a_max, length) ||
                !extract_min_max(b, b_min, b_max, length))
                return 0;

            /*
             * Punt misordered list, overlapping start, or inverted range.
             */
            if (memcmp(a_min, b_min, length) >= 0 ||
                memcmp(a_min, a_max, length) > 0 ||
                memcmp(b_min, b_max, length) > 0)
                return 0;

            /*
             * Punt if adjacent or overlapping.  Check for adjacency by
             * subtracting one from b_min first.
             */
            for (k = length - 1; k >= 0 && b_min[k]-- == 0x00; k--) ;
            if (memcmp(a_max, b_min, length) >= 0)
                return 0;

            /*
             * Check for range that should be expressed as a prefix.
             */
            if (a->type == IPAddressOrRange_addressRange &&
                range_should_be_prefix(a_min, a_max, length) >= 0)
                return 0;
        }

        /*
         * Check range to see if it's inverted or should be a
         * prefix.
         */
        j = sk_IPAddressOrRange_num(aors) - 1;
        {
            IPAddressOrRange *a = sk_IPAddressOrRange_value(aors, j);
            if (a != NULL && a->type == IPAddressOrRange_addressRange) {
                if (!extract_min_max(a, a_min, a_max, length))
                    return 0;
                if (memcmp(a_min, a_max, length) > 0 ||
                    range_should_be_prefix(a_min, a_max, length) >= 0)
                    return 0;
            }
        }
    }

    /*
     * If we made it through all that, we're happy.
     */
    return 1;
}

/*
 * Whack an IPAddressOrRanges into canonical form.
 */
static int IPAddressOrRanges_canonize(IPAddressOrRanges *aors,
                                      const unsigned afi)
{
    int i, j, length = length_from_afi(afi);

    /*
     * Sort the IPAddressOrRanges sequence.
     */
    sk_IPAddressOrRange_sort(aors);

    /*
     * Clean up representation issues, punt on duplicates or overlaps.
     */
    for (i = 0; i < sk_IPAddressOrRange_num(aors) - 1; i++) {
        IPAddressOrRange *a = sk_IPAddressOrRange_value(aors, i);
        IPAddressOrRange *b = sk_IPAddressOrRange_value(aors, i + 1);
        unsigned char a_min[ADDR_RAW_BUF_LEN], a_max[ADDR_RAW_BUF_LEN];
        unsigned char b_min[ADDR_RAW_BUF_LEN], b_max[ADDR_RAW_BUF_LEN];

        if (!extract_min_max(a, a_min, a_max, length) ||
            !extract_min_max(b, b_min, b_max, length))
            return 0;

        /*
         * Punt inverted ranges.
         */
        if (memcmp(a_min, a_max, length) > 0 ||
            memcmp(b_min, b_max, length) > 0)
            return 0;

        /*
         * Punt overlaps.
         */
        if (memcmp(a_max, b_min, length) >= 0)
            return 0;

        /*
         * Merge if a and b are adjacent.  We check for
         * adjacency by subtracting one from b_min first.
         */
        for (j = length - 1; j >= 0 && b_min[j]-- == 0x00; j--) ;
        if (memcmp(a_max, b_min, length) == 0) {
            IPAddressOrRange *merged;
            if (!make_addressRange(&merged, a_min, b_max, length))
                return 0;
            (void)sk_IPAddressOrRange_set(aors, i, merged);
            (void)sk_IPAddressOrRange_delete(aors, i + 1);
            IPAddressOrRange_free(a);
            IPAddressOrRange_free(b);
            --i;
            continue;
        }
    }

    /*
     * Check for inverted final range.
     */
    j = sk_IPAddressOrRange_num(aors) - 1;
    {
        IPAddressOrRange *a = sk_IPAddressOrRange_value(aors, j);
        if (a != NULL && a->type == IPAddressOrRange_addressRange) {
            unsigned char a_min[ADDR_RAW_BUF_LEN], a_max[ADDR_RAW_BUF_LEN];
            extract_min_max(a, a_min, a_max, length);
            if (memcmp(a_min, a_max, length) > 0)
                return 0;
        }
    }

    return 1;
}

/*
 * Whack an IPAddrBlocks extension into canonical form.
 */
int v3_addr_canonize(IPAddrBlocks *addr)
{
    int i;
    for (i = 0; i < sk_IPAddressFamily_num(addr); i++) {
        IPAddressFamily *f = sk_IPAddressFamily_value(addr, i);
        if (f->ipAddressChoice->type == IPAddressChoice_addressesOrRanges &&
            !IPAddressOrRanges_canonize(f->ipAddressChoice->
                                        u.addressesOrRanges,
                                        v3_addr_get_afi(f)))
            return 0;
    }
    (void)sk_IPAddressFamily_set_cmp_func(addr, IPAddressFamily_cmp);
    sk_IPAddressFamily_sort(addr);
    OPENSSL_assert(v3_addr_is_canonical(addr));
    return 1;
}

/*
 * v2i handler for the IPAddrBlocks extension.
 */
static void *v2i_IPAddrBlocks(const struct v3_ext_method *method,
                              struct v3_ext_ctx *ctx,
                              STACK_OF(CONF_VALUE) *values)
{
    static const char v4addr_chars[] = "0123456789.";
    static const char v6addr_chars[] = "0123456789.:abcdefABCDEF";
    IPAddrBlocks *addr = NULL;
    char *s = NULL, *t;
    int i;

    if ((addr = sk_IPAddressFamily_new(IPAddressFamily_cmp)) == NULL) {
        X509V3err(X509V3_F_V2I_IPADDRBLOCKS, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    for (i = 0; i < sk_CONF_VALUE_num(values); i++) {
        CONF_VALUE *val = sk_CONF_VALUE_value(values, i);
        unsigned char min[ADDR_RAW_BUF_LEN], max[ADDR_RAW_BUF_LEN];
        unsigned afi, *safi = NULL, safi_;
        const char *addr_chars;
        int prefixlen, i1, i2, delim, length;

        if (!name_cmp(val->name, "IPv4")) {
            afi = IANA_AFI_IPV4;
        } else if (!name_cmp(val->name, "IPv6")) {
            afi = IANA_AFI_IPV6;
        } else if (!name_cmp(val->name, "IPv4-SAFI")) {
            afi = IANA_AFI_IPV4;
            safi = &safi_;
        } else if (!name_cmp(val->name, "IPv6-SAFI")) {
            afi = IANA_AFI_IPV6;
            safi = &safi_;
        } else {
            X509V3err(X509V3_F_V2I_IPADDRBLOCKS,
                      X509V3_R_EXTENSION_NAME_ERROR);
            X509V3_conf_err(val);
            goto err;
        }

        switch (afi) {
        case IANA_AFI_IPV4:
            addr_chars = v4addr_chars;
            break;
        case IANA_AFI_IPV6:
            addr_chars = v6addr_chars;
            break;
        }

        length = length_from_afi(afi);

        /*
         * Handle SAFI, if any, and BUF_strdup() so we can null-terminate
         * the other input values.
         */
        if (safi != NULL) {
            *safi = strtoul(val->value, &t, 0);
            t += strspn(t, " \t");
            if (*safi > 0xFF || *t++ != ':') {
                X509V3err(X509V3_F_V2I_IPADDRBLOCKS, X509V3_R_INVALID_SAFI);
                X509V3_conf_err(val);
                goto err;
            }
            t += strspn(t, " \t");
            s = BUF_strdup(t);
        } else {
            s = BUF_strdup(val->value);
        }
        if (s == NULL) {
            X509V3err(X509V3_F_V2I_IPADDRBLOCKS, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        /*
         * Check for inheritance.  Not worth additional complexity to
         * optimize this (seldom-used) case.
         */
        if (!strcmp(s, "inherit")) {
            if (!v3_addr_add_inherit(addr, afi, safi)) {
                X509V3err(X509V3_F_V2I_IPADDRBLOCKS,
                          X509V3_R_INVALID_INHERITANCE);
                X509V3_conf_err(val);
                goto err;
            }
            OPENSSL_free(s);
            s = NULL;
            continue;
        }

        i1 = strspn(s, addr_chars);
        i2 = i1 + strspn(s + i1, " \t");
        delim = s[i2++];
        s[i1] = '\0';

        if (a2i_ipadd(min, s) != length) {
            X509V3err(X509V3_F_V2I_IPADDRBLOCKS, X509V3_R_INVALID_IPADDRESS);
            X509V3_conf_err(val);
            goto err;
        }

        switch (delim) {
        case '/':
            prefixlen = (int)strtoul(s + i2, &t, 10);
            if (t == s + i2 || *t != '\0') {
                X509V3err(X509V3_F_V2I_IPADDRBLOCKS,
                          X509V3_R_EXTENSION_VALUE_ERROR);
                X509V3_conf_err(val);
                goto err;
            }
            if (!v3_addr_add_prefix(addr, afi, safi, min, prefixlen)) {
                X509V3err(X509V3_F_V2I_IPADDRBLOCKS, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            break;
        case '-':
            i1 = i2 + strspn(s + i2, " \t");
            i2 = i1 + strspn(s + i1, addr_chars);
            if (i1 == i2 || s[i2] != '\0') {
                X509V3err(X509V3_F_V2I_IPADDRBLOCKS,
                          X509V3_R_EXTENSION_VALUE_ERROR);
                X509V3_conf_err(val);
                goto err;
            }
            if (a2i_ipadd(max, s + i1) != length) {
                X509V3err(X509V3_F_V2I_IPADDRBLOCKS,
                          X509V3_R_INVALID_IPADDRESS);
                X509V3_conf_err(val);
                goto err;
            }
            if (memcmp(min, max, length_from_afi(afi)) > 0) {
                X509V3err(X509V3_F_V2I_IPADDRBLOCKS,
                          X509V3_R_EXTENSION_VALUE_ERROR);
                X509V3_conf_err(val);
                goto err;
            }
            if (!v3_addr_add_range(addr, afi, safi, min, max)) {
                X509V3err(X509V3_F_V2I_IPADDRBLOCKS, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            break;
        case '\0':
            if (!v3_addr_add_prefix(addr, afi, safi, min, length * 8)) {
                X509V3err(X509V3_F_V2I_IPADDRBLOCKS, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            break;
        default:
            X509V3err(X509V3_F_V2I_IPADDRBLOCKS,
                      X509V3_R_EXTENSION_VALUE_ERROR);
            X509V3_conf_err(val);
            goto err;
        }

        OPENSSL_free(s);
        s = NULL;
    }

    /*
     * Canonize the result, then we're done.
     */
    if (!v3_addr_canonize(addr))
        goto err;
    return addr;

 err:
    OPENSSL_free(s);
    sk_IPAddressFamily_pop_free(addr, IPAddressFamily_free);
    return NULL;
}

/*
 * OpenSSL dispatch
 */
const X509V3_EXT_METHOD v3_addr = {
    NID_sbgp_ipAddrBlock,       /* nid */
    0,                          /* flags */
    ASN1_ITEM_ref(IPAddrBlocks), /* template */
    0, 0, 0, 0,                 /* old functions, ignored */
    0,                          /* i2s */
    0,                          /* s2i */
    0,                          /* i2v */
    v2i_IPAddrBlocks,           /* v2i */
    i2r_IPAddrBlocks,           /* i2r */
    0,                          /* r2i */
    NULL                        /* extension-specific data */
};

/*
 * Figure out whether extension sues inheritance.
 */
int v3_addr_inherits(IPAddrBlocks *addr)
{
    int i;
    if (addr == NULL)
        return 0;
    for (i = 0; i < sk_IPAddressFamily_num(addr); i++) {
        IPAddressFamily *f = sk_IPAddressFamily_value(addr, i);
        if (f->ipAddressChoice->type == IPAddressChoice_inherit)
            return 1;
    }
    return 0;
}

/*
 * Figure out whether parent contains child.
 */
static int addr_contains(IPAddressOrRanges *parent,
                         IPAddressOrRanges *child, int length)
{
    unsigned char p_min[ADDR_RAW_BUF_LEN], p_max[ADDR_RAW_BUF_LEN];
    unsigned char c_min[ADDR_RAW_BUF_LEN], c_max[ADDR_RAW_BUF_LEN];
    int p, c;

    if (child == NULL || parent == child)
        return 1;
    if (parent == NULL)
        return 0;

    p = 0;
    for (c = 0; c < sk_IPAddressOrRange_num(child); c++) {
        if (!extract_min_max(sk_IPAddressOrRange_value(child, c),
                             c_min, c_max, length))
            return -1;
        for (;; p++) {
            if (p >= sk_IPAddressOrRange_num(parent))
                return 0;
            if (!extract_min_max(sk_IPAddressOrRange_value(parent, p),
                                 p_min, p_max, length))
                return 0;
            if (memcmp(p_max, c_max, length) < 0)
                continue;
            if (memcmp(p_min, c_min, length) > 0)
                return 0;
            break;
        }
    }

    return 1;
}

/*
 * Test whether a is a subset of b.
 */
int v3_addr_subset(IPAddrBlocks *a, IPAddrBlocks *b)
{
    int i;
    if (a == NULL || a == b)
        return 1;
    if (b == NULL || v3_addr_inherits(a) || v3_addr_inherits(b))
        return 0;
    (void)sk_IPAddressFamily_set_cmp_func(b, IPAddressFamily_cmp);
    for (i = 0; i < sk_IPAddressFamily_num(a); i++) {
        IPAddressFamily *fa = sk_IPAddressFamily_value(a, i);
        int j = sk_IPAddressFamily_find(b, fa);
        IPAddressFamily *fb;
        fb = sk_IPAddressFamily_value(b, j);
        if (fb == NULL)
            return 0;
        if (!addr_contains(fb->ipAddressChoice->u.addressesOrRanges,
                           fa->ipAddressChoice->u.addressesOrRanges,
                           length_from_afi(v3_addr_get_afi(fb))))
            return 0;
    }
    return 1;
}

/*
 * Validation error handling via callback.
 */
# define validation_err(_err_)           \
  do {                                  \
    if (ctx != NULL) {                  \
      ctx->error = _err_;               \
      ctx->error_depth = i;             \
      ctx->current_cert = x;            \
      ret = ctx->verify_cb(0, ctx);     \
    } else {                            \
      ret = 0;                          \
    }                                   \
    if (!ret)                           \
      goto done;                        \
  } while (0)

/*
 * Core code for RFC 3779 2.3 path validation.
 *
 * Returns 1 for success, 0 on error.
 *
 * When returning 0, ctx->error MUST be set to an appropriate value other than
 * X509_V_OK.
 */
static int v3_addr_validate_path_internal(X509_STORE_CTX *ctx,
                                          STACK_OF(X509) *chain,
                                          IPAddrBlocks *ext)
{
    IPAddrBlocks *child = NULL;
    int i, j, ret = 1;
    X509 *x;

    OPENSSL_assert(chain != NULL && sk_X509_num(chain) > 0);
    OPENSSL_assert(ctx != NULL || ext != NULL);
    OPENSSL_assert(ctx == NULL || ctx->verify_cb != NULL);

    /*
     * Figure out where to start.  If we don't have an extension to
     * check, we're done.  Otherwise, check canonical form and
     * set up for walking up the chain.
     */
    if (ext != NULL) {
        i = -1;
        x = NULL;
    } else {
        i = 0;
        x = sk_X509_value(chain, i);
        OPENSSL_assert(x != NULL);
        if ((ext = x->rfc3779_addr) == NULL)
            goto done;
    }
    if (!v3_addr_is_canonical(ext))
        validation_err(X509_V_ERR_INVALID_EXTENSION);
    (void)sk_IPAddressFamily_set_cmp_func(ext, IPAddressFamily_cmp);
    if ((child = sk_IPAddressFamily_dup(ext)) == NULL) {
        X509V3err(X509V3_F_V3_ADDR_VALIDATE_PATH_INTERNAL,
                  ERR_R_MALLOC_FAILURE);
        ctx->error = X509_V_ERR_OUT_OF_MEM;
        ret = 0;
        goto done;
    }

    /*
     * Now walk up the chain.  No cert may list resources that its
     * parent doesn't list.
     */
    for (i++; i < sk_X509_num(chain); i++) {
        x = sk_X509_value(chain, i);
        OPENSSL_assert(x != NULL);
        if (!v3_addr_is_canonical(x->rfc3779_addr))
            validation_err(X509_V_ERR_INVALID_EXTENSION);
        if (x->rfc3779_addr == NULL) {
            for (j = 0; j < sk_IPAddressFamily_num(child); j++) {
                IPAddressFamily *fc = sk_IPAddressFamily_value(child, j);
                if (fc->ipAddressChoice->type != IPAddressChoice_inherit) {
                    validation_err(X509_V_ERR_UNNESTED_RESOURCE);
                    break;
                }
            }
            continue;
        }
        (void)sk_IPAddressFamily_set_cmp_func(x->rfc3779_addr,
                                              IPAddressFamily_cmp);
        for (j = 0; j < sk_IPAddressFamily_num(child); j++) {
            IPAddressFamily *fc = sk_IPAddressFamily_value(child, j);
            int k = sk_IPAddressFamily_find(x->rfc3779_addr, fc);
            IPAddressFamily *fp =
                sk_IPAddressFamily_value(x->rfc3779_addr, k);
            if (fp == NULL) {
                if (fc->ipAddressChoice->type ==
                    IPAddressChoice_addressesOrRanges) {
                    validation_err(X509_V_ERR_UNNESTED_RESOURCE);
                    break;
                }
                continue;
            }
            if (fp->ipAddressChoice->type ==
                IPAddressChoice_addressesOrRanges) {
                if (fc->ipAddressChoice->type == IPAddressChoice_inherit
                    || addr_contains(fp->ipAddressChoice->u.addressesOrRanges,
                                     fc->ipAddressChoice->u.addressesOrRanges,
                                     length_from_afi(v3_addr_get_afi(fc))))
                    sk_IPAddressFamily_set(child, j, fp);
                else
                    validation_err(X509_V_ERR_UNNESTED_RESOURCE);
            }
        }
    }

    /*
     * Trust anchor can't inherit.
     */
    OPENSSL_assert(x != NULL);
    if (x->rfc3779_addr != NULL) {
        for (j = 0; j < sk_IPAddressFamily_num(x->rfc3779_addr); j++) {
            IPAddressFamily *fp =
                sk_IPAddressFamily_value(x->rfc3779_addr, j);
            if (fp->ipAddressChoice->type == IPAddressChoice_inherit
                && sk_IPAddressFamily_find(child, fp) >= 0)
                validation_err(X509_V_ERR_UNNESTED_RESOURCE);
        }
    }

 done:
    sk_IPAddressFamily_free(child);
    return ret;
}

# undef validation_err

/*
 * RFC 3779 2.3 path validation -- called from X509_verify_cert().
 */
int v3_addr_validate_path(X509_STORE_CTX *ctx)
{
    return v3_addr_validate_path_internal(ctx, ctx->chain, NULL);
}

/*
 * RFC 3779 2.3 path validation of an extension.
 * Test whether chain covers extension.
 */
int v3_addr_validate_resource_set(STACK_OF(X509) *chain,
                                  IPAddrBlocks *ext, int allow_inheritance)
{
    if (ext == NULL)
        return 1;
    if (chain == NULL || sk_X509_num(chain) == 0)
        return 0;
    if (!allow_inheritance && v3_addr_inherits(ext))
        return 0;
    return v3_addr_validate_path_internal(NULL, chain, ext);
}

#endif                          /* OPENSSL_NO_RFC3779 */
/* v3_akey.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 1999.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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
// #include "conf.h"
// #include "asn1.h"
// #include "asn1t.h"
// #include "x509v3.h"

static STACK_OF(CONF_VALUE) *i2v_AUTHORITY_KEYID(X509V3_EXT_METHOD *method,
                                                 AUTHORITY_KEYID *akeyid,
                                                 STACK_OF(CONF_VALUE)
                                                 *extlist);
static AUTHORITY_KEYID *v2i_AUTHORITY_KEYID(X509V3_EXT_METHOD *method,
                                            X509V3_CTX *ctx,
                                            STACK_OF(CONF_VALUE) *values);

const X509V3_EXT_METHOD v3_akey_id = {
    NID_authority_key_identifier,
    X509V3_EXT_MULTILINE, ASN1_ITEM_ref(AUTHORITY_KEYID),
    0, 0, 0, 0,
    0, 0,
    (X509V3_EXT_I2V) i2v_AUTHORITY_KEYID,
    (X509V3_EXT_V2I)v2i_AUTHORITY_KEYID,
    0, 0,
    NULL
};

static STACK_OF(CONF_VALUE) *i2v_AUTHORITY_KEYID(X509V3_EXT_METHOD *method,
                                                 AUTHORITY_KEYID *akeyid,
                                                 STACK_OF(CONF_VALUE)
                                                 *extlist)
{
    char *tmp;
    if (akeyid->keyid) {
        tmp = hex_to_string(akeyid->keyid->data, akeyid->keyid->length);
        X509V3_add_value("keyid", tmp, &extlist);
        OPENSSL_free(tmp);
    }
    if (akeyid->issuer)
        extlist = i2v_GENERAL_NAMES(NULL, akeyid->issuer, extlist);
    if (akeyid->serial) {
        tmp = hex_to_string(akeyid->serial->data, akeyid->serial->length);
        X509V3_add_value("serial", tmp, &extlist);
        OPENSSL_free(tmp);
    }
    return extlist;
}

/*-
 * Currently two options:
 * keyid: use the issuers subject keyid, the value 'always' means its is
 * an error if the issuer certificate doesn't have a key id.
 * issuer: use the issuers cert issuer and serial number. The default is
 * to only use this if keyid is not present. With the option 'always'
 * this is always included.
 */

static AUTHORITY_KEYID *v2i_AUTHORITY_KEYID(X509V3_EXT_METHOD *method,
                                            X509V3_CTX *ctx,
                                            STACK_OF(CONF_VALUE) *values)
{
    char keyid = 0, issuer = 0;
    int i;
    CONF_VALUE *cnf;
    ASN1_OCTET_STRING *ikeyid = NULL;
    X509_NAME *isname = NULL;
    GENERAL_NAMES *gens = NULL;
    GENERAL_NAME *gen = NULL;
    ASN1_INTEGER *serial = NULL;
    X509_EXTENSION *ext;
    X509 *cert;
    AUTHORITY_KEYID *akeyid;

    for (i = 0; i < sk_CONF_VALUE_num(values); i++) {
        cnf = sk_CONF_VALUE_value(values, i);
        if (!strcmp(cnf->name, "keyid")) {
            keyid = 1;
            if (cnf->value && !strcmp(cnf->value, "always"))
                keyid = 2;
        } else if (!strcmp(cnf->name, "issuer")) {
            issuer = 1;
            if (cnf->value && !strcmp(cnf->value, "always"))
                issuer = 2;
        } else {
            X509V3err(X509V3_F_V2I_AUTHORITY_KEYID, X509V3_R_UNKNOWN_OPTION);
            ERR_add_error_data(2, "name=", cnf->name);
            return NULL;
        }
    }

    if (!ctx || !ctx->issuer_cert) {
        if (ctx && (ctx->flags == CTX_TEST))
            return AUTHORITY_KEYID_new();
        X509V3err(X509V3_F_V2I_AUTHORITY_KEYID,
                  X509V3_R_NO_ISSUER_CERTIFICATE);
        return NULL;
    }

    cert = ctx->issuer_cert;

    if (keyid) {
        i = X509_get_ext_by_NID(cert, NID_subject_key_identifier, -1);
        if ((i >= 0) && (ext = X509_get_ext(cert, i)))
            ikeyid = X509V3_EXT_d2i(ext);
        if (keyid == 2 && !ikeyid) {
            X509V3err(X509V3_F_V2I_AUTHORITY_KEYID,
                      X509V3_R_UNABLE_TO_GET_ISSUER_KEYID);
            return NULL;
        }
    }

    if ((issuer && !ikeyid) || (issuer == 2)) {
        isname = X509_NAME_dup(X509_get_issuer_name(cert));
        serial = M_ASN1_INTEGER_dup(X509_get_serialNumber(cert));
        if (!isname || !serial) {
            X509V3err(X509V3_F_V2I_AUTHORITY_KEYID,
                      X509V3_R_UNABLE_TO_GET_ISSUER_DETAILS);
            goto err;
        }
    }

    if (!(akeyid = AUTHORITY_KEYID_new()))
        goto err;

    if (isname) {
        if (!(gens = sk_GENERAL_NAME_new_null())
            || !(gen = GENERAL_NAME_new())
            || !sk_GENERAL_NAME_push(gens, gen)) {
            X509V3err(X509V3_F_V2I_AUTHORITY_KEYID, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        gen->type = GEN_DIRNAME;
        gen->d.dirn = isname;
    }

    akeyid->issuer = gens;
    akeyid->serial = serial;
    akeyid->keyid = ikeyid;

    return akeyid;

 err:
    X509_NAME_free(isname);
    M_ASN1_INTEGER_free(serial);
    M_ASN1_OCTET_STRING_free(ikeyid);
    return NULL;
}
/* v3_akey_asn1.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 1999.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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
// #include "conf.h"
// #include "asn1.h"
// #include "asn1t.h"
// #include "x509v3.h"

ASN1_SEQUENCE(AUTHORITY_KEYID) = {
        ASN1_IMP_OPT(AUTHORITY_KEYID, keyid, ASN1_OCTET_STRING, 0),
        ASN1_IMP_SEQUENCE_OF_OPT(AUTHORITY_KEYID, issuer, GENERAL_NAME, 1),
        ASN1_IMP_OPT(AUTHORITY_KEYID, serial, ASN1_INTEGER, 2)
} ASN1_SEQUENCE_END(AUTHORITY_KEYID)

IMPLEMENT_ASN1_FUNCTIONS(AUTHORITY_KEYID)
/* v3_alt.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 1999-2003 The OpenSSL Project.  All rights reserved.
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
// #include "conf.h"
// #include "x509v3.h"

static GENERAL_NAMES *v2i_subject_alt(X509V3_EXT_METHOD *method,
                                      X509V3_CTX *ctx,
                                      STACK_OF(CONF_VALUE) *nval);
static GENERAL_NAMES *v2i_issuer_alt(X509V3_EXT_METHOD *method,
                                     X509V3_CTX *ctx,
                                     STACK_OF(CONF_VALUE) *nval);
static int copy_email(X509V3_CTX *ctx, GENERAL_NAMES *gens, int move_p);
static int copy_issuer(X509V3_CTX *ctx, GENERAL_NAMES *gens);
static int do_othername(GENERAL_NAME *gen, char *value, X509V3_CTX *ctx);
static int do_dirname(GENERAL_NAME *gen, char *value, X509V3_CTX *ctx);

const X509V3_EXT_METHOD v3_alt[] = {
    {NID_subject_alt_name, 0, ASN1_ITEM_ref(GENERAL_NAMES),
     0, 0, 0, 0,
     0, 0,
     (X509V3_EXT_I2V) i2v_GENERAL_NAMES,
     (X509V3_EXT_V2I)v2i_subject_alt,
     NULL, NULL, NULL},

    {NID_issuer_alt_name, 0, ASN1_ITEM_ref(GENERAL_NAMES),
     0, 0, 0, 0,
     0, 0,
     (X509V3_EXT_I2V) i2v_GENERAL_NAMES,
     (X509V3_EXT_V2I)v2i_issuer_alt,
     NULL, NULL, NULL},

    {NID_certificate_issuer, 0, ASN1_ITEM_ref(GENERAL_NAMES),
     0, 0, 0, 0,
     0, 0,
     (X509V3_EXT_I2V) i2v_GENERAL_NAMES,
     NULL, NULL, NULL, NULL},
};

STACK_OF(CONF_VALUE) *i2v_GENERAL_NAMES(X509V3_EXT_METHOD *method,
                                        GENERAL_NAMES *gens,
                                        STACK_OF(CONF_VALUE) *ret)
{
    int i;
    GENERAL_NAME *gen;
    for (i = 0; i < sk_GENERAL_NAME_num(gens); i++) {
        gen = sk_GENERAL_NAME_value(gens, i);
        ret = i2v_GENERAL_NAME(method, gen, ret);
    }
    if (!ret)
        return sk_CONF_VALUE_new_null();
    return ret;
}

STACK_OF(CONF_VALUE) *i2v_GENERAL_NAME(X509V3_EXT_METHOD *method,
                                       GENERAL_NAME *gen,
                                       STACK_OF(CONF_VALUE) *ret)
{
    unsigned char *p;
    char oline[256], htmp[5];
    int i;
    switch (gen->type) {
    case GEN_OTHERNAME:
        if (!X509V3_add_value("othername", "<unsupported>", &ret))
            return NULL;
        break;

    case GEN_X400:
        if (!X509V3_add_value("X400Name", "<unsupported>", &ret))
            return NULL;
        break;

    case GEN_EDIPARTY:
        if (!X509V3_add_value("EdiPartyName", "<unsupported>", &ret))
            return NULL;
        break;

    case GEN_EMAIL:
        if (!X509V3_add_value_uchar("email", gen->d.ia5->data, &ret))
            return NULL;
        break;

    case GEN_DNS:
        if (!X509V3_add_value_uchar("DNS", gen->d.ia5->data, &ret))
            return NULL;
        break;

    case GEN_URI:
        if (!X509V3_add_value_uchar("URI", gen->d.ia5->data, &ret))
            return NULL;
        break;

    case GEN_DIRNAME:
        if (X509_NAME_oneline(gen->d.dirn, oline, 256) == NULL
                || !X509V3_add_value("DirName", oline, &ret))
            return NULL;
        break;

    case GEN_IPADD:
        p = gen->d.ip->data;
        if (gen->d.ip->length == 4)
            BIO_snprintf(oline, sizeof(oline),
                         "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
        else if (gen->d.ip->length == 16) {
            oline[0] = 0;
            for (i = 0; i < 8; i++) {
                BIO_snprintf(htmp, sizeof(htmp), "%X", p[0] << 8 | p[1]);
                p += 2;
                strcat(oline, htmp);
                if (i != 7)
                    strcat(oline, ":");
            }
        } else {
            if (!X509V3_add_value("IP Address", "<invalid>", &ret))
                return NULL;
            break;
        }
        if (!X509V3_add_value("IP Address", oline, &ret))
            return NULL;
        break;

    case GEN_RID:
        i2t_ASN1_OBJECT(oline, 256, gen->d.rid);
        if (!X509V3_add_value("Registered ID", oline, &ret))
            return NULL;
        break;
    }
    return ret;
}

int GENERAL_NAME_print(BIO *out, GENERAL_NAME *gen)
{
    unsigned char *p;
    int i;
    switch (gen->type) {
    case GEN_OTHERNAME:
        BIO_printf(out, "othername:<unsupported>");
        break;

    case GEN_X400:
        BIO_printf(out, "X400Name:<unsupported>");
        break;

    case GEN_EDIPARTY:
        /* Maybe fix this: it is supported now */
        BIO_printf(out, "EdiPartyName:<unsupported>");
        break;

    case GEN_EMAIL:
        BIO_printf(out, "email:%s", gen->d.ia5->data);
        break;

    case GEN_DNS:
        BIO_printf(out, "DNS:%s", gen->d.ia5->data);
        break;

    case GEN_URI:
        BIO_printf(out, "URI:%s", gen->d.ia5->data);
        break;

    case GEN_DIRNAME:
        BIO_printf(out, "DirName: ");
        X509_NAME_print_ex(out, gen->d.dirn, 0, XN_FLAG_ONELINE);
        break;

    case GEN_IPADD:
        p = gen->d.ip->data;
        if (gen->d.ip->length == 4)
            BIO_printf(out, "IP Address:%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
        else if (gen->d.ip->length == 16) {
            BIO_printf(out, "IP Address");
            for (i = 0; i < 8; i++) {
                BIO_printf(out, ":%X", p[0] << 8 | p[1]);
                p += 2;
            }
            BIO_puts(out, "\n");
        } else {
            BIO_printf(out, "IP Address:<invalid>");
            break;
        }
        break;

    case GEN_RID:
        BIO_printf(out, "Registered ID");
        i2a_ASN1_OBJECT(out, gen->d.rid);
        break;
    }
    return 1;
}

static GENERAL_NAMES *v2i_issuer_alt(X509V3_EXT_METHOD *method,
                                     X509V3_CTX *ctx,
                                     STACK_OF(CONF_VALUE) *nval)
{
    GENERAL_NAMES *gens = NULL;
    CONF_VALUE *cnf;
    int i;
    if (!(gens = sk_GENERAL_NAME_new_null())) {
        X509V3err(X509V3_F_V2I_ISSUER_ALT, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    for (i = 0; i < sk_CONF_VALUE_num(nval); i++) {
        cnf = sk_CONF_VALUE_value(nval, i);
        if (!name_cmp(cnf->name, "issuer") && cnf->value &&
            !strcmp(cnf->value, "copy")) {
            if (!copy_issuer(ctx, gens))
                goto err;
        } else {
            GENERAL_NAME *gen;
            if (!(gen = v2i_GENERAL_NAME(method, ctx, cnf)))
                goto err;
            sk_GENERAL_NAME_push(gens, gen);
        }
    }
    return gens;
 err:
    sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
    return NULL;
}

/* Append subject altname of issuer to issuer alt name of subject */

static int copy_issuer(X509V3_CTX *ctx, GENERAL_NAMES *gens)
{
    GENERAL_NAMES *ialt;
    GENERAL_NAME *gen;
    X509_EXTENSION *ext;
    int i;
    if (ctx && (ctx->flags == CTX_TEST))
        return 1;
    if (!ctx || !ctx->issuer_cert) {
        X509V3err(X509V3_F_COPY_ISSUER, X509V3_R_NO_ISSUER_DETAILS);
        goto err;
    }
    i = X509_get_ext_by_NID(ctx->issuer_cert, NID_subject_alt_name, -1);
    if (i < 0)
        return 1;
    if (!(ext = X509_get_ext(ctx->issuer_cert, i)) ||
        !(ialt = X509V3_EXT_d2i(ext))) {
        X509V3err(X509V3_F_COPY_ISSUER, X509V3_R_ISSUER_DECODE_ERROR);
        goto err;
    }

    for (i = 0; i < sk_GENERAL_NAME_num(ialt); i++) {
        gen = sk_GENERAL_NAME_value(ialt, i);
        if (!sk_GENERAL_NAME_push(gens, gen)) {
            X509V3err(X509V3_F_COPY_ISSUER, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    }
    sk_GENERAL_NAME_free(ialt);

    return 1;

 err:
    return 0;

}

static GENERAL_NAMES *v2i_subject_alt(X509V3_EXT_METHOD *method,
                                      X509V3_CTX *ctx,
                                      STACK_OF(CONF_VALUE) *nval)
{
    GENERAL_NAMES *gens = NULL;
    CONF_VALUE *cnf;
    int i;
    if (!(gens = sk_GENERAL_NAME_new_null())) {
        X509V3err(X509V3_F_V2I_SUBJECT_ALT, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    for (i = 0; i < sk_CONF_VALUE_num(nval); i++) {
        cnf = sk_CONF_VALUE_value(nval, i);
        if (!name_cmp(cnf->name, "email") && cnf->value &&
            !strcmp(cnf->value, "copy")) {
            if (!copy_email(ctx, gens, 0))
                goto err;
        } else if (!name_cmp(cnf->name, "email") && cnf->value &&
                   !strcmp(cnf->value, "move")) {
            if (!copy_email(ctx, gens, 1))
                goto err;
        } else {
            GENERAL_NAME *gen;
            if (!(gen = v2i_GENERAL_NAME(method, ctx, cnf)))
                goto err;
            sk_GENERAL_NAME_push(gens, gen);
        }
    }
    return gens;
 err:
    sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
    return NULL;
}

/*
 * Copy any email addresses in a certificate or request to GENERAL_NAMES
 */

static int copy_email(X509V3_CTX *ctx, GENERAL_NAMES *gens, int move_p)
{
    X509_NAME *nm;
    ASN1_IA5STRING *email = NULL;
    X509_NAME_ENTRY *ne;
    GENERAL_NAME *gen = NULL;
    int i;
    if (ctx != NULL && ctx->flags == CTX_TEST)
        return 1;
    if (!ctx || (!ctx->subject_cert && !ctx->subject_req)) {
        X509V3err(X509V3_F_COPY_EMAIL, X509V3_R_NO_SUBJECT_DETAILS);
        goto err;
    }
    /* Find the subject name */
    if (ctx->subject_cert)
        nm = X509_get_subject_name(ctx->subject_cert);
    else
        nm = X509_REQ_get_subject_name(ctx->subject_req);

    /* Now add any email address(es) to STACK */
    i = -1;
    while ((i = X509_NAME_get_index_by_NID(nm,
                                           NID_pkcs9_emailAddress, i)) >= 0) {
        ne = X509_NAME_get_entry(nm, i);
        email = M_ASN1_IA5STRING_dup(X509_NAME_ENTRY_get_data(ne));
        if (move_p) {
            X509_NAME_delete_entry(nm, i);
            X509_NAME_ENTRY_free(ne);
            i--;
        }
        if (!email || !(gen = GENERAL_NAME_new())) {
            X509V3err(X509V3_F_COPY_EMAIL, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        gen->d.ia5 = email;
        email = NULL;
        gen->type = GEN_EMAIL;
        if (!sk_GENERAL_NAME_push(gens, gen)) {
            X509V3err(X509V3_F_COPY_EMAIL, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        gen = NULL;
    }

    return 1;

 err:
    GENERAL_NAME_free(gen);
    M_ASN1_IA5STRING_free(email);
    return 0;

}

GENERAL_NAMES *v2i_GENERAL_NAMES(const X509V3_EXT_METHOD *method,
                                 X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval)
{
    GENERAL_NAME *gen;
    GENERAL_NAMES *gens = NULL;
    CONF_VALUE *cnf;
    int i;
    if (!(gens = sk_GENERAL_NAME_new_null())) {
        X509V3err(X509V3_F_V2I_GENERAL_NAMES, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    for (i = 0; i < sk_CONF_VALUE_num(nval); i++) {
        cnf = sk_CONF_VALUE_value(nval, i);
        if (!(gen = v2i_GENERAL_NAME(method, ctx, cnf)))
            goto err;
        sk_GENERAL_NAME_push(gens, gen);
    }
    return gens;
 err:
    sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
    return NULL;
}

GENERAL_NAME *v2i_GENERAL_NAME(const X509V3_EXT_METHOD *method,
                               X509V3_CTX *ctx, CONF_VALUE *cnf)
{
    return v2i_GENERAL_NAME_ex(NULL, method, ctx, cnf, 0);
}

GENERAL_NAME *a2i_GENERAL_NAME(GENERAL_NAME *out,
                               const X509V3_EXT_METHOD *method,
                               X509V3_CTX *ctx, int gen_type, char *value,
                               int is_nc)
{
    char is_string = 0;
    GENERAL_NAME *gen = NULL;

    if (!value) {
        X509V3err(X509V3_F_A2I_GENERAL_NAME, X509V3_R_MISSING_VALUE);
        return NULL;
    }

    if (out)
        gen = out;
    else {
        gen = GENERAL_NAME_new();
        if (gen == NULL) {
            X509V3err(X509V3_F_A2I_GENERAL_NAME, ERR_R_MALLOC_FAILURE);
            return NULL;
        }
    }

    switch (gen_type) {
    case GEN_URI:
    case GEN_EMAIL:
    case GEN_DNS:
        is_string = 1;
        break;

    case GEN_RID:
        {
            ASN1_OBJECT *obj;
            if (!(obj = OBJ_txt2obj(value, 0))) {
                X509V3err(X509V3_F_A2I_GENERAL_NAME, X509V3_R_BAD_OBJECT);
                ERR_add_error_data(2, "value=", value);
                goto err;
            }
            gen->d.rid = obj;
        }
        break;

    case GEN_IPADD:
        if (is_nc)
            gen->d.ip = a2i_IPADDRESS_NC(value);
        else
            gen->d.ip = a2i_IPADDRESS(value);
        if (gen->d.ip == NULL) {
            X509V3err(X509V3_F_A2I_GENERAL_NAME, X509V3_R_BAD_IP_ADDRESS);
            ERR_add_error_data(2, "value=", value);
            goto err;
        }
        break;

    case GEN_DIRNAME:
        if (!do_dirname(gen, value, ctx)) {
            X509V3err(X509V3_F_A2I_GENERAL_NAME, X509V3_R_DIRNAME_ERROR);
            goto err;
        }
        break;

    case GEN_OTHERNAME:
        if (!do_othername(gen, value, ctx)) {
            X509V3err(X509V3_F_A2I_GENERAL_NAME, X509V3_R_OTHERNAME_ERROR);
            goto err;
        }
        break;
    default:
        X509V3err(X509V3_F_A2I_GENERAL_NAME, X509V3_R_UNSUPPORTED_TYPE);
        goto err;
    }

    if (is_string) {
        if (!(gen->d.ia5 = M_ASN1_IA5STRING_new()) ||
            !ASN1_STRING_set(gen->d.ia5, (unsigned char *)value,
                             strlen(value))) {
            X509V3err(X509V3_F_A2I_GENERAL_NAME, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    }

    gen->type = gen_type;

    return gen;

 err:
    if (!out)
        GENERAL_NAME_free(gen);
    return NULL;
}

GENERAL_NAME *v2i_GENERAL_NAME_ex(GENERAL_NAME *out,
                                  const X509V3_EXT_METHOD *method,
                                  X509V3_CTX *ctx, CONF_VALUE *cnf, int is_nc)
{
    int type;

    char *name, *value;

    name = cnf->name;
    value = cnf->value;

    if (!value) {
        X509V3err(X509V3_F_V2I_GENERAL_NAME_EX, X509V3_R_MISSING_VALUE);
        return NULL;
    }

    if (!name_cmp(name, "email"))
        type = GEN_EMAIL;
    else if (!name_cmp(name, "URI"))
        type = GEN_URI;
    else if (!name_cmp(name, "DNS"))
        type = GEN_DNS;
    else if (!name_cmp(name, "RID"))
        type = GEN_RID;
    else if (!name_cmp(name, "IP"))
        type = GEN_IPADD;
    else if (!name_cmp(name, "dirName"))
        type = GEN_DIRNAME;
    else if (!name_cmp(name, "otherName"))
        type = GEN_OTHERNAME;
    else {
        X509V3err(X509V3_F_V2I_GENERAL_NAME_EX, X509V3_R_UNSUPPORTED_OPTION);
        ERR_add_error_data(2, "name=", name);
        return NULL;
    }

    return a2i_GENERAL_NAME(out, method, ctx, type, value, is_nc);

}

static int do_othername(GENERAL_NAME *gen, char *value, X509V3_CTX *ctx)
{
    char *objtmp = NULL, *p;
    int objlen;
    if (!(p = strchr(value, ';')))
        return 0;
    if (!(gen->d.otherName = OTHERNAME_new()))
        return 0;
    /*
     * Free this up because we will overwrite it. no need to free type_id
     * because it is static
     */
    ASN1_TYPE_free(gen->d.otherName->value);
    if (!(gen->d.otherName->value = ASN1_generate_v3(p + 1, ctx)))
        return 0;
    objlen = p - value;
    objtmp = OPENSSL_malloc(objlen + 1);
    if (objtmp == NULL)
        return 0;
    strncpy(objtmp, value, objlen);
    objtmp[objlen] = 0;
    gen->d.otherName->type_id = OBJ_txt2obj(objtmp, 0);
    OPENSSL_free(objtmp);
    if (!gen->d.otherName->type_id)
        return 0;
    return 1;
}

static int do_dirname(GENERAL_NAME *gen, char *value, X509V3_CTX *ctx)
{
    int ret = 0;
    STACK_OF(CONF_VALUE) *sk = NULL;
    X509_NAME *nm = NULL;
    if (!(nm = X509_NAME_new()))
        goto err;
    sk = X509V3_get_section(ctx, value);
    if (!sk) {
        X509V3err(X509V3_F_DO_DIRNAME, X509V3_R_SECTION_NOT_FOUND);
        ERR_add_error_data(2, "section=", value);
        goto err;
    }
    /* FIXME: should allow other character types... */
    ret = X509V3_NAME_from_section(nm, sk, MBSTRING_ASC);
    if (!ret)
        goto err;
    gen->d.dirn = nm;

err:
    if (ret == 0)
        X509_NAME_free(nm);
    X509V3_section_free(ctx, sk);
    return ret;
}
/*
 * Contributed to the OpenSSL Project by the American Registry for
 * Internet Numbers ("ARIN").
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
 */

/*
 * Implementation of RFC 3779 section 3.2.
 */

#include <stdio.h>
#include <string.h>
// #include "cryptlib.h"
// #include "conf.h"
// #include "asn1.h"
// #include "asn1t.h"
// #include "x509v3.h"
#include "x509.h"
#include "bn.h"

#ifndef OPENSSL_NO_RFC3779

/*
 * OpenSSL ASN.1 template translation of RFC 3779 3.2.3.
 */

ASN1_SEQUENCE(ASRange) = {
  ASN1_SIMPLE(ASRange, min, ASN1_INTEGER),
  ASN1_SIMPLE(ASRange, max, ASN1_INTEGER)
} ASN1_SEQUENCE_END(ASRange)

ASN1_CHOICE(ASIdOrRange) = {
  ASN1_SIMPLE(ASIdOrRange, u.id,    ASN1_INTEGER),
  ASN1_SIMPLE(ASIdOrRange, u.range, ASRange)
} ASN1_CHOICE_END(ASIdOrRange)

ASN1_CHOICE(ASIdentifierChoice) = {
  ASN1_SIMPLE(ASIdentifierChoice,      u.inherit,       ASN1_NULL),
  ASN1_SEQUENCE_OF(ASIdentifierChoice, u.asIdsOrRanges, ASIdOrRange)
} ASN1_CHOICE_END(ASIdentifierChoice)

ASN1_SEQUENCE(ASIdentifiers) = {
  ASN1_EXP_OPT(ASIdentifiers, asnum, ASIdentifierChoice, 0),
  ASN1_EXP_OPT(ASIdentifiers, rdi,   ASIdentifierChoice, 1)
} ASN1_SEQUENCE_END(ASIdentifiers)

IMPLEMENT_ASN1_FUNCTIONS(ASRange)
IMPLEMENT_ASN1_FUNCTIONS(ASIdOrRange)
IMPLEMENT_ASN1_FUNCTIONS(ASIdentifierChoice)
IMPLEMENT_ASN1_FUNCTIONS(ASIdentifiers)

/*
 * i2r method for an ASIdentifierChoice.
 */
static int i2r_ASIdentifierChoice(BIO *out,
                                  ASIdentifierChoice *choice,
                                  int indent, const char *msg)
{
    int i;
    char *s;
    if (choice == NULL)
        return 1;
    BIO_printf(out, "%*s%s:\n", indent, "", msg);
    switch (choice->type) {
    case ASIdentifierChoice_inherit:
        BIO_printf(out, "%*sinherit\n", indent + 2, "");
        break;
    case ASIdentifierChoice_asIdsOrRanges:
        for (i = 0; i < sk_ASIdOrRange_num(choice->u.asIdsOrRanges); i++) {
            ASIdOrRange *aor =
                sk_ASIdOrRange_value(choice->u.asIdsOrRanges, i);
            switch (aor->type) {
            case ASIdOrRange_id:
                if ((s = i2s_ASN1_INTEGER(NULL, aor->u.id)) == NULL)
                    return 0;
                BIO_printf(out, "%*s%s\n", indent + 2, "", s);
                OPENSSL_free(s);
                break;
            case ASIdOrRange_range:
                if ((s = i2s_ASN1_INTEGER(NULL, aor->u.range->min)) == NULL)
                    return 0;
                BIO_printf(out, "%*s%s-", indent + 2, "", s);
                OPENSSL_free(s);
                if ((s = i2s_ASN1_INTEGER(NULL, aor->u.range->max)) == NULL)
                    return 0;
                BIO_printf(out, "%s\n", s);
                OPENSSL_free(s);
                break;
            default:
                return 0;
            }
        }
        break;
    default:
        return 0;
    }
    return 1;
}

/*
 * i2r method for an ASIdentifier extension.
 */
static int i2r_ASIdentifiers(const X509V3_EXT_METHOD *method,
                             void *ext, BIO *out, int indent)
{
    ASIdentifiers *asid = ext;
    return (i2r_ASIdentifierChoice(out, asid->asnum, indent,
                                   "Autonomous System Numbers") &&
            i2r_ASIdentifierChoice(out, asid->rdi, indent,
                                   "Routing Domain Identifiers"));
}

/*
 * Sort comparision function for a sequence of ASIdOrRange elements.
 */
static int ASIdOrRange_cmp(const ASIdOrRange *const *a_,
                           const ASIdOrRange *const *b_)
{
    const ASIdOrRange *a = *a_, *b = *b_;

    OPENSSL_assert((a->type == ASIdOrRange_id && a->u.id != NULL) ||
                   (a->type == ASIdOrRange_range && a->u.range != NULL &&
                    a->u.range->min != NULL && a->u.range->max != NULL));

    OPENSSL_assert((b->type == ASIdOrRange_id && b->u.id != NULL) ||
                   (b->type == ASIdOrRange_range && b->u.range != NULL &&
                    b->u.range->min != NULL && b->u.range->max != NULL));

    if (a->type == ASIdOrRange_id && b->type == ASIdOrRange_id)
        return ASN1_INTEGER_cmp(a->u.id, b->u.id);

    if (a->type == ASIdOrRange_range && b->type == ASIdOrRange_range) {
        int r = ASN1_INTEGER_cmp(a->u.range->min, b->u.range->min);
        return r != 0 ? r : ASN1_INTEGER_cmp(a->u.range->max,
                                             b->u.range->max);
    }

    if (a->type == ASIdOrRange_id)
        return ASN1_INTEGER_cmp(a->u.id, b->u.range->min);
    else
        return ASN1_INTEGER_cmp(a->u.range->min, b->u.id);
}

/*
 * Add an inherit element.
 */
int v3_asid_add_inherit(ASIdentifiers *asid, int which)
{
    ASIdentifierChoice **choice;
    if (asid == NULL)
        return 0;
    switch (which) {
    case V3_ASID_ASNUM:
        choice = &asid->asnum;
        break;
    case V3_ASID_RDI:
        choice = &asid->rdi;
        break;
    default:
        return 0;
    }
    if (*choice == NULL) {
        if ((*choice = ASIdentifierChoice_new()) == NULL)
            return 0;
        OPENSSL_assert((*choice)->u.inherit == NULL);
        if (((*choice)->u.inherit = ASN1_NULL_new()) == NULL)
            return 0;
        (*choice)->type = ASIdentifierChoice_inherit;
    }
    return (*choice)->type == ASIdentifierChoice_inherit;
}

/*
 * Add an ID or range to an ASIdentifierChoice.
 */
int v3_asid_add_id_or_range(ASIdentifiers *asid,
                            int which, ASN1_INTEGER *min, ASN1_INTEGER *max)
{
    ASIdentifierChoice **choice;
    ASIdOrRange *aor;
    if (asid == NULL)
        return 0;
    switch (which) {
    case V3_ASID_ASNUM:
        choice = &asid->asnum;
        break;
    case V3_ASID_RDI:
        choice = &asid->rdi;
        break;
    default:
        return 0;
    }
    if (*choice != NULL && (*choice)->type == ASIdentifierChoice_inherit)
        return 0;
    if (*choice == NULL) {
        if ((*choice = ASIdentifierChoice_new()) == NULL)
            return 0;
        OPENSSL_assert((*choice)->u.asIdsOrRanges == NULL);
        (*choice)->u.asIdsOrRanges = sk_ASIdOrRange_new(ASIdOrRange_cmp);
        if ((*choice)->u.asIdsOrRanges == NULL)
            return 0;
        (*choice)->type = ASIdentifierChoice_asIdsOrRanges;
    }
    if ((aor = ASIdOrRange_new()) == NULL)
        return 0;
    if (max == NULL) {
        aor->type = ASIdOrRange_id;
        aor->u.id = min;
    } else {
        aor->type = ASIdOrRange_range;
        if ((aor->u.range = ASRange_new()) == NULL)
            goto err;
        ASN1_INTEGER_free(aor->u.range->min);
        aor->u.range->min = min;
        ASN1_INTEGER_free(aor->u.range->max);
        aor->u.range->max = max;
    }
    if (!(sk_ASIdOrRange_push((*choice)->u.asIdsOrRanges, aor)))
        goto err;
    return 1;

 err:
    ASIdOrRange_free(aor);
    return 0;
}

/*
 * Extract min and max values from an ASIdOrRange.
 */
static void extract_min_max(ASIdOrRange *aor,
                            ASN1_INTEGER **min, ASN1_INTEGER **max)
{
    OPENSSL_assert(aor != NULL && min != NULL && max != NULL);
    switch (aor->type) {
    case ASIdOrRange_id:
        *min = aor->u.id;
        *max = aor->u.id;
        return;
    case ASIdOrRange_range:
        *min = aor->u.range->min;
        *max = aor->u.range->max;
        return;
    }
}

/*
 * Check whether an ASIdentifierChoice is in canonical form.
 */
static int ASIdentifierChoice_is_canonical(ASIdentifierChoice *choice)
{
    ASN1_INTEGER *a_max_plus_one = NULL;
    BIGNUM *bn = NULL;
    int i, ret = 0;

    /*
     * Empty element or inheritance is canonical.
     */
    if (choice == NULL || choice->type == ASIdentifierChoice_inherit)
        return 1;

    /*
     * If not a list, or if empty list, it's broken.
     */
    if (choice->type != ASIdentifierChoice_asIdsOrRanges ||
        sk_ASIdOrRange_num(choice->u.asIdsOrRanges) == 0)
        return 0;

    /*
     * It's a list, check it.
     */
    for (i = 0; i < sk_ASIdOrRange_num(choice->u.asIdsOrRanges) - 1; i++) {
        ASIdOrRange *a = sk_ASIdOrRange_value(choice->u.asIdsOrRanges, i);
        ASIdOrRange *b = sk_ASIdOrRange_value(choice->u.asIdsOrRanges, i + 1);
        ASN1_INTEGER *a_min, *a_max, *b_min, *b_max;

        extract_min_max(a, &a_min, &a_max);
        extract_min_max(b, &b_min, &b_max);

        /*
         * Punt misordered list, overlapping start, or inverted range.
         */
        if (ASN1_INTEGER_cmp(a_min, b_min) >= 0 ||
            ASN1_INTEGER_cmp(a_min, a_max) > 0 ||
            ASN1_INTEGER_cmp(b_min, b_max) > 0)
            goto done;

        /*
         * Calculate a_max + 1 to check for adjacency.
         */
        if ((bn == NULL && (bn = BN_new()) == NULL) ||
            ASN1_INTEGER_to_BN(a_max, bn) == NULL ||
            !BN_add_word(bn, 1) ||
            (a_max_plus_one =
             BN_to_ASN1_INTEGER(bn, a_max_plus_one)) == NULL) {
            X509V3err(X509V3_F_ASIDENTIFIERCHOICE_IS_CANONICAL,
                      ERR_R_MALLOC_FAILURE);
            goto done;
        }

        /*
         * Punt if adjacent or overlapping.
         */
        if (ASN1_INTEGER_cmp(a_max_plus_one, b_min) >= 0)
            goto done;
    }

    /*
     * Check for inverted range.
     */
    i = sk_ASIdOrRange_num(choice->u.asIdsOrRanges) - 1;
    {
        ASIdOrRange *a = sk_ASIdOrRange_value(choice->u.asIdsOrRanges, i);
        ASN1_INTEGER *a_min, *a_max;
        if (a != NULL && a->type == ASIdOrRange_range) {
            extract_min_max(a, &a_min, &a_max);
            if (ASN1_INTEGER_cmp(a_min, a_max) > 0)
                goto done;
        }
    }

    ret = 1;

 done:
    ASN1_INTEGER_free(a_max_plus_one);
    BN_free(bn);
    return ret;
}

/*
 * Check whether an ASIdentifier extension is in canonical form.
 */
int v3_asid_is_canonical(ASIdentifiers *asid)
{
    return (asid == NULL ||
            (ASIdentifierChoice_is_canonical(asid->asnum) &&
             ASIdentifierChoice_is_canonical(asid->rdi)));
}

/*
 * Whack an ASIdentifierChoice into canonical form.
 */
static int ASIdentifierChoice_canonize(ASIdentifierChoice *choice)
{
    ASN1_INTEGER *a_max_plus_one = NULL;
    BIGNUM *bn = NULL;
    int i, ret = 0;

    /*
     * Nothing to do for empty element or inheritance.
     */
    if (choice == NULL || choice->type == ASIdentifierChoice_inherit)
        return 1;

    /*
     * If not a list, or if empty list, it's broken.
     */
    if (choice->type != ASIdentifierChoice_asIdsOrRanges ||
        sk_ASIdOrRange_num(choice->u.asIdsOrRanges) == 0) {
        X509V3err(X509V3_F_ASIDENTIFIERCHOICE_CANONIZE,
                  X509V3_R_EXTENSION_VALUE_ERROR);
        return 0;
    }

    /*
     * We have a non-empty list.  Sort it.
     */
    sk_ASIdOrRange_sort(choice->u.asIdsOrRanges);

    /*
     * Now check for errors and suboptimal encoding, rejecting the
     * former and fixing the latter.
     */
    for (i = 0; i < sk_ASIdOrRange_num(choice->u.asIdsOrRanges) - 1; i++) {
        ASIdOrRange *a = sk_ASIdOrRange_value(choice->u.asIdsOrRanges, i);
        ASIdOrRange *b = sk_ASIdOrRange_value(choice->u.asIdsOrRanges, i + 1);
        ASN1_INTEGER *a_min, *a_max, *b_min, *b_max;

        extract_min_max(a, &a_min, &a_max);
        extract_min_max(b, &b_min, &b_max);

        /*
         * Make sure we're properly sorted (paranoia).
         */
        OPENSSL_assert(ASN1_INTEGER_cmp(a_min, b_min) <= 0);

        /*
         * Punt inverted ranges.
         */
        if (ASN1_INTEGER_cmp(a_min, a_max) > 0 ||
            ASN1_INTEGER_cmp(b_min, b_max) > 0)
            goto done;

        /*
         * Check for overlaps.
         */
        if (ASN1_INTEGER_cmp(a_max, b_min) >= 0) {
            X509V3err(X509V3_F_ASIDENTIFIERCHOICE_CANONIZE,
                      X509V3_R_EXTENSION_VALUE_ERROR);
            goto done;
        }

        /*
         * Calculate a_max + 1 to check for adjacency.
         */
        if ((bn == NULL && (bn = BN_new()) == NULL) ||
            ASN1_INTEGER_to_BN(a_max, bn) == NULL ||
            !BN_add_word(bn, 1) ||
            (a_max_plus_one =
             BN_to_ASN1_INTEGER(bn, a_max_plus_one)) == NULL) {
            X509V3err(X509V3_F_ASIDENTIFIERCHOICE_CANONIZE,
                      ERR_R_MALLOC_FAILURE);
            goto done;
        }

        /*
         * If a and b are adjacent, merge them.
         */
        if (ASN1_INTEGER_cmp(a_max_plus_one, b_min) == 0) {
            ASRange *r;
            switch (a->type) {
            case ASIdOrRange_id:
                if ((r = OPENSSL_malloc(sizeof(ASRange))) == NULL) {
                    X509V3err(X509V3_F_ASIDENTIFIERCHOICE_CANONIZE,
                              ERR_R_MALLOC_FAILURE);
                    goto done;
                }
                r->min = a_min;
                r->max = b_max;
                a->type = ASIdOrRange_range;
                a->u.range = r;
                break;
            case ASIdOrRange_range:
                ASN1_INTEGER_free(a->u.range->max);
                a->u.range->max = b_max;
                break;
            }
            switch (b->type) {
            case ASIdOrRange_id:
                b->u.id = NULL;
                break;
            case ASIdOrRange_range:
                b->u.range->max = NULL;
                break;
            }
            ASIdOrRange_free(b);
            (void)sk_ASIdOrRange_delete(choice->u.asIdsOrRanges, i + 1);
            i--;
            continue;
        }
    }

    /*
     * Check for final inverted range.
     */
    i = sk_ASIdOrRange_num(choice->u.asIdsOrRanges) - 1;
    {
        ASIdOrRange *a = sk_ASIdOrRange_value(choice->u.asIdsOrRanges, i);
        ASN1_INTEGER *a_min, *a_max;
        if (a != NULL && a->type == ASIdOrRange_range) {
            extract_min_max(a, &a_min, &a_max);
            if (ASN1_INTEGER_cmp(a_min, a_max) > 0)
                goto done;
        }
    }

    OPENSSL_assert(ASIdentifierChoice_is_canonical(choice)); /* Paranoia */

    ret = 1;

 done:
    ASN1_INTEGER_free(a_max_plus_one);
    BN_free(bn);
    return ret;
}

/*
 * Whack an ASIdentifier extension into canonical form.
 */
int v3_asid_canonize(ASIdentifiers *asid)
{
    return (asid == NULL ||
            (ASIdentifierChoice_canonize(asid->asnum) &&
             ASIdentifierChoice_canonize(asid->rdi)));
}

/*
 * v2i method for an ASIdentifier extension.
 */
static void *v2i_ASIdentifiers(const struct v3_ext_method *method,
                               struct v3_ext_ctx *ctx,
                               STACK_OF(CONF_VALUE) *values)
{
    ASN1_INTEGER *min = NULL, *max = NULL;
    ASIdentifiers *asid = NULL;
    int i;

    if ((asid = ASIdentifiers_new()) == NULL) {
        X509V3err(X509V3_F_V2I_ASIDENTIFIERS, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    for (i = 0; i < sk_CONF_VALUE_num(values); i++) {
        CONF_VALUE *val = sk_CONF_VALUE_value(values, i);
        int i1, i2, i3, is_range, which;

        /*
         * Figure out whether this is an AS or an RDI.
         */
        if (!name_cmp(val->name, "AS")) {
            which = V3_ASID_ASNUM;
        } else if (!name_cmp(val->name, "RDI")) {
            which = V3_ASID_RDI;
        } else {
            X509V3err(X509V3_F_V2I_ASIDENTIFIERS,
                      X509V3_R_EXTENSION_NAME_ERROR);
            X509V3_conf_err(val);
            goto err;
        }

        /*
         * Handle inheritance.
         */
        if (!strcmp(val->value, "inherit")) {
            if (v3_asid_add_inherit(asid, which))
                continue;
            X509V3err(X509V3_F_V2I_ASIDENTIFIERS,
                      X509V3_R_INVALID_INHERITANCE);
            X509V3_conf_err(val);
            goto err;
        }

        /*
         * Number, range, or mistake, pick it apart and figure out which.
         */
        i1 = strspn(val->value, "0123456789");
        if (val->value[i1] == '\0') {
            is_range = 0;
        } else {
            is_range = 1;
            i2 = i1 + strspn(val->value + i1, " \t");
            if (val->value[i2] != '-') {
                X509V3err(X509V3_F_V2I_ASIDENTIFIERS,
                          X509V3_R_INVALID_ASNUMBER);
                X509V3_conf_err(val);
                goto err;
            }
            i2++;
            i2 = i2 + strspn(val->value + i2, " \t");
            i3 = i2 + strspn(val->value + i2, "0123456789");
            if (val->value[i3] != '\0') {
                X509V3err(X509V3_F_V2I_ASIDENTIFIERS,
                          X509V3_R_INVALID_ASRANGE);
                X509V3_conf_err(val);
                goto err;
            }
        }

        /*
         * Syntax is ok, read and add it.
         */
        if (!is_range) {
            if (!X509V3_get_value_int(val, &min)) {
                X509V3err(X509V3_F_V2I_ASIDENTIFIERS, ERR_R_MALLOC_FAILURE);
                goto err;
            }
        } else {
            char *s = BUF_strdup(val->value);
            if (s == NULL) {
                X509V3err(X509V3_F_V2I_ASIDENTIFIERS, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            s[i1] = '\0';
            min = s2i_ASN1_INTEGER(NULL, s);
            max = s2i_ASN1_INTEGER(NULL, s + i2);
            OPENSSL_free(s);
            if (min == NULL || max == NULL) {
                X509V3err(X509V3_F_V2I_ASIDENTIFIERS, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            if (ASN1_INTEGER_cmp(min, max) > 0) {
                X509V3err(X509V3_F_V2I_ASIDENTIFIERS,
                          X509V3_R_EXTENSION_VALUE_ERROR);
                goto err;
            }
        }
        if (!v3_asid_add_id_or_range(asid, which, min, max)) {
            X509V3err(X509V3_F_V2I_ASIDENTIFIERS, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        min = max = NULL;
    }

    /*
     * Canonize the result, then we're done.
     */
    if (!v3_asid_canonize(asid))
        goto err;
    return asid;

 err:
    ASIdentifiers_free(asid);
    ASN1_INTEGER_free(min);
    ASN1_INTEGER_free(max);
    return NULL;
}

/*
 * OpenSSL dispatch.
 */
const X509V3_EXT_METHOD v3_asid = {
    NID_sbgp_autonomousSysNum,  /* nid */
    0,                          /* flags */
    ASN1_ITEM_ref(ASIdentifiers), /* template */
    0, 0, 0, 0,                 /* old functions, ignored */
    0,                          /* i2s */
    0,                          /* s2i */
    0,                          /* i2v */
    v2i_ASIdentifiers,          /* v2i */
    i2r_ASIdentifiers,          /* i2r */
    0,                          /* r2i */
    NULL                        /* extension-specific data */
};

/*
 * Figure out whether extension uses inheritance.
 */
int v3_asid_inherits(ASIdentifiers *asid)
{
    return (asid != NULL &&
            ((asid->asnum != NULL &&
              asid->asnum->type == ASIdentifierChoice_inherit) ||
             (asid->rdi != NULL &&
              asid->rdi->type == ASIdentifierChoice_inherit)));
}

/*
 * Figure out whether parent contains child.
 */
static int asid_contains(ASIdOrRanges *parent, ASIdOrRanges *child)
{
    ASN1_INTEGER *p_min, *p_max, *c_min, *c_max;
    int p, c;

    if (child == NULL || parent == child)
        return 1;
    if (parent == NULL)
        return 0;

    p = 0;
    for (c = 0; c < sk_ASIdOrRange_num(child); c++) {
        extract_min_max(sk_ASIdOrRange_value(child, c), &c_min, &c_max);
        for (;; p++) {
            if (p >= sk_ASIdOrRange_num(parent))
                return 0;
            extract_min_max(sk_ASIdOrRange_value(parent, p), &p_min, &p_max);
            if (ASN1_INTEGER_cmp(p_max, c_max) < 0)
                continue;
            if (ASN1_INTEGER_cmp(p_min, c_min) > 0)
                return 0;
            break;
        }
    }

    return 1;
}

/*
 * Test whether a is a subet of b.
 */
int v3_asid_subset(ASIdentifiers *a, ASIdentifiers *b)
{
    return (a == NULL ||
            a == b ||
            (b != NULL &&
             !v3_asid_inherits(a) &&
             !v3_asid_inherits(b) &&
             asid_contains(b->asnum->u.asIdsOrRanges,
                           a->asnum->u.asIdsOrRanges) &&
             asid_contains(b->rdi->u.asIdsOrRanges,
                           a->rdi->u.asIdsOrRanges)));
}

/*
 * Validation error handling via callback.
 */
# define validation_err(_err_)           \
  do {                                  \
    if (ctx != NULL) {                  \
      ctx->error = _err_;               \
      ctx->error_depth = i;             \
      ctx->current_cert = x;            \
      ret = ctx->verify_cb(0, ctx);     \
    } else {                            \
      ret = 0;                          \
    }                                   \
    if (!ret)                           \
      goto done;                        \
  } while (0)

/*
 * Core code for RFC 3779 3.3 path validation.
 */
static int v3_asid_validate_path_internal(X509_STORE_CTX *ctx,
                                          STACK_OF(X509) *chain,
                                          ASIdentifiers *ext)
{
    ASIdOrRanges *child_as = NULL, *child_rdi = NULL;
    int i, ret = 1, inherit_as = 0, inherit_rdi = 0;
    X509 *x;

    OPENSSL_assert(chain != NULL && sk_X509_num(chain) > 0);
    OPENSSL_assert(ctx != NULL || ext != NULL);
    OPENSSL_assert(ctx == NULL || ctx->verify_cb != NULL);

    /*
     * Figure out where to start.  If we don't have an extension to
     * check, we're done.  Otherwise, check canonical form and
     * set up for walking up the chain.
     */
    if (ext != NULL) {
        i = -1;
        x = NULL;
    } else {
        i = 0;
        x = sk_X509_value(chain, i);
        OPENSSL_assert(x != NULL);
        if ((ext = x->rfc3779_asid) == NULL)
            goto done;
    }
    if (!v3_asid_is_canonical(ext))
        validation_err(X509_V_ERR_INVALID_EXTENSION);
    if (ext->asnum != NULL) {
        switch (ext->asnum->type) {
        case ASIdentifierChoice_inherit:
            inherit_as = 1;
            break;
        case ASIdentifierChoice_asIdsOrRanges:
            child_as = ext->asnum->u.asIdsOrRanges;
            break;
        }
    }
    if (ext->rdi != NULL) {
        switch (ext->rdi->type) {
        case ASIdentifierChoice_inherit:
            inherit_rdi = 1;
            break;
        case ASIdentifierChoice_asIdsOrRanges:
            child_rdi = ext->rdi->u.asIdsOrRanges;
            break;
        }
    }

    /*
     * Now walk up the chain.  Extensions must be in canonical form, no
     * cert may list resources that its parent doesn't list.
     */
    for (i++; i < sk_X509_num(chain); i++) {
        x = sk_X509_value(chain, i);
        OPENSSL_assert(x != NULL);
        if (x->rfc3779_asid == NULL) {
            if (child_as != NULL || child_rdi != NULL)
                validation_err(X509_V_ERR_UNNESTED_RESOURCE);
            continue;
        }
        if (!v3_asid_is_canonical(x->rfc3779_asid))
            validation_err(X509_V_ERR_INVALID_EXTENSION);
        if (x->rfc3779_asid->asnum == NULL && child_as != NULL) {
            validation_err(X509_V_ERR_UNNESTED_RESOURCE);
            child_as = NULL;
            inherit_as = 0;
        }
        if (x->rfc3779_asid->asnum != NULL &&
            x->rfc3779_asid->asnum->type ==
            ASIdentifierChoice_asIdsOrRanges) {
            if (inherit_as
                || asid_contains(x->rfc3779_asid->asnum->u.asIdsOrRanges,
                                 child_as)) {
                child_as = x->rfc3779_asid->asnum->u.asIdsOrRanges;
                inherit_as = 0;
            } else {
                validation_err(X509_V_ERR_UNNESTED_RESOURCE);
            }
        }
        if (x->rfc3779_asid->rdi == NULL && child_rdi != NULL) {
            validation_err(X509_V_ERR_UNNESTED_RESOURCE);
            child_rdi = NULL;
            inherit_rdi = 0;
        }
        if (x->rfc3779_asid->rdi != NULL &&
            x->rfc3779_asid->rdi->type == ASIdentifierChoice_asIdsOrRanges) {
            if (inherit_rdi ||
                asid_contains(x->rfc3779_asid->rdi->u.asIdsOrRanges,
                              child_rdi)) {
                child_rdi = x->rfc3779_asid->rdi->u.asIdsOrRanges;
                inherit_rdi = 0;
            } else {
                validation_err(X509_V_ERR_UNNESTED_RESOURCE);
            }
        }
    }

    /*
     * Trust anchor can't inherit.
     */
    OPENSSL_assert(x != NULL);
    if (x->rfc3779_asid != NULL) {
        if (x->rfc3779_asid->asnum != NULL &&
            x->rfc3779_asid->asnum->type == ASIdentifierChoice_inherit)
            validation_err(X509_V_ERR_UNNESTED_RESOURCE);
        if (x->rfc3779_asid->rdi != NULL &&
            x->rfc3779_asid->rdi->type == ASIdentifierChoice_inherit)
            validation_err(X509_V_ERR_UNNESTED_RESOURCE);
    }

 done:
    return ret;
}

# undef validation_err

/*
 * RFC 3779 3.3 path validation -- called from X509_verify_cert().
 */
int v3_asid_validate_path(X509_STORE_CTX *ctx)
{
    return v3_asid_validate_path_internal(ctx, ctx->chain, NULL);
}

/*
 * RFC 3779 3.3 path validation of an extension.
 * Test whether chain covers extension.
 */
int v3_asid_validate_resource_set(STACK_OF(X509) *chain,
                                  ASIdentifiers *ext, int allow_inheritance)
{
    if (ext == NULL)
        return 1;
    if (chain == NULL || sk_X509_num(chain) == 0)
        return 0;
    if (!allow_inheritance && v3_asid_inherits(ext))
        return 0;
    return v3_asid_validate_path_internal(NULL, chain, ext);
}

#endif                          /* OPENSSL_NO_RFC3779 */
/* v3_bcons.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 1999.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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
// #include "asn1.h"
// #include "asn1t.h"
// #include "conf.h"
// #include "x509v3.h"

static STACK_OF(CONF_VALUE) *i2v_BASIC_CONSTRAINTS(X509V3_EXT_METHOD *method,
                                                   BASIC_CONSTRAINTS *bcons,
                                                   STACK_OF(CONF_VALUE)
                                                   *extlist);
static BASIC_CONSTRAINTS *v2i_BASIC_CONSTRAINTS(X509V3_EXT_METHOD *method,
                                                X509V3_CTX *ctx,
                                                STACK_OF(CONF_VALUE) *values);

const X509V3_EXT_METHOD v3_bcons = {
    NID_basic_constraints, 0,
    ASN1_ITEM_ref(BASIC_CONSTRAINTS),
    0, 0, 0, 0,
    0, 0,
    (X509V3_EXT_I2V) i2v_BASIC_CONSTRAINTS,
    (X509V3_EXT_V2I)v2i_BASIC_CONSTRAINTS,
    NULL, NULL,
    NULL
};

ASN1_SEQUENCE(BASIC_CONSTRAINTS) = {
        ASN1_OPT(BASIC_CONSTRAINTS, ca, ASN1_FBOOLEAN),
        ASN1_OPT(BASIC_CONSTRAINTS, pathlen, ASN1_INTEGER)
} ASN1_SEQUENCE_END(BASIC_CONSTRAINTS)

IMPLEMENT_ASN1_FUNCTIONS(BASIC_CONSTRAINTS)

static STACK_OF(CONF_VALUE) *i2v_BASIC_CONSTRAINTS(X509V3_EXT_METHOD *method,
                                                   BASIC_CONSTRAINTS *bcons,
                                                   STACK_OF(CONF_VALUE)
                                                   *extlist)
{
    X509V3_add_value_bool("CA", bcons->ca, &extlist);
    X509V3_add_value_int("pathlen", bcons->pathlen, &extlist);
    return extlist;
}

static BASIC_CONSTRAINTS *v2i_BASIC_CONSTRAINTS(X509V3_EXT_METHOD *method,
                                                X509V3_CTX *ctx,
                                                STACK_OF(CONF_VALUE) *values)
{
    BASIC_CONSTRAINTS *bcons = NULL;
    CONF_VALUE *val;
    int i;
    if (!(bcons = BASIC_CONSTRAINTS_new())) {
        X509V3err(X509V3_F_V2I_BASIC_CONSTRAINTS, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    for (i = 0; i < sk_CONF_VALUE_num(values); i++) {
        val = sk_CONF_VALUE_value(values, i);
        if (!strcmp(val->name, "CA")) {
            if (!X509V3_get_value_bool(val, &bcons->ca))
                goto err;
        } else if (!strcmp(val->name, "pathlen")) {
            if (!X509V3_get_value_int(val, &bcons->pathlen))
                goto err;
        } else {
            X509V3err(X509V3_F_V2I_BASIC_CONSTRAINTS, X509V3_R_INVALID_NAME);
            X509V3_conf_err(val);
            goto err;
        }
    }
    return bcons;
 err:
    BASIC_CONSTRAINTS_free(bcons);
    return NULL;
}
/* v3_bitst.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 1999.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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
// #include "conf.h"
// #include "x509v3.h"

static BIT_STRING_BITNAME ns_cert_type_table[] = {
    {0, "SSL Client", "client"},
    {1, "SSL Server", "server"},
    {2, "S/MIME", "email"},
    {3, "Object Signing", "objsign"},
    {4, "Unused", "reserved"},
    {5, "SSL CA", "sslCA"},
    {6, "S/MIME CA", "emailCA"},
    {7, "Object Signing CA", "objCA"},
    {-1, NULL, NULL}
};

static BIT_STRING_BITNAME key_usage_type_table[] = {
    {0, "Digital Signature", "digitalSignature"},
    {1, "Non Repudiation", "nonRepudiation"},
    {2, "Key Encipherment", "keyEncipherment"},
    {3, "Data Encipherment", "dataEncipherment"},
    {4, "Key Agreement", "keyAgreement"},
    {5, "Certificate Sign", "keyCertSign"},
    {6, "CRL Sign", "cRLSign"},
    {7, "Encipher Only", "encipherOnly"},
    {8, "Decipher Only", "decipherOnly"},
    {-1, NULL, NULL}
};

const X509V3_EXT_METHOD v3_nscert =
EXT_BITSTRING(NID_netscape_cert_type, ns_cert_type_table);
const X509V3_EXT_METHOD v3_key_usage =
EXT_BITSTRING(NID_key_usage, key_usage_type_table);

STACK_OF(CONF_VALUE) *i2v_ASN1_BIT_STRING(X509V3_EXT_METHOD *method,
                                          ASN1_BIT_STRING *bits,
                                          STACK_OF(CONF_VALUE) *ret)
{
    BIT_STRING_BITNAME *bnam;
    for (bnam = method->usr_data; bnam->lname; bnam++) {
        if (ASN1_BIT_STRING_get_bit(bits, bnam->bitnum))
            X509V3_add_value(bnam->lname, NULL, &ret);
    }
    return ret;
}

ASN1_BIT_STRING *v2i_ASN1_BIT_STRING(X509V3_EXT_METHOD *method,
                                     X509V3_CTX *ctx,
                                     STACK_OF(CONF_VALUE) *nval)
{
    CONF_VALUE *val;
    ASN1_BIT_STRING *bs;
    int i;
    BIT_STRING_BITNAME *bnam;
    if (!(bs = M_ASN1_BIT_STRING_new())) {
        X509V3err(X509V3_F_V2I_ASN1_BIT_STRING, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    for (i = 0; i < sk_CONF_VALUE_num(nval); i++) {
        val = sk_CONF_VALUE_value(nval, i);
        for (bnam = method->usr_data; bnam->lname; bnam++) {
            if (!strcmp(bnam->sname, val->name) ||
                !strcmp(bnam->lname, val->name)) {
                if (!ASN1_BIT_STRING_set_bit(bs, bnam->bitnum, 1)) {
                    X509V3err(X509V3_F_V2I_ASN1_BIT_STRING,
                              ERR_R_MALLOC_FAILURE);
                    M_ASN1_BIT_STRING_free(bs);
                    return NULL;
                }
                break;
            }
        }
        if (!bnam->lname) {
            X509V3err(X509V3_F_V2I_ASN1_BIT_STRING,
                      X509V3_R_UNKNOWN_BIT_STRING_ARGUMENT);
            X509V3_conf_err(val);
            M_ASN1_BIT_STRING_free(bs);
            return NULL;
        }
    }
    return bs;
}
/* v3_conf.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 1999.
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
/* extension creation utilities */

#include <stdio.h>
#include <ctype.h>
// #include "cryptlib.h"
// #include "conf.h"
// #include "x509.h"
// #include "x509v3.h"

static int v3_check_critical(char **value);
static int v3_check_generic(char **value);
static X509_EXTENSION *do_ext_nconf(CONF *conf, X509V3_CTX *ctx, int ext_nid,
                                    int crit, char *value);
static X509_EXTENSION *v3_generic_extension(const char *ext, char *value,
                                            int crit, int type,
                                            X509V3_CTX *ctx);
static char *conf_lhash_get_string(void *db, char *section, char *value);
static STACK_OF(CONF_VALUE) *conf_lhash_get_section(void *db, char *section);
static X509_EXTENSION *do_ext_i2d(const X509V3_EXT_METHOD *method,
                                  int ext_nid, int crit, void *ext_struc);
static unsigned char *generic_asn1(char *value, X509V3_CTX *ctx,
                                   long *ext_len);
/* CONF *conf:  Config file    */
/* char *name:  Name    */
/* char *value:  Value    */
X509_EXTENSION *X509V3_EXT_nconf(CONF *conf, X509V3_CTX *ctx, char *name,
                                 char *value)
{
    int crit;
    int ext_type;
    X509_EXTENSION *ret;
    crit = v3_check_critical(&value);
    if ((ext_type = v3_check_generic(&value)))
        return v3_generic_extension(name, value, crit, ext_type, ctx);
    ret = do_ext_nconf(conf, ctx, OBJ_sn2nid(name), crit, value);
    if (!ret) {
        X509V3err(X509V3_F_X509V3_EXT_NCONF, X509V3_R_ERROR_IN_EXTENSION);
        ERR_add_error_data(4, "name=", name, ", value=", value);
    }
    return ret;
}

/* CONF *conf:  Config file    */
/* char *value:  Value    */
X509_EXTENSION *X509V3_EXT_nconf_nid(CONF *conf, X509V3_CTX *ctx, int ext_nid,
                                     char *value)
{
    int crit;
    int ext_type;
    crit = v3_check_critical(&value);
    if ((ext_type = v3_check_generic(&value)))
        return v3_generic_extension(OBJ_nid2sn(ext_nid),
                                    value, crit, ext_type, ctx);
    return do_ext_nconf(conf, ctx, ext_nid, crit, value);
}

/* CONF *conf:  Config file    */
/* char *value:  Value    */
static X509_EXTENSION *do_ext_nconf(CONF *conf, X509V3_CTX *ctx, int ext_nid,
                                    int crit, char *value)
{
    const X509V3_EXT_METHOD *method;
    X509_EXTENSION *ext;
    STACK_OF(CONF_VALUE) *nval;
    void *ext_struc;
    if (ext_nid == NID_undef) {
        X509V3err(X509V3_F_DO_EXT_NCONF, X509V3_R_UNKNOWN_EXTENSION_NAME);
        return NULL;
    }
    if (!(method = X509V3_EXT_get_nid(ext_nid))) {
        X509V3err(X509V3_F_DO_EXT_NCONF, X509V3_R_UNKNOWN_EXTENSION);
        return NULL;
    }
    /* Now get internal extension representation based on type */
    if (method->v2i) {
        if (*value == '@')
            nval = NCONF_get_section(conf, value + 1);
        else
            nval = X509V3_parse_list(value);
        if (nval == NULL || sk_CONF_VALUE_num(nval) <= 0) {
            X509V3err(X509V3_F_DO_EXT_NCONF,
                      X509V3_R_INVALID_EXTENSION_STRING);
            ERR_add_error_data(4, "name=", OBJ_nid2sn(ext_nid), ",section=",
                               value);
            if (*value != '@')
                sk_CONF_VALUE_free(nval);
            return NULL;
        }
        ext_struc = method->v2i(method, ctx, nval);
        if (*value != '@')
            sk_CONF_VALUE_pop_free(nval, X509V3_conf_free);
        if (!ext_struc)
            return NULL;
    } else if (method->s2i) {
        if (!(ext_struc = method->s2i(method, ctx, value)))
            return NULL;
    } else if (method->r2i) {
        if (!ctx->db || !ctx->db_meth) {
            X509V3err(X509V3_F_DO_EXT_NCONF, X509V3_R_NO_CONFIG_DATABASE);
            return NULL;
        }
        if (!(ext_struc = method->r2i(method, ctx, value)))
            return NULL;
    } else {
        X509V3err(X509V3_F_DO_EXT_NCONF,
                  X509V3_R_EXTENSION_SETTING_NOT_SUPPORTED);
        ERR_add_error_data(2, "name=", OBJ_nid2sn(ext_nid));
        return NULL;
    }

    ext = do_ext_i2d(method, ext_nid, crit, ext_struc);
    if (method->it)
        ASN1_item_free(ext_struc, ASN1_ITEM_ptr(method->it));
    else
        method->ext_free(ext_struc);
    return ext;

}

static X509_EXTENSION *do_ext_i2d(const X509V3_EXT_METHOD *method,
                                  int ext_nid, int crit, void *ext_struc)
{
    unsigned char *ext_der;
    int ext_len;
    ASN1_OCTET_STRING *ext_oct;
    X509_EXTENSION *ext;
    /* Convert internal representation to DER */
    if (method->it) {
        ext_der = NULL;
        ext_len =
            ASN1_item_i2d(ext_struc, &ext_der, ASN1_ITEM_ptr(method->it));
        if (ext_len < 0)
            goto merr;
    } else {
        unsigned char *p;
        ext_len = method->i2d(ext_struc, NULL);
        if (!(ext_der = OPENSSL_malloc(ext_len)))
            goto merr;
        p = ext_der;
        method->i2d(ext_struc, &p);
    }
    if (!(ext_oct = M_ASN1_OCTET_STRING_new()))
        goto merr;
    ext_oct->data = ext_der;
    ext_oct->length = ext_len;

    ext = X509_EXTENSION_create_by_NID(NULL, ext_nid, crit, ext_oct);
    if (!ext)
        goto merr;
    M_ASN1_OCTET_STRING_free(ext_oct);

    return ext;

 merr:
    X509V3err(X509V3_F_DO_EXT_I2D, ERR_R_MALLOC_FAILURE);
    return NULL;

}

/* Given an internal structure, nid and critical flag create an extension */

X509_EXTENSION *X509V3_EXT_i2d(int ext_nid, int crit, void *ext_struc)
{
    const X509V3_EXT_METHOD *method;
    if (!(method = X509V3_EXT_get_nid(ext_nid))) {
        X509V3err(X509V3_F_X509V3_EXT_I2D, X509V3_R_UNKNOWN_EXTENSION);
        return NULL;
    }
    return do_ext_i2d(method, ext_nid, crit, ext_struc);
}

/* Check the extension string for critical flag */
static int v3_check_critical(char **value)
{
    char *p = *value;
    if ((strlen(p) < 9) || strncmp(p, "critical,", 9))
        return 0;
    p += 9;
    while (isspace((unsigned char)*p))
        p++;
    *value = p;
    return 1;
}

/* Check extension string for generic extension and return the type */
static int v3_check_generic(char **value)
{
    int gen_type = 0;
    char *p = *value;
    if ((strlen(p) >= 4) && !strncmp(p, "DER:", 4)) {
        p += 4;
        gen_type = 1;
    } else if ((strlen(p) >= 5) && !strncmp(p, "ASN1:", 5)) {
        p += 5;
        gen_type = 2;
    } else
        return 0;

    while (isspace((unsigned char)*p))
        p++;
    *value = p;
    return gen_type;
}

/* Create a generic extension: for now just handle DER type */
static X509_EXTENSION *v3_generic_extension(const char *ext, char *value,
                                            int crit, int gen_type,
                                            X509V3_CTX *ctx)
{
    unsigned char *ext_der = NULL;
    long ext_len;
    ASN1_OBJECT *obj = NULL;
    ASN1_OCTET_STRING *oct = NULL;
    X509_EXTENSION *extension = NULL;
    if (!(obj = OBJ_txt2obj(ext, 0))) {
        X509V3err(X509V3_F_V3_GENERIC_EXTENSION,
                  X509V3_R_EXTENSION_NAME_ERROR);
        ERR_add_error_data(2, "name=", ext);
        goto err;
    }

    if (gen_type == 1)
        ext_der = string_to_hex(value, &ext_len);
    else if (gen_type == 2)
        ext_der = generic_asn1(value, ctx, &ext_len);

    if (ext_der == NULL) {
        X509V3err(X509V3_F_V3_GENERIC_EXTENSION,
                  X509V3_R_EXTENSION_VALUE_ERROR);
        ERR_add_error_data(2, "value=", value);
        goto err;
    }

    if (!(oct = M_ASN1_OCTET_STRING_new())) {
        X509V3err(X509V3_F_V3_GENERIC_EXTENSION, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    oct->data = ext_der;
    oct->length = ext_len;
    ext_der = NULL;

    extension = X509_EXTENSION_create_by_OBJ(NULL, obj, crit, oct);

 err:
    ASN1_OBJECT_free(obj);
    M_ASN1_OCTET_STRING_free(oct);
    if (ext_der)
        OPENSSL_free(ext_der);
    return extension;

}

static unsigned char *generic_asn1(char *value, X509V3_CTX *ctx,
                                   long *ext_len)
{
    ASN1_TYPE *typ;
    unsigned char *ext_der = NULL;
    typ = ASN1_generate_v3(value, ctx);
    if (typ == NULL)
        return NULL;
    *ext_len = i2d_ASN1_TYPE(typ, &ext_der);
    ASN1_TYPE_free(typ);
    return ext_der;
}

/*
 * This is the main function: add a bunch of extensions based on a config
 * file section to an extension STACK.
 */

int X509V3_EXT_add_nconf_sk(CONF *conf, X509V3_CTX *ctx, char *section,
                            STACK_OF(X509_EXTENSION) **sk)
{
    X509_EXTENSION *ext;
    STACK_OF(CONF_VALUE) *nval;
    CONF_VALUE *val;
    int i;
    if (!(nval = NCONF_get_section(conf, section)))
        return 0;
    for (i = 0; i < sk_CONF_VALUE_num(nval); i++) {
        val = sk_CONF_VALUE_value(nval, i);
        if (!(ext = X509V3_EXT_nconf(conf, ctx, val->name, val->value)))
            return 0;
        if (sk != NULL) {
            if (X509v3_add_ext(sk, ext, -1) == NULL) {
                X509_EXTENSION_free(ext);
                return 0;
            }
        }
        X509_EXTENSION_free(ext);
    }
    return 1;
}

/*
 * Convenience functions to add extensions to a certificate, CRL and request
 */

int X509V3_EXT_add_nconf(CONF *conf, X509V3_CTX *ctx, char *section,
                         X509 *cert)
{
    STACK_OF(X509_EXTENSION) **sk = NULL;
    if (cert)
        sk = &cert->cert_info->extensions;
    return X509V3_EXT_add_nconf_sk(conf, ctx, section, sk);
}

/* Same as above but for a CRL */

int X509V3_EXT_CRL_add_nconf(CONF *conf, X509V3_CTX *ctx, char *section,
                             X509_CRL *crl)
{
    STACK_OF(X509_EXTENSION) **sk = NULL;
    if (crl)
        sk = &crl->crl->extensions;
    return X509V3_EXT_add_nconf_sk(conf, ctx, section, sk);
}

/* Add extensions to certificate request */

int X509V3_EXT_REQ_add_nconf(CONF *conf, X509V3_CTX *ctx, char *section,
                             X509_REQ *req)
{
    STACK_OF(X509_EXTENSION) *extlist = NULL, **sk = NULL;
    int i;
    if (req)
        sk = &extlist;
    i = X509V3_EXT_add_nconf_sk(conf, ctx, section, sk);
    if (!i || !sk)
        return i;
    i = X509_REQ_add_extensions(req, extlist);
    sk_X509_EXTENSION_pop_free(extlist, X509_EXTENSION_free);
    return i;
}

/* Config database functions */

char *X509V3_get_string(X509V3_CTX *ctx, char *name, char *section)
{
    if (!ctx->db || !ctx->db_meth || !ctx->db_meth->get_string) {
        X509V3err(X509V3_F_X509V3_GET_STRING, X509V3_R_OPERATION_NOT_DEFINED);
        return NULL;
    }
    if (ctx->db_meth->get_string)
        return ctx->db_meth->get_string(ctx->db, name, section);
    return NULL;
}

STACK_OF(CONF_VALUE) *X509V3_get_section(X509V3_CTX *ctx, char *section)
{
    if (!ctx->db || !ctx->db_meth || !ctx->db_meth->get_section) {
        X509V3err(X509V3_F_X509V3_GET_SECTION,
                  X509V3_R_OPERATION_NOT_DEFINED);
        return NULL;
    }
    if (ctx->db_meth->get_section)
        return ctx->db_meth->get_section(ctx->db, section);
    return NULL;
}

void X509V3_string_free(X509V3_CTX *ctx, char *str)
{
    if (!str)
        return;
    if (ctx->db_meth->free_string)
        ctx->db_meth->free_string(ctx->db, str);
}

void X509V3_section_free(X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *section)
{
    if (!section)
        return;
    if (ctx->db_meth->free_section)
        ctx->db_meth->free_section(ctx->db, section);
}

static char *nconf_get_string(void *db, char *section, char *value)
{
    return NCONF_get_string(db, section, value);
}

static STACK_OF(CONF_VALUE) *nconf_get_section(void *db, char *section)
{
    return NCONF_get_section(db, section);
}

static X509V3_CONF_METHOD nconf_method = {
    nconf_get_string,
    nconf_get_section,
    NULL,
    NULL
};

void X509V3_set_nconf(X509V3_CTX *ctx, CONF *conf)
{
    ctx->db_meth = &nconf_method;
    ctx->db = conf;
}

void X509V3_set_ctx(X509V3_CTX *ctx, X509 *issuer, X509 *subj, X509_REQ *req,
                    X509_CRL *crl, int flags)
{
    ctx->issuer_cert = issuer;
    ctx->subject_cert = subj;
    ctx->crl = crl;
    ctx->subject_req = req;
    ctx->flags = flags;
}

/* Old conf compatibility functions */

X509_EXTENSION *X509V3_EXT_conf(LHASH_OF(CONF_VALUE) *conf, X509V3_CTX *ctx,
                                char *name, char *value)
{
    CONF ctmp;
    CONF_set_nconf(&ctmp, conf);
    return X509V3_EXT_nconf(&ctmp, ctx, name, value);
}

/* LHASH *conf:  Config file    */
/* char *value:  Value    */
X509_EXTENSION *X509V3_EXT_conf_nid(LHASH_OF(CONF_VALUE) *conf,
                                    X509V3_CTX *ctx, int ext_nid, char *value)
{
    CONF ctmp;
    CONF_set_nconf(&ctmp, conf);
    return X509V3_EXT_nconf_nid(&ctmp, ctx, ext_nid, value);
}

static char *conf_lhash_get_string(void *db, char *section, char *value)
{
    return CONF_get_string(db, section, value);
}

static STACK_OF(CONF_VALUE) *conf_lhash_get_section(void *db, char *section)
{
    return CONF_get_section(db, section);
}

static X509V3_CONF_METHOD conf_lhash_method = {
    conf_lhash_get_string,
    conf_lhash_get_section,
    NULL,
    NULL
};

void X509V3_set_conf_lhash(X509V3_CTX *ctx, LHASH_OF(CONF_VALUE) *lhash)
{
    ctx->db_meth = &conf_lhash_method;
    ctx->db = lhash;
}

int X509V3_EXT_add_conf(LHASH_OF(CONF_VALUE) *conf, X509V3_CTX *ctx,
                        char *section, X509 *cert)
{
    CONF ctmp;
    CONF_set_nconf(&ctmp, conf);
    return X509V3_EXT_add_nconf(&ctmp, ctx, section, cert);
}

/* Same as above but for a CRL */

int X509V3_EXT_CRL_add_conf(LHASH_OF(CONF_VALUE) *conf, X509V3_CTX *ctx,
                            char *section, X509_CRL *crl)
{
    CONF ctmp;
    CONF_set_nconf(&ctmp, conf);
    return X509V3_EXT_CRL_add_nconf(&ctmp, ctx, section, crl);
}

/* Add extensions to certificate request */

int X509V3_EXT_REQ_add_conf(LHASH_OF(CONF_VALUE) *conf, X509V3_CTX *ctx,
                            char *section, X509_REQ *req)
{
    CONF ctmp;
    CONF_set_nconf(&ctmp, conf);
    return X509V3_EXT_REQ_add_nconf(&ctmp, ctx, section, req);
}
/* v3_cpols.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 1999.
 */
/* ====================================================================
 * Copyright (c) 1999-2004 The OpenSSL Project.  All rights reserved.
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
// #include "conf.h"
// #include "asn1.h"
// #include "asn1t.h"
// #include "x509v3.h"

#include "pcy_int.h"

/* Certificate policies extension support: this one is a bit complex... */

static int i2r_certpol(X509V3_EXT_METHOD *method, STACK_OF(POLICYINFO) *pol,
                       BIO *out, int indent);
static STACK_OF(POLICYINFO) *r2i_certpol(X509V3_EXT_METHOD *method,
                                         X509V3_CTX *ctx, char *value);
static void print_qualifiers(BIO *out, STACK_OF(POLICYQUALINFO) *quals,
                             int indent);
static void print_notice(BIO *out, USERNOTICE *notice, int indent);
static POLICYINFO *policy_section(X509V3_CTX *ctx,
                                  STACK_OF(CONF_VALUE) *polstrs, int ia5org);
static POLICYQUALINFO *notice_section(X509V3_CTX *ctx,
                                      STACK_OF(CONF_VALUE) *unot, int ia5org);
static int nref_nos(STACK_OF(ASN1_INTEGER) *nnums, STACK_OF(CONF_VALUE) *nos);

const X509V3_EXT_METHOD v3_cpols = {
    NID_certificate_policies, 0, ASN1_ITEM_ref(CERTIFICATEPOLICIES),
    0, 0, 0, 0,
    0, 0,
    0, 0,
    (X509V3_EXT_I2R)i2r_certpol,
    (X509V3_EXT_R2I)r2i_certpol,
    NULL
};

ASN1_ITEM_TEMPLATE(CERTIFICATEPOLICIES) =
        ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, CERTIFICATEPOLICIES, POLICYINFO)
ASN1_ITEM_TEMPLATE_END(CERTIFICATEPOLICIES)

IMPLEMENT_ASN1_FUNCTIONS(CERTIFICATEPOLICIES)

ASN1_SEQUENCE(POLICYINFO) = {
        ASN1_SIMPLE(POLICYINFO, policyid, ASN1_OBJECT),
        ASN1_SEQUENCE_OF_OPT(POLICYINFO, qualifiers, POLICYQUALINFO)
} ASN1_SEQUENCE_END(POLICYINFO)

IMPLEMENT_ASN1_FUNCTIONS(POLICYINFO)

ASN1_ADB_TEMPLATE(policydefault) = ASN1_SIMPLE(POLICYQUALINFO, d.other, ASN1_ANY);

ASN1_ADB(POLICYQUALINFO) = {
        ADB_ENTRY(NID_id_qt_cps, ASN1_SIMPLE(POLICYQUALINFO, d.cpsuri, ASN1_IA5STRING)),
        ADB_ENTRY(NID_id_qt_unotice, ASN1_SIMPLE(POLICYQUALINFO, d.usernotice, USERNOTICE))
} ASN1_ADB_END(POLICYQUALINFO, 0, pqualid, 0, &policydefault_tt, NULL);

ASN1_SEQUENCE(POLICYQUALINFO) = {
        ASN1_SIMPLE(POLICYQUALINFO, pqualid, ASN1_OBJECT),
        ASN1_ADB_OBJECT(POLICYQUALINFO)
} ASN1_SEQUENCE_END(POLICYQUALINFO)

IMPLEMENT_ASN1_FUNCTIONS(POLICYQUALINFO)

ASN1_SEQUENCE(USERNOTICE) = {
        ASN1_OPT(USERNOTICE, noticeref, NOTICEREF),
        ASN1_OPT(USERNOTICE, exptext, DISPLAYTEXT)
} ASN1_SEQUENCE_END(USERNOTICE)

IMPLEMENT_ASN1_FUNCTIONS(USERNOTICE)

ASN1_SEQUENCE(NOTICEREF) = {
        ASN1_SIMPLE(NOTICEREF, organization, DISPLAYTEXT),
        ASN1_SEQUENCE_OF(NOTICEREF, noticenos, ASN1_INTEGER)
} ASN1_SEQUENCE_END(NOTICEREF)

IMPLEMENT_ASN1_FUNCTIONS(NOTICEREF)

static STACK_OF(POLICYINFO) *r2i_certpol(X509V3_EXT_METHOD *method,
                                         X509V3_CTX *ctx, char *value)
{
    STACK_OF(POLICYINFO) *pols = NULL;
    char *pstr;
    POLICYINFO *pol;
    ASN1_OBJECT *pobj;
    STACK_OF(CONF_VALUE) *vals;
    CONF_VALUE *cnf;
    int i, ia5org;
    pols = sk_POLICYINFO_new_null();
    if (pols == NULL) {
        X509V3err(X509V3_F_R2I_CERTPOL, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    vals = X509V3_parse_list(value);
    if (vals == NULL) {
        X509V3err(X509V3_F_R2I_CERTPOL, ERR_R_X509V3_LIB);
        goto err;
    }
    ia5org = 0;
    for (i = 0; i < sk_CONF_VALUE_num(vals); i++) {
        cnf = sk_CONF_VALUE_value(vals, i);
        if (cnf->value || !cnf->name) {
            X509V3err(X509V3_F_R2I_CERTPOL,
                      X509V3_R_INVALID_POLICY_IDENTIFIER);
            X509V3_conf_err(cnf);
            goto err;
        }
        pstr = cnf->name;
        if (!strcmp(pstr, "ia5org")) {
            ia5org = 1;
            continue;
        } else if (*pstr == '@') {
            STACK_OF(CONF_VALUE) *polsect;
            polsect = X509V3_get_section(ctx, pstr + 1);
            if (!polsect) {
                X509V3err(X509V3_F_R2I_CERTPOL, X509V3_R_INVALID_SECTION);

                X509V3_conf_err(cnf);
                goto err;
            }
            pol = policy_section(ctx, polsect, ia5org);
            X509V3_section_free(ctx, polsect);
            if (!pol)
                goto err;
        } else {
            if (!(pobj = OBJ_txt2obj(cnf->name, 0))) {
                X509V3err(X509V3_F_R2I_CERTPOL,
                          X509V3_R_INVALID_OBJECT_IDENTIFIER);
                X509V3_conf_err(cnf);
                goto err;
            }
            pol = POLICYINFO_new();
            if (pol == NULL) {
                X509V3err(X509V3_F_R2I_CERTPOL, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            pol->policyid = pobj;
        }
        if (!sk_POLICYINFO_push(pols, pol)) {
            POLICYINFO_free(pol);
            X509V3err(X509V3_F_R2I_CERTPOL, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    }
    sk_CONF_VALUE_pop_free(vals, X509V3_conf_free);
    return pols;
 err:
    sk_CONF_VALUE_pop_free(vals, X509V3_conf_free);
    sk_POLICYINFO_pop_free(pols, POLICYINFO_free);
    return NULL;
}

static POLICYINFO *policy_section(X509V3_CTX *ctx,
                                  STACK_OF(CONF_VALUE) *polstrs, int ia5org)
{
    int i;
    CONF_VALUE *cnf;
    POLICYINFO *pol;
    POLICYQUALINFO *qual;
    if (!(pol = POLICYINFO_new()))
        goto merr;
    for (i = 0; i < sk_CONF_VALUE_num(polstrs); i++) {
        cnf = sk_CONF_VALUE_value(polstrs, i);
        if (!strcmp(cnf->name, "policyIdentifier")) {
            ASN1_OBJECT *pobj;
            if (!(pobj = OBJ_txt2obj(cnf->value, 0))) {
                X509V3err(X509V3_F_POLICY_SECTION,
                          X509V3_R_INVALID_OBJECT_IDENTIFIER);
                X509V3_conf_err(cnf);
                goto err;
            }
            pol->policyid = pobj;

        } else if (!name_cmp(cnf->name, "CPS")) {
            if (!pol->qualifiers)
                pol->qualifiers = sk_POLICYQUALINFO_new_null();
            if (!(qual = POLICYQUALINFO_new()))
                goto merr;
            if (!sk_POLICYQUALINFO_push(pol->qualifiers, qual))
                goto merr;
            if (!(qual->pqualid = OBJ_nid2obj(NID_id_qt_cps))) {
                X509V3err(X509V3_F_POLICY_SECTION, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            if (!(qual->d.cpsuri = M_ASN1_IA5STRING_new()))
                goto merr;
            if (!ASN1_STRING_set(qual->d.cpsuri, cnf->value,
                                 strlen(cnf->value)))
                goto merr;
        } else if (!name_cmp(cnf->name, "userNotice")) {
            STACK_OF(CONF_VALUE) *unot;
            if (*cnf->value != '@') {
                X509V3err(X509V3_F_POLICY_SECTION,
                          X509V3_R_EXPECTED_A_SECTION_NAME);
                X509V3_conf_err(cnf);
                goto err;
            }
            unot = X509V3_get_section(ctx, cnf->value + 1);
            if (!unot) {
                X509V3err(X509V3_F_POLICY_SECTION, X509V3_R_INVALID_SECTION);

                X509V3_conf_err(cnf);
                goto err;
            }
            qual = notice_section(ctx, unot, ia5org);
            X509V3_section_free(ctx, unot);
            if (!qual)
                goto err;
            if (!pol->qualifiers)
                pol->qualifiers = sk_POLICYQUALINFO_new_null();
            if (!sk_POLICYQUALINFO_push(pol->qualifiers, qual))
                goto merr;
        } else {
            X509V3err(X509V3_F_POLICY_SECTION, X509V3_R_INVALID_OPTION);

            X509V3_conf_err(cnf);
            goto err;
        }
    }
    if (!pol->policyid) {
        X509V3err(X509V3_F_POLICY_SECTION, X509V3_R_NO_POLICY_IDENTIFIER);
        goto err;
    }

    return pol;

 merr:
    X509V3err(X509V3_F_POLICY_SECTION, ERR_R_MALLOC_FAILURE);

 err:
    POLICYINFO_free(pol);
    return NULL;

}

static POLICYQUALINFO *notice_section(X509V3_CTX *ctx,
                                      STACK_OF(CONF_VALUE) *unot, int ia5org)
{
    int i, ret;
    CONF_VALUE *cnf;
    USERNOTICE *not;
    POLICYQUALINFO *qual;
    if (!(qual = POLICYQUALINFO_new()))
        goto merr;
    if (!(qual->pqualid = OBJ_nid2obj(NID_id_qt_unotice))) {
        X509V3err(X509V3_F_NOTICE_SECTION, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (!(not = USERNOTICE_new()))
        goto merr;
    qual->d.usernotice = not;
    for (i = 0; i < sk_CONF_VALUE_num(unot); i++) {
        cnf = sk_CONF_VALUE_value(unot, i);
        if (!strcmp(cnf->name, "explicitText")) {
            if (!(not->exptext = M_ASN1_VISIBLESTRING_new()))
                goto merr;
            if (!ASN1_STRING_set(not->exptext, cnf->value,
                                 strlen(cnf->value)))
                goto merr;
        } else if (!strcmp(cnf->name, "organization")) {
            NOTICEREF *nref;
            if (!not->noticeref) {
                if (!(nref = NOTICEREF_new()))
                    goto merr;
                not->noticeref = nref;
            } else
                nref = not->noticeref;
            if (ia5org)
                nref->organization->type = V_ASN1_IA5STRING;
            else
                nref->organization->type = V_ASN1_VISIBLESTRING;
            if (!ASN1_STRING_set(nref->organization, cnf->value,
                                 strlen(cnf->value)))
                goto merr;
        } else if (!strcmp(cnf->name, "noticeNumbers")) {
            NOTICEREF *nref;
            STACK_OF(CONF_VALUE) *nos;
            if (!not->noticeref) {
                if (!(nref = NOTICEREF_new()))
                    goto merr;
                not->noticeref = nref;
            } else
                nref = not->noticeref;
            nos = X509V3_parse_list(cnf->value);
            if (!nos || !sk_CONF_VALUE_num(nos)) {
                X509V3err(X509V3_F_NOTICE_SECTION, X509V3_R_INVALID_NUMBERS);
                X509V3_conf_err(cnf);
                goto err;
            }
            ret = nref_nos(nref->noticenos, nos);
            sk_CONF_VALUE_pop_free(nos, X509V3_conf_free);
            if (!ret)
                goto err;
        } else {
            X509V3err(X509V3_F_NOTICE_SECTION, X509V3_R_INVALID_OPTION);
            X509V3_conf_err(cnf);
            goto err;
        }
    }

    if (not->noticeref &&
        (!not->noticeref->noticenos || !not->noticeref->organization)) {
        X509V3err(X509V3_F_NOTICE_SECTION,
                  X509V3_R_NEED_ORGANIZATION_AND_NUMBERS);
        goto err;
    }

    return qual;

 merr:
    X509V3err(X509V3_F_NOTICE_SECTION, ERR_R_MALLOC_FAILURE);

 err:
    POLICYQUALINFO_free(qual);
    return NULL;
}

static int nref_nos(STACK_OF(ASN1_INTEGER) *nnums, STACK_OF(CONF_VALUE) *nos)
{
    CONF_VALUE *cnf;
    ASN1_INTEGER *aint;

    int i;

    for (i = 0; i < sk_CONF_VALUE_num(nos); i++) {
        cnf = sk_CONF_VALUE_value(nos, i);
        if (!(aint = s2i_ASN1_INTEGER(NULL, cnf->name))) {
            X509V3err(X509V3_F_NREF_NOS, X509V3_R_INVALID_NUMBER);
            goto err;
        }
        if (!sk_ASN1_INTEGER_push(nnums, aint))
            goto merr;
    }
    return 1;

 merr:
    ASN1_INTEGER_free(aint);
    X509V3err(X509V3_F_NREF_NOS, ERR_R_MALLOC_FAILURE);

 err:
    return 0;
}

static int i2r_certpol(X509V3_EXT_METHOD *method, STACK_OF(POLICYINFO) *pol,
                       BIO *out, int indent)
{
    int i;
    POLICYINFO *pinfo;
    /* First print out the policy OIDs */
    for (i = 0; i < sk_POLICYINFO_num(pol); i++) {
        pinfo = sk_POLICYINFO_value(pol, i);
        BIO_printf(out, "%*sPolicy: ", indent, "");
        i2a_ASN1_OBJECT(out, pinfo->policyid);
        BIO_puts(out, "\n");
        if (pinfo->qualifiers)
            print_qualifiers(out, pinfo->qualifiers, indent + 2);
    }
    return 1;
}

static void print_qualifiers(BIO *out, STACK_OF(POLICYQUALINFO) *quals,
                             int indent)
{
    POLICYQUALINFO *qualinfo;
    int i;
    for (i = 0; i < sk_POLICYQUALINFO_num(quals); i++) {
        qualinfo = sk_POLICYQUALINFO_value(quals, i);
        switch (OBJ_obj2nid(qualinfo->pqualid)) {
        case NID_id_qt_cps:
            BIO_printf(out, "%*sCPS: %s\n", indent, "",
                       qualinfo->d.cpsuri->data);
            break;

        case NID_id_qt_unotice:
            BIO_printf(out, "%*sUser Notice:\n", indent, "");
            print_notice(out, qualinfo->d.usernotice, indent + 2);
            break;

        default:
            BIO_printf(out, "%*sUnknown Qualifier: ", indent + 2, "");

            i2a_ASN1_OBJECT(out, qualinfo->pqualid);
            BIO_puts(out, "\n");
            break;
        }
    }
}

static void print_notice(BIO *out, USERNOTICE *notice, int indent)
{
    int i;
    if (notice->noticeref) {
        NOTICEREF *ref;
        ref = notice->noticeref;
        BIO_printf(out, "%*sOrganization: %s\n", indent, "",
                   ref->organization->data);
        BIO_printf(out, "%*sNumber%s: ", indent, "",
                   sk_ASN1_INTEGER_num(ref->noticenos) > 1 ? "s" : "");
        for (i = 0; i < sk_ASN1_INTEGER_num(ref->noticenos); i++) {
            ASN1_INTEGER *num;
            char *tmp;
            num = sk_ASN1_INTEGER_value(ref->noticenos, i);
            if (i)
                BIO_puts(out, ", ");
            if (num == NULL)
                BIO_puts(out, "(null)");
            else {
                tmp = i2s_ASN1_INTEGER(NULL, num);
                if (tmp == NULL)
                    return;
                BIO_puts(out, tmp);
                OPENSSL_free(tmp);
            }
        }
        BIO_puts(out, "\n");
    }
    if (notice->exptext)
        BIO_printf(out, "%*sExplicit Text: %s\n", indent, "",
                   notice->exptext->data);
}

void X509_POLICY_NODE_print(BIO *out, X509_POLICY_NODE *node, int indent)
{
    const X509_POLICY_DATA *dat = node->data;

    BIO_printf(out, "%*sPolicy: ", indent, "");

    i2a_ASN1_OBJECT(out, dat->valid_policy);
    BIO_puts(out, "\n");
    BIO_printf(out, "%*s%s\n", indent + 2, "",
               node_data_critical(dat) ? "Critical" : "Non Critical");
    if (dat->qualifier_set)
        print_qualifiers(out, dat->qualifier_set, indent + 2);
    else
        BIO_printf(out, "%*sNo Qualifiers\n", indent + 2, "");
}


IMPLEMENT_STACK_OF(X509_POLICY_NODE)

IMPLEMENT_STACK_OF(X509_POLICY_DATA)
/* v3_crld.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 1999.
 */
/* ====================================================================
 * Copyright (c) 1999-2008 The OpenSSL Project.  All rights reserved.
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
// #include "conf.h"
// #include "asn1.h"
// #include "asn1t.h"
// #include "x509v3.h"

static void *v2i_crld(const X509V3_EXT_METHOD *method,
                      X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval);
static int i2r_crldp(const X509V3_EXT_METHOD *method, void *pcrldp, BIO *out,
                     int indent);

const X509V3_EXT_METHOD v3_crld = {
    NID_crl_distribution_points, 0, ASN1_ITEM_ref(CRL_DIST_POINTS),
    0, 0, 0, 0,
    0, 0,
    0,
    v2i_crld,
    i2r_crldp, 0,
    NULL
};

const X509V3_EXT_METHOD v3_freshest_crl = {
    NID_freshest_crl, 0, ASN1_ITEM_ref(CRL_DIST_POINTS),
    0, 0, 0, 0,
    0, 0,
    0,
    v2i_crld,
    i2r_crldp, 0,
    NULL
};

static STACK_OF(GENERAL_NAME) *gnames_from_sectname(X509V3_CTX *ctx,
                                                    char *sect)
{
    STACK_OF(CONF_VALUE) *gnsect;
    STACK_OF(GENERAL_NAME) *gens;
    if (*sect == '@')
        gnsect = X509V3_get_section(ctx, sect + 1);
    else
        gnsect = X509V3_parse_list(sect);
    if (!gnsect) {
        X509V3err(X509V3_F_GNAMES_FROM_SECTNAME, X509V3_R_SECTION_NOT_FOUND);
        return NULL;
    }
    gens = v2i_GENERAL_NAMES(NULL, ctx, gnsect);
    if (*sect == '@')
        X509V3_section_free(ctx, gnsect);
    else
        sk_CONF_VALUE_pop_free(gnsect, X509V3_conf_free);
    return gens;
}

static int set_dist_point_name(DIST_POINT_NAME **pdp, X509V3_CTX *ctx,
                               CONF_VALUE *cnf)
{
    STACK_OF(GENERAL_NAME) *fnm = NULL;
    STACK_OF(X509_NAME_ENTRY) *rnm = NULL;
    if (!strncmp(cnf->name, "fullname", 9)) {
        fnm = gnames_from_sectname(ctx, cnf->value);
        if (!fnm)
            goto err;
    } else if (!strcmp(cnf->name, "relativename")) {
        int ret;
        STACK_OF(CONF_VALUE) *dnsect;
        X509_NAME *nm;
        nm = X509_NAME_new();
        if (!nm)
            return -1;
        dnsect = X509V3_get_section(ctx, cnf->value);
        if (!dnsect) {
            X509V3err(X509V3_F_SET_DIST_POINT_NAME,
                      X509V3_R_SECTION_NOT_FOUND);
            return -1;
        }
        ret = X509V3_NAME_from_section(nm, dnsect, MBSTRING_ASC);
        X509V3_section_free(ctx, dnsect);
        rnm = nm->entries;
        nm->entries = NULL;
        X509_NAME_free(nm);
        if (!ret || sk_X509_NAME_ENTRY_num(rnm) <= 0)
            goto err;
        /*
         * Since its a name fragment can't have more than one RDNSequence
         */
        if (sk_X509_NAME_ENTRY_value(rnm,
                                     sk_X509_NAME_ENTRY_num(rnm) - 1)->set) {
            X509V3err(X509V3_F_SET_DIST_POINT_NAME,
                      X509V3_R_INVALID_MULTIPLE_RDNS);
            goto err;
        }
    } else
        return 0;

    if (*pdp) {
        X509V3err(X509V3_F_SET_DIST_POINT_NAME,
                  X509V3_R_DISTPOINT_ALREADY_SET);
        goto err;
    }

    *pdp = DIST_POINT_NAME_new();
    if (!*pdp)
        goto err;
    if (fnm) {
        (*pdp)->type = 0;
        (*pdp)->name.fullname = fnm;
    } else {
        (*pdp)->type = 1;
        (*pdp)->name.relativename = rnm;
    }

    return 1;

 err:
    if (fnm)
        sk_GENERAL_NAME_pop_free(fnm, GENERAL_NAME_free);
    if (rnm)
        sk_X509_NAME_ENTRY_pop_free(rnm, X509_NAME_ENTRY_free);
    return -1;
}

static const BIT_STRING_BITNAME reason_flags[] = {
    {0, "Unused", "unused"},
    {1, "Key Compromise", "keyCompromise"},
    {2, "CA Compromise", "CACompromise"},
    {3, "Affiliation Changed", "affiliationChanged"},
    {4, "Superseded", "superseded"},
    {5, "Cessation Of Operation", "cessationOfOperation"},
    {6, "Certificate Hold", "certificateHold"},
    {7, "Privilege Withdrawn", "privilegeWithdrawn"},
    {8, "AA Compromise", "AACompromise"},
    {-1, NULL, NULL}
};

static int set_reasons(ASN1_BIT_STRING **preas, char *value)
{
    STACK_OF(CONF_VALUE) *rsk = NULL;
    const BIT_STRING_BITNAME *pbn;
    const char *bnam;
    int i, ret = 0;
    rsk = X509V3_parse_list(value);
    if (!rsk)
        return 0;
    if (*preas)
        return 0;
    for (i = 0; i < sk_CONF_VALUE_num(rsk); i++) {
        bnam = sk_CONF_VALUE_value(rsk, i)->name;
        if (!*preas) {
            *preas = ASN1_BIT_STRING_new();
            if (!*preas)
                goto err;
        }
        for (pbn = reason_flags; pbn->lname; pbn++) {
            if (!strcmp(pbn->sname, bnam)) {
                if (!ASN1_BIT_STRING_set_bit(*preas, pbn->bitnum, 1))
                    goto err;
                break;
            }
        }
        if (!pbn->lname)
            goto err;
    }
    ret = 1;

 err:
    sk_CONF_VALUE_pop_free(rsk, X509V3_conf_free);
    return ret;
}

static int print_reasons(BIO *out, const char *rname,
                         ASN1_BIT_STRING *rflags, int indent)
{
    int first = 1;
    const BIT_STRING_BITNAME *pbn;
    BIO_printf(out, "%*s%s:\n%*s", indent, "", rname, indent + 2, "");
    for (pbn = reason_flags; pbn->lname; pbn++) {
        if (ASN1_BIT_STRING_get_bit(rflags, pbn->bitnum)) {
            if (first)
                first = 0;
            else
                BIO_puts(out, ", ");
            BIO_puts(out, pbn->lname);
        }
    }
    if (first)
        BIO_puts(out, "<EMPTY>\n");
    else
        BIO_puts(out, "\n");
    return 1;
}

static DIST_POINT *crldp_from_section(X509V3_CTX *ctx,
                                      STACK_OF(CONF_VALUE) *nval)
{
    int i;
    CONF_VALUE *cnf;
    DIST_POINT *point = NULL;
    point = DIST_POINT_new();
    if (!point)
        goto err;
    for (i = 0; i < sk_CONF_VALUE_num(nval); i++) {
        int ret;
        cnf = sk_CONF_VALUE_value(nval, i);
        ret = set_dist_point_name(&point->distpoint, ctx, cnf);
        if (ret > 0)
            continue;
        if (ret < 0)
            goto err;
        if (!strcmp(cnf->name, "reasons")) {
            if (!set_reasons(&point->reasons, cnf->value))
                goto err;
        } else if (!strcmp(cnf->name, "CRLissuer")) {
            point->CRLissuer = gnames_from_sectname(ctx, cnf->value);
            if (!point->CRLissuer)
                goto err;
        }
    }

    return point;

 err:
    if (point)
        DIST_POINT_free(point);
    return NULL;
}

static void *v2i_crld(const X509V3_EXT_METHOD *method,
                      X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval)
{
    STACK_OF(DIST_POINT) *crld = NULL;
    GENERAL_NAMES *gens = NULL;
    GENERAL_NAME *gen = NULL;
    CONF_VALUE *cnf;
    int i;
    if (!(crld = sk_DIST_POINT_new_null()))
        goto merr;
    for (i = 0; i < sk_CONF_VALUE_num(nval); i++) {
        DIST_POINT *point;
        cnf = sk_CONF_VALUE_value(nval, i);
        if (!cnf->value) {
            STACK_OF(CONF_VALUE) *dpsect;
            dpsect = X509V3_get_section(ctx, cnf->name);
            if (!dpsect)
                goto err;
            point = crldp_from_section(ctx, dpsect);
            X509V3_section_free(ctx, dpsect);
            if (!point)
                goto err;
            if (!sk_DIST_POINT_push(crld, point)) {
                DIST_POINT_free(point);
                goto merr;
            }
        } else {
            if (!(gen = v2i_GENERAL_NAME(method, ctx, cnf)))
                goto err;
            if (!(gens = GENERAL_NAMES_new()))
                goto merr;
            if (!sk_GENERAL_NAME_push(gens, gen))
                goto merr;
            gen = NULL;
            if (!(point = DIST_POINT_new()))
                goto merr;
            if (!sk_DIST_POINT_push(crld, point)) {
                DIST_POINT_free(point);
                goto merr;
            }
            if (!(point->distpoint = DIST_POINT_NAME_new()))
                goto merr;
            point->distpoint->name.fullname = gens;
            point->distpoint->type = 0;
            gens = NULL;
        }
    }
    return crld;

 merr:
    X509V3err(X509V3_F_V2I_CRLD, ERR_R_MALLOC_FAILURE);
 err:
    GENERAL_NAME_free(gen);
    GENERAL_NAMES_free(gens);
    sk_DIST_POINT_pop_free(crld, DIST_POINT_free);
    return NULL;
}

IMPLEMENT_STACK_OF(DIST_POINT)

IMPLEMENT_ASN1_SET_OF(DIST_POINT)

static int dpn_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                  void *exarg)
{
    DIST_POINT_NAME *dpn = (DIST_POINT_NAME *)*pval;

    switch (operation) {
    case ASN1_OP_NEW_POST:
        dpn->dpname = NULL;
        break;

    case ASN1_OP_FREE_POST:
        if (dpn->dpname)
            X509_NAME_free(dpn->dpname);
        break;
    }
    return 1;
}


ASN1_CHOICE_cb(DIST_POINT_NAME, dpn_cb) = {
        ASN1_IMP_SEQUENCE_OF(DIST_POINT_NAME, name.fullname, GENERAL_NAME, 0),
        ASN1_IMP_SET_OF(DIST_POINT_NAME, name.relativename, X509_NAME_ENTRY, 1)
} ASN1_CHOICE_END_cb(DIST_POINT_NAME, DIST_POINT_NAME, type)


IMPLEMENT_ASN1_FUNCTIONS(DIST_POINT_NAME)

ASN1_SEQUENCE(DIST_POINT) = {
        ASN1_EXP_OPT(DIST_POINT, distpoint, DIST_POINT_NAME, 0),
        ASN1_IMP_OPT(DIST_POINT, reasons, ASN1_BIT_STRING, 1),
        ASN1_IMP_SEQUENCE_OF_OPT(DIST_POINT, CRLissuer, GENERAL_NAME, 2)
} ASN1_SEQUENCE_END(DIST_POINT)

IMPLEMENT_ASN1_FUNCTIONS(DIST_POINT)

ASN1_ITEM_TEMPLATE(CRL_DIST_POINTS) =
        ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, CRLDistributionPoints, DIST_POINT)
ASN1_ITEM_TEMPLATE_END(CRL_DIST_POINTS)

IMPLEMENT_ASN1_FUNCTIONS(CRL_DIST_POINTS)

ASN1_SEQUENCE(ISSUING_DIST_POINT) = {
        ASN1_EXP_OPT(ISSUING_DIST_POINT, distpoint, DIST_POINT_NAME, 0),
        ASN1_IMP_OPT(ISSUING_DIST_POINT, onlyuser, ASN1_FBOOLEAN, 1),
        ASN1_IMP_OPT(ISSUING_DIST_POINT, onlyCA, ASN1_FBOOLEAN, 2),
        ASN1_IMP_OPT(ISSUING_DIST_POINT, onlysomereasons, ASN1_BIT_STRING, 3),
        ASN1_IMP_OPT(ISSUING_DIST_POINT, indirectCRL, ASN1_FBOOLEAN, 4),
        ASN1_IMP_OPT(ISSUING_DIST_POINT, onlyattr, ASN1_FBOOLEAN, 5)
} ASN1_SEQUENCE_END(ISSUING_DIST_POINT)

IMPLEMENT_ASN1_FUNCTIONS(ISSUING_DIST_POINT)

static int i2r_idp(const X509V3_EXT_METHOD *method, void *pidp, BIO *out,
                   int indent);
static void *v2i_idp(const X509V3_EXT_METHOD *method, X509V3_CTX *ctx,
                     STACK_OF(CONF_VALUE) *nval);

const X509V3_EXT_METHOD v3_idp = {
    NID_issuing_distribution_point, X509V3_EXT_MULTILINE,
    ASN1_ITEM_ref(ISSUING_DIST_POINT),
    0, 0, 0, 0,
    0, 0,
    0,
    v2i_idp,
    i2r_idp, 0,
    NULL
};

static void *v2i_idp(const X509V3_EXT_METHOD *method, X509V3_CTX *ctx,
                     STACK_OF(CONF_VALUE) *nval)
{
    ISSUING_DIST_POINT *idp = NULL;
    CONF_VALUE *cnf;
    char *name, *val;
    int i, ret;
    idp = ISSUING_DIST_POINT_new();
    if (!idp)
        goto merr;
    for (i = 0; i < sk_CONF_VALUE_num(nval); i++) {
        cnf = sk_CONF_VALUE_value(nval, i);
        name = cnf->name;
        val = cnf->value;
        ret = set_dist_point_name(&idp->distpoint, ctx, cnf);
        if (ret > 0)
            continue;
        if (ret < 0)
            goto err;
        if (!strcmp(name, "onlyuser")) {
            if (!X509V3_get_value_bool(cnf, &idp->onlyuser))
                goto err;
        } else if (!strcmp(name, "onlyCA")) {
            if (!X509V3_get_value_bool(cnf, &idp->onlyCA))
                goto err;
        } else if (!strcmp(name, "onlyAA")) {
            if (!X509V3_get_value_bool(cnf, &idp->onlyattr))
                goto err;
        } else if (!strcmp(name, "indirectCRL")) {
            if (!X509V3_get_value_bool(cnf, &idp->indirectCRL))
                goto err;
        } else if (!strcmp(name, "onlysomereasons")) {
            if (!set_reasons(&idp->onlysomereasons, val))
                goto err;
        } else {
            X509V3err(X509V3_F_V2I_IDP, X509V3_R_INVALID_NAME);
            X509V3_conf_err(cnf);
            goto err;
        }
    }
    return idp;

 merr:
    X509V3err(X509V3_F_V2I_IDP, ERR_R_MALLOC_FAILURE);
 err:
    ISSUING_DIST_POINT_free(idp);
    return NULL;
}

static int print_gens(BIO *out, STACK_OF(GENERAL_NAME) *gens, int indent)
{
    int i;
    for (i = 0; i < sk_GENERAL_NAME_num(gens); i++) {
        BIO_printf(out, "%*s", indent + 2, "");
        GENERAL_NAME_print(out, sk_GENERAL_NAME_value(gens, i));
        BIO_puts(out, "\n");
    }
    return 1;
}

static int print_distpoint(BIO *out, DIST_POINT_NAME *dpn, int indent)
{
    if (dpn->type == 0) {
        BIO_printf(out, "%*sFull Name:\n", indent, "");
        print_gens(out, dpn->name.fullname, indent);
    } else {
        X509_NAME ntmp;
        ntmp.entries = dpn->name.relativename;
        BIO_printf(out, "%*sRelative Name:\n%*s", indent, "", indent + 2, "");
        X509_NAME_print_ex(out, &ntmp, 0, XN_FLAG_ONELINE);
        BIO_puts(out, "\n");
    }
    return 1;
}

static int i2r_idp(const X509V3_EXT_METHOD *method, void *pidp, BIO *out,
                   int indent)
{
    ISSUING_DIST_POINT *idp = pidp;
    if (idp->distpoint)
        print_distpoint(out, idp->distpoint, indent);
    if (idp->onlyuser > 0)
        BIO_printf(out, "%*sOnly User Certificates\n", indent, "");
    if (idp->onlyCA > 0)
        BIO_printf(out, "%*sOnly CA Certificates\n", indent, "");
    if (idp->indirectCRL > 0)
        BIO_printf(out, "%*sIndirect CRL\n", indent, "");
    if (idp->onlysomereasons)
        print_reasons(out, "Only Some Reasons", idp->onlysomereasons, indent);
    if (idp->onlyattr > 0)
        BIO_printf(out, "%*sOnly Attribute Certificates\n", indent, "");
    if (!idp->distpoint && (idp->onlyuser <= 0) && (idp->onlyCA <= 0)
        && (idp->indirectCRL <= 0) && !idp->onlysomereasons
        && (idp->onlyattr <= 0))
        BIO_printf(out, "%*s<EMPTY>\n", indent, "");

    return 1;
}

static int i2r_crldp(const X509V3_EXT_METHOD *method, void *pcrldp, BIO *out,
                     int indent)
{
    STACK_OF(DIST_POINT) *crld = pcrldp;
    DIST_POINT *point;
    int i;
    for (i = 0; i < sk_DIST_POINT_num(crld); i++) {
        BIO_puts(out, "\n");
        point = sk_DIST_POINT_value(crld, i);
        if (point->distpoint)
            print_distpoint(out, point->distpoint, indent);
        if (point->reasons)
            print_reasons(out, "Reasons", point->reasons, indent);
        if (point->CRLissuer) {
            BIO_printf(out, "%*sCRL Issuer:\n", indent, "");
            print_gens(out, point->CRLissuer, indent);
        }
    }
    return 1;
}

int DIST_POINT_set_dpname(DIST_POINT_NAME *dpn, X509_NAME *iname)
{
    int i;
    STACK_OF(X509_NAME_ENTRY) *frag;
    X509_NAME_ENTRY *ne;
    if (!dpn || (dpn->type != 1))
        return 1;
    frag = dpn->name.relativename;
    dpn->dpname = X509_NAME_dup(iname);
    if (!dpn->dpname)
        return 0;
    for (i = 0; i < sk_X509_NAME_ENTRY_num(frag); i++) {
        ne = sk_X509_NAME_ENTRY_value(frag, i);
        if (!X509_NAME_add_entry(dpn->dpname, ne, -1, i ? 0 : 1)) {
            X509_NAME_free(dpn->dpname);
            dpn->dpname = NULL;
            return 0;
        }
    }
    /* generate cached encoding of name */
    if (i2d_X509_NAME(dpn->dpname, NULL) < 0) {
        X509_NAME_free(dpn->dpname);
        dpn->dpname = NULL;
        return 0;
    }
    return 1;
}
/* v3_enum.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 1999.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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
// #include "x509v3.h"

static ENUMERATED_NAMES crl_reasons[] = {
    {CRL_REASON_UNSPECIFIED, "Unspecified", "unspecified"},
    {CRL_REASON_KEY_COMPROMISE, "Key Compromise", "keyCompromise"},
    {CRL_REASON_CA_COMPROMISE, "CA Compromise", "CACompromise"},
    {CRL_REASON_AFFILIATION_CHANGED, "Affiliation Changed",
     "affiliationChanged"},
    {CRL_REASON_SUPERSEDED, "Superseded", "superseded"},
    {CRL_REASON_CESSATION_OF_OPERATION,
     "Cessation Of Operation", "cessationOfOperation"},
    {CRL_REASON_CERTIFICATE_HOLD, "Certificate Hold", "certificateHold"},
    {CRL_REASON_REMOVE_FROM_CRL, "Remove From CRL", "removeFromCRL"},
    {CRL_REASON_PRIVILEGE_WITHDRAWN, "Privilege Withdrawn",
     "privilegeWithdrawn"},
    {CRL_REASON_AA_COMPROMISE, "AA Compromise", "AACompromise"},
    {-1, NULL, NULL}
};

const X509V3_EXT_METHOD v3_crl_reason = {
    NID_crl_reason, 0, ASN1_ITEM_ref(ASN1_ENUMERATED),
    0, 0, 0, 0,
    (X509V3_EXT_I2S)i2s_ASN1_ENUMERATED_TABLE,
    0,
    0, 0, 0, 0,
    crl_reasons
};

char *i2s_ASN1_ENUMERATED_TABLE(X509V3_EXT_METHOD *method, ASN1_ENUMERATED *e)
{
    ENUMERATED_NAMES *enam;
    long strval;
    strval = ASN1_ENUMERATED_get(e);
    for (enam = method->usr_data; enam->lname; enam++) {
        if (strval == enam->bitnum)
            return BUF_strdup(enam->lname);
    }
    return i2s_ASN1_ENUMERATED(method, e);
}
/* v3_extku.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 1999.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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
// #include "asn1t.h"
// #include "conf.h"
// #include "x509v3.h"

static void *v2i_EXTENDED_KEY_USAGE(const X509V3_EXT_METHOD *method,
                                    X509V3_CTX *ctx,
                                    STACK_OF(CONF_VALUE) *nval);
static STACK_OF(CONF_VALUE) *i2v_EXTENDED_KEY_USAGE(const X509V3_EXT_METHOD
                                                    *method, void *eku, STACK_OF(CONF_VALUE)
                                                    *extlist);

const X509V3_EXT_METHOD v3_ext_ku = {
    NID_ext_key_usage, 0,
    ASN1_ITEM_ref(EXTENDED_KEY_USAGE),
    0, 0, 0, 0,
    0, 0,
    i2v_EXTENDED_KEY_USAGE,
    v2i_EXTENDED_KEY_USAGE,
    0, 0,
    NULL
};

/* NB OCSP acceptable responses also is a SEQUENCE OF OBJECT */
const X509V3_EXT_METHOD v3_ocsp_accresp = {
    NID_id_pkix_OCSP_acceptableResponses, 0,
    ASN1_ITEM_ref(EXTENDED_KEY_USAGE),
    0, 0, 0, 0,
    0, 0,
    i2v_EXTENDED_KEY_USAGE,
    v2i_EXTENDED_KEY_USAGE,
    0, 0,
    NULL
};

ASN1_ITEM_TEMPLATE(EXTENDED_KEY_USAGE) =
        ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, EXTENDED_KEY_USAGE, ASN1_OBJECT)
ASN1_ITEM_TEMPLATE_END(EXTENDED_KEY_USAGE)

IMPLEMENT_ASN1_FUNCTIONS(EXTENDED_KEY_USAGE)

static STACK_OF(CONF_VALUE) *i2v_EXTENDED_KEY_USAGE(const X509V3_EXT_METHOD
                                                    *method, void *a, STACK_OF(CONF_VALUE)
                                                    *ext_list)
{
    EXTENDED_KEY_USAGE *eku = a;
    int i;
    ASN1_OBJECT *obj;
    char obj_tmp[80];
    for (i = 0; i < sk_ASN1_OBJECT_num(eku); i++) {
        obj = sk_ASN1_OBJECT_value(eku, i);
        i2t_ASN1_OBJECT(obj_tmp, 80, obj);
        X509V3_add_value(NULL, obj_tmp, &ext_list);
    }
    return ext_list;
}

static void *v2i_EXTENDED_KEY_USAGE(const X509V3_EXT_METHOD *method,
                                    X509V3_CTX *ctx,
                                    STACK_OF(CONF_VALUE) *nval)
{
    EXTENDED_KEY_USAGE *extku;
    char *extval;
    ASN1_OBJECT *objtmp;
    CONF_VALUE *val;
    int i;

    if (!(extku = sk_ASN1_OBJECT_new_null())) {
        X509V3err(X509V3_F_V2I_EXTENDED_KEY_USAGE, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    for (i = 0; i < sk_CONF_VALUE_num(nval); i++) {
        val = sk_CONF_VALUE_value(nval, i);
        if (val->value)
            extval = val->value;
        else
            extval = val->name;
        if (!(objtmp = OBJ_txt2obj(extval, 0))) {
            sk_ASN1_OBJECT_pop_free(extku, ASN1_OBJECT_free);
            X509V3err(X509V3_F_V2I_EXTENDED_KEY_USAGE,
                      X509V3_R_INVALID_OBJECT_IDENTIFIER);
            X509V3_conf_err(val);
            return NULL;
        }
        sk_ASN1_OBJECT_push(extku, objtmp);
    }
    return extku;
}
/* v3_genn.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 1999.
 */
/* ====================================================================
 * Copyright (c) 1999-2008 The OpenSSL Project.  All rights reserved.
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
// #include "asn1t.h"
// #include "conf.h"
// #include "x509v3.h"

ASN1_SEQUENCE(OTHERNAME) = {
        ASN1_SIMPLE(OTHERNAME, type_id, ASN1_OBJECT),
        /* Maybe have a true ANY DEFINED BY later */
        ASN1_EXP(OTHERNAME, value, ASN1_ANY, 0)
} ASN1_SEQUENCE_END(OTHERNAME)

IMPLEMENT_ASN1_FUNCTIONS(OTHERNAME)

ASN1_SEQUENCE(EDIPARTYNAME) = {
        ASN1_IMP_OPT(EDIPARTYNAME, nameAssigner, DIRECTORYSTRING, 0),
        ASN1_IMP_OPT(EDIPARTYNAME, partyName, DIRECTORYSTRING, 1)
} ASN1_SEQUENCE_END(EDIPARTYNAME)

IMPLEMENT_ASN1_FUNCTIONS(EDIPARTYNAME)

ASN1_CHOICE(GENERAL_NAME) = {
        ASN1_IMP(GENERAL_NAME, d.otherName, OTHERNAME, GEN_OTHERNAME),
        ASN1_IMP(GENERAL_NAME, d.rfc822Name, ASN1_IA5STRING, GEN_EMAIL),
        ASN1_IMP(GENERAL_NAME, d.dNSName, ASN1_IA5STRING, GEN_DNS),
        /* Don't decode this */
        ASN1_IMP(GENERAL_NAME, d.x400Address, ASN1_SEQUENCE, GEN_X400),
        /* X509_NAME is a CHOICE type so use EXPLICIT */
        ASN1_EXP(GENERAL_NAME, d.directoryName, X509_NAME, GEN_DIRNAME),
        ASN1_IMP(GENERAL_NAME, d.ediPartyName, EDIPARTYNAME, GEN_EDIPARTY),
        ASN1_IMP(GENERAL_NAME, d.uniformResourceIdentifier, ASN1_IA5STRING, GEN_URI),
        ASN1_IMP(GENERAL_NAME, d.iPAddress, ASN1_OCTET_STRING, GEN_IPADD),
        ASN1_IMP(GENERAL_NAME, d.registeredID, ASN1_OBJECT, GEN_RID)
} ASN1_CHOICE_END(GENERAL_NAME)

IMPLEMENT_ASN1_FUNCTIONS(GENERAL_NAME)

ASN1_ITEM_TEMPLATE(GENERAL_NAMES) =
        ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, GeneralNames, GENERAL_NAME)
ASN1_ITEM_TEMPLATE_END(GENERAL_NAMES)

IMPLEMENT_ASN1_FUNCTIONS(GENERAL_NAMES)

GENERAL_NAME *GENERAL_NAME_dup(GENERAL_NAME *a)
{
    return (GENERAL_NAME *)ASN1_dup((i2d_of_void *)i2d_GENERAL_NAME,
                                    (d2i_of_void *)d2i_GENERAL_NAME,
                                    (char *)a);
}

/* Returns 0 if they are equal, != 0 otherwise. */
int GENERAL_NAME_cmp(GENERAL_NAME *a, GENERAL_NAME *b)
{
    int result = -1;

    if (!a || !b || a->type != b->type)
        return -1;
    switch (a->type) {
    case GEN_X400:
    case GEN_EDIPARTY:
        result = ASN1_TYPE_cmp(a->d.other, b->d.other);
        break;

    case GEN_OTHERNAME:
        result = OTHERNAME_cmp(a->d.otherName, b->d.otherName);
        break;

    case GEN_EMAIL:
    case GEN_DNS:
    case GEN_URI:
        result = ASN1_STRING_cmp(a->d.ia5, b->d.ia5);
        break;

    case GEN_DIRNAME:
        result = X509_NAME_cmp(a->d.dirn, b->d.dirn);
        break;

    case GEN_IPADD:
        result = ASN1_OCTET_STRING_cmp(a->d.ip, b->d.ip);
        break;

    case GEN_RID:
        result = OBJ_cmp(a->d.rid, b->d.rid);
        break;
    }
    return result;
}

/* Returns 0 if they are equal, != 0 otherwise. */
int OTHERNAME_cmp(OTHERNAME *a, OTHERNAME *b)
{
    int result = -1;

    if (!a || !b)
        return -1;
    /* Check their type first. */
    if ((result = OBJ_cmp(a->type_id, b->type_id)) != 0)
        return result;
    /* Check the value. */
    result = ASN1_TYPE_cmp(a->value, b->value);
    return result;
}

void GENERAL_NAME_set0_value(GENERAL_NAME *a, int type, void *value)
{
    switch (type) {
    case GEN_X400:
    case GEN_EDIPARTY:
        a->d.other = value;
        break;

    case GEN_OTHERNAME:
        a->d.otherName = value;
        break;

    case GEN_EMAIL:
    case GEN_DNS:
    case GEN_URI:
        a->d.ia5 = value;
        break;

    case GEN_DIRNAME:
        a->d.dirn = value;
        break;

    case GEN_IPADD:
        a->d.ip = value;
        break;

    case GEN_RID:
        a->d.rid = value;
        break;
    }
    a->type = type;
}

void *GENERAL_NAME_get0_value(GENERAL_NAME *a, int *ptype)
{
    if (ptype)
        *ptype = a->type;
    switch (a->type) {
    case GEN_X400:
    case GEN_EDIPARTY:
        return a->d.other;

    case GEN_OTHERNAME:
        return a->d.otherName;

    case GEN_EMAIL:
    case GEN_DNS:
    case GEN_URI:
        return a->d.ia5;

    case GEN_DIRNAME:
        return a->d.dirn;

    case GEN_IPADD:
        return a->d.ip;

    case GEN_RID:
        return a->d.rid;

    default:
        return NULL;
    }
}

int GENERAL_NAME_set0_othername(GENERAL_NAME *gen,
                                ASN1_OBJECT *oid, ASN1_TYPE *value)
{
    OTHERNAME *oth;
    oth = OTHERNAME_new();
    if (!oth)
        return 0;
    ASN1_TYPE_free(oth->value);
    oth->type_id = oid;
    oth->value = value;
    GENERAL_NAME_set0_value(gen, GEN_OTHERNAME, oth);
    return 1;
}

int GENERAL_NAME_get0_otherName(GENERAL_NAME *gen,
                                ASN1_OBJECT **poid, ASN1_TYPE **pvalue)
{
    if (gen->type != GEN_OTHERNAME)
        return 0;
    if (poid)
        *poid = gen->d.otherName->type_id;
    if (pvalue)
        *pvalue = gen->d.otherName->value;
    return 1;
}
/* v3_ia5.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 1999.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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
// #include "asn1.h"
// #include "conf.h"
// #include "x509v3.h"

static char *i2s_ASN1_IA5STRING(X509V3_EXT_METHOD *method,
                                ASN1_IA5STRING *ia5);
static ASN1_IA5STRING *s2i_ASN1_IA5STRING(X509V3_EXT_METHOD *method,
                                          X509V3_CTX *ctx, char *str);
const X509V3_EXT_METHOD v3_ns_ia5_list[] = {
    EXT_IA5STRING(NID_netscape_base_url),
    EXT_IA5STRING(NID_netscape_revocation_url),
    EXT_IA5STRING(NID_netscape_ca_revocation_url),
    EXT_IA5STRING(NID_netscape_renewal_url),
    EXT_IA5STRING(NID_netscape_ca_policy_url),
    EXT_IA5STRING(NID_netscape_ssl_server_name),
    EXT_IA5STRING(NID_netscape_comment),
    EXT_END
};

static char *i2s_ASN1_IA5STRING(X509V3_EXT_METHOD *method,
                                ASN1_IA5STRING *ia5)
{
    char *tmp;
    if (!ia5 || !ia5->length)
        return NULL;
    if (!(tmp = OPENSSL_malloc(ia5->length + 1))) {
        X509V3err(X509V3_F_I2S_ASN1_IA5STRING, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    memcpy(tmp, ia5->data, ia5->length);
    tmp[ia5->length] = 0;
    return tmp;
}

static ASN1_IA5STRING *s2i_ASN1_IA5STRING(X509V3_EXT_METHOD *method,
                                          X509V3_CTX *ctx, char *str)
{
    ASN1_IA5STRING *ia5;
    if (!str) {
        X509V3err(X509V3_F_S2I_ASN1_IA5STRING,
                  X509V3_R_INVALID_NULL_ARGUMENT);
        return NULL;
    }
    if (!(ia5 = M_ASN1_IA5STRING_new()))
        goto err;
    if (!ASN1_STRING_set((ASN1_STRING *)ia5, (unsigned char *)str,
                         strlen(str))) {
        M_ASN1_IA5STRING_free(ia5);
        goto err;
    }
#ifdef CHARSET_EBCDIC
    ebcdic2ascii(ia5->data, ia5->data, ia5->length);
#endif                          /* CHARSET_EBCDIC */
    return ia5;
 err:
    X509V3err(X509V3_F_S2I_ASN1_IA5STRING, ERR_R_MALLOC_FAILURE);
    return NULL;
}
/* v3_info.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 1999.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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
// #include "conf.h"
// #include "asn1.h"
// #include "asn1t.h"
// #include "x509v3.h"

static STACK_OF(CONF_VALUE) *i2v_AUTHORITY_INFO_ACCESS(X509V3_EXT_METHOD
                                                       *method, AUTHORITY_INFO_ACCESS
                                                       *ainfo, STACK_OF(CONF_VALUE)
                                                       *ret);
static AUTHORITY_INFO_ACCESS *v2i_AUTHORITY_INFO_ACCESS(X509V3_EXT_METHOD
                                                        *method,
                                                        X509V3_CTX *ctx,
                                                        STACK_OF(CONF_VALUE)
                                                        *nval);

const X509V3_EXT_METHOD v3_info = { NID_info_access, X509V3_EXT_MULTILINE,
    ASN1_ITEM_ref(AUTHORITY_INFO_ACCESS),
    0, 0, 0, 0,
    0, 0,
    (X509V3_EXT_I2V) i2v_AUTHORITY_INFO_ACCESS,
    (X509V3_EXT_V2I)v2i_AUTHORITY_INFO_ACCESS,
    0, 0,
    NULL
};

const X509V3_EXT_METHOD v3_sinfo = { NID_sinfo_access, X509V3_EXT_MULTILINE,
    ASN1_ITEM_ref(AUTHORITY_INFO_ACCESS),
    0, 0, 0, 0,
    0, 0,
    (X509V3_EXT_I2V) i2v_AUTHORITY_INFO_ACCESS,
    (X509V3_EXT_V2I)v2i_AUTHORITY_INFO_ACCESS,
    0, 0,
    NULL
};

ASN1_SEQUENCE(ACCESS_DESCRIPTION) = {
        ASN1_SIMPLE(ACCESS_DESCRIPTION, method, ASN1_OBJECT),
        ASN1_SIMPLE(ACCESS_DESCRIPTION, location, GENERAL_NAME)
} ASN1_SEQUENCE_END(ACCESS_DESCRIPTION)

IMPLEMENT_ASN1_FUNCTIONS(ACCESS_DESCRIPTION)

ASN1_ITEM_TEMPLATE(AUTHORITY_INFO_ACCESS) =
        ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, GeneralNames, ACCESS_DESCRIPTION)
ASN1_ITEM_TEMPLATE_END(AUTHORITY_INFO_ACCESS)

IMPLEMENT_ASN1_FUNCTIONS(AUTHORITY_INFO_ACCESS)

static STACK_OF(CONF_VALUE) *i2v_AUTHORITY_INFO_ACCESS(
    X509V3_EXT_METHOD *method, AUTHORITY_INFO_ACCESS *ainfo,
    STACK_OF(CONF_VALUE) *ret)
{
    ACCESS_DESCRIPTION *desc;
    int i, nlen;
    char objtmp[80], *ntmp;
    CONF_VALUE *vtmp;
    STACK_OF(CONF_VALUE) *tret = ret;

    for (i = 0; i < sk_ACCESS_DESCRIPTION_num(ainfo); i++) {
        STACK_OF(CONF_VALUE) *tmp;

        desc = sk_ACCESS_DESCRIPTION_value(ainfo, i);
        tmp = i2v_GENERAL_NAME(method, desc->location, tret);
        if (tmp == NULL)
            goto err;
        tret = tmp;
        vtmp = sk_CONF_VALUE_value(tret, i);
        i2t_ASN1_OBJECT(objtmp, sizeof(objtmp), desc->method);
        nlen = strlen(objtmp) + strlen(vtmp->name) + 5;
        ntmp = OPENSSL_malloc(nlen);
        if (ntmp == NULL)
            goto err;
        BUF_strlcpy(ntmp, objtmp, nlen);
        BUF_strlcat(ntmp, " - ", nlen);
        BUF_strlcat(ntmp, vtmp->name, nlen);
        OPENSSL_free(vtmp->name);
        vtmp->name = ntmp;

    }
    if (ret == NULL && tret == NULL)
        return sk_CONF_VALUE_new_null();

    return tret;
 err:
    X509V3err(X509V3_F_I2V_AUTHORITY_INFO_ACCESS, ERR_R_MALLOC_FAILURE);
    if (ret == NULL && tret != NULL)
        sk_CONF_VALUE_pop_free(tret, X509V3_conf_free);
    return NULL;
}

static AUTHORITY_INFO_ACCESS *v2i_AUTHORITY_INFO_ACCESS(X509V3_EXT_METHOD
                                                        *method,
                                                        X509V3_CTX *ctx,
                                                        STACK_OF(CONF_VALUE)
                                                        *nval)
{
    AUTHORITY_INFO_ACCESS *ainfo = NULL;
    CONF_VALUE *cnf, ctmp;
    ACCESS_DESCRIPTION *acc;
    int i, objlen;
    char *objtmp, *ptmp;
    if (!(ainfo = sk_ACCESS_DESCRIPTION_new_null())) {
        X509V3err(X509V3_F_V2I_AUTHORITY_INFO_ACCESS, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    for (i = 0; i < sk_CONF_VALUE_num(nval); i++) {
        cnf = sk_CONF_VALUE_value(nval, i);
        if (!(acc = ACCESS_DESCRIPTION_new())
            || !sk_ACCESS_DESCRIPTION_push(ainfo, acc)) {
            X509V3err(X509V3_F_V2I_AUTHORITY_INFO_ACCESS,
                      ERR_R_MALLOC_FAILURE);
            goto err;
        }
        ptmp = strchr(cnf->name, ';');
        if (!ptmp) {
            X509V3err(X509V3_F_V2I_AUTHORITY_INFO_ACCESS,
                      X509V3_R_INVALID_SYNTAX);
            goto err;
        }
        objlen = ptmp - cnf->name;
        ctmp.name = ptmp + 1;
        ctmp.value = cnf->value;
        if (!v2i_GENERAL_NAME_ex(acc->location, method, ctx, &ctmp, 0))
            goto err;
        if (!(objtmp = OPENSSL_malloc(objlen + 1))) {
            X509V3err(X509V3_F_V2I_AUTHORITY_INFO_ACCESS,
                      ERR_R_MALLOC_FAILURE);
            goto err;
        }
        strncpy(objtmp, cnf->name, objlen);
        objtmp[objlen] = 0;
        acc->method = OBJ_txt2obj(objtmp, 0);
        if (!acc->method) {
            X509V3err(X509V3_F_V2I_AUTHORITY_INFO_ACCESS,
                      X509V3_R_BAD_OBJECT);
            ERR_add_error_data(2, "value=", objtmp);
            OPENSSL_free(objtmp);
            goto err;
        }
        OPENSSL_free(objtmp);

    }
    return ainfo;
 err:
    sk_ACCESS_DESCRIPTION_pop_free(ainfo, ACCESS_DESCRIPTION_free);
    return NULL;
}

int i2a_ACCESS_DESCRIPTION(BIO *bp, ACCESS_DESCRIPTION *a)
{
    i2a_ASN1_OBJECT(bp, a->method);
#ifdef UNDEF
    i2a_GENERAL_NAME(bp, a->location);
#endif
    return 2;
}
/* v3_int.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 1999.
 */
/* ====================================================================
 * Copyright (c) 1999-2004 The OpenSSL Project.  All rights reserved.
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
// #include "x509v3.h"

const X509V3_EXT_METHOD v3_crl_num = {
    NID_crl_number, 0, ASN1_ITEM_ref(ASN1_INTEGER),
    0, 0, 0, 0,
    (X509V3_EXT_I2S)i2s_ASN1_INTEGER,
    0,
    0, 0, 0, 0, NULL
};

const X509V3_EXT_METHOD v3_delta_crl = {
    NID_delta_crl, 0, ASN1_ITEM_ref(ASN1_INTEGER),
    0, 0, 0, 0,
    (X509V3_EXT_I2S)i2s_ASN1_INTEGER,
    0,
    0, 0, 0, 0, NULL
};

static void *s2i_asn1_int(X509V3_EXT_METHOD *meth, X509V3_CTX *ctx,
                          char *value)
{
    return s2i_ASN1_INTEGER(meth, value);
}

const X509V3_EXT_METHOD v3_inhibit_anyp = {
    NID_inhibit_any_policy, 0, ASN1_ITEM_ref(ASN1_INTEGER),
    0, 0, 0, 0,
    (X509V3_EXT_I2S)i2s_ASN1_INTEGER,
    (X509V3_EXT_S2I)s2i_asn1_int,
    0, 0, 0, 0, NULL
};
/* v3_ncons.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
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
// #include "asn1t.h"
// #include "conf.h"
// #include "x509v3.h"

static void *v2i_NAME_CONSTRAINTS(const X509V3_EXT_METHOD *method,
                                  X509V3_CTX *ctx,
                                  STACK_OF(CONF_VALUE) *nval);
static int i2r_NAME_CONSTRAINTS(const X509V3_EXT_METHOD *method, void *a,
                                BIO *bp, int ind);
static int do_i2r_name_constraints(const X509V3_EXT_METHOD *method,
                                   STACK_OF(GENERAL_SUBTREE) *trees, BIO *bp,
                                   int ind, char *name);
static int print_nc_ipadd(BIO *bp, ASN1_OCTET_STRING *ip);

static int nc_match(GENERAL_NAME *gen, NAME_CONSTRAINTS *nc);
static int nc_match_single(GENERAL_NAME *sub, GENERAL_NAME *gen);
static int nc_dn(X509_NAME *sub, X509_NAME *nm);
static int nc_dns(ASN1_IA5STRING *sub, ASN1_IA5STRING *dns);
static int nc_email(ASN1_IA5STRING *sub, ASN1_IA5STRING *eml);
static int nc_uri(ASN1_IA5STRING *uri, ASN1_IA5STRING *base);

const X509V3_EXT_METHOD v3_name_constraints = {
    NID_name_constraints, 0,
    ASN1_ITEM_ref(NAME_CONSTRAINTS),
    0, 0, 0, 0,
    0, 0,
    0, v2i_NAME_CONSTRAINTS,
    i2r_NAME_CONSTRAINTS, 0,
    NULL
};

ASN1_SEQUENCE(GENERAL_SUBTREE) = {
        ASN1_SIMPLE(GENERAL_SUBTREE, base, GENERAL_NAME),
        ASN1_IMP_OPT(GENERAL_SUBTREE, minimum, ASN1_INTEGER, 0),
        ASN1_IMP_OPT(GENERAL_SUBTREE, maximum, ASN1_INTEGER, 1)
} ASN1_SEQUENCE_END(GENERAL_SUBTREE)

ASN1_SEQUENCE(NAME_CONSTRAINTS) = {
        ASN1_IMP_SEQUENCE_OF_OPT(NAME_CONSTRAINTS, permittedSubtrees,
                                                        GENERAL_SUBTREE, 0),
        ASN1_IMP_SEQUENCE_OF_OPT(NAME_CONSTRAINTS, excludedSubtrees,
                                                        GENERAL_SUBTREE, 1),
} ASN1_SEQUENCE_END(NAME_CONSTRAINTS)


IMPLEMENT_ASN1_ALLOC_FUNCTIONS(GENERAL_SUBTREE)
IMPLEMENT_ASN1_ALLOC_FUNCTIONS(NAME_CONSTRAINTS)

/*
 * We cannot use strncasecmp here because that applies locale specific rules.
 * For example in Turkish 'I' is not the uppercase character for 'i'. We need to
 * do a simple ASCII case comparison ignoring the locale (that is why we use
 * numeric constants below).
 */
static int ia5ncasecmp(const char *s1, const char *s2, size_t n)
{
    for (; n > 0; n--, s1++, s2++) {
        if (*s1 != *s2) {
            unsigned char c1 = (unsigned char)*s1, c2 = (unsigned char)*s2;

            /* Convert to lower case */
            if (c1 >= 0x41 /* A */ && c1 <= 0x5A /* Z */)
                c1 += 0x20;
            if (c2 >= 0x41 /* A */ && c2 <= 0x5A /* Z */)
                c2 += 0x20;

            if (c1 == c2)
                continue;

            if (c1 < c2)
                return -1;

            /* c1 > c2 */
            return 1;
        } else if (*s1 == 0) {
            /* If we get here we know that *s2 == 0 too */
            return 0;
        }
    }

    return 0;
}

static int ia5casecmp(const char *s1, const char *s2)
{
    /* No portable definition of SIZE_MAX, so we use (size_t)(-1) instead */
    return ia5ncasecmp(s1, s2, (size_t)(-1));
}

static void *v2i_NAME_CONSTRAINTS(const X509V3_EXT_METHOD *method,
                                  X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval)
{
    int i;
    CONF_VALUE tval, *val;
    STACK_OF(GENERAL_SUBTREE) **ptree = NULL;
    NAME_CONSTRAINTS *ncons = NULL;
    GENERAL_SUBTREE *sub = NULL;
    ncons = NAME_CONSTRAINTS_new();
    if (!ncons)
        goto memerr;
    for (i = 0; i < sk_CONF_VALUE_num(nval); i++) {
        val = sk_CONF_VALUE_value(nval, i);
        if (!strncmp(val->name, "permitted", 9) && val->name[9]) {
            ptree = &ncons->permittedSubtrees;
            tval.name = val->name + 10;
        } else if (!strncmp(val->name, "excluded", 8) && val->name[8]) {
            ptree = &ncons->excludedSubtrees;
            tval.name = val->name + 9;
        } else {
            X509V3err(X509V3_F_V2I_NAME_CONSTRAINTS, X509V3_R_INVALID_SYNTAX);
            goto err;
        }
        tval.value = val->value;
        sub = GENERAL_SUBTREE_new();
        if (sub == NULL)
            goto memerr;
        if (!v2i_GENERAL_NAME_ex(sub->base, method, ctx, &tval, 1))
            goto err;
        if (!*ptree)
            *ptree = sk_GENERAL_SUBTREE_new_null();
        if (!*ptree || !sk_GENERAL_SUBTREE_push(*ptree, sub))
            goto memerr;
        sub = NULL;
    }

    return ncons;

 memerr:
    X509V3err(X509V3_F_V2I_NAME_CONSTRAINTS, ERR_R_MALLOC_FAILURE);
 err:
    if (ncons)
        NAME_CONSTRAINTS_free(ncons);
    if (sub)
        GENERAL_SUBTREE_free(sub);

    return NULL;
}

static int i2r_NAME_CONSTRAINTS(const X509V3_EXT_METHOD *method, void *a,
                                BIO *bp, int ind)
{
    NAME_CONSTRAINTS *ncons = a;
    do_i2r_name_constraints(method, ncons->permittedSubtrees,
                            bp, ind, "Permitted");
    do_i2r_name_constraints(method, ncons->excludedSubtrees,
                            bp, ind, "Excluded");
    return 1;
}

static int do_i2r_name_constraints(const X509V3_EXT_METHOD *method,
                                   STACK_OF(GENERAL_SUBTREE) *trees,
                                   BIO *bp, int ind, char *name)
{
    GENERAL_SUBTREE *tree;
    int i;
    if (sk_GENERAL_SUBTREE_num(trees) > 0)
        BIO_printf(bp, "%*s%s:\n", ind, "", name);
    for (i = 0; i < sk_GENERAL_SUBTREE_num(trees); i++) {
        tree = sk_GENERAL_SUBTREE_value(trees, i);
        BIO_printf(bp, "%*s", ind + 2, "");
        if (tree->base->type == GEN_IPADD)
            print_nc_ipadd(bp, tree->base->d.ip);
        else
            GENERAL_NAME_print(bp, tree->base);
        BIO_puts(bp, "\n");
    }
    return 1;
}

static int print_nc_ipadd(BIO *bp, ASN1_OCTET_STRING *ip)
{
    int i, len;
    unsigned char *p;
    p = ip->data;
    len = ip->length;
    BIO_puts(bp, "IP:");
    if (len == 8) {
        BIO_printf(bp, "%d.%d.%d.%d/%d.%d.%d.%d",
                   p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
    } else if (len == 32) {
        for (i = 0; i < 16; i++) {
            BIO_printf(bp, "%X", p[0] << 8 | p[1]);
            p += 2;
            if (i == 7)
                BIO_puts(bp, "/");
            else if (i != 15)
                BIO_puts(bp, ":");
        }
    } else
        BIO_printf(bp, "IP Address:<invalid>");
    return 1;
}

/*-
 * Check a certificate conforms to a specified set of constraints.
 * Return values:
 *  X509_V_OK: All constraints obeyed.
 *  X509_V_ERR_PERMITTED_VIOLATION: Permitted subtree violation.
 *  X509_V_ERR_EXCLUDED_VIOLATION: Excluded subtree violation.
 *  X509_V_ERR_SUBTREE_MINMAX: Min or max values present and matching type.
 *  X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE:  Unsupported constraint type.
 *  X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX: bad unsupported constraint syntax.
 *  X509_V_ERR_UNSUPPORTED_NAME_SYNTAX: bad or unsupported syntax of name
 */

int NAME_CONSTRAINTS_check(X509 *x, NAME_CONSTRAINTS *nc)
{
    int r, i;
    X509_NAME *nm;

    nm = X509_get_subject_name(x);

    if (X509_NAME_entry_count(nm) > 0) {
        GENERAL_NAME gntmp;
        gntmp.type = GEN_DIRNAME;
        gntmp.d.directoryName = nm;

        r = nc_match(&gntmp, nc);

        if (r != X509_V_OK)
            return r;

        gntmp.type = GEN_EMAIL;

        /* Process any email address attributes in subject name */

        for (i = -1;;) {
            X509_NAME_ENTRY *ne;
            i = X509_NAME_get_index_by_NID(nm, NID_pkcs9_emailAddress, i);
            if (i == -1)
                break;
            ne = X509_NAME_get_entry(nm, i);
            gntmp.d.rfc822Name = X509_NAME_ENTRY_get_data(ne);
            if (gntmp.d.rfc822Name->type != V_ASN1_IA5STRING)
                return X509_V_ERR_UNSUPPORTED_NAME_SYNTAX;

            r = nc_match(&gntmp, nc);

            if (r != X509_V_OK)
                return r;
        }

    }

    for (i = 0; i < sk_GENERAL_NAME_num(x->altname); i++) {
        GENERAL_NAME *gen = sk_GENERAL_NAME_value(x->altname, i);
        r = nc_match(gen, nc);
        if (r != X509_V_OK)
            return r;
    }

    return X509_V_OK;

}

static int nc_match(GENERAL_NAME *gen, NAME_CONSTRAINTS *nc)
{
    GENERAL_SUBTREE *sub;
    int i, r, match = 0;

    /*
     * Permitted subtrees: if any subtrees exist of matching the type at
     * least one subtree must match.
     */

    for (i = 0; i < sk_GENERAL_SUBTREE_num(nc->permittedSubtrees); i++) {
        sub = sk_GENERAL_SUBTREE_value(nc->permittedSubtrees, i);
        if (gen->type != sub->base->type)
            continue;
        if (sub->minimum || sub->maximum)
            return X509_V_ERR_SUBTREE_MINMAX;
        /* If we already have a match don't bother trying any more */
        if (match == 2)
            continue;
        if (match == 0)
            match = 1;
        r = nc_match_single(gen, sub->base);
        if (r == X509_V_OK)
            match = 2;
        else if (r != X509_V_ERR_PERMITTED_VIOLATION)
            return r;
    }

    if (match == 1)
        return X509_V_ERR_PERMITTED_VIOLATION;

    /* Excluded subtrees: must not match any of these */

    for (i = 0; i < sk_GENERAL_SUBTREE_num(nc->excludedSubtrees); i++) {
        sub = sk_GENERAL_SUBTREE_value(nc->excludedSubtrees, i);
        if (gen->type != sub->base->type)
            continue;
        if (sub->minimum || sub->maximum)
            return X509_V_ERR_SUBTREE_MINMAX;

        r = nc_match_single(gen, sub->base);
        if (r == X509_V_OK)
            return X509_V_ERR_EXCLUDED_VIOLATION;
        else if (r != X509_V_ERR_PERMITTED_VIOLATION)
            return r;

    }

    return X509_V_OK;

}

static int nc_match_single(GENERAL_NAME *gen, GENERAL_NAME *base)
{
    switch (base->type) {
    case GEN_DIRNAME:
        return nc_dn(gen->d.directoryName, base->d.directoryName);

    case GEN_DNS:
        return nc_dns(gen->d.dNSName, base->d.dNSName);

    case GEN_EMAIL:
        return nc_email(gen->d.rfc822Name, base->d.rfc822Name);

    case GEN_URI:
        return nc_uri(gen->d.uniformResourceIdentifier,
                      base->d.uniformResourceIdentifier);

    default:
        return X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE;
    }

}

/*
 * directoryName name constraint matching. The canonical encoding of
 * X509_NAME makes this comparison easy. It is matched if the subtree is a
 * subset of the name.
 */

static int nc_dn(X509_NAME *nm, X509_NAME *base)
{
    /* Ensure canonical encodings are up to date.  */
    if (nm->modified && i2d_X509_NAME(nm, NULL) < 0)
        return X509_V_ERR_OUT_OF_MEM;
    if (base->modified && i2d_X509_NAME(base, NULL) < 0)
        return X509_V_ERR_OUT_OF_MEM;
    if (base->canon_enclen > nm->canon_enclen)
        return X509_V_ERR_PERMITTED_VIOLATION;
    if (memcmp(base->canon_enc, nm->canon_enc, base->canon_enclen))
        return X509_V_ERR_PERMITTED_VIOLATION;
    return X509_V_OK;
}

static int nc_dns(ASN1_IA5STRING *dns, ASN1_IA5STRING *base)
{
    char *baseptr = (char *)base->data;
    char *dnsptr = (char *)dns->data;
    /* Empty matches everything */
    if (!*baseptr)
        return X509_V_OK;
    /*
     * Otherwise can add zero or more components on the left so compare RHS
     * and if dns is longer and expect '.' as preceding character.
     */
    if (dns->length > base->length) {
        dnsptr += dns->length - base->length;
        if (*baseptr != '.' && dnsptr[-1] != '.')
            return X509_V_ERR_PERMITTED_VIOLATION;
    }

    if (ia5casecmp(baseptr, dnsptr))
        return X509_V_ERR_PERMITTED_VIOLATION;

    return X509_V_OK;

}

static int nc_email(ASN1_IA5STRING *eml, ASN1_IA5STRING *base)
{
    const char *baseptr = (char *)base->data;
    const char *emlptr = (char *)eml->data;

    const char *baseat = strchr(baseptr, '@');
    const char *emlat = strchr(emlptr, '@');
    if (!emlat)
        return X509_V_ERR_UNSUPPORTED_NAME_SYNTAX;
    /* Special case: inital '.' is RHS match */
    if (!baseat && (*baseptr == '.')) {
        if (eml->length > base->length) {
            emlptr += eml->length - base->length;
            if (ia5casecmp(baseptr, emlptr) == 0)
                return X509_V_OK;
        }
        return X509_V_ERR_PERMITTED_VIOLATION;
    }

    /* If we have anything before '@' match local part */

    if (baseat) {
        if (baseat != baseptr) {
            if ((baseat - baseptr) != (emlat - emlptr))
                return X509_V_ERR_PERMITTED_VIOLATION;
            /* Case sensitive match of local part */
            if (strncmp(baseptr, emlptr, emlat - emlptr))
                return X509_V_ERR_PERMITTED_VIOLATION;
        }
        /* Position base after '@' */
        baseptr = baseat + 1;
    }
    emlptr = emlat + 1;
    /* Just have hostname left to match: case insensitive */
    if (ia5casecmp(baseptr, emlptr))
        return X509_V_ERR_PERMITTED_VIOLATION;

    return X509_V_OK;

}

static int nc_uri(ASN1_IA5STRING *uri, ASN1_IA5STRING *base)
{
    const char *baseptr = (char *)base->data;
    const char *hostptr = (char *)uri->data;
    const char *p = strchr(hostptr, ':');
    int hostlen;
    /* Check for foo:// and skip past it */
    if (!p || (p[1] != '/') || (p[2] != '/'))
        return X509_V_ERR_UNSUPPORTED_NAME_SYNTAX;
    hostptr = p + 3;

    /* Determine length of hostname part of URI */

    /* Look for a port indicator as end of hostname first */

    p = strchr(hostptr, ':');
    /* Otherwise look for trailing slash */
    if (!p)
        p = strchr(hostptr, '/');

    if (!p)
        hostlen = strlen(hostptr);
    else
        hostlen = p - hostptr;

    if (hostlen == 0)
        return X509_V_ERR_UNSUPPORTED_NAME_SYNTAX;

    /* Special case: inital '.' is RHS match */
    if (*baseptr == '.') {
        if (hostlen > base->length) {
            p = hostptr + hostlen - base->length;
            if (ia5ncasecmp(p, baseptr, base->length) == 0)
                return X509_V_OK;
        }
        return X509_V_ERR_PERMITTED_VIOLATION;
    }

    if ((base->length != (int)hostlen)
        || ia5ncasecmp(hostptr, baseptr, hostlen))
        return X509_V_ERR_PERMITTED_VIOLATION;

    return X509_V_OK;

}
/* v3_ocsp.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 1999.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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

#ifndef OPENSSL_NO_OCSP

# include <stdio.h>
# include "cryptlib.h"
# include "conf.h"
# include "asn1.h"
# include "ocsp.h"
# include "x509v3.h"

/*
 * OCSP extensions and a couple of CRL entry extensions
 */

static int i2r_ocsp_crlid(const X509V3_EXT_METHOD *method, void *nonce,
                          BIO *out, int indent);
static int i2r_ocsp_acutoff(const X509V3_EXT_METHOD *method, void *nonce,
                            BIO *out, int indent);
static int i2r_object(const X509V3_EXT_METHOD *method, void *obj, BIO *out,
                      int indent);

static void *ocsp_nonce_new(void);
static int i2d_ocsp_nonce(void *a, unsigned char **pp);
static void *d2i_ocsp_nonce(void *a, const unsigned char **pp, long length);
static void ocsp_nonce_free(void *a);
static int i2r_ocsp_nonce(const X509V3_EXT_METHOD *method, void *nonce,
                          BIO *out, int indent);

static int i2r_ocsp_nocheck(const X509V3_EXT_METHOD *method,
                            void *nocheck, BIO *out, int indent);
static void *s2i_ocsp_nocheck(const X509V3_EXT_METHOD *method,
                              X509V3_CTX *ctx, const char *str);
static int i2r_ocsp_serviceloc(const X509V3_EXT_METHOD *method, void *in,
                               BIO *bp, int ind);

const X509V3_EXT_METHOD v3_ocsp_crlid = {
    NID_id_pkix_OCSP_CrlID, 0, ASN1_ITEM_ref(OCSP_CRLID),
    0, 0, 0, 0,
    0, 0,
    0, 0,
    i2r_ocsp_crlid, 0,
    NULL
};

const X509V3_EXT_METHOD v3_ocsp_acutoff = {
    NID_id_pkix_OCSP_archiveCutoff, 0, ASN1_ITEM_ref(ASN1_GENERALIZEDTIME),
    0, 0, 0, 0,
    0, 0,
    0, 0,
    i2r_ocsp_acutoff, 0,
    NULL
};

const X509V3_EXT_METHOD v3_crl_invdate = {
    NID_invalidity_date, 0, ASN1_ITEM_ref(ASN1_GENERALIZEDTIME),
    0, 0, 0, 0,
    0, 0,
    0, 0,
    i2r_ocsp_acutoff, 0,
    NULL
};

const X509V3_EXT_METHOD v3_crl_hold = {
    NID_hold_instruction_code, 0, ASN1_ITEM_ref(ASN1_OBJECT),
    0, 0, 0, 0,
    0, 0,
    0, 0,
    i2r_object, 0,
    NULL
};

const X509V3_EXT_METHOD v3_ocsp_nonce = {
    NID_id_pkix_OCSP_Nonce, 0, NULL,
    ocsp_nonce_new,
    ocsp_nonce_free,
    d2i_ocsp_nonce,
    i2d_ocsp_nonce,
    0, 0,
    0, 0,
    i2r_ocsp_nonce, 0,
    NULL
};

const X509V3_EXT_METHOD v3_ocsp_nocheck = {
    NID_id_pkix_OCSP_noCheck, 0, ASN1_ITEM_ref(ASN1_NULL),
    0, 0, 0, 0,
    0, s2i_ocsp_nocheck,
    0, 0,
    i2r_ocsp_nocheck, 0,
    NULL
};

const X509V3_EXT_METHOD v3_ocsp_serviceloc = {
    NID_id_pkix_OCSP_serviceLocator, 0, ASN1_ITEM_ref(OCSP_SERVICELOC),
    0, 0, 0, 0,
    0, 0,
    0, 0,
    i2r_ocsp_serviceloc, 0,
    NULL
};

static int i2r_ocsp_crlid(const X509V3_EXT_METHOD *method, void *in, BIO *bp,
                          int ind)
{
    OCSP_CRLID *a = in;
    if (a->crlUrl) {
        if (BIO_printf(bp, "%*scrlUrl: ", ind, "") <= 0)
            goto err;
        if (!ASN1_STRING_print(bp, (ASN1_STRING *)a->crlUrl))
            goto err;
        if (BIO_write(bp, "\n", 1) <= 0)
            goto err;
    }
    if (a->crlNum) {
        if (BIO_printf(bp, "%*scrlNum: ", ind, "") <= 0)
            goto err;
        if (i2a_ASN1_INTEGER(bp, a->crlNum) <= 0)
            goto err;
        if (BIO_write(bp, "\n", 1) <= 0)
            goto err;
    }
    if (a->crlTime) {
        if (BIO_printf(bp, "%*scrlTime: ", ind, "") <= 0)
            goto err;
        if (!ASN1_GENERALIZEDTIME_print(bp, a->crlTime))
            goto err;
        if (BIO_write(bp, "\n", 1) <= 0)
            goto err;
    }
    return 1;
 err:
    return 0;
}

static int i2r_ocsp_acutoff(const X509V3_EXT_METHOD *method, void *cutoff,
                            BIO *bp, int ind)
{
    if (BIO_printf(bp, "%*s", ind, "") <= 0)
        return 0;
    if (!ASN1_GENERALIZEDTIME_print(bp, cutoff))
        return 0;
    return 1;
}

static int i2r_object(const X509V3_EXT_METHOD *method, void *oid, BIO *bp,
                      int ind)
{
    if (BIO_printf(bp, "%*s", ind, "") <= 0)
        return 0;
    if (i2a_ASN1_OBJECT(bp, oid) <= 0)
        return 0;
    return 1;
}

/*
 * OCSP nonce. This is needs special treatment because it doesn't have an
 * ASN1 encoding at all: it just contains arbitrary data.
 */

static void *ocsp_nonce_new(void)
{
    return ASN1_OCTET_STRING_new();
}

static int i2d_ocsp_nonce(void *a, unsigned char **pp)
{
    ASN1_OCTET_STRING *os = a;
    if (pp) {
        memcpy(*pp, os->data, os->length);
        *pp += os->length;
    }
    return os->length;
}

static void *d2i_ocsp_nonce(void *a, const unsigned char **pp, long length)
{
    ASN1_OCTET_STRING *os, **pos;
    pos = a;
    if (!pos || !*pos)
        os = ASN1_OCTET_STRING_new();
    else
        os = *pos;
    if (!ASN1_OCTET_STRING_set(os, *pp, length))
        goto err;

    *pp += length;

    if (pos)
        *pos = os;
    return os;

 err:
    if (os && (!pos || (*pos != os)))
        M_ASN1_OCTET_STRING_free(os);
    OCSPerr(OCSP_F_D2I_OCSP_NONCE, ERR_R_MALLOC_FAILURE);
    return NULL;
}

static void ocsp_nonce_free(void *a)
{
    M_ASN1_OCTET_STRING_free(a);
}

static int i2r_ocsp_nonce(const X509V3_EXT_METHOD *method, void *nonce,
                          BIO *out, int indent)
{
    if (BIO_printf(out, "%*s", indent, "") <= 0)
        return 0;
    if (i2a_ASN1_STRING(out, nonce, V_ASN1_OCTET_STRING) <= 0)
        return 0;
    return 1;
}

/* Nocheck is just a single NULL. Don't print anything and always set it */

static int i2r_ocsp_nocheck(const X509V3_EXT_METHOD *method, void *nocheck,
                            BIO *out, int indent)
{
    return 1;
}

static void *s2i_ocsp_nocheck(const X509V3_EXT_METHOD *method,
                              X509V3_CTX *ctx, const char *str)
{
    return ASN1_NULL_new();
}

static int i2r_ocsp_serviceloc(const X509V3_EXT_METHOD *method, void *in,
                               BIO *bp, int ind)
{
    int i;
    OCSP_SERVICELOC *a = in;
    ACCESS_DESCRIPTION *ad;

    if (BIO_printf(bp, "%*sIssuer: ", ind, "") <= 0)
        goto err;
    if (X509_NAME_print_ex(bp, a->issuer, 0, XN_FLAG_ONELINE) <= 0)
        goto err;
    for (i = 0; i < sk_ACCESS_DESCRIPTION_num(a->locator); i++) {
        ad = sk_ACCESS_DESCRIPTION_value(a->locator, i);
        if (BIO_printf(bp, "\n%*s", (2 * ind), "") <= 0)
            goto err;
        if (i2a_ASN1_OBJECT(bp, ad->method) <= 0)
            goto err;
        if (BIO_puts(bp, " - ") <= 0)
            goto err;
        if (GENERAL_NAME_print(bp, ad->location) <= 0)
            goto err;
    }
    return 1;
 err:
    return 0;
}
#endif
/* v3_pci.c */
/*
 * Contributed to the OpenSSL Project 2004 by Richard Levitte
 * (richard@levitte.org)
 */
/* Copyright (c) 2004 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdio.h>
// #include "cryptlib.h"
// #include "conf.h"
// #include "x509v3.h"

static int i2r_pci(X509V3_EXT_METHOD *method, PROXY_CERT_INFO_EXTENSION *ext,
                   BIO *out, int indent);
static PROXY_CERT_INFO_EXTENSION *r2i_pci(X509V3_EXT_METHOD *method,
                                          X509V3_CTX *ctx, char *str);

const X509V3_EXT_METHOD v3_pci =
    { NID_proxyCertInfo, 0, ASN1_ITEM_ref(PROXY_CERT_INFO_EXTENSION),
    0, 0, 0, 0,
    0, 0,
    NULL, NULL,
    (X509V3_EXT_I2R)i2r_pci,
    (X509V3_EXT_R2I)r2i_pci,
    NULL,
};

static int i2r_pci(X509V3_EXT_METHOD *method, PROXY_CERT_INFO_EXTENSION *pci,
                   BIO *out, int indent)
{
    BIO_printf(out, "%*sPath Length Constraint: ", indent, "");
    if (pci->pcPathLengthConstraint)
        i2a_ASN1_INTEGER(out, pci->pcPathLengthConstraint);
    else
        BIO_printf(out, "infinite");
    BIO_puts(out, "\n");
    BIO_printf(out, "%*sPolicy Language: ", indent, "");
    i2a_ASN1_OBJECT(out, pci->proxyPolicy->policyLanguage);
    BIO_puts(out, "\n");
    if (pci->proxyPolicy->policy && pci->proxyPolicy->policy->data)
        BIO_printf(out, "%*sPolicy Text: %s\n", indent, "",
                   pci->proxyPolicy->policy->data);
    return 1;
}

static int process_pci_value(CONF_VALUE *val,
                             ASN1_OBJECT **language, ASN1_INTEGER **pathlen,
                             ASN1_OCTET_STRING **policy)
{
    int free_policy = 0;

    if (strcmp(val->name, "language") == 0) {
        if (*language) {
            X509V3err(X509V3_F_PROCESS_PCI_VALUE,
                      X509V3_R_POLICY_LANGUAGE_ALREADY_DEFINED);
            X509V3_conf_err(val);
            return 0;
        }
        if (!(*language = OBJ_txt2obj(val->value, 0))) {
            X509V3err(X509V3_F_PROCESS_PCI_VALUE,
                      X509V3_R_INVALID_OBJECT_IDENTIFIER);
            X509V3_conf_err(val);
            return 0;
        }
    } else if (strcmp(val->name, "pathlen") == 0) {
        if (*pathlen) {
            X509V3err(X509V3_F_PROCESS_PCI_VALUE,
                      X509V3_R_POLICY_PATH_LENGTH_ALREADY_DEFINED);
            X509V3_conf_err(val);
            return 0;
        }
        if (!X509V3_get_value_int(val, pathlen)) {
            X509V3err(X509V3_F_PROCESS_PCI_VALUE,
                      X509V3_R_POLICY_PATH_LENGTH);
            X509V3_conf_err(val);
            return 0;
        }
    } else if (strcmp(val->name, "policy") == 0) {
        unsigned char *tmp_data = NULL;
        long val_len;
        if (!*policy) {
            *policy = ASN1_OCTET_STRING_new();
            if (!*policy) {
                X509V3err(X509V3_F_PROCESS_PCI_VALUE, ERR_R_MALLOC_FAILURE);
                X509V3_conf_err(val);
                return 0;
            }
            free_policy = 1;
        }
        if (strncmp(val->value, "hex:", 4) == 0) {
            unsigned char *tmp_data2 =
                string_to_hex(val->value + 4, &val_len);

            if (!tmp_data2) {
                X509V3err(X509V3_F_PROCESS_PCI_VALUE,
                          X509V3_R_ILLEGAL_HEX_DIGIT);
                X509V3_conf_err(val);
                goto err;
            }

            tmp_data = OPENSSL_realloc((*policy)->data,
                                       (*policy)->length + val_len + 1);
            if (tmp_data) {
                (*policy)->data = tmp_data;
                memcpy(&(*policy)->data[(*policy)->length],
                       tmp_data2, val_len);
                (*policy)->length += val_len;
                (*policy)->data[(*policy)->length] = '\0';
            } else {
                OPENSSL_free(tmp_data2);
                /*
                 * realloc failure implies the original data space is b0rked
                 * too!
                 */
                (*policy)->data = NULL;
                (*policy)->length = 0;
                X509V3err(X509V3_F_PROCESS_PCI_VALUE, ERR_R_MALLOC_FAILURE);
                X509V3_conf_err(val);
                goto err;
            }
            OPENSSL_free(tmp_data2);
        } else if (strncmp(val->value, "file:", 5) == 0) {
            unsigned char buf[2048];
            int n;
            BIO *b = BIO_new_file(val->value + 5, "r");
            if (!b) {
                X509V3err(X509V3_F_PROCESS_PCI_VALUE, ERR_R_BIO_LIB);
                X509V3_conf_err(val);
                goto err;
            }
            while ((n = BIO_read(b, buf, sizeof(buf))) > 0
                   || (n == 0 && BIO_should_retry(b))) {
                if (!n)
                    continue;

                tmp_data = OPENSSL_realloc((*policy)->data,
                                           (*policy)->length + n + 1);

                if (!tmp_data)
                    break;

                (*policy)->data = tmp_data;
                memcpy(&(*policy)->data[(*policy)->length], buf, n);
                (*policy)->length += n;
                (*policy)->data[(*policy)->length] = '\0';
            }
            BIO_free_all(b);

            if (n < 0) {
                X509V3err(X509V3_F_PROCESS_PCI_VALUE, ERR_R_BIO_LIB);
                X509V3_conf_err(val);
                goto err;
            }
        } else if (strncmp(val->value, "text:", 5) == 0) {
            val_len = strlen(val->value + 5);
            tmp_data = OPENSSL_realloc((*policy)->data,
                                       (*policy)->length + val_len + 1);
            if (tmp_data) {
                (*policy)->data = tmp_data;
                memcpy(&(*policy)->data[(*policy)->length],
                       val->value + 5, val_len);
                (*policy)->length += val_len;
                (*policy)->data[(*policy)->length] = '\0';
            } else {
                /*
                 * realloc failure implies the original data space is b0rked
                 * too!
                 */
                (*policy)->data = NULL;
                (*policy)->length = 0;
                X509V3err(X509V3_F_PROCESS_PCI_VALUE, ERR_R_MALLOC_FAILURE);
                X509V3_conf_err(val);
                goto err;
            }
        } else {
            X509V3err(X509V3_F_PROCESS_PCI_VALUE,
                      X509V3_R_INCORRECT_POLICY_SYNTAX_TAG);
            X509V3_conf_err(val);
            goto err;
        }
        if (!tmp_data) {
            X509V3err(X509V3_F_PROCESS_PCI_VALUE, ERR_R_MALLOC_FAILURE);
            X509V3_conf_err(val);
            goto err;
        }
    }
    return 1;
 err:
    if (free_policy) {
        ASN1_OCTET_STRING_free(*policy);
        *policy = NULL;
    }
    return 0;
}

static PROXY_CERT_INFO_EXTENSION *r2i_pci(X509V3_EXT_METHOD *method,
                                          X509V3_CTX *ctx, char *value)
{
    PROXY_CERT_INFO_EXTENSION *pci = NULL;
    STACK_OF(CONF_VALUE) *vals;
    ASN1_OBJECT *language = NULL;
    ASN1_INTEGER *pathlen = NULL;
    ASN1_OCTET_STRING *policy = NULL;
    int i, j;

    vals = X509V3_parse_list(value);
    for (i = 0; i < sk_CONF_VALUE_num(vals); i++) {
        CONF_VALUE *cnf = sk_CONF_VALUE_value(vals, i);
        if (!cnf->name || (*cnf->name != '@' && !cnf->value)) {
            X509V3err(X509V3_F_R2I_PCI,
                      X509V3_R_INVALID_PROXY_POLICY_SETTING);
            X509V3_conf_err(cnf);
            goto err;
        }
        if (*cnf->name == '@') {
            STACK_OF(CONF_VALUE) *sect;
            int success_p = 1;

            sect = X509V3_get_section(ctx, cnf->name + 1);
            if (!sect) {
                X509V3err(X509V3_F_R2I_PCI, X509V3_R_INVALID_SECTION);
                X509V3_conf_err(cnf);
                goto err;
            }
            for (j = 0; success_p && j < sk_CONF_VALUE_num(sect); j++) {
                success_p =
                    process_pci_value(sk_CONF_VALUE_value(sect, j),
                                      &language, &pathlen, &policy);
            }
            X509V3_section_free(ctx, sect);
            if (!success_p)
                goto err;
        } else {
            if (!process_pci_value(cnf, &language, &pathlen, &policy)) {
                X509V3_conf_err(cnf);
                goto err;
            }
        }
    }

    /* Language is mandatory */
    if (!language) {
        X509V3err(X509V3_F_R2I_PCI,
                  X509V3_R_NO_PROXY_CERT_POLICY_LANGUAGE_DEFINED);
        goto err;
    }
    i = OBJ_obj2nid(language);
    if ((i == NID_Independent || i == NID_id_ppl_inheritAll) && policy) {
        X509V3err(X509V3_F_R2I_PCI,
                  X509V3_R_POLICY_WHEN_PROXY_LANGUAGE_REQUIRES_NO_POLICY);
        goto err;
    }

    pci = PROXY_CERT_INFO_EXTENSION_new();
    if (!pci) {
        X509V3err(X509V3_F_R2I_PCI, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    pci->proxyPolicy->policyLanguage = language;
    language = NULL;
    pci->proxyPolicy->policy = policy;
    policy = NULL;
    pci->pcPathLengthConstraint = pathlen;
    pathlen = NULL;
    goto end;
 err:
    if (language) {
        ASN1_OBJECT_free(language);
        language = NULL;
    }
    if (pathlen) {
        ASN1_INTEGER_free(pathlen);
        pathlen = NULL;
    }
    if (policy) {
        ASN1_OCTET_STRING_free(policy);
        policy = NULL;
    }
    if (pci) {
        PROXY_CERT_INFO_EXTENSION_free(pci);
        pci = NULL;
    }
 end:
    sk_CONF_VALUE_pop_free(vals, X509V3_conf_free);
    return pci;
}
/* v3_pcia.c */
/*
 * Contributed to the OpenSSL Project 2004 by Richard Levitte
 * (richard@levitte.org)
 */
/* Copyright (c) 2004 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

// #include "asn1.h"
// #include "asn1t.h"
// #include "x509v3.h"

ASN1_SEQUENCE(PROXY_POLICY) =
        {
        ASN1_SIMPLE(PROXY_POLICY,policyLanguage,ASN1_OBJECT),
        ASN1_OPT(PROXY_POLICY,policy,ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(PROXY_POLICY)

IMPLEMENT_ASN1_FUNCTIONS(PROXY_POLICY)

ASN1_SEQUENCE(PROXY_CERT_INFO_EXTENSION) =
        {
        ASN1_OPT(PROXY_CERT_INFO_EXTENSION,pcPathLengthConstraint,ASN1_INTEGER),
        ASN1_SIMPLE(PROXY_CERT_INFO_EXTENSION,proxyPolicy,PROXY_POLICY)
} ASN1_SEQUENCE_END(PROXY_CERT_INFO_EXTENSION)

IMPLEMENT_ASN1_FUNCTIONS(PROXY_CERT_INFO_EXTENSION)
/* v3_pcons.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
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
// #include "asn1.h"
// #include "asn1t.h"
// #include "conf.h"
// #include "x509v3.h"

static STACK_OF(CONF_VALUE) *i2v_POLICY_CONSTRAINTS(const X509V3_EXT_METHOD
                                                    *method, void *bcons, STACK_OF(CONF_VALUE)
                                                    *extlist);
static void *v2i_POLICY_CONSTRAINTS(const X509V3_EXT_METHOD *method,
                                    X509V3_CTX *ctx,
                                    STACK_OF(CONF_VALUE) *values);

const X509V3_EXT_METHOD v3_policy_constraints = {
    NID_policy_constraints, 0,
    ASN1_ITEM_ref(POLICY_CONSTRAINTS),
    0, 0, 0, 0,
    0, 0,
    i2v_POLICY_CONSTRAINTS,
    v2i_POLICY_CONSTRAINTS,
    NULL, NULL,
    NULL
};

ASN1_SEQUENCE(POLICY_CONSTRAINTS) = {
        ASN1_IMP_OPT(POLICY_CONSTRAINTS, requireExplicitPolicy, ASN1_INTEGER,0),
        ASN1_IMP_OPT(POLICY_CONSTRAINTS, inhibitPolicyMapping, ASN1_INTEGER,1)
} ASN1_SEQUENCE_END(POLICY_CONSTRAINTS)

IMPLEMENT_ASN1_ALLOC_FUNCTIONS(POLICY_CONSTRAINTS)

static STACK_OF(CONF_VALUE) *i2v_POLICY_CONSTRAINTS(const X509V3_EXT_METHOD
                                                    *method, void *a, STACK_OF(CONF_VALUE)
                                                    *extlist)
{
    POLICY_CONSTRAINTS *pcons = a;
    X509V3_add_value_int("Require Explicit Policy",
                         pcons->requireExplicitPolicy, &extlist);
    X509V3_add_value_int("Inhibit Policy Mapping",
                         pcons->inhibitPolicyMapping, &extlist);
    return extlist;
}

static void *v2i_POLICY_CONSTRAINTS(const X509V3_EXT_METHOD *method,
                                    X509V3_CTX *ctx,
                                    STACK_OF(CONF_VALUE) *values)
{
    POLICY_CONSTRAINTS *pcons = NULL;
    CONF_VALUE *val;
    int i;
    if (!(pcons = POLICY_CONSTRAINTS_new())) {
        X509V3err(X509V3_F_V2I_POLICY_CONSTRAINTS, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    for (i = 0; i < sk_CONF_VALUE_num(values); i++) {
        val = sk_CONF_VALUE_value(values, i);
        if (!strcmp(val->name, "requireExplicitPolicy")) {
            if (!X509V3_get_value_int(val, &pcons->requireExplicitPolicy))
                goto err;
        } else if (!strcmp(val->name, "inhibitPolicyMapping")) {
            if (!X509V3_get_value_int(val, &pcons->inhibitPolicyMapping))
                goto err;
        } else {
            X509V3err(X509V3_F_V2I_POLICY_CONSTRAINTS, X509V3_R_INVALID_NAME);
            X509V3_conf_err(val);
            goto err;
        }
    }
    if (!pcons->inhibitPolicyMapping && !pcons->requireExplicitPolicy) {
        X509V3err(X509V3_F_V2I_POLICY_CONSTRAINTS,
                  X509V3_R_ILLEGAL_EMPTY_EXTENSION);
        goto err;
    }

    return pcons;
 err:
    POLICY_CONSTRAINTS_free(pcons);
    return NULL;
}
/* v3_pku.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 1999.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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
// #include "asn1.h"
// #include "asn1t.h"
// #include "x509v3.h"

static int i2r_PKEY_USAGE_PERIOD(X509V3_EXT_METHOD *method,
                                 PKEY_USAGE_PERIOD *usage, BIO *out,
                                 int indent);
/*
 * static PKEY_USAGE_PERIOD *v2i_PKEY_USAGE_PERIOD(X509V3_EXT_METHOD *method,
 * X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *values);
 */
const X509V3_EXT_METHOD v3_pkey_usage_period = {
    NID_private_key_usage_period, 0, ASN1_ITEM_ref(PKEY_USAGE_PERIOD),
    0, 0, 0, 0,
    0, 0, 0, 0,
    (X509V3_EXT_I2R)i2r_PKEY_USAGE_PERIOD, NULL,
    NULL
};

ASN1_SEQUENCE(PKEY_USAGE_PERIOD) = {
        ASN1_IMP_OPT(PKEY_USAGE_PERIOD, notBefore, ASN1_GENERALIZEDTIME, 0),
        ASN1_IMP_OPT(PKEY_USAGE_PERIOD, notAfter, ASN1_GENERALIZEDTIME, 1)
} ASN1_SEQUENCE_END(PKEY_USAGE_PERIOD)

IMPLEMENT_ASN1_FUNCTIONS(PKEY_USAGE_PERIOD)

static int i2r_PKEY_USAGE_PERIOD(X509V3_EXT_METHOD *method,
                                 PKEY_USAGE_PERIOD *usage, BIO *out,
                                 int indent)
{
    BIO_printf(out, "%*s", indent, "");
    if (usage->notBefore) {
        BIO_write(out, "Not Before: ", 12);
        ASN1_GENERALIZEDTIME_print(out, usage->notBefore);
        if (usage->notAfter)
            BIO_write(out, ", ", 2);
    }
    if (usage->notAfter) {
        BIO_write(out, "Not After: ", 11);
        ASN1_GENERALIZEDTIME_print(out, usage->notAfter);
    }
    return 1;
}

/*-
static PKEY_USAGE_PERIOD *v2i_PKEY_USAGE_PERIOD(method, ctx, values)
X509V3_EXT_METHOD *method;
X509V3_CTX *ctx;
STACK_OF(CONF_VALUE) *values;
{
return NULL;
}
*/
/* v3_pmaps.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
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
// #include "asn1t.h"
// #include "conf.h"
// #include "x509v3.h"

static void *v2i_POLICY_MAPPINGS(const X509V3_EXT_METHOD *method,
                                 X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval);
static STACK_OF(CONF_VALUE) *i2v_POLICY_MAPPINGS(const X509V3_EXT_METHOD
                                                 *method, void *pmps, STACK_OF(CONF_VALUE)
                                                 *extlist);

const X509V3_EXT_METHOD v3_policy_mappings = {
    NID_policy_mappings, 0,
    ASN1_ITEM_ref(POLICY_MAPPINGS),
    0, 0, 0, 0,
    0, 0,
    i2v_POLICY_MAPPINGS,
    v2i_POLICY_MAPPINGS,
    0, 0,
    NULL
};

ASN1_SEQUENCE(POLICY_MAPPING) = {
        ASN1_SIMPLE(POLICY_MAPPING, issuerDomainPolicy, ASN1_OBJECT),
        ASN1_SIMPLE(POLICY_MAPPING, subjectDomainPolicy, ASN1_OBJECT)
} ASN1_SEQUENCE_END(POLICY_MAPPING)

ASN1_ITEM_TEMPLATE(POLICY_MAPPINGS) =
        ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, POLICY_MAPPINGS,
                                                                POLICY_MAPPING)
ASN1_ITEM_TEMPLATE_END(POLICY_MAPPINGS)

IMPLEMENT_ASN1_ALLOC_FUNCTIONS(POLICY_MAPPING)

static STACK_OF(CONF_VALUE) *i2v_POLICY_MAPPINGS(const X509V3_EXT_METHOD
                                                 *method, void *a, STACK_OF(CONF_VALUE)
                                                 *ext_list)
{
    POLICY_MAPPINGS *pmaps = a;
    POLICY_MAPPING *pmap;
    int i;
    char obj_tmp1[80];
    char obj_tmp2[80];
    for (i = 0; i < sk_POLICY_MAPPING_num(pmaps); i++) {
        pmap = sk_POLICY_MAPPING_value(pmaps, i);
        i2t_ASN1_OBJECT(obj_tmp1, 80, pmap->issuerDomainPolicy);
        i2t_ASN1_OBJECT(obj_tmp2, 80, pmap->subjectDomainPolicy);
        X509V3_add_value(obj_tmp1, obj_tmp2, &ext_list);
    }
    return ext_list;
}

static void *v2i_POLICY_MAPPINGS(const X509V3_EXT_METHOD *method,
                                 X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval)
{
    POLICY_MAPPINGS *pmaps;
    POLICY_MAPPING *pmap;
    ASN1_OBJECT *obj1, *obj2;
    CONF_VALUE *val;
    int i;

    if (!(pmaps = sk_POLICY_MAPPING_new_null())) {
        X509V3err(X509V3_F_V2I_POLICY_MAPPINGS, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    for (i = 0; i < sk_CONF_VALUE_num(nval); i++) {
        val = sk_CONF_VALUE_value(nval, i);
        if (!val->value || !val->name) {
            sk_POLICY_MAPPING_pop_free(pmaps, POLICY_MAPPING_free);
            X509V3err(X509V3_F_V2I_POLICY_MAPPINGS,
                      X509V3_R_INVALID_OBJECT_IDENTIFIER);
            X509V3_conf_err(val);
            return NULL;
        }
        obj1 = OBJ_txt2obj(val->name, 0);
        obj2 = OBJ_txt2obj(val->value, 0);
        if (!obj1 || !obj2) {
            sk_POLICY_MAPPING_pop_free(pmaps, POLICY_MAPPING_free);
            X509V3err(X509V3_F_V2I_POLICY_MAPPINGS,
                      X509V3_R_INVALID_OBJECT_IDENTIFIER);
            X509V3_conf_err(val);
            return NULL;
        }
        pmap = POLICY_MAPPING_new();
        if (!pmap) {
            sk_POLICY_MAPPING_pop_free(pmaps, POLICY_MAPPING_free);
            X509V3err(X509V3_F_V2I_POLICY_MAPPINGS, ERR_R_MALLOC_FAILURE);
            return NULL;
        }
        pmap->issuerDomainPolicy = obj1;
        pmap->subjectDomainPolicy = obj2;
        sk_POLICY_MAPPING_push(pmaps, pmap);
    }
    return pmaps;
}
/* v3_prn.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 1999.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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
/* X509 v3 extension utilities */

#include <stdio.h>
// #include "cryptlib.h"
// #include "conf.h"
// #include "x509v3.h"

/* Extension printing routines */

static int unknown_ext_print(BIO *out, X509_EXTENSION *ext,
                             unsigned long flag, int indent, int supported);

/* Print out a name+value stack */

void X509V3_EXT_val_prn(BIO *out, STACK_OF(CONF_VALUE) *val, int indent,
                        int ml)
{
    int i;
    CONF_VALUE *nval;
    if (!val)
        return;
    if (!ml || !sk_CONF_VALUE_num(val)) {
        BIO_printf(out, "%*s", indent, "");
        if (!sk_CONF_VALUE_num(val))
            BIO_puts(out, "<EMPTY>\n");
    }
    for (i = 0; i < sk_CONF_VALUE_num(val); i++) {
        if (ml)
            BIO_printf(out, "%*s", indent, "");
        else if (i > 0)
            BIO_printf(out, ", ");
        nval = sk_CONF_VALUE_value(val, i);
        if (!nval->name)
            BIO_puts(out, nval->value);
        else if (!nval->value)
            BIO_puts(out, nval->name);
#ifndef CHARSET_EBCDIC
        else
            BIO_printf(out, "%s:%s", nval->name, nval->value);
#else
        else {
            int len;
            char *tmp;
            len = strlen(nval->value) + 1;
            tmp = OPENSSL_malloc(len);
            if (tmp) {
                ascii2ebcdic(tmp, nval->value, len);
                BIO_printf(out, "%s:%s", nval->name, tmp);
                OPENSSL_free(tmp);
            }
        }
#endif
        if (ml)
            BIO_puts(out, "\n");
    }
}

/* Main routine: print out a general extension */

int X509V3_EXT_print(BIO *out, X509_EXTENSION *ext, unsigned long flag,
                     int indent)
{
    void *ext_str = NULL;
    char *value = NULL;
    const unsigned char *p;
    const X509V3_EXT_METHOD *method;
    STACK_OF(CONF_VALUE) *nval = NULL;
    int ok = 1;

    if (!(method = X509V3_EXT_get(ext)))
        return unknown_ext_print(out, ext, flag, indent, 0);
    p = ext->value->data;
    if (method->it)
        ext_str =
            ASN1_item_d2i(NULL, &p, ext->value->length,
                          ASN1_ITEM_ptr(method->it));
    else
        ext_str = method->d2i(NULL, &p, ext->value->length);

    if (!ext_str)
        return unknown_ext_print(out, ext, flag, indent, 1);

    if (method->i2s) {
        if (!(value = method->i2s(method, ext_str))) {
            ok = 0;
            goto err;
        }
#ifndef CHARSET_EBCDIC
        BIO_printf(out, "%*s%s", indent, "", value);
#else
        {
            int len;
            char *tmp;
            len = strlen(value) + 1;
            tmp = OPENSSL_malloc(len);
            if (tmp) {
                ascii2ebcdic(tmp, value, len);
                BIO_printf(out, "%*s%s", indent, "", tmp);
                OPENSSL_free(tmp);
            }
        }
#endif
    } else if (method->i2v) {
        if (!(nval = method->i2v(method, ext_str, NULL))) {
            ok = 0;
            goto err;
        }
        X509V3_EXT_val_prn(out, nval, indent,
                           method->ext_flags & X509V3_EXT_MULTILINE);
    } else if (method->i2r) {
        if (!method->i2r(method, ext_str, out, indent))
            ok = 0;
    } else
        ok = 0;

 err:
    sk_CONF_VALUE_pop_free(nval, X509V3_conf_free);
    if (value)
        OPENSSL_free(value);
    if (method->it)
        ASN1_item_free(ext_str, ASN1_ITEM_ptr(method->it));
    else
        method->ext_free(ext_str);
    return ok;
}

int X509V3_extensions_print(BIO *bp, char *title,
                            STACK_OF(X509_EXTENSION) *exts,
                            unsigned long flag, int indent)
{
    int i, j;

    if (sk_X509_EXTENSION_num(exts) <= 0)
        return 1;

    if (title) {
        BIO_printf(bp, "%*s%s:\n", indent, "", title);
        indent += 4;
    }

    for (i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
        ASN1_OBJECT *obj;
        X509_EXTENSION *ex;
        ex = sk_X509_EXTENSION_value(exts, i);
        if (indent && BIO_printf(bp, "%*s", indent, "") <= 0)
            return 0;
        obj = X509_EXTENSION_get_object(ex);
        i2a_ASN1_OBJECT(bp, obj);
        j = X509_EXTENSION_get_critical(ex);
        if (BIO_printf(bp, ": %s\n", j ? "critical" : "") <= 0)
            return 0;
        if (!X509V3_EXT_print(bp, ex, flag, indent + 4)) {
            BIO_printf(bp, "%*s", indent + 4, "");
            M_ASN1_OCTET_STRING_print(bp, ex->value);
        }
        if (BIO_write(bp, "\n", 1) <= 0)
            return 0;
    }
    return 1;
}

static int unknown_ext_print(BIO *out, X509_EXTENSION *ext,
                             unsigned long flag, int indent, int supported)
{
    switch (flag & X509V3_EXT_UNKNOWN_MASK) {

    case X509V3_EXT_DEFAULT:
        return 0;

    case X509V3_EXT_ERROR_UNKNOWN:
        if (supported)
            BIO_printf(out, "%*s<Parse Error>", indent, "");
        else
            BIO_printf(out, "%*s<Not Supported>", indent, "");
        return 1;

    case X509V3_EXT_PARSE_UNKNOWN:
        return ASN1_parse_dump(out,
                               ext->value->data, ext->value->length, indent,
                               -1);
    case X509V3_EXT_DUMP_UNKNOWN:
        return BIO_dump_indent(out, (char *)ext->value->data,
                               ext->value->length, indent);

    default:
        return 1;
    }
}

#ifndef OPENSSL_NO_FP_API
int X509V3_EXT_print_fp(FILE *fp, X509_EXTENSION *ext, int flag, int indent)
{
    BIO *bio_tmp;
    int ret;
    if (!(bio_tmp = BIO_new_fp(fp, BIO_NOCLOSE)))
        return 0;
    ret = X509V3_EXT_print(bio_tmp, ext, flag, indent);
    BIO_free(bio_tmp);
    return ret;
}
#endif
/* v3_purp.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2001.
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

#include <stdio.h>
// #include "cryptlib.h"
// #include "x509v3.h"
#include "x509_vfy.h"

static void x509v3_cache_extensions(X509 *x);

static int check_ssl_ca(const X509 *x);
static int check_purpose_ssl_client(const X509_PURPOSE *xp, const X509 *x,
                                    int ca);
static int check_purpose_ssl_server(const X509_PURPOSE *xp, const X509 *x,
                                    int ca);
static int check_purpose_ns_ssl_server(const X509_PURPOSE *xp, const X509 *x,
                                       int ca);
static int purpose_smime(const X509 *x, int ca);
static int check_purpose_smime_sign(const X509_PURPOSE *xp, const X509 *x,
                                    int ca);
static int check_purpose_smime_encrypt(const X509_PURPOSE *xp, const X509 *x,
                                       int ca);
static int check_purpose_crl_sign(const X509_PURPOSE *xp, const X509 *x,
                                  int ca);
static int check_purpose_timestamp_sign(const X509_PURPOSE *xp, const X509 *x,
                                        int ca);
static int no_check(const X509_PURPOSE *xp, const X509 *x, int ca);
static int ocsp_helper(const X509_PURPOSE *xp, const X509 *x, int ca);

static int xp_cmp(const X509_PURPOSE *const *a, const X509_PURPOSE *const *b);
static void xptable_free(X509_PURPOSE *p);

static X509_PURPOSE xstandard[] = {
    {X509_PURPOSE_SSL_CLIENT, X509_TRUST_SSL_CLIENT, 0,
     check_purpose_ssl_client, "SSL client", "sslclient", NULL},
    {X509_PURPOSE_SSL_SERVER, X509_TRUST_SSL_SERVER, 0,
     check_purpose_ssl_server, "SSL server", "sslserver", NULL},
    {X509_PURPOSE_NS_SSL_SERVER, X509_TRUST_SSL_SERVER, 0,
     check_purpose_ns_ssl_server, "Netscape SSL server", "nssslserver", NULL},
    {X509_PURPOSE_SMIME_SIGN, X509_TRUST_EMAIL, 0, check_purpose_smime_sign,
     "S/MIME signing", "smimesign", NULL},
    {X509_PURPOSE_SMIME_ENCRYPT, X509_TRUST_EMAIL, 0,
     check_purpose_smime_encrypt, "S/MIME encryption", "smimeencrypt", NULL},
    {X509_PURPOSE_CRL_SIGN, X509_TRUST_COMPAT, 0, check_purpose_crl_sign,
     "CRL signing", "crlsign", NULL},
    {X509_PURPOSE_ANY, X509_TRUST_DEFAULT, 0, no_check, "Any Purpose", "any",
     NULL},
    {X509_PURPOSE_OCSP_HELPER, X509_TRUST_COMPAT, 0, ocsp_helper,
     "OCSP helper", "ocsphelper", NULL},
    {X509_PURPOSE_TIMESTAMP_SIGN, X509_TRUST_TSA, 0,
     check_purpose_timestamp_sign, "Time Stamp signing", "timestampsign",
     NULL},
};

#define X509_PURPOSE_COUNT (sizeof(xstandard)/sizeof(X509_PURPOSE))

IMPLEMENT_STACK_OF(X509_PURPOSE)

static STACK_OF(X509_PURPOSE) *xptable = NULL;

static int xp_cmp(const X509_PURPOSE *const *a, const X509_PURPOSE *const *b)
{
    return (*a)->purpose - (*b)->purpose;
}

/*
 * As much as I'd like to make X509_check_purpose use a "const" X509* I
 * really can't because it does recalculate hashes and do other non-const
 * things.
 */
int X509_check_purpose(X509 *x, int id, int ca)
{
    int idx;
    const X509_PURPOSE *pt;

    x509v3_cache_extensions(x);

    /* Return if side-effect only call */
    if (id == -1)
        return 1;
    idx = X509_PURPOSE_get_by_id(id);
    if (idx == -1)
        return -1;
    pt = X509_PURPOSE_get0(idx);
    return pt->check_purpose(pt, x, ca);
}

int X509_PURPOSE_set(int *p, int purpose)
{
    if (X509_PURPOSE_get_by_id(purpose) == -1) {
        X509V3err(X509V3_F_X509_PURPOSE_SET, X509V3_R_INVALID_PURPOSE);
        return 0;
    }
    *p = purpose;
    return 1;
}

int X509_PURPOSE_get_count(void)
{
    if (!xptable)
        return X509_PURPOSE_COUNT;
    return sk_X509_PURPOSE_num(xptable) + X509_PURPOSE_COUNT;
}

X509_PURPOSE *X509_PURPOSE_get0(int idx)
{
    if (idx < 0)
        return NULL;
    if (idx < (int)X509_PURPOSE_COUNT)
        return xstandard + idx;
    return sk_X509_PURPOSE_value(xptable, idx - X509_PURPOSE_COUNT);
}

int X509_PURPOSE_get_by_sname(char *sname)
{
    int i;
    X509_PURPOSE *xptmp;
    for (i = 0; i < X509_PURPOSE_get_count(); i++) {
        xptmp = X509_PURPOSE_get0(i);
        if (!strcmp(xptmp->sname, sname))
            return i;
    }
    return -1;
}

int X509_PURPOSE_get_by_id(int purpose)
{
    X509_PURPOSE tmp;
    int idx;
    if ((purpose >= X509_PURPOSE_MIN) && (purpose <= X509_PURPOSE_MAX))
        return purpose - X509_PURPOSE_MIN;
    tmp.purpose = purpose;
    if (!xptable)
        return -1;
    idx = sk_X509_PURPOSE_find(xptable, &tmp);
    if (idx == -1)
        return -1;
    return idx + X509_PURPOSE_COUNT;
}

int X509_PURPOSE_add(int id, int trust, int flags,
                     int (*ck) (const X509_PURPOSE *, const X509 *, int),
                     char *name, char *sname, void *arg)
{
    int idx;
    X509_PURPOSE *ptmp;
    /*
     * This is set according to what we change: application can't set it
     */
    flags &= ~X509_PURPOSE_DYNAMIC;
    /* This will always be set for application modified trust entries */
    flags |= X509_PURPOSE_DYNAMIC_NAME;
    /* Get existing entry if any */
    idx = X509_PURPOSE_get_by_id(id);
    /* Need a new entry */
    if (idx == -1) {
        if (!(ptmp = OPENSSL_malloc(sizeof(X509_PURPOSE)))) {
            X509V3err(X509V3_F_X509_PURPOSE_ADD, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        ptmp->flags = X509_PURPOSE_DYNAMIC;
    } else
        ptmp = X509_PURPOSE_get0(idx);

    /* OPENSSL_free existing name if dynamic */
    if (ptmp->flags & X509_PURPOSE_DYNAMIC_NAME) {
        OPENSSL_free(ptmp->name);
        OPENSSL_free(ptmp->sname);
    }
    /* dup supplied name */
    ptmp->name = BUF_strdup(name);
    ptmp->sname = BUF_strdup(sname);
    if (!ptmp->name || !ptmp->sname) {
        X509V3err(X509V3_F_X509_PURPOSE_ADD, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    /* Keep the dynamic flag of existing entry */
    ptmp->flags &= X509_PURPOSE_DYNAMIC;
    /* Set all other flags */
    ptmp->flags |= flags;

    ptmp->purpose = id;
    ptmp->trust = trust;
    ptmp->check_purpose = ck;
    ptmp->usr_data = arg;

    /* If its a new entry manage the dynamic table */
    if (idx == -1) {
        if (!xptable && !(xptable = sk_X509_PURPOSE_new(xp_cmp))) {
            X509V3err(X509V3_F_X509_PURPOSE_ADD, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        if (!sk_X509_PURPOSE_push(xptable, ptmp)) {
            X509V3err(X509V3_F_X509_PURPOSE_ADD, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    }
    return 1;
}

static void xptable_free(X509_PURPOSE *p)
{
    if (!p)
        return;
    if (p->flags & X509_PURPOSE_DYNAMIC) {
        if (p->flags & X509_PURPOSE_DYNAMIC_NAME) {
            OPENSSL_free(p->name);
            OPENSSL_free(p->sname);
        }
        OPENSSL_free(p);
    }
}

void X509_PURPOSE_cleanup(void)
{
    unsigned int i;
    sk_X509_PURPOSE_pop_free(xptable, xptable_free);
    for (i = 0; i < X509_PURPOSE_COUNT; i++)
        xptable_free(xstandard + i);
    xptable = NULL;
}

int X509_PURPOSE_get_id(X509_PURPOSE *xp)
{
    return xp->purpose;
}

char *X509_PURPOSE_get0_name(X509_PURPOSE *xp)
{
    return xp->name;
}

char *X509_PURPOSE_get0_sname(X509_PURPOSE *xp)
{
    return xp->sname;
}

int X509_PURPOSE_get_trust(X509_PURPOSE *xp)
{
    return xp->trust;
}

static int nid_cmp(const int *a, const int *b)
{
    return *a - *b;
}

DECLARE_OBJ_BSEARCH_CMP_FN(int, int, nid);
IMPLEMENT_OBJ_BSEARCH_CMP_FN(int, int, nid);

int X509_supported_extension(X509_EXTENSION *ex)
{
    /*
     * This table is a list of the NIDs of supported extensions: that is
     * those which are used by the verify process. If an extension is
     * critical and doesn't appear in this list then the verify process will
     * normally reject the certificate. The list must be kept in numerical
     * order because it will be searched using bsearch.
     */

    static const int supported_nids[] = {
        NID_netscape_cert_type, /* 71 */
        NID_key_usage,          /* 83 */
        NID_subject_alt_name,   /* 85 */
        NID_basic_constraints,  /* 87 */
        NID_certificate_policies, /* 89 */
        NID_crl_distribution_points, /* 103 */
        NID_ext_key_usage,      /* 126 */
#ifndef OPENSSL_NO_RFC3779
        NID_sbgp_ipAddrBlock,   /* 290 */
        NID_sbgp_autonomousSysNum, /* 291 */
#endif
        NID_policy_constraints, /* 401 */
        NID_proxyCertInfo,      /* 663 */
        NID_name_constraints,   /* 666 */
        NID_policy_mappings,    /* 747 */
        NID_inhibit_any_policy  /* 748 */
    };

    int ex_nid = OBJ_obj2nid(X509_EXTENSION_get_object(ex));

    if (ex_nid == NID_undef)
        return 0;

    if (OBJ_bsearch_nid(&ex_nid, supported_nids,
                        sizeof(supported_nids) / sizeof(int)))
        return 1;
    return 0;
}

static void setup_dp(X509 *x, DIST_POINT *dp)
{
    X509_NAME *iname = NULL;
    int i;
    if (dp->reasons) {
        if (dp->reasons->length > 0)
            dp->dp_reasons = dp->reasons->data[0];
        if (dp->reasons->length > 1)
            dp->dp_reasons |= (dp->reasons->data[1] << 8);
        dp->dp_reasons &= CRLDP_ALL_REASONS;
    } else
        dp->dp_reasons = CRLDP_ALL_REASONS;
    if (!dp->distpoint || (dp->distpoint->type != 1))
        return;
    for (i = 0; i < sk_GENERAL_NAME_num(dp->CRLissuer); i++) {
        GENERAL_NAME *gen = sk_GENERAL_NAME_value(dp->CRLissuer, i);
        if (gen->type == GEN_DIRNAME) {
            iname = gen->d.directoryName;
            break;
        }
    }
    if (!iname)
        iname = X509_get_issuer_name(x);

    DIST_POINT_set_dpname(dp->distpoint, iname);

}

static void setup_crldp(X509 *x)
{
    int i;
    x->crldp = X509_get_ext_d2i(x, NID_crl_distribution_points, NULL, NULL);
    for (i = 0; i < sk_DIST_POINT_num(x->crldp); i++)
        setup_dp(x, sk_DIST_POINT_value(x->crldp, i));
}

#define V1_ROOT (EXFLAG_V1|EXFLAG_SS)
#define ku_reject(x, usage) \
        (((x)->ex_flags & EXFLAG_KUSAGE) && !((x)->ex_kusage & (usage)))
#define xku_reject(x, usage) \
        (((x)->ex_flags & EXFLAG_XKUSAGE) && !((x)->ex_xkusage & (usage)))
#define ns_reject(x, usage) \
        (((x)->ex_flags & EXFLAG_NSCERT) && !((x)->ex_nscert & (usage)))

static void x509v3_cache_extensions(X509 *x)
{
    BASIC_CONSTRAINTS *bs;
    PROXY_CERT_INFO_EXTENSION *pci;
    ASN1_BIT_STRING *usage;
    ASN1_BIT_STRING *ns;
    EXTENDED_KEY_USAGE *extusage;
    X509_EXTENSION *ex;
    int i;

    CRYPTO_w_lock(CRYPTO_LOCK_X509);
    if (x->ex_flags & EXFLAG_SET) {
        CRYPTO_w_unlock(CRYPTO_LOCK_X509);
        return;
    }

#ifndef OPENSSL_NO_SHA
    X509_digest(x, EVP_sha1(), x->sha1_hash, NULL);
#endif
    /* V1 should mean no extensions ... */
    if (!X509_get_version(x))
        x->ex_flags |= EXFLAG_V1;
    /* Handle basic constraints */
    if ((bs = X509_get_ext_d2i(x, NID_basic_constraints, NULL, NULL))) {
        if (bs->ca)
            x->ex_flags |= EXFLAG_CA;
        if (bs->pathlen) {
            if ((bs->pathlen->type == V_ASN1_NEG_INTEGER)
                || !bs->ca) {
                x->ex_flags |= EXFLAG_INVALID;
                x->ex_pathlen = 0;
            } else
                x->ex_pathlen = ASN1_INTEGER_get(bs->pathlen);
        } else
            x->ex_pathlen = -1;
        BASIC_CONSTRAINTS_free(bs);
        x->ex_flags |= EXFLAG_BCONS;
    }
    /* Handle proxy certificates */
    if ((pci = X509_get_ext_d2i(x, NID_proxyCertInfo, NULL, NULL))) {
        if (x->ex_flags & EXFLAG_CA
            || X509_get_ext_by_NID(x, NID_subject_alt_name, -1) >= 0
            || X509_get_ext_by_NID(x, NID_issuer_alt_name, -1) >= 0) {
            x->ex_flags |= EXFLAG_INVALID;
        }
        if (pci->pcPathLengthConstraint) {
            x->ex_pcpathlen = ASN1_INTEGER_get(pci->pcPathLengthConstraint);
        } else
            x->ex_pcpathlen = -1;
        PROXY_CERT_INFO_EXTENSION_free(pci);
        x->ex_flags |= EXFLAG_PROXY;
    }
    /* Handle key usage */
    if ((usage = X509_get_ext_d2i(x, NID_key_usage, NULL, NULL))) {
        if (usage->length > 0) {
            x->ex_kusage = usage->data[0];
            if (usage->length > 1)
                x->ex_kusage |= usage->data[1] << 8;
        } else
            x->ex_kusage = 0;
        x->ex_flags |= EXFLAG_KUSAGE;
        ASN1_BIT_STRING_free(usage);
    }
    x->ex_xkusage = 0;
    if ((extusage = X509_get_ext_d2i(x, NID_ext_key_usage, NULL, NULL))) {
        x->ex_flags |= EXFLAG_XKUSAGE;
        for (i = 0; i < sk_ASN1_OBJECT_num(extusage); i++) {
            switch (OBJ_obj2nid(sk_ASN1_OBJECT_value(extusage, i))) {
            case NID_server_auth:
                x->ex_xkusage |= XKU_SSL_SERVER;
                break;

            case NID_client_auth:
                x->ex_xkusage |= XKU_SSL_CLIENT;
                break;

            case NID_email_protect:
                x->ex_xkusage |= XKU_SMIME;
                break;

            case NID_code_sign:
                x->ex_xkusage |= XKU_CODE_SIGN;
                break;

            case NID_ms_sgc:
            case NID_ns_sgc:
                x->ex_xkusage |= XKU_SGC;
                break;

            case NID_OCSP_sign:
                x->ex_xkusage |= XKU_OCSP_SIGN;
                break;

            case NID_time_stamp:
                x->ex_xkusage |= XKU_TIMESTAMP;
                break;

            case NID_dvcs:
                x->ex_xkusage |= XKU_DVCS;
                break;

            case NID_anyExtendedKeyUsage:
                x->ex_xkusage |= XKU_ANYEKU;
                break;
            }
        }
        sk_ASN1_OBJECT_pop_free(extusage, ASN1_OBJECT_free);
    }

    if ((ns = X509_get_ext_d2i(x, NID_netscape_cert_type, NULL, NULL))) {
        if (ns->length > 0)
            x->ex_nscert = ns->data[0];
        else
            x->ex_nscert = 0;
        x->ex_flags |= EXFLAG_NSCERT;
        ASN1_BIT_STRING_free(ns);
    }
    x->skid = X509_get_ext_d2i(x, NID_subject_key_identifier, NULL, NULL);
    x->akid = X509_get_ext_d2i(x, NID_authority_key_identifier, NULL, NULL);
    /* Does subject name match issuer ? */
    if (!X509_NAME_cmp(X509_get_subject_name(x), X509_get_issuer_name(x))) {
        x->ex_flags |= EXFLAG_SI;
        /* If SKID matches AKID also indicate self signed */
        if (X509_check_akid(x, x->akid) == X509_V_OK &&
            !ku_reject(x, KU_KEY_CERT_SIGN))
            x->ex_flags |= EXFLAG_SS;
    }
    x->altname = X509_get_ext_d2i(x, NID_subject_alt_name, NULL, NULL);
    x->nc = X509_get_ext_d2i(x, NID_name_constraints, &i, NULL);
    if (!x->nc && (i != -1))
        x->ex_flags |= EXFLAG_INVALID;
    setup_crldp(x);

#ifndef OPENSSL_NO_RFC3779
    x->rfc3779_addr = X509_get_ext_d2i(x, NID_sbgp_ipAddrBlock, NULL, NULL);
    x->rfc3779_asid = X509_get_ext_d2i(x, NID_sbgp_autonomousSysNum,
                                       NULL, NULL);
#endif
    for (i = 0; i < X509_get_ext_count(x); i++) {
        ex = X509_get_ext(x, i);
        if (OBJ_obj2nid(X509_EXTENSION_get_object(ex))
            == NID_freshest_crl)
            x->ex_flags |= EXFLAG_FRESHEST;
        if (!X509_EXTENSION_get_critical(ex))
            continue;
        if (!X509_supported_extension(ex)) {
            x->ex_flags |= EXFLAG_CRITICAL;
            break;
        }
    }
    x->ex_flags |= EXFLAG_SET;
    CRYPTO_w_unlock(CRYPTO_LOCK_X509);
}

/*-
 * CA checks common to all purposes
 * return codes:
 * 0 not a CA
 * 1 is a CA
 * 2 basicConstraints absent so "maybe" a CA
 * 3 basicConstraints absent but self signed V1.
 * 4 basicConstraints absent but keyUsage present and keyCertSign asserted.
 */

static int check_ca(const X509 *x)
{
    /* keyUsage if present should allow cert signing */
    if (ku_reject(x, KU_KEY_CERT_SIGN))
        return 0;
    if (x->ex_flags & EXFLAG_BCONS) {
        if (x->ex_flags & EXFLAG_CA)
            return 1;
        /* If basicConstraints says not a CA then say so */
        else
            return 0;
    } else {
        /* we support V1 roots for...  uh, I don't really know why. */
        if ((x->ex_flags & V1_ROOT) == V1_ROOT)
            return 3;
        /*
         * If key usage present it must have certSign so tolerate it
         */
        else if (x->ex_flags & EXFLAG_KUSAGE)
            return 4;
        /* Older certificates could have Netscape-specific CA types */
        else if (x->ex_flags & EXFLAG_NSCERT && x->ex_nscert & NS_ANY_CA)
            return 5;
        /* can this still be regarded a CA certificate?  I doubt it */
        return 0;
    }
}

int X509_check_ca(X509 *x)
{
    x509v3_cache_extensions(x);

    return check_ca(x);
}

/* Check SSL CA: common checks for SSL client and server */
static int check_ssl_ca(const X509 *x)
{
    int ca_ret;
    ca_ret = check_ca(x);
    if (!ca_ret)
        return 0;
    /* check nsCertType if present */
    if (ca_ret != 5 || x->ex_nscert & NS_SSL_CA)
        return ca_ret;
    else
        return 0;
}

static int check_purpose_ssl_client(const X509_PURPOSE *xp, const X509 *x,
                                    int ca)
{
    if (xku_reject(x, XKU_SSL_CLIENT))
        return 0;
    if (ca)
        return check_ssl_ca(x);
    /* We need to do digital signatures or key agreement */
    if (ku_reject(x, KU_DIGITAL_SIGNATURE | KU_KEY_AGREEMENT))
        return 0;
    /* nsCertType if present should allow SSL client use */
    if (ns_reject(x, NS_SSL_CLIENT))
        return 0;
    return 1;
}

/*
 * Key usage needed for TLS/SSL server: digital signature, encipherment or
 * key agreement. The ssl code can check this more thoroughly for individual
 * key types.
 */
#define KU_TLS \
        KU_DIGITAL_SIGNATURE|KU_KEY_ENCIPHERMENT|KU_KEY_AGREEMENT

static int check_purpose_ssl_server(const X509_PURPOSE *xp, const X509 *x,
                                    int ca)
{
    if (xku_reject(x, XKU_SSL_SERVER | XKU_SGC))
        return 0;
    if (ca)
        return check_ssl_ca(x);

    if (ns_reject(x, NS_SSL_SERVER))
        return 0;
    if (ku_reject(x, KU_TLS))
        return 0;

    return 1;

}

static int check_purpose_ns_ssl_server(const X509_PURPOSE *xp, const X509 *x,
                                       int ca)
{
    int ret;
    ret = check_purpose_ssl_server(xp, x, ca);
    if (!ret || ca)
        return ret;
    /* We need to encipher or Netscape complains */
    if (ku_reject(x, KU_KEY_ENCIPHERMENT))
        return 0;
    return ret;
}

/* common S/MIME checks */
static int purpose_smime(const X509 *x, int ca)
{
    if (xku_reject(x, XKU_SMIME))
        return 0;
    if (ca) {
        int ca_ret;
        ca_ret = check_ca(x);
        if (!ca_ret)
            return 0;
        /* check nsCertType if present */
        if (ca_ret != 5 || x->ex_nscert & NS_SMIME_CA)
            return ca_ret;
        else
            return 0;
    }
    if (x->ex_flags & EXFLAG_NSCERT) {
        if (x->ex_nscert & NS_SMIME)
            return 1;
        /* Workaround for some buggy certificates */
        if (x->ex_nscert & NS_SSL_CLIENT)
            return 2;
        return 0;
    }
    return 1;
}

static int check_purpose_smime_sign(const X509_PURPOSE *xp, const X509 *x,
                                    int ca)
{
    int ret;
    ret = purpose_smime(x, ca);
    if (!ret || ca)
        return ret;
    if (ku_reject(x, KU_DIGITAL_SIGNATURE | KU_NON_REPUDIATION))
        return 0;
    return ret;
}

static int check_purpose_smime_encrypt(const X509_PURPOSE *xp, const X509 *x,
                                       int ca)
{
    int ret;
    ret = purpose_smime(x, ca);
    if (!ret || ca)
        return ret;
    if (ku_reject(x, KU_KEY_ENCIPHERMENT))
        return 0;
    return ret;
}

static int check_purpose_crl_sign(const X509_PURPOSE *xp, const X509 *x,
                                  int ca)
{
    if (ca) {
        int ca_ret;
        if ((ca_ret = check_ca(x)) != 2)
            return ca_ret;
        else
            return 0;
    }
    if (ku_reject(x, KU_CRL_SIGN))
        return 0;
    return 1;
}

/*
 * OCSP helper: this is *not* a full OCSP check. It just checks that each CA
 * is valid. Additional checks must be made on the chain.
 */

static int ocsp_helper(const X509_PURPOSE *xp, const X509 *x, int ca)
{
    /*
     * Must be a valid CA.  Should we really support the "I don't know" value
     * (2)?
     */
    if (ca)
        return check_ca(x);
    /* leaf certificate is checked in OCSP_verify() */
    return 1;
}

static int check_purpose_timestamp_sign(const X509_PURPOSE *xp, const X509 *x,
                                        int ca)
{
    int i_ext;

    /* If ca is true we must return if this is a valid CA certificate. */
    if (ca)
        return check_ca(x);

    /*
     * Check the optional key usage field:
     * if Key Usage is present, it must be one of digitalSignature
     * and/or nonRepudiation (other values are not consistent and shall
     * be rejected).
     */
    if ((x->ex_flags & EXFLAG_KUSAGE)
        && ((x->ex_kusage & ~(KU_NON_REPUDIATION | KU_DIGITAL_SIGNATURE)) ||
            !(x->ex_kusage & (KU_NON_REPUDIATION | KU_DIGITAL_SIGNATURE))))
        return 0;

    /* Only time stamp key usage is permitted and it's required. */
    if (!(x->ex_flags & EXFLAG_XKUSAGE) || x->ex_xkusage != XKU_TIMESTAMP)
        return 0;

    /* Extended Key Usage MUST be critical */
    i_ext = X509_get_ext_by_NID((X509 *)x, NID_ext_key_usage, -1);
    if (i_ext >= 0) {
        X509_EXTENSION *ext = X509_get_ext((X509 *)x, i_ext);
        if (!X509_EXTENSION_get_critical(ext))
            return 0;
    }

    return 1;
}

static int no_check(const X509_PURPOSE *xp, const X509 *x, int ca)
{
    return 1;
}

/*-
 * Various checks to see if one certificate issued the second.
 * This can be used to prune a set of possible issuer certificates
 * which have been looked up using some simple method such as by
 * subject name.
 * These are:
 * 1. Check issuer_name(subject) == subject_name(issuer)
 * 2. If akid(subject) exists check it matches issuer
 * 3. If key_usage(issuer) exists check it supports certificate signing
 * returns 0 for OK, positive for reason for mismatch, reasons match
 * codes for X509_verify_cert()
 */

int X509_check_issued(X509 *issuer, X509 *subject)
{
    if (X509_NAME_cmp(X509_get_subject_name(issuer),
                      X509_get_issuer_name(subject)))
        return X509_V_ERR_SUBJECT_ISSUER_MISMATCH;

    x509v3_cache_extensions(issuer);
    x509v3_cache_extensions(subject);

    if (subject->akid) {
        int ret = X509_check_akid(issuer, subject->akid);
        if (ret != X509_V_OK)
            return ret;
    }

    if (subject->ex_flags & EXFLAG_PROXY) {
        if (ku_reject(issuer, KU_DIGITAL_SIGNATURE))
            return X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE;
    } else if (ku_reject(issuer, KU_KEY_CERT_SIGN))
        return X509_V_ERR_KEYUSAGE_NO_CERTSIGN;
    return X509_V_OK;
}

int X509_check_akid(X509 *issuer, AUTHORITY_KEYID *akid)
{

    if (!akid)
        return X509_V_OK;

    /* Check key ids (if present) */
    if (akid->keyid && issuer->skid &&
        ASN1_OCTET_STRING_cmp(akid->keyid, issuer->skid))
        return X509_V_ERR_AKID_SKID_MISMATCH;
    /* Check serial number */
    if (akid->serial &&
        ASN1_INTEGER_cmp(X509_get_serialNumber(issuer), akid->serial))
        return X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH;
    /* Check issuer name */
    if (akid->issuer) {
        /*
         * Ugh, for some peculiar reason AKID includes SEQUENCE OF
         * GeneralName. So look for a DirName. There may be more than one but
         * we only take any notice of the first.
         */
        GENERAL_NAMES *gens;
        GENERAL_NAME *gen;
        X509_NAME *nm = NULL;
        int i;
        gens = akid->issuer;
        for (i = 0; i < sk_GENERAL_NAME_num(gens); i++) {
            gen = sk_GENERAL_NAME_value(gens, i);
            if (gen->type == GEN_DIRNAME) {
                nm = gen->d.dirn;
                break;
            }
        }
        if (nm && X509_NAME_cmp(nm, X509_get_issuer_name(issuer)))
            return X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH;
    }
    return X509_V_OK;
}
/* v3_scts.c */
/*
 * Written by Rob Stradling (rob@comodo.com) for the OpenSSL project 2014.
 */
/* ====================================================================
 * Copyright (c) 2014 The OpenSSL Project.  All rights reserved.
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
// #include "asn1.h"
// #include "x509v3.h"

/* Signature and hash algorithms from RFC 5246 */
#define TLSEXT_hash_sha256                              4

#define TLSEXT_signature_rsa                            1
#define TLSEXT_signature_ecdsa                          3


#define n2s(c,s)        ((s=(((unsigned int)(c[0]))<< 8)| \
                            (((unsigned int)(c[1]))    )),c+=2)

#if (defined(_WIN32) || defined(_WIN64)) && !defined(__MINGW32__)
# define SCT_TIMESTAMP unsigned __int64
#elif defined(__arch64__)
# define SCT_TIMESTAMP unsigned long
#else
# define SCT_TIMESTAMP unsigned long long
#endif

#define n2l8(c,l)       (l =((SCT_TIMESTAMP)(*((c)++)))<<56, \
                         l|=((SCT_TIMESTAMP)(*((c)++)))<<48, \
                         l|=((SCT_TIMESTAMP)(*((c)++)))<<40, \
                         l|=((SCT_TIMESTAMP)(*((c)++)))<<32, \
                         l|=((SCT_TIMESTAMP)(*((c)++)))<<24, \
                         l|=((SCT_TIMESTAMP)(*((c)++)))<<16, \
                         l|=((SCT_TIMESTAMP)(*((c)++)))<< 8, \
                         l|=((SCT_TIMESTAMP)(*((c)++))))

typedef struct SCT_st {
    /* The encoded SCT */
    unsigned char *sct;
    unsigned short sctlen;
    /*
     * Components of the SCT.  "logid", "ext" and "sig" point to addresses
     * inside "sct".
     */
    unsigned char version;
    unsigned char *logid;
    unsigned short logidlen;
    SCT_TIMESTAMP timestamp;
    unsigned char *ext;
    unsigned short extlen;
    unsigned char hash_alg;
    unsigned char sig_alg;
    unsigned char *sig;
    unsigned short siglen;
} SCT;

DECLARE_STACK_OF(SCT)

static void SCT_LIST_free(STACK_OF(SCT) *a);
static STACK_OF(SCT) *d2i_SCT_LIST(STACK_OF(SCT) **a,
                                   const unsigned char **pp, long length);
static int i2r_SCT_LIST(X509V3_EXT_METHOD *method, STACK_OF(SCT) *sct_list,
                        BIO *out, int indent);

const X509V3_EXT_METHOD v3_ct_scts[] = {
    {NID_ct_precert_scts, 0, NULL,
     0, (X509V3_EXT_FREE)SCT_LIST_free,
     (X509V3_EXT_D2I)d2i_SCT_LIST, 0,
     0, 0, 0, 0,
     (X509V3_EXT_I2R)i2r_SCT_LIST, 0,
     NULL},

    {NID_ct_cert_scts, 0, NULL,
     0, (X509V3_EXT_FREE)SCT_LIST_free,
     (X509V3_EXT_D2I)d2i_SCT_LIST, 0,
     0, 0, 0, 0,
     (X509V3_EXT_I2R)i2r_SCT_LIST, 0,
     NULL},
};

static void tls12_signature_print(BIO *out, const unsigned char hash_alg,
                                  const unsigned char sig_alg)
{
    int nid = NID_undef;
    /* RFC6962 only permits two signature algorithms */
    if (hash_alg == TLSEXT_hash_sha256) {
        if (sig_alg == TLSEXT_signature_rsa)
            nid = NID_sha256WithRSAEncryption;
        else if (sig_alg == TLSEXT_signature_ecdsa)
            nid = NID_ecdsa_with_SHA256;
    }
    if (nid == NID_undef)
        BIO_printf(out, "%02X%02X", hash_alg, sig_alg);
    else
        BIO_printf(out, "%s", OBJ_nid2ln(nid));
}

static void timestamp_print(BIO *out, SCT_TIMESTAMP timestamp)
{
    ASN1_GENERALIZEDTIME *gen;
    char genstr[20];
    gen = ASN1_GENERALIZEDTIME_new();
    ASN1_GENERALIZEDTIME_adj(gen, (time_t)0,
                             (int)(timestamp / 86400000),
                             (int)(timestamp % 86400000) / 1000);
    /*
     * Note GeneralizedTime from ASN1_GENERALIZETIME_adj is always 15
     * characters long with a final Z. Update it with fractional seconds.
     */
    BIO_snprintf(genstr, sizeof(genstr), "%.14s.%03dZ",
                 ASN1_STRING_data(gen), (unsigned int)(timestamp % 1000));
    ASN1_GENERALIZEDTIME_set_string(gen, genstr);
    ASN1_GENERALIZEDTIME_print(out, gen);
    ASN1_GENERALIZEDTIME_free(gen);
}

static void SCT_free(SCT *sct)
{
    if (sct) {
        if (sct->sct)
            OPENSSL_free(sct->sct);
        OPENSSL_free(sct);
    }
}

static void SCT_LIST_free(STACK_OF(SCT) *a)
{
    sk_SCT_pop_free(a, SCT_free);
}

static STACK_OF(SCT) *d2i_SCT_LIST(STACK_OF(SCT) **a,
                                   const unsigned char **pp, long length)
{
    ASN1_OCTET_STRING *oct = NULL;
    STACK_OF(SCT) *sk = NULL;
    SCT *sct;
    unsigned char *p, *p2;
    unsigned short listlen, sctlen = 0, fieldlen;
    const unsigned char *q = *pp;

    if (d2i_ASN1_OCTET_STRING(&oct, &q, length) == NULL)
        return NULL;
    if (oct->length < 2)
        goto done;
    p = oct->data;
    n2s(p, listlen);
    if (listlen != oct->length - 2)
        goto done;

    if ((sk = sk_SCT_new_null()) == NULL)
        goto done;

    while (listlen > 0) {
        if (listlen < 2)
            goto err;
        n2s(p, sctlen);
        listlen -= 2;

        if ((sctlen < 1) || (sctlen > listlen))
            goto err;
        listlen -= sctlen;

        sct = OPENSSL_malloc(sizeof(SCT));
        if (!sct)
            goto err;
        if (!sk_SCT_push(sk, sct)) {
            OPENSSL_free(sct);
            goto err;
        }

        sct->sct = OPENSSL_malloc(sctlen);
        if (!sct->sct)
            goto err;
        memcpy(sct->sct, p, sctlen);
        sct->sctlen = sctlen;
        p += sctlen;
        p2 = sct->sct;

        sct->version = *p2++;
        if (sct->version == 0) { /* SCT v1 */
            /*-
             * Fixed-length header:
             *              struct {
             * (1 byte)       Version sct_version;
             * (32 bytes)     LogID id;
             * (8 bytes)      uint64 timestamp;
             * (2 bytes + ?)  CtExtensions extensions;
             */
            if (sctlen < 43)
                goto err;
            sctlen -= 43;

            sct->logid = p2;
            sct->logidlen = 32;
            p2 += 32;

            n2l8(p2, sct->timestamp);

            n2s(p2, fieldlen);
            if (sctlen < fieldlen)
                goto err;
            sct->ext = p2;
            sct->extlen = fieldlen;
            p2 += fieldlen;
            sctlen -= fieldlen;

            /*-
             * digitally-signed struct header:
             * (1 byte)       Hash algorithm
             * (1 byte)       Signature algorithm
             * (2 bytes + ?)  Signature
             */
            if (sctlen < 4)
                goto err;
            sctlen -= 4;

            sct->hash_alg = *p2++;
            sct->sig_alg = *p2++;
            n2s(p2, fieldlen);
            if (sctlen != fieldlen)
                goto err;
            sct->sig = p2;
            sct->siglen = fieldlen;
        }
    }

 done:
    ASN1_OCTET_STRING_free(oct);
    *pp = q;
    return sk;

 err:
    SCT_LIST_free(sk);
    sk = NULL;
    goto done;
}

static int i2r_SCT_LIST(X509V3_EXT_METHOD *method, STACK_OF(SCT) *sct_list,
                        BIO *out, int indent)
{
    SCT *sct;
    int i;

    for (i = 0; i < sk_SCT_num(sct_list);) {
        sct = sk_SCT_value(sct_list, i);

        BIO_printf(out, "%*sSigned Certificate Timestamp:", indent, "");
        BIO_printf(out, "\n%*sVersion   : ", indent + 4, "");

        if (sct->version == 0) { /* SCT v1 */
            BIO_printf(out, "v1(0)");

            BIO_printf(out, "\n%*sLog ID    : ", indent + 4, "");
            BIO_hex_string(out, indent + 16, 16, sct->logid, sct->logidlen);

            BIO_printf(out, "\n%*sTimestamp : ", indent + 4, "");
            timestamp_print(out, sct->timestamp);

            BIO_printf(out, "\n%*sExtensions: ", indent + 4, "");
            if (sct->extlen == 0)
                BIO_printf(out, "none");
            else
                BIO_hex_string(out, indent + 16, 16, sct->ext, sct->extlen);

            BIO_printf(out, "\n%*sSignature : ", indent + 4, "");
            tls12_signature_print(out, sct->hash_alg, sct->sig_alg);
            BIO_printf(out, "\n%*s            ", indent + 4, "");
            BIO_hex_string(out, indent + 16, 16, sct->sig, sct->siglen);
        } else {                /* Unknown version */

            BIO_printf(out, "unknown\n%*s", indent + 16, "");
            BIO_hex_string(out, indent + 16, 16, sct->sct, sct->sctlen);
        }

        if (++i < sk_SCT_num(sct_list))
            BIO_printf(out, "\n");
    }

    return 1;
}
/* v3_skey.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 1999.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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
// #include "x509v3.h"

static ASN1_OCTET_STRING *s2i_skey_id(X509V3_EXT_METHOD *method,
                                      X509V3_CTX *ctx, char *str);
const X509V3_EXT_METHOD v3_skey_id = {
    NID_subject_key_identifier, 0, ASN1_ITEM_ref(ASN1_OCTET_STRING),
    0, 0, 0, 0,
    (X509V3_EXT_I2S)i2s_ASN1_OCTET_STRING,
    (X509V3_EXT_S2I)s2i_skey_id,
    0, 0, 0, 0,
    NULL
};

char *i2s_ASN1_OCTET_STRING(X509V3_EXT_METHOD *method, ASN1_OCTET_STRING *oct)
{
    return hex_to_string(oct->data, oct->length);
}

ASN1_OCTET_STRING *s2i_ASN1_OCTET_STRING(X509V3_EXT_METHOD *method,
                                         X509V3_CTX *ctx, char *str)
{
    ASN1_OCTET_STRING *oct;
    long length;

    if (!(oct = M_ASN1_OCTET_STRING_new())) {
        X509V3err(X509V3_F_S2I_ASN1_OCTET_STRING, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (!(oct->data = string_to_hex(str, &length))) {
        M_ASN1_OCTET_STRING_free(oct);
        return NULL;
    }

    oct->length = length;

    return oct;

}

static ASN1_OCTET_STRING *s2i_skey_id(X509V3_EXT_METHOD *method,
                                      X509V3_CTX *ctx, char *str)
{
    ASN1_OCTET_STRING *oct;
    ASN1_BIT_STRING *pk;
    unsigned char pkey_dig[EVP_MAX_MD_SIZE];
    unsigned int diglen;

    if (strcmp(str, "hash"))
        return s2i_ASN1_OCTET_STRING(method, ctx, str);

    if (!(oct = M_ASN1_OCTET_STRING_new())) {
        X509V3err(X509V3_F_S2I_SKEY_ID, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (ctx && (ctx->flags == CTX_TEST))
        return oct;

    if (!ctx || (!ctx->subject_req && !ctx->subject_cert)) {
        X509V3err(X509V3_F_S2I_SKEY_ID, X509V3_R_NO_PUBLIC_KEY);
        goto err;
    }

    if (ctx->subject_req)
        pk = ctx->subject_req->req_info->pubkey->public_key;
    else
        pk = ctx->subject_cert->cert_info->key->public_key;

    if (!pk) {
        X509V3err(X509V3_F_S2I_SKEY_ID, X509V3_R_NO_PUBLIC_KEY);
        goto err;
    }

    if (!EVP_Digest
        (pk->data, pk->length, pkey_dig, &diglen, EVP_sha1(), NULL))
        goto err;

    if (!M_ASN1_OCTET_STRING_set(oct, pkey_dig, diglen)) {
        X509V3err(X509V3_F_S2I_SKEY_ID, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    return oct;

 err:
    M_ASN1_OCTET_STRING_free(oct);
    return NULL;
}
/* v3_sxnet.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 1999.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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
// #include "conf.h"
// #include "asn1.h"
// #include "asn1t.h"
// #include "x509v3.h"

/* Support for Thawte strong extranet extension */

#define SXNET_TEST

static int sxnet_i2r(X509V3_EXT_METHOD *method, SXNET *sx, BIO *out,
                     int indent);
#ifdef SXNET_TEST
static SXNET *sxnet_v2i(X509V3_EXT_METHOD *method, X509V3_CTX *ctx,
                        STACK_OF(CONF_VALUE) *nval);
#endif
const X509V3_EXT_METHOD v3_sxnet = {
    NID_sxnet, X509V3_EXT_MULTILINE, ASN1_ITEM_ref(SXNET),
    0, 0, 0, 0,
    0, 0,
    0,
#ifdef SXNET_TEST
    (X509V3_EXT_V2I)sxnet_v2i,
#else
    0,
#endif
    (X509V3_EXT_I2R)sxnet_i2r,
    0,
    NULL
};

ASN1_SEQUENCE(SXNETID) = {
        ASN1_SIMPLE(SXNETID, zone, ASN1_INTEGER),
        ASN1_SIMPLE(SXNETID, user, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(SXNETID)

IMPLEMENT_ASN1_FUNCTIONS(SXNETID)

ASN1_SEQUENCE(SXNET) = {
        ASN1_SIMPLE(SXNET, version, ASN1_INTEGER),
        ASN1_SEQUENCE_OF(SXNET, ids, SXNETID)
} ASN1_SEQUENCE_END(SXNET)

IMPLEMENT_ASN1_FUNCTIONS(SXNET)

static int sxnet_i2r(X509V3_EXT_METHOD *method, SXNET *sx, BIO *out,
                     int indent)
{
    long v;
    char *tmp;
    SXNETID *id;
    int i;
    v = ASN1_INTEGER_get(sx->version);
    BIO_printf(out, "%*sVersion: %ld (0x%lX)", indent, "", v + 1, v);
    for (i = 0; i < sk_SXNETID_num(sx->ids); i++) {
        id = sk_SXNETID_value(sx->ids, i);
        tmp = i2s_ASN1_INTEGER(NULL, id->zone);
        BIO_printf(out, "\n%*sZone: %s, User: ", indent, "", tmp);
        OPENSSL_free(tmp);
        M_ASN1_OCTET_STRING_print(out, id->user);
    }
    return 1;
}

#ifdef SXNET_TEST

/*
 * NBB: this is used for testing only. It should *not* be used for anything
 * else because it will just take static IDs from the configuration file and
 * they should really be separate values for each user.
 */

static SXNET *sxnet_v2i(X509V3_EXT_METHOD *method, X509V3_CTX *ctx,
                        STACK_OF(CONF_VALUE) *nval)
{
    CONF_VALUE *cnf;
    SXNET *sx = NULL;
    int i;
    for (i = 0; i < sk_CONF_VALUE_num(nval); i++) {
        cnf = sk_CONF_VALUE_value(nval, i);
        if (!SXNET_add_id_asc(&sx, cnf->name, cnf->value, -1))
            return NULL;
    }
    return sx;
}

#endif

/* Strong Extranet utility functions */

/* Add an id given the zone as an ASCII number */

int SXNET_add_id_asc(SXNET **psx, char *zone, char *user, int userlen)
{
    ASN1_INTEGER *izone = NULL;
    if (!(izone = s2i_ASN1_INTEGER(NULL, zone))) {
        X509V3err(X509V3_F_SXNET_ADD_ID_ASC, X509V3_R_ERROR_CONVERTING_ZONE);
        return 0;
    }
    return SXNET_add_id_INTEGER(psx, izone, user, userlen);
}

/* Add an id given the zone as an unsigned long */

int SXNET_add_id_ulong(SXNET **psx, unsigned long lzone, char *user,
                       int userlen)
{
    ASN1_INTEGER *izone = NULL;
    if (!(izone = M_ASN1_INTEGER_new()) || !ASN1_INTEGER_set(izone, lzone)) {
        X509V3err(X509V3_F_SXNET_ADD_ID_ULONG, ERR_R_MALLOC_FAILURE);
        M_ASN1_INTEGER_free(izone);
        return 0;
    }
    return SXNET_add_id_INTEGER(psx, izone, user, userlen);

}

/*
 * Add an id given the zone as an ASN1_INTEGER. Note this version uses the
 * passed integer and doesn't make a copy so don't free it up afterwards.
 */

int SXNET_add_id_INTEGER(SXNET **psx, ASN1_INTEGER *zone, char *user,
                         int userlen)
{
    SXNET *sx = NULL;
    SXNETID *id = NULL;
    if (!psx || !zone || !user) {
        X509V3err(X509V3_F_SXNET_ADD_ID_INTEGER,
                  X509V3_R_INVALID_NULL_ARGUMENT);
        return 0;
    }
    if (userlen == -1)
        userlen = strlen(user);
    if (userlen > 64) {
        X509V3err(X509V3_F_SXNET_ADD_ID_INTEGER, X509V3_R_USER_TOO_LONG);
        return 0;
    }
    if (!*psx) {
        if (!(sx = SXNET_new()))
            goto err;
        if (!ASN1_INTEGER_set(sx->version, 0))
            goto err;
        *psx = sx;
    } else
        sx = *psx;
    if (SXNET_get_id_INTEGER(sx, zone)) {
        X509V3err(X509V3_F_SXNET_ADD_ID_INTEGER, X509V3_R_DUPLICATE_ZONE_ID);
        return 0;
    }

    if (!(id = SXNETID_new()))
        goto err;
    if (userlen == -1)
        userlen = strlen(user);

    if (!M_ASN1_OCTET_STRING_set(id->user, user, userlen))
        goto err;
    if (!sk_SXNETID_push(sx->ids, id))
        goto err;
    id->zone = zone;
    return 1;

 err:
    X509V3err(X509V3_F_SXNET_ADD_ID_INTEGER, ERR_R_MALLOC_FAILURE);
    SXNETID_free(id);
    SXNET_free(sx);
    *psx = NULL;
    return 0;
}

ASN1_OCTET_STRING *SXNET_get_id_asc(SXNET *sx, char *zone)
{
    ASN1_INTEGER *izone = NULL;
    ASN1_OCTET_STRING *oct;
    if (!(izone = s2i_ASN1_INTEGER(NULL, zone))) {
        X509V3err(X509V3_F_SXNET_GET_ID_ASC, X509V3_R_ERROR_CONVERTING_ZONE);
        return NULL;
    }
    oct = SXNET_get_id_INTEGER(sx, izone);
    M_ASN1_INTEGER_free(izone);
    return oct;
}

ASN1_OCTET_STRING *SXNET_get_id_ulong(SXNET *sx, unsigned long lzone)
{
    ASN1_INTEGER *izone = NULL;
    ASN1_OCTET_STRING *oct;
    if (!(izone = M_ASN1_INTEGER_new()) || !ASN1_INTEGER_set(izone, lzone)) {
        X509V3err(X509V3_F_SXNET_GET_ID_ULONG, ERR_R_MALLOC_FAILURE);
        M_ASN1_INTEGER_free(izone);
        return NULL;
    }
    oct = SXNET_get_id_INTEGER(sx, izone);
    M_ASN1_INTEGER_free(izone);
    return oct;
}

ASN1_OCTET_STRING *SXNET_get_id_INTEGER(SXNET *sx, ASN1_INTEGER *zone)
{
    SXNETID *id;
    int i;
    for (i = 0; i < sk_SXNETID_num(sx->ids); i++) {
        id = sk_SXNETID_value(sx->ids, i);
        if (!M_ASN1_INTEGER_cmp(id->zone, zone))
            return id->user;
    }
    return NULL;
}

IMPLEMENT_STACK_OF(SXNETID)

IMPLEMENT_ASN1_SET_OF(SXNETID)
/* v3_utl.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 1999-2003 The OpenSSL Project.  All rights reserved.
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
/* X509 v3 extension utilities */

#include <stdio.h>
#include <ctype.h>
// #include "cryptlib.h"
// #include "conf.h"
// #include "x509v3.h"
// #include "bn.h"

static char *strip_spaces(char *name);
static int sk_strcmp(const char *const *a, const char *const *b);
static STACK_OF(OPENSSL_STRING) *get_email(X509_NAME *name,
                                           GENERAL_NAMES *gens);
static void str_free(OPENSSL_STRING str);
static int append_ia5(STACK_OF(OPENSSL_STRING) **sk, ASN1_IA5STRING *email);

static int ipv4_from_asc(unsigned char *v4, const char *in);
static int ipv6_from_asc(unsigned char *v6, const char *in);
static int ipv6_cb(const char *elem, int len, void *usr);
static int ipv6_hex(unsigned char *out, const char *in, int inlen);

/* Add a CONF_VALUE name value pair to stack */

int X509V3_add_value(const char *name, const char *value,
                     STACK_OF(CONF_VALUE) **extlist)
{
    CONF_VALUE *vtmp = NULL;
    char *tname = NULL, *tvalue = NULL;
    if (name && !(tname = BUF_strdup(name)))
        goto err;
    if (value && !(tvalue = BUF_strdup(value)))
        goto err;
    if (!(vtmp = (CONF_VALUE *)OPENSSL_malloc(sizeof(CONF_VALUE))))
        goto err;
    if (!*extlist && !(*extlist = sk_CONF_VALUE_new_null()))
        goto err;
    vtmp->section = NULL;
    vtmp->name = tname;
    vtmp->value = tvalue;
    if (!sk_CONF_VALUE_push(*extlist, vtmp))
        goto err;
    return 1;
 err:
    X509V3err(X509V3_F_X509V3_ADD_VALUE, ERR_R_MALLOC_FAILURE);
    if (vtmp)
        OPENSSL_free(vtmp);
    if (tname)
        OPENSSL_free(tname);
    if (tvalue)
        OPENSSL_free(tvalue);
    return 0;
}

int X509V3_add_value_uchar(const char *name, const unsigned char *value,
                           STACK_OF(CONF_VALUE) **extlist)
{
    return X509V3_add_value(name, (const char *)value, extlist);
}

/* Free function for STACK_OF(CONF_VALUE) */

void X509V3_conf_free(CONF_VALUE *conf)
{
    if (!conf)
        return;
    if (conf->name)
        OPENSSL_free(conf->name);
    if (conf->value)
        OPENSSL_free(conf->value);
    if (conf->section)
        OPENSSL_free(conf->section);
    OPENSSL_free(conf);
}

int X509V3_add_value_bool(const char *name, int asn1_bool,
                          STACK_OF(CONF_VALUE) **extlist)
{
    if (asn1_bool)
        return X509V3_add_value(name, "TRUE", extlist);
    return X509V3_add_value(name, "FALSE", extlist);
}

int X509V3_add_value_bool_nf(char *name, int asn1_bool,
                             STACK_OF(CONF_VALUE) **extlist)
{
    if (asn1_bool)
        return X509V3_add_value(name, "TRUE", extlist);
    return 1;
}

char *i2s_ASN1_ENUMERATED(X509V3_EXT_METHOD *method, ASN1_ENUMERATED *a)
{
    BIGNUM *bntmp = NULL;
    char *strtmp = NULL;
    if (!a)
        return NULL;
    if (!(bntmp = ASN1_ENUMERATED_to_BN(a, NULL)) ||
        !(strtmp = BN_bn2dec(bntmp)))
        X509V3err(X509V3_F_I2S_ASN1_ENUMERATED, ERR_R_MALLOC_FAILURE);
    BN_free(bntmp);
    return strtmp;
}

char *i2s_ASN1_INTEGER(X509V3_EXT_METHOD *method, ASN1_INTEGER *a)
{
    BIGNUM *bntmp = NULL;
    char *strtmp = NULL;
    if (!a)
        return NULL;
    if (!(bntmp = ASN1_INTEGER_to_BN(a, NULL)) ||
        !(strtmp = BN_bn2dec(bntmp)))
        X509V3err(X509V3_F_I2S_ASN1_INTEGER, ERR_R_MALLOC_FAILURE);
    BN_free(bntmp);
    return strtmp;
}

ASN1_INTEGER *s2i_ASN1_INTEGER(X509V3_EXT_METHOD *method, char *value)
{
    BIGNUM *bn = NULL;
    ASN1_INTEGER *aint;
    int isneg, ishex;
    int ret;
    if (!value) {
        X509V3err(X509V3_F_S2I_ASN1_INTEGER, X509V3_R_INVALID_NULL_VALUE);
        return 0;
    }
    bn = BN_new();
    if (value[0] == '-') {
        value++;
        isneg = 1;
    } else
        isneg = 0;

    if (value[0] == '0' && ((value[1] == 'x') || (value[1] == 'X'))) {
        value += 2;
        ishex = 1;
    } else
        ishex = 0;

    if (ishex)
        ret = BN_hex2bn(&bn, value);
    else
        ret = BN_dec2bn(&bn, value);

    if (!ret || value[ret]) {
        BN_free(bn);
        X509V3err(X509V3_F_S2I_ASN1_INTEGER, X509V3_R_BN_DEC2BN_ERROR);
        return 0;
    }

    if (isneg && BN_is_zero(bn))
        isneg = 0;

    aint = BN_to_ASN1_INTEGER(bn, NULL);
    BN_free(bn);
    if (!aint) {
        X509V3err(X509V3_F_S2I_ASN1_INTEGER,
                  X509V3_R_BN_TO_ASN1_INTEGER_ERROR);
        return 0;
    }
    if (isneg)
        aint->type |= V_ASN1_NEG;
    return aint;
}

int X509V3_add_value_int(const char *name, ASN1_INTEGER *aint,
                         STACK_OF(CONF_VALUE) **extlist)
{
    char *strtmp;
    int ret;
    if (!aint)
        return 1;
    if (!(strtmp = i2s_ASN1_INTEGER(NULL, aint)))
        return 0;
    ret = X509V3_add_value(name, strtmp, extlist);
    OPENSSL_free(strtmp);
    return ret;
}

int X509V3_get_value_bool(CONF_VALUE *value, int *asn1_bool)
{
    char *btmp;
    if (!(btmp = value->value))
        goto err;
    if (!strcmp(btmp, "TRUE") || !strcmp(btmp, "true")
        || !strcmp(btmp, "Y") || !strcmp(btmp, "y")
        || !strcmp(btmp, "YES") || !strcmp(btmp, "yes")) {
        *asn1_bool = 0xff;
        return 1;
    } else if (!strcmp(btmp, "FALSE") || !strcmp(btmp, "false")
               || !strcmp(btmp, "N") || !strcmp(btmp, "n")
               || !strcmp(btmp, "NO") || !strcmp(btmp, "no")) {
        *asn1_bool = 0;
        return 1;
    }
 err:
    X509V3err(X509V3_F_X509V3_GET_VALUE_BOOL,
              X509V3_R_INVALID_BOOLEAN_STRING);
    X509V3_conf_err(value);
    return 0;
}

int X509V3_get_value_int(CONF_VALUE *value, ASN1_INTEGER **aint)
{
    ASN1_INTEGER *itmp;
    if (!(itmp = s2i_ASN1_INTEGER(NULL, value->value))) {
        X509V3_conf_err(value);
        return 0;
    }
    *aint = itmp;
    return 1;
}

#define HDR_NAME        1
#define HDR_VALUE       2

/*
 * #define DEBUG
 */

STACK_OF(CONF_VALUE) *X509V3_parse_list(const char *line)
{
    char *p, *q, c;
    char *ntmp, *vtmp;
    STACK_OF(CONF_VALUE) *values = NULL;
    char *linebuf;
    int state;
    /* We are going to modify the line so copy it first */
    linebuf = BUF_strdup(line);
    if (linebuf == NULL) {
        X509V3err(X509V3_F_X509V3_PARSE_LIST, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    state = HDR_NAME;
    ntmp = NULL;
    /* Go through all characters */
    for (p = linebuf, q = linebuf; (c = *p) && (c != '\r') && (c != '\n');
         p++) {

        switch (state) {
        case HDR_NAME:
            if (c == ':') {
                state = HDR_VALUE;
                *p = 0;
                ntmp = strip_spaces(q);
                if (!ntmp) {
                    X509V3err(X509V3_F_X509V3_PARSE_LIST,
                              X509V3_R_INVALID_NULL_NAME);
                    goto err;
                }
                q = p + 1;
            } else if (c == ',') {
                *p = 0;
                ntmp = strip_spaces(q);
                q = p + 1;
#if 0
                printf("%s\n", ntmp);
#endif
                if (!ntmp) {
                    X509V3err(X509V3_F_X509V3_PARSE_LIST,
                              X509V3_R_INVALID_NULL_NAME);
                    goto err;
                }
                X509V3_add_value(ntmp, NULL, &values);
            }
            break;

        case HDR_VALUE:
            if (c == ',') {
                state = HDR_NAME;
                *p = 0;
                vtmp = strip_spaces(q);
#if 0
                printf("%s\n", ntmp);
#endif
                if (!vtmp) {
                    X509V3err(X509V3_F_X509V3_PARSE_LIST,
                              X509V3_R_INVALID_NULL_VALUE);
                    goto err;
                }
                X509V3_add_value(ntmp, vtmp, &values);
                ntmp = NULL;
                q = p + 1;
            }

        }
    }

    if (state == HDR_VALUE) {
        vtmp = strip_spaces(q);
#if 0
        printf("%s=%s\n", ntmp, vtmp);
#endif
        if (!vtmp) {
            X509V3err(X509V3_F_X509V3_PARSE_LIST,
                      X509V3_R_INVALID_NULL_VALUE);
            goto err;
        }
        X509V3_add_value(ntmp, vtmp, &values);
    } else {
        ntmp = strip_spaces(q);
#if 0
        printf("%s\n", ntmp);
#endif
        if (!ntmp) {
            X509V3err(X509V3_F_X509V3_PARSE_LIST, X509V3_R_INVALID_NULL_NAME);
            goto err;
        }
        X509V3_add_value(ntmp, NULL, &values);
    }
    OPENSSL_free(linebuf);
    return values;

 err:
    OPENSSL_free(linebuf);
    sk_CONF_VALUE_pop_free(values, X509V3_conf_free);
    return NULL;

}

/* Delete leading and trailing spaces from a string */
static char *strip_spaces(char *name)
{
    char *p, *q;
    /* Skip over leading spaces */
    p = name;
    while (*p && isspace((unsigned char)*p))
        p++;
    if (!*p)
        return NULL;
    q = p + strlen(p) - 1;
    while ((q != p) && isspace((unsigned char)*q))
        q--;
    if (p != q)
        q[1] = 0;
    if (!*p)
        return NULL;
    return p;
}

/* hex string utilities */

/*
 * Given a buffer of length 'len' return a OPENSSL_malloc'ed string with its
 * hex representation @@@ (Contents of buffer are always kept in ASCII, also
 * on EBCDIC machines)
 */

char *hex_to_string(const unsigned char *buffer, long len)
{
    char *tmp, *q;
    const unsigned char *p;
    int i;
    const static char hexdig[] = "0123456789ABCDEF";
    if (!buffer || !len)
        return NULL;
    if (!(tmp = OPENSSL_malloc(len * 3 + 1))) {
        X509V3err(X509V3_F_HEX_TO_STRING, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    q = tmp;
    for (i = 0, p = buffer; i < len; i++, p++) {
        *q++ = hexdig[(*p >> 4) & 0xf];
        *q++ = hexdig[*p & 0xf];
        *q++ = ':';
    }
    q[-1] = 0;
#ifdef CHARSET_EBCDIC
    ebcdic2ascii(tmp, tmp, q - tmp - 1);
#endif

    return tmp;
}

/*
 * Give a string of hex digits convert to a buffer
 */

unsigned char *string_to_hex(const char *str, long *len)
{
    unsigned char *hexbuf, *q;
    unsigned char ch, cl, *p;
    if (!str) {
        X509V3err(X509V3_F_STRING_TO_HEX, X509V3_R_INVALID_NULL_ARGUMENT);
        return NULL;
    }
    if (!(hexbuf = OPENSSL_malloc(strlen(str) >> 1)))
        goto err;
    for (p = (unsigned char *)str, q = hexbuf; *p;) {
        ch = *p++;
#ifdef CHARSET_EBCDIC
        ch = os_toebcdic[ch];
#endif
        if (ch == ':')
            continue;
        cl = *p++;
#ifdef CHARSET_EBCDIC
        cl = os_toebcdic[cl];
#endif
        if (!cl) {
            X509V3err(X509V3_F_STRING_TO_HEX, X509V3_R_ODD_NUMBER_OF_DIGITS);
            OPENSSL_free(hexbuf);
            return NULL;
        }
        if (isupper(ch))
            ch = tolower(ch);
        if (isupper(cl))
            cl = tolower(cl);

        if ((ch >= '0') && (ch <= '9'))
            ch -= '0';
        else if ((ch >= 'a') && (ch <= 'f'))
            ch -= 'a' - 10;
        else
            goto badhex;

        if ((cl >= '0') && (cl <= '9'))
            cl -= '0';
        else if ((cl >= 'a') && (cl <= 'f'))
            cl -= 'a' - 10;
        else
            goto badhex;

        *q++ = (ch << 4) | cl;
    }

    if (len)
        *len = q - hexbuf;

    return hexbuf;

 err:
    if (hexbuf)
        OPENSSL_free(hexbuf);
    X509V3err(X509V3_F_STRING_TO_HEX, ERR_R_MALLOC_FAILURE);
    return NULL;

 badhex:
    OPENSSL_free(hexbuf);
    X509V3err(X509V3_F_STRING_TO_HEX, X509V3_R_ILLEGAL_HEX_DIGIT);
    return NULL;

}

/*
 * V2I name comparison function: returns zero if 'name' matches cmp or cmp.*
 */

int name_cmp(const char *name, const char *cmp)
{
    int len, ret;
    char c;
    len = strlen(cmp);
    if ((ret = strncmp(name, cmp, len)))
        return ret;
    c = name[len];
    if (!c || (c == '.'))
        return 0;
    return 1;
}

static int sk_strcmp(const char *const *a, const char *const *b)
{
    return strcmp(*a, *b);
}

STACK_OF(OPENSSL_STRING) *X509_get1_email(X509 *x)
{
    GENERAL_NAMES *gens;
    STACK_OF(OPENSSL_STRING) *ret;

    gens = X509_get_ext_d2i(x, NID_subject_alt_name, NULL, NULL);
    ret = get_email(X509_get_subject_name(x), gens);
    sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
    return ret;
}

STACK_OF(OPENSSL_STRING) *X509_get1_ocsp(X509 *x)
{
    AUTHORITY_INFO_ACCESS *info;
    STACK_OF(OPENSSL_STRING) *ret = NULL;
    int i;

    info = X509_get_ext_d2i(x, NID_info_access, NULL, NULL);
    if (!info)
        return NULL;
    for (i = 0; i < sk_ACCESS_DESCRIPTION_num(info); i++) {
        ACCESS_DESCRIPTION *ad = sk_ACCESS_DESCRIPTION_value(info, i);
        if (OBJ_obj2nid(ad->method) == NID_ad_OCSP) {
            if (ad->location->type == GEN_URI) {
                if (!append_ia5
                    (&ret, ad->location->d.uniformResourceIdentifier))
                    break;
            }
        }
    }
    AUTHORITY_INFO_ACCESS_free(info);
    return ret;
}

STACK_OF(OPENSSL_STRING) *X509_REQ_get1_email(X509_REQ *x)
{
    GENERAL_NAMES *gens;
    STACK_OF(X509_EXTENSION) *exts;
    STACK_OF(OPENSSL_STRING) *ret;

    exts = X509_REQ_get_extensions(x);
    gens = X509V3_get_d2i(exts, NID_subject_alt_name, NULL, NULL);
    ret = get_email(X509_REQ_get_subject_name(x), gens);
    sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    return ret;
}

static STACK_OF(OPENSSL_STRING) *get_email(X509_NAME *name,
                                           GENERAL_NAMES *gens)
{
    STACK_OF(OPENSSL_STRING) *ret = NULL;
    X509_NAME_ENTRY *ne;
    ASN1_IA5STRING *email;
    GENERAL_NAME *gen;
    int i;
    /* Now add any email address(es) to STACK */
    i = -1;
    /* First supplied X509_NAME */
    while ((i = X509_NAME_get_index_by_NID(name,
                                           NID_pkcs9_emailAddress, i)) >= 0) {
        ne = X509_NAME_get_entry(name, i);
        email = X509_NAME_ENTRY_get_data(ne);
        if (!append_ia5(&ret, email))
            return NULL;
    }
    for (i = 0; i < sk_GENERAL_NAME_num(gens); i++) {
        gen = sk_GENERAL_NAME_value(gens, i);
        if (gen->type != GEN_EMAIL)
            continue;
        if (!append_ia5(&ret, gen->d.ia5))
            return NULL;
    }
    return ret;
}

static void str_free(OPENSSL_STRING str)
{
    OPENSSL_free(str);
}

static int append_ia5(STACK_OF(OPENSSL_STRING) **sk, ASN1_IA5STRING *email)
{
    char *emtmp;
    /* First some sanity checks */
    if (email->type != V_ASN1_IA5STRING)
        return 1;
    if (!email->data || !email->length)
        return 1;
    if (!*sk)
        *sk = sk_OPENSSL_STRING_new(sk_strcmp);
    if (!*sk)
        return 0;
    /* Don't add duplicates */
    if (sk_OPENSSL_STRING_find(*sk, (char *)email->data) != -1)
        return 1;
    emtmp = BUF_strdup((char *)email->data);
    if (!emtmp || !sk_OPENSSL_STRING_push(*sk, emtmp)) {
        X509_email_free(*sk);
        *sk = NULL;
        return 0;
    }
    return 1;
}

void X509_email_free(STACK_OF(OPENSSL_STRING) *sk)
{
    sk_OPENSSL_STRING_pop_free(sk, str_free);
}

typedef int (*equal_fn) (const unsigned char *pattern, size_t pattern_len,
                         const unsigned char *subject, size_t subject_len,
                         unsigned int flags);

/* Skip pattern prefix to match "wildcard" subject */
static void skip_prefix(const unsigned char **p, size_t *plen,
                        const unsigned char *subject, size_t subject_len,
                        unsigned int flags)
{
    const unsigned char *pattern = *p;
    size_t pattern_len = *plen;

    /*
     * If subject starts with a leading '.' followed by more octets, and
     * pattern is longer, compare just an equal-length suffix with the
     * full subject (starting at the '.'), provided the prefix contains
     * no NULs.
     */
    if ((flags & _X509_CHECK_FLAG_DOT_SUBDOMAINS) == 0)
        return;

    while (pattern_len > subject_len && *pattern) {
        if ((flags & X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS) &&
            *pattern == '.')
            break;
        ++pattern;
        --pattern_len;
    }

    /* Skip if entire prefix acceptable */
    if (pattern_len == subject_len) {
        *p = pattern;
        *plen = pattern_len;
    }
}

/* Compare while ASCII ignoring case. */
static int equal_nocase(const unsigned char *pattern, size_t pattern_len,
                        const unsigned char *subject, size_t subject_len,
                        unsigned int flags)
{
    skip_prefix(&pattern, &pattern_len, subject, subject_len, flags);
    if (pattern_len != subject_len)
        return 0;
    while (pattern_len) {
        unsigned char l = *pattern;
        unsigned char r = *subject;
        /* The pattern must not contain NUL characters. */
        if (l == 0)
            return 0;
        if (l != r) {
            if ('A' <= l && l <= 'Z')
                l = (l - 'A') + 'a';
            if ('A' <= r && r <= 'Z')
                r = (r - 'A') + 'a';
            if (l != r)
                return 0;
        }
        ++pattern;
        ++subject;
        --pattern_len;
    }
    return 1;
}

/* Compare using memcmp. */
static int equal_case(const unsigned char *pattern, size_t pattern_len,
                      const unsigned char *subject, size_t subject_len,
                      unsigned int flags)
{
    skip_prefix(&pattern, &pattern_len, subject, subject_len, flags);
    if (pattern_len != subject_len)
        return 0;
    return !memcmp(pattern, subject, pattern_len);
}

/*
 * RFC 5280, section 7.5, requires that only the domain is compared in a
 * case-insensitive manner.
 */
static int equal_email(const unsigned char *a, size_t a_len,
                       const unsigned char *b, size_t b_len,
                       unsigned int unused_flags)
{
    size_t i = a_len;
    if (a_len != b_len)
        return 0;
    /*
     * We search backwards for the '@' character, so that we do not have to
     * deal with quoted local-parts.  The domain part is compared in a
     * case-insensitive manner.
     */
    while (i > 0) {
        --i;
        if (a[i] == '@' || b[i] == '@') {
            if (!equal_nocase(a + i, a_len - i, b + i, a_len - i, 0))
                return 0;
            break;
        }
    }
    if (i == 0)
        i = a_len;
    return equal_case(a, i, b, i, 0);
}

/*
 * Compare the prefix and suffix with the subject, and check that the
 * characters in-between are valid.
 */
static int wildcard_match(const unsigned char *prefix, size_t prefix_len,
                          const unsigned char *suffix, size_t suffix_len,
                          const unsigned char *subject, size_t subject_len,
                          unsigned int flags)
{
    const unsigned char *wildcard_start;
    const unsigned char *wildcard_end;
    const unsigned char *p;
    int allow_multi = 0;
    int allow_idna = 0;

    if (subject_len < prefix_len + suffix_len)
        return 0;
    if (!equal_nocase(prefix, prefix_len, subject, prefix_len, flags))
        return 0;
    wildcard_start = subject + prefix_len;
    wildcard_end = subject + (subject_len - suffix_len);
    if (!equal_nocase(wildcard_end, suffix_len, suffix, suffix_len, flags))
        return 0;
    /*
     * If the wildcard makes up the entire first label, it must match at
     * least one character.
     */
    if (prefix_len == 0 && *suffix == '.') {
        if (wildcard_start == wildcard_end)
            return 0;
        allow_idna = 1;
        if (flags & X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS)
            allow_multi = 1;
    }
    /* IDNA labels cannot match partial wildcards */
    if (!allow_idna &&
        subject_len >= 4 && strncasecmp((char *)subject, "xn--", 4) == 0)
        return 0;
    /* The wildcard may match a literal '*' */
    if (wildcard_end == wildcard_start + 1 && *wildcard_start == '*')
        return 1;
    /*
     * Check that the part matched by the wildcard contains only
     * permitted characters and only matches a single label unless
     * allow_multi is set.
     */
    for (p = wildcard_start; p != wildcard_end; ++p)
        if (!(('0' <= *p && *p <= '9') ||
              ('A' <= *p && *p <= 'Z') ||
              ('a' <= *p && *p <= 'z') ||
              *p == '-' || (allow_multi && *p == '.')))
            return 0;
    return 1;
}

#define LABEL_START     (1 << 0)
#define LABEL_END       (1 << 1)
#define LABEL_HYPHEN    (1 << 2)
#define LABEL_IDNA      (1 << 3)

static const unsigned char *valid_star(const unsigned char *p, size_t len,
                                       unsigned int flags)
{
    const unsigned char *star = 0;
    size_t i;
    int state = LABEL_START;
    int dots = 0;
    for (i = 0; i < len; ++i) {
        /*
         * Locate first and only legal wildcard, either at the start
         * or end of a non-IDNA first and not final label.
         */
        if (p[i] == '*') {
            int atstart = (state & LABEL_START);
            int atend = (i == len - 1 || p[i + 1] == '.');
            /*-
             * At most one wildcard per pattern.
             * No wildcards in IDNA labels.
             * No wildcards after the first label.
             */
            if (star != NULL || (state & LABEL_IDNA) != 0 || dots)
                return NULL;
            /* Only full-label '*.example.com' wildcards? */
            if ((flags & X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS)
                && (!atstart || !atend))
                return NULL;
            /* No 'foo*bar' wildcards */
            if (!atstart && !atend)
                return NULL;
            star = &p[i];
            state &= ~LABEL_START;
        } else if (('a' <= p[i] && p[i] <= 'z')
                   || ('A' <= p[i] && p[i] <= 'Z')
                   || ('0' <= p[i] && p[i] <= '9')) {
            if ((state & LABEL_START) != 0
                && len - i >= 4 && strncasecmp((char *)&p[i], "xn--", 4) == 0)
                state |= LABEL_IDNA;
            state &= ~(LABEL_HYPHEN | LABEL_START);
        } else if (p[i] == '.') {
            if ((state & (LABEL_HYPHEN | LABEL_START)) != 0)
                return NULL;
            state = LABEL_START;
            ++dots;
        } else if (p[i] == '-') {
            /* no domain/subdomain starts with '-' */
            if ((state & LABEL_START) != 0)
                return NULL;
            state |= LABEL_HYPHEN;
        } else
            return NULL;
    }

    /*
     * The final label must not end in a hyphen or ".", and
     * there must be at least two dots after the star.
     */
    if ((state & (LABEL_START | LABEL_HYPHEN)) != 0 || dots < 2)
        return NULL;
    return star;
}

/* Compare using wildcards. */
static int equal_wildcard(const unsigned char *pattern, size_t pattern_len,
                          const unsigned char *subject, size_t subject_len,
                          unsigned int flags)
{
    const unsigned char *star = NULL;

    /*
     * Subject names starting with '.' can only match a wildcard pattern
     * via a subject sub-domain pattern suffix match.
     */
    if (!(subject_len > 1 && subject[0] == '.'))
        star = valid_star(pattern, pattern_len, flags);
    if (star == NULL)
        return equal_nocase(pattern, pattern_len,
                            subject, subject_len, flags);
    return wildcard_match(pattern, star - pattern,
                          star + 1, (pattern + pattern_len) - star - 1,
                          subject, subject_len, flags);
}

/*
 * Compare an ASN1_STRING to a supplied string. If they match return 1. If
 * cmp_type > 0 only compare if string matches the type, otherwise convert it
 * to UTF8.
 */

static int do_check_string(ASN1_STRING *a, int cmp_type, equal_fn equal,
                           unsigned int flags, const char *b, size_t blen,
                           char **peername)
{
    int rv = 0;

    if (!a->data || !a->length)
        return 0;
    if (cmp_type > 0) {
        if (cmp_type != a->type)
            return 0;
        if (cmp_type == V_ASN1_IA5STRING)
            rv = equal(a->data, a->length, (unsigned char *)b, blen, flags);
        else if (a->length == (int)blen && !memcmp(a->data, b, blen))
            rv = 1;
        if (rv > 0 && peername)
            *peername = BUF_strndup((char *)a->data, a->length);
    } else {
        int astrlen;
        unsigned char *astr;
        astrlen = ASN1_STRING_to_UTF8(&astr, a);
        if (astrlen < 0) {
            /*
             * -1 could be an internal malloc failure or a decoding error from
             * malformed input; we can't distinguish.
             */
            return -1;
        }
        rv = equal(astr, astrlen, (unsigned char *)b, blen, flags);
        if (rv > 0 && peername)
            *peername = BUF_strndup((char *)astr, astrlen);
        OPENSSL_free(astr);
    }
    return rv;
}

static int do_x509_check(X509 *x, const char *chk, size_t chklen,
                         unsigned int flags, int check_type, char **peername)
{
    GENERAL_NAMES *gens = NULL;
    X509_NAME *name = NULL;
    int i;
    int cnid = NID_undef;
    int alt_type;
    int san_present = 0;
    int rv = 0;
    equal_fn equal;

    /* See below, this flag is internal-only */
    flags &= ~_X509_CHECK_FLAG_DOT_SUBDOMAINS;
    if (check_type == GEN_EMAIL) {
        cnid = NID_pkcs9_emailAddress;
        alt_type = V_ASN1_IA5STRING;
        equal = equal_email;
    } else if (check_type == GEN_DNS) {
        cnid = NID_commonName;
        /* Implicit client-side DNS sub-domain pattern */
        if (chklen > 1 && chk[0] == '.')
            flags |= _X509_CHECK_FLAG_DOT_SUBDOMAINS;
        alt_type = V_ASN1_IA5STRING;
        if (flags & X509_CHECK_FLAG_NO_WILDCARDS)
            equal = equal_nocase;
        else
            equal = equal_wildcard;
    } else {
        alt_type = V_ASN1_OCTET_STRING;
        equal = equal_case;
    }

    if (chklen == 0)
        chklen = strlen(chk);

    gens = X509_get_ext_d2i(x, NID_subject_alt_name, NULL, NULL);
    if (gens) {
        for (i = 0; i < sk_GENERAL_NAME_num(gens); i++) {
            GENERAL_NAME *gen;
            ASN1_STRING *cstr;
            gen = sk_GENERAL_NAME_value(gens, i);
            if (gen->type != check_type)
                continue;
            san_present = 1;
            if (check_type == GEN_EMAIL)
                cstr = gen->d.rfc822Name;
            else if (check_type == GEN_DNS)
                cstr = gen->d.dNSName;
            else
                cstr = gen->d.iPAddress;
            /* Positive on success, negative on error! */
            if ((rv = do_check_string(cstr, alt_type, equal, flags,
                                      chk, chklen, peername)) != 0)
                break;
        }
        GENERAL_NAMES_free(gens);
        if (rv != 0)
            return rv;
        if (cnid == NID_undef
            || (san_present
                && !(flags & X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT)))
            return 0;
    }

    /* We're done if CN-ID is not pertinent */
    if (cnid == NID_undef)
        return 0;

    i = -1;
    name = X509_get_subject_name(x);
    while ((i = X509_NAME_get_index_by_NID(name, cnid, i)) >= 0) {
        X509_NAME_ENTRY *ne;
        ASN1_STRING *str;
        ne = X509_NAME_get_entry(name, i);
        str = X509_NAME_ENTRY_get_data(ne);
        /* Positive on success, negative on error! */
        if ((rv = do_check_string(str, -1, equal, flags,
                                  chk, chklen, peername)) != 0)
            return rv;
    }
    return 0;
}

int X509_check_host(X509 *x, const char *chk, size_t chklen,
                    unsigned int flags, char **peername)
{
    if (chk == NULL)
        return -2;
    /*
     * Embedded NULs are disallowed, except as the last character of a
     * string of length 2 or more (tolerate caller including terminating
     * NUL in string length).
     */
    if (chklen == 0)
        chklen = strlen(chk);
    else if (memchr(chk, '\0', chklen > 1 ? chklen - 1 : chklen))
        return -2;
    if (chklen > 1 && chk[chklen - 1] == '\0')
        --chklen;
    return do_x509_check(x, chk, chklen, flags, GEN_DNS, peername);
}

int X509_check_email(X509 *x, const char *chk, size_t chklen,
                     unsigned int flags)
{
    if (chk == NULL)
        return -2;
    /*
     * Embedded NULs are disallowed, except as the last character of a
     * string of length 2 or more (tolerate caller including terminating
     * NUL in string length).
     */
    if (chklen == 0)
        chklen = strlen((char *)chk);
    else if (memchr(chk, '\0', chklen > 1 ? chklen - 1 : chklen))
        return -2;
    if (chklen > 1 && chk[chklen - 1] == '\0')
        --chklen;
    return do_x509_check(x, chk, chklen, flags, GEN_EMAIL, NULL);
}

int X509_check_ip(X509 *x, const unsigned char *chk, size_t chklen,
                  unsigned int flags)
{
    if (chk == NULL)
        return -2;
    return do_x509_check(x, (char *)chk, chklen, flags, GEN_IPADD, NULL);
}

int X509_check_ip_asc(X509 *x, const char *ipasc, unsigned int flags)
{
    unsigned char ipout[16];
    size_t iplen;

    if (ipasc == NULL)
        return -2;
    iplen = (size_t)a2i_ipadd(ipout, ipasc);
    if (iplen == 0)
        return -2;
    return do_x509_check(x, (char *)ipout, iplen, flags, GEN_IPADD, NULL);
}

/*
 * Convert IP addresses both IPv4 and IPv6 into an OCTET STRING compatible
 * with RFC3280.
 */

ASN1_OCTET_STRING *a2i_IPADDRESS(const char *ipasc)
{
    unsigned char ipout[16];
    ASN1_OCTET_STRING *ret;
    int iplen;

    /* If string contains a ':' assume IPv6 */

    iplen = a2i_ipadd(ipout, ipasc);

    if (!iplen)
        return NULL;

    ret = ASN1_OCTET_STRING_new();
    if (!ret)
        return NULL;
    if (!ASN1_OCTET_STRING_set(ret, ipout, iplen)) {
        ASN1_OCTET_STRING_free(ret);
        return NULL;
    }
    return ret;
}

ASN1_OCTET_STRING *a2i_IPADDRESS_NC(const char *ipasc)
{
    ASN1_OCTET_STRING *ret = NULL;
    unsigned char ipout[32];
    char *iptmp = NULL, *p;
    int iplen1, iplen2;
    p = strchr(ipasc, '/');
    if (!p)
        return NULL;
    iptmp = BUF_strdup(ipasc);
    if (!iptmp)
        return NULL;
    p = iptmp + (p - ipasc);
    *p++ = 0;

    iplen1 = a2i_ipadd(ipout, iptmp);

    if (!iplen1)
        goto err;

    iplen2 = a2i_ipadd(ipout + iplen1, p);

    OPENSSL_free(iptmp);
    iptmp = NULL;

    if (!iplen2 || (iplen1 != iplen2))
        goto err;

    ret = ASN1_OCTET_STRING_new();
    if (!ret)
        goto err;
    if (!ASN1_OCTET_STRING_set(ret, ipout, iplen1 + iplen2))
        goto err;

    return ret;

 err:
    if (iptmp)
        OPENSSL_free(iptmp);
    if (ret)
        ASN1_OCTET_STRING_free(ret);
    return NULL;
}

int a2i_ipadd(unsigned char *ipout, const char *ipasc)
{
    /* If string contains a ':' assume IPv6 */

    if (strchr(ipasc, ':')) {
        if (!ipv6_from_asc(ipout, ipasc))
            return 0;
        return 16;
    } else {
        if (!ipv4_from_asc(ipout, ipasc))
            return 0;
        return 4;
    }
}

static int ipv4_from_asc(unsigned char *v4, const char *in)
{
    int a0, a1, a2, a3;
    if (sscanf(in, "%d.%d.%d.%d", &a0, &a1, &a2, &a3) != 4)
        return 0;
    if ((a0 < 0) || (a0 > 255) || (a1 < 0) || (a1 > 255)
        || (a2 < 0) || (a2 > 255) || (a3 < 0) || (a3 > 255))
        return 0;
    v4[0] = a0;
    v4[1] = a1;
    v4[2] = a2;
    v4[3] = a3;
    return 1;
}

typedef struct {
    /* Temporary store for IPV6 output */
    unsigned char tmp[16];
    /* Total number of bytes in tmp */
    int total;
    /* The position of a zero (corresponding to '::') */
    int zero_pos;
    /* Number of zeroes */
    int zero_cnt;
} IPV6_STAT;

static int ipv6_from_asc(unsigned char *v6, const char *in)
{
    IPV6_STAT v6stat;
    v6stat.total = 0;
    v6stat.zero_pos = -1;
    v6stat.zero_cnt = 0;
    /*
     * Treat the IPv6 representation as a list of values separated by ':'.
     * The presence of a '::' will parse as one, two or three zero length
     * elements.
     */
    if (!CONF_parse_list(in, ':', 0, ipv6_cb, &v6stat))
        return 0;

    /* Now for some sanity checks */

    if (v6stat.zero_pos == -1) {
        /* If no '::' must have exactly 16 bytes */
        if (v6stat.total != 16)
            return 0;
    } else {
        /* If '::' must have less than 16 bytes */
        if (v6stat.total == 16)
            return 0;
        /* More than three zeroes is an error */
        if (v6stat.zero_cnt > 3)
            return 0;
        /* Can only have three zeroes if nothing else present */
        else if (v6stat.zero_cnt == 3) {
            if (v6stat.total > 0)
                return 0;
        }
        /* Can only have two zeroes if at start or end */
        else if (v6stat.zero_cnt == 2) {
            if ((v6stat.zero_pos != 0)
                && (v6stat.zero_pos != v6stat.total))
                return 0;
        } else
            /* Can only have one zero if *not* start or end */
        {
            if ((v6stat.zero_pos == 0)
                || (v6stat.zero_pos == v6stat.total))
                return 0;
        }
    }

    /* Format result */

    if (v6stat.zero_pos >= 0) {
        /* Copy initial part */
        memcpy(v6, v6stat.tmp, v6stat.zero_pos);
        /* Zero middle */
        memset(v6 + v6stat.zero_pos, 0, 16 - v6stat.total);
        /* Copy final part */
        if (v6stat.total != v6stat.zero_pos)
            memcpy(v6 + v6stat.zero_pos + 16 - v6stat.total,
                   v6stat.tmp + v6stat.zero_pos,
                   v6stat.total - v6stat.zero_pos);
    } else
        memcpy(v6, v6stat.tmp, 16);

    return 1;
}

static int ipv6_cb(const char *elem, int len, void *usr)
{
    IPV6_STAT *s = usr;
    /* Error if 16 bytes written */
    if (s->total == 16)
        return 0;
    if (len == 0) {
        /* Zero length element, corresponds to '::' */
        if (s->zero_pos == -1)
            s->zero_pos = s->total;
        /* If we've already got a :: its an error */
        else if (s->zero_pos != s->total)
            return 0;
        s->zero_cnt++;
    } else {
        /* If more than 4 characters could be final a.b.c.d form */
        if (len > 4) {
            /* Need at least 4 bytes left */
            if (s->total > 12)
                return 0;
            /* Must be end of string */
            if (elem[len])
                return 0;
            if (!ipv4_from_asc(s->tmp + s->total, elem))
                return 0;
            s->total += 4;
        } else {
            if (!ipv6_hex(s->tmp + s->total, elem, len))
                return 0;
            s->total += 2;
        }
    }
    return 1;
}

/*
 * Convert a string of up to 4 hex digits into the corresponding IPv6 form.
 */

static int ipv6_hex(unsigned char *out, const char *in, int inlen)
{
    unsigned char c;
    unsigned int num = 0;
    if (inlen > 4)
        return 0;
    while (inlen--) {
        c = *in++;
        num <<= 4;
        if ((c >= '0') && (c <= '9'))
            num |= c - '0';
        else if ((c >= 'A') && (c <= 'F'))
            num |= c - 'A' + 10;
        else if ((c >= 'a') && (c <= 'f'))
            num |= c - 'a' + 10;
        else
            return 0;
    }
    out[0] = num >> 8;
    out[1] = num & 0xff;
    return 1;
}

int X509V3_NAME_from_section(X509_NAME *nm, STACK_OF(CONF_VALUE) *dn_sk,
                             unsigned long chtype)
{
    CONF_VALUE *v;
    int i, mval;
    char *p, *type;
    if (!nm)
        return 0;

    for (i = 0; i < sk_CONF_VALUE_num(dn_sk); i++) {
        v = sk_CONF_VALUE_value(dn_sk, i);
        type = v->name;
        /*
         * Skip past any leading X. X: X, etc to allow for multiple instances
         */
        for (p = type; *p; p++)
#ifndef CHARSET_EBCDIC
            if ((*p == ':') || (*p == ',') || (*p == '.'))
#else
            if ((*p == os_toascii[':']) || (*p == os_toascii[','])
                || (*p == os_toascii['.']))
#endif
            {
                p++;
                if (*p)
                    type = p;
                break;
            }
#ifndef CHARSET_EBCDIC
        if (*type == '+')
#else
        if (*type == os_toascii['+'])
#endif
        {
            mval = -1;
            type++;
        } else
            mval = 0;
        if (!X509_NAME_add_entry_by_txt(nm, type, chtype,
                                        (unsigned char *)v->value, -1, -1,
                                        mval))
            return 0;

    }
    return 1;
}
