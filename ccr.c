/*
 * Copyright (c) 2025 Job Snijders <job@sobornost.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

#include <openssl/asn1t.h>
#include <openssl/safestack.h>
#include <openssl/x509v3.h>

#include "asn1.h"

ASN1_ITEM_EXP ContentInfo_it;
ASN1_ITEM_EXP CanonicalCacheRepresentation_it;
ASN1_ITEM_EXP ManifestRefs_it;
ASN1_ITEM_EXP ManifestRef_it;

/*
 * Can't use CMS_ContentInfo since it is not backed by a public struct
 * and since the OpenSSL CMS API does not support custom contentTypes.
 */
ASN1_SEQUENCE(ContentInfo) = {
	ASN1_SIMPLE(ContentInfo, contentType, ASN1_OBJECT),
	ASN1_EXP(ContentInfo, content, ASN1_OCTET_STRING, 0),
} ASN1_SEQUENCE_END(ContentInfo);

IMPLEMENT_ASN1_FUNCTIONS(ContentInfo);

ASN1_SEQUENCE(CanonicalCacheRepresentation) = {
	ASN1_EXP_OPT(CanonicalCacheRepresentation, version, ASN1_INTEGER, 0),
	ASN1_SIMPLE(CanonicalCacheRepresentation, hashAlg, ASN1_OBJECT),
	ASN1_SIMPLE(CanonicalCacheRepresentation, producedAt,
	    ASN1_GENERALIZEDTIME),
	ASN1_EXP_OPT(CanonicalCacheRepresentation, mfts, ManifestState, 1),
	ASN1_EXP_OPT(CanonicalCacheRepresentation, vrps, ASN1_SEQUENCE_ANY, 2),
	ASN1_EXP_OPT(CanonicalCacheRepresentation, vaps, ASN1_SEQUENCE_ANY, 3),
	ASN1_EXP_OPT(CanonicalCacheRepresentation, tas, ASN1_SEQUENCE_ANY, 4),
} ASN1_SEQUENCE_END(CanonicalCacheRepresentation);

IMPLEMENT_ASN1_FUNCTIONS(CanonicalCacheRepresentation);

ASN1_SEQUENCE(ManifestState) = {
	ASN1_SEQUENCE_OF(ManifestState, mftrefs, ManifestRef),
	ASN1_SIMPLE(ManifestState, mostRecentUpdate, ASN1_GENERALIZEDTIME),
	ASN1_SIMPLE(ManifestState, hash, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(ManifestState);

IMPLEMENT_ASN1_FUNCTIONS(ManifestState);

ASN1_ITEM_TEMPLATE(ManifestRefs) =
    ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, mftrefs, ManifestRef)
ASN1_ITEM_TEMPLATE_END(ManifestRefs);

IMPLEMENT_ASN1_ENCODE_FUNCTIONS_fname(ManifestRefs, ManifestRefs, ManifestRefs);

ASN1_SEQUENCE(ManifestRef) = {
	ASN1_SIMPLE(ManifestRef, hash, ASN1_OCTET_STRING),
	ASN1_SIMPLE(ManifestRef, size, ASN1_INTEGER),
	ASN1_SIMPLE(ManifestRef, aki, ASN1_OCTET_STRING),
	ASN1_SIMPLE(ManifestRef, manifestNumber, ASN1_INTEGER),
	ASN1_SEQUENCE_OF(ManifestRef, location, ACCESS_DESCRIPTION),
} ASN1_SEQUENCE_END(ManifestRef);

IMPLEMENT_ASN1_FUNCTIONS(ManifestRef);
