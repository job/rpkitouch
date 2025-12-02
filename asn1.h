/*
 * Copyright (c) 2025 Job Snijders <job@sobornost.net>
 * Copyright (c) 2022 Theo Buehler <tb@openbsd.org>
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

#ifndef RPKITOUCH_ASN1_H
#define RPKITOUCH_ASN1_H

#include <openssl/asn1t.h>
#include <openssl/stack.h>
#include <openssl/safestack.h>

#ifndef DECLARE_STACK_OF
#define DECLARE_STACK_OF DEFINE_STACK_OF
#endif

/*
 * Erik protocol elements
 * reference: draft-ietf-sidrops-rpki-erik-protocol-01
 */

extern ASN1_ITEM_EXP ErikIndex_it;
extern ASN1_ITEM_EXP PartitionRef_it;
extern ASN1_ITEM_EXP ErikPartition_it;
extern ASN1_ITEM_EXP ManifestRef_it;

typedef struct {
	ASN1_INTEGER *version;
	ASN1_IA5STRING *indexScope;
	ASN1_GENERALIZEDTIME *indexTime;
	ASN1_OBJECT *hashAlg;
	STACK_OF(PartitionRef) *partitionList;
} ErikIndex;

DECLARE_ASN1_FUNCTIONS(ErikIndex);

typedef struct {
	ASN1_OCTET_STRING *hash;
	ASN1_INTEGER *size;
} PartitionRef;

DECLARE_STACK_OF(PartitionRef);

#ifndef DEFINE_STACK_OF
#define sk_PartitionRef_num(st) SKM_sk_num(PartitionRef, (st))
#define sk_PartitionRef_push(st, i) SKM_sk_push(PartitionRef, (st), (i))
#endif

DECLARE_ASN1_FUNCTIONS(PartitionRef);

typedef struct {
	ASN1_INTEGER *version;
	ASN1_GENERALIZEDTIME *partitionTime;
	ASN1_OBJECT *hashAlg;
	STACK_OF(ManifestRef) *manifestList;
} ErikPartition;

DECLARE_ASN1_FUNCTIONS(ErikPartition);

typedef struct {
	ASN1_OCTET_STRING *hash;
	ASN1_INTEGER *size;
	ASN1_OCTET_STRING *aki;
	ASN1_INTEGER *manifestNumber;
	ASN1_GENERALIZEDTIME *thisUpdate;
	STACK_OF(ACCESS_DESCRIPTION) *location;
} ManifestRef;

DECLARE_STACK_OF(ManifestRef);

#ifndef DEFINE_STACK_OF
#define sk_ManifestRef_num(st) SKM_sk_num(ManifestRef, (st))
#define sk_ManifestRef_push(st, i) SKM_sk_push(ManifestRef, (st), (i))
#define sk_ManifestRef_value(st, i) SKM_sk_value(ManifestRef, (st), (i))
#endif

DECLARE_ASN1_FUNCTIONS(ManifestRef);

typedef STACK_OF(ManifestRef) ManifestRefs;

DECLARE_ASN1_FUNCTIONS(ManifestRefs);

/*
 * Canonical Cache Representation (CCR)
 * reference: draft-ietf-sidrops-rpki-ccr-01
 */

extern ASN1_ITEM_EXP EncapContentInfo_it;
extern ASN1_ITEM_EXP CanonicalCacheRepresentation_it;
extern ASN1_ITEM_EXP ManifestInstance_it;

DECLARE_STACK_OF(ASN1_OCTET_STRING);

#ifndef DEFINE_STACK_OF
#define sk_ASN1_OCTET_STRING_new(cmp) SKM_sk_new(ASN1_OCTET_STRING, (cmp))
#define sk_ASN1_OCTET_STRING_push(st, i) SKM_sk_push(ASN1_OCTET_STRING, (st), (i))
#define sk_ASN1_OCTET_STRING_sort(sk) SKM_sk_sort(ASN1_OCTET_STRING, (sk))
#define sk_ASN1_OCTET_STRING_set_cmp_func(sk, cmp) \
    SKM_sk_set_cmp_func(ASN1_OCTET_STRING, (sk), (cmp))
#endif

DECLARE_ASN1_FUNCTIONS(ASN1_OCTET_STRING);

DECLARE_ASN1_FUNCTIONS(ASN1_OCTET_STRING);

typedef struct {
	ASN1_OCTET_STRING *hash;
	ASN1_INTEGER *size;
	ASN1_OCTET_STRING *aki;
	ASN1_INTEGER *manifestNumber;
	ASN1_GENERALIZEDTIME *thisUpdate;
	STACK_OF(ACCESS_DESCRIPTION) *locations;
	STACK_OF(ASN1_OCTET_STRING) *subordinates;
} ManifestInstance;

DECLARE_STACK_OF(ManifestInstance);

#ifndef DEFINE_STACK_OF
#define sk_ManifestInstance_num(st) SKM_sk_num(ManifestInstance, (st))
#define sk_ManifestInstance_push(st, i) SKM_sk_push(ManifestInstance, (st), (i))
#define sk_ManifestInstance_value(st, i) SKM_sk_value(ManifestInstance, (st), (i))
#endif

DECLARE_ASN1_FUNCTIONS(ManifestInstance);

typedef STACK_OF(ManifestInstance) ManifestInstances;

DECLARE_ASN1_FUNCTIONS(ManifestInstances);

typedef struct {
	STACK_OF(ManifestInstance) *mis;
	ASN1_GENERALIZEDTIME *mostRecentUpdate;
	ASN1_OCTET_STRING *hash;
} ManifestState;

DECLARE_ASN1_FUNCTIONS(ManifestState);

typedef struct {
	ASN1_INTEGER *version;
	ASN1_OBJECT *hashAlg;
	ASN1_GENERALIZEDTIME *producedAt;
	ManifestState *mfts;
	ASN1_SEQUENCE_ANY *vrps;
	ASN1_SEQUENCE_ANY *vaps;
	ASN1_SEQUENCE_ANY *tas;
	ASN1_SEQUENCE_ANY *rks;
} CanonicalCacheRepresentation;

DECLARE_ASN1_FUNCTIONS(CanonicalCacheRepresentation);

typedef struct {
	ASN1_OBJECT *contentType;
	ASN1_OCTET_STRING *content;
} EncapContentInfo;

DECLARE_ASN1_FUNCTIONS(EncapContentInfo);

/*
 * RPKI Manifest
 * reference: RFC 9286.
 */

extern ASN1_ITEM_EXP FileAndHash_it;
extern ASN1_ITEM_EXP Manifest_it;

typedef struct {
	ASN1_IA5STRING *file;
	ASN1_BIT_STRING	*hash;
} FileAndHash;

DECLARE_STACK_OF(FileAndHash);

#ifndef DEFINE_STACK_OF
#define sk_FileAndHash_dup(sk) SKM_sk_dup(FileAndHash, (sk))
#define sk_FileAndHash_free(sk) SKM_sk_free(FileAndHash, (sk))
#define sk_FileAndHash_num(sk) SKM_sk_num(FileAndHash, (sk))
#define sk_FileAndHash_value(sk, i) SKM_sk_value(FileAndHash, (sk), (i))
#define sk_FileAndHash_sort(sk) SKM_sk_sort(FileAndHash, (sk))
#define sk_FileAndHash_set_cmp_func(sk, cmp) \
    SKM_sk_set_cmp_func(FileAndHash, (sk), (cmp))
#endif

typedef struct {
	ASN1_INTEGER *version;
	ASN1_INTEGER *manifestNumber;
	ASN1_GENERALIZEDTIME *thisUpdate;
	ASN1_GENERALIZEDTIME *nextUpdate;
	ASN1_OBJECT *fileHashAlg;
	STACK_OF(FileAndHash) *fileList;
} Manifest;

DECLARE_ASN1_FUNCTIONS(Manifest);

#endif /* ! RPKITOUCH_ASN1_H */
