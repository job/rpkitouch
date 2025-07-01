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

#include <openssl/asn1t.h>
#include <openssl/safestack.h>

/*
 * From draft-spaghetti-sidrops-rpki-erik-protocol-00
 */

typedef struct {
	ASN1_INTEGER *partitionIdentifier;
	ASN1_BIT_STRING *hash;
} PartitionListEntry;

ASN1_SEQUENCE(PartitionListEntry) = {
	ASN1_SIMPLE(PartitionListEntry, partitionIdentifier, ASN1_INTEGER),
	ASN1_SIMPLE(PartitionListEntry, hash, ASN1_BIT_STRING),
} ASN1_SEQUENCE_END(PartitionListEntry);

#ifndef DEFINE_STACK_OF
#define sk_PartitionListEntry_dup(sk)	SKM_sk_dup(PartitionListEntry, (sk))
#define sk_PartitionListEntry_free(sk)	SKM_sk_free(PartitionListEntry, (sk))
#define sk_PartitionListEntry_num(sk)	SKM_sk_num(PartitionListEntry, (sk))
#define sk_PartitionListEntry_set_cmp_func(sk, cmp) \
    SKM_sk_set_cmp_func(PartitionListEntry, (sk), (cmp))
#define sk_PartitionListEntry_sort(sk)	SKM_sk_sort(PartitionListEntry, (sk))
#define sk_PartitionListEntry_value(sk, i) \
    SKM_sk_value(PartitionListEntry, (sk), (i))
#endif

DECLARE_ASN1_FUNCTIONS(PartitionListEntry);
IMPLEMENT_ASN1_FUNCTIONS(PartitionListEntry);

typedef struct {
	ASN1_INTEGER *version;
	ASN1_IA5STRING *indexScope;
	ASN1_GENERALIZEDTIME *indexTime;
	ASN1_OBJECT *hashAlg;
	ASN1_BIT_STRING *previousIndex;
	STACK_OF(PartitionListEntry) *partitionList;
} ErikIndex;

ASN1_SEQUENCE(ErikIndex) = {
	ASN1_EXP_OPT(ErikIndex, version, ASN1_INTEGER, 0),
	ASN1_SIMPLE(ErikIndex, indexScope, ASN1_IA5STRING),
	ASN1_SIMPLE(ErikIndex, indexTime, ASN1_GENERALIZEDTIME),
	ASN1_SIMPLE(ErikIndex, hashAlg, ASN1_OBJECT),
	ASN1_EXP_OPT(ErikIndex, previousIndex, ASN1_BIT_STRING, 0),
	ASN1_SEQUENCE_OF(ErikIndex, partitionList, PartitionListEntry),
} ASN1_SEQUENCE_END(ErikIndex);

DECLARE_ASN1_FUNCTIONS(ErikIndex);
IMPLEMENT_ASN1_FUNCTIONS(ErikIndex);

typedef struct {
	ASN1_BIT_STRING *hash;
	ASN1_INTEGER *manifestNumber;
	ASN1_OCTET_STRING *location;
} ManifestListEntry;

DECLARE_STACK_OF(ManifestListEntry);

#ifndef DEFINE_STACK_OF
#define sk_ManifestListEntry_dup(sk)	SKM_sk_dup(ManifestListEntry, (sk))
#define sk_ManifestListEntry_free(sk)	SKM_sk_free(ManifestListEntry, (sk))
#define sk_ManifestListEntry_num(sk)	SKM_sk_num(ManifestListEntry, (sk))
#define sk_ManifestListEntry_set_cmp_func(sk, cmp) \
    SKM_sk_set_cmp_func(ManifestListEntry, (sk), (cmp))
#define sk_ManifestListEntry_sort(sk)	SKM_sk_sort(ManifestListEntry, (sk))
#define sk_ManifestListEntry_value(sk, i) \
    SKM_sk_value(ManifestListEntry, (sk), (i))
#endif

ASN1_SEQUENCE(ManifestListEntry) = {
	ASN1_SIMPLE(ManifestListEntry, hash, ASN1_OCTET_STRING),
	ASN1_SIMPLE(ManifestListEntry, manifestNumber, ASN1_INTEGER),
	ASN1_SIMPLE(ManifestListEntry, location, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(ManifestListEntry)

DECLARE_ASN1_FUNCTIONS(ManifestListEntry);
IMPLEMENT_ASN1_FUNCTIONS(ManifestListEntry);

typedef struct {
	ASN1_INTEGER *version;
	ASN1_GENERALIZEDTIME *partitionTime;
	ASN1_OBJECT *hashAlg;
	STACK_OF(ManifestListEntry) *manifestList;
} ErikPartition;

ASN1_SEQUENCE(ErikPartition) = {
	ASN1_EXP_OPT(ErikPartition, version, ASN1_INTEGER, 0),
	ASN1_SIMPLE(ErikPartition, partitionTime, ASN1_GENERALIZEDTIME),
	ASN1_SIMPLE(ErikPartition, hashAlg, ASN1_OBJECT),
	ASN1_SEQUENCE_OF(ErikPartition, manifestList, ManifestListEntry),
} ASN1_SEQUENCE_END(ErikPartition);

DECLARE_ASN1_FUNCTIONS(ErikPartition);
IMPLEMENT_ASN1_FUNCTIONS(ErikPartition);

typedef struct {
	ASN1_INTEGER *version;
	ASN1_INTEGER *manifestNumber;
	ASN1_GENERALIZEDTIME *thisUpdate;
	ASN1_GENERALIZEDTIME *nextUpdate;
	ASN1_OBJECT *fileHashAlg;
	STACK_OF(ASN1_SEQUENCE) *fileList;
} Manifest;

ASN1_SEQUENCE(Manifest) = {
	ASN1_EXP_OPT(Manifest, version, ASN1_INTEGER, 0),
	ASN1_SIMPLE(Manifest, manifestNumber, ASN1_INTEGER),
	ASN1_SIMPLE(Manifest, thisUpdate, ASN1_GENERALIZEDTIME),
	ASN1_SIMPLE(Manifest, nextUpdate, ASN1_GENERALIZEDTIME),
	ASN1_SIMPLE(Manifest, fileHashAlg, ASN1_OBJECT),
	ASN1_SEQUENCE_OF(Manifest, fileList, ASN1_SEQUENCE),
} ASN1_SEQUENCE_END(Manifest);

DECLARE_ASN1_FUNCTIONS(Manifest);
IMPLEMENT_ASN1_FUNCTIONS(Manifest);
