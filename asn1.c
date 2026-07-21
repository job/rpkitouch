/*
 * Copyright (c) 2025-2026 Job Snijders <job@bsd.nl>
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

#include <sys/stat.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <openssl/asn1t.h>
#include <openssl/safestack.h>
#include <openssl/x509v3.h>

#include "compat/tree.h"

#include "asn1.h"
#include "extern.h"

ASN1_ITEM_EXP CCR_ContentInfo_it;
ASN1_ITEM_EXP EI_ContentInfo_it;
ASN1_ITEM_EXP EP_ContentInfo_it;
ASN1_ITEM_EXP ESI_ContentInfo_it;
ASN1_ITEM_EXP CanonicalCacheRepresentation_it;
ASN1_ITEM_EXP ErikIndex_it;
ASN1_ITEM_EXP PartitionRef_it;
ASN1_ITEM_EXP ErikPartition_it;
ASN1_ITEM_EXP ManifestRef_it;
ASN1_ITEM_EXP ManifestInstance_it;
ASN1_ITEM_EXP ManifestInstances_it;
ASN1_ITEM_EXP ROAIPAddress_it;
ASN1_ITEM_EXP ROAIPAddressFamily_it;
ASN1_ITEM_EXP ROAPayloadSet_it;
ASN1_ITEM_EXP ROAPayloadSets_it;

ASN1_SEQUENCE(CCR_ContentInfo) = {
	ASN1_SIMPLE(CCR_ContentInfo, contentType, ASN1_OBJECT),
	ASN1_EXP(CCR_ContentInfo, content, CanonicalCacheRepresentation, 0),
} ASN1_SEQUENCE_END(CCR_ContentInfo);

IMPLEMENT_ASN1_FUNCTIONS(CCR_ContentInfo);

ASN1_SEQUENCE(EI_ContentInfo) = {
	ASN1_SIMPLE(EI_ContentInfo, contentType, ASN1_OBJECT),
	ASN1_EXP(EI_ContentInfo, content, ErikIndex, 0),
} ASN1_SEQUENCE_END(EI_ContentInfo);

IMPLEMENT_ASN1_FUNCTIONS(EI_ContentInfo);

ASN1_SEQUENCE(EP_ContentInfo) = {
	ASN1_SIMPLE(EP_ContentInfo, contentType, ASN1_OBJECT),
	ASN1_EXP(EP_ContentInfo, content, ErikPartition, 0),
} ASN1_SEQUENCE_END(EP_ContentInfo);

IMPLEMENT_ASN1_FUNCTIONS(EP_ContentInfo);

ASN1_SEQUENCE(ESI_ContentInfo) = {
	ASN1_SIMPLE(ESI_ContentInfo, contentType, ASN1_OBJECT),
	ASN1_EXP(ESI_ContentInfo, content, ErikSegmentIndex, 0),
} ASN1_SEQUENCE_END(ESI_ContentInfo);

IMPLEMENT_ASN1_FUNCTIONS(ESI_ContentInfo);

ASN1_SEQUENCE(CanonicalCacheRepresentation) = {
	ASN1_EXP_OPT(CanonicalCacheRepresentation, version, ASN1_INTEGER, 0),
	ASN1_SIMPLE(CanonicalCacheRepresentation, hashAlg, X509_ALGOR),
	ASN1_SIMPLE(CanonicalCacheRepresentation, producedAt,
	    ASN1_GENERALIZEDTIME),
	ASN1_EXP_OPT(CanonicalCacheRepresentation, mfts, ManifestState, 1),
	ASN1_EXP_OPT(CanonicalCacheRepresentation, vrps, ROAPayloadState, 2),
	ASN1_EXP_OPT(CanonicalCacheRepresentation, vaps, ASN1_SEQUENCE_ANY, 3),
	ASN1_EXP_OPT(CanonicalCacheRepresentation, tas, ASN1_SEQUENCE_ANY, 4),
	ASN1_EXP_OPT(CanonicalCacheRepresentation, rks, ASN1_SEQUENCE_ANY, 5),
} ASN1_SEQUENCE_END(CanonicalCacheRepresentation);

IMPLEMENT_ASN1_FUNCTIONS(CanonicalCacheRepresentation);

ASN1_SEQUENCE(ROAPayloadState) = {
	ASN1_SEQUENCE_OF(ROAPayloadState, rps, ROAPayloadSet),
	ASN1_SIMPLE(ROAPayloadState, hash, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(ROAPayloadState);

IMPLEMENT_ASN1_FUNCTIONS(ROAPayloadState);

ASN1_ITEM_TEMPLATE(ROAPayloadSets) =
    ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, rps, ROAPayloadSet)
ASN1_ITEM_TEMPLATE_END(ROAPayloadSets);

ASN1_SEQUENCE(ROAPayloadSet) = {
	ASN1_SIMPLE(ROAPayloadSet, asID, ASN1_INTEGER),
	ASN1_SEQUENCE_OF(ROAPayloadSet, ipAddrBlocks, ROAIPAddressFamily),
} ASN1_SEQUENCE_END(ROAPayloadSet);

ASN1_SEQUENCE(ROAIPAddressFamily) = {
	ASN1_SIMPLE(ROAIPAddressFamily, addressFamily, ASN1_OCTET_STRING),
	ASN1_SEQUENCE_OF(ROAIPAddressFamily, addresses, ROAIPAddress),
} ASN1_SEQUENCE_END(ROAIPAddressFamily);

ASN1_SEQUENCE(ROAIPAddress) = {
	ASN1_SIMPLE(ROAIPAddress, address, ASN1_BIT_STRING),
	ASN1_OPT(ROAIPAddress, maxLength, ASN1_INTEGER),
} ASN1_SEQUENCE_END(ROAIPAddress);

IMPLEMENT_ASN1_FUNCTIONS(ROAPayloadSet);
IMPLEMENT_ASN1_FUNCTIONS(ROAIPAddressFamily);
IMPLEMENT_ASN1_FUNCTIONS(ROAIPAddress);

ASN1_SEQUENCE(ManifestState) = {
	ASN1_SEQUENCE_OF(ManifestState, mis, ManifestInstance),
	ASN1_SIMPLE(ManifestState, mostRecentUpdate, ASN1_GENERALIZEDTIME),
	ASN1_SIMPLE(ManifestState, hash, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(ManifestState);

IMPLEMENT_ASN1_FUNCTIONS(ManifestState);

ASN1_SEQUENCE(ManifestInstance) = {
	ASN1_SIMPLE(ManifestInstance, hash, ASN1_OCTET_STRING),
	ASN1_SIMPLE(ManifestInstance, size, ASN1_INTEGER),
	ASN1_SIMPLE(ManifestInstance, aki, ASN1_OCTET_STRING),
	ASN1_SIMPLE(ManifestInstance, manifestNumber, ASN1_INTEGER),
	ASN1_SIMPLE(ManifestInstance, thisUpdate, ASN1_GENERALIZEDTIME),
	ASN1_SEQUENCE_OF(ManifestInstance, locations, ACCESS_DESCRIPTION),
	ASN1_SEQUENCE_OF_OPT(ManifestInstance, subordinates, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(ManifestInstance);

IMPLEMENT_ASN1_FUNCTIONS(ManifestInstance);

ASN1_SEQUENCE(ErikIndex) = {
	ASN1_EXP_OPT(ErikIndex, version, ASN1_INTEGER, 0),
	ASN1_SIMPLE(ErikIndex, indexScope, ASN1_IA5STRING),
	ASN1_SIMPLE(ErikIndex, indexTime, ASN1_GENERALIZEDTIME),
	ASN1_SIMPLE(ErikIndex, hashAlg, X509_ALGOR),
	ASN1_SEQUENCE_OF(ErikIndex, partitionList, PartitionRef),
} ASN1_SEQUENCE_END(ErikIndex);

IMPLEMENT_ASN1_FUNCTIONS(ErikIndex);

ASN1_SEQUENCE(PartitionRef) = {
	ASN1_SIMPLE(PartitionRef, hash, ASN1_OCTET_STRING),
	ASN1_SIMPLE(PartitionRef, size, ASN1_INTEGER),
} ASN1_SEQUENCE_END(PartitionRef);

IMPLEMENT_ASN1_FUNCTIONS(PartitionRef);

ASN1_SEQUENCE(ErikPartition) = {
	ASN1_EXP_OPT(ErikPartition, version, ASN1_INTEGER, 0),
	ASN1_SIMPLE(ErikPartition, partitionTime, ASN1_GENERALIZEDTIME),
	ASN1_SIMPLE(ErikPartition, hashAlg, X509_ALGOR),
	ASN1_SEQUENCE_OF(ErikPartition, manifestList, ManifestRef),
} ASN1_SEQUENCE_END(ErikPartition);

IMPLEMENT_ASN1_FUNCTIONS(ErikPartition);

ASN1_SEQUENCE(ManifestRef) = {
	ASN1_SIMPLE(ManifestRef, hash, ASN1_OCTET_STRING),
	ASN1_SIMPLE(ManifestRef, size, ASN1_INTEGER),
	ASN1_SIMPLE(ManifestRef, aki, ASN1_OCTET_STRING),
	ASN1_SIMPLE(ManifestRef, manifestNumber, ASN1_INTEGER),
	ASN1_SIMPLE(ManifestRef, thisUpdate, ASN1_GENERALIZEDTIME),
	ASN1_SEQUENCE_OF(ManifestRef, location, ACCESS_DESCRIPTION),
} ASN1_SEQUENCE_END(ManifestRef);

IMPLEMENT_ASN1_FUNCTIONS(ManifestRef);

ASN1_ITEM_TEMPLATE(ManifestInstances) =
    ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, mis, ManifestInstance)
ASN1_ITEM_TEMPLATE_END(ManifestInstances);

ASN1_SEQUENCE(ErikSegmentIndex) = {
	ASN1_EXP_OPT(ErikSegmentIndex, version, ASN1_INTEGER, 0),
	ASN1_SIMPLE(ErikSegmentIndex, segmentScope, ASN1_IA5STRING),
	ASN1_SIMPLE(ErikSegmentIndex, segmentTime, ASN1_GENERALIZEDTIME),
	ASN1_SIMPLE(ErikSegmentIndex, hashAlg, X509_ALGOR),
	ASN1_SEQUENCE_OF(ErikSegmentIndex, segmentList, SegmentRef),
} ASN1_SEQUENCE_END(ErikSegmentIndex);

IMPLEMENT_ASN1_FUNCTIONS(ErikSegmentIndex);

ASN1_SEQUENCE(SegmentRef) = {
	ASN1_SIMPLE(SegmentRef, segment, ASN1_GENERALIZEDTIME),
	ASN1_SIMPLE(SegmentRef, index, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(SegmentRef);

IMPLEMENT_ASN1_FUNCTIONS(SegmentRef);

#define MAX_SEGMENT_REFS 36

static inline int
mftinstancecmp(const struct mftinstance *a, const struct mftinstance *b)
{
	return strcmp(a->sia, b->sia);
}

RB_GENERATE(mftinstance_tree, mftinstance, entry, mftinstancecmp);

void
mftref_free(struct mftref *mftref)
{
	if (mftref == NULL)
		return;

	free(mftref->hash);
	free(mftref->aki);
	free(mftref->seqnum);
	free(mftref->sia);
	free(mftref->fqdn);
	free(mftref);
}

void
mftinstance_free(struct mftinstance *mftinstance)
{
	struct ccr_mft_sub_ski *sub_ski;

	if (mftinstance == NULL)
		return;

	free(mftinstance->hash);
	free(mftinstance->aki);
	free(mftinstance->seqnum);
	free(mftinstance->sia);
	free(mftinstance->fqdn);

	while (!SLIST_EMPTY(&mftinstance->subordinates)) {
		sub_ski = SLIST_FIRST(&mftinstance->subordinates);
		SLIST_REMOVE_HEAD(&mftinstance->subordinates, entry);
		free(sub_ski);
	}

	free(mftinstance);
}

static inline int
mft_compare_seqnum(char *a, char *b)
{
	int r;

	r = strlen(a) - strlen(b);
	if (r > 0)
		return 1;
	if (r < 0)
		return -1;

	r = strcmp(a, b);
	if (r > 0)
		return 1;
	if (r < 0)
		return -1;

	return 0;
}

/*
 * Insert new ManifestInstances into tree, or replacing an existing entry
 * if the existing entry's thisUpdate is older.
 * Return 1 if a new object was added to the tree, and otherwise 0.
 */
static inline int
insert_mftinstance_tree(struct mftinstance **mi, struct mftinstance_tree *tree)
{
	struct mftinstance *found;

	/*
	 * Check if the mft instance at hand is 'more recent' than the
	 * one in the RB tree, if so replace the in-tree version.
	 */
	if ((found = RB_INSERT(mftinstance_tree, tree, (*mi))) != NULL) {
		/*
		 * RFC 9286, section 4.2.1:
		 * manifestNumber: Each RP MUST verify that a purported "new"
		 *   manifest contains a higher manifestNumber than previously
		 *   validated manifests. If equal or lower use previously
		 *   validated manifest.
		 * thisUpdate: Each RP MUST verify that this field value is
		 *   greater (more recent) than the most recent manifest it has
		 *   validated.
		 */
		if (mft_compare_seqnum(found->seqnum, (*mi)->seqnum) == -1 &&
		    (*mi)->thisupdate > found->thisupdate) {
			RB_REMOVE(mftinstance_tree, tree, found);
			mftinstance_free(found);

			RB_INSERT(mftinstance_tree, tree, (*mi));

			/* steal the resource from the ccr struct */
			*mi = NULL;
		}

		return 0;
	}

	/* steal the resource from the ccr struct */
	*mi = NULL;

	return 1;
}

int
merge_ccrs(char *argv[], struct mftinstance_tree *tree)
{
	struct file *f;
	struct ccr *ccr;
	int i, count = 0;

	for (; *argv != NULL; ++argv) {
		if ((f = calloc(1, sizeof(*f))) == NULL)
			err(1, NULL);

		f->name = strdup(*argv);

		if ((f->type = detect_ftype_from_fn(*argv)) != TYPE_CCR) {
			warnx("%s: -C only accepts .ccr", f->name);
			usage();
		}

		f->content = load_file(f->name, &f->content_len, &f->disktime);
		if (f->content == NULL)
			errx(1, "%s: load_file failed", f->name);

		if ((ccr = parse_ccr(f)) == NULL) {
			warnx("%s: parsing failed", f->name);
			goto out;
		}

		for (i = 0; i < ccr->mis_num; i++) {
			count += insert_mftinstance_tree(&ccr->mis[i], tree);
		}

		ccr_free(ccr);
		ccr = NULL;
		file_free(f);
		f = NULL;
	}

 out:
	ccr_free(ccr);
	file_free(f);

	return count;
}

static void
asn1int_set_seqnum(ASN1_INTEGER *aint, const char *seqnum)
{
	BIGNUM *bn = NULL;

	if (!BN_hex2bn(&bn, seqnum))
		errx(1, "BN_hex2bn");

	if (BN_to_ASN1_INTEGER(bn, aint) == NULL)
		errx(1, "BN_to_ASN1_INTEGER");

	BN_free(bn);
}

static void
location_add_sia(STACK_OF(ACCESS_DESCRIPTION) *sad, const char *sia)
{
	ACCESS_DESCRIPTION *ad = NULL;

	if ((ad = ACCESS_DESCRIPTION_new()) == NULL)
		errx(1, "ACCESS_DESCRIPTION_new");

	ASN1_OBJECT_free(ad->method);
	if ((ad->method = OBJ_nid2obj(NID_signedObject)) == NULL)
		errx(1, "OBJ_nid2obj");

	GENERAL_NAME_free(ad->location);
	ad->location = a2i_GENERAL_NAME(NULL, NULL, NULL, GEN_URI, sia, 0);
	if (ad->location == NULL)
		errx(1, "a2i_GENERAL_NAME");

	if (sk_ACCESS_DESCRIPTION_push(sad, ad) <= 0)
		errx(1, "sk_ACCESS_DESCRIPTION_push");
}

static ManifestRef *
make_manifestref(struct mftinstance *m)
{
	ManifestRef *mr = NULL;
	static unsigned char hash[SHA256_DIGEST_LENGTH] = { 0 };
	static unsigned char aki[SHA_DIGEST_LENGTH] = { 0 };

	if ((mr = ManifestRef_new()) == NULL)
		errx(1, "ManifestRef_new");

	if (hex_decode(m->hash, (char *)hash, sizeof(hash)) != 0)
		errx(1, "hex_decode");

	if (!ASN1_OCTET_STRING_set(mr->hash, hash, sizeof(hash)))
		errx(1, "ASN1_OCTET_STRING_set");

	if (!ASN1_INTEGER_set_uint64(mr->size, m->size))
		errx(1, "ASN1_INTEGER_set_uint64");

	if (hex_decode(m->aki, (char *)aki, sizeof(aki)) != 0)
		errx(1, "hex_decode");

	if (!ASN1_OCTET_STRING_set(mr->aki, aki, sizeof(aki)))
		errx(1, "ASN1_OCTET_STRING_set");

	asn1int_set_seqnum(mr->manifestNumber, m->seqnum);

	if (ASN1_GENERALIZEDTIME_set(mr->thisUpdate, m->thisupdate) == NULL)
		errx(1, "ASN1_GENERALIZEDTIME_set");

	location_add_sia(mr->location, m->sia);

	return mr;
}

static ErikIndex *
start_ErikIndex(const char *fqdn)
{
	ErikIndex *ei;
	ASN1_OBJECT *oid;

	if ((ei = ErikIndex_new()) == NULL)
		errx(1, "ErikIndex_new");

	if (!ASN1_STRING_set(ei->indexScope, fqdn, -1))
		errx(1, "ASN1_STRING_set");

	if ((oid = OBJ_nid2obj(NID_sha256)) == NULL)
		errx(1, "OBJ_nid2obj");

	if (!X509_ALGOR_set0(ei->hashAlg, oid, V_ASN1_UNDEF, NULL))
		errx(1, "X509_ALGOR_set0");

	return ei;
}

static ErikPartition *
start_ErikPartition(void)
{
	ErikPartition *ep;
	ASN1_OBJECT *oid;

	if ((ep = ErikPartition_new()) == NULL)
		errx(1, "ErikPartition_new");

	if ((oid = OBJ_nid2obj(NID_sha256)) == NULL)
		errx(1, "OBJ_nid2obj");

	if (!X509_ALGOR_set0(ep->hashAlg, oid, V_ASN1_UNDEF, NULL))
		errx(1, "X509_ALGOR_set0");

	return ep;
}

static void
update_index_ptr(char *fqdn, unsigned char hash[SHA256_DIGEST_LENGTH])
{
	char *fqdn_fn, *ni_fn, *ni_path, *oi_fn, *oi_path, *tmp;

	if (mkpathat(outdirfd, "erik/index") == -1)
		err(1, "mkpathat %s", "erik/index");

	if (asprintf(&fqdn_fn, "erik/index/%s", fqdn) == -1)
		err(1, NULL);

	if (!b64uri_encode(hash, SHA256_DIGEST_LENGTH, &ni_fn))
		err(1, "b64uri_encode");

	if (asprintf(&ni_path, "../../static/%c%c/%c%c/%s", ni_fn[39],
	    ni_fn[40], ni_fn[41], ni_fn[42], ni_fn) == -1)
		err(1, NULL);

	if ((oi_path = strdup(ni_path)) == NULL)
		err(1, NULL);

	errno = 0;
	if (readlinkat(outdirfd, fqdn_fn, oi_path, strlen(oi_path) + 1) == -1
	    && (errno != ENOENT && errno != EINVAL))
		errx(1, "readlinkat");
	if (errno == ENOENT || errno == EINVAL) {
		warnx("new erik index ptr: %s %s", fqdn_fn, ni_fn);
	} else if (strcmp(ni_path, oi_path) == 0)
		goto out;
	else {
		oi_fn = strrchr(oi_path, '/');
		warnx("erik index ptr changed: %s %s -> %s", fqdn_fn, oi_fn,
		    ni_fn);
	}

	if (asprintf(&tmp, "erik/index/.%s.XXXXXXXXX", fqdn) == -1)
		err(1, NULL);

	if (mkstemplinkat(outdirfd, tmp, ni_path) == -1)
		errx(1, "mkstemplinkat");

	if (renameat(outdirfd, tmp, outdirfd, fqdn_fn) == -1)
		errx(1, "renameat");

 out:
	free(fqdn_fn);
	free(ni_fn);
	free(ni_path);
	free(oi_path);
}

static void
update_segmentindex(char *fqdn, time_t indextime, time_t segmenttime,
    unsigned char idxhash[SHA256_DIGEST_LENGTH])
{
	struct file *f;
	const unsigned char *oder, *der;
	ESI_ContentInfo *ci = NULL;
	ErikSegmentIndex *esi_asn1;
	time_t segtime = 0, srtime = 0;
	ASN1_OBJECT *oid;
	ASN1_IA5STRING *ia5;
	ASN1_OCTET_STRING *aos;
	SegmentRef *sr;
	int refs_num = 0;

	if (segmenttime == 0)
		return;

	assert(indextime != 0);

	if ((aos = ASN1_OCTET_STRING_new()) == NULL)
		errx(1, "ASN1_OCTET_STRING_new");

	if (!ASN1_OCTET_STRING_set(aos, idxhash, SHA256_DIGEST_LENGTH))
		errx(1, "ASN1_OCTET_STRING_set");

	if (mkpathat(outdirfd, "erik/segmentindex"))
		err(1, "mkpathat erik/segmentindex");

	if ((f = calloc(1, sizeof(*f))) == NULL)
		err(1, NULL);

	if (asprintf(&f->name, "erik/segmentindex/%s", fqdn) == -1)
		err(1, NULL);

	f->content = load_fileat(f->name, &f->content_len, &f->disktime);

	if (f->content != NULL) {
		oder = der = f->content;
		if ((ci = d2i_ESI_ContentInfo(NULL, &der, f->content_len)) == NULL) {
			warnx("%s: d2i_ESI_ContentInfo failed", f->name);
			goto new;
		}
		if (der != oder + f->content_len) {
			warnx("%s: %td bytes trailing garbage", f->name,
			    oder + f->content_len - der);
			goto new;
		}

		if (OBJ_cmp(ci->contentType, esi_oid) != 0) {
			char buf[128];

			OBJ_obj2txt(buf, sizeof(buf), ci->contentType, 1);
			warnx("%s: unexpected OID: got %s, want "
			    "1.2.840.113549.1.9.16.1.59", f->name, buf);
			goto new;
		}

		esi_asn1 = ci->content;

		if (esi_asn1->version != NULL) {
			warnx("%s: version not 0", f->name);
			goto new;
		}

		ia5 = esi_asn1->segmentScope;
		if (ia5->length != (int)strlen(fqdn) ||
		    (strncasecmp((char *)ia5->data, fqdn, strlen(fqdn)) != 0)) {
			warnx("%s: wrong segmentScope (got %s, want %s)",
			    f->name, (char *)ia5->data, fqdn);
			goto new;
		}

		if (!asn1time_to_time(esi_asn1->segmentTime, &segtime, 1)) {
			warnx("%s: failed to convert segmentTime", f->name);
			goto new;
		}
		if (indextime != segtime) {
			if (ASN1_GENERALIZEDTIME_set(esi_asn1->segmentTime,
			    indextime) == NULL)
				errx(1, "ASN1_GENERALIZEDTIME_set");
		}

		/* XXX: add check for esi_asn1->hashAlg */

		refs_num = sk_SegmentRef_num(esi_asn1->segmentList);
		if (refs_num < 1 || refs_num > MAX_SEGMENT_REFS) {
			warnx("%s: malformed segmentList", f->name);
			goto new;
		}

		/* XXX: add check for sorting */

		sr = sk_SegmentRef_value(esi_asn1->segmentList, refs_num - 1);
		if (sr == NULL)
			errx(1, "sk_SegmentRef_value");

		if (!asn1time_to_time(sr->segment, &srtime, 1)) {
			warnx("%s: failed to convert SegmentRef segment",
			    f->name);
			goto new;
		}
		if (segmenttime == srtime) {
			if (ASN1_OCTET_STRING_cmp(sr->index, aos) == 0) {
				warnx("%s: nothing to update", f->name);
				goto out;
			} else {
				ASN1_OCTET_STRING_free(sr->index);
				sr->index = aos;
			}
		} else {
			if ((sr = SegmentRef_new()) == NULL)
				errx(1, "SegmentRef_new");

			if (ASN1_GENERALIZEDTIME_set(sr->segment, segmenttime)
			    == NULL)
				errx(1, "ASN1_GENERALIZEDTIME_set");

			sr->index = aos;

			if (sk_SegmentRef_push(esi_asn1->segmentList, sr) <= 0)
				errx(1, "sk_SegmentRef_push");
		}

		while (refs_num > MAX_SEGMENT_REFS) {
			/* XXX: use sr to delete the old segment on disk? */
			sr = sk_SegmentRef_shift(esi_asn1->segmentList);
			SegmentRef_free(sr);
			refs_num--;
		}

	} else {
 new:
		if (ci != NULL)
			ESI_ContentInfo_free(ci);

		if ((ci = ESI_ContentInfo_new()) == NULL)
			errx(1, "ESI_ContentInfo");

		ASN1_OBJECT_free(ci->contentType);
		if ((ci->contentType = OBJ_dup(esi_oid)) == NULL)
			errx(1, "OBJ_dup");

		if ((esi_asn1 = ErikSegmentIndex_new()) == NULL)
			err(1, "ErikSegmentIndex_new");

		if (!ASN1_STRING_set(esi_asn1->segmentScope, fqdn, -1))
			errx(1, "ASN1_STRING_set");

		if (ASN1_GENERALIZEDTIME_set(esi_asn1->segmentTime, indextime)
		    == NULL)
			errx(1, "ASN1_GENERALIZEDTIME_set");

		if ((oid = OBJ_nid2obj(NID_sha256)) == NULL)
			errx(1, "OBJ_nid2obj");

		if (!X509_ALGOR_set0(esi_asn1->hashAlg, oid, V_ASN1_UNDEF, NULL))
			errx(1, "X509_ALGOR_set0");

		if ((esi_asn1->segmentList = sk_SegmentRef_new_null()) == NULL)
			errx(1, "sk_SegmentRef_new_null");

		if ((sr = SegmentRef_new()) == NULL)
			errx(1, "SegmentRef_new");

		if (ASN1_GENERALIZEDTIME_set(sr->segment, segmenttime) == NULL)
			errx(1, "ASN1_GENERALIZEDTIME_set");

		sr->index = aos;

		if (sk_SegmentRef_push(esi_asn1->segmentList, sr) <= 0)
			errx(1, "sk_SegmentRef_push");
	}

	ci->content = esi_asn1;

	free(f->content);
	f->content = NULL;
	if ((f->content_len = i2d_ESI_ContentInfo(ci, &f->content)) <= 0)
		errx(1, "i2d_ESI_ContentInfo");

	if (verbose) {
		int delay;
		char *h;

		delay = time(NULL) - indextime;

		if (!b64uri_encode(idxhash, SHA256_DIGEST_LENGTH, &h))
			err(1, "b64uri_encode");

		warnx("added to %s segment:%lld index:%s (itime:%lld, d:%d)",
		    f->name, (long long)segmenttime, h, (long long)indextime,
		    delay);

		free(h);
	}

	write_file(f->name, f->content, f->content_len, 0);
 out:
	ESI_ContentInfo_free(ci);
	file_free(f);
}

static void
finalize_ErikIndex(ErikIndex *ei, char *fqdn, time_t itime, uint64_t csize,
    time_t segment)
{
	EI_ContentInfo *ci = NULL;
	struct file *f;

	if (ASN1_GENERALIZEDTIME_set(ei->indexTime, itime) == NULL)
		errx(1, "ASN1_GENERALIZEDTIME_set");

	if ((ci = EI_ContentInfo_new()) == NULL)
		errx(1, "EI_ContentInfo_new");

	ASN1_OBJECT_free(ci->contentType);
	if ((ci->contentType = OBJ_dup(eidx_oid)) == NULL)
		errx(1, "OBJ_dup");

	ErikIndex_free(ci->content);
	ci->content = ei;

	if ((f = calloc(1, sizeof(*f))) == NULL)
		err(1, NULL);

	f->content = NULL;
	if ((f->content_len = i2d_EI_ContentInfo(ci, &f->content)) <= 0)
		errx(1, "i2d_EI_ContentInfo");

	EI_ContentInfo_free(ci);

	SHA256(f->content, f->content_len, f->hash);

	f->signtime = itime;

	if (asprintf(&f->name, "erik index: %s", fqdn) == -1)
		err(1, "asprintf");

	if (store_by_hash(f, 0) && !noop) {
		update_index_ptr(fqdn, f->hash);
		append_to_segment(fqdn, f, itime, segment);
		update_segmentindex(fqdn, itime, segment, f->hash);
	}

	file_free(f);
}

static PartitionRef *
finalize_ErikPartition(ErikPartition *ep, char *fqdn, int num, time_t ptime,
    time_t segment)
{
	EP_ContentInfo *ci = NULL;
	PartitionRef *pr = NULL;
	struct file *f;

	if (ASN1_GENERALIZEDTIME_set(ep->partitionTime, ptime) == NULL)
		errx(1, "ASN1_GENERALIZEDTIME_set");

	if ((ci = EP_ContentInfo_new()) == NULL)
		errx(1, "EP_ContentInfo_new");

	ASN1_OBJECT_free(ci->contentType);
	if ((ci->contentType = OBJ_dup(epar_oid)) == NULL)
		errx(1, "OBJ_dup");

	ErikPartition_free(ci->content);
	ci->content = ep;

	if ((f = calloc(1, sizeof(*f))) == NULL)
		err(1, NULL);

	f->content = NULL;
	if ((f->content_len = i2d_EP_ContentInfo(ci, &f->content)) <= 0)
		errx(1, "i2d_EP_ContentInfo");

	EP_ContentInfo_free(ci);

	SHA256(f->content, f->content_len, f->hash);

	f->signtime = ptime;

	if (asprintf(&f->name, "erik partition: %s#%d", fqdn, num) == -1)
		err(1, "asprintf");

	if (store_by_hash(f, 0) && !noop)
		append_to_segment(fqdn, f, ptime, segment);

	if ((pr = PartitionRef_new()) == NULL)
		errx(1, "PartitionRef_new");

	if (!ASN1_OCTET_STRING_set(pr->hash, f->hash, sizeof(f->hash)))
		errx(1, "ASN1_OCTET_STRING_set");

	if (!ASN1_INTEGER_set_uint64(pr->size, f->content_len))
		errx(1, "ASN1_INTEGER_set_uint64");

	file_free(f);

	return pr;
}

void
generate_erik_objects(struct mftinstance **mis, int count, char *single_fqdn,
    time_t segment)
{
	struct mftinstance *mi;
	char *prev_fqdn, *prev_aki;
	ErikIndex *ei = NULL;
	ErikPartition *ep = NULL;
	PartitionRef *pr = NULL;
	ManifestRef *mr = NULL;
	time_t itime = 0, ptime = 0;
	uint64_t csize = 0;
	int i, num;

	prev_fqdn = prev_aki = NULL;
	for (i = 0; i < count; i++) {
		if (single_fqdn != NULL) {
			if (strcmp(mis[i]->fqdn, single_fqdn) != 0)
				continue;
		}

		mi = mis[i];
		mr = make_manifestref(mi);

		if (prev_fqdn == NULL && prev_aki == NULL) {
			prev_fqdn = mi->fqdn;
			prev_aki = mi->aki;

			ei = start_ErikIndex(mi->fqdn);
			itime = 0;
			csize = 0;

			ep = start_ErikPartition();
			ptime = 0;
		}

		if (strcmp(prev_fqdn, mi->fqdn) != 0) {
			num = sk_PartitionRef_num(ei->partitionList) + 1;

			pr = finalize_ErikPartition(ep, prev_fqdn, num, ptime,
			    segment);

			if (sk_PartitionRef_push(ei->partitionList, pr) <= 0)
				errx(1, "sk_PartitionRef_push");

			finalize_ErikIndex(ei, prev_fqdn, itime, csize, segment);

			ei = start_ErikIndex(mi->fqdn);
			itime = 0;
			csize = 0;

			ep = start_ErikPartition();
			ptime = 0;
		} else if (strncmp(prev_aki, mi->aki, 2) != 0) {
			num = sk_PartitionRef_num(ei->partitionList) + 1;

			pr = finalize_ErikPartition(ep, prev_fqdn, num, ptime,
			    segment);

			if (sk_PartitionRef_push(ei->partitionList, pr) <= 0)
				errx(1, "sk_PartitionRef_push");

			ep = start_ErikPartition();
			ptime = 0;
		}

		if (sk_ManifestRef_push(ep->manifestList, mr) <= 0)
			errx(1, "sk_ManifestRef_push");

		if (mi->thisupdate > itime)
			itime = mi->thisupdate;

		if (mi->thisupdate > ptime)
			ptime = mi->thisupdate;

		csize += mi->size;

		prev_fqdn = mi->fqdn;
		prev_aki = mi->aki;
	}

	if (prev_fqdn == NULL)
		return;

	num = sk_PartitionRef_num(ei->partitionList) + 1;
	pr = finalize_ErikPartition(ep, prev_fqdn, num, ptime, segment);
	if (sk_PartitionRef_push(ei->partitionList, pr) <= 0)
		errx(1, "sk_PartitionRef_push");
	finalize_ErikIndex(ei, mi->fqdn, itime, csize, segment);
}

static int
ski_cmp(const ASN1_OCTET_STRING *const *a, const ASN1_OCTET_STRING *const *b)
{
	return ASN1_OCTET_STRING_cmp(*a, *b);
}

static ManifestInstance *
make_manifestinstance(struct mftinstance *m)
{
	ManifestInstance *mi = NULL;
	ASN1_OCTET_STRING *asn1_ski;
	struct ccr_mft_sub_ski *sub;
	static unsigned char hash[SHA256_DIGEST_LENGTH] = { 0 };
	static unsigned char aki[SHA_DIGEST_LENGTH] = { 0 };

	if ((mi = ManifestInstance_new()) == NULL)
		errx(1, "ManifestInstance_new");

	if (hex_decode(m->hash, (char *)hash, sizeof(hash)) != 0)
		errx(1, "hex_decode");

	if (!ASN1_OCTET_STRING_set(mi->hash, hash, sizeof(hash)))
		errx(1, "ASN1_OCTET_STRING_set");

	if (!ASN1_INTEGER_set_uint64(mi->size, m->size))
		errx(1, "ASN1_INTEGER_set_uint64");

	if (hex_decode(m->aki, (char *)aki, sizeof(aki)) != 0)
		errx(1, "hex_decode");

	if (!ASN1_OCTET_STRING_set(mi->aki, aki, sizeof(aki)))
		errx(1, "ASN1_OCTET_STRING_set");

	asn1int_set_seqnum(mi->manifestNumber, m->seqnum);

	if (ASN1_GENERALIZEDTIME_set(mi->thisUpdate, m->thisupdate) == NULL)
		errx(1, "ASN1_GENERALIZEDTIME_set");

	location_add_sia(mi->locations, m->sia);

	if (SLIST_EMPTY(&m->subordinates))
		return mi;

	if ((mi->subordinates = sk_ASN1_OCTET_STRING_new(ski_cmp)) == NULL)
		err(1, NULL);

	SLIST_FOREACH(sub, &m->subordinates, entry) {
		if ((asn1_ski = ASN1_OCTET_STRING_new()) == NULL)
			err(1, NULL);

		if (!ASN1_OCTET_STRING_set(asn1_ski, sub->ski, sizeof(sub->ski)))
			errx(1, "ASN1_OCTET_STRING_set");

		if (sk_ASN1_OCTET_STRING_push(mi->subordinates, asn1_ski) <= 0)
			errx(1, "sk_ASN1_OCTET_STRING_push");
	}

	sk_ASN1_OCTET_STRING_sort(mi->subordinates);

	return mi;
}

struct file *
generate_reduced_ccr(struct mftinstance **mis, int count)
{
	ManifestState *ms = NULL;
	ManifestInstance *asn1_mi = NULL;
	time_t mostrecent = 0, producedat = 0;
	char *mshash;
	CanonicalCacheRepresentation *ccr = NULL;
	ASN1_OBJECT *oid;
	CCR_ContentInfo *ci = NULL;
	struct file *f;
	int i;

	if ((ms = ManifestState_new()) == NULL)
		errx(1, "ManifestState_new");

	for (i = 0; i < count; i++) {
		asn1_mi = make_manifestinstance(mis[i]);

		if (sk_ManifestInstance_push(ms->mis, asn1_mi) <= 0)
			errx(1, "sk_ManifestRef_push");

		if (mis[i]->thisupdate > mostrecent)
			mostrecent = mis[i]->thisupdate;
	}

	if (ASN1_GENERALIZEDTIME_set(ms->mostRecentUpdate, mostrecent) == NULL)
		errx(1, "ASN1_GENERALIZEDTIME_set");

	hash_asn1_item(ms->hash, ASN1_ITEM_rptr(ManifestInstances), ms->mis);

	if (!b64_encode(ms->hash->data, ms->hash->length, &mshash))
		errx(1, "b64_encode");
	printf("%s\n", mshash);
	free(mshash);

	if ((ccr = CanonicalCacheRepresentation_new()) == NULL)
		errx(1, "CanonicalCacheRepresentation_new");

	if ((oid = OBJ_nid2obj(NID_sha256)) == NULL)
		errx(1, "OBJ_nid2obj");

	if (!X509_ALGOR_set0(ccr->hashAlg, oid, V_ASN1_UNDEF, NULL))
		errx(1, "X509_ALGOR_set0");

	producedat = time(NULL);
	if (ASN1_GENERALIZEDTIME_set(ccr->producedAt, producedat) == NULL)
		errx(1, "ASN1_GENERALIZEDTIME_set");

	ccr->mfts = ms;

	if ((ci = CCR_ContentInfo_new()) == NULL)
		errx(1, "CCR_ContentInfo_new");

	ASN1_OBJECT_free(ci->contentType);
	if ((ci->contentType = OBJ_dup(ccr_oid)) == NULL)
		errx(1, "OBJ_dup");

	CanonicalCacheRepresentation_free(ci->content);
	ci->content = ccr;

	if ((f = calloc(1, sizeof(*f))) == NULL)
		err(1, NULL);

	f->name = NULL;
	f->content = NULL;
	f->signtime = producedat;
	if ((f->content_len = i2d_CCR_ContentInfo(ci, &f->content)) <= 0)
		errx(1, "i2d_CCR_ContentInfo");

	CCR_ContentInfo_free(ci);

	return f;
}
