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

#include <sys/stat.h>

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
ASN1_ITEM_EXP CanonicalCacheRepresentation_it;
ASN1_ITEM_EXP ErikIndex_it;
ASN1_ITEM_EXP PartitionRef_it;
ASN1_ITEM_EXP ErikPartition_it;
ASN1_ITEM_EXP ManifestRef_it;
ASN1_ITEM_EXP ManifestInstance_it;
ASN1_ITEM_EXP ManifestInstances_it;

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

ASN1_SEQUENCE(CanonicalCacheRepresentation) = {
	ASN1_EXP_OPT(CanonicalCacheRepresentation, version, ASN1_INTEGER, 0),
	ASN1_SIMPLE(CanonicalCacheRepresentation, hashAlg, X509_ALGOR),
	ASN1_SIMPLE(CanonicalCacheRepresentation, producedAt,
	    ASN1_GENERALIZEDTIME),
	ASN1_EXP_OPT(CanonicalCacheRepresentation, mfts, ManifestState, 1),
	ASN1_EXP_OPT(CanonicalCacheRepresentation, vrps, ASN1_SEQUENCE_ANY, 2),
	ASN1_EXP_OPT(CanonicalCacheRepresentation, vaps, ASN1_SEQUENCE_ANY, 3),
	ASN1_EXP_OPT(CanonicalCacheRepresentation, tas, ASN1_SEQUENCE_ANY, 4),
	ASN1_EXP_OPT(CanonicalCacheRepresentation, rks, ASN1_SEQUENCE_ANY, 5),
} ASN1_SEQUENCE_END(CanonicalCacheRepresentation);

IMPLEMENT_ASN1_FUNCTIONS(CanonicalCacheRepresentation);

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

/*
 * Insert new ManifestInstances into tree, or replacing an existing entry
 * if the existing entry's thisUpdate is older.
 * Return 1 if a new object was added to the tree, and otherwise 0.
 */
static inline int
insert_mftinstance_tree(struct mftinstance **mi, struct mftinstance_tree *tree)
{
	struct mftinstance *found;

	if ((found = RB_INSERT(mftinstance_tree, tree, (*mi))) != NULL) {

		/*
		 * Check if the mft instance at hand is newer than the one
		 * in the RB tree, if so replace the in-tree version.
		 */
		if ((*mi)->thisupdate > found->thisupdate) {
			RB_REMOVE(mftinstance_tree, tree, found);
			mftinstance_free(found);

			RB_INSERT(mftinstance_tree, tree, (*mi));

			/* steal the resource from the ccr struct */
			*mi = NULL;
		}

		/* XXX: should also compare seqnum */

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
	unsigned char *fc;
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

		fc = load_file(f->name, &f->content_len, &f->disktime);
		if (fc == NULL)
			errx(1, "%s: load_file failed", f->name);
		f->content = fc;

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
	char *fqdn_fn, *hash_fn, *hash_path;
	struct stat f_st, h_st;

	if (!noop) {
		if (mkpathat(outdirfd, "erik/index") == -1)
			err(1, "mkpathat %s", "erik/index");
	}

	if (!b64uri_encode(hash, SHA256_DIGEST_LENGTH, &hash_fn))
		err(1, "b64uri_encode");

	if (asprintf(&hash_path, "static/%c%c/%c%c/%s", hash_fn[39],
	    hash_fn[40], hash_fn[41], hash_fn[42], hash_fn) == -1)
		err(1, NULL);

	if (asprintf(&fqdn_fn, "erik/index/%s", fqdn) == -1)
		err(1, NULL);

	memset(&f_st, 0, sizeof(f_st));

	if ((fstatat(outdirfd, fqdn_fn, &f_st, 0) != 0) && errno != ENOENT)
		err(1, "fstatat %s", fqdn_fn);

	memset(&h_st, 0, sizeof(h_st));

	if (fstatat(outdirfd, hash_path, &h_st, 0) != 0)
		err(1, "fstatat %s", hash_fn);

	if (f_st.st_ino != h_st.st_ino) {
		if ((unlinkat(outdirfd, fqdn_fn, 0) == -1 && errno != ENOENT) ||
		    linkat(outdirfd, hash_path, outdirfd, fqdn_fn, 0))
			errx(1, "linkat %s %s", hash_path, fqdn_fn);
		warnx("erik index ptr changed: %s %s", fqdn_fn, hash_path);
	}

	free(fqdn_fn);
	free(hash_fn);
	free(hash_path);
}

static void
finalize_ErikIndex(ErikIndex *ei, char *fqdn, time_t itime)
{
	EI_ContentInfo *ci = NULL;
	struct file *f;

	if (ASN1_GENERALIZEDTIME_set(ei->indexTime, itime) == NULL)
		errx(1, "ASN1_GENERALIZEDTIME_set");

	if ((ci = EI_ContentInfo_new()) == NULL)
		errx(1, "EI_ContentInfo_new");

	ASN1_OBJECT_free(ci->contentType);
	if ((ci->contentType = OBJ_dup(idx_oid)) == NULL)
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

	store_by_hash(f);

	update_index_ptr(fqdn, f->hash);

	file_free(f);
}

static PartitionRef *
finalize_ErikPartition(ErikPartition *ep, char *fqdn, int num, time_t ptime)
{
	EP_ContentInfo *ci = NULL;
	PartitionRef *pr = NULL;
	struct file *f;

	if (ASN1_GENERALIZEDTIME_set(ep->partitionTime, ptime) == NULL)
		errx(1, "ASN1_GENERALIZEDTIME_set");

	if ((ci = EP_ContentInfo_new()) == NULL)
		errx(1, "EP_ContentInfo_new");

	ASN1_OBJECT_free(ci->contentType);
	if ((ci->contentType = OBJ_dup(par_oid)) == NULL)
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

	store_by_hash(f);

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
generate_erik_objects(struct mftinstance **mis, int count, char *single_fqdn)
{
	struct mftinstance *mi;
	char *prev_fqdn, *prev_aki;
	ErikIndex *ei = NULL;
	ErikPartition *ep = NULL;
	PartitionRef *pr = NULL;
	ManifestRef *mr = NULL;
	time_t itime = 0, ptime = 0;
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

			ep = start_ErikPartition();
			ptime = 0;
		}

		if (strcmp(prev_fqdn, mi->fqdn) != 0) {
			num = sk_PartitionRef_num(ei->partitionList) + 1;

			pr = finalize_ErikPartition(ep, prev_fqdn, num, ptime);

			if (sk_PartitionRef_push(ei->partitionList, pr) <= 0)
				errx(1, "sk_PartitionRef_push");

			finalize_ErikIndex(ei, prev_fqdn, itime);

			ei = start_ErikIndex(mi->fqdn);
			itime = 0;

			ep = start_ErikPartition();
			ptime = 0;
		} else if (strncmp(prev_aki, mi->aki, 2) != 0) {
			num = sk_PartitionRef_num(ei->partitionList) + 1;

			pr = finalize_ErikPartition(ep, prev_fqdn, num, ptime);

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

		prev_fqdn = mi->fqdn;
		prev_aki = mi->aki;
	}

	if (prev_fqdn == NULL)
		return;

	num = sk_PartitionRef_num(ei->partitionList) + 1;
	pr = finalize_ErikPartition(ep, prev_fqdn, num, ptime);
	if (sk_PartitionRef_push(ei->partitionList, pr) <= 0)
		errx(1, "sk_PartitionRef_push");
	finalize_ErikIndex(ei, mi->fqdn, itime);
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
	struct mftinstance *mi;
	ManifestState *ms = NULL;
	ManifestInstance *asn1_mi = NULL;
	time_t mostrecent = 0;
	CanonicalCacheRepresentation *ccr = NULL;
	ASN1_OBJECT *oid;
	CCR_ContentInfo *ci = NULL;
	struct file *f;
	int i;

	if ((ms = ManifestState_new()) == NULL)
		errx(1, "ManifestState_new");

	for (i = 0; i < count; i++) {
		char *sia;
		mi = mis[i];

		if (asprintf(&sia, "rsync://%s", mi->sia) == -1)
			err(1, "asprintf");
		free(mi->sia);
		mi->sia = sia;

		asn1_mi = make_manifestinstance(mi);

		if (sk_ManifestInstance_push(ms->mis, asn1_mi) <= 0)
			errx(1, "sk_ManifestRef_push");

		if (mi->thisupdate > mostrecent)
			mostrecent = mi->thisupdate;
	}

	if (ASN1_GENERALIZEDTIME_set(ms->mostRecentUpdate, mostrecent) == NULL)
		errx(1, "ASN1_GENERALIZEDTIME_set");

	hash_asn1_item(ms->hash, ASN1_ITEM_rptr(ManifestInstances), ms->mis);

	if ((ccr = CanonicalCacheRepresentation_new()) == NULL)
		errx(1, "CanonicalCacheRepresentation_new");

	if ((oid = OBJ_nid2obj(NID_sha256)) == NULL)
		errx(1, "OBJ_nid2obj");

	if (!X509_ALGOR_set0(ccr->hashAlg, oid, V_ASN1_UNDEF, NULL))
		errx(1, "X509_ALGOR_set0");

	if (ASN1_GENERALIZEDTIME_set(ccr->producedAt, time(NULL)) == NULL)
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
	if ((f->content_len = i2d_CCR_ContentInfo(ci, &f->content)) <= 0)
		errx(1, "i2d_CCR_ContentInfo");

	CCR_ContentInfo_free(ci);

	return f;
}
