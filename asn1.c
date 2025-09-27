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

ASN1_ITEM_EXP ContentInfo_it;
ASN1_ITEM_EXP CanonicalCacheRepresentation_it;
ASN1_ITEM_EXP ErikIndex_it;
ASN1_ITEM_EXP PartitionRef_it;
ASN1_ITEM_EXP ErikPartition_it;
ASN1_ITEM_EXP ManifestRef_it;
ASN1_ITEM_EXP ManifestRefs_it;

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
	ASN1_EXP_OPT(CanonicalCacheRepresentation, rks, ASN1_SEQUENCE_ANY, 5),
} ASN1_SEQUENCE_END(CanonicalCacheRepresentation);

IMPLEMENT_ASN1_FUNCTIONS(CanonicalCacheRepresentation);

ASN1_SEQUENCE(ManifestState) = {
	ASN1_SEQUENCE_OF(ManifestState, mftrefs, ManifestRef),
	ASN1_SIMPLE(ManifestState, mostRecentUpdate, ASN1_GENERALIZEDTIME),
	ASN1_SIMPLE(ManifestState, hash, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(ManifestState);

IMPLEMENT_ASN1_FUNCTIONS(ManifestState);

ASN1_SEQUENCE(ErikIndex) = {
	ASN1_EXP_OPT(ErikIndex, version, ASN1_INTEGER, 0),
	ASN1_SIMPLE(ErikIndex, indexScope, ASN1_IA5STRING),
	ASN1_SIMPLE(ErikIndex, indexTime, ASN1_GENERALIZEDTIME),
	ASN1_SIMPLE(ErikIndex, hashAlg, ASN1_OBJECT),
	ASN1_SEQUENCE_OF(ErikIndex, partitionList, PartitionRef),
} ASN1_SEQUENCE_END(ErikIndex);

IMPLEMENT_ASN1_FUNCTIONS(ErikIndex);

ASN1_SEQUENCE(PartitionRef) = {
	ASN1_SIMPLE(PartitionRef, identifier, ASN1_INTEGER),
	ASN1_SIMPLE(PartitionRef, hash, ASN1_OCTET_STRING),
	ASN1_SIMPLE(PartitionRef, size, ASN1_INTEGER),
} ASN1_SEQUENCE_END(PartitionRef);

IMPLEMENT_ASN1_FUNCTIONS(PartitionRef);

ASN1_SEQUENCE(ErikPartition) = {
	ASN1_EXP_OPT(ErikPartition, version, ASN1_INTEGER, 0),
	ASN1_SIMPLE(ErikPartition, partitionTime, ASN1_GENERALIZEDTIME),
	ASN1_SIMPLE(ErikPartition, hashAlg, ASN1_OBJECT),
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

ASN1_ITEM_TEMPLATE(ManifestRefs) =
    ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, mftrefs, ManifestRef)
ASN1_ITEM_TEMPLATE_END(ManifestRefs);

static inline int
mftrefcmp(const struct mftref *a, const struct mftref *b)
{
	return strcmp(a->sia, b->sia);
}

RB_GENERATE(mftref_tree, mftref, entry, mftrefcmp);

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

/*
 * Insert new ManifestRefs into tree, or replacing an existing entry
 * if the existing entry's thisUpdate is older.
 * Return 1 if a new object was added to the tree, and otherwise 0.
 */
static inline int
insert_mftref_tree(struct mftref **mftref, struct mftref_tree *tree)
{
	struct mftref *found;

	if ((found = RB_INSERT(mftref_tree, tree, (*mftref))) != NULL) {

		/*
		 * Check if the mftref at hand is newer than the one
		 * in the RB tree, if so replace the in-tree version.
		 */
		if ((*mftref)->thisupdate > found->thisupdate) {
			RB_REMOVE(mftref_tree, tree, found);
			mftref_free(found);

			RB_INSERT(mftref_tree, tree, (*mftref));

			/* steal the resource from the ccr struct */
			*mftref = NULL;
		}

		/* XXX: should also compare seqnum */

		return 0;
	}

	/* steal the resource from the ccr struct */
	*mftref = NULL;

	return 1;
}

int
merge_ccrs(char *argv[], struct mftref_tree *tree)
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

		for (i = 0; i < ccr->refs_num; i++) {
			count += insert_mftref_tree(&ccr->refs[i], tree);
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
make_manifestref(struct mftref *m)
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

	if ((ei = ErikIndex_new()) == NULL)
		errx(1, "ErikIndex_new");

	if (!ASN1_STRING_set(ei->indexScope, fqdn, -1))
		errx(1, "ASN1_STRING_set");

	ASN1_OBJECT_free(ei->hashAlg);
	if ((ei->hashAlg = OBJ_nid2obj(NID_sha256)) == NULL)
		errx(1, "OBJ_nid2obj");

	return ei;
}

static ErikPartition *
start_ErikPartition(void)
{
	ErikPartition *ep;

	if ((ep = ErikPartition_new()) == NULL)
		errx(1, "ErikPartition_new");

	ASN1_OBJECT_free(ep->hashAlg);
	if ((ep->hashAlg = OBJ_nid2obj(NID_sha256)) == NULL)
		errx(1, "OBJ_nid2obj");

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

	if (asprintf(&hash_path, "static/%c%c/%c%c/%c%c/%s", hash_fn[0],
	    hash_fn[1], hash_fn[2], hash_fn[3], hash_fn[4], hash_fn[5],
	    hash_fn) == -1)
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
	unsigned char *ei_der;
	int ei_der_len;
	ContentInfo *ci = NULL;
	struct file *f;

	if (ASN1_GENERALIZEDTIME_set(ei->indexTime, itime) == NULL)
		errx(1, "ASN1_GENERALIZEDTIME_set");

	ei_der = NULL;
	if ((ei_der_len = i2d_ErikIndex(ei, &ei_der)) <= 0)
		errx(1, "i2d_ErikIndex");

	ErikIndex_free(ei);

	if ((ci = ContentInfo_new()) == NULL)
		errx(1, "ContentInfo_new");

	ASN1_OBJECT_free(ci->contentType);
	if ((ci->contentType = OBJ_dup(idx_oid)) == NULL)
		errx(1, "OBJ_dup");

	if (!ASN1_OCTET_STRING_set(ci->content, ei_der, ei_der_len))
		errx(1, "ASN1_OCTET_STRING_set");

	free(ei_der);

	if ((f = calloc(1, sizeof(*f))) == NULL)
		err(1, NULL);

	f->content = NULL;
	if ((f->content_len = i2d_ContentInfo(ci, &f->content)) <= 0)
		errx(1, "i2d_ContentInfo");

	ContentInfo_free(ci);

	SHA256(f->content, f->content_len, f->hash);

	f->signtime = itime;

	if (asprintf(&f->name, "erik index: %s", fqdn) == -1)
		err(1, "asprintf");

	store_by_hash(f);

	update_index_ptr(fqdn, f->hash);

	file_free(f);
}

static PartitionRef *
finalize_ErikPartition(ErikPartition *ep, char *fqdn, int part_id, time_t ptime)
{
	unsigned char *ep_der;
	int ep_der_len;
	ContentInfo *ci = NULL;
	PartitionRef *pr = NULL;
	struct file *f;

	if (ASN1_GENERALIZEDTIME_set(ep->partitionTime, ptime) == NULL)
		errx(1, "ASN1_GENERALIZEDTIME_set");

	ep_der = NULL;
	if ((ep_der_len = i2d_ErikPartition(ep, &ep_der)) <= 0)
		errx(1, "i2d_ErikPartition");

	ErikPartition_free(ep);

	if ((ci = ContentInfo_new()) == NULL)
		errx(1, "ContentInfo_new");

	ASN1_OBJECT_free(ci->contentType);
	if ((ci->contentType = OBJ_dup(par_oid)) == NULL)
		errx(1, "OBJ_dup");

	if (!ASN1_OCTET_STRING_set(ci->content, ep_der, ep_der_len))
		errx(1, "ASN1_OCTET_STRING_set");

	free(ep_der);

	if ((f = calloc(1, sizeof(*f))) == NULL)
		err(1, NULL);

	f->content = NULL;
	if ((f->content_len = i2d_ContentInfo(ci, &f->content)) <= 0)
		errx(1, "i2d_ContentInfo");

	ContentInfo_free(ci);

	SHA256(f->content, f->content_len, f->hash);

	f->signtime = ptime;

	if (asprintf(&f->name, "erik partition: %s#%d", fqdn, part_id) == -1)
		err(1, "asprintf");

	store_by_hash(f);

	if ((pr = PartitionRef_new()) == NULL)
		errx(1, "PartitionRef_new");

	if (!ASN1_INTEGER_set_uint64(pr->identifier, part_id))
		errx(1, "ASN1_INTEGER_set_uint64");

	if (!ASN1_OCTET_STRING_set(pr->hash, f->hash, sizeof(f->hash)))
		errx(1, "ASN1_OCTET_STRING_set");

	if (!ASN1_INTEGER_set_uint64(pr->size, f->content_len))
		errx(1, "ASN1_INTEGER_set_uint64");

	file_free(f);

	return pr;
}

void
generate_erik_objects(struct mftref **refs, int count)
{
	struct mftref *mftref;
	char *prev_fqdn, *prev_aki;
	ErikIndex *ei = NULL;
	ErikPartition *ep = NULL;
	PartitionRef *pr = NULL;
	ManifestRef *mr = NULL;
	time_t itime = 0, ptime = 0;
	int i, part_id = 0;

	prev_fqdn = prev_aki = NULL;
	for (i = 0; i < count; i++) {
		mftref = refs[i];

		mr = make_manifestref(mftref);

		if (prev_fqdn == NULL && prev_aki == NULL) {
			prev_fqdn = mftref->fqdn;
			prev_aki = mftref->aki;

			ei = start_ErikIndex(mftref->fqdn);
			itime = 0;
			part_id = 0;

			ep = start_ErikPartition();
			ptime = 0;
		}

		if (strcmp(prev_fqdn, mftref->fqdn) != 0) {
			pr = finalize_ErikPartition(ep, prev_fqdn, part_id,
			    ptime);

			if (sk_PartitionRef_push(ei->partitionList, pr) <= 0)
				errx(1, "sk_PartitionRef_push");

			finalize_ErikIndex(ei, prev_fqdn, itime);

			ei = start_ErikIndex(mftref->fqdn);
			itime = 0;
			part_id = 0;

			ep = start_ErikPartition();
			ptime = 0;
		} else if (strncmp(prev_aki, mftref->aki, 2) != 0) {
			pr = finalize_ErikPartition(ep, prev_fqdn, part_id,
			    ptime);

			if (sk_PartitionRef_push(ei->partitionList, pr) <= 0)
				errx(1, "sk_PartitionRef_push");

			ep = start_ErikPartition();
			ptime = 0;
			part_id++;
		}

		if (sk_ManifestRef_push(ep->manifestList, mr) <= 0)
			errx(1, "sk_ManifestRef_push");

		if (mftref->thisupdate > itime)
			itime = mftref->thisupdate;

		if (mftref->thisupdate > ptime)
			ptime = mftref->thisupdate;

		prev_fqdn = mftref->fqdn;
		prev_aki = mftref->aki;
	}
	pr = finalize_ErikPartition(ep, prev_fqdn, part_id, ptime);
	if (sk_PartitionRef_push(ei->partitionList, pr) <= 0)
		errx(1, "sk_PartitionRef_push");
	finalize_ErikIndex(ei, mftref->fqdn, itime);
}

struct file *
generate_reduced_ccr(struct mftref **refs, int count)
{
	struct mftref *mftref;
	ManifestState *ms = NULL;
	ManifestRef *mr = NULL;
	time_t mostrecent = 0;
	CanonicalCacheRepresentation *ccr = NULL;
	unsigned char *ccr_der;
	int ccr_der_len;
	ContentInfo *ci = NULL;
	struct file *f;
	int i;

	if ((ms = ManifestState_new()) == NULL)
		errx(1, "ManifestState_new");

	for (i = 0; i < count; i++) {
		char *sia;
		mftref = refs[i];

		if (asprintf(&sia, "rsync://%s", mftref->sia) == -1)
			err(1, "asprintf");
		free(mftref->sia);
		mftref->sia = sia;

		mr = make_manifestref(mftref);

		if (sk_ManifestRef_push(ms->mftrefs, mr) <= 0)
			errx(1, "sk_ManifestRef_push");

		if (mftref->thisupdate > mostrecent)
			mostrecent = mftref->thisupdate;
	}

	if (ASN1_GENERALIZEDTIME_set(ms->mostRecentUpdate, mostrecent) == NULL)
		errx(1, "ASN1_GENERALIZEDTIME_set");

	hash_asn1_item(ms->hash, ASN1_ITEM_rptr(ManifestRefs), ms->mftrefs);

	if ((ccr = CanonicalCacheRepresentation_new()) == NULL)
		errx(1, "CanonicalCacheRepresentation_new");

	ASN1_OBJECT_free(ccr->hashAlg);
	if ((ccr->hashAlg = OBJ_nid2obj(NID_sha256)) == NULL)
		errx(1, "OBJ_nid2obj");

	if (ASN1_GENERALIZEDTIME_set(ccr->producedAt, time(NULL)) == NULL)
		errx(1, "ASN1_GENERALIZEDTIME_set");

	ccr->mfts = ms;

	ccr_der = NULL;
	if ((ccr_der_len = i2d_CanonicalCacheRepresentation(ccr, &ccr_der)) <= 0)
		errx(1, "i2d_CanonicalCacheRepresentation");

	CanonicalCacheRepresentation_free(ccr);

	if ((ci = ContentInfo_new()) == NULL)
		errx(1, "ContentInfo_new");

	ASN1_OBJECT_free(ci->contentType);
	if ((ci->contentType = OBJ_dup(ccr_oid)) == NULL)
		errx(1, "OBJ_dup");

	if (!ASN1_OCTET_STRING_set(ci->content, ccr_der, ccr_der_len))
		errx(1, "ASN1_OCTET_STRING_set");

	free(ccr_der);

	if ((f = calloc(1, sizeof(*f))) == NULL)
		err(1, NULL);

	f->name = NULL;
	f->content = NULL;
	if ((f->content_len = i2d_ContentInfo(ci, &f->content)) <= 0)
		errx(1, "i2d_ContentInfo");

	ContentInfo_free(ci);

	return f;
}
