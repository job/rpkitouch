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

#include <err.h>
#include <string.h>

#include <openssl/asn1t.h>
#include <openssl/safestack.h>
#include <openssl/x509v3.h>

#include "compat/tree.h"

#include "asn1.h"
#include "extern.h"

ASN1_ITEM_EXP ContentInfo_it;
ASN1_ITEM_EXP CanonicalCacheRepresentation_it;
ASN1_ITEM_EXP ManifestRef_it;
ASN1_ITEM_EXP ManifestRefs_it;

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
	ASN1_EXP_OPT(CanonicalCacheRepresentation, rks, ASN1_SEQUENCE_ANY, 5),
} ASN1_SEQUENCE_END(CanonicalCacheRepresentation);

IMPLEMENT_ASN1_FUNCTIONS(CanonicalCacheRepresentation);

ASN1_SEQUENCE(ManifestState) = {
	ASN1_SEQUENCE_OF(ManifestState, mftrefs, ManifestRef),
	ASN1_SIMPLE(ManifestState, mostRecentUpdate, ASN1_GENERALIZEDTIME),
	ASN1_SIMPLE(ManifestState, hash, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(ManifestState);

IMPLEMENT_ASN1_FUNCTIONS(ManifestState);

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
	free(mftref->seqnum);
	free(mftref->sia);
	free(mftref->fqdn);
	free(mftref);
}

static inline int
insert_mftref_tree(struct mftref **mftref, struct mftref_tree *tree)
{
	struct mftref *found;

	if ((found = RB_INSERT(mftref_tree, tree, *mftref)) != NULL) {
		if (strcmp(found->hash, (*mftref)->hash) == 0) {
			mftref_free(*mftref);
			*mftref = NULL;
			return 0;
		}

		/* XXX: should also compare seqnum */

		if ((*mftref)->thisupdate > found->thisupdate) {
			RB_REMOVE(mftref_tree, tree, found);
			mftref_free(found);
			RB_INSERT(mftref_tree, tree, (*mftref));
			return 0;
		} else {
			mftref_free(*mftref);
			*mftref = NULL;
			return 0;
		}
	}

	return 1;
}

int
compare_ccrs(char *argv[], struct mftref_tree *tree)
{
	struct file *f;
	unsigned char *fc;
	struct ccr *ccr;
	int i, count = 0;

	for (; *argv != NULL; ++argv) {
		if ((f = calloc(1, sizeof(struct file))) == NULL)
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

		free(ccr->refs);
		free(ccr);
		ccr = NULL;
		file_free(f);
		f = NULL;
	}

 out:
	free(ccr);
	file_free(f);

	return count;
}
