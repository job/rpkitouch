/*
 * Copyright (c) 2023-2025 Job Snijders <job@sobornost.net>
 * Copyright (c) 2022 Theo Buehler <tb@openbsd.org>
 * Copyright (c) 2020 Claudio Jeker <claudio@openbsd.org>
 * Copyright (c) 2019 Kristaps Dzonsons <kristaps@bsd.lv>
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

#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/asn1t.h>
#include <openssl/cms.h>
#include <openssl/safestack.h>

#include "extern.h"
#include "asn1.h"

#define GENTIME_LENGTH 15
#define MAX_URI_LENGTH 2048
#define RSYNC_PROTO "rsync://"
#define RSYNC_PROTO_LEN (sizeof(RSYNC_PROTO) - 1)

ASN1_ITEM_EXP Manifest_it;
ASN1_ITEM_EXP FileAndHash_it;

ASN1_SEQUENCE(Manifest) = {
	ASN1_EXP_OPT(Manifest, version, ASN1_INTEGER, 0),
	ASN1_SIMPLE(Manifest, manifestNumber, ASN1_INTEGER),
	ASN1_SIMPLE(Manifest, thisUpdate, ASN1_GENERALIZEDTIME),
	ASN1_SIMPLE(Manifest, nextUpdate, ASN1_GENERALIZEDTIME),
	ASN1_SIMPLE(Manifest, fileHashAlg, ASN1_OBJECT),
	ASN1_SEQUENCE_OF(Manifest, fileList, FileAndHash),
} ASN1_SEQUENCE_END(Manifest);

IMPLEMENT_ASN1_FUNCTIONS(Manifest);

ASN1_SEQUENCE(FileAndHash) = {
	ASN1_SIMPLE(FileAndHash, file, ASN1_IA5STRING),
	ASN1_SIMPLE(FileAndHash, hash, ASN1_BIT_STRING),
} ASN1_SEQUENCE_END(FileAndHash);


void
hash_asn1_item(ASN1_OCTET_STRING *astr, const ASN1_ITEM *it, void *val)
{
	unsigned char hash[SHA256_DIGEST_LENGTH];

	if (!ASN1_item_digest(it, EVP_sha256(), val, hash, NULL))
		errx(1, "ASN1_item_digest");

	if (!ASN1_OCTET_STRING_set(astr, hash, sizeof(hash)))
		errx(1, "ASN1_STRING_set");
}

static int
validate_asn1_hash(const char *fn, const char *descr,
    const ASN1_OCTET_STRING *hash, const ASN1_ITEM *it, void *val)
{
	ASN1_OCTET_STRING *astr = NULL;
	int rc = 0;

	if ((astr = ASN1_OCTET_STRING_new()) == NULL)
		err(1, NULL);

	hash_asn1_item(astr, it, val);

	if (ASN1_OCTET_STRING_cmp(hash, astr) != 0) {
		warnx("%s: corrupted %s state", fn, descr);
		goto out;
	}

	rc = 1;
 out:
	ASN1_OCTET_STRING_free(astr);
	return rc;
}

static int
asn1time_to_time(const ASN1_TIME *at, time_t *t, int expect_gen)
{
	struct tm tm;

	*t = 0;
	/* Error instead of silently falling back to current time. */
	if (at == NULL)
		return 0;

	if (expect_gen) {
		if (at->length != GENTIME_LENGTH)
			return 0;
	}

	memset(&tm, 0, sizeof(tm));
	if (!ASN1_TIME_to_tm(at, &tm))
		return 0;
	if ((*t = timegm(&tm)) == -1)
		errx(1, "timegm failed");

	return 1;
}

/*
 * Parse the Subject Information Access (SIA) in a CCR ManifestRef.
 * Returns 0 on failure, out_sia has to be freed after use.
 */
static int
ccr_get_sia(STACK_OF(ACCESS_DESCRIPTION) *location, char **out_sia)
{
	ACCESS_DESCRIPTION *ad;
	ASN1_IA5STRING *uri;
	ASN1_OBJECT *oid;
	int rc = 0, s;

	assert(*out_sia == NULL);

	if (sk_ACCESS_DESCRIPTION_num(location) != 1)
		goto out;

	ad = sk_ACCESS_DESCRIPTION_value(location, 0);

	oid = ad->method;
	if (OBJ_cmp(oid, signedobj_oid) != 0)
		goto out;
	if (ad->location->type != GEN_URI)
		goto out;

	uri = ad->location->d.uniformResourceIdentifier;
	if (uri->length > MAX_URI_LENGTH)
		goto out;

	/* rsync://x.net/x.mft */
	if (uri->length <= 20)
		goto out;

	for (s = 0; s < uri->length; s++) {
		if (!isalnum((unsigned char)uri->data[s]) &&
		    !ispunct((unsigned char)uri->data[s]))
			goto out;
	}

	if (strstr((char *)uri->data, "/.") != NULL)
		goto out;

	if (strncasecmp((char *)uri->data, RSYNC_PROTO, RSYNC_PROTO_LEN) != 0)
		goto out;

	*out_sia = strndup((char *)uri->data + RSYNC_PROTO_LEN, uri->length);
	if (*out_sia == NULL)
		err(1, NULL);

	rc = 1;
 out:
	return rc;
}

static int
cms_get_signtime_attr(const char *fn, X509_ATTRIBUTE *attr, time_t *signtime)
{
	const ASN1_TIME *at;
	const char *time_str = "UTCtime";
	int time_type = V_ASN1_UTCTIME;

	*signtime = 0;
	at = X509_ATTRIBUTE_get0_data(attr, 0, time_type, NULL);
	if (at == NULL) {
		time_str = "GeneralizedTime";
		time_type = V_ASN1_GENERALIZEDTIME;
		at = X509_ATTRIBUTE_get0_data(attr, 0, time_type, NULL);
		if (at == NULL) {
			warnx("%s: CMS signing-time issue", fn);
			return 0;
		}
		warnx("%s: GeneralizedTime instead of UTCtime", fn);
	}

	if (!asn1time_to_time(at, signtime, 0)) {
		warnx("%s: failed to convert %s", fn, time_str);
		return 0;
	}

	return 1;
}

/*
 * Parse the Subject Information Access (SIA) extension for an EE cert.
 * Returns 0 on failure, out_sia has to be freed after use.
 */
static int
x509_get_sia(X509 *x, char **out_sia)
{
	ACCESS_DESCRIPTION *ad;
	AUTHORITY_INFO_ACCESS *info;
	ASN1_OBJECT *oid;
	int i, crit, rc = 0;

	assert(*out_sia == NULL);

	info = X509_get_ext_d2i(x, NID_sinfo_access, &crit, NULL);
	if (info == NULL)
		goto out;
	if (crit != 0)
		goto out;

	for (i = 0; i < sk_ACCESS_DESCRIPTION_num(info); i++) {
		ASN1_IA5STRING *uri;
		int s;

		ad = sk_ACCESS_DESCRIPTION_value(info, i);

		/*
		 * Ignore and skip rpkiNotify accessMethods.
		 * See https://www.rfc-editor.org/errata/eid7239.
		 */
		oid = ad->method;
		if (OBJ_cmp(oid, notify_oid) == 0)
			continue;

		if (OBJ_cmp(oid, signedobj_oid) != 0)
			goto out;

		if (ad->location->type != GEN_URI)
			goto out;

		uri = ad->location->d.uniformResourceIdentifier;

		if (uri->length > MAX_URI_LENGTH)
			goto out;

		/* rsync://x.net/x.mft */
		if (uri->length <= 20)
			goto out;

		for (s = 0; s < uri->length; s++) {
			if (!isalnum((unsigned char)uri->data[s]) &&
			    !ispunct((unsigned char)uri->data[s]))
				goto out;
		}

		if (strstr((char *)uri->data, "/.") != NULL)
			goto out;

		if (strncasecmp((char *)uri->data, RSYNC_PROTO,
		    RSYNC_PROTO_LEN) != 0)
			goto out;

		if ((*out_sia = strndup((char *)uri->data + RSYNC_PROTO_LEN,
		    uri->length)) == NULL)
			err(1, NULL);
	}

	if (*out_sia == NULL)
		goto out;

	rc = 1;

 out:
	AUTHORITY_INFO_ACCESS_free(info);
	return rc;
}

/*
 * Extract CMS signing-time.
 */
static time_t
get_time_from_sobject(const char *fn, unsigned char *content, size_t len)
{
	CMS_ContentInfo *cms = NULL;
	STACK_OF(CMS_SignerInfo) *sinfos;
	CMS_SignerInfo *si;
	const ASN1_OBJECT *obj;
	const unsigned char *der, *oder;
	int i, has_st = 0, nattrs;
	time_t signtime = 0;

	oder = der = content;
	if ((cms = d2i_CMS_ContentInfo(NULL, &der, len)) == NULL) {
		warnx("%s: d2i_CMS_ContentInfo failed", fn);
		goto out;
	}
	if (der != oder + len) {
		warnx("%s: %td bytes trailing garbage", fn, oder + len - der);
		goto out;
	}

	if (!CMS_verify(cms, NULL, NULL, NULL, NULL,
	    CMS_NO_SIGNER_CERT_VERIFY)) {
		warnx("%s: CMS_verify failed", fn);
		goto out;
	}

	if ((sinfos = CMS_get0_SignerInfos(cms)) == NULL) {
		if ((obj = CMS_get0_type(cms)) == NULL) {
			warnx("%s: RFC 6488: missing content-type", fn);
			goto out;
		}
		warnx("%s: RFC 6488: no signerInfo in CMS object", fn);
		goto out;
	}

	if (sk_CMS_SignerInfo_num(sinfos) != 1) {
		warnx("%s: multiple signerInfos", fn);
		goto out;
	}
	si = sk_CMS_SignerInfo_value(sinfos, 0);

	nattrs = CMS_signed_get_attr_count(si);
	if (nattrs <= 0) {
		warnx("%s: CMS_signed_get_attr_count failed", fn);
		goto out;
	}
	for (i = 0; i < nattrs; i++) {
		X509_ATTRIBUTE *attr;

		attr = CMS_signed_get_attr(si, i);
		if (attr == NULL || X509_ATTRIBUTE_count(attr) != 1) {
			warnx("%s: bad signed attribute encoding", fn);
			goto out;
		}

		if ((obj = X509_ATTRIBUTE_get0_object(attr)) == NULL) {
			warnx("%s: bad signed object", fn);
			goto out;
		}
		if (OBJ_cmp(obj, sign_time_oid) == 0) {
			if (has_st++ != 0) {
				warnx("%s: duplicate signing-time attr", fn);
				goto out;
			}
			if (!cms_get_signtime_attr(fn, attr, &signtime))
				goto out;
			break;
		}
	}

 out:
	CMS_ContentInfo_free(cms);
	return signtime;
}

static time_t
get_cert_notbefore(const char *fn, unsigned char *content, size_t len)
{
	X509 *x = NULL;
	const ASN1_TIME *at;
	const unsigned char *der, *oder;
	time_t time = 0;

	oder = der = content;
	if ((x = d2i_X509(NULL, &der, len)) == NULL) {
		warnx("%s: d2i_X509 failed", fn);
		goto out;
	}
	if (der != oder + len) {
		warnx("%s: %td bytes trailing garbage", fn, oder + len - der);
		goto out;
	}

	if (X509_check_purpose(x, -1, 0) <= 0) {
		warnx("%s: could not cache X509v3 extensions", fn);
		goto out;
	}

	if ((at = X509_get0_notBefore(x)) == NULL) {
		warn("%s: X509_get0_notBefore failed", fn);
		goto out;
	}

	if (!asn1time_to_time(at, &time, 0)) {
		warnx("%s: failed to convert ASN1_TIME", fn);
		goto out;
	}

 out:
	X509_free(x);
	return time;
}

static time_t
get_crl_thisupdate(const char *fn, unsigned char *content, size_t len)
{
	X509_CRL *x = NULL;
	const ASN1_TIME *at;
	const unsigned char *der, *oder;
	time_t time = 0;

	oder = der = content;
	if ((x = d2i_X509_CRL(NULL, &der, len)) == NULL) {
		warnx("%s: d2i_X509_CRL failed", fn);
		goto out;
	}
	if (der != oder + len) {
		warnx("%s: %td bytes trailing garbage", fn, oder + len - der);
		goto out;
	}

	if ((at = X509_CRL_get0_lastUpdate(x)) == NULL) {
		warn("%s: X509_CRL_get0_lastUpdate failed", fn);
		goto out;
	}

	if (!asn1time_to_time(at, &time, 0)) {
		warnx("%s: failed to convert ASN1_TIME", fn);
		goto out;
	}

 out:
	X509_CRL_free(x);
	return time;
}

time_t
get_time_from_content(struct file *f)
{
	time_t time = 0;
	char *name;
	unsigned char *content;
	size_t len;

	name = f->name;
	content = f->content;
	len = f->content_len;

	switch (f->type) {
	case TYPE_CER:
		time = get_cert_notbefore(name, content, len);
		break;
	case TYPE_CRL:
		time = get_crl_thisupdate(name, content, len);
		break;
	case TYPE_ASPA:
	case TYPE_GBR:
	case TYPE_MFT:
	case TYPE_ROA:
	case TYPE_SPL:
	case TYPE_TAK:
		time = get_time_from_sobject(name, content, len);
		break;
	case TYPE_TAL:
		return 0;
	default:
		warnx("%s: unsupported file", name);
		return 0;
	}

	return time;
}

static char *
mft_convert_seqnum(const ASN1_INTEGER *i)
{
	BIGNUM *bn = NULL;
	char *s = NULL;

	if (i == NULL)
		goto out;

	if ((bn = ASN1_INTEGER_to_BN(i, NULL)) == NULL)
		goto out;

	if (BN_is_negative(bn))
		goto out;

	if (BN_num_bytes(bn) > 20 || BN_is_bit_set(bn, 159))
		goto out;

	if ((s = BN_bn2hex(bn)) == NULL)
		goto out;

 out:
	BN_free(bn);
	return s;
}

static int
valid_mft_filename(const unsigned char *fn, size_t len)
{
	const unsigned char *c;
	size_t i;

	for (c = fn, i = 0; i < len; i++, c++)
		if (!isalnum(*c) && *c != '-' && *c != '_' && *c != '.')
			return 0;

	c = memchr(fn, '.', len);
	if (c == NULL || c != memrchr(fn, '.', len))
		return 0;

	return 1;
}

static void
mft_free(struct mft *mft)
{
	if (mft == NULL)
		return;

	free(mft->files);
	free(mft->sia);
	free(mft->sia_dirname);
	free(mft->seqnum);
	free(mft);
}

struct mft *
parse_manifest(struct file *f)
{
	CMS_ContentInfo *cms = NULL;
	STACK_OF(X509) *certs = NULL;
	X509 *x;
	char *fn, *sia_dir = NULL;
	const ASN1_OBJECT *obj;
	const unsigned char *der, *oder;
	int i, rc = 0;
	ASN1_OCTET_STRING **os = NULL;
	unsigned char *econtent_der = NULL;
	const unsigned char *p;
	size_t econtent_der_len;
	Manifest *mft_asn1 = NULL;
	struct mft *mft = NULL;

	fn = f->name;

	oder = der = f->content;
	if ((cms = d2i_CMS_ContentInfo(NULL, &der, f->content_len)) == NULL) {
		warnx("%s: d2i_CMS_ContentInfo failed", fn);
		goto out;
	}
	if (der != oder + f->content_len) {
		warnx("%s: %td bytes trailing garbage", fn,
		    oder + f->content_len - der);
		goto out;
	}

	if (!CMS_verify(cms, NULL, NULL, NULL, NULL,
	    CMS_NO_SIGNER_CERT_VERIFY)) {
		warnx("%s: CMS_verify failed", fn);
		goto out;
	}

	certs = CMS_get0_signers(cms);
	if (certs == NULL || sk_X509_num(certs) != 1)
		goto out;
	x = sk_X509_value(certs, 0);

	if (X509_check_purpose(x, -1, 0) <= 0) {
		warnx("%s: could not cache X509v3 extensions", fn);
		goto out;
	}

	if ((mft = calloc(1, sizeof(*mft))) == NULL)
		err(1, NULL);

	if (x509_get_sia(x, &mft->sia) != 1)
		goto out;

	sia_dir = strdup(mft->sia);
	if (asprintf(&mft->sia_dirname, "%s", dirname(sia_dir)) == -1)
		err(1, "asprintf");
	free(sia_dir);

	obj = CMS_get0_eContentType(cms);
	if (obj == NULL) {
		warnx("%s: eContentType is NULL", fn);
		goto out;
	}
	if (OBJ_cmp(obj, manifest_oid) != 0) {
		char buf[128], obuf[128];

		OBJ_obj2txt(buf, sizeof(buf), obj, 1);
		OBJ_obj2txt(obuf, sizeof(obuf), manifest_oid, 1);
		warnx("%s: eContentType: unknown OID: %s, want %s", fn, buf,
		    obuf);
		goto out;
	}

	if ((os = CMS_get0_content(cms)) == NULL || *os == NULL) {
		warnx("%s: CMS_get0_content failed", fn);
		goto out;
	}

	econtent_der_len = (*os)->length;
	if ((econtent_der = malloc(econtent_der_len)) == NULL)
		err(1, NULL);
	memcpy(econtent_der, (*os)->data, econtent_der_len);

	p = econtent_der;
	if ((mft_asn1 = d2i_Manifest(NULL, &p, econtent_der_len)) == NULL) {
		warnx("%s: parsing eContent failed", fn);
		goto out;
	}
	if (p != econtent_der + econtent_der_len) {
		warnx("%s: bytes trailing in eContent", fn);
		goto out;
	}

	if (!asn1time_to_time(mft_asn1->thisUpdate, &mft->thisupdate, 1)) {
		warnx("%s: failed to convert %s", f->name, "thisUpdate");
		goto out;
	}

	mft->seqnum = mft_convert_seqnum(mft_asn1->manifestNumber);
	if (mft->seqnum == NULL) {
		warnx("%s: manifestNumber conversion failure", fn);
		goto out;
	}

	mft->fh_num = sk_FileAndHash_num(mft_asn1->fileList);

	mft->files = calloc(mft->fh_num, sizeof(mft->files[0]));
	if (mft->files == NULL)
		err(1, NULL);

	for (i = 0; i < mft->fh_num; i++) {
		const FileAndHash *fah = sk_FileAndHash_value(mft_asn1->fileList, i);

		if (!valid_mft_filename(fah->file->data, fah->file->length)) {
			warnx("%s: invalid FileAndHash", f->name);
			goto out;
		}

		mft->files[i].fn = strndup((const char *)fah->file->data,
		    fah->file->length);
		if (mft->files[i].fn == NULL)
			err(1, NULL);

		if (fah->hash->length != SHA256_DIGEST_LENGTH)
			goto out;

		if (!b64uri_encode(fah->hash->data, fah->hash->length,
		    &mft->files[i].hash))
			err(1, NULL);
	}

	rc = 1;
 out:
	if (rc == 0) {
		mft_free(mft);
		mft = NULL;
	}

	free(econtent_der);
	Manifest_free(mft_asn1);
	sk_X509_free(certs);
	CMS_ContentInfo_free(cms);

	return mft;
}

void
ccr_free(struct ccr *ccr)
{
	int i;

	if (ccr == NULL)
		return;

	for (i = 0; i < ccr->refs_num; i++) {
		free(ccr->refs[i]);
	}

	free(ccr->refs);
	free(ccr);
}

static void
mftref_set_fqdn(struct mftref *ref)
{
	char *fqdn, *needle;

	if ((fqdn = strdup(ref->sia)) == NULL)
		err(1, NULL);

	needle = strchr(fqdn, '/');
	*needle = '\0';

	ref->fqdn = fqdn;
}

struct ccr *
parse_ccr(struct file *f)
{
	const unsigned char *oder, *der;
	ContentInfo *ci = NULL;
	CanonicalCacheRepresentation *ccr_asn1 = NULL;
	long len;
	struct ccr *ccr = NULL;
	struct mftref **refs = NULL;
	int i, rc = 0;

	oder = der = f->content;
	if ((ci = d2i_ContentInfo(NULL, &der, f->content_len)) == NULL) {
		warnx("%s: d2i_ContentInfo failed", f->name);
		goto out;
	}
	if (der != oder + f->content_len) {
		warnx("%s: %td bytes trailing garbage", f->name,
		    oder + f->content_len - der);
		goto out;
	}

	if (OBJ_cmp(ci->contentType, ccr_oid) != 0) {
		char buf[128];

		OBJ_obj2txt(buf, sizeof(buf), ci->contentType, 1);
		warnx("%s: unexpected OID: got %s, want 1.3.6.1.4.1.41948.825",
		    f->name, buf);
		goto out;
	}

	der = ASN1_STRING_get0_data(ci->content);
	len = ASN1_STRING_length(ci->content);

	oder = der;
	ccr_asn1 = d2i_CanonicalCacheRepresentation(NULL, &der, len);
	if (ccr_asn1 == NULL) {
		warnx("%s: d2i_CanonicalCacheRepresentation failed", f->name);
		goto out;
	}
	if (der != oder + len) {
		warnx("%s: %td bytes trailing garbage", f->name, oder + len - der);
		goto out;
	}

	if ((ccr = calloc(1, sizeof(*ccr))) == NULL)
		err(1, NULL);

	if (!asn1time_to_time(ccr_asn1->producedAt, &ccr->producedat, 1)) {
		warnx("%s: failed to convert %s", f->name, "producedAt");
		goto out;
	}

	if (f->disktime != ccr->producedat)
		set_mtime(AT_FDCWD, f->name, ccr->producedat);

	if (ccr_asn1->mfts == NULL || ccr_asn1->mfts->hash == NULL ||
	    ccr_asn1->mfts->mftrefs == NULL) {
		warnx("%s: missing Manifest state", f->name);
		goto out;
	}

	if (!validate_asn1_hash(f->name, "ManifestState", ccr_asn1->mfts->hash,
	    ASN1_ITEM_rptr(ManifestRefs), ccr_asn1->mfts->mftrefs)) {
		warnx("%s: ManifestState hash mismatch", f->name);
		goto out;
	}

	ccr->refs_num = sk_ManifestRef_num(ccr_asn1->mfts->mftrefs);
	if (ccr->refs_num == 0) {
		warnx("%s: missing ManifestRefs", f->name);
		goto out;
	}

	refs = calloc(ccr->refs_num, sizeof(ccr->refs));
	if (refs == NULL)
		err(1, NULL);

	for (i = 0; i < ccr->refs_num; i++) {
		const ManifestRef *mr;

		mr = sk_ManifestRef_value(ccr_asn1->mfts->mftrefs, i);

		if ((refs[i] = calloc(1, sizeof(*refs[i]))) == NULL)
			err(1, NULL);

		if (mr->hash->length != SHA256_DIGEST_LENGTH) {
			warnx("%s: manifest ref #%d corrupted", f->name, i);
			goto out;
		}
		refs[i]->hash = hex_encode(mr->hash->data, mr->hash->length);

		if (!ASN1_INTEGER_get_uint64(&refs[i]->size, mr->size)) {
			warnx("%s: manifest ref #%d corrupted", f->name, i);
			goto out;
		}

		if (mr->aki->length != SHA_DIGEST_LENGTH) {
			warnx("%s: manifest ref #%d corrupted", f->name, i);
			goto out;
		}
		refs[i]->aki = hex_encode(mr->aki->data, mr->aki->length);

		if (!asn1time_to_time(mr->thisUpdate, &refs[i]->thisupdate, 1)) {
			warnx("%s: failed to convert %s", f->name, "thisUpdate");
			goto out;
		}

		refs[i]->seqnum = mft_convert_seqnum(mr->manifestNumber);
		if (refs[i]->seqnum == NULL) {
			warnx("%s: mft_convert_seqnum failed", f->name);
			goto out;
		}

		if (!ccr_get_sia(mr->location, &refs[i]->sia))
			goto out;

		mftref_set_fqdn(refs[i]);
	}

	ccr->refs = refs;

	rc = 1;
 out:
	if (rc == 0) {
		ccr_free(ccr);
		ccr = NULL;
	}
	ContentInfo_free(ci);
	CanonicalCacheRepresentation_free(ccr_asn1);

	return ccr;
}
