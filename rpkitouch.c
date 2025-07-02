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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>

#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/cms.h>
#include <openssl/safestack.h>
#include <openssl/sha.h>

#include "asn1.h"

int count = 0;
int erikmode = 0;
int noop = 0;
int outdirfd;
int verbose = 0;

#define GENTIME_LENGTH 15
#define MAX_URI_LENGTH 2048
#define RSYNC_PROTO "rsync://"
#define RSYNC_PROTO_LEN (sizeof(RSYNC_PROTO) - 1)

enum filetype {
	TYPE_CER,	/* Certificate */
	TYPE_CRL,	/* Certificate Revocation List */
	TYPE_ASPA,	/* Autonomous System Provider Authorisation */
	TYPE_GBR,	/* Ghostbuster Record */
	TYPE_MFT,	/* Manifest */
	TYPE_ROA,	/* Route Origin Authorization */
	TYPE_SPL,	/* Signed Prefix List */
	TYPE_TAK,	/* Trust Anchor Key */
	TYPE_TAL,	/* Trust Anchor Locator */
	TYPE_UNKNOWN,
};

/*
 * https://www.iana.org/assignments/rpki/rpki.xhtml
 * .tal is not IANA registered, but added as convenience.
 */
const struct {
	const char *ext;
	enum filetype type;
} ext_tab[] = {
	{ .ext = ".cer", .type = TYPE_CER },
	{ .ext = ".crl", .type = TYPE_CRL },
	{ .ext = ".asa", .type = TYPE_ASPA },
	{ .ext = ".gbr", .type = TYPE_GBR },
	{ .ext = ".mft", .type = TYPE_MFT },
	{ .ext = ".roa", .type = TYPE_ROA },
	{ .ext = ".spl", .type = TYPE_SPL },
	{ .ext = ".tak", .type = TYPE_TAK },
	{ .ext = ".tal", .type = TYPE_TAL }
};

struct file {
	SLIST_ENTRY(file) entry;
	int id;
	enum filetype type;
	char *name;
};

static SLIST_HEAD(, file)	files = SLIST_HEAD_INITIALIZER(files);

ASN1_OBJECT *notify_oid;
ASN1_OBJECT *sign_time_oid;
ASN1_OBJECT *signedobj_oid;
ASN1_OBJECT *manifest_oid;

int mkpathat(int, const char *);
int mkstempat(int, char *);
void usage(void);

static void
setup_oids(void) {
	if ((notify_oid = OBJ_txt2obj("1.3.6.1.5.5.7.48.13", 1)) == NULL)
		errx(1, "OBJ_txt2obj for %s failed", "1.3.6.1.5.5.7.48.13");
	if ((sign_time_oid = OBJ_txt2obj("1.2.840.113549.1.9.5", 1)) == NULL)
		errx(1, "OBJ_txt2obj for %s failed", "1.2.840.113549.1.9.5");
	if ((signedobj_oid = OBJ_txt2obj("1.3.6.1.5.5.7.48.11", 1)) == NULL)
		errx(1, "OBJ_txt2obj for %s failed", "1.3.6.1.5.5.7.48.11");
	if ((manifest_oid = OBJ_txt2obj("1.2.840.113549.1.9.16.1.26", 1))
	    == NULL)
		errx(1, "OBJ_txt2obj for %s failed",
		    "1.2.840.113549.1.9.16.1.26");
}

static char *
hex_encode(const unsigned char *in, size_t insz)
{
	const char hex[] = "0123456789ABCDEF";
	size_t i;
	char *out;

	if ((out = calloc(2, insz + 1)) == NULL)
		err(1, NULL);

	for (i = 0; i < insz; i++) {
		out[i * 2] = hex[in[i] >> 4];
		out[i * 2 + 1] = hex[in[i] & 0xf];
	}
	out[i * 2] = '\0';

	return out;
}

static unsigned char *
load_file(const char *fn, size_t *len, time_t *time)
{
	unsigned char *buf = NULL;
	struct stat st;
	ssize_t n;
	size_t size;
	int fd, saved_errno;

	*len = 0;
	*time = 0;

	memset(&st, 0, sizeof(st));

	if ((fd = open(fn, O_RDONLY)) == -1)
		return NULL;
	if (fstat(fd, &st) != 0)
		goto err;
	if (st.st_size <= 0) {
		errno = EFBIG;
		goto err;
	}

	size = (size_t)st.st_size;
	if ((buf = malloc(size)) == NULL)
		goto err;

	n = read(fd, buf, size);
	if (n == -1)
		goto err;
	if ((size_t)n != size) {
		errno = EIO;
		goto err;
	}

	close(fd);
	*len = size;
	*time = st.st_mtim.tv_sec;
	return buf;

 err:
	saved_errno = errno;
	close(fd);
	free(buf);
	errno = saved_errno;
	return NULL;
}

static int
asn1time_to_time(const ASN1_TIME *at, time_t *t)
{
	struct tm tm;

	*t = 0;
	/* Error instead of silently falling back to current time. */
	if (at == NULL)
		return 0;
	memset(&tm, 0, sizeof(tm));
	if (!ASN1_TIME_to_tm(at, &tm))
		return 0;
	if ((*t = timegm(&tm)) == -1)
		errx(1, "timegm failed");

	return 1;
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

	if (!asn1time_to_time(at, signtime)) {
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
	ACCESS_DESCRIPTION		*ad;
	AUTHORITY_INFO_ACCESS		*info;
	ASN1_OBJECT			*oid;
	int				 i, crit, rc = 0;

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
get_time_from_object(const char *fn, unsigned char *content, size_t len)
{
	CMS_ContentInfo *cms = NULL;
	STACK_OF(CMS_SignerInfo) *sinfos;
	CMS_SignerInfo *si;
	STACK_OF(X509) *certs = NULL;
	X509 *x;
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

	certs = CMS_get0_signers(cms);
	if (certs == NULL || sk_X509_num(certs) != 1)
		goto out;
	x = sk_X509_value(certs, 0);

	if (X509_check_purpose(x, -1, 0) <= 0) {
		warnx("%s: could not cache X509v3 extensions", fn);
		goto out;
	}

 out:
	sk_X509_free(certs);
	CMS_ContentInfo_free(cms);
	return signtime;
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

/*
 * Extract the Manifest signing-time and the EE cert's SignedObject SIA.
 * Return POSTACTION bitfield.
 */
static int
parse_manifest(const char *fn, unsigned char *content, size_t len,
    time_t *out_signtime, char **out_sia, char **out_seqnum)
{
	CMS_ContentInfo *cms = NULL;
	STACK_OF(CMS_SignerInfo) *sinfos;
	CMS_SignerInfo *si;
	STACK_OF(X509) *certs = NULL;
	X509 *x;
	const ASN1_TIME *at;
	char *sia = NULL, *seqnum = NULL;
	const ASN1_OBJECT *obj;
	const unsigned char *der, *oder;
	int i, has_st = 0, nattrs, ret = 0;
	time_t now, signtime = 0, expiry = 0;
	ASN1_OCTET_STRING **os = NULL;
	unsigned char *econtent_der = NULL;
	const unsigned char *p;
	size_t econtent_der_len;
	Manifest *mft = NULL;

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
			*out_signtime = signtime;
			break;
		}
	}

	certs = CMS_get0_signers(cms);
	if (certs == NULL || sk_X509_num(certs) != 1)
		goto out;
	x = sk_X509_value(certs, 0);

	if (X509_check_purpose(x, -1, 0) <= 0) {
		warnx("%s: could not cache X509v3 extensions", fn);
		goto out;
	}

	if ((at = X509_get0_notAfter(x)) == NULL) {
		warnx("%s: X509_get0_notAfter failed", fn);
		goto out;
	}

	if (!asn1time_to_time(at, &expiry)) {
		warnx("%s: failed to convert ASN1_TIME", fn);
		goto out;
	}

	now = time(NULL);
	if (expiry < now)
		ret = 1;

	if (x509_get_sia(x, &sia) != 1)
		goto out;
	*out_sia = sia;

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
	if ((mft = d2i_Manifest(NULL, &p, econtent_der_len)) == NULL) {
		warnx("%s: parsing eContent failed", fn);
		goto out;
	}
	if (p != econtent_der + econtent_der_len) {
		warnx("%s: bytes trailing in eContent", fn);
		goto out;
	}

	if ((seqnum = mft_convert_seqnum(mft->manifestNumber)) == NULL) {
		warnx("%s: manifestNumber conversion failure", fn);
		goto out;
	}
	*out_seqnum = seqnum;

	ret = 1;
 out:
	free(econtent_der);
	Manifest_free(mft);
	sk_X509_free(certs);
	CMS_ContentInfo_free(cms);
	return ret;
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

	if (!asn1time_to_time(at, &time)) {
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

	if (!asn1time_to_time(at, &time)) {
		warnx("%s: failed to convert ASN1_TIME", fn);
		goto out;
	}

 out:
	X509_CRL_free(x);
	return time;
}

static void
set_atime(int fd, const char *fn)
{
	struct timespec ts[2];

	if (noop)
		return;

	ts[0].tv_nsec = UTIME_NOW;
	ts[1].tv_nsec = UTIME_OMIT;

	if (utimensat(fd, fn, ts, 0) == -1)
		err(1, "utimensat %s", fn);
}

static void
set_mtime(int fd, const char *fn, time_t mtime)
{
	struct timespec ts[2];

	if (noop)
		return;

	ts[0].tv_nsec = UTIME_NOW;
	ts[1].tv_sec = mtime;
	ts[1].tv_nsec = 0;

	if (utimensat(fd, fn, ts, 0) == -1)
		err(1, "utimensat %s", fn);
}

/*
 * Base 64 encoding with URL and filename safe alphabet.
 * RFC 4648 section 5
 */
static int
b64uri_encode(const unsigned char *in, size_t inlen, unsigned char **out)
{
	unsigned char *to;
	size_t tolen = 0;
	char *c = NULL;

	*out = NULL;

	if (inlen >= INT_MAX / 2)
		return -1;

	tolen = ((inlen + 2) / 3) * 4 + 1;

	if ((to = malloc(tolen)) == NULL)
		return -1;

	EVP_EncodeBlock(to, in, inlen);
	*out = to;

	c = (char *)to;
	while ((c = strchr(c, '+')) != NULL)
		*c = '-';
	c = (char *)to;
	while ((c = strchr(c, '/')) != NULL)
		*c = '_';
	if ((c = strchr((char *)to, '=')) != NULL)
		*c = '\0';

	return 0;
}

/*
 * Write content to a temp file and then atomically move it into place.
 */
static void
write_file(char *path, unsigned char *content, off_t content_len, time_t mtime)
{
	char *dir, *dn, *file, *bn, *tmpbn;
	struct timespec ts[2];
	int fd;

	if (noop)
		return;

	if ((dir = strdup(path)) == NULL)
		err(1, "strdup");
	if ((dn = dirname(dir)) == NULL)
		err(1, "dirname");

	if ((file = strdup(path)) == NULL)
		err(1, "strdup");
	if ((bn = basename(file)) == NULL)
		err(1, "basename");

	if (asprintf(&tmpbn, "%s/.%s.XXXXXXXXXX", dn, bn) == -1)
		err(1, "asprintf");

	if (mkpathat(outdirfd, dn) == -1)
		err(1, "mkpathat %s", dn);

	if ((fd = mkstempat(outdirfd, tmpbn)) == -1)
		err(1, "mkstempat %s", tmpbn);

	(void)fchmod(fd, 0644);

	if (write(fd, content, content_len) != content_len)
		err(1, "write %s/%s", dn, tmpbn);

	ts[0].tv_nsec = UTIME_OMIT;
	ts[1].tv_sec = mtime;
	ts[1].tv_nsec = 0;

	if (futimens(fd, ts))
		err(1, "futimens %s/%s", dn, tmpbn);

	if (close(fd) != 0)
		err(1, "close failed %s/%s", dn, tmpbn);

	if (renameat(outdirfd, tmpbn, outdirfd, path) == -1) {
		unlink(tmpbn);
		err(1, "%s: rename to %s failed", tmpbn, path);
	}

	free(dir);
	free(file);
	free(tmpbn);
}

static int
store(enum filetype ftype, char *fn, char *sia, unsigned char *content,
    off_t content_len, time_t mtime)
{
	unsigned char md[SHA256_DIGEST_LENGTH];
	char cpath[6], *path = NULL, *tfn = NULL, *tmppath = NULL;
	char *mftdir = NULL, *mfttmppath = NULL;
	unsigned char *cfn;
	struct stat st;
	size_t i;
	time_t delay;

	memset(&st, 0, sizeof(st));

	SHA256(content, content_len, md);

	if (b64uri_encode(md, SHA256_DIGEST_LENGTH, &cfn) != 0)
		err(1, "b64uri_encode");

	snprintf(cpath, sizeof(cpath), "%c%c/%c%c",
	    cfn[0], cfn[1], cfn[2], cfn[3]);

	for (i = 0; i < sizeof(ext_tab) / sizeof(ext_tab[0]); i++) {
		if (ext_tab[i].type == ftype) {
			if (asprintf(&path, "%s/%s%s", cpath, cfn,
			    ext_tab[i].ext) == -1) {
				err(1, "asprintf");
			}
			if (asprintf(&tmppath, "%s/.%s%s.XXXXXXXXXX", cpath,
			    cfn, ext_tab[i].ext) == -1) {
				err(1, "asprintf");
			}
			if (ftype == TYPE_MFT) {
				if (asprintf(&mfttmppath,
				    "mft/%s/.%s%s.XXXXXXXXXX", cpath, cfn,
				    ext_tab[i].ext) == -1) {
					err(1, "asprintf");
				}
			}
			break;
		}
	}

	if (!noop) {
		if (mkpathat(outdirfd, cpath) == -1)
			err(1, "mkpathat %s", cpath);
	}

	if (fstatat(outdirfd, path, &st, 0) != 0) {
		if (errno != ENOTDIR && errno != ENOENT)
			err(1, "fstatat %s", path);
	}

	/*
	 * Skip files that already are of the same size and have the same
	 * last data modification timestamp.
	 */
	if (st.st_size != content_len || st.st_mtim.tv_sec != mtime) {
		write_file(path, content, content_len, mtime);

		if (verbose) {
			delay = time(NULL) - mtime;
			warnx("%s %s %lld (%lld)", fn, path,
			    (long long)mtime, (long long)delay);
		}
	} else
		set_atime(outdirfd, path);

	/*
	 * Now also write Manifests into their named location (using the
	 * SIA SignedObject).
	 * Only overwrite if the on-disk copy is older.
	 */

	if (ftype != TYPE_MFT)
		goto out;

	if ((tfn = strdup(sia)) == NULL)
		err(1, "strdup");

	if (asprintf(&mftdir, "mft/%s", dirname(tfn)) == -1)
		err(1, "asprintf");

	if (!noop) {
		if (mkpathat(outdirfd, mftdir) == -1)
			err(1, "mkpathat %s", mftdir);
	}

	free(tmppath);
	tmppath = NULL;
	if (asprintf(&tmppath, "mft/%s", sia) == -1)
		err(1, "asprintf");

	memset(&st, 0, sizeof(st));
	if (fstatat(outdirfd, tmppath, &st, 0) != 0) {
		if (errno != ENOTDIR && errno != ENOENT)
			err(1, "fstatat %s", tmppath);
	}

	if (st.st_mtim.tv_sec < mtime) {
		write_file(tmppath, content, content_len, mtime);

		if (verbose) {
			delay = time(NULL) - mtime;
			warnx("%s %lld (%lld)", tmppath, (long long)mtime,
			    (long long)delay);
		}
	}

 out:
	free(cfn);
	free(tfn);
	free(mftdir);
	free(path);
	free(tmppath);
	free(mfttmppath);
	return 0;
}

static enum filetype
detect_ftype_from_fn(char *fn)
{
	enum filetype ftype = TYPE_UNKNOWN;
	size_t fn_len, i;

	fn_len = strlen(fn);
	if (fn_len < 5) {
		warnx("%s: unsupported file", fn);
		goto out;
	}

	for (i = 0; i < sizeof(ext_tab) / sizeof(ext_tab[0]); i++) {
		if (strcasecmp(fn + (fn_len - 4), ext_tab[i].ext) == 0) {
			ftype = ext_tab[i].type;
			break;
		}
	}

 out:
	return ftype;
}

/*
 * Adjust mod-times on the disk.
 */
static int
touch(struct file *f)
{
	size_t content_len;
	time_t otime, time = 0;
	unsigned char *content = NULL;

	if ((content = load_file(f->name, &content_len, &otime)) == NULL)
		return 1;

	switch (f->type) {
	case TYPE_CER:
		time = get_cert_notbefore(f->name, content, content_len);
		break;
	case TYPE_CRL:
		time = get_crl_thisupdate(f->name, content, content_len);
		break;
	case TYPE_ASPA:
	case TYPE_GBR:
	case TYPE_MFT:
	case TYPE_ROA:
	case TYPE_SPL:
	case TYPE_TAK:
		time = get_time_from_object(f->name, content, content_len);
		break;
	case TYPE_TAL:
		return 0;
	default:
		warnx("%s: unsupported file", f->name);
		return 0;
	}

	if (time == 0)
		goto cleanup;

	if (otime != time) {
		if (verbose)
			warnx("%s %lld -> %lld", f->name,
			    (long long)otime, (long long)time);
		set_mtime(AT_FDCWD, f->name, time);
	} else
		set_atime(AT_FDCWD, f->name);

 cleanup:
	free(content);

	return time;
}

static void
parse_stdin_input(void)
{
	char *line = NULL;
	size_t linesize = 0;
	ssize_t linelen;
	struct file *f;

	while ((linelen = getdelim(&line, &linesize, '\0', stdin)) != -1) {
		if ((f = malloc(sizeof(struct file))) == NULL)
			err(1, NULL);
		f->id = ++count;
		f->type = detect_ftype_from_fn(line);
		if ((f->name = strdup(line)) == NULL)
			err(1, NULL);
		SLIST_INSERT_HEAD(&files, f, entry);
	}

	if (ferror(stdin))
		err(1, "getdelim");

	free(line);
}

int
main(int argc, char *argv[])
{
	int c, rc = 0;
	char *outdir = NULL;

	while ((c = getopt(argc, argv, "d:hnVv")) != -1)
		switch (c) {
		case 'd':
			outdir = optarg;
			break;
		case 'n':
			noop = 1;
			break;
		case 'V':
			printf("version 1.7\n");
			exit(0);
		case 'v':
			verbose = 1;
			break;
		case 'h':
		default:
			usage();
		}

	argc -= optind;
	argv += optind;

	setup_oids();

	if (outdir != NULL && !noop) {
		if ((outdirfd = open(outdir, O_RDONLY | O_DIRECTORY)) == -1)
			err(1, "output directory %s", outdir);
	}

	if (*argv == NULL) {
		erikmode = 1;
		parse_stdin_input();
	} else for (; *argv != NULL; ++argv) {
		struct file *f;

		if ((f = calloc(1, sizeof(struct file))) == NULL)
			err(1, NULL);

		f->id = ++count;
		f->type = detect_ftype_from_fn(*argv);
		f->name = *argv;
		touch(f);
	}

	return rc;
}

void
usage(void)
{
	fprintf(stderr, "usage: rpkitouch [-nVv] [-d directory] file ...\n");
	exit(1);
}
