/*
 * Copyright (c) 2023 Job Snijders <job@fastly.com>
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

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/asn1.h>
#include <openssl/cms.h>

int verbose;

enum filetype {
	TYPE_ASPA,
	TYPE_CER,
	TYPE_CRL,
	TYPE_GBR,
	TYPE_MFT,
	TYPE_ROA,
	TYPE_TAK,
	TYPE_UNKNOWN,
};

/*
 * https://www.iana.org/assignments/rpki/rpki.xhtml
 */
const struct {
	const char *ext;
	enum filetype type;
} ext_tab[] = {
	{ .ext = ".asa", .type = TYPE_ASPA },
	{ .ext = ".cer", .type = TYPE_CER },
	{ .ext = ".crl", .type = TYPE_CRL },
	{ .ext = ".gbr", .type = TYPE_GBR },
	{ .ext = ".tak", .type = TYPE_TAK },
	{ .ext = ".mft", .type = TYPE_MFT },
	{ .ext = ".roa", .type = TYPE_ROA },
};

ASN1_OBJECT *sign_time_oid;

void usage(void);

void
setup_oids(void) {
	if ((sign_time_oid = OBJ_txt2obj("1.2.840.113549.1.9.5", 1)) == NULL)
		errx(1, "OBJ_txt2obj for %s failed", "1.2.840.113549.1.9.5");
}

unsigned char *
load_file(const char *fn, size_t *len)
{
	unsigned char *buf = NULL;
	struct stat st;
	ssize_t n;
	size_t size;
	int fd, saved_errno;

	*len = 0;

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
	return buf;

 err:
	saved_errno = errno;
	close(fd);
	free(buf);
	errno = saved_errno;
	return NULL;
}

int
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

int
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

time_t
cms_get_signtime(const char *fn)
{
	CMS_ContentInfo *cms = NULL;
	STACK_OF(CMS_SignerInfo) *sinfos;
	CMS_SignerInfo *si;
	const ASN1_OBJECT *obj;
	const unsigned char *der, *oder;
	unsigned char *content;
	int i, has_st = 0, nattrs;
	size_t len;
	time_t time = 0;

	if ((content = load_file(fn, &len)) == NULL)
		goto out;

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

	sinfos = CMS_get0_SignerInfos(cms);
	assert(sinfos != NULL);
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
			if (!cms_get_signtime_attr(fn, attr, &time))
				goto out;
			break;
		}
	}

 out:
	free(content);
	CMS_ContentInfo_free(cms);
	return time;
}

time_t
get_cert_notbefore(const char *fn)
{
	X509 *x = NULL;
	const ASN1_TIME *at;
	const unsigned char *der, *oder;
	unsigned char *content;
	size_t len;
	time_t time = 0;

	if ((content = load_file(fn, &len)) == NULL)
		goto out;

	oder = der = content;
	if ((x = d2i_X509(NULL, &der, len)) == NULL) {
		warnx("%s: d2i_X509 failed", fn);
		goto out;
	}
	if (der != oder + len) {
		warnx("%s: %td bytes trailing garbage", fn, oder + len - der);
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
	free(content);
	X509_free(x);
	return time;
}

time_t
get_crl_lastupdate(const char *fn)
{
	X509_CRL *x = NULL;
	const ASN1_TIME *at;
	const unsigned char *der, *oder;
	unsigned char *content;
	size_t len;
	time_t time = 0;

	if ((content = load_file(fn, &len)) == NULL)
		goto out;

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
	free(content);
	X509_CRL_free(x);
	return time;
}


int
set_mtime(const char *fn, time_t mtime)
{
	struct timespec ts[2];
	int rc = 0;

	ts[0].tv_nsec = UTIME_OMIT;
	ts[1].tv_sec = mtime;
	ts[1].tv_nsec = 0;

	if (utimensat(AT_FDCWD, fn, ts, 0) == -1) {
		warn("%s: utimensat failed", fn);
		rc = 1;
	} else if (verbose)
		printf("%s: mtime set to %lld\n", fn, (long long)mtime);

	return rc;
}

int
main(int argc, char *argv[])
{
	int c, i, rc;

	while ((c = getopt(argc, argv, "hVv")) != -1)
		switch (c) {
		case 'V':
			printf("version 0.1\n");
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

	if (*argv == NULL)
		usage();

	setup_oids();

	for (rc = 0; *argv; ++argv) {
		char *fn;
		size_t fnsz;
		time_t time;
		enum filetype ftype;

		fn = *argv;
		fnsz = strlen(fn);
		if (fnsz < 5) {
			warnx("%s: unsupported file", fn);
			continue;
		}

		ftype = TYPE_UNKNOWN;
		for (i = 0; i < sizeof(ext_tab) / sizeof(ext_tab[0]); i++) {
			if (strcasecmp(fn + fnsz - 4, ext_tab[i].ext) == 0) {
				ftype = ext_tab[i].type;
				break;
			}
		}

		switch (ftype) {
		case TYPE_CER:
			time = get_cert_notbefore(fn);
			break;
		case TYPE_CRL:
			time = get_crl_lastupdate(fn);
			break;
		case TYPE_ASPA:
		case TYPE_GBR:
		case TYPE_MFT:
		case TYPE_ROA:
		case TYPE_TAK:
			time = cms_get_signtime(fn);
			break;
		default:
			warnx("%s: unsupported file", fn);
			rc = 1;
			continue;
		}

		if (time == 0)
			continue;

		if (!set_mtime(fn, time))
			rc = 1;
	}

	return rc;
}

void
usage(void)
{
	fprintf(stderr, "usage: rpkitouch [-hVv] file ...\n");
	exit(1);
}
