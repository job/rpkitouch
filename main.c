/*
 * Copyright (c) 2023-2026 Job Snijders <job@bsd.nl>
 * Copyright (c) 2025 Theo Buehler <tb@openbsd.org>
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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/objects.h>
#include <openssl/cms.h>
#include <openssl/sha.h>

#include "compat/queue.h"
#include "compat/tree.h"

#include "extern.h"

int compare = 0;
int noop = 0;
int pack = 0;
int print = 0;
int verbose = 0;
int outdirfd;

/*
 * https://www.iana.org/assignments/rpki/rpki.xhtml
 * .tal is not IANA registered, but added as convenience.
 */
const struct {
	const char *ext;
	enum filetype type;
} ext_tab[] = {
	{ .ext = ".asa", .type = TYPE_ASPA },
	{ .ext = ".ccr", .type = TYPE_CCR },
	{ .ext = ".cer", .type = TYPE_CER },
	{ .ext = ".crl", .type = TYPE_CRL },
	{ .ext = ".mft", .type = TYPE_MFT },
	{ .ext = ".roa", .type = TYPE_ROA },
	{ .ext = ".spl", .type = TYPE_SPL },
	{ .ext = ".tak", .type = TYPE_TAK },
	{ .ext = ".tal", .type = TYPE_TAL }
};

ASN1_OBJECT *notify_oid;
ASN1_OBJECT *sign_time_oid;
ASN1_OBJECT *signedobj_oid;
ASN1_OBJECT *manifest_oid;
ASN1_OBJECT *ccr_oid;
ASN1_OBJECT *eidx_oid;
ASN1_OBJECT *epar_oid;
ASN1_OBJECT *aspa_oid;
ASN1_OBJECT *roa_oid;
ASN1_OBJECT *spl_oid;
ASN1_OBJECT *tak_oid;

static void
setup_oids(void) {
	if ((notify_oid = OBJ_txt2obj("1.3.6.1.5.5.7.48.13", 1)) == NULL)
		errx(1, "OBJ_txt2obj for %s failed", "notify_oid");
	if ((sign_time_oid = OBJ_txt2obj("1.2.840.113549.1.9.5", 1)) == NULL)
		errx(1, "OBJ_txt2obj for %s failed", "sign_time_oid");
	if ((signedobj_oid = OBJ_txt2obj("1.3.6.1.5.5.7.48.11", 1)) == NULL)
		errx(1, "OBJ_txt2obj for %s failed", "signedobj_oid");
	if ((manifest_oid = OBJ_txt2obj("1.2.840.113549.1.9.16.1.26", 1))
	    == NULL)
		errx(1, "OBJ_txt2obj for %s failed", "manifest_oid");
	if ((ccr_oid = OBJ_txt2obj("1.2.840.113549.1.9.16.1.54", 1)) == NULL)
		errx(1, "OBJ_txt2obj for %s failed", "ccr_oid");
	if ((eidx_oid = OBJ_txt2obj("1.2.840.113549.1.9.16.1.55", 1)) == NULL)
		errx(1, "OBJ_txt2obj for %s failed", "eidx_oid");
	if ((epar_oid = OBJ_txt2obj("1.2.840.113549.1.9.16.1.56", 1)) == NULL)
		errx(1, "OBJ_txt2obj for %s failed", "epar_oid");
	if ((aspa_oid = OBJ_txt2obj("1.2.840.113549.1.9.16.1.49", 1)) == NULL)
		errx(1, "OBJ_txt2obj for %s failed", "aspa_oid");
	if ((roa_oid = OBJ_txt2obj("1.2.840.113549.1.9.16.1.24", 1)) == NULL)
		errx(1, "OBJ_txt2obj for %s failed", "roa_oid");
	if ((spl_oid = OBJ_txt2obj("1.2.840.113549.1.9.16.1.51", 1)) == NULL)
		errx(1, "OBJ_txt2obj for %s failed", "spl_oid");
	if ((tak_oid = OBJ_txt2obj("1.2.840.113549.1.9.16.1.50", 1)) == NULL)
		errx(1, "OBJ_txt2obj for %s failed", "tak_oid");
}

static void
destroy_oids(void)
{
	ASN1_OBJECT_free(notify_oid);
	ASN1_OBJECT_free(sign_time_oid);
	ASN1_OBJECT_free(signedobj_oid);
	ASN1_OBJECT_free(manifest_oid);
	ASN1_OBJECT_free(ccr_oid);
	ASN1_OBJECT_free(eidx_oid);
	ASN1_OBJECT_free(epar_oid);
}

enum filetype
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

enum filetype
detect_ftype_from_der(struct file *f)
{
	CMS_ContentInfo *cms = NULL;
	X509 *x509 = NULL;
	X509_CRL *crl = NULL;
	const unsigned char *p;
	enum filetype ftype = TYPE_UNKNOWN;

	p = f->content;
	if ((cms = d2i_CMS_ContentInfo(NULL, &p, f->content_len)) != NULL) {
		const ASN1_OBJECT *obj;

		if ((obj = CMS_get0_type(cms)) != NULL) {
			if (OBJ_cmp(obj, ccr_oid) == 0) {
				ftype = TYPE_CCR;
				goto out;
			}
			if (OBJ_cmp(obj, eidx_oid) == 0) {
				ftype = TYPE_EIDX;
				goto out;
			}
			if (OBJ_cmp(obj, epar_oid) == 0) {
				ftype = TYPE_EPAR;
				goto out;
			}
		}

		if (CMS_get0_SignerInfos(cms) == NULL) {
			warnx("%s: CMS object not signedData", f->name);
			goto out;
		}

		if ((obj = CMS_get0_eContentType(cms)) == NULL) {
			warnx("%s: RFC 6488, section 2.1.3.1: eContentType: "
			    "OID object is NULL", f->name);
			goto out;
		}

		if (OBJ_cmp(obj, aspa_oid) == 0)
			ftype = TYPE_ASPA;
		else if (OBJ_cmp(obj, manifest_oid) == 0)
			ftype = TYPE_MFT;
		else if (OBJ_cmp(obj, roa_oid) == 0)
			ftype = TYPE_ROA;
		else if (OBJ_cmp(obj, spl_oid) == 0)
			ftype = TYPE_SPL;
		else if (OBJ_cmp(obj, tak_oid) == 0)
			ftype = TYPE_TAK;

		goto out;
	}

	/* Does der parse as a certificate? */
	p = f->content;
	if ((x509 = d2i_X509(NULL, &p, f->content_len)) != NULL) {
		ftype = TYPE_CER;
		goto out;
	}

	/* Does der parse as a CRL? */
	p = f->content;
	if ((crl = d2i_X509_CRL(NULL, &p, f->content_len)) != NULL) {
		ftype = TYPE_CRL;
		goto out;
	}

 out:
	CMS_ContentInfo_free(cms);
	X509_free(x509);
	X509_CRL_free(crl);

	return ftype;
}

void
file_free(struct file *f)
{
	if (f == NULL)
		return;

	free(f->name);
	free(f->content);
	free(f);
}

/*
 * First sort by FQDN, then by first 2 octets of AKI, then by hash.
 * This way all ErikParition / ErikIndex objects can be generated
 * in a single pass.
 */
static int
fqdn_aki_hash_cmp(const void *a, const void *b)
{
	int cmp;
	struct mftinstance *ma = *(struct mftinstance **)a;
	struct mftinstance *mb = *(struct mftinstance **)b;

	cmp = strcmp(ma->fqdn, mb->fqdn);
	if (cmp > 0)
		return 1;
	if (cmp < 0)
		return -1;

	cmp = strncmp(ma->aki, mb->aki, 2);
	if (cmp > 0)
		return 1;
	if (cmp < 0)
		return -1;

	return strcmp(ma->hash, mb->hash);
}

/*
 * Sort by hash.
 */
static int
hash_cmp(const void *a, const void *b)
{
	struct mftinstance *ma = *(struct mftinstance **)a;
	struct mftinstance *mb = *(struct mftinstance **)b;

	return strcmp(ma->hash, mb->hash);
}

static struct mftinstance **
load_mftinstances_from_ccr(char *argv[], int *count)
{
	struct mftinstance_tree mftinstance_tree;
	struct mftinstance **mis, *mi, *mi_tmp;
	int i;

	RB_INIT(&mftinstance_tree);

	if ((i = merge_ccrs(argv, &mftinstance_tree)) == 0)
		errx(1, "merge_ccrs");

	*argv = NULL;

	if ((mis = calloc(i, sizeof(mis[0]))) == NULL)
		err(1, NULL);

	*count = i;

	RB_FOREACH_SAFE(mi, mftinstance_tree, &mftinstance_tree, mi_tmp) {
		RB_REMOVE(mftinstance_tree, &mftinstance_tree, mi);
		mis[--i] = mi;
	}

	return mis;
}

int
main(int argc, char *argv[])
{
	int c, count = 0, i, rc = 0;
	char *ccr_file = NULL, *outdir = NULL, *reduce = NULL, *repair = NULL;
	char *single_fqdn = NULL;
	struct file *f;
	unsigned char *fc;
	struct mftinstance **mis = NULL;
	struct ccr *ccr = NULL;
	struct mft *mft = NULL;

	while ((c = getopt(argc, argv, "Cc:d:H:hnPpR:r:Vv")) != -1)
		switch (c) {
		case 'C':
			compare = 1;
			break;
		case 'c':
			ccr_file = optarg;
			break;
		case 'd':
			outdir = optarg;
			break;
		case 'H':
			single_fqdn = optarg;
			break;
		case 'n':
			noop = 1;
			break;
		case 'P':
			pack = 1;
			break;
		case 'p':
			noop = 1;
			print = 1;
			break;
		case 'R':
			reduce = optarg;
			break;
		case 'r':
			repair = optarg;
			break;
		case 'V':
			printf("version 1.8\n");
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

	if (outdir == NULL && *argv == NULL && ccr_file == NULL && repair == NULL)
		usage();

	if (outdir != NULL && print) {
		warnx("cannot combine -d and -p");
		usage();
	}

	if (reduce != NULL && outdir != NULL)
		usage();

	if (reduce != NULL && ccr_file != NULL)
		usage();

	if (ccr_file != NULL && outdir != NULL)
		usage();

	if (outdir == NULL && repair == NULL) {
		if (pack) {
			usage();
		}
	}

	setup_oids();

	if (outdir != NULL && !noop) {
		if ((outdirfd = open(outdir, O_RDONLY | O_DIRECTORY)) == -1)
			err(1, "output directory %s", outdir);
	}

	if (compare) {
		if  (*argv == NULL)
			usage();

		mis = load_mftinstances_from_ccr(argv, &count);

		qsort(mis, count, sizeof(mis[0]), fqdn_aki_hash_cmp);

		if (outdir != NULL) {
			generate_erik_objects(mis, count, single_fqdn);
		} else {
			for (i = 0; i < count; i++) {
				printf("aki:%s seqnum:%s tu:%lld %s %s\n",
				    mis[i]->aki, mis[i]->seqnum,
				    (long long)mis[i]->thisupdate,
				    mis[i]->hash, mis[i]->sia);
			}
		}

		for (i = 0; i < count; i++)
			mftinstance_free(mis[i]);

		free(mis);
	}

	if (reduce != NULL) {
		if  (*argv == NULL)
			usage();

		mis = load_mftinstances_from_ccr(argv, &count);

		qsort(mis, count, sizeof(mis[0]), hash_cmp);

		f = generate_reduced_ccr(mis, count);

		write_file(reduce, f->content, f->content_len, 0);

		for (i = 0; i < count; i++)
			mftinstance_free(mis[i]);

		free(mis);
		file_free(f);
	}

	if (repair != NULL) {
		if ((f = calloc(1, sizeof(*f))) == NULL)
			err(1, NULL);

		if ((f->type = detect_ftype_from_fn(repair)) != TYPE_CCR) {
			warnx("%s: -r only accepts .ccr", repair);
			usage();
		}

		f->name = strdup(repair);

		fc = load_file(repair, &f->content_len, &f->disktime);
		if (fc == NULL)
			errx(1, "%s: load_file failed", f->name);
		f->content = fc;

		if (!repair_ccr(f)) {
			warnx("%s: repair failed", f->name);
			file_free(f);
			return 1;
		}

		return 0;
	}

	if (ccr_file != NULL) {
		if ((f = calloc(1, sizeof(*f))) == NULL)
			err(1, NULL);

		if ((f->type = detect_ftype_from_fn(ccr_file)) != TYPE_CCR) {
			warnx("%s: -c only accepts .ccr", ccr_file);
			usage();
		}

		f->name = strdup(ccr_file);

		fc = load_file(ccr_file, &f->content_len, &f->disktime);
		if (fc == NULL)
			errx(1, "%s: load_file failed", f->name);
		f->content = fc;

		if ((ccr = parse_ccr(f)) == NULL) {
			warnx("%s: parsing failed", f->name);
			file_free(f);
			return 1;
		}
		for (i = 0; i < ccr->mis_num; i++) {
			if (single_fqdn != NULL) {
				if (strncmp(ccr->mis[i]->sia, single_fqdn,
				    strlen(single_fqdn)) != 0)
					continue;
			}
			printf("%s %s\n", ccr->mis[i]->hash,
			    ccr->mis[i]->sia + RSYNC_PROTO_LEN);
		}

		file_free(f);
		ccr_free(ccr);
	}

	for (; *argv != NULL; ++argv) {
		if ((f = calloc(1, sizeof(*f))) == NULL)
			err(1, NULL);

		f->id = ++count;
		f->type = detect_ftype_from_fn(*argv);
		if ((f->name = strdup(*argv)) == NULL)
			err(1, NULL);

		fc = load_file(f->name, &f->content_len, &f->disktime);
		if (fc == NULL)
			errx(1, "%s: load_file failed", f->name);

		f->content = fc;
		SHA256(f->content, f->content_len, f->hash);

		if (f->type == TYPE_UNKNOWN)
			f->type = detect_ftype_from_der(f);

		if ((f->signtime = get_time_from_content(f)) == 0) {
			file_free(f);
			continue;
		}

		if (f->type == TYPE_MFT) {
			if ((mft = parse_manifest(f)) == NULL) {
				warnx("%s: parse_manifest", f->name);
				continue;
			}

			for (i = 0; i < mft->fh_num; i++) {
				if (detect_ftype_from_fn(mft->files[i].fn)
				    == TYPE_UNKNOWN)
					continue;
				if (detect_ftype_from_fn(mft->files[i].fn)
				    == TYPE_CRL)
					mft->crlhash = mft->files[i].hash;
				if (!print)
					continue;
				printf("%s/%s\n", mft->sia_dirname, mft->files[i].fn);
			}
			if (print)
				printf("%s\n", mft->sia + RSYNC_PROTO_LEN);
		}
		if (f->type == TYPE_EIDX || f->type == TYPE_EPAR) {
			if (print)
				printf("%s %lld\n", f->name, (long long)f->signtime);
		}

		/*
		 * Update the mod-time
		 */

		if (outdir == NULL) {
			if (f->disktime != f->signtime) {
				if (verbose) {
					warnx("%s %lld -> %lld", f->name,
					    (long long)f->disktime, (long long)f->signtime);
				}
				set_mtime(AT_FDCWD, f->name, f->signtime);
			}
		}

		/*
		 * Optionally, store the object using the content
		 * addressable scheme.
		 */
		if (outdir != NULL)
			store_by_hash(f, 0);

		if (outdir != NULL && f->type == TYPE_MFT)
			store_by_name(f, mft);

		if (pack && f->type == TYPE_MFT)
			store_pack(f, mft->crlhash);

		if (f->type == TYPE_MFT) {
			mft_free(mft);
			mft = NULL;
		}
		file_free(f);
		f = NULL;
	}

	destroy_oids();
	return rc;
}

void
usage(void)
{
	fprintf(stderr, "usage: rpkitouch [-CnPpVv] [-d dir] [-H fqdn] file ...\n");
	fprintf(stderr, "       rpkitouch [-n] [-H fqdn] -c ccr_file\n");
	fprintf(stderr, "       rpkitouch [-n] -R out_ccr ccr_file ...\n");
	fprintf(stderr, "       rpkitouch [-n] -r ccr_file\n");
	exit(1);
}
