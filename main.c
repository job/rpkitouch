/*
 * Copyright (c) 2023-2025 Job Snijders <job@sobornost.net>
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

#include <sys/queue.h>

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/objects.h>
#include <openssl/sha.h>

#include "compat/tree.h"

#include "extern.h"

int outputerik = 0;
int noop = 0;
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
	{ .ext = ".gbr", .type = TYPE_GBR },
	{ .ext = ".mft", .type = TYPE_MFT },
	{ .ext = ".roa", .type = TYPE_ROA },
	{ .ext = ".spl", .type = TYPE_SPL },
	{ .ext = ".tak", .type = TYPE_TAK },
	{ .ext = ".tal", .type = TYPE_TAL }
};

ASN1_OBJECT *ccr_oid;
ASN1_OBJECT *manifest_oid;
ASN1_OBJECT *notify_oid;
ASN1_OBJECT *sign_time_oid;
ASN1_OBJECT *signedobj_oid;
ASN1_OBJECT *idx_oid;
ASN1_OBJECT *par_oid;

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
	if ((ccr_oid = OBJ_txt2obj("1.3.6.1.4.1.41948.825", 1)) == NULL)
		errx(1, "OBJ_txt2obj for %s failed", "ccr_oid");
	if ((idx_oid = OBJ_txt2obj("1.3.6.1.4.1.41948.826", 1)) == NULL)
		errx(1, "OBJ_txt2obj for %s failed", "idx_oid");
	if ((par_oid = OBJ_txt2obj("1.3.6.1.4.1.41948.827", 1)) == NULL)
		errx(1, "OBJ_txt2obj for %s failed", "par_oid");
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
	struct mftref *ma = *(struct mftref **)a;
	struct mftref *mb = *(struct mftref **)b;

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

int
main(int argc, char *argv[])
{
	int c, count = 0, i, rc = 0;
	char *ccr_file = NULL, *outdir = NULL;
	struct file *f;
	unsigned char *fc;
	struct mftref_tree mftref_tree;
	struct ccr *ccr = NULL;
	struct mft *mft = NULL;

	while ((c = getopt(argc, argv, "Cc:d:hnpVv")) != -1)
		switch (c) {
		case 'C':
			outputerik = 1;
			break;
		case 'c':
			ccr_file = optarg;
			break;
		case 'd':
			outdir = optarg;
			break;
		case 'n':
			noop = 1;
			break;
		case 'p':
			noop = 1;
			print = 1;
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

	if (outdir == NULL && *argv == NULL && ccr_file == NULL)
		usage();

	if (outdir != NULL && print) {
		warnx("cannot combine -d and -p");
		usage();
	}

	if (ccr_file != NULL && outdir != NULL)
		usage();

	setup_oids();

	if (outdir != NULL && !noop) {
		if ((outdirfd = open(outdir, O_RDONLY | O_DIRECTORY)) == -1)
			err(1, "output directory %s", outdir);
	}

	if (outputerik) {
		struct mftref *mftref;
		struct mftref **refs;

		if  (*argv == NULL)
			usage();

		RB_INIT(&mftref_tree);

		if ((count = compare_ccrs(argv, &mftref_tree)) == 0)
			errx(1, "compare_ccrs");

		if ((refs = calloc(count, sizeof(refs))) == NULL)
			err(1, NULL);

		i = count;
		RB_FOREACH(mftref, mftref_tree, &mftref_tree) {
			refs[--i] = mftref;
		}

		qsort(refs, count, sizeof(refs[0]), fqdn_aki_hash_cmp);

		if (outdir == NULL) {
			for (i = 0; i < count; i++) {
				printf("aki:%s seqnum:%s tu:%lld %s %s\n",
				    refs[i]->aki, refs[i]->seqnum,
				    (long long)refs[i]->thisupdate,
				    refs[i]->hash, refs[i]->sia);
			}
		} else {
			generate_erik_objects(refs, count);
		}

		free(refs);

		struct mftref *tmp_mftref;
		RB_FOREACH_SAFE(mftref, mftref_tree, &mftref_tree, tmp_mftref) {
			RB_REMOVE(mftref_tree, &mftref_tree, mftref);
			mftref_free(mftref);
		}

		return 0;
	}

	if (ccr_file != NULL) {
		if ((f = calloc(1, sizeof(struct file))) == NULL)
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

		for (i = 0; i < ccr->refs_num; i++)
			printf("%s %s\n", ccr->refs[i]->hash, ccr->refs[i]->sia);

		file_free(f);
		return 0;
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

		if ((f->signtime = get_time_from_content(f)) == 0) {
			file_free(f);
			continue;
		}

		if (f->type == TYPE_MFT) {
			if ((mft = parse_manifest(f)) == NULL) {
				warnx("%s: parse_manifest", f->name);
				continue;
			}

			if (print) {
				for (i = 0; i < mft->fh_num; i++) {
					printf("%s/%s\n", mft->sia_dirname,
					    mft->files[i].fn);
				}
				printf("%s\n", mft->sia);
			}
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
			store_by_hash(f);

		if (outdir != NULL && f->type == TYPE_MFT)
			store_by_name(f, mft);

		file_free(f);
		f = NULL;
	}

	return rc;
}

void
usage(void)
{
	fprintf(stderr, "usage: rpkitouch [-CnpVv] [-d dir] file ...\n");
	fprintf(stderr, "       rpkitouch [-n] -c ccr_file\n");
	exit(1);
}
