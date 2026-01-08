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

#include <limits.h>

#include <openssl/asn1.h>

#include "compat/queue.h"
#include "compat/tree.h"

#define GENTIME_LENGTH 15
#define MAX_URI_LENGTH 2048
#define RSYNC_PROTO "rsync://"
#define RSYNC_PROTO_LEN (sizeof(RSYNC_PROTO) - 1)

enum filetype {
	TYPE_ASPA,
	TYPE_CCR,
	TYPE_CER,
	TYPE_CRL,
	TYPE_GBR,
	TYPE_MFT,
	TYPE_ROA,
	TYPE_SPL,
	TYPE_TAK,
	TYPE_TAL,
	TYPE_UNKNOWN,
};

struct mftref {
	RB_ENTRY(mftref) entry;
	char *hash;
	uint64_t size;
	char *aki;
	time_t thisupdate;
	char *seqnum;
	char *sia;
	char *fqdn;
};

struct ccr_mft_sub_ski {
	SLIST_ENTRY(ccr_mft_sub_ski) entry;
	unsigned char ski[SHA_DIGEST_LENGTH];
};

SLIST_HEAD(subordinates_head, ccr_mft_sub_ski);

struct mftinstance {
	RB_ENTRY(mftinstance) entry;
	char *hash;
	uint64_t size;
	char *aki;
	time_t thisupdate;
	char *seqnum;
	char *sia;
	char *fqdn;
	struct subordinates_head subordinates;
};

RB_HEAD(mftinstance_tree, mftinstance);
RB_PROTOTYPE(mftinstance_tree, mftinstance, entry, mftinstancecmp);

struct ccr {
	time_t producedat;
	struct mftinstance **mis;
	int mis_num;
};

struct fileandhash {
	char *fn;
	char *hash;
};

struct mft {
	time_t thisupdate;
	char *sia;
	char *sia_dirname;
	struct fileandhash *files;
	int fh_num;
	char *seqnum;
};

struct file {
	int id;
	enum filetype type;
	char *name;
	time_t disktime;
	time_t signtime;
	unsigned char hash[SHA256_DIGEST_LENGTH];
	unsigned char *content;
	off_t content_len;
};


int b64uri_encode(const unsigned char *, size_t, char **);
char *hex_encode(const unsigned char *, size_t);
int hex_decode(const char *, char *, size_t);

unsigned char *load_file(const char *, off_t *, time_t *);
unsigned char *load_fileat(int, const char *, off_t *, time_t *);
void write_file(char *, unsigned char *, off_t, time_t);

int mkpathat(int, const char *);
int mkstempat(int, char *);

struct ccr *parse_ccr(struct file *f);
struct mft *parse_manifest(struct file *f);
void hash_asn1_item(ASN1_OCTET_STRING *, const ASN1_ITEM *, void *);

time_t get_time_from_content(struct file *f);

void set_mtime(int, const char *, time_t);

int store_by_hash(struct file *);
int store_by_name(struct file *, struct mft *);

void ccr_free(struct ccr *);
void mftref_free(struct mftref *);
void mftinstance_free(struct mftinstance *);
void file_free(struct file *);
enum filetype detect_ftype_from_fn(char *);
int merge_ccrs(char **, struct mftinstance_tree *);
void generate_erik_objects(struct mftinstance **, int, char *);
struct file *generate_reduced_ccr(struct mftinstance **, int);
void usage(void);

extern ASN1_OBJECT *ccr_oid;
extern ASN1_OBJECT *manifest_oid;
extern ASN1_OBJECT *notify_oid;
extern ASN1_OBJECT *sign_time_oid;
extern ASN1_OBJECT *signedobj_oid;
extern ASN1_OBJECT *idx_oid;
extern ASN1_OBJECT *par_oid;

extern int noop;
extern int verbose;
extern int outdirfd;
