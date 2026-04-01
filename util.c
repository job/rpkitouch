/*
 * Copyright (c) 2020 Claudio Jeker <claudio@openbsd.org>
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

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include "extern.h"

unsigned char *
load_file(const char *fn, off_t *len, time_t *time)
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

unsigned char *
load_fileat(const char *fn, off_t *len, time_t *time)
{
	unsigned char *buf = NULL;
	struct stat st;
	ssize_t n;
	size_t size;
	int fd, saved_errno;

	*len = 0;
	*time = 0;

	memset(&st, 0, sizeof(st));

	if ((fd = openat(outdirfd, fn, O_RDONLY)) == -1)
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

/*
 * Write content to a temp file and then atomically move it into place.
 */
void
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

	if (outdirfd == 0)
		outdirfd = AT_FDCWD;

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

	if (mtime != 0) {
		if (futimens(fd, ts))
			err(1, "futimens %s/%s", dn, tmpbn);
	}

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
update_atime(const char *file)
{
	struct timespec ts[2];

	ts[0].tv_nsec = UTIME_NOW;
	ts[1].tv_nsec = UTIME_OMIT;

	if (utimensat(outdirfd, file, ts, 0) == -1) {
		warn("%s: utimensat failed", file);
		return -1;
	}

	return 0;
}

int
store_by_hash(struct file *f)
{
	char *b = NULL;
	char *dir = NULL, *path = NULL;
	struct stat st;
	time_t delay = 0;
	int wrote = 0;

	if (!b64uri_encode(f->hash, SHA256_DIGEST_LENGTH, &b))
		err(1, "b64uri_encode");

	/*
	 * Two levels of directory-based sharding.
	 * The last few byte of the hash are used as directory path to
	 * increase prefix diversity.
	 */
	if (asprintf(&dir, "static/%c%c/%c%c", b[39], b[40], b[41], b[42])
	    == -1)
		err(1, NULL);

	if (!noop) {
		if (mkpathat(outdirfd, dir) == -1)
			err(1, "mkpathat %s", dir);
	}

	if (asprintf(&path, "%s/%s", dir, b) == -1)
		err(1, "asprintf");

	free(dir);

	memset(&st, 0, sizeof(struct stat));
	if (fstatat(outdirfd, path, &st, 0) != 0) {
		if (errno != ENOTDIR && errno != ENOENT)
			err(1, "fstatat %s", path);
	}

	/*
	 * Skip files that already are of the same size and have the same
	 * last data modification timestamp.
	 */
	if (st.st_size != f->content_len || st.st_mtim.tv_sec != f->signtime) {
		if (verbose) {
			if (time(NULL) > f->signtime)
				delay = time(NULL) - f->signtime;
			warnx("%s %s (st:%lld sz:%lld d:%lld)", f->name, b,
			    (long long)f->signtime, (long long)f->content_len,
			    (long long)delay);
		}
		write_file(path, f->content, f->content_len, f->signtime);
		wrote = 1;
	} else
		update_atime(path);

	free(b);
	free(path);

	return wrote;
}

/*
 * Store Manifests into their named location (using the SIA SignedObject).
 * Only overwrite if the on-disk copy is older.
 */
int
store_by_name(struct file *f, struct mft *mft)
{
	char *dir = NULL, *path = NULL;
	struct stat st;
	time_t delay = 0;

	if (asprintf(&dir, "named/%s", mft->sia_dirname) == -1)
		err(1, "asprintf");

	if (!noop) {
		if (mkpathat(outdirfd, dir) == -1)
			err(1, "mkpathat %s", dir);
	}

	if (asprintf(&path, "named/%s", mft->sia + RSYNC_PROTO_LEN) == -1)
		err(1, "asprintf");

	memset(&st, 0, sizeof(st));
	if (fstatat(outdirfd, path, &st, 0) != 0) {
		if (errno != ENOTDIR && errno != ENOENT)
			err(1, "fstatat %s", path);
	}

	if (st.st_mtim.tv_sec < mft->thisupdate) {
		if (verbose) {
			if (time(NULL) > mft->thisupdate)
				delay = time(NULL) - mft->thisupdate;
			warnx("%s (st:%lld sz:%lld d:%lld)", path,
			    (long long)mft->thisupdate,
			    (long long)f->content_len, (long long)delay);
		}
		write_file(path, f->content, f->content_len, mft->thisupdate);
	} else
		update_atime(path);

	free(dir);
	free(path);

	return 0;
}

void
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
 * RFC 4648 section 5.
 */
int
b64uri_encode(const unsigned char *in, size_t inlen, char **out)
{
	char *to;
	size_t tolen = 0;
	char *c = NULL;

	*out = NULL;

	if (inlen >= INT_MAX / 2)
		return 0;

	tolen = ((inlen + 2) / 3) * 4 + 1;

	if ((to = malloc(tolen)) == NULL)
		return 0;

	EVP_EncodeBlock((unsigned char *)to, in, inlen);
	*out = to;

	c = (char *)to;
	while ((c = strchr(c, '+')) != NULL)
		*c = '-';
	c = (char *)to;
	while ((c = strchr(c, '/')) != NULL)
		*c = '_';
	if ((c = strchr((char *)to, '=')) != NULL)
		*c = '\0';

	return 1;
}

/*
 * Convert binary buffer of size dsz into an upper-case hex-string.
 * Returns pointer to the newly allocated string. Function can't fail.
 */
char *
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

/*
 * Hex decode hexstring into the supplied buffer.
 * Return 0 on success else -1, if buffer too small or bad encoding.
 */
int
hex_decode(const char *hexstr, char *buf, size_t len)
{
	unsigned char ch, r;
	size_t pos = 0;
	int i;

	while (*hexstr) {
		r = 0;
		for (i = 0; i < 2; i++) {
			ch = hexstr[i];
			if (isdigit(ch))
				ch -= '0';
			else if (islower(ch))
				ch -= ('a' - 10);
			else if (isupper(ch))
				ch -= ('A' - 10);
			else
				return -1;
			if (ch > 0xf)
				return -1;
			r = r << 4 | ch;
		}
		if (pos < len)
			buf[pos++] = r;
		else
			return -1;

		hexstr += 2;
	}
	return 0;
}

/*
 * Pack a manifest and CRL together and store in gzip compressed form.
 */
void
store_pack(struct file *m, char *crlhash)
{
	char *pn;
	struct file *crl, *pack;
	unsigned char *buf = NULL;
	off_t packlen;
	z_stream zs;
	struct stat st;

	if (!noop) {
		if (mkpathat(outdirfd, "erik/pack") == -1)
			err(1, "mkpathat %s", "erik/pack");
	}

	if (!b64uri_encode(m->hash, SHA256_DIGEST_LENGTH, &pn))
		err(1, "b64uri_encode");

	if ((pack = calloc(1, sizeof(*pack))) == NULL)
		err(1, NULL);

	if (asprintf(&pack->name, "erik/pack/%s", pn) == -1)
		err(1, NULL);

	if ((crl = calloc(1, sizeof(*crl))) == NULL)
		err(1, NULL);

	if (asprintf(&crl->name, "static/%c%c/%c%c/%s", crlhash[39],
	    crlhash[40], crlhash[41], crlhash[42], crlhash) == -1)
		err(1, NULL);

	crl->content = load_fileat(crl->name, &crl->content_len,
	    &crl->disktime);

	if ((buf = malloc(m->content_len + crl->content_len)) == NULL)
		err(1, NULL);

	memmove(buf, m->content, m->content_len);
	memmove(buf + m->content_len, crl->content, crl->content_len);

	memset(&zs, 0, sizeof(zs));

	if (deflateInit2(&zs, Z_BEST_COMPRESSION, Z_DEFLATED, (15 + 16), 8,
	    Z_DEFAULT_STRATEGY) != Z_OK)
		errx(1, "deflateInit2");

	packlen = deflateBound(&zs, m->content_len + crl->content_len);

	if ((pack->content = malloc(packlen)) == NULL)
		err(1, NULL);

	zs.avail_in = m->content_len + crl->content_len;
	zs.next_in = buf;
	zs.avail_out = packlen;
	zs.next_out = pack->content;

	if (deflate(&zs, Z_FINISH) != Z_STREAM_END)
		errx(1, "deflate");

	pack->content_len = zs.total_out;

	deflateEnd(&zs);

	memset(&st, 0, sizeof(struct stat));
	if (fstatat(outdirfd, pack->name, &st, 0) != 0) {
		if (errno != ENOTDIR && errno != ENOENT)
			err(1, "fstatat %s", pack->name);
	}

	/*
	 * Skip writing packs that already are of the same size and have the
	 * same last data modification timestamp.
	 */
	if (st.st_size != pack->content_len ||
	    st.st_mtim.tv_sec != m->signtime) {
		if (verbose) {
			warnx("%s (st:%lld osz:%lld sz:%lld)", pack->name,
			    (long long)m->signtime,
			    (long long)(m->content_len + crl->content_len),
			    (long long)pack->content_len);
		}
		write_file(pack->name, pack->content, pack->content_len,
		    m->signtime);
	} else
		update_atime(pack->name);

	free(buf);
	free(pn);
	file_free(pack);
	file_free(crl);
}
