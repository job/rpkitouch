RPKITOUCH(8) - System Manager's Manual

# NAME

**rpkitouch** - set file modification times to internal RPKI timestamps

# SYNOPSIS

**rpkitouch**
\[**-n**]
\[**-H**&nbsp;*fqdn*]
**-c**&nbsp;*ccr\_file*  
**rpkitouch**
\[**-n**]
**-R**&nbsp;*out\_ccr*
*file&nbsp;...*  
**rpkitouch**
\[**-CnpVv**]
\[**-d**&nbsp;*directory*]
\[**-H**&nbsp;*fqdn*]
*file&nbsp;...*

# DESCRIPTION

The
**rpkitouch**
utility can inspect
*Canonical Cache Representation* (CCR)
objects, generate content-addressable filesystem hierarchies, and set the last
data modification time of
*file*
to the timestamp internal to the contained
*RPKI*
object.

**rpkitouch**
is useful for
*RPKI*
Publication Point operators who serialize
*RPKI*
objects from data sources lacking file modification times (such as
*RRDP*)
to a disk hierachy for public consumption via
*RSYNC*.

*RPKI*
Publication Point operators as well as
*Relying Parties*
benefit from deterministic file modification times when synchronizing local
caches following data transfer protocol switches between
*RRDP*
to
*RSYNC*,
because deterministic mod-times help minimize RP synchronisation load.

For
*Autonomous System Provider Authorisation* (ASPA),
*Manifests* (MFT),
*Route Origin Authorization* (ROA),
*Signed Prefix Lists* (SPL),
and
*Trust Anchor Key* (TAK)
objects the
*CMS signing-time*
attribute is used as timestamp; for
*X.509*
*CA*
and
*EE*
certificates the
*notBefore*
is used as timestamp; for
*Certificate Revocation Lists* (CRL)
the
*thisUpdate*
is used as timestamp.

While the
**rpkitouch**
utility does not perform any cryptographic validation, the following sanity
checks are performed before setting the file modification time.
For
*CMS*
files the self-signage and the presence of no more than one
*CMS\_SignerInfo*
and one
*signing-time*
attribute are confirmed.
*X.509*
*Certificate*
and
*CRL*
files must successfully decode into the applicable ASN.1 structure.
Files may not contain trailing data beyond the internal length markers.

The options are as follows:

**-C**

> Compare and deduplicate ManifestInstances contained with the specified CCR
> file(s).
> If
> **-d**
> is specified, generate and store Erik Synchronisation objects in
> *directory*.

**-c** *ccr\_file*

> Print the SHA-256 message digest and SIA field values (without the scheme) of
> the ManifestInstances contained within
> *ccr\_file*.

**-d** *directory*

> SHA-256 message digests are calculated for all objects and their content is
> stored in
> *directory*
> using a content-addressable file naming scheme.
> To improve performance, existing files are only overwritten if the size or
> last modification timestamp differ.

**-H** *fqdn*

> Only emit ManifestInstances within the scope of
> *fqdn*.
> Can only be combined with
> **-C**
> and
> **-c**.

**-h**

> Display usage.

**-n**

> No-op.
> The file's modification time is computed but not set and no copies are made.
> Can be combined with
> **-d**
> and
> **-v**
> to see what
> **rpkitouch**
> would change.

**-p**

> Print the directory path derived from the SIA and the FileAndHashes contained
> in a Manifest's payload, followed by the Manifest's own filename.

**-R** *out\_ccr*

> Output a reduced CCR in
> *out\_ccr*
> by removing all states except the ManifestState, and comparing and deduplicating
> ManifestInstances in the specified CCR file(s).

**-V**

> Display the version number and exit.

**-v**

> Verbose operation.

# INSTALLATION

**rpkitouch**
runs on all operating systems with a libcrypto library based on
OpenSSL 1.1 or LibreSSL 3.6 or later.

# EXIT STATUS

The **rpkitouch** utility exits&#160;0 on success, and&#160;&gt;0 if an error occurs.

# EXAMPLES

Recursively set all data modification times of all files in a given directory
hierarchy to their respective
*RPKI*
derived timestamps:

	$ cd /usr/share/rpki/publication/
	$ find . -type f -exec rpkitouch {} \+

Copy a signed object to
*/tmp/a*
with the Base64 encoded SHA-256 message digest as its target file name.

	$ rpkitouch -vd /tmp/test ./rpki.ripe.net/repository/ripe-ncc-ta.mft
	rpkitouch: rpki.ripe.net/repository/ripe-ncc-ta.mft wtBCe8WjLELuoatWY9WSsfwpx9TvFqsLXh1jHQOdzCE (st:1756387926 sz:1786 d:1126859)
	rpkitouch: named/rpki.ripe.net/repository/ripe-ncc-ta.mft (st:1756387926 sz:1786 d:1126859)
	
	$ find /tmp/test
	/tmp/test
	/tmp/test/static
	/tmp/test/static/wt
	/tmp/test/static/wt/BC
	/tmp/test/static/wt/BC/e8
	/tmp/test/static/wt/BC/e8/wtBCe8WjLELuoatWY9WSsfwpx9TvFqsLXh1jHQOdzCE
	/tmp/test/named
	/tmp/test/named/rpki.ripe.net
	/tmp/test/named/rpki.ripe.net/repository
	/tmp/test/named/rpki.ripe.net/repository/ripe-ncc-ta.mft

# SETTING UP AN ERIK RELAY

An Erik relay worker job could be summarised as the following sequence of shell
commands:

	#!/bin/sh
	set -ev
	while true; do
	    rpki-client
	    if [ -f /tmp/previous.ccr ]; then
	        rpkitouch -c /tmp/previous.ccr > /tmp/previous.txt
	    else
	        echo > /tmp/previous.txt
	    fi
	
	    cp /var/db/rpki-client/rpki.ccr /tmp/current.ccr
	    rpkitouch -c /tmp/current.ccr > /tmp/current.txt
	    comm -1 -3 /tmp/previous.txt /tmp/current.txt | awk '{ print $NF }' > /tmp/new.txt
	    cd /var/cache/rpki-client
	    sort -R /tmp/new.txt | xargs rpkitouch -p | xargs rpkitouch -v -d /nfs
	    rpkitouch -C -v -d /nfs /tmp/current.ccr
	done

A simple webserver configuration for an Erik relay would then look like:

	server {
	    listen 80 default_server;
	    server_name _;
	    root /nfs;
	    rewrite ^/.well-known/ni/sha-256/(..)(..)(..)(.*)$ /static/$1/$2/$3/$1$2$3$4;
	    rewrite ^/.well-known/erik/index/(.*)$ /erik/index/$1;
	}

# STANDARDS

*Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile*,
[RFC 5280](http://www.rfc-editor.org/rfc/rfc5280.html).

*Cryptographic Message Syntax (CMS)*,
[RFC 5652](http://www.rfc-editor.org/rfc/rfc5652.html).

*A Profile for X.509 PKIX Resource Certificates*,
[RFC 6487](http://www.rfc-editor.org/rfc/rfc6487.html).

*On the Use of the CMS Signing-Time Attribute in RPKI Signed Objects*,
[RFC 9589](http://www.rfc-editor.org/rfc/rfc9589.html).

*A Profile for RPKI Canonical Cache Representation*,
https://datatracker.ietf.org/doc/html/draft-ietf-sidrops-rpki-ccr.

*The Erik Synchronization Protocol for use with the RPKI*,
https://datatracker.ietf.org/doc/html/draft-ietf-sidrops-rpki-erik-protocol.

# AUTHORS

Job Snijders &lt;[job@openbsd.org](mailto:job@openbsd.org)&gt;

OpenBSD 7.8 - January 27, 2026 - RPKITOUCH(8)
