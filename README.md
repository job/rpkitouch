RPKITOUCH(8) - System Manager's Manual

# NAME

**rpkitouch** - set file modification times to internal RPKI timestamps

# SYNOPSIS

**rpkitouch**
\[**-hnVv**]
\[**-d**&nbsp;*directory*]
*file&nbsp;...*

# DESCRIPTION

The
**rpkitouch**
utility sets the last data modification time of
*file*
to the timestamp internal to the contained
*RPKI*
object.
Deterministic timestamps help minimize RP synchronisation times.

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
*RSYNC*.

For
*Autonomous System Provider Authorisation* (ASPA),
*Ghostbuster Records* (GBR),
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

**-d** *directory*

> Calculate the SHA-256 message digest for
> *file*
> and copy its contents to
> *directory*
> using a content-addressable file naming scheme.
> To improve performance, existing files are only overwritten if the size or
> last modification timestamp differ.

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

**-V**

> Display the version number and exit.

**-v**

> Verbose operation.

# INSTALLATION

**rpkitouch**
runs on all operating systems with a libcrypto library based on
OpenSSL 1.1 or LibreSSL 3.6 or later.

On Ubuntu/Debian install the
*libssl-dev*
package, on Redhat/Rocky/Fedora install the
*openssl-devel*
package, then simply issue
'`make`'
to build;
on Centos 7 install
*openssl11-devel*
from EPEL and then build the program using this special target
'`make centos7`'

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

	$ rpkitouch -vd /tmp/a rpki.ripe.net/repository/ripe-ncc-ta.mft
	rpki.ripe.net/repository/ripe-ncc-ta.mft kX/xB/kXxBgilLlXi4SJHY9JoWnmJAtRoO5oE084UXV6TsQ20.mft 1744024405 (271880)
	
	$ find /tmp/a
	/tmp/a
	/tmp/a/kX
	/tmp/a/kX/xB
	/tmp/a/kX/xB/kXxBgilLlXi4SJHY9JoWnmJAtRoO5oE084UXV6TsQ20.mft
	/tmp/a/mft
	/tmp/a/mft/rpki.ripe.net
	/tmp/a/mft/rpki.ripe.net/repository
	/tmp/a/mft/rpki.ripe.net/repository/ripe-ncc-ta.mft

# STANDARDS

*On the Use of the CMS Signing-Time Attribute in RPKI Signed Objects*,
[RFC 9589](http://www.rfc-editor.org/rfc/rfc9589.html).

*Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile*,
[RFC 5280](http://www.rfc-editor.org/rfc/rfc5280.html).

*Cryptographic Message Syntax (CMS)*,
[RFC 5652](http://www.rfc-editor.org/rfc/rfc5652.html).

*A Profile for X.509 PKIX Resource Certificates*,
[RFC 6487](http://www.rfc-editor.org/rfc/rfc6487.html).

# AUTHORS

Job Snijders &lt;[job@openbsd.org](mailto:job@openbsd.org)&gt;

OpenBSD 7.7 - April 10, 2025
