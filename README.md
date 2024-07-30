RPKITOUCH(8) - System Manager's Manual

# NAME

**rpkitouch** - set file modification times to internal RPKI timestamps

# SYNOPSIS

**rpkitouch**
\[**-hnVv**]
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
*Autonomous System Provider Authorization* (ASPA),
*Ghostbuster Records* (GBR),
*Manifests* (MFT),
*Route Origin Authorization* (ROA)
*Signed Prefix Lists* (SPL)
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

**-h**

> Display usage.

**-n**

> No-op.
> The file's modification time is computed but not set.
> Can be combined with
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
package.

# EXIT STATUS

The **rpkitouch** utility exits&#160;0 on success, and&#160;&gt;0 if an error occurs.

# EXAMPLES

Recursively set all data modification times of all files in a given directory
hierarchy to their respective
*RPKI*
derived timestamps:

	$ cd /usr/share/rpki/publication/
	$ find . -type f -exec rpkitouch {} \+

# STANDARDS

*On the Use of the CMS Signing-Time Attribute in RPKI Signed Objects*,
RFC 9589.

*Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile*,
RFC 5280.

*Cryptographic Message Syntax (CMS)*,
RFC 5652.

*A Profile for X.509 PKIX Resource Certificates*,
RFC 6487.

# AUTHORS

Job Snijders &lt;[job@fastly.com](mailto:job@fastly.com)&gt;

OpenBSD 7.5 - July 30, 2024
