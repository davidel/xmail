#!/usr/bin/perl -w
#
# Used to regenerate ca-bundle.crt from the Mozilla certdata.txt.
# Run as ./mkcabundle.pl > ca-bundle.crt
#

my $cert_url = 'https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt';

open(IN, "curl $cert_url|")
    || die "could not fetch certificate data: $cert_url";

my $incert = 0;

print<<EOH;
# This is a bundle of X.509 certificates of public Certificate
# Authorities.  It was generated from the Mozilla root CA list.
#
# Source: $certdata
#
EOH
    ;

while (<IN>) {
    if (/^CKA_VALUE MULTILINE_OCTAL/) {
	$incert = 1;
	open(OUT, "|openssl x509 -text -inform DER -fingerprint")
	    || die "could not pipe to openssl x509";
    } elsif (/^END/ && $incert) {
	close(OUT);
	$incert = 0;
	print "\n\n";
    } elsif ($incert) {
	my @bs = split(/\\/);
	foreach my $b (@bs) {
	    chomp $b;
	    printf(OUT "%c", oct($b)) unless $b eq '';
	}
    } elsif (/^CVS_ID.*Revision: ([^ ]*).*/) {
	print "# Generated from certdata.txt RCS revision $1\n#\n";
    }
}
