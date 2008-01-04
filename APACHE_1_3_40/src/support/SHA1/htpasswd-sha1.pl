#!/usr/bin/perl -w
use strict;
#
# Utility which takes a username and password
# on the command line and generates a username
# sha1-encrytped password on the stdout.
# 
# Typical useage:
# 	./htpasswd-sha1.pl dirkx MySecret >> sha1-passwd
#
# This is public domain code.  Do whatever you want with it.
# It was originally included in Clinton Wong's Apache 1.3.6 SHA1/ldif
# patch distribution as sample code for generating entries for
# Apache password files using SHA1.

use MIME::Base64;  # http://www.cpan.org/modules/by-module/MIME/
use Digest::SHA1;  # http://www.cpan.org/modules/by-module/MD5/

if ($#ARGV!=1) { die "Usage $0: user password\n" }

print $ARGV[0], ':{SHA}', encode_base64( Digest::SHA1::sha1($ARGV[1]) );

