#!/usr/bin/perl -w
use strict;

# This is public domain code.  Do whatever you want with it.
# It was originally included in Clinton Wong's Apache 1.3.6 SHA1/ldif
# patch distribution as sample code for converting accounts from
# ldif format (as used by Netscape web servers) to Apache password format.

my $uid='';
my $passwd='';

while (my $line = <>) {
  chomp $line;
  if ( $line =~ /uid:\s*(.+)/) { $uid = $1 }
  if ( $line =~ /userpassword:\s*(\{\w+\}.+)/) {
    $passwd = $1;
    $passwd =~ s/^\{crypt\}//i;  # Apache stores crypt without a magic string
  }

  if (length($line)==0) {

    if (length $uid and length $passwd) {
      print $uid, ':', $passwd, "\n";
    } # output if we have something to print

    $uid = '';
    $passwd = '';

  } # if newline
} # while something to read

# handle last entry if there isn't a newline before EOF
    if (length $uid and length $passwd) {
  print $uid, ':', $passwd, "\n";
}

