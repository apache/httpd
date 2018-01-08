#! /usr/bin/env perl

#
# Generates a code stub that adds unit tests to a Check test case.
#
# Supply the test case's source file contents on stdin; the resulting code will
# be printed to stdout. This code is designed to be included as part of the
# boilerplate at the end of each test case.
#

use strict;
use warnings;

while (my $line = <>) {
    # FIXME: this does not correctly handle macro invocations that are split
    # over multiple lines.
    if ($line =~ /^HTTPD_START_LOOP_TEST\((\w+),(.*)\)/) {
        print "tcase_add_loop_test(testcase, $1, 0, ($2));\n";
    } elsif ($line =~ /^START_TEST\((\w+)\)/) {
        print "tcase_add_test(testcase, $1);\n"
    }
}
