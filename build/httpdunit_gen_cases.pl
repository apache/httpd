#! /usr/bin/env perl

#
# Generates a list of test cases to be pulled into the httpdunit main test
# suite.
#
# Supply all the test cases' source file contents on stdin; the resulting code
# will be printed to stdout. Normally you will want to call this twice: once
# with --declaration to print the function declarations of all the test cases,
# and once without any options to produce the code that actually adds each test
# case to the main suite.
#

use strict;
use warnings;

use Getopt::Long;

my $print_declaration = 0;

GetOptions("declaration" => \$print_declaration)
    or die("unknown option");

while (my $line = <>) {
    if ($line =~ /^HTTPD_BEGIN_TEST_CASE(?:\w+)?\((\w+)/) {
        my $name = "$1_test_case";

        if ($print_declaration) {
            print "TCase *$name(void);\n";
        } else {
            print "suite_add_tcase(suite, $name());\n";
        }
    }
}
