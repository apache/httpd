#!/bin/sh
##
##  ppl.sh -- pretty print a colon-sperarated list by avoiding 
##            `tr' and `fmt' because these tools are different
##            between Unix platforms
##
##  Written by Ralf S. Engelschall <rse@apache.org>
##  for pretty printing lists in the --help option of
##  Apache's Autoconf-style Interface (APACI)
##
#
# This script falls under the Apache License.
# See http://www.apache.org/docs/LICENSE


list=`
IFS=:
for entry in $*; do
    if [ ".$entry" != . ]; then
        echo $entry
    fi
done |\
sort |\
awk '
    BEGIN { list = ""; n = 0; }
    { 
        list = list $1;
        n = n + 1;
        if (n == 1 || n == 2) {
            list = list ":";
        }
        if (n == 3) {
            list = list "\n";
            n = 0;
        }
    }
    END { print list; }
'`
IFS='
'
for entry in $list; do
    echo $entry |\
    awk -F: '
        { printf("%-15s %-15s %-15s\n", $1, $2, $3); }
    '
done |\
awk '{ 
    if (length($0) > 48) { 
        printf("%s\n", substr($0, 0, 47));
    } else { 
        print $0; 
    }
}' |\
sed -e 's/^/                        [/' -e 's/$/]/'

