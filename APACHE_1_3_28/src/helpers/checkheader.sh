#!/bin/sh
##
##  checkheader.sh -- Check whether a C header file exists
##  Initially written by Ralf S. Engelschall for the Apache
##   configuration mechanism
##
#
# This script falls under the Apache License.
# See http://www.apache.org/docs/LICENSE


header=$1
rc=1
if [ "x$CPP" = "x" ]; then
    CPP='NOT-AVAILABLE'
fi
if [ "x$CPP" != "xNOT-AVAILABLE" ]; then
    #   create a test C source
    cat >conftest.c <<EOF
#include <$header>
Syntax Error
EOF
    (eval "$CPP conftest.c >/dev/null") 2>conftest.out
    my_error=`grep -v '^ *+' conftest.out`
    if [ "x$my_error" = "x" ]; then
        rc=0
    fi
else
    if [ -f "/usr/include/$header" ]; then
        rc=0
    fi
fi
rm -f conftest.*
exit $rc
    
