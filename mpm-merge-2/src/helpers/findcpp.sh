#!/bin/sh
##
##  findcpp.sh -- Find out how to _directly_ run the C Pre-Processor (CPP)
##  Initially written by Ralf S. Engelschall for the Apache configuration
##   mechanism
##
#
# This script falls under the Apache License.
# See http://www.apache.org/docs/LICENSE


#   create a test C source:
#   - has to use extension ".c" because some CPP only accept this one
#   - uses assert.h because this is a standard header and harmless to include
#   - contains a Syntax Error to make sure it passes only the preprocessor
#     but not the real compiler pass
cat >conftest.c <<EOF
#include <assert.h>
Syntax Error
EOF

#   some braindead systems have a CPP define for a directory :-(
if [ "x$CPP" != "x" ]; then
    if [ -d "$CPP" ]; then
        CPP=''
    fi
fi
if [ "x$CPP" != "x" ]; then
    #   case 1: user provided a default CPP variable (we only check)
    (eval "$CPP conftest.c >/dev/null") 2>conftest.out
    my_error=`grep -v '^ *+' conftest.out`
    if [ "x$my_error" != "x" ]; then
        CPP=''
    fi
else
    #   case 2: no default CPP variable (we have to find one)
    #   1. try the standard -E option
    CPP="${CC-cc} -E"
    (eval "$CPP conftest.c >/dev/null") 2>conftest.out
    my_error=`grep -v '^ *+' conftest.out`
    if [ "x$my_error" != "x" ]; then
        #   2. try the -E option and GCC's -traditional-ccp option
        CPP="${CC-cc} -E -traditional-cpp"
        (eval "$CPP conftest.c >/dev/null") 2>conftest.out
        my_error=`grep -v '^ *+' conftest.out`
        if [ "x$my_error" != "x" ]; then
            #   3. try a standalone cpp command in $PATH and lib dirs
            CPP="`./helpers/PrintPath cpp`"
            if [ "x$CPP" = "x" ]; then
                CPP="`./helpers/PrintPath -p/lib:/usr/lib:/usr/local/lib cpp`"
            fi
            if [ "x$CPP" != "x" ]; then
                (eval "$CPP conftest.c >/dev/null") 2>conftest.out
                my_error=`grep -v '^ *+' conftest.out`
                if [ "x$my_error" != "x" ]; then
                    #   ok, we gave up...
                    CPP=''
                fi
            fi
        fi
    fi
fi

#   cleanup after work
rm -f conftest.*

#   Ok, empty CPP variable now means it's not available
if [ "x$CPP" = "x" ]; then
    CPP='NOT-AVAILABLE'
fi

echo $CPP

