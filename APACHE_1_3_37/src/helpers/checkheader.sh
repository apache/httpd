#!/bin/sh
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#
#  checkheader.sh -- Check whether a C header file exists
#  Initially written by Ralf S. Engelschall for the Apache
#   configuration mechanism

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
    
