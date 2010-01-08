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
#  ppl.sh -- pretty print a colon-sperarated list by avoiding 
#            `tr' and `fmt' because these tools are different
#            between Unix platforms
#
#  Initially written by Ralf S. Engelschall <rse apache.org>
#  for pretty printing lists in the --help option of
#  Apache's Autoconf-style Interface (APACI)

list=`
IFS=:
for entry in $*; do
    if [ "x$entry" != "x" ]; then
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

