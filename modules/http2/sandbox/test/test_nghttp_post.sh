#!/bin/bash
# Copyright 2015 greenbytes GmbH (https://www.greenbytes.de)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

source test_common.sh
echo "nghttp POST on: $@"

CHR100="012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678
"

if [ ! -f $GEN/data-1k ]; then
    i=0; while [ $i -lt 10 ]; do
        echo -n "$CHR100"
        i=$[ i + 1 ]
    done > $GEN/data-1k
fi

if [ ! -f $GEN/data-10k ]; then
    i=0; while [ $i -lt 10 ]; do
        cat $GEN/data-1k
        i=$[ i + 1 ]
    done  > $GEN/data-10k
fi

if [ ! -f $GEN/data-100k ]; then
    i=0; while [ $i -lt 10 ]; do
        cat $GEN/data-10k
        i=$[ i + 1 ]
    done > $GEN/data-100k
fi

if [ ! -f $GEN/data-1m ]; then
    i=0; while [ $i -lt 10 ]; do
        cat $GEN/data-100k
        i=$[ i + 1 ]
    done > $GEN/data-1m
fi

# Tests witht the nghttp client that *requires* h2/h2c. Sends "OPTIONS *"
# on h2c which is a good test.
#
nghttp_remove_file upload.py data-1k  "rm data-1k"
nghttp_post_file upload.py $GEN/data-1k   "1k upload"
nghttp_remove_file upload.py data-10k  "rm data-10k"
nghttp_post_file upload.py $GEN/data-10k  "10k upload"
nghttp_remove_file upload.py data-100k  "rm data-100k"
nghttp_post_file upload.py $GEN/data-100k "100k upload"
nghttp_remove_file upload.py data-1m  "rm data-1m"
nghttp_post_file upload.py $GEN/data-1m   "1m upload"

# Tests without content-length announced
nghttp_remove_file upload.py data-1k  "rm data-1k"
nghttp_post_file upload.py $GEN/data-1k   "1k upload w/o c-len" --no-content-length
nghttp_remove_file upload.py data-10k  "rm data-10k"
nghttp_post_file upload.py $GEN/data-10k  "10k upload w/o c-len" --no-content-length
nghttp_remove_file upload.py data-100k  "rm data-100k"
nghttp_post_file upload.py $GEN/data-100k "100k upload w/o c-len" --no-content-length
nghttp_remove_file upload.py data-1m  "rm data-1m"
nghttp_post_file upload.py $GEN/data-1m   "1m upload w/o c-len" --no-content-length




