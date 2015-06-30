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
echo "curl POST on: $@"

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

# just a check that things are working
curl_post_data upload.py $GEN/data-1k "file upload via http/1.1" --http1.1

# on curl 7.40.0 and earlier, there will be a delay before the upload
# commences. Fix is underway, thanks @badger!
# Caveat: on h2c, the connection will not be upgraded, since curl sends
# the POST as first request and mod_h2 does not upgrade on requests with
# content. Currently we have no means to check that his is happening.
# on curl 7.41.0 and earlier, the transfer of the upload data will be
# extremely slow. Fix will be in 7.42.0, thanks @bagder!
#
# disable until 7.42.0 arrives....
#curl_post_data upload.py $GEN/data-1k "1k file upload via http/2" --http2
#curl_post_data upload.py $GEN/data-10k "10k file upload via http/2" --http2
#curl_post_data upload.py $GEN/data-100k "100k file upload via http/2" --http2
#curl_post_data upload.py $GEN/data-1m "1m file upload via http/2" --http2





