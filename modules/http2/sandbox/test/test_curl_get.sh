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
echo "curl GET on: $@"

################################################################################
# check content of resources via different methods
################################################################################
curl_check_doc index.html "default"
curl_check_doc index.html "http/1.1" --http1.1
curl_check_doc index.html "http2"    --http2

################################################################################
# check some redir handling
################################################################################
curl_check_doc xxx-1.0.2a.tar.gz  "http2"  --http2

if [ "$URL_PATH" = "" ]; then
    curl_check_redir latest.tar.gz  xxx-1.0.2a.tar.gz  "http2"  --http2
fi

################################################################################
# check cgi generated content
################################################################################
if [ "$URL_SCHEME" = "https" ]; then
    CONTENT="<html>
<body>
<h2>Hello World!</h2>
SSL_PROTOCOL=TLSv1.2
</body>
</html>"
else
    CONTENT="<html>
<body>
<h2>Hello World!</h2>
SSL_PROTOCOL=
</body>
</html>"
fi

curl_check_content hello.py "default" <<EOF
$CONTENT
EOF

curl_check_content hello.py "http/1.1" --http1.1 <<EOF
$CONTENT
EOF

curl_check_content hello.py "http2"    --http2 <<EOF
$CONTENT
EOF


curl_check_content upload.py "http/1.1" --http1.1 <<EOF
    <html><body>
    <p>        Upload File<form method="POST" enctype="multipart/form-data">
        <input type="file" name="file">
        <button type="submit">Upload</button></form>
        </p>
    </body></html>
EOF

curl_check_content upload.py "http2"    --http2 <<EOF
    <html><body>
    <p>        Upload File<form method="POST" enctype="multipart/form-data">
        <input type="file" name="file">
        <button type="submit">Upload</button></form>
        </p>
    </body></html>
EOF


################################################################################
# check chunked content from cgi
################################################################################

if [ ! -f $GEN/necho-100 ]; then
i=0; while [ $i -lt 10 ]; do
echo "0123456789"
i=$[ i + 1 ]
done > $GEN/necho-100
fi

if [ ! -f $GEN/necho-1k ]; then
i=0; while [ $i -lt 10 ]; do
cat $GEN/necho-100
i=$[ i + 1 ]
done > $GEN/necho-1k
fi

if [ ! -f $GEN/necho-10k ]; then
i=0; while [ $i -lt 10 ]; do
cat $GEN/necho-1k
i=$[ i + 1 ]
done > $GEN/necho-10k
fi

if [ ! -f $GEN/necho-100k ]; then
i=0; while [ $i -lt 10 ]; do
cat $GEN/necho-10k
i=$[ i + 1 ]
done > $GEN/necho-100k
fi

if [ ! -f $GEN/necho-1m ]; then
i=0; while [ $i -lt 10 ]; do
cat $GEN/necho-100k
i=$[ i + 1 ]
done > $GEN/necho-1m
fi

curl_check_necho 10 "0123456789" $GEN/necho-100 "http/2" --http2
curl_check_necho 100 "0123456789" $GEN/necho-1k "http/2" --http2
curl_check_necho 1000 "0123456789" $GEN/necho-10k "http/2" --http2
curl_check_necho 10000 "0123456789" $GEN/necho-100k "http/2" --http2
curl_check_necho 100000 "0123456789" $GEN/necho-1m "http/2" --http2


