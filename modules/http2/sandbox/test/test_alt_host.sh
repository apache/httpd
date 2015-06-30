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
echo "alt host access: $@"

################################################################################
# check access to other hosts on same connection
################################################################################

# The correct answer is 421 and mod_h2 will created if once the SSL parse 
# request filter is no longer strict on SNI name checking. See
# https://bz.apache.org/bugzilla/show_bug.cgi?id=58007#c9
#
MISDIR_STATUS="421 Misdirected Request"
#MISDIR_STATUS="400 Bad Request"

nghttp_check_content index.html "noh2 host" -H'Host: noh2.example.org' <<EOF
[ERROR] HTTP/2 protocol was not selected. (nghttp2 expects h2)
Some requests were not processed. total=1, processed=0
EOF

curl_check_content index.html "noh2 host" -H'Host: noh2.example.org' <<EOF
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>$MISDIR_STATUS</title>
</head><body>
<h1>Misdirected Request</h1>
<p>The client needs to use a new connection for this 
request as it does not match the SNI name used.</p>
</body></html>
EOF

