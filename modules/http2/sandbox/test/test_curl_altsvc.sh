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

HTTP_URL="$1"
HTTPS_URL="$2"

source test_common.sh
echo "curl ALT-SVC on: $@"

URL_PREFIX="$HTTP_URL"
curl_check_altsvc index.html '' --http1.1
curl_check_altsvc index.html '' "http/1.1, signal used"             --http1.1 -H'Alt-Svc-Used: 1'
curl_check_altsvc index.html '' "http/2"                            --http2

URL_PREFIX="$HTTPS_URL"
curl_check_altsvc index.html 'h2=":12346", h2c=":12345", h2="mod-h2.greenbytes.de:12346"' "http/1.1" --http1.1
curl_check_altsvc index.html '' "http/2" --http2
