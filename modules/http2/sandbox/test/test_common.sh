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
#
# common test functions
#

URL_PREFIX="$1"
OPT_DIRECT="$2"
AUTH="${URL_PREFIX#*://}"
HOST="${AUTH%%:*}"
URL_SCHEME="${URL_PREFIX%%:*}"
URL_PATH="/${AUTH#*/}"
if [ "$URL_PATH" = "/$AUTH" ]; then
    URL_PATH=""
fi

INSTALL_DIR="../install"
BIN_DIR="${INSTALL_DIR}/bin"
if [ "${HOST#*.}" = 'example.org' ]; then
    DOC_ROOT="htdocs/test.example.org"
else 
    DOC_ROOT="htdocs/${HOST}"
fi

GEN="gen"
TMP="$GEN/tmp"

CURL="${BIN_DIR}/curl  -sk --resolv ${HOST#*://}:127.0.0.1"
NGHTTP="${BIN_DIR}/nghttp"


fail() {
    echo "$@"
    exit 1
}

case "$OPT_DIRECT" in
  "direct")
        ARG_UPGRADE=""
        ;;
    *)  
        ARG_UPGRADE=" -u"
        ;;
esac

curl_check_doc() {
    DOC="$1"; shift;
    MSG="$1"; shift;
    ARGS="$@"
    echo -n " * curl /$DOC: $MSG..."
    rm -rf $TMP
    mkdir -p $TMP
    ${CURL} $ARGS $URL_PREFIX/$DOC > $TMP/$DOC 2>&1 || fail
    diff  $DOC_ROOT/$DOC $TMP/$DOC || fail
    echo ok.
}

nghttp_check_doc() {
    DOC="$1"; shift;
    MSG="$1"; shift;
    ARGS="$@"$ARG_UPGRADE
    echo -n " * nghttp /$DOC: $MSG..."
    rm -rf $TMP &&
    mkdir -p $TMP &&
    ${NGHTTP} $ARGS $URL_PREFIX/$DOC > $TMP/$DOC 2>&1 || fail
    diff  $DOC_ROOT/$DOC $TMP/$DOC || fail
    echo ok.
}

nghttp_check_assets() {
    DOC="$1"; shift;
    MSG="$1"; shift;
    ARGS="$@"$ARG_UPGRADE
    echo -n " * nghttp /$DOC: $MSG..."
    rm -rf $TMP &&
    mkdir -p $TMP &&
    sort > $TMP/reference
    ${NGHTTP} -ans $ARGS $URL_PREFIX/$DOC > $TMP/out 2>&1 || fail
    fgrep " /" $TMP/out | while read id begin end dur stat size path; do
        echo "$path $size $stat"
    done | sort > $TMP/output || fail
    diff $TMP/reference $TMP/output  || fail
    echo ok.
}

nghttp_check_content() {
    DOC="$1"; shift;
    MSG="$1"; shift;
    rm -rf $TMP
    mkdir -p $TMP
    cat > $TMP/expected
    echo -n " * nghttp /$DOC: $MSG..."
    ${NGHTTP} "$@" $URL_PREFIX/$DOC > $TMP/$DOC 2>&1 || fail
    diff  $TMP/expected $TMP/$DOC || fail
    echo ok.
}


curl_check_content() {
    DOC="$1"; shift;
    MSG="$1"; shift;
    rm -rf $TMP
    mkdir -p $TMP
    cat > $TMP/expected
    echo -n " * curl /$DOC: $MSG..."
    ${CURL} "$@" $URL_PREFIX/$DOC > $TMP/$DOC 2>&1 || fail
    diff  $TMP/expected $TMP/$DOC || fail
    echo ok.
}

curl_check_redir() {
    DOC="$1"; shift;
    REF_DOC="$1"; shift;
    MSG="$1"; shift;
    ARGS="$@"
    echo -n " * curl redir /$DOC: $MSG..."
    rm -rf $TMP
    mkdir -p $TMP
    ${CURL} -D - $ARGS $URL_PREFIX/$DOC >$TMP/redir.out || fail
    LOCATION=$( fgrep -i 'location:' $TMP/redir.out | sed -e "s,.*$URL_PREFIX/,," | tr -d '\r\n' )
    test "$REF_DOC" != "$LOCATION" && fail "expected redirect to >>>$REF_DOC<<<, found >>>$LOCATION<<<"
    ${CURL} $ARGS $URL_PREFIX/$LOCATION >$TMP/$LOCATION || fail
    diff  $DOC_ROOT/$REF_DOC $TMP/$LOCATION || fail
    echo ok.
}

curl_check_necho() {
    COUNT="$1"; shift;
    TEXT="$1"; shift;
    REF="$1"; shift;
    MSG="$1"; shift;
    ARGS="$@"
    rm -rf $TMP
    mkdir -p $TMP
    echo -n " * curl /necho.py?count=$COUNT&text=$TEXT..."
    ${CURL} $ARGS -F count="$COUNT" -F text="$TEXT" $URL_PREFIX/necho.py > $TMP/echo 2>&1 || fail
    diff  $REF $TMP/echo || fail
    echo ok.
}

curl_post_file() {
    DOC="$1"; shift;
    FILE="$1"; shift;
    MSG="$1"; shift;
    ARGS="$@"
    fname="$(basename $FILE)"
    rm -rf $TMP
    mkdir -p $TMP
    echo -n " * curl /$DOC: $MSG..."
    ${CURL} $ARGS --form file=@"$FILE" $URL_PREFIX/$DOC > $TMP/$DOC 2>&1 || fail "error uploading $fname"
    ${CURL} $ARGS $URL_PREFIX/files/"$fname" > $TMP/data.down 2>&1 || fail "error downloding $fname"
    diff  $FILE $TMP/data.down || fail
    echo ok.
}

curl_post_data() {
    DOC="$1"; shift;
    FILE="$1"; shift;
    MSG="$1"; shift;
    ARGS="$@"
    fname="$(basename $FILE)"
    rm -rf $TMP
    mkdir -p $TMP
    echo -n " * curl /$DOC: $MSG..."
    ${CURL} $ARGS --form file=@"$FILE" $URL_PREFIX/$DOC > $TMP/$DOC 2>&1 || fail
    ${CURL} $ARGS $URL_PREFIX/files/"$fname" > $TMP/data.down 2>&1 || fail
    diff  $FILE $TMP/data.down || fail
    echo ok.
}

nghttp_remove_file() {
    DOC="$1"; shift;
    FILE="$1"; shift;
    MSG="$1"; shift;
    ARGS="$@"$ARG_UPGRADE
    fname="$(basename $FILE)"
    rm -rf $TMP
    mkdir -p $TMP
    cat > $TMP/updata <<EOF
--DSAJKcd9876
Content-Disposition: form-data; name="remove";
Content-Type: text/plain

$fname
--DSAJKcd9876--
EOF
    echo -n " * nghttp /$DOC: rm $fname..."
    ${NGHTTP} -v $ARGS --data=$TMP/updata -H'Content-Type: multipart/form-data; boundary=DSAJKcd9876' $URL_PREFIX/$DOC > $TMP/$DOC || fail "error removing $fname"
    echo ok.
}

nghttp_post_file() {
    DOC="$1"; shift;
    FILE="$1"; shift;
    MSG="$1"; shift;
    ARGS="$@"$ARG_UPGRADE
    fname="$(basename $FILE)"
    rm -rf $TMP
    mkdir -p $TMP
    cat > $TMP/updata <<EOF
--DSAJKcd9876
Content-Disposition: form-data; name="xxx"; filename="xxxxx"
Content-Type: text/plain

testing mod_h2
--DSAJKcd9876
Content-Disposition: form-data; name="file"; filename="$fname"
Content-Type: application/octet-stream
Content-Transfer-Encoding: binary

EOF
    cat $FILE >> $TMP/updata || fail "error reading $FILE"
    echo >> $TMP/updata <<EOF
--DSAJKcd9876--
EOF
    echo -n " * nghttp /$DOC: $MSG..."
    ${NGHTTP} -v $ARGS --data=$TMP/updata -H'Content-Type: multipart/form-data; boundary=DSAJKcd9876' $URL_PREFIX/$DOC > $TMP/$DOC || fail "error uploading $fname"

    ${NGHTTP} $ARG_UPGRADE $URL_PREFIX/files/"$fname" > $TMP/data.down || fail "error downloding $fname"
    diff  $FILE $TMP/data.down || fail
    echo ok.
}

curl_check_altsvc() {
    DOC="$1"; shift;
    EXP_ALT_SVC="$1"; shift;
    MSG="$1"; shift;
    mkdir -p $TMP
    echo -n " * curl check alt_svc at /$DOC..."
    ${CURL} "$@" -D $TMP/headers $URL_PREFIX/$DOC > /dev/null 2>&1 || fail
    alt_svc="$( fgrep -i 'Alt-Svc: ' $TMP/headers | tr -d "\r\n" )"
    alt_svc="${alt_svc#*: }"
    test "$EXP_ALT_SVC" = "$alt_svc" || fail "failed. Expected '$EXP_ALT_SVC', got '$alt_svc'"
    echo ok.
}

