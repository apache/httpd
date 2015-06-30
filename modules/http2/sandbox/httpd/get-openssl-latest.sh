#!/bin/sh

#  get-openssl-latest.sh
#  mod-h2
#
#  Created by Stefan Eissing on 24.03.15.
#  Inspects the given URL for redirects and downloads tar file
#  to real name. Symlinks given tar name to real name

URL=$1
DESTDIR=$2

usage() {
    echo "$@"
    echo "usage: $(basename $0) url dir"
    echo "  download and extract latest openssl url to given directory,"
    echo "  using real version name and symlinks"
    exit 2
}

fail() {
    echo "$@"
    exit 1
}

[ -z "$URL" ] && usage "url parameter missing"
[ -z "$DESTDIR" ] && usage "dir parameter missing"

GEN=$(dirname "$DESTDIR")
[ -d "$GEN" ] || fail "destination dir $GEN does not exist"

curl -s -D "$GEN"/xxx-header $URL > "$GEN"/xxx-content || fail "error downloading $URL"
REAL_URL=$( fgrep -i location: < "$GEN"/xxx-header | sed s',.*: ,,' | tr -d '\r\n' )

case "$REAL_URL" in
    */var/www/*)
        # currently openssl returns the wrong path - yet the correct tar name
        REAL_TAR=$(basename $REAL_URL)
        REAL_URL=$(dirname $URL)/$REAL_TAR
        ;;
    *)
        REAL_TAR=$(basename $REAL_URL)
        ;;
esac

echo "downloading latest openssl from $REAL_URL"

REAL_DIR=$(basename $REAL_TAR .tar.gz)
rm -f "$GEN/$REAL_TAR" "$DESTDIR" "$GEN"/xxx-header "$GEN"/xxx-content

curl -'#' "$REAL_URL" > "$GEN/$REAL_TAR" || fail "error downloading $REAL_URL"
(cd "$GEN" && tar xfz "$REAL_TAR") || fail "error extracting $GEN/$REAL_TAR"
[ -d "$GEN/$REAL_DIR" ] || fail "expected directory $GEN/$REAL_DIR"
(cd $GEN && ln -s "$REAL_DIR" $(basename $DESTDIR))

