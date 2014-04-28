#!/bin/bash
#
# This script builds mod_ssl.so for Apache 2.2.x, with SSL NPN
# support.
#
# NPN is not yet supported in Apache HTTPD mod_ssl. A patch has been
# submitted to Apache to enable NPN in mod_ssl:
# https://issues.apache.org/bugzilla/show_bug.cgi?id=52210
#
# Thus, we download the 1.0.1 release of OpenSSL and the most recent
# release of Apache 2.2, and apply a patch to enable NPN support in
# Apache mod_ssl.
#
# We currently statically link OpenSSL with mod_ssl, which results in
# a large (several megabyte) mod_ssl.so. If you prefer, you can
# install NPN-enabled OpenSSL as a shared library system-wide, by
# building OpenSSL like so:
#
# ./config shared -fPIC  # -fPIC is only needed on some architectures
# make
# sudo make install
#
# And Apache like so (after applying the NPN patch):
#
# ./configure --enable-ssl=shared
# make

MODSSL_SO_DESTPATH=$(pwd)/mod_ssl.so

if [ -f $MODSSL_SO_DESTPATH ]; then
  echo "mod_ssl already exists at $MODSSL_SO_DESTPATH. Please remove."
  exit 1
fi

if [ -z "$BUILDROOT" ]; then
  BUILDROOT=$(mktemp -d)
  REMOVE_BUILDROOT=1
else
  REMOVE_BUILDROOT=0
fi

if [ ! -d "$BUILDROOT" ]; then
  echo "Not a directory: $BUILDROOT"
  exit 1
fi

# Convert BUILDROOT to an absolute path.
BUILDROOT="$(cd $(dirname $BUILDROOT); pwd)/$(basename $BUILDROOT)"
echo "Using buildroot: $BUILDROOT"
echo ""

function do_cleanup {
  echo ""
  echo "Build aborted."
  if [ $REMOVE_BUILDROOT -eq 1 ]; then
    echo -n "Cleaning up ... "
    rm -rf "$BUILDROOT"
    echo "done"
  fi
  exit 1
}

trap 'do_cleanup' SIGINT SIGTERM

PROGRESS_DIR=$BUILDROOT/progress
mkdir -p $PROGRESS_DIR
if [ $? -ne 0 ]; then
  do_cleanup
fi

function download_file {
  if [ ! -f "$PROGRESS_DIR/$2.downloaded" ]; then
    echo "Downloading $1"
    curl -f -# "$1" -o $2 || do_cleanup
    if [[ $(md5sum $2 | cut -d\  -f1) != $3 ]]; then
      echo "md5sum mismatch for $2"
      do_cleanup
    fi
    touch "$PROGRESS_DIR/$2.downloaded"
  else
    echo "Already downloaded $1"
  fi
}

function uncompress_file {
  if [ ! -f "$PROGRESS_DIR/$1.uncompressed" ]; then
    echo -n "Uncompressing $1 ... "
    tar xzf $1 || do_cleanup
    echo "done"
    touch "$PROGRESS_DIR/$1.uncompressed"
  else
    echo "Already uncompressed $1"
  fi
}

OPENSSL_SRC_TGZ_URL="https://www.openssl.org/source/openssl-1.0.1g.tar.gz"
APACHE_HTTPD_SRC_TGZ_URL="https://archive.apache.org/dist/httpd/httpd-2.2.27.tar.gz"
APACHE_HTTPD_MODSSL_NPN_PATCH_PATH="$(dirname $0)/scripts/mod_ssl_with_npn.patch"

OPENSSL_SRC_TGZ=$(basename $OPENSSL_SRC_TGZ_URL)
APACHE_HTTPD_SRC_TGZ=$(basename $APACHE_HTTPD_SRC_TGZ_URL)
APACHE_HTTPD_MODSSL_NPN_PATCH="mod_ssl_npn.patch"

OPENSSL_SRC_ROOT=${OPENSSL_SRC_TGZ%.tar.gz}
OPENSSL_INST_ROOT=${OPENSSL_SRC_ROOT}_install
APACHE_HTTPD_SRC_ROOT=${APACHE_HTTPD_SRC_TGZ%.tar.gz}

OPENSSL_BUILDLOG=$(mktemp -p /tmp openssl_buildlog.XXXXXXXXXX)
APACHE_HTTPD_BUILDLOG=$(mktemp -p /tmp httpd_buildlog.XXXXXXXXXX)

cp $APACHE_HTTPD_MODSSL_NPN_PATCH_PATH $BUILDROOT/$APACHE_HTTPD_MODSSL_NPN_PATCH

pushd $BUILDROOT >/dev/null

download_file $OPENSSL_SRC_TGZ_URL $OPENSSL_SRC_TGZ de62b43dfcd858e66a74bee1c834e959
download_file $APACHE_HTTPD_SRC_TGZ_URL $APACHE_HTTPD_SRC_TGZ 148eb08e731916a43a33a6ffa25f17c0

echo ""

uncompress_file $OPENSSL_SRC_TGZ
uncompress_file $APACHE_HTTPD_SRC_TGZ

if [ ! -f "$PROGRESS_DIR/modssl_patched" ]; then
  pushd $APACHE_HTTPD_SRC_ROOT >/dev/null
  echo "Applying Apache mod_ssl NPN patch ... "
  patch -p0 < $BUILDROOT/$APACHE_HTTPD_MODSSL_NPN_PATCH
  if [ $? -ne 0 ]; then
    echo "Failed to patch."
    do_cleanup
  fi
  echo "done"
  popd >/dev/null  # $APACHE_HTTPD_SRC_ROOT
  touch "$PROGRESS_DIR/modssl_patched"
else
  echo "Already applied Apache mod_ssl NPN patch."
fi

echo ""

if [ ! -f "$PROGRESS_DIR/openssl_configured" ]; then
  pushd $OPENSSL_SRC_ROOT >/dev/null
  echo -n "Configuring OpenSSL ... "
  ./config no-shared -fPIC --openssldir=$BUILDROOT/$OPENSSL_INST_ROOT >> $OPENSSL_BUILDLOG
  if [ $? -ne 0 ]; then
    echo "Failed. Build log at $OPENSSL_BUILDLOG."
    do_cleanup
  fi
  echo "done"
  popd >/dev/null  # $OPENSSL_SRC_ROOT
  touch "$PROGRESS_DIR/openssl_configured"
else
  echo "Already configured OpenSSL."
fi

if [ ! -f "$PROGRESS_DIR/openssl_built" ]; then
  pushd $OPENSSL_SRC_ROOT >/dev/null
  echo -n "Building OpenSSL (this may take a while) ... "
  make install >> $OPENSSL_BUILDLOG 2>&1
  if [ $? -ne 0 ]; then
    echo "Failed. Build log at $OPENSSL_BUILDLOG."
    do_cleanup
  fi
  # A hacky fix that helps things build on CentOS:
  if grep -q CentOS /etc/issue; then
    sed --in-place 's/^Libs\.private: -ldl$/& -lcrypto/' \
      $BUILDROOT/$OPENSSL_INST_ROOT/lib/pkgconfig/openssl.pc
  fi
  echo "done"
  popd >/dev/null  # $OPENSSL_SRC_ROOT
  touch "$PROGRESS_DIR/openssl_built"
else
  echo "Already built OpenSSL."
fi

rm -f "$OPENSSL_BUILDLOG"

echo ""

if [ ! -f "$PROGRESS_DIR/modssl_configured" ]; then
  pushd $APACHE_HTTPD_SRC_ROOT >/dev/null
  echo -n "Configuring Apache mod_ssl ... "

  # OpenSSL, as of version 1.0.1, changed its pkg-config file to list
  # its dependent libraries in Libs.private. Prior to this, dependent
  # libraries were listed in Libs. This change in 1.0.1 is the right
  # thing for OpenSSL, but it breaks the Apache 2.2.x configure when
  # linking statically against OpenSSL, since it assumes that all
  # dependent libs are provided in the pkg config Libs directive. We
  # run a search-replace on the configure script to tell it to include
  # not only libraries in Libs, but also those in Libs.private:
  mv configure configure.bak
  sed 's/--libs-only-l openssl/--libs-only-l --static openssl/' configure.bak > configure
  chmod --reference=configure.bak configure

  ./configure --enable-ssl=shared --with-ssl=$BUILDROOT/$OPENSSL_INST_ROOT >> $APACHE_HTTPD_BUILDLOG
  if [ $? -ne 0 ]; then
    echo "Failed. Build log at $APACHE_HTTPD_BUILDLOG."
    do_cleanup
  fi
  echo "done"
  popd >/dev/null  # $APACHE_HTTPD_SRC_ROOT
  touch "$PROGRESS_DIR/modssl_configured"
else
  echo "Already configured Apache mod_ssl."
fi

if [ ! -f "$PROGRESS_DIR/modssl_built" ]; then
  pushd $APACHE_HTTPD_SRC_ROOT >/dev/null
  echo -n "Building Apache mod_ssl (this may take a while) ... "
  make >> $APACHE_HTTPD_BUILDLOG 2>&1
  if [ $? -ne 0 ]; then
    echo "Failed. Build log at $APACHE_HTTPD_BUILDLOG."
    do_cleanup
  fi
  echo "done"
  popd >/dev/null  # $APACHE_HTTPD_SRC_ROOT
  touch "$PROGRESS_DIR/modssl_built"
else
  echo "Already built Apache mod_ssl."
fi

rm -f "$APACHE_HTTPD_BUILDLOG"

popd >/dev/null  # $BUILDROOT

MODSSL_SO_SRCPATH=$(find $BUILDROOT/$APACHE_HTTPD_SRC_ROOT -name mod_ssl.so)
if [ $(echo $MODSSL_SO_SRCPATH | wc -l) -ne 1 ]; then
  echo "Found multiple mod_ssl.so's:"
  echo $MODSSL_SO_SRCPATH
  do_cleanup
fi

cp $MODSSL_SO_SRCPATH $MODSSL_SO_DESTPATH

if [ $REMOVE_BUILDROOT -eq 1 ]; then
  rm -rf "$BUILDROOT"
fi

echo ""
echo "Generated mod_ssl.so at $MODSSL_SO_DESTPATH."
