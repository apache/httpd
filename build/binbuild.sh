#!/bin/sh
#
# binbuild.sh - Builds an Apache binary distribution.
# Initially written by Lars Eilebrecht <lars@apache.org>.
#
# This script falls under the Apache License.
# See http://www.apache.org/docs/LICENSE

OS=`./build/config.guess`
PRINTPATH="build/PrintPath"
APFULLDIR=`pwd`
BUILD_DIR="$APFULLDIR/bindist"
DEFAULT_DIR="/usr/local/apache2"
APDIR="$APFULLDIR"
APDIR=`basename $APDIR`
CONFIGPARAM="--enable-layout=Apache --prefix=$BUILD_DIR --enable-mods-shared=most --with-expat=$APFULLDIR/srclib/apr-util/xml/expat --enable-static-support"
VER=`echo $APDIR | sed s/httpd-//`
TAR="`$PRINTPATH tar`"
GZIP="`$PRINTPATH gzip`"
COMPRESS="`$PRINTPATH compress`"
MD5="`$PRINTPATH md5`"
if [ x$MD5 = x ]; then
  OPENSSL="`$PRINTPATH openssl`"
  if [ x$OPENSSL != x ]; then
    MD5="$OPENSSL md5"
  fi
fi

if [ x$1 != x ]; then
  USER=$1
else
  USER="`build/buildinfo.sh -n %u@%h%d`"
fi

if [ ! -f ./ABOUT_APACHE ]; then
  echo "ERROR: The current directory contains no valid Apache distribution."
  echo "Please change the directory to the top level directory of a freshly"
  echo "unpacked Apache 2.0 source distribution and re-execute the script"
  echo "'./build/binbuild.sh'." 
  exit 1;
fi

if [ -d ./CVS ]; then
  echo "ERROR: The current directory is a CVS checkout of Apache."
  echo "Only a standard Apache 2.0 source distribution should be used to"
  echo "create a binary distribution."
  exit 1;
fi

echo "Building Apache $VER binary distribution..."
echo "Platform is \"$OS\"..."

( echo "Build log for Apache binary distribution" && \
  echo "----------------------------------------------------------------------" && \
  ./configure $CONFIGPARAM && \
  echo "----------------------------------------------------------------------" && \
  make clean && \
  rm -rf bindist install-bindist.sh *.bindist
  echo "----------------------------------------------------------------------" && \
  make && \
  echo "----------------------------------------------------------------------" && \
  make install root="bindist/" && \
  echo "----------------------------------------------------------------------" && \
  make clean && \
  echo "----------------------------------------------------------------------" && \
  echo "[EOF]" \
) 2>&1 | tee build.log

if [ ! -f ./bindist/bin/httpd ]; then
  echo "ERROR: Failed to build Apache. See \"build.log\" for details."
  exit 1;
fi

echo "Binary image successfully created..."

./bindist/bin/httpd -v

echo "Creating supplementary files..."

( echo " " && \
  echo "Apache $VER binary distribution" && \
  echo "================================" && \
  echo " " && \
  echo "This binary distribution is usable on a \"$OS\"" && \
  echo "system and was built by \"$USER\"." && \
  echo "" && \
  echo "The distribution contains all standard Apache modules as shared" && \
  echo "objects. This allows you to enable or disable particular modules" && \
  echo "with the LoadModule/AddModule directives in the configuration file" && \
  echo "without the need to re-compile Apache." && \
  echo "" && \
  echo "See \"INSTALL.bindist\" on how to install the distribution." && \
  echo " " && \
  echo "NOTE: Please do not send support-related mails to the address mentioned" && \
  echo "      above or to any member of the Apache Group! Support questions" && \
  echo "      should be directed to the forums mentioned at" && \
  echo "      http://httpd.apache.org/lists.html#http-users" && \
  echo "      where some of the Apache team lurk, in the company of many other" && \
  echo "      Apache gurus who should be able to help." && \
  echo "      If you think you found a bug in Apache or have a suggestion please" && \
  echo "      visit the bug report page at http://httpd.apache.org/bug_report.html" && \
  echo " " && \
  echo "----------------------------------------------------------------------" && \
  ./bindist/bin/httpd -V && \
  echo "----------------------------------------------------------------------" \
) > README.bindist
cp README.bindist ../httpd-$VER-$OS.README

( echo " " && \
  echo "Apache $VER binary installation" && \
  echo "================================" && \
  echo " " && \
  echo "To install this binary distribution you have to execute the installation" && \
  echo "script \"install-bindist.sh\" in the top-level directory of the distribution." && \
  echo " " && \
  echo "The script takes the ServerRoot directory into which you want to install" && \
  echo "Apache as an option. If you omit the option the default path" && \
  echo "\"$DEFAULT_DIR\" is used." && \
  echo "Make sure you have write permissions in the target directory, e.g. switch" && \
  echo "to user \"root\" before you execute the script." && \
  echo " " && \
  echo "See \"README.bindist\" for further details about this distribution." && \
  echo " " && \
  echo "Please note that this distribution includes the complete Apache source code." && \
  echo "Therefore you may compile Apache yourself at any time if you have a compiler" && \
  echo "installation on your system." && \
  echo "See \"INSTALL\" for details on how to accomplish this." && \
  echo " " \
) > INSTALL.bindist

sed -e "s%\@default_dir\@%$DEFAULT_DIR%" \
    -e "s%\@ver\@%$VER%" \
    -e "s%\@os\@%$OS%" \
    build/install-bindist.sh.in > install-bindist.sh
    
chmod 755 install-bindist.sh

sed -e "s%$BUILD_DIR%$DEFAULT_DIR%" \
    -e "s%^ServerAdmin.*%ServerAdmin you@your.address%" \
    -e "s%#ServerName.*%#ServerName localhost%" \
    bindist/conf/httpd-std.conf > bindist/conf/httpd.conf
cp bindist/conf/httpd.conf bindist/conf/httpd-std.conf

for one_file in apachectl envvars envvars-std; do
    sed -e "s%$BUILD_DIR%$DEFAULT_DIR%" \
        bindist/bin/$one_file > bindist/bin/$one_file.tmp
    mv bindist/bin/$one_file.tmp bindist/bin/$one_file
done

echo "Creating distribution archive and readme file..."
 
if [ ".`grep -i error build.log > /dev/null`" != . ]; then
  echo "ERROR: Failed to build Apache. See \"build.log\" for details."
  exit 1;
else
  if [ "x$TAR" != "x" ]; then
    case "x$OS" in
      x*os390*) $TAR -cfU ../httpd-$VER-$OS.tar -C .. httpd-$VER;;
      *) (cd .. && $TAR -cf httpd-$VER-$OS.tar httpd-$VER);;
    esac
    if [ "x$GZIP" != "x" ]; then
      $GZIP -9 ../httpd-$VER-$OS.tar
      ARCHIVE=../httpd-$VER-$OS.tar.gz
    elif [ "x$COMPRESS" != "x" ]; then
      $COMPRESS ../httpd-$VER-$OS.tar
      ARCHIVE=../httpd-$VER-$OS.tar.Z
    else
      echo "WARNING: Could not find a 'gzip' program!"
      echo "       tar archive is not compressed."
      ARCHIVE=../httpd-$VER-$OS.tar
    fi
  else
    echo "ERROR: Could not find a 'tar' program!"
    echo "       Please execute the following commands manually:"
    echo "         tar -cf ../httpd-$VER-$OS.tar ."
    echo "         gzip -9 ../httpd-$VER-$OS.tar"
  fi

  if [ "x$MD5" != "x" ]; then
    $MD5 $ARCHIVE > $ARCHIVE.md5
  fi

  if [ -f $ARCHIVE ] && [ -f ../httpd-$VER-$OS.README ]; then
    echo "Ready."
    echo "You can find the binary archive ($ARCHIVE)"
    echo "and the readme file (httpd-$VER-$OS.README) in the"
    echo "parent directory."
    exit 0;
  else
    echo "ERROR: Archive or README is missing."
    exit 1;
  fi
fi
