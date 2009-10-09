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
# instdso.sh - install Apache DSO modules
#
# we use this instead of libtool --install because:
# 1) on a few platforms libtool doesn't install DSOs exactly like we'd
#    want (weird names, doesn't remove DSO first)
# 2) we never want the .la files copied, so we might as well copy
#    the .so files ourselves

if test "$#" != "3"; then
    echo "wrong number of arguments to instdso.sh"
    echo "Usage: instdso.sh SH_LIBTOOL-value dso-name path-to-modules"
    exit 1
fi

SH_LIBTOOL=`echo $1 | sed -e 's/^SH_LIBTOOL=//'`
DSOARCHIVE=$2
DSOARCHIVE_BASENAME=`basename $2`
TARGETDIR=$3
DSOBASE=`echo $DSOARCHIVE_BASENAME | sed -e 's/\.la$//'`
TARGET_NAME="$DSOBASE.so"

SYS=`uname -s`

if test "$SYS" = "AIX"
then
    # on AIX, shared libraries remain in storage even when
    # all processes using them have exited; standard practice
    # prior to installing a shared library is to rm -f first
    CMD="rm -f $TARGETDIR/$TARGET_NAME"
    echo $CMD
    $CMD || exit $?
fi

type install >/dev/null 2>&1 && INSTALL_CMD=install || INSTALL_CMD=cp
CMD="$SH_LIBTOOL --mode=install $INSTALL_CMD $DSOARCHIVE $TARGETDIR/"
echo $CMD
$CMD || exit $?

if test "$SYS" = "OS/2"
then
    # on OS/2, aplibtool --install doesn't copy the .la files & we can't
    # rename DLLs to have a .so extension or they won't load so none of the 
    # steps below make sense.
    exit 0
fi

if test -s "$TARGETDIR/$DSOARCHIVE_BASENAME"
then
  DLNAME=`sed -n "/^dlname=/{s/.*='\([^']*\)'/\1/;p;}" $TARGETDIR/$DSOARCHIVE_BASENAME`
  LIBRARY_NAMES=`sed -n "/^library_names/{s/library_names='\([^']*\)'/\1/;p;}" $TARGETDIR/$DSOARCHIVE_BASENAME`
  LIBRARY_NAMES=`echo $LIBRARY_NAMES | sed -e "s/ *$DLNAME//g"`
fi

if test -z "$DLNAME"
then
  echo "Warning!  dlname not found in $TARGETDIR/$DSOARCHIVE_BASENAME."
  echo "Assuming installing a .so rather than a libtool archive."
  exit 0
fi

if test -n "$LIBRARY_NAMES"
then
    for f in $LIBRARY_NAMES
    do
        rm -f $TARGETDIR/$f
    done
fi

if test "$DLNAME" != "$TARGET_NAME"
then
    mv $TARGETDIR/$DLNAME $TARGETDIR/$TARGET_NAME
fi

rm -f $TARGETDIR/$DSOARCHIVE_BASENAME
rm -f $TARGETDIR/$DSOBASE.a
rm -f $TARGETDIR/lib$DSOBASE.a
rm -f $TARGETDIR/lib$TARGET_NAME

exit 0
