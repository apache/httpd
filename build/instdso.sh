#!/bin/sh
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

CMD="$SH_LIBTOOL --mode=install cp $DSOARCHIVE $TARGETDIR/"
echo $CMD
$CMD || exit $?

if test "$SYS" = "OS/2"
then
    # on OS/2, aplibtool --install doesn't copy the .la files & we can't
    # rename DLLs to have a .so extension or they won't load so none of the 
    # steps below make sense.
    exit 0
fi

DLNAME=`grep "^dlname" $TARGETDIR/$DSOARCHIVE_BASENAME | sed -e "s/dlname='\([^']*\)'/\1/"`
LIBRARY_NAMES=`grep "library_names" $TARGETDIR/$DSOARCHIVE_BASENAME | sed -e "s/dlname='\([^']*\)'/\1/"`
LIBRARY_NAMES=`echo $LIBRARY_NAMES | sed -e "s/ *$DLNAME//g"`

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
