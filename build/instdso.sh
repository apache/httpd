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
TARGETDIR=$3
DSOBASE=`echo $DSOARCHIVE | sed -e 's/\.la$//'`
TARGET_NAME="$DSOBASE.so"

SYS=`uname -s`
case $SYS in
    AIX)
        # on AIX, shared libraries remain in storage even when
        # all processes using them have exited; standard practice
        # prior to installing a shared library is to rm -f first
        CMD="rm -f $TARGETDIR/$TARGET_NAME"
        echo $CMD
        $CMD || exit $?
        CMD="cp .libs/lib$DSOBASE.so.0 $TARGETDIR/$TARGET_NAME"
        echo $CMD
        $CMD || exit $?
        ;;
    HP-UX)
        CMD="cp .libs/$DSOBASE.sl $TARGETDIR/$TARGET_NAME"
        echo $CMD
        $CMD || exit $?
        ;;
    OSF1)
        CMD="cp .libs/lib$DSOBASE.so $TARGETDIR/$TARGET_NAME"
        echo $CMD
        $CMD || exit $?
        ;;
    OS/2|OS/390)
        CMD="$SH_LIBTOOL --mode=install cp $DSOARCHIVE $TARGETDIR/"
        echo $CMD
        $CMD || exit $?
        ;;
    *)
        CMD="cp .libs/$TARGET_NAME $TARGETDIR/$TARGET_NAME"
        echo $CMD
        $CMD || exit $?
        ;;
esac

exit 0
