#!/bin/sh
##
##  fmn.sh -- find a modules (structure) name
##
##  Extracted from the Configure script for use with
##  Apache's Autoconf-style Interface (APACI).
##
#
# This script falls under the Apache License.
# See http://www.apache.org/docs/LICENSE


#   input: the modules source file
modfile=$1

#   the part from the Configure script
tmpfile=${TMPDIR-/tmp}/fmn.tmp.$$
rm -f $tmpfile
modname=''
ext=`echo $modfile | sed 's/^.*\.//'`
modbase=`echo $modfile | sed 's/\.[^.]*$//'`
if [ "x$ext" = "x$modfile" ]; then ext=o; modbase=$modfile; modfile=$modbase.o; fi
if [ "x$ext" = "x" ] ; then ext=o; modbase=$modfile; fi
if [ "x$ext" = "xc" ] ; then ext=o; fi
if [ -r $modbase.module ] ; then
    cat $modbase.module >$tmpfile
else
    if [ -f $modbase.c ] ; then
        modname=`egrep '^module .*;' $modbase.c | head -1 |\
                sed 's/^module.*[ 	][ 	]*//' | \
                sed 's/[ 	]*;[ 	]*$//'`
        if grep "MODULE-DEFINITION-" $modbase.c >/dev/null; then
            cat $modbase.c | \
            sed '1,/MODULE-DEFINITION-START/d;/MODULE-DEFINITION-END/,$d' >$tmpfile
        fi
    fi
fi              
if [ -r $tmpfile ] ; then
    modname=`grep "Name:" $tmpfile | sed 's/^.*Name:[ 	]*//'`
fi
if [ "x$modname" = "x" ] ; then
    modname=`echo $modbase | sed 's/^.*\///' | \
        sed 's/^mod_//' | sed 's/^lib//' | sed 's/$/_module/'`
fi
rm -f $tmpfile

#   output: the name of the module structure symbol
echo "$modname"

