#!/bin/sh
##
##  mkshadow.sh -- create a shadow tree
##
##  Written by Ralf S. Engelschall <rse@apache.org>
##  for the shadow tree generation option (--shadow) of 
##  Apache's Autoconf-style Interface (APACI) 
##
#
# This script falls under the Apache License.
# See http://www.apache.org/docs/LICENSE


#   default IFS
DIFS=' 	
'

#   source and destination directory
src=`echo $1 | sed -e 's:/$::'`
dst=`echo $2 | sed -e 's:/$::'`

#   check whether source exists
if [ ! -d $src ]; then
    echo "mkshadow.sh:Error: source directory not found" 1>&2
    exit 1
fi

#   determine if one of the paths is an absolute path,
#   because then we have to use an absolute symlink
oneisabs=0
case $src in
    /* ) oneisabs=1 ;;
esac
case $dst in
    /* ) oneisabs=1 ;;
esac

#   determine reverse directory for destination directory
dstrevdir=''
if [ $oneisabs = 0 ]; then
    #   (inlined fp2rp)
    OIFS2="$IFS"; IFS='/'
    for pe in $dst; do
        dstrevdir="../$dstrevdir"
    done
    IFS="$OIFS2"
else
    src="`cd $src; pwd`";
fi

#   create directory tree at destination
if [ ! -d $dst ]; then
    mkdir $dst
fi
DIRS="`cd $src
       find . -type d -print |\
       sed -e '/\/CVS/d' \
           -e '/^\.$/d' \
           -e 's:^\./::'`"
OIFS="$IFS" IFS="$DIFS"
for dir in $DIRS; do
    mkdir $dst/$dir
done
IFS="$OIFS"

#   fill directory tree with symlinks to files
FILES="`cd $src
        find . -depth -print |\
        sed -e '/\.o$/d' \
            -e '/\.a$/d' \
            -e '/\.so$/d' \
            -e '/\.so-o$/d' \
            -e '/\.cvsignore$/d' \
            -e '/\/CVS/d' \
            -e '/\.indent\.pro$/d' \
            -e '/\.apaci.*/d' \
            -e '/Makefile$/d' \
            -e '/\/\.#/d' \
            -e '/\.orig$/d' \
            -e 's/^\.\///'`"
OIFS="$IFS" IFS="$DIFS"
for file in $FILES; do
     #  don't use `-type f' above for find because of symlinks
     if [ -d $file ]; then
         continue
     fi
     basename=`echo $file | sed -e 's:^.*/::'`
     dir=`echo $file | sed -e 's:[^/]*$::' -e 's:/$::' -e 's:$:/:' -e 's:^/$::'`
     from="$src/$file"
     to="$dst/$dir$basename"
     if [ $oneisabs = 0 ]; then
         if [ ".$dir" != . ]; then
             subdir=`echo $dir | sed -e 's:/$::'`
             #   (inlined fp2rp)
             revdir=''
             OIFS2="$IFS"; IFS='/'
             for pe in $subdir; do
                 revdir="../$revdir"
             done
             IFS="$OIFS2"
             #   finalize from
             from="$revdir$from"
         fi
         from="$dstrevdir$from"
     fi
     echo "    $to"
     ln -s $from $to
done
IFS="$OIFS"

