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

#   determine if source is an absolute path
case $src in
    /* ) srcisabs=1 ;;
     * ) srcisabs=0 ;;
esac

#   determine reverse directory to directory
case $dst in
    /* ) dstrevdir='' ;;
     * ) dstrevdir="`$src/helpers/fp2rp $dst`/" ;;
esac

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
        find . -type f -depth -print |\
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
     basename=`echo $file | sed -e 's:^.*/::'`
     dir=`echo $file | sed -e 's:[^/]*$::' -e 's:/$::' -e 's:$:/:' -e 's:^/$::'`
     from="$src/$file"
     to="$dst/$dir$basename"
     if [ $srcisabs = 0 -a ".$dir" != . ]; then
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
     echo "    $to"
     ln -s $from $to
done
IFS="$OIFS"

