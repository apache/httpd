#!/bin/sh
##
##  mkshadow.sh -- create a shadow tree
##
##  Written by Ralf S. Engelschall <rse@apache.org>
##  for the shadow tree generation option (--shadow) of 
##  Apache's Autoconf-style Interface (APACI) 
##

src=`echo $1 | sed -e 's:/$::'`
dst=`echo $2 | sed -e 's:/$::'`
aux=$3

#   create directory tree
DIRS="`cd $src
       find . -type d -print |\
       sed -e '/\/CVS/d' \
           -e '/^\.$/d' \
           -e 's/^\.\///'`"
for dir in $DIRS; do
    mkdir $dst/$dir
done

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
            -e '/Makefile$/d' \
            -e '/\/\.#/d' \
            -e '/\.orig$/d' \
            -e 's/^\.\///'`"
for file in $FILES; do
     basename=`echo $file | sed -e 's:^.*/::'`
     dir=`echo $file | sed -e 's:[^/]*$::' -e 's:/$::' -e 's:$:/:' -e 's:^/$::'`
     from="$src/$file"
     to="$dst/$dir$basename"
     case $from in
         /* ) ;;
          * ) 
             if [ ".$dir" != . ]; then
                 subdir=`echo $dir | sed -e 's:/$::'`
                 revdir=`$src/helpers/fp2rp $subdir`
                 from="$revdir/$from"
             fi
             ;;
     esac
     case $dst in
         /* ) ;;
          * ) 
             subdir=`echo $dst | sed -e 's:/$::'`
             revdir=`$src/helpers/fp2rp $subdir`
             from="$revdir/$from"
             ;;
     esac
     echo "    $to"
     ln -s $from $to
done

