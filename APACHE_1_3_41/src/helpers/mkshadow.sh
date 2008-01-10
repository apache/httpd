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
#  mkshadow.sh -- create a shadow tree
#
#  Initially written by Ralf S. Engelschall <rse apache.org>
#  for the shadow tree generation option (--shadow) of 
#  Apache's Autoconf-style Interface (APACI) 

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
if [ "x$oneisabs" = "x0" ]; then
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
DIRS="`cd $src; \
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
FILES="`cd $src; \
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
     if [ -d "$src/$file" ]; then
         continue
     fi
     basename=`echo $file | sed -e 's:^.*/::'`
     dir=`echo $file | sed -e 's:[^/]*$::' -e 's:/$::' -e 's:$:/:' -e 's:^/$::'`
     from="$src/$file"
     to="$dst/$dir$basename"
     if [ "x$oneisabs" = "x0" ]; then
         if [ "x$dir" != "x" ]; then
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

