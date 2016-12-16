#! /bin/sh
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
# The build environment was provided by Sascha Schumann.

srcdir=$1
shift

mkdir_p=$1
shift

bsd_makefile=$1
shift

top_srcdir=`(cd $srcdir; pwd)`
top_builddir=`pwd`

if test "$mkdir_p" = "yes"; then
  mkdir_p="mkdir -p"
else
  mkdir_p="$top_srcdir/build/mkdir.sh"
fi

if test "$bsd_makefile" = "yes"; then
  (cd $top_srcdir; ./build/bsd_makefile)  

  for makefile in $@; do
    echo "creating $makefile"
    dir=`echo $makefile|sed 's%/*[^/][^/]*$%%'`

    if test -z "$dir"; then
        real_srcdir=$top_srcdir
        real_builddir=$top_builddir
        dir="."
    else
        $mkdir_p "$dir/"
        real_srcdir=$top_srcdir/$dir
        real_builddir=$top_builddir/$dir
    fi
    cat - $top_srcdir/$makefile.in <<EOF |sed 's/^include \(.*\)/.include "\1"/' >$makefile 
top_srcdir   = $top_srcdir
top_builddir = $top_builddir
srcdir       = $real_srcdir
builddir     = $real_builddir
VPATH        = $real_srcdir
EOF
    
    touch $dir/.deps
  done
else  
  for makefile in $@; do
    echo "creating $makefile"
    dir=`echo $makefile|sed 's%/*[^/][^/]*$%%'`

    if test -z "$dir"; then
        real_srcdir=$top_srcdir
        real_builddir=$top_builddir
        dir="."
    else
        $mkdir_p "$dir/"
        real_srcdir=$top_srcdir/$dir
        real_builddir=$top_builddir/$dir
    fi
    cat - $top_srcdir/$makefile.in <<EOF >$makefile
top_srcdir   = $top_srcdir
top_builddir = $top_builddir
srcdir       = $real_srcdir
builddir     = $real_builddir
VPATH        = $real_srcdir
EOF

    touch $dir/.deps
  done
fi
