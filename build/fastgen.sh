#! /bin/sh
# ====================================================================
# The Apache Software License, Version 1.1
#
# Copyright (c) 2000-2003 The Apache Software Foundation.  All rights
# reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# 3. The end-user documentation included with the redistribution,
#    if any, must include the following acknowledgment:
#       "This product includes software developed by the
#        Apache Software Foundation (http://www.apache.org/)."
#    Alternately, this acknowledgment may appear in the software itself,
#    if and wherever such third-party acknowledgments normally appear.
#
# 4. The names "Apache" and "Apache Software Foundation" must
#    not be used to endorse or promote products derived from this
#    software without prior written permission. For written
#    permission, please contact apache@apache.org.
#
# 5. Products derived from this software may not be called "Apache",
#    nor may "Apache" appear in their name, without prior written
#    permission of the Apache Software Foundation.
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
# ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
# USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
# ====================================================================
#
# This software consists of voluntary contributions made by many
# individuals on behalf of the Apache Software Foundation.  For more
# information on the Apache Software Foundation, please see
# <http://www.apache.org/>.
#
# The build environment was provided by Sascha Schumann.
#

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
