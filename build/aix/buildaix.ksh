#!/usr/bin/ksh
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

# buildaix.ksh: This script builds an AIX fileset

LAYOUT=AIX
TEMPDIR=/var/tmp/$USER/httpd-root
rm -rf $TEMPDIR

## strange interaction between install and libtool requires a regular install
## for all the links to succeed in the TEMPDIR
## httpd-2.0 does not include ssl by default
## will make a seperate build for that later

> nohup.out
./configure \
 	--enable-layout=$LAYOUT \
 	--enable-module=so \
 	--enable-proxy \
 	--enable-cache \
 	--enable-disk-cache \
 	--with-mpm=worker \
 	--enable-mods-shared=all | tee nohup.out

make | tee -a nohup.out

make install > install.log
make install DESTDIR=$TEMPDIR

# will make use of the pkginfo data as input for mkinstallp template
cp build/aix/pkginfo $TEMPDIR

## no seperate filesets for man pages, documents, etc.

build/aix/aixproto.ksh $TEMPDIR

# rm -rf $TEMPDIR
ls -ltr build/aix | grep -i aix
