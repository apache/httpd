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

# buildaix.ksh: This script builds an AIX fileset of Apache httpd

# if arguments - try to run fast
cmd=$0

export CFLAGS='-O2'

lslpp -L bos.adt.insttools >/dev/null
 [[ $? -ne 0 ]] && echo "must have bos.adt.insttools installed" && exit -1

apr_config=`which apr-1-config`
apu_config=`which apu-1-config`

if [[ -z ${apr_config} && -z ${apu_config} ]]
then
	export PATH=/opt/bin:${PATH}
	apr_config=`which apr-1-config`
	apu_config=`which apu-1-config`
fi

while test $# -gt 0
do
  # Normalize
  case "$1" in
  -*=*) optarg=`echo "$1" | sed 's/[-_a-zA-Z0-9]*=//'` ;;
  *) optarg= ;;
  esac

  case "$1" in
  --with-apr=*)
  apr_config=$optarg
  ;;
  esac

  case "$1" in
  --with-apr-util=*)
  apu_config=$optarg
  ;;
  esac

  shift
  argc--
done

if [ ! -f "$apr_config" -a ! -f "$apr_config/configure.in" ]; then
  echo "The apr source directory / apr-1-config could not be found"
  echo "If available, install the ASF.apu.rte and ASF.apr.rte filesets"
  echo "Usage: $cmd [--with-apr=[dir|file]] [--with-apr-util=[dir|file]]"
  exit 1
fi

if [ ! -f "$apu_config" -a ! -f "$apu_config/configure.in" ]; then
  echo "The apu source directory / apu-1-config could not be found"
  echo "If available, install the ASF.apu.rte and ASF.apr.rte filesets"
  echo "Usage: $cmd [--with-apr=[dir|file]] [--with-apr-util=[dir|file]]"
  exit 1
fi

. build/aix/aixinfo
LAYOUT=AIX
TEMPDIR=/var/tmp/$USER/${NAME}.${VERSION}
rm -rf $TEMPDIR

if [[ ! -e ./Makefile ]] # if Makefile exists go faster
then
	echo "+ ./configure \n\
		--enable-layout=$LAYOUT \n\
		--with-apr=$apr_config \n\
		--with-apr-util=$apu_config \n\
		--with-mpm=worker \n\
		--enable-ssl \n\
		--enable-mods-shared=all > build/aix/configure.out"
	./configure \
		--enable-layout=$LAYOUT \
		--with-apr=$apr_config \
		--with-apr-util=$apu_config \
		--with-mpm=worker \
		--enable-ssl \
		--enable-mods-shared=all > build/aix/configure.out
		 [[ $? -ne 0 ]] && echo './configure' returned an error && exit -1
else
	echo $0: using existing Makefile
	echo $0: run make distclean to get a standard AIX configure
	echo
	ls -l ./Makefile config.*
	echo
fi

echo "+ make > build/aix/make.out"
make > build/aix/make.out
 [[ $? -ne 0 ]] && echo 'make' returned an error && exit -1

echo "+ make install DESTDIR=$TEMPDIR > build/aix/install.out"
make install DESTDIR=$TEMPDIR > build/aix/install.out
 [[ $? -ne 0 ]] && echo 'make install' returned an error && exit -1

echo "+ build/aix/mkinstallp.ksh $TEMPDIR > build/aix/mkinstallp.out"
build/aix/mkinstallp.ksh $TEMPDIR > build/aix/mkinstallp.out
 [[ $? -ne 0 ]] && echo mkinstallp.ksh returned an error && exit -1

rm -rf $TEMPDIR

# list installable fileset(s)
echo ========================
installp -d build/aix -L
echo ========================
