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

# minstallp.ksh # create an installp image of ${NAME} (defined in aixinfo)
# from TEMPDIR using mkinstallp (part of bos.adt.insttools)

[[ $# == 0 ]] && echo $0: Syntax error && echo "Syntax: $0 <BaseDirectory>" && exit -1

umask 022
TEMPDIR=$1
BASE=`pwd`
cd ${TEMPDIR}
[[ $? != 0 ]] && echo $0: ${TEMPDIR} -- bad directory && exit -1

# clean up side-effects from DEBUG passes - usr/local might be there as
# a circular link i.e. usr/local points at /usr/local
# as we are not using /usr/local for ASF packaging, remove it!
# mkinstallp seems to make usr/local -> /usr/local 
[[ -f usr/local ]] && rm -f usr/local && echo removed unexpected usr/local !!
[[ -L usr/local ]] && rm -f usr/local && echo removed unexpected usr/local !!
[[ -d usr/local ]] && rm -rf usr/local && echo removed unexpected usr/local !!

# use the aixinfo for PKG NAME VERSION etc labels
cd ${BASE}
. build/aix/aixinfo
# INFO=${BASE}/build/aix/.info
# mkdir -p $INFO
INFO=${BASE}/build/aix
template=${INFO}/${PKG}.${NAME}.${VERSION}.template
>$template

# mkinstallp template definitions
# TODO: add AIX oslevel/uname information for package filename
package=$PKG
name=$NAME
vrmf=$VERSION
release=$RELEASE
descr="$NAME version ${VERSION} for $ARCH ${VENDOR}"

# copy LICENSE information
# TODO: setup template so that license acceptance is required
# TODO: add Copyright Information for display during install
mkdir -p ${TEMPDIR}/usr/swlag/en_US
cp ${BASE}/LICENSE ${TEMPDIR}/usr/swlag/en_US/${PKG}.${NAME}.la

cd ${TEMPDIR}
# remove files we do not want as "part" possibly
# left-over from a previous packaging
rm -rf .info lpp_name tmp usr/lpp
[[ $? -ne 0 ]] && echo $cmd: cleanup error && pwd && ls -ltr && exit -1

#if we are going to add extra symbolic links - do it now
[[ -r build/aix/aixlinks ]] && ksh build/aix/aixlinks

# get the directory sizes in blocks
for d in etc opt var
do
	if [[ -d $d/${NAME} ]]
	then
		set `du -s $d/${NAME}`
	else
		[[ -d $d ]] && set `du -s $d`
	fi
	# make sure the argument exists before using setting values
	if [[ -d $d ]]
	then
		eval nm$d=/"$2"
		let sz$d=$1
	fi
done

files=./${NAME}.${VERSION}
cd ${TEMPDIR}/..
find ${files} -type d -exec chmod og+rx {} \;
chmod -R go+r ${files}
chown -R 0.0 ${files}

cat - <<EOF >>$template
Package Name: ${PKG}.${NAME}
Package VRMF: ${VERSION}.${RELEASE}
Update: N
Fileset
  Fileset Name: ${PKG}.${NAME}.rte
  Fileset VRMF: ${VERSION}.${RELEASE}
  Fileset Description: ${descr}
  USRLIBLPPFiles
  EOUSRLIBLPPFiles
  Bosboot required: N
  License agreement acceptance required: N
  Name of license agreement: 
  Include license files in this package: N
  Requisites:
EOF

[[ $szetc -ne 0 ]] && echo "        Upsize: ${nmetc} $szetc;" >> $template
[[ $szopt -ne 0 ]] && echo "        Upsize: ${nmopt} $szopt;" >> $template
[[ $szvar -ne 0 ]] && echo "        Upsize: ${nmvar} $szvar;" >> $template
echo "  USRFiles" >> $template

# USR part -- i.e. files in /usr and /opt
cd ${TEMPDIR}/..
find ${files}/usr/swlag ${files}/opt \
	| sed -e s#^${files}## | sed -e "/^$/d" >>$template
echo "  EOUSRFiles" >> $template

if [[ $szetc -gt 0 || $szvar -gt 0 ]]
then
INSTROOT=${TEMPDIR}/usr/lpp/${PKG}.${NAME}/inst_root
mkdir -p ${INSTROOT}
cd ${TEMPDIR}
[[ $szetc -gt 0 ]] && find ./etc -type d | backup -if - | (cd ${INSTROOT}; restore -xqf -) >/dev/null
[[ $szvar -gt 0 ]] && find ./var -type d | backup -if - | (cd ${INSTROOT}; restore -xqf -) >/dev/null
cat - <<EOF >>$template
  ROOT Part: Y
  ROOTFiles
EOF

# ROOT part 
cd ${TEMPDIR}/..
find ${files}/etc ${files}/var \
	| sed -e s#^${files}## | sed -e "/^$/d" >>$template
else
# no ROOT parts to include
cat - <<EOF >>$template
  ROOT Part: N
  ROOTFiles
EOF
fi
cat - <<EOF >>$template
  EOROOTFiles
  Relocatable: N
EOFileset
EOF
# man pages as seperate fileset
cd ${TEMPDIR}
if [[ -d usr/share/man ]]
then
	# manual pages, space required calculation
	set `du -s usr/share/man`
	szman=$1
	descr="$NAME ${VERSION} man pages ${VENDOR}"
	cat - <<EOF >>$template
Fileset
  Fileset Name: ${PKG}.${NAME}.man.en_US
  Fileset VRMF: ${VERSION}.${RELEASE}
  Fileset Description: ${descr}
  USRLIBLPPFiles
  EOUSRLIBLPPFiles
  Bosboot required: N
  License agreement acceptance required: N
  Name of license agreement:
  Include license files in this package: N
  Requisites:
EOF

	echo "        Upsize: /usr/share/man ${szman};" >> $template
	echo "  USRFiles" >> $template
	cd ${TEMPDIR}/..
	find ${files}/usr/share | sed -e s#^${files}## | sed -e "/^$/d" >>$template
	cat - <<EOF >>$template
  EOUSRFiles
  ROOT Part: N
  ROOTFiles
  EOROOTFiles
  Relocatable: N
EOFileset
EOF
fi

# use mkinstallp to create the fileset. result is in ${TEMPDIR}/tmp
# must actually sit in TEMPDIR for ROOT part processing to succeed
# also - need "empty" directories to exist, as they do not get copied
# in the inst_root part
cd ${TEMPDIR}
mkinstallp -d ${TEMPDIR} -T ${template}
[[ $? -ne 0 ]] && echo mkinstallp returned error status && exit -1

# copy package to build/aix
# create TOC
cp ${TEMPDIR}/tmp/$PKG.$NAME.$VERSION.0.bff ${BASE}/build/aix
cd ${BASE}/build/aix
rm -f $PKG.$NAME.$VERSION.$ARCH.I
mv $PKG.$NAME.$VERSION.0.bff $PKG.$NAME.$ARCH.$VERSION.I
rm -f .toc
inutoc .
