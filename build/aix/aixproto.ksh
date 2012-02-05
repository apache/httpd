#!/usr/bin/ksh
TEMPDIR=$1
BUILD=`pwd`
. build/aix/pkginfo

package=$PKG
name=$NAME
vrmf=$VERSION
descr="$VENDOR $NAME for $ARCH"
umask 022
INFO=$BUILD/build/aix/.info
mkdir -p $INFO

template=${INFO}/${PKG}.${NAME}.${vrmf}.template
>$template

cd ${TEMPDIR}
rm -rf .info lpp_name tmp
# get the directory sizes in blocks
for d in etc opt var
do
        set `du -s $d/${NAME}`
        let sz$d=$1+1
done
set `du -s usr/share/man`
szman=$1+1

files=./httpd-root
cd ${TEMPDIR}/..
find ${files} -type d -exec chmod og+rx {} \;
chmod -R go+r ${files}
chown -R 0:0 ${files}

cat - <<EOF >>$template
Package Name: ${package}.${NAME}
Package VRMF: ${vrmf}.0
Update: N
Fileset
  Fileset Name: ${package}.${NAME}.rte
  Fileset VRMF: ${vrmf}.0
  Fileset Description: ${descr}
  USRLIBLPPFiles
  EOUSRLIBLPPFiles
  Bosboot required: N
  License agreement acceptance required: N
  Include license files in this package: N
  Requisites:
        Upsize: /usr/share/man ${szman};
        Upsize: /etc/${NAME} $szetc;
        Upsize: /opt/${NAME} $szopt;
        Upsize: /var/${NAME} $szvar;
  USRFiles
EOF

find ${files} | sed -e s#^${files}## | sed -e "/^$/d" >>$template

cat - <<EOF >>$template
  EOUSRFiles
  ROOT Part: N
  ROOTFiles
  EOROOTFiles
  Relocatable: N
EOFileset
EOF

cp ${template} ${BUILD}/build/aix

# use mkinstallp to create the fileset. result is in ${TEMPDIR}/tmp
mkinstallp -d ${TEMPDIR} -T ${template}

cp ${TEMPDIR}/tmp/$PKG.$NAME.$VERSION.0.bff ${BUILD}/build/aix
cd $BUILD/build/aix
rm -f $PKG.$NAME.$VERSION.$ARCH.I
mv $PKG.$NAME.$VERSION.0.bff $PKG.$NAME.$VERSION.$ARCH.I
rm .toc
inutoc .
installp -d . -ap ${PKG}.${NAME}
installp -d . -L
