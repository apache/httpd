#!/bin/bash -xe

if test -v CLEAR_CACHE; then
    rm -rf $HOME/root
fi

# Use a rudimental retry workflow as workaround to svn export hanging for minutes.
# Travis automatically kills a build if one step takes more than 10 minutes without
# reporting any progress. 
function run_svn_export() {
   local url=$1
   local revision=$2
   local dest_dir=$3
   local max_tries=$4

   # Disable -e to allow fail/retry
   set +e

   for i in $(seq 1 $max_tries)
   do
       timeout 60 svn export -r ${revision} --force -q $url $dest_dir
       if [ $? -eq 0 ]; then
           break
       else
           if [ $i -eq $max_tries ]; then
               exit 1
           else
               sleep 180
           fi
       fi
   done

   # Restore -e behavior after fail/retry
   set -e
}

function install_apx() {
    local name=$1
    local version=$2
    local root=https://svn.apache.org/repos/asf/apr/${name}
    local prefix=${HOME}/root/${name}-${version}
    local build=${HOME}/build/${name}-${version}
    local config=$3
    local buildconf=$4

    case $version in
    trunk) url=${root}/trunk ;;
    *.x) url=${root}/branches/${version} ;;
    *) url=${root}/tags/${version} ;;
    esac

    local revision=`svn info --show-item last-changed-revision ${url}`

    # Blow away the cached install root if the revision does not
    # match.
    test -f ${prefix}/.revision-is-${revision} || rm -rf ${prefix}

    if test -d ${prefix}; then
        return 0
    fi

    svn export -q -r ${revision} ${url} ${build}
    pushd $build
         ./buildconf ${buildconf}
         ./configure --prefix=${prefix} ${config}
         make -j2
         make install
    popd

    touch ${prefix}/.revision-is-${revision}
}


if ! test -v SKIP_TESTING; then
    framework=https://svn.apache.org/repos/asf/httpd/test/framework/trunk
    fcache=$HOME/root/framework
    frev=`svn info --show-item last-changed-revision ${framework} || echo HEAD`
    if [ -n "${frev}" -a ! -f ${fcache}/.revision-is-${frev} ]; then
        : Purging stale cache at ${fcache}
        rm -rf ${fcache}
    fi

    if [ ! -d ${fcache} ]; then
        run_svn_export ${framework} ${frev} ${fcache} 5
        touch ${fcache}/.revision-is-${frev}
    fi

    cp -a ${fcache} test/perl-framework
fi

if test -v APR_VERSION; then
    install_apx apr ${APR_VERSION} "${APR_CONFIG}"
    APU_CONFIG="$APU_CONFIG --with-apr=$HOME/root/apr-${APR_VERSION}"
fi

if test -v APU_VERSION; then
    install_apx apr-util ${APU_VERSION} "${APU_CONFIG}" --with-apr=$HOME/build/apr-${APR_VERSION}
fi
