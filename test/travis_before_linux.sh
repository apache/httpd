#!/bin/bash -ex
if ! test -v SKIP_TESTING; then
   svn export -q https://svn.apache.org/repos/asf/httpd/test/framework/trunk test/perl-framework
fi
if test -v APR_VERSION; then
    # For APR trunk the cached version at ~/root/apr-trunk will be
    # stale if the current trunk revision is different from that of
    # the cached build.  Here, cache and check the rev number of the
    # build accordingly.
    trunk_url=https://svn.apache.org/repos/asf/apr/apr/trunk
    if test $APR_VERSION = trunk; then
        trunk_rev=`svn info --show-item last-changed-revision ${trunk_url}`
        # Blow away the cached trunk install if the revision does not
        # match.
        test -f $HOME/root/apr-trunk/.revision-is-${trunk_rev} || rm -rf $HOME/root/apr-trunk
    fi
    if ! test -d $HOME/root/apr-${APR_VERSION}; then
        case $APR_VERSION in
            trunk) svn export -q -r ${trunk_rev} ${trunk_url} $HOME/build/apr-trunk ;;
            *) svn export -q https://svn.apache.org/repos/asf/apr/apr/tags/${APR_VERSION} \
                   $HOME/build/apr-${APR_VERSION} ;;
        esac
        pushd $HOME/build/apr-${APR_VERSION}
        ./buildconf
        ./configure ${APR_CONFIG} --prefix=$HOME/root/apr-${APR_VERSION}
        make -j2
        make install
        if test -v trunk_rev; then
            # Record the revision built in the cache.
            touch $HOME/root/apr-${APR_VERSION}/.revision-is-${trunk_rev}
        fi
        popd
        APU_CONFIG="$APU_CONFIG --with-apr=$HOME/root/apr-${APR_VERSION}"
    fi
fi
if test -v APU_VERSION; then
    if ! test -d $HOME/root/apu-${APU_VERSION}; then
        case $APU_VERSION in
            trunk) url=https://svn.apache.org/repos/asf/apr/apr-util/trunk ;;
            *) url=https://svn.apache.org/repos/asf/apr/apr-util/tags/${APU_VERSION} ;;
        esac
        svn export -q ${url} $HOME/build/apu-${APU_VERSION}
        pushd $HOME/build/apu-${APU_VERSION}
        ./buildconf --with-apr=$HOME/build/apr-${APR_VERSION}
        ./configure ${APU_CONFIG} --prefix=$HOME/root/apu-${APU_VERSION}
        make -j2
        make install
        popd
    fi
fi
