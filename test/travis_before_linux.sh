#!/bin/bash -xe

if test -v CLEAR_CACHE; then
    rm -rf $HOME/root
fi

: Travis tag = ${TRAVIS_TAG}
: Travis branch = ${TRAVIS_BRANCH}

: /etc/hosts --
cat /etc/hosts
: -- ends

# ### FIXME: This is a workaround, non-x86 builds have an IPv6
# configuration which somehow breaks the test suite runs.  Appears
# that Apache::Test only configures the server to Listen on 0.0.0.0
# (that is hard-coded), but then Apache::TestSerer::wait_till_is_up()
# tries to connect via ::1, which fails/times out.
if grep ip6-localhost /etc/hosts; then
    sudo sed -i "/ip6-/d" /etc/hosts
    cat /etc/hosts
fi

# Use a rudimental retry workflow as workaround to svn export hanging
# for minutes or failing randomly.  Travis automatically kills a build
# if one step takes more than 10 minutes without reporting any
# progress.
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
               sleep $((100 * i))
           fi
       fi
   done

   # Restore -e behavior after fail/retry
   set -e
}

function install_apx() {
    local name=$1
    local version=$2
    local prefix=${HOME}/root/${name}-${version}
    local build=${HOME}/build/${name}-${version}
    local giturl=https://github.com/apache/${name}.git
    local config=$3
    local buildconf=$4

    case $version in
    trunk|*.x) ref=refs/heads/${version} ;;
    *) ref=refs/tags/${version} ;;
    esac

    # Fetch the object ID (hash) of latest commit
    local commit=`git ls-remote ${giturl} ${ref} | cut -f1`
    if test -z "$commit"; then
        : Could not determine latest commit hash for ${ref} in ${giturl} - check branch is valid?
        exit 1
    fi

    # Blow away the cached install root if the cached install is stale
    # or doesn't match the expected configuration.
    grep -q "${version} ${commit} ${config} CC=$CC" ${HOME}/root/.key-${name} || rm -rf ${prefix}

    if test -d ${prefix}; then
        return 0
    fi

    git init -q ${build}
    pushd $build
         # Clone and checkout the commit identified above.
         git remote add origin ${giturl}
         git fetch -q --depth=1 origin ${commit}
         git checkout ${commit}
         ./buildconf ${buildconf}
         ./configure --prefix=${prefix} ${config}
         make -j2
         make install
    popd

    echo ${version} ${commit} "${config}" "CC=${CC}" > ${HOME}/root/.key-${name}
}

# Allow to load $HOME/build/apache/httpd/.gdbinit
echo "add-auto-load-safe-path $HOME/work/httpd/httpd/.gdbinit" >> $HOME/.gdbinit

# Unless either SKIP_TESTING or NO_TEST_FRAMEWORK are set, install
# CPAN modules required to run the Perl test framework.
if ! test -v SKIP_TESTING -o -v NO_TEST_FRAMEWORK; then
    # Clear CPAN cache if necessary
    if [ -v CLEAR_CACHE ]; then rm -rf ~/perl5; fi

    if ! perl -V > perlver; then
        : Perl binary broken
        perl -V
        exit 1
    fi

    # Compare the current "perl -V" output with the output at the time
    # the cache was built; flush the cache if it's changed to avoid
    # failure later when /usr/bin/perl refuses to load a mismatched XS
    # module.
    if ! cmp -s perlver ~/perl5/.perlver; then
        : Purging cache since "perl -V" output has changed
        rm -rf ~/perl5
    fi
    
    cpanm --local-lib=~/perl5 local::lib && eval $(perl -I ~/perl5/lib/perl5/ -Mlocal::lib)

    pkgs="Net::SSL LWP::Protocol::https                                 \
           LWP::Protocol::AnyEvent::http ExtUtils::Embed Test::More     \
           AnyEvent DateTime HTTP::DAV FCGI                             \
           AnyEvent::WebSocket::Client Apache::Test"

    # CPAN modules are to be used with the system Perl and always with
    # CC=gcc, e.g. for the CC="gcc -m32" case the builds are not correct
    # otherwise.
    CC=gcc cpanm --notest $pkgs
    unset pkgs

    # Cache the perl -V output for future verification.
    mv perlver ~/perl5/.perlver

    # Make a shallow clone of httpd-tests git repo.
    git clone -q --depth=1 https://github.com/apache/httpd-tests.git test/perl-framework

    # For OpenSSL 3.2+ testing, Apache::Test r1916067 is required, so
    # use a checkout of trunk until there is an updated CPAN release
    # with that revision.
    if test -v TEST_OPENSSL3; then
       run_svn_export https://svn.apache.org/repos/asf/perl/Apache-Test/trunk HEAD test/perl-framework/Apache-Test 5
    fi
fi

# For LDAP testing, run slapd listening on port 8389 and populate the
# directory as described in t/modules/ldap.t in the test framework:
if test -v TEST_LDAP -a -x test/perl-framework/scripts/ldap-init.sh; then
    docker build -t httpd_ldap -f test/travis_Dockerfile_slapd.centos test/
    pushd test/perl-framework
       ./scripts/ldap-init.sh
    popd
fi

if test -v TEST_SSL; then
    pushd test/perl-framework
       ./scripts/memcached-init.sh
       ./scripts/redis-init.sh
    popd
fi

# Build the requested version of OpenSSL if it's not already installed
# in the cached ~/root
if test -v TEST_OPENSSL3; then
    # For a branch, rebuild if the remote branch has updated.
    if test -v TEST_OPENSSL3_BRANCH -a -f $HOME/root/openssl-is-${TEST_OPENSSL3}; then
        latest=`git ls-remote https://github.com/openssl/openssl refs/heads/${TEST_OPENSSL3_BRANCH} | cut -f1`
        : Got branch latest commit ${latest}
        if grep -q ^${latest} $HOME/root/openssl-is-${TEST_OPENSSL3}; then
            : Cached repos already at ${latest}
        else
            : Forcing rebuild
            rm -f $HOME/root/openssl-is-${TEST_OPENSSL3}
        fi
    fi

    if ! test -f $HOME/root/openssl-is-${TEST_OPENSSL3}; then
        # Remove any previous install.
        rm -rf $HOME/root/openssl3

        mkdir -p build/openssl
        pushd build/openssl
           if test -v TEST_OPENSSL3_BRANCH; then
               git clone --depth=1 -b $TEST_OPENSSL3_BRANCH -q https://github.com/openssl/openssl openssl-${TEST_OPENSSL3}
           else
               curl -L "https://github.com/openssl/openssl/releases/download/openssl-${TEST_OPENSSL3}/openssl-${TEST_OPENSSL3}.tar.gz" |
                   tar -xzf -
           fi
           cd openssl-${TEST_OPENSSL3}
           # Build with RPATH so ./bin/openssl doesn't require $LD_LIBRARY_PATH
           ./Configure --prefix=$HOME/root/openssl3 \
                       shared no-tests ${OPENSSL_CONFIG} \
                       '-Wl,-rpath=$(LIBRPATH)'
           make $MFLAGS
           make install_sw
           if test -d .git; then
               : Caching git commit hash:
               git rev-parse HEAD | tee $HOME/root/openssl-is-${TEST_OPENSSL3}
           else
               touch $HOME/root/openssl-is-${TEST_OPENSSL3}
           fi
       popd
    fi

    # Point APR/APR-util at the installed version of OpenSSL.
    if test -v APU_VERSION; then
        APU_CONFIG="${APU_CONFIG} --with-openssl=$HOME/root/openssl3"
    elif test -v APR_VERSION; then
        APR_CONFIG="${APR_CONFIG} --with-openssl=$HOME/root/openssl3"
    else
        : Non-system APR/APR-util must be used to build with OpenSSL 3 to avoid mismatch with system libraries
        exit 1
    fi
fi

if test -v APR_VERSION; then
    install_apx apr ${APR_VERSION} "${APR_CONFIG}"
    ldd $HOME/root/apr-${APR_VERSION}/lib/libapr-?.so || true
    APU_CONFIG="$APU_CONFIG --with-apr=$HOME/root/apr-${APR_VERSION}"
fi

if test -v APU_VERSION; then
    install_apx apr-util ${APU_VERSION} "${APU_CONFIG}" --with-apr=$HOME/build/apr-${APR_VERSION}
    ldd $HOME/root/apr-util-${APU_VERSION}/lib/libaprutil-?.so || true
fi

# Since librustls is not a package (yet) on any platform, we
# build the version we want from source
if test -v TEST_MOD_TLS -a -v RUSTLS_VERSION; then
    if ! test -d $HOME/root/rustls; then
        RUSTLS_HOME="$HOME/build/rustls-ffi"
        git clone -q --depth=1 -b "$RUSTLS_VERSION" https://github.com/rustls/rustls-ffi.git "$RUSTLS_HOME"
        pushd "$RUSTLS_HOME"
            make install DESTDIR="$HOME/root/rustls"
        popd
    fi
fi
