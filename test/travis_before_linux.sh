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

function install_apx() {
    local name=$1
    local version=$2
    local root=https://svn.apache.org/repos/asf/apr/${name}
    local prefix=${HOME}/root/${name}-${version}
    local build=${HOME}/build/${name}-${version}
    local giturl=https://github.com/apache/${name}.git
    local config=$3
    local buildconf=$4

    case $version in
    trunk) url=${root}/trunk ;;
    *.x) url=${root}/branches/${version} ;;
    *) url=${root}/tags/${version} ;;
    esac

    local revision=`svn info --show-item last-changed-revision ${url}`

    # Blow away the cached install root if the cached install is stale
    # or doesn't match the expected configuration.
    grep -q "${version} ${revision} ${config} CC=$CC" ${HOME}/root/.key-${name} || rm -rf ${prefix}

    if test -d ${prefix}; then
        return 0
    fi

    git clone -q --depth=1 --branch=$version ${giturl} ${build}
    pushd $build
         ./buildconf ${buildconf}
         ./configure --prefix=${prefix} ${config}
         make -j2
         make install
    popd

    echo ${version} ${revision} "${config}" "CC=${CC}" > ${HOME}/root/.key-${name}
}

# Allow to load $HOME/build/apache/httpd/.gdbinit
echo "add-auto-load-safe-path $HOME/work/httpd/httpd/.gdbinit" >> $HOME/.gdbinit

# Unless either SKIP_TESTING or NO_TEST_FRAMEWORK are set, install
# CPAN modules required to run the Perl test framework.
if ! test -v SKIP_TESTING -o -v NO_TEST_FRAMEWORK; then
    # Clear CPAN cache if necessary
    if [ -v CLEAR_CACHE ]; then rm -rf ~/perl5; fi
    
    cpanm --local-lib=~/perl5 local::lib && eval $(perl -I ~/perl5/lib/perl5/ -Mlocal::lib)

    pkgs="Net::SSL LWP::Protocol::https                                 \
           LWP::Protocol::AnyEvent::http ExtUtils::Embed Test::More     \
           AnyEvent DateTime HTTP::DAV FCGI                             \
           AnyEvent::WebSocket::Client Apache::Test"

    # CPAN modules are to be used with the system Perl and always with
    # CC=gcc, e.g. for the CC="gcc -m32" case the builds are not correct
    # otherwise.
    CC=gcc cpanm --notest $pkgs

    # Set cache key.
    echo $pkgs > ~/perl5/.key
    unset pkgs

    # Make a shallow clone of httpd-tests git repo.
    git clone -q --depth=1 https://github.com/apache/httpd-tests.git test/perl-framework
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

if test -v TEST_OPENSSL3; then
    # Build the requested version of OpenSSL if it's not already
    # installed in the cached ~/root
    if ! test -f $HOME/root/openssl-is-${TEST_OPENSSL3}; then
        # Remove any previous install.
        rm -rf $HOME/root/openssl3

        mkdir -p build/openssl
        pushd build/openssl
           curl "https://www.openssl.org/source/openssl-${TEST_OPENSSL3}.tar.gz" |
              tar -xzf -
           cd openssl-${TEST_OPENSSL3}
           ./Configure --prefix=$HOME/root/openssl3 shared no-tests
           make $MFLAGS
           make install_sw
           touch $HOME/root/openssl-is-${TEST_OPENSSL3}
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
