#!/bin/bash -xe

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

# Build and install $1 at version $2 into the cached
# $HOME/root/$1-$2, configured with the arguments in $3 and bootstrapped
# with ./buildconf $4, unless it was restored from the cache.  The
# source goes in $HOME/build, which is not cached; it is a git checkout
# or, with TEST_APR_TARBALL, the release tarball.
#
# The cache key covers APR and APR-util together, along with the
# configuration, $CC and, for a branch, the commit which
# gha-resolve-deps.sh resolved it to, so an install restored here is
# usable as-is.  The build uses that same commit, since resolving the
# branch again would race with it moving.
function install_apx() {
    local name=$1
    local version=$2
    local config=$3
    local buildconf=$4
    local prefix=${HOME}/root/${name}-${version}
    local build=${HOME}/build/${name}-${version}
    local ref

    if test -d ${prefix}; then
        return 0
    fi

    if test -v TEST_APR_TARBALL; then
        mkdir -p ${HOME}/build
        curl https://archive.apache.org/dist/apr/${name}-${version}.tar.gz |
            tar -C ${HOME}/build -xzf -
        pushd ${build}
    else
        case ${name}:${version} in
           apr:trunk|apr:*.x) ref=${APR_COMMIT:-refs/heads/${version}} ;;
           apr-util:trunk|apr-util:*.x) ref=${APU_COMMIT:-refs/heads/${version}} ;;
           *) ref=refs/tags/${version} ;;
        esac

        mkdir -p ${build}
        pushd ${build}
        git init -q
        git fetch -q --depth=1 https://github.com/apache/${name}.git ${ref}
        git checkout -q FETCH_HEAD
        ./buildconf ${buildconf}
    fi
    ./configure --prefix=${prefix} ${config}
    make -j2
    make install
    popd
}

# Allow to load $HOME/build/apache/httpd/.gdbinit
echo "add-auto-load-safe-path $HOME/work/httpd/httpd/.gdbinit" >> $HOME/.gdbinit

# Unless either SKIP_TESTING or NO_TEST_FRAMEWORK are set, install
# CPAN modules required to run the Perl test framework.
if ! test -v SKIP_TESTING -o -v NO_TEST_FRAMEWORK; then
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
    # The cache key covers $TEST_OPENSSL3, $OPENSSL_CONFIG and, for a
    # branch build, the resolved commit, so an install found here is
    # current.
    if ! test -d $HOME/root/openssl3; then
        mkdir -p build/openssl
        pushd build/openssl
           if test -v TEST_OPENSSL3_BRANCH; then
               git clone --depth=1 -b $TEST_OPENSSL3_BRANCH -q https://github.com/openssl/openssl openssl-${TEST_OPENSSL3}
               # Build the commit named in the cache key, not whatever
               # the branch tip has become since it was resolved.
               if test -n "${OPENSSL_COMMIT-}"; then
                   git -C openssl-${TEST_OPENSSL3} fetch -q --depth=1 origin ${OPENSSL_COMMIT}
                   git -C openssl-${TEST_OPENSSL3} checkout -q ${OPENSSL_COMMIT}
               fi
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

# Build the requested version of nghttp2 if it's not already installed
# in the cached ~/root; the nghttp/h2load tools come from the package.
if test -v TEST_NGHTTP2; then
    if ! test -d $HOME/root/nghttp2; then
        mkdir -p build/nghttp2
        pushd build/nghttp2
           curl -L "https://github.com/nghttp2/nghttp2/releases/download/v${TEST_NGHTTP2}/nghttp2-${TEST_NGHTTP2}.tar.xz" |
               tar -xJf -
           cd nghttp2-${TEST_NGHTTP2}
           ./configure --prefix=$HOME/root/nghttp2 --enable-lib-only
           make $MFLAGS
           make install
        popd
    fi

    : -- Using nghttp2 from $HOME/root/nghttp2 --
    grep -H '^Version' $HOME/root/nghttp2/lib/pkgconfig/libnghttp2.pc
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

if test -v PHP_FPM -a ! -v SKIP_TESTING; then
    # Sanity test the php-fpm executable exists.
    $PHP_FPM --version || exit 1
fi
