#!/bin/bash -xe

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

# Echo the object ID (hash) of the commit to build for $1 at version
# $2, or "tarball" if a release tarball is used instead of a checkout.
function resolve_apx() {
    local name=$1
    local version=$2
    local ref commit

    if test -v TEST_APR_TARBALL; then
        echo tarball
        return 0
    fi

    # For a branch, prefer the commit already resolved by
    # gha-resolve-deps.sh for the cache key; resolving it again here
    # would race with the branch moving in the meantime.  Tags are
    # immutable so they are always resolved below.
    case $name in
       apr)      commit=${APR_COMMIT-} ;;
       apr-util) commit=${APU_COMMIT-} ;;
    esac
    if test -n "$commit"; then
        echo ${commit}
        return 0
    fi

    case $version in
       trunk|*.x) ref=refs/heads/${version} ;;
       *) ref=refs/tags/${version} ;;
    esac

    commit=`git ls-remote https://github.com/apache/${name}.git ${ref} | cut -f1`
    if test -z "$commit"; then
       : Could not determine latest commit hash for ${ref} in ${name} - check branch is valid?
       exit 1
    fi

    echo ${commit}
}

# Unpack the source for $1 at version $2, commit $3, into
# $HOME/build/$1-$2, running ./buildconf with the arguments in $4.  Does
# nothing if the source tree is already present.  Note $HOME/build is
# not cached, unlike the install root in $HOME/root.
function fetch_apx() {
    local name=$1
    local version=$2
    local commit=$3
    local buildconf=$4
    local build=${HOME}/build/${name}-${version}

    if test -d ${build}; then
        return 0
    fi

    mkdir -p ${HOME}/build

    if test -v TEST_APR_TARBALL; then
         curl https://archive.apache.org/dist/apr/${name}-${version}.tar.gz > apx.tar.gz
         tar -C ${HOME}/build -xzf apx.tar.gz
         rm apx.tar.gz
    else
         git init -q ${build}
         pushd $build
         # Clone and checkout the commit identified above.
         git remote add origin https://github.com/apache/${name}.git
         git fetch -q --depth=1 origin ${commit}
         git checkout ${commit}
         ./buildconf ${buildconf}
         popd
    fi
}

function install_apx() {
    local name=$1
    local version=$2
    local prefix=${HOME}/root/${name}-${version}
    local build=${HOME}/build/${name}-${version}
    local config=$3
    local buildconf=$4
    local commit

    # The cache key covers the version, the resolved commit for a branch
    # build, the configuration and $CC, and is only written once the
    # build has succeeded, so anything restored here is usable as-is.
    if test -d ${prefix}; then
        return 0
    fi

    commit=`resolve_apx ${name} ${version}`

    # apr-util's buildconf needs APR's source tree, which is not cached.
    # If APR itself was restored from the cache it was never built here,
    # so fetch the source now - otherwise a stale APR-util alongside a
    # fresh APR cannot be rebuilt.
    if test ${name} = apr-util -a ! -d ${HOME}/build/apr-${APR_VERSION}; then
        fetch_apx apr ${APR_VERSION} `resolve_apx apr ${APR_VERSION}`
    fi

    fetch_apx ${name} ${version} ${commit} "${buildconf}"

    pushd ${build}
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
        # $PERLID covers this in the cache key, so it should now only
        # fire for a cold cache; show what changed if it fires anyway.
        if test -f ~/perl5/.perlver; then
            diff -u ~/perl5/.perlver perlver || true
        fi
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
    if ! test -f $HOME/root/nghttp2-is-${TEST_NGHTTP2}; then
        # Remove any previous install.
        rm -rf $HOME/root/nghttp2

        mkdir -p build/nghttp2
        pushd build/nghttp2
           curl -L "https://github.com/nghttp2/nghttp2/releases/download/v${TEST_NGHTTP2}/nghttp2-${TEST_NGHTTP2}.tar.xz" |
               tar -xJf -
           cd nghttp2-${TEST_NGHTTP2}
           ./configure --prefix=$HOME/root/nghttp2 --enable-lib-only
           make $MFLAGS
           make install
           touch $HOME/root/nghttp2-is-${TEST_NGHTTP2}
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

if test -v PHP_FPM -a ! -v SKIP_TESTING; then
    # Sanity test the php-fpm executable exists.
    $PHP_FPM --version || exit 1
fi
