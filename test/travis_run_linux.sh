#!/bin/bash -ex

# Test for empty APLOGNO() macro use; if the script changes
# any files, the git diff will be non-empty and fail.
if test -v TEST_LOGNO; then
    find server modules os -name \*.c | xargs perl \
		docs/log-message-tags/update-log-msg-tags
    git diff --exit-code .
    : PASSED
    exit 0
fi

### Installed apr/apr-util don't include the *.m4 files but the
### Debian packages helpfully install them, so use the system APR to buildconf
./buildconf --with-apr=/usr/bin/apr-1-config ${BUILDCONFIG}

PREFIX=${PREFIX:-$HOME/build/httpd-root}

# For trunk, "make check" is sufficient to run the test suite.
# For 2.4.x, the test suite must be run manually
if test ! -v SKIP_TESTING; then
    CONFIG="$CONFIG --enable-load-all-modules"
    if grep -q ^check: Makefile.in; then
        CONFIG="--with-test-suite=test/perl-framework $CONFIG"
        WITH_TEST_SUITE=1
    fi
fi
if test -v APR_VERSION; then
    CONFIG="$CONFIG --with-apr=$HOME/root/apr-${APR_VERSION}"
else
    CONFIG="$CONFIG --with-apr=/usr"
fi
if test -v APU_VERSION; then
    CONFIG="$CONFIG --with-apr-util=$HOME/root/apr-util-${APU_VERSION}"
else
    CONFIG="$CONFIG --with-apr-util=/usr"
fi

./configure --prefix=$PREFIX $CONFIG
make $MFLAGS

if test -v TEST_INSTALL; then
   make install
   pushd $PREFIX
     test `./bin/apxs -q PREFIX` = $PREFIX
     test `$PWD/bin/apxs -q PREFIX` = $PREFIX
     ./bin/apxs -g -n foobar
     cd foobar; make
   popd
fi

if ! test -v SKIP_TESTING; then
    set +e

    if test -v TEST_MALLOC; then
        # Enable enhanced glibc malloc debugging, see mallopt(3)
        export MALLOC_PERTURB_=65 MALLOC_CHECK_=3
        export LIBC_FATAL_STDERR_=1
    fi

    if test -v TEST_UBSAN; then
        export UBSAN_OPTIONS="log_path=$PWD/ubsan.log"
    fi

    if test -v WITH_TEST_SUITE; then
        make check TESTS="${TESTS}" TEST_CONFIG="${TEST_ARGS}"
        RV=$?
    else
        test -v TEST_INSTALL || make install
        pushd test/perl-framework
            perl Makefile.PL -apxs $PREFIX/bin/apxs
            make test APACHE_TEST_EXTRA_ARGS="${TEST_ARGS} ${TESTS}"
            RV=$?
        popd
    fi

    if test -v TEST_SSL -a $RV -eq 0; then
        pushd test/perl-framework
            # A test suite run with SSLSessionCache defined (see t/conf/ssl.conf.in)
            ./t/TEST -defines TEST_SSL_SESSCACHE t/ssl
            RV=$?
            if test $RV -eq 0; then
                # A test suite run with "SSLProtocol TLSv1.2" (see t/conf/ssl.conf.in)
                ./t/TEST -sslproto TLSv1.2 t/ssl
                RV=$?
            fi
        popd
    fi

    if test -v LITMUS -a $RV -eq 0; then
        pushd test/perl-framework
           mkdir -p t/htdocs/modules/dav
           ./t/TEST -start
           # litmus uses $TESTS, so unset it.
           unset TESTS
           litmus http://localhost:8529/modules/dav/
           RV=$?
           ./t/TEST -stop
        popd
    fi

    if grep -q 'Segmentation fault' test/perl-framework/t/logs/error_log; then
        grep --color=always -C5 'Segmentation fault' test/perl-framework/t/logs/error_log
        RV=2
    fi

    if test -v TEST_UBSAN && ls ubsan.log.* &> /dev/null; then
        cat ubsan.log.*
        RV=3
    fi

    # With LIBC_FATAL_STDERR_/MALLOC_CHECK_ glibc will abort when
    # malloc errors are detected.  This should get caught by the
    # segfault grep above, but in case it is not, catch it here too:
    if grep 'glibc detected' test/perl-framework/t/logs/error_log; then
        grep --color=always -C20 'glibc detected' test/perl-framework/t/logs/error_log
        RV=4
    fi

    exit $RV
fi
