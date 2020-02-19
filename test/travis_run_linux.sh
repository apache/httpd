#!/bin/bash -ex
### Installed apr/apr-util don't include the *.m4 files but the
### Debian packages helpfully install them, so use the system APR to buildconf
./buildconf --with-apr=/usr/bin/apr-1-config ${BUILDCONFIG}
# For trunk, "make check" is sufficient to run the test suite.
# For 2.4.x, the test suite must be run manually
if test ! -v SKIP_TESTING; then
    CONFIG="$CONFIG --enable-load-all-modules"
    if grep -q ^check: Makefile.in; then
        CONFIG="--with-test-suite=test/perl-framework $CONFIG"
        WITH_TEST_SUITE=1
    else
        CONFIG="--prefix=$HOME/build/httpd-root $CONFIG"
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
./configure $CONFIG
make $MFLAGS

if ! test -v SKIP_TESTING; then
    set +e

    if test -v TEST_UBSAN; then
        export UBSAN_OPTIONS="log_path=$PWD/ubsan.log"
    fi

    if test -v WITH_TEST_SUITE; then
        make check TESTS="${TEST_ARGS}"
        RV=$?
    else
        make install
        pushd test/perl-framework
            perl Makefile.PL -apxs $HOME/build/httpd-root/bin/apxs
            make test APACHE_TEST_EXTRA_ARGS="${TEST_ARGS}"
            RV=$?
        popd
    fi
    if test -v LITMUS; then
        pushd test/perl-framework
           mkdir -p t/htdocs/modules/dav
           ./t/TEST -start
           litmus http://localhost:8529/modules/dav/
           RV=$?
           ./t/TEST -stop
        popd
    fi

    if grep -q 'Segmentation fault' test/perl-framework/t/logs/error_log; then
        grep -C5 'Segmentation fault' test/perl-framework/t/logs/error_log
        RV=2
    fi
    if test -v TEST_UBSAN && ls ubsan.log.* &> /dev/null; then
        cat ubsan.log.*
        RV=3
    fi

    exit $RV
fi
