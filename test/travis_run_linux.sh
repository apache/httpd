#!/bin/bash -ex

# Test for APLOGNO() macro errors (duplicates, empty args) etc.  For
# trunk, run the updater script to see if it fails.  If it succeeds
# and changes any files (because there was a missing argument), the
# git diff will be non-empty, so fail for that case too.  For
# non-trunk use a grep and only catch the empty argument case.
if test -v TEST_LOGNO; then
    if test -f docs/log-message-tags/update-log-msg-tags; then
        find server modules os -name \*.c | \
            xargs perl docs/log-message-tags/update-log-msg-tags
        git diff --exit-code .
        : PASSED
        exit 0
    else
        set -o pipefail
        if find server modules os -name \*.c | \
                xargs grep -C1 --color=always 'APLOGNO()'; then
            : FAILED
            exit 1
        else
            : PASSED
            exit 0
        fi
    fi
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

    if test -v TEST_ASAN; then
        export ASAN_OPTIONS="log_path=$PWD/asan.log"
    fi

    # Try to keep all potential coredumps from all processes
    sudo sysctl -w kernel.core_uses_pid=1 2>/dev/null || true

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

    # Skip further testing if a core dump was created during the test
    # suite run above.
    if test $RV -eq 0 && ls test/perl-framework/t/core test/perl-framework/t/core.* &>/dev/null; then
        RV=4
    fi            
    
    if test -v TEST_SSL -a $RV -eq 0; then
        pushd test/perl-framework
            for cache in shmcb redis:localhost:6379 memcache:localhost:11211; do
                SSL_SESSCACHE=$cache ./t/TEST -sslproto TLSv1.2 -defines TEST_SSL_SESSCACHE t/ssl
                RV=$?
                test $RV -eq 0 || break
            done
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

    # Catch cases where abort()s get logged to stderr by libraries but
    # only cause child processes to terminate e.g. during shutdown,
    # which may not otherwise trigger test failures.

    # "glibc detected": printed with LIBC_FATAL_STDERR_/MALLOC_CHECK_
    # glibc will abort when malloc errors are detected.  This will get
    # caught by the segfault grep as well.

    # "pool concurrency check": printed by APR built with
    # --enable-thread-debug when an APR pool concurrency check aborts

    for phrase in 'Segmentation fault' 'glibc detected' 'pool concurrency check:' 'Assertion.*failed'; do
        if grep -q "$phrase" test/perl-framework/t/logs/error_log; then
            grep --color=always -C5 "$phrase" test/perl-framework/t/logs/error_log
            RV=2
        fi
    done

    if test -v TEST_UBSAN && ls ubsan.log.* &> /dev/null; then
        cat ubsan.log.*
        RV=3
    fi

    if test -v TEST_ASAN && ls asan.log.* &> /dev/null; then
        cat asan.log.*

        # ASan can report memory leaks, fail on errors only
        if grep -q "ERROR: AddressSanitizer:" `ls asan.log.*`; then
            RV=4
        fi
    fi

    shopt -s nullglob 
    for core in test/perl-framework/t/core* ; do
        gdb -ex 'thread apply all backtrace full' -batch ./httpd "$core"
        RV=5
    done

    exit $RV
fi
