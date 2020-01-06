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
    if test -v WITH_TEST_SUITE; then
        make check
    else
        make install
        cd test/perl-framework
        perl Makefile.PL -apxs $HOME/build/httpd-root/bin/apxs
        make test ${TEST_ARGS}
    fi
fi
