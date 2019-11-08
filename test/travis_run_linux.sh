#!/bin/bash -ex
./buildconf --with-apr=/usr/bin/apr-1-config
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
./configure $CONFIG --with-apr=/usr --with-apr-util=/usr
make $MAKEFLAGS -j2
if ! test -v SKIP_TESTING; then
    if test -v WITH_TEST_SUITE; then
        make check
    else
        make install
        cd test/perl-framework
        perl Makefile.PL -apxs $HOME/build/httpd-root/bin/apxs
        make test
    fi
fi
