#!/bin/bash -ex
./buildconf
test -v SKIP_TESTING || CONFIG="--with-test-suite=test/perl-framework $CONFIG"
./configure $CONFIG --with-apr=/usr --with-apr-util=/usr
make $MAKEFLAGS -j2
test -v SKIP_TESTING || make check
