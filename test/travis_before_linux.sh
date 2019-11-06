#!/bin/bash -ex
svn export -q https://svn.apache.org/repos/asf/apr/apr/trunk srclib/apr
if ! test -v SKIP_TESTING; then
   svn export -q https://svn.apache.org/repos/asf/httpd/test/framework/trunk test/perl-framework
fi
