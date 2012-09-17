#!perl -w
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

package DocUtil;
use base 'Exporter';

# against fat fingers
use strict;
use vars qw($ignore_files %suffix2lang @EXPORT_OK);

use base 'Exporter';
@EXPORT_OK = qw($ignore_files %suffix2lang docpath srcinfo prefix);

# determine ignorable files
my $ignore_ext = qr/\.(?:bak|rej|orig|meta|[^.]*~)$/i;
my $ignore_dot = qr/^\./;

$ignore_files = qr/(?:$ignore_dot)|(?:$ignore_ext)/;

# translation table taken from httpd.conf:
# (only to be used if lang != suffix)
%suffix2lang = (
    dk => 'da',
    po => 'pl',
);

# compute the absolute path of a relative docpath
use Cwd;
use File::Spec;

my $docroot = $ENV{DOCROOT};
my ($rvol, $dir) = File::Spec->splitpath($docroot, 1);
my @dirs = File::Spec->splitdir($dir);

sub docpath(;$) {
    my $addpath = shift;
    $addpath = '' unless defined $addpath;

    my @addpaths = grep length => split('/+' => $addpath);
    my $file = '';
    $file = pop @addpaths if @addpaths;

    File::Spec->catpath(
        $rvol,
        File::Spec->catdir(@dirs, @addpaths),
        $file
    );
}

sub srcinfo(;$) {
    my ($vol, $dir, $basename) = File::Spec->splitpath(shift or $ARGV[1]);

    die "Call error, CWD must be the doc root directory, stopped"
        if ($rvol ne $vol);
        
    my $docpath = File::Spec->abs2rel(
        File::Spec->catpath($vol, $dir, ''),
        $docroot
    );

    # remove suffix from basename
    $basename =~ s/\Q$ARGV[0]\E$//;

    # use HTTP path separators (/)
    $docpath = join '/' => ('', File::Spec->splitdir($docpath), '');
    1 while ($docpath =~ s,/\./,/,g); # something's bogus on the Mac otherwise
    $docpath =~ y,/,/,s; # squeeze multiple slashes

    # compute relative (HTTP-)path from srcfile to docroot
    my $relative = (join '/' => ('..') x ($docpath =~ y,/,, - 1)) || '.';

    # address metafile
    my $metafile = "$docpath$basename.xml.meta";

    ($docpath, $basename, $relative, $metafile);
}

sub prefix(@) {
    my ($vol, $dir) = File::Spec->splitpath($ARGV[1], 1);

    map {File::Spec->catpath($vol, $dir, $_)} @_;
}

42;
