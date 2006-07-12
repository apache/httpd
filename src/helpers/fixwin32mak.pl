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
#
#
# fixwin32mak.pl ::: Apache/Win32 maintanace program
#
# This program, launched from the build/ directory, replaces all nasty absoulute paths
# in the win32 .mak files with the appropriate relative root.
#
# Run this program prior to committing or packaging any newly exported make files.

use Cwd;
use IO::File;
use File::Find;

chdir '..';
$root = cwd;
$root =~ s|.:(.*)|cd "$1|;
$root =~ s|/|\\\\|g;
find(\&fixcwd, '.');

sub fixcwd { 
    if (m|.mak$|) {
	$repl = $File::Find::dir;
        $repl =~ s|^./||;
        $repl =~ s|[^\./]+|..|g;
        $repl =~ s|/|\\|;
        $oname = $_;
	$tname = '.#' . $_;
	$verchg = 0;
	$srcfl = new IO::File $_, "r" || die;
	$dstfl = new IO::File $tname, "w" || die;
	while ($src = <$srcfl>) {
	    if ($src =~ s|^(\s*)$root|$1cd "$repl|) {
		$verchg = -1;
	    }
            print $dstfl $src; 
	}
	undef $srcfl;
	undef $dstfl;
	if ($verchg) {
	    unlink $oname || die;
	    rename $tname, $oname || die;
	    print "Corrected absolute paths within " . $oname . " in " . $File::Find::dir . "\n"; 
	}
	else {
	    unlink $tname;
	}
    }
}
