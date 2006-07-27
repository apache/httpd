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

use IO::File;
use File::Find;

chdir '..';
find(\&tovc5, '.');

sub tovc5 { 

    if (m|.dsp$|) {
        $oname = $_;
	$tname = '.#' . $_;
        $verchg = 0;
	$srcfl = new IO::File $oname, "r" || die;
	$dstfl = new IO::File $tname, "w" || die;
	while ($src = <$srcfl>) {
	    if ($src =~ s|Format Version 6\.00|Format Version 5\.00|) {
		$verchg = -1;
	    }
	    if ($src =~ s|^(# ADD CPP .*)/ZI (.*)|$1/Zi $2|) {
		$verchg = -1;
	    }
	    if ($src =~ s|^(# ADD BASE CPP .*)/ZI (.*)|$1/Zi $2|) {
		$verchg = -1;
	    }
	    if ($src !~ m|^# PROP AllowPerConfigDependencies|) {
		print $dstfl $src; }
	    else {
		$verchg = -1;

	    }
	}
	undef $srcfl;
	undef $dstfl;
	if ($verchg) {
	    unlink $oname || die;
	    rename $tname, $oname || die;
	    print "Converted VC6 project " . $oname . " to VC5 in " . $File::Find::dir . "\n"; 
	}
	else {
	    unlink $tname;
	}
    }
}
