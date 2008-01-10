#!/usr/local/bin/perl
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


# logresolve.pl
#
# v 1.2 by robh @ imdb.com
# 
# usage: logresolve.pl <infile >outfile
#
# input = Apache/NCSA/.. logfile with IP numbers at start of lines
# output = same logfile with IP addresses resolved to hostnames where
#  name lookups succeeded.
#
# this differs from the C based 'logresolve' in that this script
# spawns a number ($CHILDREN) of subprocesses to resolve addresses
# concurrently and sets a short timeout ($TIMEOUT) for each lookup in
# order to keep things moving quickly.
#
# the parent process handles caching of IP->hostnames using a Perl hash
# it also avoids sending the same IP to multiple child processes to be
# resolved multiple times concurrently.
#
# Depending on the settings of $CHILDREN and $TIMEOUT you should see
# significant reductions in the overall time taken to resolve your
# logfiles. With $CHILDREN=40 and $TIMEOUT=5 I've seen 200,000 - 300,000
# logfile lines processed per hour compared to ~45,000 per hour
# with 'logresolve'.
#
# I haven't yet seen any noticable reduction in the percentage of IPs
# that fail to get resolved. Your mileage will no doubt vary. 5s is long
# enough to wait IMO.
#
# Known to work with FreeBSD 2.2
# Known to have problems with Solaris
#
# 980417 - use 'sockaddr_un' for bind/connect to make the script work
#  with linux. Fix from Luuk de Boer <luuk_de_boer@pi.net>

require 5.004;

$|=1;

use FileHandle;
use Socket;

use strict;
no strict 'refs';

use vars qw($PROTOCOL);
$PROTOCOL = 0;

my $CHILDREN = 40;
my $TIMEOUT  = 5;

my $filename;
my %hash = ();
my $parent = $$;

my @children = ();
for (my $child = 1; $child <=$CHILDREN; $child++) {
	my $f = fork();	
	if (!$f) {
		$filename = "./.socket.$parent.$child";
		if (-e $filename) { unlink($filename) || warn "$filename .. $!\n";}
		&child($child);
		exit(0);
	}
	push(@children, $f);
}

&parent;
&cleanup;

## remove all temporary files before shutting down
sub cleanup {
	 # die kiddies, die
	kill(15, @children);
	for (my $child = 1; $child <=$CHILDREN; $child++) {
		if (-e "./.socket.$parent.$child") {
			unlink("./.socket.$parent.$child")
				|| warn ".socket.$parent.$child $!";
		}
	}
}
	
sub parent {
	# Trap some possible signals to trigger temp file cleanup
	$SIG{'KILL'} = $SIG{'INT'} = $SIG{'PIPE'} = \&cleanup;

	my %CHILDSOCK;
	my $filename;
 
	 ## fork child processes. Each child will create a socket connection
	 ## to this parent and use an unique temp filename to do so.
	for (my $child = 1; $child <=$CHILDREN; $child++) {
		$CHILDSOCK{$child}= FileHandle->new;

		if (!socket($CHILDSOCK{$child}, AF_UNIX, SOCK_STREAM, $PROTOCOL)) {
			warn "parent socket to child failed $!";
		}
		$filename = "./.socket.$parent.$child";
		my $response;
		do {
			$response = connect($CHILDSOCK{$child}, sockaddr_un($filename));
			if ($response != 1) {
				sleep(1);
			}                       
		} while ($response != 1);
		$CHILDSOCK{$child}->autoflush;
	}
	## All child processes should now be ready or at worst warming up 

	my (@buffer, $child, $ip, $rest, $hostname, $response);
	 ## read the logfile lines from STDIN
	while(<STDIN>) {
		@buffer = ();	# empty the logfile line buffer array.
		$child = 1;		# children are numbered 1..N, start with #1

		# while we have a child to talk to and data to give it..
		do {
			push(@buffer, $_);					# buffer the line
			($ip, $rest) = split(/ /, $_, 2);	# separate IP form rest

			unless ($hash{$ip}) {				# resolve if unseen IP
				$CHILDSOCK{$child}->print("$ip\n"); # pass IP to next child
				$hash{$ip} = $ip;				# don't look it up again.
				$child++;
			}
		} while (($child < ($CHILDREN-1)) and ($_ = <STDIN>));

		 ## now poll each child for a response
		while (--$child > 0) { 
			$response = $CHILDSOCK{$child}->getline;
			chomp($response);
			 # child sends us back both the IP and HOSTNAME, no need for us
			 # to remember what child received any given IP, and no worries
			 # what order we talk to the children
			($ip, $hostname) = split(/\|/, $response, 2);
			$hash{$ip} = $hostname;
		}

		 # resolve all the logfiles lines held in the log buffer array..
		for (my $line = 0; $line <=$#buffer; $line++) {
			 # get next buffered line
			($ip, $rest) = split(/ /, $buffer[$line], 2);
			 # separate IP from rest and replace with cached hostname
			printf STDOUT ("%s %s", $hash{$ip}, $rest);
		}
	}
}

########################################

sub child {
	 # arg = numeric ID - how the parent refers to me
	my $me = shift;

	 # add trap for alarm signals.
	$SIG{'ALRM'} = sub { die "alarmed"; };

	 # create a socket to communicate with parent
	socket(INBOUND, AF_UNIX, SOCK_STREAM, $PROTOCOL)
		|| die "Error with Socket: !$\n";
	$filename = "./.socket.$parent.$me";
	bind(INBOUND, sockaddr_un($filename))
		|| die "Error Binding $filename: $!\n";
	listen(INBOUND, 5) || die "Error Listening: $!\n";

	my ($ip, $send_back);
	my $talk = FileHandle->new;

	 # accept a connection from the parent process. We only ever have
	 # have one connection where we exchange 1 line of info with the
	 # parent.. 1 line in (IP address), 1 line out (IP + hostname).
	accept($talk, INBOUND) || die "Error Accepting: $!\n";
	 # disable I/O buffering just in case
	$talk->autoflush;
	 # while the parent keeps sending data, we keep responding..
	while(($ip = $talk->getline)) {
		chomp($ip);
		 # resolve the IP if time permits and send back what we found..
		$send_back = sprintf("%s|%s", $ip, &nslookup($ip));
		$talk->print($send_back."\n");
	}
}

# perform a time restricted hostname lookup.
sub nslookup {
	 # get the IP as an arg
	my $ip = shift;
	my $hostname = undef;

	 # do the hostname lookup inside an eval. The eval will use the
	 # already configured SIGnal handler and drop out of the {} block
	 # regardless of whether the alarm occured or not.
	eval {
		alarm($TIMEOUT);
		$hostname = gethostbyaddr(gethostbyname($ip), AF_INET);
		alarm(0);
	};
	if ($@ =~ /alarm/) {
		 # useful for debugging perhaps..
		# print "alarming, isn't it? ($ip)";
	}

	 # return the hostname or the IP address itself if there is no hostname
	$hostname ne "" ? $hostname : $ip;
}


