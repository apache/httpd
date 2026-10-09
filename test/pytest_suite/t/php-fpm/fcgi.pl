#!/usr/bin/env perl
use FCGI;
use Socket;
use FCGI::ProcManager;
use Data::Dumper;

$num_args = $#ARGV + 1;
if ($num_args != 1) {
  print "\nUsage: fcgi.pl <socket>\n";
  exit 1;
}

$proc_manager = FCGI::ProcManager->new( {n_processes => 1} );
$socket = FCGI::OpenSocket( $ARGV[0], 10 );
$request = FCGI::Request( \*STDIN, \*STDOUT, \*STDERR, \%req_params,
$socket, &FCGI::FAIL_ACCEPT_ON_INTR );
$proc_manager->pm_manage();
if ($request) {
  while ( $request->Accept() >= 0 ) {
    $proc_manager->pm_pre_dispatch();
    print("Content-type: text/plain\r\n\r\n");
    print Dumper(\%req_params);
  }
}
FCGI::CloseSocket($socket);
