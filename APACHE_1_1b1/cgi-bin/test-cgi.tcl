#!/usr/local/bin/tclsh
# tcl-cgi.tcl
# robert.bagwill@nist.gov, no warranty, no rights reserved
# print out command line args, stdin, and environment variables
#
set envvars {SERVER_SOFTWARE SERVER_NAME GATEWAY_INTERFACE SERVER_PROTOCOL SERVER_PORT REQUEST_METHOD PATH_INFO PATH_TRANSLATED SCRIPT_NAME QUERY_STRING REMOTE_HOST REMOTE_ADDR REMOTE_USER AUTH_TYPE CONTENT_TYPE CONTENT_LENGTH HTTP_ACCEPT}

puts "Content-type: text/HTML\n"
puts "<HTML>"
puts "<HEAD>"
puts "<TITLE>CGI/1.0 TCL script report:</TITLE>"
puts "</HEAD>"

puts "<BODY>"
puts "<H1>Command Line Arguments</H1>"
puts "argc is $argc. argv is $argv."
puts ""

puts "<H1>Message</H1>"
puts "<PRE>"
set message [split [read stdin $env(CONTENT_LENGTH)] &]
foreach pair $message {
	set name [lindex [split $pair =] 0]
	set val [lindex [split $pair =] 1]
	regsub -all {\+} $val { } val
	# kludge to unescape chars
	regsub -all {\%0A} $val \n\t val
	regsub -all {\%2C} $val {,} val
	regsub -all {\%27} $val {'} val
	puts "$name\t= $val"
}
puts "</PRE>"

puts "<H1>Environment Variables</H1>"
puts "<DL>"
foreach var $envvars {
	if {[info exists env($var)]} {
		puts -nonewline "<DT>$var"
		eval {set val $env($var)}
		if {[llength $val] > 1} {
			puts "<DD>"
			foreach subval [lsort $val] {
				puts "$subval"
			}
		} else {
			puts "<DD>$val"
		}
	}
}
puts "</DL>"
puts "</BODY>"
puts "</HTML>"
######################
# end of tcl-cgi.tcl
######################

