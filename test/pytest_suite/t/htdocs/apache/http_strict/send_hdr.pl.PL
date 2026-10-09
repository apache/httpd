use MIME::Base64;
use strict;
use warnings;

print "Content-type: text/plain\r\n";
print decode_base64($ENV{QUERY_STRING}), "\r\n";
print "\r\n";
print "Hi!\n";
print "SERVERNAME=$ENV{SERVER_NAME}\n";
print "HTTP_HOST=$ENV{HTTP_HOST}\n";
