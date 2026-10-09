foreach $i (1..5) {
print <<EOT1
HTTP/1.1 100 Continue
Server: Sausages/1.0

EOT1
;
}

print <<EOT2
HTTP/1.1 200 OK
Content-Type: text/html

Hello world
EOT2
;
