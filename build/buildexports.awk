/^APR_/     { print "#if", $1 }
/^\t*apr?_/ { print "const void *ap_hack_" $1 " = " $1 ";" }
/^\/APR_/   { print "#endif /*", substr($1,2), "*/" }
