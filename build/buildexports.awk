/^(APR?_|defined)/     { print "#if", $1 }
/^\t*apr?_/ { print "const void *ap_hack_" $1 " = (const void *)" $1 ";" }
/^\/(APR?_|defined)/   { print "#endif /*", substr($1,2), "*/" }
