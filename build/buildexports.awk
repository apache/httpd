{
    if ($1 ~ /^APR_/)
        print "#if", $1;
    if ($1 ~ /^apr?_/)
        print "const void *ap_hack_" $1 " = (const void *)" $1 ";";
    if ($1 ~ /^\/APR_/)
        print "#endif /*", substr($1,2), "*/";
}
