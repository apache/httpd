#! /bin/sh

exec >$1
exec <$2

echo "/* This is an ugly hack that needs to be here, so that libtool will"
echo " * link all of the APR functions into server regardless of whether"
echo " * the base server uses them."
echo " */"

echo ""

while read LINE
do
    if [ "x`echo $LINE | egrep  '^[:space:]*apr_'`" != "x" ]; then
        newline=`echo "$LINE" |\
            sed -e 's%^\(.*\)%extern const void *\1\\(void\);%'`
        echo $newline
        newline=`echo "$LINE" |\
            sed -e 's%^\(.*\)%const void *ap_hack_\1 = \(const void *\)\1\;%'`
        echo $newline
    fi
done

echo ""
echo "void *ap_ugly_hack;"
exit 0
