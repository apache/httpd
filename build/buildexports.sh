#! /bin/sh

exec >$1
exec <$2

echo "/* This is an ugly hack that needs to be here, so that libtool will"
echo " * link all of the APR functions into server regardless of whether"
echo " * the base server uses them."
echo " */"
echo ""

cd lib/apr/include
for file in *.h
do
    echo "#include \"$file\""
done
cd ../../../
echo ""
echo ""

while read LINE
do
    if [ "x`echo $LINE | egrep  '^[:space:]*apr_'`" != "x" ]; then
        newline=`echo "$LINE" |\
            sed -e 's%^\(.*\)%void *ap_hack_\1 = \1\;%'`
        echo $newline
    fi
done

echo "void *ap_ugly_hack;"
exit 0
