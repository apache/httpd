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

while read LINE
do
    if [ "x`echo $LINE | egrep  '^[:space:]*APR_'`" != "x" ]; then
        ifline=`echo "$LINE" |\
            sed -e 's%^\(.*\)%\#if \1%'`
        echo $ifline
    fi
    if [ "x`echo $LINE | egrep  '^[:space:]*apr_'`" != "x" ]; then
#        newline=`echo "$LINE" |\
#            sed -e 's%^\(.*\)%extern const void *\1\\(void\);%'`
#        echo $newline
        newline=`echo "$LINE" |\
            sed -e 's%^\(.*\)%const void *ap_hack_\1 = \(const void *\)\1\;%'`
        echo $newline
    fi
    if [ "x`echo $LINE | egrep  '^[:space:]*\/APR_'`" != "x" ]; then
        endline=`echo "$LINE" |\
            sed -e 's%^\/\(.*\)%\#endif \/\*\1\*\/%'`
        echo "$endline"
    fi
done

echo ""
echo "void *ap_ugly_hack;"
exit 0
