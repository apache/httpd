#! /bin/sh

exec >$1
exec <$2

echo "/* This is an ugly hack that needs to be here, so that libtool will"
echo " * link all of the APR functions into server regardless of whether"
echo " * the base server uses them."
echo " */"
echo ""
 
cd srclib/apr/include 
for file in *.h
do
    echo "#include \"$file\""
done
cd ../../../
echo ""

awk -f build/buildexports.awk

echo ""
echo "void *ap_ugly_hack;"
exit 0
