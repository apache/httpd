#! /bin/sh

outfile=$1
exec >$outfile
shift

echo "/* This is an ugly hack that needs to be here, so that libtool will"
echo " * link all of the APR functions into server regardless of whether"
echo " * the base server uses them."
echo " */"
echo ""

for dir in srclib/apr/include srclib/apr-util/include
do
    cd $dir
    for file in *.h
    do
        echo "#include \"$file\""
    done
    cd ../../../
done
echo ""

for file
do
    exec <$file
    awk -f build/buildexports.awk
done

echo ""
echo "void *ap_ugly_hack;"
exit 0
