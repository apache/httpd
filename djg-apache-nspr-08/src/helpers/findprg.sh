#!/bin/sh
##
##  findprg.sh -- find a program
##
##  Look for one or more programs somewhere in $PATH (or the -p argument).
##  Will print out the full pathname unless called with the -s
##  (silence) option.
##
##  Written by Ralf S. Engelschall <rse@apache.org> for the
##  Apache's Autoconf-style Interface (APACI)
##
##  Usage: findprg.sh [-s] [-pPATH] name [name ...]
##

#   parameters
silent=no
pathlist=$PATH
namelist=''

#   parse argument line
for opt
do
    case $opt in
        -s  ) silent=yes ;;
        -p* ) pathlist="`echo $opt | cut -c3-`" ;;
        *   ) namelist="$namelist $opt" ;;
    esac
done

#   check whether the test command supports the -x option
testfile="findprg.t.$$"
cat >$testfile <<EOT
#!/bin/sh
if [ -x / ] || [ -x /bin ] || [ -x /bin/ls ]; then
    exit 0
fi
exit 1
EOT
if /bin/sh $testfile 2>/dev/null; then
    minusx="-x"
else
    minusx="-r"
fi
rm -f $testfile

paths="`echo $pathlist |\
	 sed -e 's/^:/.:/' \
	     -e 's/::/:.:/g' \
	     -e 's/:$/:./' \
	     -e 's/:/ /g'`"
#   iterate over names
for name in $namelist; do
    #   iterate over paths
    for path in $paths; do
        if [ $minusx "$path/$name" ] && [ ! -d "$path/$name" ]; then
            if [ "$silent" != "yes" ]; then
                echo "$path/$name"
            fi
            #   found!
            exit 0
        fi
    done
done

#   not found!
exit 1
