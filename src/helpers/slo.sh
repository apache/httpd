#!/bin/sh
##
##  slo.h -- (S)eparate (L)inker (O)ptions by library class
##  Written by Ralf S. Engelschall <rse@apache.org>
##
#
# This script falls under the Apache License.
# See http://www.apache.org/docs/LICENSE


DIFS=' 	
'

#   
#   parse out -L and -l options from command line
#
DIRS=''
LIBS=''
ARGV=''
optprev=""
OIFS="$IFS" IFS="$DIFS"
for opt
do
    #   concatenate with previous option if exists
    if [ ".$optprev" != . ]; then
        opt="${optprev}${opt}";
        optprev=''
    fi
    #   remember options for arg when used stand-alone
    if [ ".$opt" = ".-L" -o ".$opt" = ".-l" ]; then
        optprev="$opt"
        continue;
    fi
    #   split argument into option plus option argument
    arg="`echo $opt | cut -c3-`"
    opt="`echo $opt | cut -c1-2`"
    #   store into containers
    case $opt in
        -L) DIRS="$DIRS:$arg" ;;
        -l) LIBS="$LIBS:$arg" ;;
         *) ARGV="$ARGV $opt" ;;
    esac
done
IFS="$OIFS"

#
#   set linker default directories
#
DIRS_DEFAULT='/lib:/usr/lib'
if [ ".$LD_LIBRARY_PATH" != . ]; then
    DIRS_DEFAULT="$DIRS_DEFAULT:$LD_LIBRARY_PATH"
fi

#
#   sort options by class
#
DIRS_OBJ=''
LIBS_OBJ=''
DIRS_PIC=''
LIBS_PIC=''
DIRS_DSO=''
LIBS_DSO=''

#    for each library...
OIFS="$IFS" IFS=':'
for lib in $LIBS; do
    [ ".$lib" = . ] && continue

    found='no'
    found_indefdir='no'
    found_type=''
    found_dir=''

    #    for each directory...
    OIFS2="$IFS" IFS=":$DIFS"
    for dir in ${DIRS} switch-to-defdirs ${DIRS_DEFAULT}; do
        [ ".$dir" = . ] && continue
        [ ".$dir" = .switch-to-defdirs ] && found_indefdir=yes
        [ ! -d $dir ] && continue

        #    search the file
        OIFS3="$IFS" IFS="$DIFS"
        for file in '' `cd $dir && ls lib${lib}.* 2>/dev/null`; do
             [ ".$file" = . ] && continue
             case $file in
                 *.so|*.so.[0-9]*|*.sl|*.sl.[0-9]* )
                      found=yes;
                      found_type=DSO; 
                      break 
                      ;;
                 *.lo|*.la )
                      found=yes;
                      found_type=PIC 
                      ;;
                 *.a )
                      if [ ".$found_type" = . ]; then
                          found=yes
                          found_type=OBJ 
                      fi
                      ;;
             esac
        done
        IFS="$OIFS3"
        if [ ".$found" = .yes ]; then
            found_dir="$dir"
            break
        fi
    done
    IFS="$OIFS2"

    if [ ".$found" = .yes ]; then
        if [ ".$found_indefdir" != .yes ]; then
            eval "dirlist=\"\${DIRS_${found_type}}:\""
            if [ ".`echo \"$dirlist\" | fgrep :$found_dir:`" = . ]; then
                eval "DIRS_${found_type}=\"\$DIRS_${found_type}:${found_dir}\""
            fi
            eval "LIBS_${found_type}=\"\$LIBS_${found_type}:$lib\""
        else
            eval "LIBS_${found_type}=\"\$LIBS_${found_type}:$lib\""
        fi
    else
        LIBS_OBJ="$LIBS_OBJ:$lib"
        #dirlist="`echo $DIRS $DIRS_DEFAULT | sed -e 's/:/ /g'`"
        #echo "splitlibs:Warning: library \"$lib\" not found in any of the following dirs:" 2>&1
        #echo "splitlibs:Warning: $dirlist" 1>&1
    fi
done
IFS="$OIFS"

#
#   also pass-through unused dirs even if it's useless
#
OIFS="$IFS" IFS=':'
for dir in $DIRS; do
    dirlist="${DIRS_OBJ}:${DIRS_PIC}:${DIRS_DSO}:"
    if [ ".`echo \"$dirlist\" | fgrep :$dir:`" = . ]; then
        DIRS_OBJ="$DIRS_OBJ:$dir"
    fi
done
IFS="$OIFS"

#
#   reassemble the options but seperated by type
#
OIFS="$IFS" IFS="$DIFS"
for type in OBJ PIC DSO; do
    OIFS2="$IFS" IFS=':'
    eval "libs=\"\$LIBS_${type}\""
    opts=''
    for lib in $libs; do
        [ ".$lib" = . ] && continue
        opts="$opts -l$lib"
    done
    eval "LIBS_${type}=\"$opts\""

    eval "dirs=\"\$DIRS_${type}\""
    opts=''
    for dir in $dirs; do
        [ ".$dir" = . ] && continue
        opts="$opts -L$dir"
    done
    eval "DIRS_${type}=\"$opts\""
    IFS="$OIFS2"
done
IFS="$OIFS"

#
#   give back results
#
OIFS="$IFS" IFS="$DIFS"
for var in ARGV DIRS_OBJ LIBS_OBJ DIRS_PIC LIBS_PIC DIRS_DSO LIBS_DSO; do
    eval "val=\"\$${var}\""
    val="`echo $val | sed -e 's/^ *//'`"
    echo "SLO_${var}=\"${val}\""
done
IFS="$OIFS"

##EOF##
