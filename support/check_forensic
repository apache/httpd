#!/bin/sh

# check_forensic <forensic log file>

# check the forensic log for requests that did not complete
# output the request log for each one

F=$1

temp_create_method=file
if test -f `which mktemp`; then
  temp_create_method=mktemp
elif test -f `which tempfile`; then
  temp_create_method=tempfile
fi

create_temp()
{
  prefix=$1
  case "$temp_create_method" in
    file)
      name="/tmp/$1.$$"
      ;;
    mktemp)
      name=`mktemp -t $1.XXXXXX`
      ;;
    tempfile)
      name=`tempfile --prefix=$1`
      ;;
    *)
      echo "$0: Cannot create temporary file"
      exit 1
      ;;
  esac
}

create_temp fcall
all=$name
create_temp fcin
in=$name
create_temp fcout
out=$name
trap "rm -f -- \"$all\" \"$in\" \"$out\";" 0 1 2 3 13 15

cut -f 1 -d '|' $F  > $all
grep + < $all | cut -c2- | sort > $in
grep -- - < $all | cut -c2- | sort > $out

# use -i instead of -I for GNU xargs
join -v 1 $in $out | xargs -I xx egrep "^\\+xx" $F
exit 0
