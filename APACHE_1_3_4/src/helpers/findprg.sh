#!/bin/sh
#
# Usage: findprg.sh <program-name>
# Return value is the absolute path of the program if it was found.
# Initially written by Lars Eilebrecht <lars@apache.org>.
#
# This script falls under the Apache License.
# See http://www.apache.org/docs/LICENSE


if [ ".`which $1`" != . ]
then
  echo `which $1`
  exit 0
else
  PATH="/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin"
  if [ ".`which $1`" != . ]
  then
    echo `which $1`
    exit 0
  else
    exit 1
  fi
fi
