#!/bin/sh
# Return the uid of the process being run. If we cannot
# determine what it is, return '?'.
#
# Initially written by Jim Jagielski for the Apache configuration mechanism
#
# This script falls under the Apache License.
# See http://www.apache.org/docs/LICENSE

# First we try 'id'
if `./src/helpers/PrintPath -s id` ; then
    AP_IDPATH=`./src/helpers/PrintPath id`
    # See if it's a POSIX 'id'
    if `$AP_IDPATH -u >/dev/null 2>&1` ; then
	AP_RETVAL=`$AP_IDPATH -u` 
	echo $AP_RETVAL
	exit 0
    else
	AP_RETVAL=`$AP_IDPATH | \
	    sed -e 's/^.*uid[ 	]*=[ 	]*[^0123456789]*//' | \
	    sed -e 's/[ 	]*(.*$//'`
	echo $AP_RETVAL
	exit 0
    fi
fi

#
# Ugg. Now we have to grab the login name of the process, and
# scan /etc/passwd.
#
# Try 'whoami' first, then 'who am i' (making sure to strip away
# the who crud) and finally just copy $LOGNAME
#
if `./src/helpers/PrintPath -s whoami` ; then
    AP_WAIPATH=`./src/helpers/PrintPath whoami`
    AP_LOGNAME=`$AP_WAIPATH`
else
    AP_LOGNAME=`who am i | tail -1 | sed -e 's/[ 	][ 	]*.*$//'`
fi

#
# See if we have a valid login name.
#
if [ "x$AP_LOGNAME" = "x" ]; then
    AP_LOGNAME=$LOGNAME
    if [ "x$AP_LOGNAME" = "x" ]; then
	echo "?"
	exit 1
    fi
fi

#
# Ok, now we scan through /etc/passwd
#
AP_RETVAL=`egrep \^${AP_LOGNAME}: /etc/passwd | \
	sed -e 's/[^:]*:[^:]*://' | \
	sed -e 's/:.*$//'`

if [ "x$AP_RETVAL" = "x" ]; then
    echo "?"
    exit 1
else
    echo $AP_RETVAL
    exit 0
fi
