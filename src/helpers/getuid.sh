#!/bin/sh
# Return the uid of the process being run. If we cannot
# determine what it is, return '?'.
#
# Initially written by Jim Jagielski for the Apache configuration mechanism
#
# This script falls under the Apache License.
# See http://www.apache.org/docs/LICENSE

# First we try 'id'
if AP_IDPATH=`./src/helpers/PrintPath id` ; then
    # See if it's a POSIX 'id'
    if AP_RETVAL=`$AP_IDPATH -u 2>/dev/null` ; then
	echo $AP_RETVAL
	exit 0
    else
	AP_RETVAL=`$AP_IDPATH | \
	    sed -e 's/^.*uid=//' | \
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
if AP_WHOAMI=`./src/helpers/PrintPath whoami` ; then
    AP_LOGNAME=`$AP_WHOAMI`
else
    if AP_LOGNAME=`who am i | sed -e 's/[ 	]*.*$//'` ; then
	:
    else
	AP_LOGNAME=$LOGNAME
    fi
fi

#
# See if we have a valid login name.
#
if [ "x$AP_LOGNAME" = "x" ]; then
    echo "?"
    exit 1
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
