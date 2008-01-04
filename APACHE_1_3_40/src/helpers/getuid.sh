#!/bin/sh
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#
# Return the uid of the process being run. If we cannot
# determine what it is, return '?'.
#
# Initially written by Jim Jagielski for the Apache configuration mechanism

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
