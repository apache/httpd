#!/bin/bash
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
# httpd        Startup script for the Apache Web Server
#
# chkconfig: - 85 15
# description: The Apache HTTP Server is an efficient and extensible  \
#             server implementing the current HTTP standards.
# processname: httpd
# pidfile: /var/run/httpd.pid
# config: /etc/sysconfig/httpd
#
### BEGIN INIT INFO
# Provides: httpd
# Required-Start: $local_fs $remote_fs $network $named
# Required-Stop: $local_fs $remote_fs $network
# Should-Start: distcache
# Short-Description: start and stop Apache HTTP Server
# Description: The Apache HTTP Server is an extensible server 
#  implementing the current HTTP standards.
### END INIT INFO

# Source function library.
. /etc/rc.d/init.d/functions

# What were we called? Multiple instances of the same daemon can be
# created by creating suitably named symlinks to this startup script
prog=$(basename $0 | sed -e 's/^[SK][0-9][0-9]//')

if [ -f /etc/sysconfig/${prog} ]; then
        . /etc/sysconfig/${prog}
fi

# Start httpd in the C locale by default.
HTTPD_LANG=${HTTPD_LANG-"C"}

# This will prevent initlog from swallowing up a pass-phrase prompt if
# mod_ssl needs a pass-phrase from the user.
INITLOG_ARGS=""

# Set HTTPD=/usr/sbin/httpd.worker in /etc/sysconfig/httpd to use a server
# with the thread-based "worker" MPM; BE WARNED that some modules may not
# work correctly with a thread-based MPM; notably PHP will refuse to start.

httpd=${HTTPD-/usr/sbin/httpd}
pidfile=${PIDFILE-/var/run/${prog}.pid}
lockfile=${LOCKFILE-/var/lock/subsys/${prog}}
RETVAL=0

# check for 1.3 configuration
check13 () {
	CONFFILE=/etc/httpd/conf/httpd.conf
	GONE="(ServerType|BindAddress|Port|AddModule|ClearModuleList|"
	GONE="${GONE}AgentLog|RefererLog|RefererIgnore|FancyIndexing|"
	GONE="${GONE}AccessConfig|ResourceConfig)"
	if grep -Eiq "^[[:space:]]*($GONE)" $CONFFILE; then
		echo
		echo 1>&2 " Apache 1.3 configuration directives found"
		echo 1>&2 " please read @docdir@/migration.html"
		failure "Apache 1.3 config directives test"
		echo
		exit 1
	fi
}

# The semantics of these two functions differ from the way apachectl does
# things -- attempting to start while running is a failure, and shutdown
# when not running is also a failure.  So we just do it the way init scripts
# are expected to behave here.
start() {
        echo -n $"Starting $prog: "
        check13 || exit 1
        LANG=$HTTPD_LANG daemon --pidfile=${pidfile} $httpd $OPTIONS
        RETVAL=$?
        echo
        [ $RETVAL = 0 ] && touch ${lockfile}
        return $RETVAL
}
stop() {
	echo -n $"Stopping $prog: "
	killproc -p ${pidfile} -d 10 $httpd
	RETVAL=$?
	echo
	[ $RETVAL = 0 ] && rm -f ${lockfile} ${pidfile}
}
reload() {
	echo -n $"Reloading $prog: "
	check13 || exit 1
	killproc -p ${pidfile} $httpd -HUP
	RETVAL=$?
	echo
}

# See how we were called.
case "$1" in
  start)
	start
	;;
  stop)
	stop
	;;
  status)
        if ! test -f ${pidfile}; then
            echo $prog is stopped
            RETVAL=3
        else  
            status -p ${pidfile} $httpd
            RETVAL=$?
        fi
        ;;
  restart)
	stop
	start
	;;
  condrestart)
	if test -f ${pidfile} && status -p ${pidfile} $httpd >&/dev/null; then
		stop
		start
	fi
	;;
  reload)
        reload
	;;
  configtest)
        LANG=$HTTPD_LANG $httpd $OPTIONS -t
        RETVAL=$?
        ;;
  graceful)
        echo -n $"Gracefully restarting $prog: "
        LANG=$HTTPD_LANG $httpd $OPTIONS -k $@
        RETVAL=$?
        echo
        ;;
  *)
	echo $"Usage: $prog {start|stop|restart|condrestart|reload|status|graceful|help|configtest}"
	exit 1
esac

exit $RETVAL

