#!/bin/sh
##
##  buildinfo.sh -- Determine Build Information
##  Written by Ralf S. Engelschall <rse@apache.org>
##  for the Apache's Autoconf-style Interface (APACI) 
##
#
# This script falls under the Apache License.
# See http://www.apache.org/docs/LICENSE


#
#   argument line handling
#
error=no
if [ $# -ne 1 -a $# -ne 2 ]; then
    error=yes
fi
if [ $# -eq 2 -a ".$1" != ".-n" ]; then
    error=yes
fi
if [ $error = yes ]; then
    echo "$0:Error: invalid argument line"
    echo "$0:Usage: $0 [-n] <format-string>"
    echo "Where <format-string> can contain:"
    echo "   %u ...... substituted by determined username    (foo)"
    echo "   %h ...... substituted by determined hostname    (bar)"
    echo "   %d ...... substituted by determined domainname  (.com)"
    echo "   %D ...... substituted by determined day         (DD)"
    echo "   %M ...... substituted by determined month       (MM)"
    echo "   %Y ...... substituted by determined year        (YYYYY)"
    echo "   %m ...... substituted by determined monthname   (Jan)"
    exit 1
fi
if [ $# -eq 2 ]; then
    newline=no
    format_string="$2"
else
    newline=yes
    format_string="$1"
fi

#
#   initialization
#
username=''
hostname=''
domainname=''
time_day=''
time_month=''
time_year=''
time_monthname=''

#
#   determine username
#
username="$LOGNAME"
if [ ".$username" = . ]; then
    username="$USER"
    if [ ".$username" = . ]; then
        username="`whoami 2>/dev/null |\
                   awk '{ printf("%s", $1); }'`"
        if [ ".$username" = . ]; then
            username="`who am i 2>/dev/null |\
                       awk '{ printf("%s", $1); }'`"
            if [ ".$username" = . ]; then
                username='unknown'
            fi
        fi
    fi
fi

#
#   determine hostname and domainname
#
hostname="`uname -n 2>/dev/null |\
           awk '{ printf("%s", $1); }'`"
if [ ".$hostname" = . ]; then
    hostname="`hostname 2>/dev/null |\
               awk '{ printf("%s", $1); }'`"
    if [ ".$hostname" = . ]; then
        hostname='unknown'
    fi
fi
case $hostname in
    *.* )
        domainname=".`echo $hostname | cut -d. -f2-`"
        hostname="`echo $hostname | cut -d. -f1`"
        ;;
esac
if [ ".$domainname" = . ]; then
    if [ -f /etc/resolv.conf ]; then
        domainname="`egrep '^[ 	]*domain' /etc/resolv.conf | head -1 |\
                     sed -e 's/.*domain//' \
                         -e 's/^[ 	]*//' -e 's/^ *//' -e 's/^	*//' \
                         -e 's/^\.//' -e 's/^/./' |\
                     awk '{ printf("%s", $1); }'`"
        if [ ".$domainname" = . ]; then
            domainname="`egrep '^[ 	]*search' /etc/resolv.conf | head -1 |\
                         sed -e 's/.*search//' \
                             -e 's/^[ 	]*//' -e 's/^ *//' -e 's/^	*//' \
                             -e 's/ .*//' -e 's/	.*//' \
                             -e 's/^\.//' -e 's/^/./' |\
                         awk '{ printf("%s", $1); }'`"
        fi
    fi
fi

#
#   determine current time
#
time_day="`date '+%d' | awk '{ printf("%s", $1); }'`"
time_month="`date '+%m' | awk '{ printf("%s", $1); }'`"
time_year="`date '+%Y' 2>/dev/null | awk '{ printf("%s", $1); }'`"
if test ".$time_year" = .; then
    time_year="`date '+%y' | awk '{ printf("%s", $1); }'`"
    case $time_year in
        9[0-9]*) time_year="19$time_year" ;;
              *) time_year="20$time_year" ;;
    esac
fi
case $time_month in
    1|01) time_monthname='Jan' ;;
    2|02) time_monthname='Feb' ;;
    3|03) time_monthname='Mar' ;;
    4|04) time_monthname='Apr' ;;
    5|05) time_monthname='May' ;;
    6|06) time_monthname='Jun' ;;
    7|07) time_monthname='Jul' ;;
    8|08) time_monthname='Aug' ;;
    9|09) time_monthname='Sep' ;;
      10) time_monthname='Oct' ;;
      11) time_monthname='Nov' ;;
      12) time_monthname='Dec' ;;
esac

#
#   create result string
#
if [ ".$newline" = .yes ]; then
    echo $format_string |\
    sed -e "s;%u;$username;g" \
        -e "s;%h;$hostname;g" \
        -e "s;%d;$domainname;g" \
        -e "s;%D;$time_day;g" \
        -e "s;%M;$time_month;g" \
        -e "s;%Y;$time_year;g" \
        -e "s;%m;$time_monthname;g"
else
    echo "${format_string}&" |\
    sed -e "s;%u;$username;g" \
        -e "s;%h;$hostname;g" \
        -e "s;%d;$domainname;g" \
        -e "s;%D;$time_day;g" \
        -e "s;%M;$time_month;g" \
        -e "s;%Y;$time_year;g" \
        -e "s;%m;$time_monthname;g" |\
    awk '-F&' '{ printf("%s", $1); }'
fi

