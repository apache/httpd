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
# This script will populate a directory 'sni' with 3 sites, httpd.conf
# and certificates as to facilitate testing of TLS server name 
# indication support (RFC 4366) or SNI.
#
# $Id$
#
#
OPENSSL=${OPENSSL:-openssl}
DOMAIN=${DOMAIN:-my-sni-test.org}
DIR=${DIR:-$PWD/sni}

# List of hostnames automatically created by default.
NAMES=${NAMES:-ape nut pear apple banana}

# IP address these hostnames are bound to.
IP=${IP:-127.0.0.1}

args=`getopt a:fd:D: $*`
if [ $? != 0 ]; then
    echo "Syntax: $0 [-f] [-a IPaddress] [-d outdir] [-D domain ] [two or more vhost names ]"
    echo "    -f        Force overwriting of outdir (default is $DIR)"
    echo "    -d dir    Directory to create the SNI test server in (default is $DIR)"
    echo "    -D domain Domain name to use for this test (default is $DOMAIN)"
    echo "    -a IP     IP address to use for this virtual host (default is $IP)"
    echo "    [names]   List of optional vhost names (default is $NAMES)"
    echo 
    echo "Example:"
    echo "    $0 -D SecureBlogsAreUs.com peter fred mary jane ardy"
    echo
    echo "Which will create peter.SecureBlogsAreUs.com, fred.SecureBlogsAreUs.com and"
    echo "so on. Note that the _first_ FQDN is also the default for non SNI hosts. It"
    echo "may make sense to give this host a generic name - and allow each of the real"
    echo "SNI site as sub directories/URI's of this generic name; thus allowing the "
    echo "few non-SNI browsers access."
    exit 1
fi
set -- $args
for i
do
    case "$i"
    in
        -f)
            FORCE=1
            shift;;
        -a)
            IP=$2; shift
            shift;;
        -d)
            DIR=$2; shift
            shift;;
        -D)
            DOMAIN=$2; shift
            shift;;
        --) 
            shift; break;
    esac
done

if [ $# = 1 ]; then
    echo "Aborted - just specifing one vhost makes no sense for SNI testing. Go wild !"
    exit 1
fi

if [ $# -gt 0 ]; then
    NAMES=$*
fi

if ! openssl version | grep -q OpenSSL; then
    echo Aborted - your openssl is very old or misconfigured.
    exit 1
fi

set `openssl version`
if test "0$2" \< "00.9"; then
    echo Aborted - version of openssl too old, 0.9 or up required.
    exit 1 
fi

if test -d ${DIR} -a "x$FORCE" != "x1"; then
    echo Aborted - already an ${DIR} directory. Use the -f flag to overwrite.
    exit 1
fi

mkdir -p ${DIR} || exit 1
mkdir -p ${DIR}/ssl ${DIR}/htdocs ${DIR}/logs || exit 1
        
# Create a 'CA' - keep using different serial numbers
# as the browsers get upset if they see an identical 
# serial with a different pub-key.
#
# Note that we're not relying on the 'v3_ca' section as
# in the default openssl.conf file - so the certificate
# will be without the basicConstraints = CA:true and
# keyUsage = cRLSign, keyCertSign values. This is fine
# for most browsers.
#
serial=$$
openssl req -new -nodes -batch \
    -x509  \
    -days 10 -subj '/CN=Da Root/O=SNI testing/' -set_serial $serial \
    -keyout ${DIR}/root.key -out ${DIR}/root.pem  \
    || exit 2


# Create the header for the example '/etc/hosts' file.
#
echo '# To append to your hosts file' > ${DIR}/hosts

# Create a header for the httpd.conf snipped.
#
cat > ${DIR}/httpd-sni.conf << EOM
# To append to your httpd.conf file'
Listen ${IP}:443
NameVirtualHost ${IP}:443

LoadModule ssl_module modules/mod_ssl.so

SSLRandomSeed startup builtin
SSLRandomSeed connect builtin

LogLevel debug
TransferLog ${DIR}/logs/access_log
ErrorLog ${DIR}/logs/error_log

# You'll get a warning about this.
#
SSLSessionCache none

# Note that this SSL configuration is far
# from complete - you propably will want
# to configure SSLMutex-es and SSLSession
# Caches at the very least.

<Directory />
    Options None
    AllowOverride None
    Require all denied
</Directory>

<Directory "${DIR}/htdocs">
    allow from all
    Require all granted
</Directory>

# This first entry is also the default for non SNI
# supporting clients.
#
EOM

# Create the header of a sample BIND zone file.
#
(
        echo "; Configuration sample to be added to the $DOMAIN zone file of BIND."
        echo "\$ORIGIN $DOMAIN."
) > ${DIR}/zone-file

ZADD="IN A $IP"
INFO="and also the site you see when the browser does not support SNI."

set -- ${NAMES}
DEFAULT=$1

for n in ${NAMES}
do
    FQDN=$n.$DOMAIN
    serial=`expr $serial + 1`

    # Create a certificate request for this host.
    #
    openssl req -new -nodes -batch \
        -days 9 -subj "/CN=$FQDN/O=SNI Testing/" \
        -keyout ${DIR}/$n.key -out ${DIR}/$n.req -batch  \
                || exit 3

    # And get it signed by our root authority.
    #
    openssl x509 -text -req \
        -CA ${DIR}/root.pem -CAkey ${DIR}/root.key \
        -set_serial $serial -in ${DIR}/$n.req -out ${DIR}/$n.pem \
                || exit 4

    # Combine the key and certificate in one file.
    #
    cat ${DIR}/$n.pem ${DIR}/$n.key > ${DIR}/ssl/$n.crt
    rm ${DIR}/$n.req ${DIR}/$n.key ${DIR}/$n.pem

    LST="$LST
    https://$FQDN/index.html"

    # Create a /etc/host and bind-zone file example
    #
    echo "${IP}         $FQDN $n" >> ${DIR}/hosts
    echo "$n    $ZADD" >> ${DIR}/zone-file
    ZADD="IN CNAME $DEFAULT"

    # Create and populate a docroot for this host.
    #
    mkdir -p ${DIR}/htdocs/$n || exit 1
    echo We are $FQDN $INFO > ${DIR}/htdocs/$n/index.html || exit 1

    # And change the info text - so that only the default/fallback site
    # gets marked as such.
    #
    INFO="and you'd normally only see this site when there is proper SNI support."

    # And create a configuration snipped.
    #
    cat >> ${DIR}/httpd-sni.conf << EOM
<VirtualHost ${IP}:443>
    SSLEngine On
    ServerName $FQDN:443
    DocumentRoot ${DIR}/htdocs/$n
    SSLCertificateChainFile ${DIR}/root.pem
    SSLCertificateFile ${DIR}/ssl/$n.crt
    TransferLog ${DIR}/logs/access_$n
</VirtualHost>

EOM

done

cat << EOM
SNI Files generated
===================

The directory ${DIR}/sni has been populated with the following

-       root.key|pem    Certificate authority root and key. (You could
                        import the root.pem key into your browser to
                        quell warnings about an unknown authority).

-       hosts           /etc/hosts file with fake entries for the hosts

-       htdocs          directory with one docroot for each domain,
                        each with a small sample file.

-       ssl             directory with an ssl cert (signed by root)
                        for each of the domains).

-       logs            logfiles, one for each domain and an
                        access_log for any misses.

SNI Test
========

A directory ${DIR}/sni has been created. Run an apache
server against it with

    .../httpd -f ${DIR}/httpd-sni.conf

and keep an eye on ${DIR}/logs/error_log. When everything 
is fine you will see entries like:

    Feb 11 16:12:26 2008] [debug] Init: 
        SSL server IP/port overlap: ape.*:443 (httpd-sni.conf:24) vs. jane.*:443 (httpd-sni.conf:42)

for each vhost configured and a concluding warning:

    [Mon Feb 11 16:12:26 2008] [warn] Init: 
        Name-based SSL virtual hosts only work for clients with TLS server name indication support (RFC 4366)

HOWEVER - If you see an entry like:

    [Mon Feb 11 15:41:41 2008] [warn] Init: 
        You should not use name-based virtual hosts in conjunction with SSL!!

then you are either using an OpenSSL which is too old and/or you need to ensure that the
TLS Extensions are compiled into openssl with the 'enable-tlsext' flag. Once you have
recompiled or reinstalled OpenSSL with TLS Extensions you will have to recompile mod_ssl
to allow it to recognize SNI support.

Meanwhile add 'hosts' to your c:\windows\system32\drivers\etc\hosts
or /etc/hosts file as to point the various URL's to your server:
$LST

and verify that each returns its own name (and an entry in its
own ${DIR}/logs) file).

NOTE
====

Note that in the generated example the 'first' domain is special - and is the
catch all for non-SNI browsers. Depending on your circumstances it may make
sense to use a generic name - and have each of the SNI domains as subdirectories
(and hence URI's under this generic name). Thus allowing non SNI browsers also
access to those sites.
EOM
exit 0
