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

# A certificate password for the .p12 files of the client
# authentication test. Normally not set. However some browsers
# require a password of at least 4 characters.
#
PASSWD=${PASSWD:-}

args=`getopt a:fd:D:p: $*`
if [ $? != 0 ]; then
    echo "Syntax: $0 [-f] [-a IPaddress] [-d outdir] [-D domain ] [two or more vhost names ]"
    echo "    -f        Force overwriting of outdir (default is $DIR)"
    echo "    -d dir    Directory to create the SNI test server in (default is $DIR)"
    echo "    -D domain Domain name to use for this test (default is $DOMAIN)"
    echo "    -a IP     IP address to use for this virtual host (default is $IP)"
    echo "    -p str    Password for the client certificate test (some browsers require a set password)"
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
        -p)
            PASSWD=$2; shift
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
serial=$RANDOM$$

openssl req -new -nodes -batch \
    -x509  \
    -days 10 -subj '/CN=Da Root/O=SNI testing/' -set_serial $serial \
    -keyout ${DIR}/root.key -out ${DIR}/root.pem  \
    || exit 2

CDIR=${DIR}/client-xs-control
mkdir -p ${CDIR}
# Create some certificate authorities for testing client controls
#
openssl req -new -nodes -batch \
    -x509  \
    -days 10 -subj '/CN=Da Second Root/O=SNI user access I/' -set_serial 2$serial$$\
    -keyout ${CDIR}/xs-root-1.key -out ${CDIR}/xs-root-1.pem  \
    || exit 2

openssl req -new -nodes -batch \
    -x509  \
    -days 10 -subj '/CN=Da Second Root/O=SNI user access II/' -set_serial 3$serial$$ \
    -keyout ${CDIR}/xs-root-2.key -out ${CDIR}/xs-root-2.pem  \
    || exit 2

# Create a chain of just the two access authorites:
cat ${CDIR}/xs-root-2.pem ${CDIR}/xs-root-1.pem > ${CDIR}/xs-root-chain.pem

# And likewise a directory with the same information (using the
# required 'hash' naming format
#
mkdir -p ${CDIR}/xs-root-dir || exit 1
rm -f {$CDIR}/*.0
ln ${CDIR}/xs-root-1.pem ${CDIR}/xs-root-dir/`openssl x509 -noout -hash -in ${CDIR}/xs-root-1.pem`.0
ln ${CDIR}/xs-root-2.pem ${CDIR}/xs-root-dir/`openssl x509 -noout -hash -in ${CDIR}/xs-root-2.pem`.0

# Use the above two client certificate authorities to make a few users
for i in 1 2
do
    # Create a certificate request for a test user.
    #
    openssl req -new -nodes -batch \
        -days 9 -subj "/CN=User $i/O=SNI Test Crash Dummy Dept/" \
        -keyout ${CDIR}/client-$i.key -out ${CDIR}/client-$i.req -batch  \
                || exit 3

    # And get it signed by either our client cert issuing root authority.
    #
    openssl x509 -text -req \
        -CA ${CDIR}/xs-root-$i.pem -CAkey ${CDIR}/xs-root-$i.key \
        -set_serial 3$serial$$ -in ${CDIR}/client-$i.req -out ${CDIR}/client-$i.pem \
                || exit 4

    # And create a pkcs#12 version for easy browser import.
    #
    openssl pkcs12 -export \
        -inkey ${CDIR}/client-$i.key -in ${CDIR}/client-$i.pem -name "Client $i" \
        -caname "Issuing client root $i" -certfile ${CDIR}/xs-root-$i.pem  \
        -out ${CDIR}/client.p12 -passout pass:"$PASSWD" || exit 5

    rm ${CDIR}/client-$i.req 
done

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

    # Uncomment the following lines if you
    # want to only allow access to clients with
    # a certificate issued/signed by some 
    # selection of the issuing authorites
    #
    # SSLCACertificate ${CDIR}/xs-root-1.pem # just root 1
    # SSLCACertificate ${CDIR}/xs-root-2.pem # just root 2
    # SSLCACertificate ${CDIR}/xs-root-chain.pem # 1 & 2 
    # SSLCACertificateDir ${CDIR}/xs-root-dir # 1 & 2 - but as a directory.
    #
    # SSLVerifyClient require
    # SSLVerifyDepth 2
    # 
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

The directory ${CDIR} contains optional test files to allow client
authentication testing:

-       client*pem/p12  Files for client authentication testing. These
                        need to be imported into the browser.

-       xs-root-1/2     Certificate authority which has issued above
                        client authentication certificates.

-       xs-root-dir     A directory specific for the SSLCACertificateDir
                        directive.

-       xs-root-chain   A chain of the two client xs authorities for the
                        SSLCACertificate directive.

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
