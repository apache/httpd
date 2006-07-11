#if 0
=pod
#endif

/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*                      _             _
 *  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
 * | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
 * | | | | | | (_) | (_| |   \__ \__ \ |
 * |_| |_| |_|\___/ \__,_|___|___/___/_|
 *                      |_____|
 * ssl_engine_dh.c
 * Diffie-Hellman Built-in Temporary Parameters
 */

#include "ssl_private.h"

/* ----BEGIN GENERATED SECTION-------- */

/*
** Diffie-Hellman-Parameters: (512 bit)
**     prime:
**         00:9f:db:8b:8a:00:45:44:f0:04:5f:17:37:d0:ba:
**         2e:0b:27:4c:df:1a:9f:58:82:18:fb:43:53:16:a1:
**         6e:37:41:71:fd:19:d8:d8:f3:7c:39:bf:86:3f:d6:
**         0e:3e:30:06:80:a3:03:0c:6e:4c:37:57:d0:8f:70:
**         e6:aa:87:10:33
**     generator: 2 (0x2)
** Diffie-Hellman-Parameters: (1024 bit)
**     prime:
**         00:d6:7d:e4:40:cb:bb:dc:19:36:d6:93:d3:4a:fd:
**         0a:d5:0c:84:d2:39:a4:5f:52:0b:b8:81:74:cb:98:
**         bc:e9:51:84:9f:91:2e:63:9c:72:fb:13:b4:b4:d7:
**         17:7e:16:d5:5a:c1:79:ba:42:0b:2a:29:fe:32:4a:
**         46:7a:63:5e:81:ff:59:01:37:7b:ed:dc:fd:33:16:
**         8a:46:1a:ad:3b:72:da:e8:86:00:78:04:5b:07:a7:
**         db:ca:78:74:08:7d:15:10:ea:9f:cc:9d:dd:33:05:
**         07:dd:62:db:88:ae:aa:74:7d:e0:f4:d6:e2:bd:68:
**         b0:e7:39:3e:0f:24:21:8e:b3
**     generator: 2 (0x2)
*/

static unsigned char dh512_p[] = {
    0x9F, 0xDB, 0x8B, 0x8A, 0x00, 0x45, 0x44, 0xF0, 0x04, 0x5F, 0x17, 0x37,
    0xD0, 0xBA, 0x2E, 0x0B, 0x27, 0x4C, 0xDF, 0x1A, 0x9F, 0x58, 0x82, 0x18,
    0xFB, 0x43, 0x53, 0x16, 0xA1, 0x6E, 0x37, 0x41, 0x71, 0xFD, 0x19, 0xD8,
    0xD8, 0xF3, 0x7C, 0x39, 0xBF, 0x86, 0x3F, 0xD6, 0x0E, 0x3E, 0x30, 0x06,
    0x80, 0xA3, 0x03, 0x0C, 0x6E, 0x4C, 0x37, 0x57, 0xD0, 0x8F, 0x70, 0xE6,
    0xAA, 0x87, 0x10, 0x33,
};
static unsigned char dh512_g[] = {
    0x02,
};

static DH *get_dh512(void)
{
    return modssl_dh_configure(dh512_p, sizeof(dh512_p),
                               dh512_g, sizeof(dh512_g));
}

static unsigned char dh1024_p[] = {
    0xD6, 0x7D, 0xE4, 0x40, 0xCB, 0xBB, 0xDC, 0x19, 0x36, 0xD6, 0x93, 0xD3,
    0x4A, 0xFD, 0x0A, 0xD5, 0x0C, 0x84, 0xD2, 0x39, 0xA4, 0x5F, 0x52, 0x0B,
    0xB8, 0x81, 0x74, 0xCB, 0x98, 0xBC, 0xE9, 0x51, 0x84, 0x9F, 0x91, 0x2E,
    0x63, 0x9C, 0x72, 0xFB, 0x13, 0xB4, 0xB4, 0xD7, 0x17, 0x7E, 0x16, 0xD5,
    0x5A, 0xC1, 0x79, 0xBA, 0x42, 0x0B, 0x2A, 0x29, 0xFE, 0x32, 0x4A, 0x46,
    0x7A, 0x63, 0x5E, 0x81, 0xFF, 0x59, 0x01, 0x37, 0x7B, 0xED, 0xDC, 0xFD,
    0x33, 0x16, 0x8A, 0x46, 0x1A, 0xAD, 0x3B, 0x72, 0xDA, 0xE8, 0x86, 0x00,
    0x78, 0x04, 0x5B, 0x07, 0xA7, 0xDB, 0xCA, 0x78, 0x74, 0x08, 0x7D, 0x15,
    0x10, 0xEA, 0x9F, 0xCC, 0x9D, 0xDD, 0x33, 0x05, 0x07, 0xDD, 0x62, 0xDB,
    0x88, 0xAE, 0xAA, 0x74, 0x7D, 0xE0, 0xF4, 0xD6, 0xE2, 0xBD, 0x68, 0xB0,
    0xE7, 0x39, 0x3E, 0x0F, 0x24, 0x21, 0x8E, 0xB3,
};
static unsigned char dh1024_g[] = {
    0x02,
};

static DH *get_dh1024(void)
{
    return modssl_dh_configure(dh1024_p, sizeof(dh1024_p),
                               dh1024_g, sizeof(dh1024_g));
}

/* ----END GENERATED SECTION---------- */

DH *ssl_dh_GetTmpParam(int nKeyLen)
{
    DH *dh;

    if (nKeyLen == 512)
        dh = get_dh512();
    else if (nKeyLen == 1024)
        dh = get_dh1024();
    else
        dh = get_dh1024();
    return dh;
}

DH *ssl_dh_GetParamFromFile(char *file)
{
    DH *dh = NULL;
    BIO *bio;

    if ((bio = BIO_new_file(file, "r")) == NULL)
        return NULL;
#if SSL_LIBRARY_VERSION < 0x00904000
    dh = PEM_read_bio_DHparams(bio, NULL, NULL);
#else
    dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
#endif
    BIO_free(bio);
    return (dh);
}

/*
=cut
##
##  Embedded Perl script for generating the temporary DH parameters
##

require 5.003;
use strict;

#   configuration
my $file  = $0;
my $begin = '----BEGIN GENERATED SECTION--------';
my $end   = '----END GENERATED SECTION----------';

#   read ourself and keep a backup
open(FP, "<$file") || die;
my $source = '';
$source .= $_ while (<FP>);
close(FP);
open(FP, ">$file.bak") || die;
print FP $source;
close(FP);

#   generate the DH parameters
print "1. Generate 512 and 1024 bit Diffie-Hellman parameters (p, g)\n";
my $rand = '';
foreach $file (qw(/var/log/messages /var/adm/messages
                  /kernel /vmunix /vmlinuz /etc/hosts /etc/resolv.conf)) {
    if (-f $file) {
        $rand = $file     if ($rand eq '');
        $rand .= ":$file" if ($rand ne '');
    }
}
$rand = "-rand $rand" if ($rand ne '');
system("openssl gendh $rand -out dh512.pem 512");
system("openssl gendh $rand -out dh1024.pem 1024");

#   generate DH param info
my $dhinfo = '';
open(FP, "openssl dh -noout -text -in dh512.pem |") || die;
$dhinfo .= $_ while (<FP>);
close(FP);
open(FP, "openssl dh -noout -text -in dh1024.pem |") || die;
$dhinfo .= $_ while (<FP>);
close(FP);
$dhinfo =~ s|^|** |mg;
$dhinfo = "\n\/\*\n$dhinfo\*\/\n\n";

#   generate C source from DH params
my $dhsource = '';
open(FP, "openssl dh -noout -C -in dh512.pem | indent | expand |") || die;
$dhsource .= $_ while (<FP>);
close(FP);
open(FP, "openssl dh -noout -C -in dh1024.pem | indent | expand |") || die;
$dhsource .= $_ while (<FP>);
close(FP);
$dhsource =~ s|(DH\s+\*get_dh)(\d+)[^}]*\n}|static $1$2(void)
{
    return modssl_dh_configure(dh$2_p, sizeof(dh$2_p),
                               dh$2_g, sizeof(dh$2_g));
}
|sg;

#   generate output
my $o = $dhinfo . $dhsource;

#   insert the generated code at the target location
$source =~ s|(\/\* $begin.+?\n).*\n(.*?\/\* $end)|$1$o$2|s;

#   and update the source on disk
print "Updating file `$file'\n";
open(FP, ">$file") || die;
print FP $source;
close(FP);

#   cleanup
unlink("dh512.pem");
unlink("dh1024.pem");

=pod
*/
