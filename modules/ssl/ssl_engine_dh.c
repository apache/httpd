#if 0
=pod
#endif
/*                      _             _
**  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
** | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
** | | | | | | (_) | (_| |   \__ \__ \ |  www.modssl.org
** |_| |_| |_|\___/ \__,_|___|___/___/_|  ftp.modssl.org
**                      |_____|
** ssl_engine_dh.c 
** Diffie-Hellman Built-in Temporary Parameters
*/

/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2003 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 */

#include "mod_ssl.h"

/* ----BEGIN GENERATED SECTION-------- */

/*
** Diffie-Hellman-Parameters: (512 bit)
**     prime:
**         00:d4:bc:d5:24:06:f6:9b:35:99:4b:88:de:5d:b8:
**         96:82:c8:15:7f:62:d8:f3:36:33:ee:57:72:f1:1f:
**         05:ab:22:d6:b5:14:5b:9f:24:1e:5a:cc:31:ff:09:
**         0a:4b:c7:11:48:97:6f:76:79:50:94:e7:1e:79:03:
**         52:9f:5a:82:4b
**     generator: 2 (0x2)
** Diffie-Hellman-Parameters: (1024 bit)
**     prime:
**         00:e6:96:9d:3d:49:5b:e3:2c:7c:f1:80:c3:bd:d4:
**         79:8e:91:b7:81:82:51:bb:05:5e:2a:20:64:90:4a:
**         79:a7:70:fa:15:a2:59:cb:d5:23:a6:a6:ef:09:c4:
**         30:48:d5:a2:2f:97:1f:3c:20:12:9b:48:00:0e:6e:
**         dd:06:1c:bc:05:3e:37:1d:79:4e:53:27:df:61:1e:
**         bb:be:1b:ac:9b:5c:60:44:cf:02:3d:76:e0:5e:ea:
**         9b:ad:99:1b:13:a6:3c:97:4e:9e:f1:83:9e:b5:db:
**         12:51:36:f7:26:2e:56:a8:87:15:38:df:d8:23:c6:
**         50:50:85:e2:1f:0d:d5:c8:6b
**     generator: 2 (0x2)
*/

static unsigned char dh512_p[] =
{
    0xD4, 0xBC, 0xD5, 0x24, 0x06, 0xF6, 0x9B, 0x35, 0x99, 0x4B, 0x88, 0xDE,
    0x5D, 0xB8, 0x96, 0x82, 0xC8, 0x15, 0x7F, 0x62, 0xD8, 0xF3, 0x36, 0x33,
    0xEE, 0x57, 0x72, 0xF1, 0x1F, 0x05, 0xAB, 0x22, 0xD6, 0xB5, 0x14, 0x5B,
    0x9F, 0x24, 0x1E, 0x5A, 0xCC, 0x31, 0xFF, 0x09, 0x0A, 0x4B, 0xC7, 0x11,
    0x48, 0x97, 0x6F, 0x76, 0x79, 0x50, 0x94, 0xE7, 0x1E, 0x79, 0x03, 0x52,
    0x9F, 0x5A, 0x82, 0x4B,
};
static unsigned char dh512_g[] =
{
    0x02,
};

static DH *get_dh512(void)
{
    return modssl_dh_configure(dh512_p, sizeof(dh512_p),
                               dh512_g, sizeof(dh512_g));
}

static unsigned char dh1024_p[] =
{
    0xE6, 0x96, 0x9D, 0x3D, 0x49, 0x5B, 0xE3, 0x2C, 0x7C, 0xF1, 0x80, 0xC3,
    0xBD, 0xD4, 0x79, 0x8E, 0x91, 0xB7, 0x81, 0x82, 0x51, 0xBB, 0x05, 0x5E,
    0x2A, 0x20, 0x64, 0x90, 0x4A, 0x79, 0xA7, 0x70, 0xFA, 0x15, 0xA2, 0x59,
    0xCB, 0xD5, 0x23, 0xA6, 0xA6, 0xEF, 0x09, 0xC4, 0x30, 0x48, 0xD5, 0xA2,
    0x2F, 0x97, 0x1F, 0x3C, 0x20, 0x12, 0x9B, 0x48, 0x00, 0x0E, 0x6E, 0xDD,
    0x06, 0x1C, 0xBC, 0x05, 0x3E, 0x37, 0x1D, 0x79, 0x4E, 0x53, 0x27, 0xDF,
    0x61, 0x1E, 0xBB, 0xBE, 0x1B, 0xAC, 0x9B, 0x5C, 0x60, 0x44, 0xCF, 0x02,
    0x3D, 0x76, 0xE0, 0x5E, 0xEA, 0x9B, 0xAD, 0x99, 0x1B, 0x13, 0xA6, 0x3C,
    0x97, 0x4E, 0x9E, 0xF1, 0x83, 0x9E, 0xB5, 0xDB, 0x12, 0x51, 0x36, 0xF7,
    0x26, 0x2E, 0x56, 0xA8, 0x87, 0x15, 0x38, 0xDF, 0xD8, 0x23, 0xC6, 0x50,
    0x50, 0x85, 0xE2, 0x1F, 0x0D, 0xD5, 0xC8, 0x6B,
};
static unsigned char dh1024_g[] =
{
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
$dhsource =~ s|(DH\s+\*get_dh)|static $1|sg;

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
