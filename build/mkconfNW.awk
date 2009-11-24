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

BEGIN {
    
    A["ServerRoot"] = "SYS:/"BDIR
    A["Port"] = PORT
    A["SSLPort"] = SSLPORT
    A["cgidir"] = "cgi-bin"
    A["logfiledir"] = "logs"
    A["htdocsdir"] = "htdocs"
    A["sysconfdir"] = "conf"
    A["iconsdir"] = "icons"
    A["manualdir"] = "manual"
    A["runtimedir"] = "logs"
    A["errordir"] = "error"
    A["proxycachedir"] = "proxy"

    B["htdocsdir"] = A["ServerRoot"]"/"A["htdocsdir"]
    B["iconsdir"] = A["ServerRoot"]"/"A["iconsdir"]
    B["manualdir"] = A["ServerRoot"]"/"A["manualdir"]
    B["errordir"] = A["ServerRoot"]"/"A["errordir"]
    B["proxycachedir"] = A["ServerRoot"]"/"A["proxycachedir"]
    B["cgidir"] = A["ServerRoot"]"/"A["cgidir"]
    B["logfiledir"] = A["logfiledir"]
    B["sysconfdir"] = A["sysconfdir"]
    B["runtimedir"] = A["runtimedir"]
    B["listen_stmt_1"] = "Listen "A["Port"]
    B["listen_stmt_2"] = ""
}

/@@LoadModule@@/ {
    print "#LoadModule access_compat_module modules/accesscompat.nlm"
    print "#LoadModule actions_module modules/actions.nlm"
    print "#LoadModule auth_basic_module modules/authbasc.nlm"
    print "#LoadModule auth_digest_module modules/authdigt.nlm"
    print "#LoadModule authn_anon_module modules/authnano.nlm"
    print "#LoadModule authn_dbd_module modules/authndbd.nlm"
    print "#LoadModule authn_dbm_module modules/authndbm.nlm"
    print "#LoadModule authn_file_module modules/authnfil.nlm"
    print "#LoadModule authz_dbd_module modules/authzdbd.nlm"
    print "#LoadModule authz_dbm_module modules/authzdbm.nlm"
    print "#LoadModule authz_groupfile_module modules/authzgrp.nlm"
    print "#LoadModule authz_user_module modules/authzusr.nlm"
    print "#LoadModule authnz_ldap_module modules/authnzldap.nlm"
    print "#LoadModule ldap_module modules/utilldap.nlm"
    print "#LoadModule asis_module modules/mod_asis.nlm"
    print "LoadModule autoindex_module modules/autoindex.nlm"
    print "#LoadModule cern_meta_module modules/cernmeta.nlm"
    print "LoadModule cgi_module modules/mod_cgi.nlm"
    print "#LoadModule dav_module modules/mod_dav.nlm"
    print "#LoadModule dav_fs_module modules/moddavfs.nlm"
    print "#LoadModule dav_lock_module modules/moddavlk.nlm"
    print "#LoadModule expires_module modules/expires.nlm"
    print "#LoadModule ext_filter_module modules/extfiltr.nlm"
    print "#LoadModule file_cache_module modules/filecach.nlm"
    print "#LoadModule headers_module modules/headers.nlm"
    print "#LoadModule ident_module modules/modident.nlm"
    print "#LoadModule imagemap_module modules/imagemap.nlm"
    print "#LoadModule info_module modules/info.nlm"
    print "#LoadModule log_forensic_module modules/forensic.nlm"
    print "#LoadModule logio_module modules/modlogio.nlm"
    print "#LoadModule mime_magic_module modules/mimemagi.nlm"
    print "#LoadModule proxy_module modules/proxy.nlm"
    print "#LoadModule proxy_connect_module modules/proxycon.nlm"
    print "#LoadModule proxy_http_module modules/proxyhtp.nlm"
    print "#LoadModule proxy_ftp_module modules/proxyftp.nlm"
    print "#LoadModule rewrite_module modules/rewrite.nlm"
    print "#LoadModule speling_module modules/speling.nlm"
    print "#LoadModule status_module modules/status.nlm"
    print "#LoadModule unique_id_module modules/uniqueid.nlm"
    print "#LoadModule usertrack_module modules/usertrk.nlm"
    print "#LoadModule version_module modules/modversion.nlm"
    print "#LoadModule userdir_module modules/userdir.nlm"
    print "#LoadModule vhost_alias_module modules/vhost.nlm"
    if (MODSSL) {
       print "#LoadModule ssl_module modules/mod_ssl.nlm"
    }
    print ""
    next
}

match ($0,/^#SSLSessionCache +"dbm:/) {
    sub(/^#/, "")
}

match ($0,/^SSLSessionCache +"shmcb:/) {
    sub(/^SSLSessionCache/, "#SSLSessionCache")
}

match ($0,/^# Mutex +default +file:@rel_runtimedir@/) {
    sub(/file:@rel_runtimedir@/, "default")
}

match ($0,/@@.*@@/) {
    s=substr($0,RSTART+2,RLENGTH-4)
    sub(/@@.*@@/,A[s],$0)
}

match ($0,/@rel_.*@/) {
    s=substr($0,RSTART+5,RLENGTH-6)
    sub(/@rel_.*@/,A[s],$0)
}

match ($0,/@exp_.*@/) {
    s=substr($0,RSTART+5,RLENGTH-6)
    sub(/@exp_.*@/,B[s],$0)
}

match ($0,/@nonssl_.*@/) {
    s=substr($0,RSTART+8,RLENGTH-9)
    sub(/@nonssl_.*@/,B[s],$0)
}

match ($0,/^<IfModule cgid_module>$/) {
    print "#"
    print "# CGIMapExtension: Technique for locating the interpreter for CGI scripts."
    print "# The special interpreter path \"OS\" can be used for NLM CGIs."
    print "#"
    print "#CGIMapExtension OS .cgi"
    print "CGIMapExtension SYS:/perl/Perlcgi/perlcgi.nlm .pl"
    print ""
}

{
    print
}

END {
    if ((ARGV[1] ~ /httpd.conf.in/) && !BSDSKT) { 
       print ""
       print "#"
       print "# SecureListen: Allows you to securely bind Apache to specific IP addresses "
       print "# and/or ports."
       print "#"
       print "# Change this to SecureListen on specific IP addresses as shown below to "
       print "# prevent Apache from glomming onto all bound IP addresses (0.0.0.0)"
       print "#"
       print "#SecureListen "SSLPORT" \"SSL CertificateDNS\""
    }
    print ""
}
