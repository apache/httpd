

BEGIN {
    
    A["ServerRoot"] = "SYS:/APACHE2"
    A["Port"] = "80"
    A["cgidir"] = "cgi-bin"
    A["logfiledir"] = "logs"
    A["htdocsdir"] = "htdocs"
    A["sysconfdir"] = "conf"
    A["iconsdir"] = "icons"
    A["manualdir"] = "manual"
    A["runtimedir"] = "logs"
    A["errordir"] = "error"
    A["proxycachedir"] = "proxy"
    
}

/@@LoadModule@@/ {
    print "#LoadModule auth_anon_module modules/authanon.nlm"
    print "#LoadModule auth_dbm_module modules/authdbm.nlm"
    print "#LoadModule auth_digest_module modules/digest.nlm"
    print "#LoadModule cern_meta_module modules/cernmeta.nlm"
    print "#LoadModule dav_module modules/mod_dav.nlm"
    print "#LoadModule dav_fs_module modules/moddavfs.nlm"
    print "#LoadModule expires_module modules/expires.nlm"
    print "#LoadModule file_cache_module modules/filecach.nlm"
    print "#LoadModule headers_module modules/headers.nlm"
    print "#LoadModule info_module modules/info.nlm"
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
    print "#LoadModule vhost_alias_module modules/vhost.nlm"
    print ""
    next
}

match ($0,/@@.*@@/) {
    s=substr($0,RSTART+2,RLENGTH-4)
    sub(/@@.*@@/,A[s],$0)
}

match ($0,/@rel_.*@/) {
    s=substr($0,RSTART+5,RLENGTH-6)
    sub(/@rel_.*@/,A[s],$0)
}

{
    print
}


END {
    print
    print "#"
    print "# SecureListen: Allows you to securely bind Apache to specific IP addresses "
    print "# and/or ports."
    print "#"
    print "# Change this to SecureListen on specific IP addresses as shown below to "
    print "# prevent Apache from glomming onto all bound IP addresses (0.0.0.0)"
    print "#"
    print "#SecureListen 443 \"SSL CertificateIP\""
}
