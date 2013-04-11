#
# InstallConf.awk Apache HTTP 2.2 script to rewrite the @@ServerRoot@@
# tags in httpd.conf.in to original\httpd.conf - then duplicate the
# conf files to the 'live' configuration if they don't already exist.
#
# Note that we -don't- want the ARGV file list, so no additional {} blocks
# are coded.  Use explicit args (more reliable on Win32) and use the fact
# that ARGV[] params are -not- '\' escaped to process the C:\Foo\Bar Win32
# path format.  Note that awk var=path would not succeed, since it -does-
# escape backslashes in the assignment.  Note also, a trailing space is
# required for paths, or the trailing quote following the backslash is
# escaped, rather than parsed.
#
BEGIN {
    domainname = ARGV[1];
    servername = ARGV[2];
    serveradmin = ARGV[3];
    serverport = ARGV[4];
    serversslport = ARGV[5];
    serverroot = ARGV[6];
    sourceroot = ARGV[7];

    delete ARGV[7];
    delete ARGV[6];
    delete ARGV[5];
    delete ARGV[4];
    delete ARGV[3];
    delete ARGV[2];
    delete ARGV[1];

    gsub( /\\/, "/", serverroot );
    gsub( /[ \/]+$/, "", serverroot );
    tstfl = serverroot "/logs/install.log"
    confroot = serverroot "/conf/";
    confdefault = confroot "original/";

    if ( sourceroot != "docs/conf/" ) {
        sourceroot = serverroot "/" sourceroot;
    }

    usertree = ENVIRON["USERPROFILE"]
    if ( usertree > "" ) {
        gsub( /\\/, "/", usertree );
        gsub( /\/[^\/]+$/, "", usertree );
    } else {
        usertree = "C:/Documents and Settings";
    }

    print "Installing Apache HTTP Server 2.x with" >tstfl;
    print " DomainName =    " domainname >tstfl;
    print " ServerName =    " servername >tstfl;
    print " ServerAdmin =   " serveradmin >tstfl;
    print " ServerPort =    " serverport >tstfl;
    print " ServerSslPort = " serversslport >tstfl;
    print " ServerRoot =    " serverroot >tstfl;

    filelist["httpd.conf"] = "httpd.conf.in";
    filelist["httpd-autoindex.conf"] = "httpd-autoindex.conf.in";
    filelist["httpd-dav.conf"] = "httpd-dav.conf.in";
    filelist["httpd-default.conf"] = "httpd-default.conf.in";
    filelist["httpd-info.conf"] = "httpd-info.conf.in";
    filelist["httpd-languages.conf"] = "httpd-languages.conf.in";
    filelist["httpd-manual.conf"] = "httpd-manual.conf.in";
    filelist["httpd-mpm.conf"] = "httpd-mpm.conf.in";
    filelist["httpd-multilang-errordoc.conf"] = "httpd-multilang-errordoc.conf.in";
    filelist["httpd-ssl.conf"] = "httpd-ssl.conf.in";
    filelist["httpd-userdir.conf"] = "httpd-userdir.conf.in";
    filelist["httpd-vhosts.conf"] = "httpd-vhosts.conf.in";

    for ( conffile in filelist ) {

      if ( conffile == "httpd.conf" ) {
        srcfl = sourceroot filelist[conffile];
        dstfl = confdefault conffile;
        bswarning = 1;
      } else {
        srcfl = sourceroot "extra/" filelist[conffile];
        dstfl = confdefault "extra/" conffile;
        bswarning = 0;
      }

      while ( ( getline < srcfl ) > 0 ) {

        if ( bswarning && /^$/ ) {
          print "#" > dstfl;
          print "# NOTE: Where filenames are specified, you must use forward slashes" > dstfl;
          print "# instead of backslashes (e.g., \"c:/apache\" instead of \"c:\\apache\")." > dstfl;
          print "# If a drive letter is omitted, the drive on which httpd.exe is located" > dstfl;
          print "# will be used by default.  It is recommended that you always supply" > dstfl;
          print "# an explicit drive letter in absolute paths to avoid confusion." > dstfl;
          bswarning = 0;
        }
        if ( /@@LoadModule@@/ ) {
          print "LoadModule actions_module modules/mod_actions.so" > dstfl;
          print "LoadModule alias_module modules/mod_alias.so" > dstfl;
          print "LoadModule asis_module modules/mod_asis.so" > dstfl;
          print "LoadModule auth_basic_module modules/mod_auth_basic.so" > dstfl;
          print "#LoadModule auth_digest_module modules/mod_auth_digest.so" > dstfl;
          print "#LoadModule authn_alias_module modules/mod_authn_alias.so" > dstfl;
          print "#LoadModule authn_anon_module modules/mod_authn_anon.so" > dstfl;
          print "#LoadModule authn_dbd_module modules/mod_authn_dbd.so" > dstfl;
          print "#LoadModule authn_dbm_module modules/mod_authn_dbm.so" > dstfl;
          print "LoadModule authn_default_module modules/mod_authn_default.so" > dstfl;
          print "LoadModule authn_file_module modules/mod_authn_file.so" > dstfl;
          print "#LoadModule authnz_ldap_module modules/mod_authnz_ldap.so" > dstfl;
          print "#LoadModule authz_dbm_module modules/mod_authz_dbm.so" > dstfl;
          print "LoadModule authz_default_module modules/mod_authz_default.so" > dstfl;
          print "LoadModule authz_groupfile_module modules/mod_authz_groupfile.so" > dstfl;
          print "LoadModule authz_host_module modules/mod_authz_host.so" > dstfl;
          print "#LoadModule authz_owner_module modules/mod_authz_owner.so" > dstfl;
          print "LoadModule authz_user_module modules/mod_authz_user.so" > dstfl;
          print "LoadModule autoindex_module modules/mod_autoindex.so" > dstfl;
          print "#LoadModule cache_module modules/mod_cache.so" > dstfl;
          print "#LoadModule cern_meta_module modules/mod_cern_meta.so" > dstfl;
          print "LoadModule cgi_module modules/mod_cgi.so" > dstfl;
          print "#LoadModule charset_lite_module modules/mod_charset_lite.so" > dstfl;
          print "#LoadModule dav_module modules/mod_dav.so" > dstfl;
          print "#LoadModule dav_fs_module modules/mod_dav_fs.so" > dstfl;
          print "#LoadModule dav_lock_module modules/mod_dav_lock.so" > dstfl;
          print "#LoadModule dbd_module modules/mod_dbd.so" > dstfl;
          print "#LoadModule deflate_module modules/mod_deflate.so" > dstfl;
          print "LoadModule dir_module modules/mod_dir.so" > dstfl;
          print "#LoadModule disk_cache_module modules/mod_disk_cache.so" > dstfl;
          print "#LoadModule dumpio_module modules/mod_dumpio.so" > dstfl;
          print "LoadModule env_module modules/mod_env.so" > dstfl;
          print "#LoadModule expires_module modules/mod_expires.so" > dstfl;
          print "#LoadModule ext_filter_module modules/mod_ext_filter.so" > dstfl;
          print "#LoadModule file_cache_module modules/mod_file_cache.so" > dstfl;
          print "#LoadModule filter_module modules/mod_filter.so" > dstfl;
          print "#LoadModule headers_module modules/mod_headers.so" > dstfl;
          print "#LoadModule ident_module modules/mod_ident.so" > dstfl;
          print "#LoadModule imagemap_module modules/mod_imagemap.so" > dstfl;
          print "LoadModule include_module modules/mod_include.so" > dstfl;
          print "#LoadModule info_module modules/mod_info.so" > dstfl;
          print "LoadModule isapi_module modules/mod_isapi.so" > dstfl;
          print "#LoadModule ldap_module modules/mod_ldap.so" > dstfl;
          print "#LoadModule logio_module modules/mod_logio.so" > dstfl;
          print "LoadModule log_config_module modules/mod_log_config.so" > dstfl;
          print "#LoadModule log_forensic_module modules/mod_log_forensic.so" > dstfl;
          print "#LoadModule mem_cache_module modules/mod_mem_cache.so" > dstfl;
          print "LoadModule mime_module modules/mod_mime.so" > dstfl;
          print "#LoadModule mime_magic_module modules/mod_mime_magic.so" > dstfl;
          print "LoadModule negotiation_module modules/mod_negotiation.so" > dstfl;
          print "#LoadModule proxy_module modules/mod_proxy.so" > dstfl;
          print "#LoadModule proxy_ajp_module modules/mod_proxy_ajp.so" > dstfl;
          print "#LoadModule proxy_balancer_module modules/mod_proxy_balancer.so" > dstfl;
          print "#LoadModule proxy_connect_module modules/mod_proxy_connect.so" > dstfl;
          print "#LoadModule proxy_ftp_module modules/mod_proxy_ftp.so" > dstfl;
          print "#LoadModule proxy_http_module modules/mod_proxy_http.so" > dstfl;
          print "#LoadModule proxy_scgi_module modules/mod_proxy_scgi.so" > dstfl;
          print "#LoadModule reqtimeout_module modules/mod_reqtimeout.so" > dstfl;
          print "#LoadModule rewrite_module modules/mod_rewrite.so" > dstfl;
          print "LoadModule setenvif_module modules/mod_setenvif.so" > dstfl;
          print "#LoadModule speling_module modules/mod_speling.so" > dstfl;
          print "#LoadModule ssl_module modules/mod_ssl.so" > dstfl;
          print "#LoadModule status_module modules/mod_status.so" > dstfl;
          print "#LoadModule substitute_module modules/mod_substitute.so" > dstfl;
          print "#LoadModule unique_id_module modules/mod_unique_id.so" > dstfl;
          print "#LoadModule userdir_module modules/mod_userdir.so" > dstfl;
          print "#LoadModule usertrack_module modules/mod_usertrack.so" > dstfl;
          print "#LoadModule version_module modules/mod_version.so" > dstfl;
          print "#LoadModule vhost_alias_module modules/mod_vhost_alias.so" > dstfl;
          continue;
        }
        gsub( /^SSLMutex.*/, "SSLMutex default" );
        gsub( /@@ServerRoot@@/,   serverroot );
        gsub( /@exp_cgidir@/,     serverroot "/cgi-bin" );
        gsub( /@exp_sysconfdir@/, serverroot "/conf" );
        gsub( /@exp_errordir@/,   serverroot "/error" );
        gsub( /@exp_htdocsdir@/,  serverroot "/htdocs" );
        gsub( /@exp_iconsdir@/,   serverroot "/icons" );
        gsub( /@exp_manualdir@/,  serverroot "/manual" );
        gsub( /@exp_runtimedir@/, serverroot "/logs" );
        if ( gsub( /@exp_logfiledir@/, serverroot "/logs" ) ||
             gsub( /@rel_logfiledir@/, "logs" ) ) {
          gsub( /_log"/, ".log\"" )
        }
        gsub( /@rel_runtimedir@/, "logs" );
        gsub( /@rel_sysconfdir@/, "conf" );
        gsub( /\/home\/\*\/public_html/, \
              usertree "/*/My Documents/My Website" );
        gsub( /UserDir public_html/, "UserDir \"My Documents/My Website\"" );
        gsub( /@@ServerName@@|www.example.com/,  servername );
        gsub( /@@ServerAdmin@@|you@example.com/, serveradmin );
        gsub( /@@DomainName@@|example.com/,      domainname );
        gsub( /@@Port@@/,                        serverport );
        gsub( /@@SSLPort@@|443/,                 serversslport );
        print $0 > dstfl;
      }
      close(srcfl);

      if ( close(dstfl) >= 0 ) {
        print "Rewrote " srcfl "\n to " dstfl > tstfl;
        if ( sourceroot != "docs/conf/" ) {
          gsub(/\//, "\\", srcfl);
          if (system("del 2>NUL \"" srcfl "\"")) {
            print "Failed to remove " srcfl > tstfl;
          } else {
            print "Successfully removed " srcfl > tstfl;
          }
        }
      } else {
        print "Failed to rewrite " srcfl "\n to " dstfl > tstfl;
      }
      filelist[conffile] = "extra/";
    }

    filelist["httpd.conf"] = "";
    filelist["charset.conv"] = "";
    filelist["magic"] = "";
    filelist["mime.types"] = "";

    for ( conffile in filelist ) {
      srcfl = confdefault filelist[conffile] conffile;
      dstfl = confroot filelist[conffile] conffile;
      if ( ( getline < dstfl ) < 0 ) {
        while ( ( getline < srcfl ) > 0 ) {
          print $0 > dstfl;
        }
        print "Duplicated " srcfl "\n to " dstfl > tstfl;
      } else {
        print "Existing file " dstfl " preserved" > tstfl;
      }
      close(srcfl);
      close(dstfl);
    }

    if ( sourceroot != "docs/conf/" ) {
      srcfl = confdefault "installwinconf.awk";
      gsub(/\//, "\\", srcfl);
      if (system("del 2>NUL \"" srcfl "\"")) {
        print "Failed to remove " srcfl > tstfl;
      } else {
        print "Successfully removed " srcfl > tstfl;
      }
    }
    close(tstfl);
}
