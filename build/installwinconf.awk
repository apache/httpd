#
# InstallConf.awk Apache HTTP 2.x script to rewrite the @@ServerRoot@@
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
    print " DomainName    = " domainname >tstfl;
    print " ServerName    = " servername >tstfl;
    print " ServerAdmin   = " serveradmin >tstfl;
    print " ServerPort    = " serverport >tstfl;
    print " ServerSslPort = " serversslport >tstfl;
    print " ServerRoot    = " serverroot >tstfl;

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
    filelist["proxy-html.conf"] = "proxy-html.conf.in";

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
          print "LoadModule access_compat_module modules/mod_access_compat.so" > dstfl;
          print "LoadModule actions_module modules/mod_actions.so" > dstfl;
          print "LoadModule alias_module modules/mod_alias.so" > dstfl;
          print "LoadModule allowmethods_module modules/mod_allowmethods.so" > dstfl;
          print "LoadModule asis_module modules/mod_asis.so" > dstfl;
          print "LoadModule auth_basic_module modules/mod_auth_basic.so" > dstfl;
          print "#LoadModule auth_digest_module modules/mod_auth_digest.so" > dstfl;
          print "#LoadModule auth_form_module modules/mod_auth_form.so" > dstfl;
          print "#LoadModule authn_anon_module modules/mod_authn_anon.so" > dstfl;
          print "LoadModule authn_core_module modules/mod_authn_core.so" > dstfl;
          print "#LoadModule authn_dbd_module modules/mod_authn_dbd.so" > dstfl;
          print "#LoadModule authn_dbm_module modules/mod_authn_dbm.so" > dstfl;
          print "LoadModule authn_file_module modules/mod_authn_file.so" > dstfl;
          print "#LoadModule authn_socache_module modules/mod_authn_socache.so" > dstfl;
          print "#LoadModule authnz_fcgi_module modules/mod_authnz_fcgi.so" > dstfl;
          print "#LoadModule authnz_ldap_module modules/mod_authnz_ldap.so" > dstfl;
          print "LoadModule authz_core_module modules/mod_authz_core.so" > dstfl;
          print "#LoadModule authz_dbd_module modules/mod_authz_dbd.so" > dstfl;
          print "#LoadModule authz_dbm_module modules/mod_authz_dbm.so" > dstfl;
          print "LoadModule authz_groupfile_module modules/mod_authz_groupfile.so" > dstfl;
          print "LoadModule authz_host_module modules/mod_authz_host.so" > dstfl;
          print "#LoadModule authz_owner_module modules/mod_authz_owner.so" > dstfl;
          print "LoadModule authz_user_module modules/mod_authz_user.so" > dstfl;
          print "LoadModule autoindex_module modules/mod_autoindex.so" > dstfl;
          print "#LoadModule brotli_module modules/mod_brotli.so" > dstfl;
          print "#LoadModule buffer_module modules/mod_buffer.so" > dstfl;
          print "#LoadModule cache_module modules/mod_cache.so" > dstfl;
          print "#LoadModule cache_disk_module modules/mod_cache_disk.so" > dstfl;
          print "#LoadModule cache_socache_module modules/mod_cache_socache.so" > dstfl;
          print "#LoadModule cern_meta_module modules/mod_cern_meta.so" > dstfl;
          print "LoadModule cgi_module modules/mod_cgi.so" > dstfl;
          print "#LoadModule charset_lite_module modules/mod_charset_lite.so" > dstfl;
          print "#LoadModule data_module modules/mod_data.so" > dstfl;
          print "#LoadModule dav_module modules/mod_dav.so" > dstfl;
          print "#LoadModule dav_fs_module modules/mod_dav_fs.so" > dstfl;
          print "#LoadModule dav_lock_module modules/mod_dav_lock.so" > dstfl;
          print "#LoadModule dbd_module modules/mod_dbd.so" > dstfl;
          print "#LoadModule deflate_module modules/mod_deflate.so" > dstfl;
          print "LoadModule dir_module modules/mod_dir.so" > dstfl;
          print "#LoadModule dumpio_module modules/mod_dumpio.so" > dstfl;
          print "LoadModule env_module modules/mod_env.so" > dstfl;
          print "#LoadModule expires_module modules/mod_expires.so" > dstfl;
          print "#LoadModule ext_filter_module modules/mod_ext_filter.so" > dstfl;
          print "#LoadModule file_cache_module modules/mod_file_cache.so" > dstfl;
          print "#LoadModule filter_module modules/mod_filter.so" > dstfl;
          print "#LoadModule http2_module modules/mod_http2.so" > dstfl;
          print "#LoadModule headers_module modules/mod_headers.so" > dstfl;
          print "#LoadModule heartbeat_module modules/mod_heartbeat.so" > dstfl;
          print "#LoadModule heartmonitor_module modules/mod_heartmonitor.so" > dstfl;
          print "#LoadModule ident_module modules/mod_ident.so" > dstfl;
          print "#LoadModule imagemap_module modules/mod_imagemap.so" > dstfl;
          print "LoadModule include_module modules/mod_include.so" > dstfl;
          print "#LoadModule info_module modules/mod_info.so" > dstfl;
          print "LoadModule isapi_module modules/mod_isapi.so" > dstfl;
          print "#LoadModule lbmethod_bybusyness_module modules/mod_lbmethod_bybusyness.so" > dstfl;
          print "#LoadModule lbmethod_byrequests_module modules/mod_lbmethod_byrequests.so" > dstfl;
          print "#LoadModule lbmethod_bytraffic_module modules/mod_lbmethod_bytraffic.so" > dstfl;
          print "#LoadModule lbmethod_heartbeat_module modules/mod_lbmethod_heartbeat.so" > dstfl;
          print "#LoadModule ldap_module modules/mod_ldap.so" > dstfl;
          print "#LoadModule logio_module modules/mod_logio.so" > dstfl;
          print "LoadModule log_config_module modules/mod_log_config.so" > dstfl;
          print "#LoadModule log_debug_module modules/mod_log_debug.so" > dstfl;
          print "#LoadModule log_forensic_module modules/mod_log_forensic.so" > dstfl;
          print "#LoadModule lua_module modules/mod_lua.so" > dstfl;
          print "#LoadModule md_module modules/mod_md.so" > dstfl;
          print "#LoadModule macro_module modules/mod_macro.so" > dstfl;
          print "LoadModule mime_module modules/mod_mime.so" > dstfl;
          print "#LoadModule mime_magic_module modules/mod_mime_magic.so" > dstfl;
          print "LoadModule negotiation_module modules/mod_negotiation.so" > dstfl;
          print "#LoadModule proxy_module modules/mod_proxy.so" > dstfl;
          print "#LoadModule proxy_ajp_module modules/mod_proxy_ajp.so" > dstfl;
          print "#LoadModule proxy_balancer_module modules/mod_proxy_balancer.so" > dstfl;
          print "#LoadModule proxy_connect_module modules/mod_proxy_connect.so" > dstfl;
          print "#LoadModule proxy_express_module modules/mod_proxy_express.so" > dstfl;
          print "#LoadModule proxy_fcgi_module modules/mod_proxy_fcgi.so" > dstfl;
          print "#LoadModule proxy_ftp_module modules/mod_proxy_ftp.so" > dstfl;
          print "#LoadModule proxy_hcheck_module modules/mod_proxy_hcheck.so" > dstfl;
          print "#LoadModule proxy_html_module modules/mod_proxy_html.so" > dstfl;
          print "#LoadModule proxy_http_module modules/mod_proxy_http.so" > dstfl;
          print "#LoadModule proxy_http2_module modules/mod_proxy_http2.so" > dstfl;
          print "#LoadModule proxy_scgi_module modules/mod_proxy_scgi.so" > dstfl;
          print "#LoadModule proxy_uwsgi_module modules/mod_proxy_uwsgi.so" > dstfl;
          print "#LoadModule proxy_wstunnel_module modules/mod_proxy_wstunnel.so" > dstfl;
          print "#LoadModule ratelimit_module modules/mod_ratelimit.so" > dstfl;
          print "#LoadModule reflector_module modules/mod_reflector.so" > dstfl;
          print "#LoadModule remoteip_module modules/mod_remoteip.so" > dstfl;
          print "#LoadModule request_module modules/mod_request.so" > dstfl;
          print "#LoadModule reqtimeout_module modules/mod_reqtimeout.so" > dstfl;
          print "#LoadModule rewrite_module modules/mod_rewrite.so" > dstfl;
          print "#LoadModule sed_module modules/mod_sed.so" > dstfl;
          print "#LoadModule session_module modules/mod_session.so" > dstfl;
          print "#LoadModule session_cookie_module modules/mod_session_cookie.so" > dstfl;
          print "#LoadModule session_crypto_module modules/mod_session_crypto.so" > dstfl;
          print "#LoadModule session_dbd_module modules/mod_session_dbd.so" > dstfl;
          print "LoadModule setenvif_module modules/mod_setenvif.so" > dstfl;
          print "#LoadModule slotmem_plain_module modules/mod_slotmem_plain.so" > dstfl;
          print "#LoadModule slotmem_shm_module modules/mod_slotmem_shm.so" > dstfl;
          print "#LoadModule socache_dbm_module modules/mod_socache_dbm.so" > dstfl;
          print "#LoadModule socache_memcache_module modules/mod_socache_memcache.so" > dstfl;
          print "#LoadModule socache_shmcb_module modules/mod_socache_shmcb.so" > dstfl;
          print "#LoadModule speling_module modules/mod_speling.so" > dstfl;
          print "#LoadModule ssl_module modules/mod_ssl.so" > dstfl;
          print "#LoadModule status_module modules/mod_status.so" > dstfl;
          print "#LoadModule substitute_module modules/mod_substitute.so" > dstfl;
          print "#LoadModule unique_id_module modules/mod_unique_id.so" > dstfl;
          print "#LoadModule userdir_module modules/mod_userdir.so" > dstfl;
          print "#LoadModule usertrack_module modules/mod_usertrack.so" > dstfl;
          print "#LoadModule version_module modules/mod_version.so" > dstfl;
          print "#LoadModule vhost_alias_module modules/mod_vhost_alias.so" > dstfl;
          print "#LoadModule watchdog_module modules/mod_watchdog.so" > dstfl;
          print "#LoadModule xml2enc_module modules/mod_xml2enc.so" > dstfl;
          continue;
        }
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

