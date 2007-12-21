#
# InstallConf.awk Apache HTTP 2.2 script to rewrite the @@ServerRoot@@ 
# tags in httpd-win.conf to httpd.default.conf - then duplicate the
# conf files if they don't already exist.
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
    confdefault = confroot "default/";

    print "Installing Apache HTTP 2.0 server with" >tstfl;
    print " DomainName =    " domainname >tstfl;
    print " ServerName =    " servername >tstfl;
    print " ServerAdmin =   " serveradmin >tstfl;
    print " ServerPort =    " serverport >tstfl;
    print " ServerSslPort = " serverport >tstfl;
    print " ServerRoot =    " serverroot >tstfl;

    filelist["httpd.conf"] = "httpd-win.conf";
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
      srcfl = confdefault filelist[conffile];
      dstfl = confdefault conffile;
      while ( ( getline < srcfl ) > 0 ) {
	gsub( /SSLMutex  file:@exp_runtimedir@\/ssl_mutex/, "SSLMutex default" );
	gsub( /@@ServerRoot@@/,   serverroot );
	gsub( /@exp_cgidir@/,     serverroot "/cgi-bin" );
	gsub( /@exp_sysconfdir@/, serverroot "/conf" );
	gsub( /@exp_errordir@/,   serverroot "/error" );
	gsub( /@exp_htdocsdir@/,  serverroot "/htdocs" );
	gsub( /@exp_iconsdir@/,   serverroot "/icons" );
	gsub( /@exp_logfiledir@/, serverroot "/logs" );
	gsub( /@exp_runtimedir@/, serverroot "/logs" );
	gsub( /@exp_manualdir@/,  serverroot "/manual" );
	gsub( /@rel_runtimedir@/, "logs" );
	gsub( /@rel_logfiledir@/, "logs" );
	gsub( /\/home\/\*\/public_html/, "\"C:/Documents and Settings/*/My Documents/My Website\"" );
	gsub( /UserDir public_html/, "UserDir \"My Documents/My Website\"" );
        gsub( /www.example.com/,  servername );
        gsub( /@@ServerAdmin@@/,  serveradmin );
        gsub( /you@example.com/,  serveradmin );
	gsub( /@@ServerName@@/,   servername );
        gsub( /www.example.com/,  servername );
        gsub( /@@ServerAdmin@@/,  serveradmin );
        gsub( /you@example.com/,  serveradmin );
        gsub( /@@DomainName@@/,   domainname );
        gsub( /example.com/,      domainname );
        gsub( /@@Port@@/,         serverport );
	gsub( /443/,              serversslport );
        print $0 > dstfl;
      }
      close(srcfl);

      if ( close(dstfl) >= 0 ) {
        print "Rewrote " srcfl "\n to " dstfl > tstfl;
        gsub(/\//, "\\", srcfl);
        if (system("del \"" srcfl "\"")) {
          print "Failed to remove " srcfl > tstfl;
        } else {
          print "Successfully removed " srcfl > tstfl;
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
      srcfl = confdefault conffile;
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

    srcfl = confdefault "InstallConf22.awk";
    gsub(/\//, "\\", srcfl);
    if (system("del \"" srcfl "\"")) {
        print "Failed to remove " srcfl > tstfl;
    } else {
        print "Successfully removed " srcfl > tstfl;
    }
    close(tstfl);
}