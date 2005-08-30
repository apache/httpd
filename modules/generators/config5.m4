dnl modules enabled in this directory by default

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(generators)

APACHE_MODULE(status, process/thread monitoring, , , yes)
APACHE_MODULE(autoindex, directory listing, , , yes)
APACHE_MODULE(asis, as-is filetypes, , , yes)
APACHE_MODULE(info, server information, , , most)
APACHE_MODULE(suexec, set uid and gid for spawned processes, , , no, [
              other_targets=suexec ] )

if ap_mpm_is_threaded; then
# if we are using a threaded MPM, we will get better performance with
# mod_cgid, so make it the default.
    APACHE_MODULE(cgid, CGI scripts, , , yes, [
    case $host in
      *-solaris2*)
        case `uname -r` in
          5.10)
          dnl Eventually, 120664 will be released for Solaris 10.
          dnl At that point, we can do a showrev -p search for that patch.
          dnl Solaris 11 (next release) as of snv_19 doesn't have this problem.
          dnl It may be possible to use /kernel/drv/tl from later releases.
          AC_MSG_ERROR([mod_cgid is non-functional on Solaris 10.
This means that threaded MPMs (such as worker MPM) with CGIs will not work.
This problem is due to an OS bug with AF_UNIX sockets.
Patches are forthcoming from Sun.
Please run configure with --disable-cgid or switch to the prefork MPM.
For more info: <http://issues.apache.org/bugzilla/show_bug.cgi?id=34264>])
          ;;
        esac
        ;;
    esac
  ])
    APACHE_MODULE(cgi, CGI scripts, , , no)
else
# if we are using a non-threaded MPM, it makes little sense to use
# mod_cgid, and it just opens up holes we don't need.  Make mod_cgi the
# default
    APACHE_MODULE(cgi, CGI scripts, , , yes)
    APACHE_MODULE(cgid, CGI scripts, , , no)
fi

APACHE_MODPATH_FINISH
