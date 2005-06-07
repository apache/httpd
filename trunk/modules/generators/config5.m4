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
    APACHE_MODULE(cgid, CGI scripts, , , yes)
    APACHE_MODULE(cgi, CGI scripts, , , no)
else
# if we are using a non-threaded MPM, it makes little sense to use
# mod_cgid, and it just opens up holes we don't need.  Make mod_cgi the
# default
    APACHE_MODULE(cgi, CGI scripts, , , yes)
    APACHE_MODULE(cgid, CGI scripts, , , no)
fi

APACHE_MODPATH_FINISH
