dnl modules enabled in this directory by default

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(generators)

APACHE_MODULE(status, process/thread monitoring, , , yes)
APACHE_MODULE(autoindex, directory listing, , , yes)
APACHE_MODULE(asis, as-is filetypes, , , yes)
APACHE_MODULE(info, server information, , , most)
APACHE_MODULE(suexec, set uid and gid for spawned processes, , , no, [
              other_targets=suexec ] )

# Is mod_cgid needed?
case $host in
    *mingw*)
        dnl No fork+thread+fd issues, and cgid doesn't work anyway.
        cgid_needed="no"
        ;;
    *)
        if ap_mpm_is_threaded; then
            dnl if we are using a threaded MPM on Unix, we can get better
            dnl performance with mod_cgid, and also avoid potential issues
            dnl with forking from a threaded process.
            cgid_needed="yes"
        else
            dnl if we are using a non-threaded MPM, it makes little sense to
            dnl use mod_cgid, and it just opens up holes we don't need.
            cgid_needed="no"
        fi
        ;;
esac

if test $cgid_needed = "yes"; then
    APACHE_MODULE(cgid, CGI scripts, , , yes)
    APACHE_MODULE(cgi, CGI scripts, , , no)
else
    APACHE_MODULE(cgi, CGI scripts, , , yes)
    APACHE_MODULE(cgid, CGI scripts, , , no)
fi

APACHE_MODPATH_FINISH
