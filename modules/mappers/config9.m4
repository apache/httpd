dnl modules enabled in this directory by default

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(mappers)

APACHE_MODULE(vhost_alias, mass hosting module, , , most)
APACHE_MODULE(negotiation, content negotiation, , , yes)
APACHE_MODULE(dir, directory request handling, , , yes)
APACHE_MODULE(imap, internal imagemaps, , , yes)
APACHE_MODULE(actions, Action triggering on requests, , , yes)
APACHE_MODULE(speling, correct common URL misspellings, , , most)
APACHE_MODULE(userdir, mapping of user requests, , , yes)
APACHE_MODULE(alias, translation of requests, , , yes)

APACHE_MODULE(rewrite, regex URL translation, , , most)


APR_CHECK_APR_DEFINE(APR_HAS_DSO)

case "x$enable_so" in
    "xyes")
        if test $ac_cv_define_APR_HAS_DSO = "no"; then
            AC_MSG_ERROR([mod_so has been requested but cannot be built on your system])
        fi
        ;;
    "xshared")
        AC_MSG_ERROR([mod_so can not be built as a shared DSO])
        ;;
    "xno")
        ;;
    "x")
        enable_so=$ac_cv_define_APR_HAS_DSO
        ;;
esac

if test "$sharedobjs" = "yes"; then
    if test $ac_cv_define_APR_HAS_DSO = "no"; then
        AC_MSG_ERROR([shared objects have been requested but cannot be built since mod_so cannot be built])
    elif test $enable_so = "no"; then
        AC_MSG_ERROR([shared objects have been requested but cannot be built since mod_so was disabled])
    fi
fi

APACHE_MODULE(so, DSO capability, , , $enable_so)

dnl ### why save the cache?
AC_CACHE_SAVE

APACHE_MODPATH_FINISH
