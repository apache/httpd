dnl modules enabled in this directory by default

if test -z "$enable_session" ; then
  session_mods_enable=most
else
  session_mods_enable=$enable_session
fi

dnl Session

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(session)

dnl Session modules; modules that are capable of storing key value pairs in
dnl various places, such as databases, LDAP, or cookies.
dnl
APACHE_MODULE(session, session module, , , most)
APACHE_MODULE(session_cookie, session cookie module, , , $session_mods_enable)
APACHE_MODULE(session_crypto, session crypto module, , , no, [
  AC_CHECK_HEADERS(apr_ssl.h, [], [ap_HAVE_APR_SSL_H="no"])
  if test $ap_HAVE_APR_SSL_H = "no"; then
    AC_MSG_WARN([Your APR does not include SSL/EVP support.])
    enable_session_crypto="no"
  fi
])
APACHE_MODULE(session_dbd, session dbd module, , , $session_mods_enable)
dnl APACHE_MODULE(session_ldap, session ldap module, , , $session_mods_enable)

APACHE_MODPATH_FINISH

