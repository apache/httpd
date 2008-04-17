dnl modules enabled in this directory by default

if test "$enable_session" = "shared"; then
  session_mods_enable=shared
elif test "$enable_proxy" = "yes"; then
  session_mods_enable=yes
else
  session_mods_enable=no
fi


dnl Session

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(session)

dnl Session modules; modules that are capable of storing key value pairs in
dnl various places, such as databases, LDAP, or cookies.
dnl
APACHE_MODULE(session, session module, , , most)
APACHE_MODULE(session_cookie, session cookie module, , , $session_mods_enable)
APACHE_MODULE(session_crypto, session crypto module, , , no)
APACHE_MODULE(session_dbd, session dbd module, , , $session_mods_enable)
dnl APACHE_MODULE(session_ldap, session ldap module, , , $session_mods_enable)

APACHE_MODPATH_FINISH

