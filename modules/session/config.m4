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
session_cookie_objects='mod_session_cookie.lo'
session_crypto_objects='mod_session_crypto.lo'
session_dbd_objects='mod_session_dbd.lo'

case "$host" in
  *os2*)
    # OS/2 DLLs must resolve all symbols at build time
    # and we need some from main session module
    session_cookie_objects="$session_cookie_objects mod_session.la"
    session_crypto_objects="$session_crypto_objects mod_session.la"
    session_dbd_objects="$session_dbd_objects mod_session.la"
    ;;
esac

APACHE_MODULE(session, session module, , , most)
APACHE_MODULE(session_cookie, session cookie module, $session_cookie_objects, , $session_mods_enable)
APACHE_MODULE(session_crypto, session crypto module, $session_crypto_objects, , no, [
  saved_CPPFLAGS="$CPPFLAGS"
  CPPFLAGS="$CPPFLAGS $APR_INCLUDES $APU_INCLUDES"
  AC_TRY_COMPILE([#include <apr_crypto.h>],[
#if APU_HAVE_CRYPTO == 0
#error no crypto support
#endif
], [ap_HAVE_APR_CRYPTO="yes"], [ap_HAVE_APR_CRYPTO="no"])
  CPPFLAGS="$saved_CPPFLAGS"
  if test $ap_HAVE_APR_CRYPTO = "no"; then
    AC_MSG_WARN([Your APR does not include SSL/EVP support.])
    enable_session_crypto="no"
  fi
])
APACHE_MODULE(session_dbd, session dbd module, $session_dbd_objects, , $session_mods_enable)
dnl APACHE_MODULE(session_ldap, session ldap module, , , $session_mods_enable)

APR_ADDTO(INCLUDES, [-I\$(top_srcdir)/$modpath_current])

APACHE_MODPATH_FINISH

