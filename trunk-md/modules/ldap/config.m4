
dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(ldap)

ldap_objects="util_ldap.lo util_ldap_cache.lo util_ldap_cache_mgr.lo"
APACHE_MODULE(ldap, LDAP caching and connection pooling services, $ldap_objects, , most , [
  APACHE_CHECK_APR_HAS_LDAP
  if test "$ac_cv_APR_HAS_LDAP" = "yes" ; then
    if test -z "$apu_config" ; then
      LDAP_LIBS="`$apr_config --ldap-libs`"
    else
      LDAP_LIBS="`$apu_config --ldap-libs`"
    fi
    APR_ADDTO(MOD_LDAP_LDADD, [$LDAP_LIBS])
    AC_SUBST(MOD_LDAP_LDADD)
  else
    AC_MSG_WARN([apr/apr-util is compiled without ldap support])
    enable_ldap=no
  fi
])

APR_ADDTO(INCLUDES, [-I\$(top_srcdir)/$modpath_current])

APACHE_MODPATH_FINISH
