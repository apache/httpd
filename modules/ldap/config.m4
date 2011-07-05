
dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(ldap)

ldap_objects="dnl
util_ldap.lo dnl
util_ldap_cache.lo dnl
util_ldap_cache_mgr.lo dnl
ap_ldap_init.lo dnl
ap_ldap_option.lo dnl
ap_ldap_rebind.lo dnl
ap_ldap_url.lo dnl
"

APACHE_MODULE(ldap, LDAP caching and connection pooling services, $ldap_objects, , no, [
  if test "$ap_has_ldap" = "1" ; then
    APR_ADDTO(MOD_LDAP_LDADD, [$LDADD_ldap])
  else
    enable_ldap=no
  fi
  AC_SUBST(MOD_LDAP_LDADD)
])

APR_ADDTO(INCLUDES, [-I\$(top_srcdir)/$modpath_current])

APACHE_MODPATH_FINISH
