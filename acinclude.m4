
dnl APACHE_HELP_STRING(LHS, RHS)
dnl Autoconf 2.50 can not handle substr correctly.  It does have 
dnl AC_HELP_STRING, so let's try to call it if we can.
dnl Note: this define must be on one line so that it can be properly returned
dnl as the help string.
AC_DEFUN([APACHE_HELP_STRING],[ifelse(regexp(AC_ACVERSION, 2\.1), -1, AC_HELP_STRING($1,$2),[  ]$1 substr([                       ],len($1))$2)])dnl

dnl APACHE_SUBST(VARIABLE)
dnl Makes VARIABLE available in generated files
dnl (do not use @variable@ in Makefiles, but $(variable))
AC_DEFUN([APACHE_SUBST],[
  APACHE_VAR_SUBST="$APACHE_VAR_SUBST $1"
  AC_SUBST($1)
])

dnl APACHE_FAST_OUTPUT(FILENAME)
dnl Perform substitutions on FILENAME (Makefiles only)
AC_DEFUN([APACHE_FAST_OUTPUT],[
  APACHE_FAST_OUTPUT_FILES="$APACHE_FAST_OUTPUT_FILES $1"
])

dnl APACHE_GEN_CONFIG_VARS
dnl Creates config_vars.mk
AC_DEFUN([APACHE_GEN_CONFIG_VARS],[
  APACHE_SUBST(HTTPD_VERSION)
  APACHE_SUBST(HTTPD_MMN)
  APACHE_SUBST(abs_srcdir)
  APACHE_SUBST(bindir)
  APACHE_SUBST(sbindir)
  APACHE_SUBST(cgidir)
  APACHE_SUBST(logfiledir)
  APACHE_SUBST(exec_prefix)
  APACHE_SUBST(datadir)
  APACHE_SUBST(localstatedir)
  APACHE_SUBST(mandir)
  APACHE_SUBST(libdir)
  APACHE_SUBST(libexecdir)
  APACHE_SUBST(htdocsdir)
  APACHE_SUBST(manualdir)
  APACHE_SUBST(includedir)
  APACHE_SUBST(errordir)
  APACHE_SUBST(iconsdir)
  APACHE_SUBST(sysconfdir)
  APACHE_SUBST(installbuilddir)
  APACHE_SUBST(runtimedir)
  APACHE_SUBST(proxycachedir)
  APACHE_SUBST(other_targets)
  APACHE_SUBST(progname)
  APACHE_SUBST(prefix)
  APACHE_SUBST(AWK)
  APACHE_SUBST(CC)
  APACHE_SUBST(CPP)
  APACHE_SUBST(CXX)
  APACHE_SUBST(CPPFLAGS)
  APACHE_SUBST(CFLAGS)
  APACHE_SUBST(CXXFLAGS)
  APACHE_SUBST(LTFLAGS)
  APACHE_SUBST(LDFLAGS)
  APACHE_SUBST(LT_LDFLAGS)
  APACHE_SUBST(SH_LDFLAGS)
  APACHE_SUBST(HTTPD_LDFLAGS)
  APACHE_SUBST(UTIL_LDFLAGS)
  APACHE_SUBST(LIBS)
  APACHE_SUBST(DEFS)
  APACHE_SUBST(INCLUDES)
  APACHE_SUBST(NOTEST_CPPFLAGS)
  APACHE_SUBST(NOTEST_CFLAGS)
  APACHE_SUBST(NOTEST_CXXFLAGS)
  APACHE_SUBST(NOTEST_LDFLAGS)
  APACHE_SUBST(NOTEST_LIBS)
  APACHE_SUBST(EXTRA_CPPFLAGS)
  APACHE_SUBST(EXTRA_CFLAGS)
  APACHE_SUBST(EXTRA_CXXFLAGS)
  APACHE_SUBST(EXTRA_LDFLAGS)
  APACHE_SUBST(EXTRA_LIBS)
  APACHE_SUBST(EXTRA_INCLUDES)
  APACHE_SUBST(INTERNAL_CPPFLAGS)
  APACHE_SUBST(LIBTOOL)
  APACHE_SUBST(SHELL)
  APACHE_SUBST(RSYNC)
  APACHE_SUBST(SVN)
  APACHE_SUBST(MODULE_DIRS)
  APACHE_SUBST(MODULE_CLEANDIRS)
  APACHE_SUBST(PORT)
  APACHE_SUBST(SSLPORT)
  APACHE_SUBST(CORE_IMPLIB_FILE)
  APACHE_SUBST(CORE_IMPLIB)
  APACHE_SUBST(SH_LIBS)
  APACHE_SUBST(SH_LIBTOOL)
  APACHE_SUBST(MK_IMPLIB)
  APACHE_SUBST(MKDEP)
  APACHE_SUBST(INSTALL_PROG_FLAGS)
  APACHE_SUBST(MPM_MODULES)
  APACHE_SUBST(ENABLED_MPM_MODULE)
  APACHE_SUBST(DSO_MODULES)
  APACHE_SUBST(ENABLED_DSO_MODULES)
  APACHE_SUBST(LOAD_ALL_MODULES)
  APACHE_SUBST(APR_BINDIR)
  APACHE_SUBST(APR_INCLUDEDIR)
  APACHE_SUBST(APR_VERSION)
  APACHE_SUBST(APR_CONFIG)
  APACHE_SUBST(APU_BINDIR)
  APACHE_SUBST(APU_INCLUDEDIR)
  APACHE_SUBST(APU_VERSION)
  APACHE_SUBST(APU_CONFIG)

  abs_srcdir="`(cd $srcdir && pwd)`"

  AC_MSG_NOTICE([creating config_vars.mk])
  test -d build || $mkdir_p build
  > build/config_vars.mk
  for i in $APACHE_VAR_SUBST; do
    eval echo "$i = \$$i" >> build/config_vars.mk
  done
])

dnl APACHE_GEN_MAKEFILES
dnl Creates Makefiles
AC_DEFUN([APACHE_GEN_MAKEFILES],[
  $SHELL $srcdir/build/fastgen.sh $srcdir $ac_cv_mkdir_p $BSD_MAKEFILE $APACHE_FAST_OUTPUT_FILES
])

dnl
dnl APACHE_TYPE_RLIM_T
dnl
dnl If rlim_t is not defined, define it to int
dnl
AC_DEFUN([APACHE_TYPE_RLIM_T], [
  AC_CACHE_CHECK([for rlim_t], ac_cv_type_rlim_t, [
    AC_TRY_COMPILE([
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
], [rlim_t spoon;], [
      ac_cv_type_rlim_t=yes
    ],[ac_cv_type_rlim_t=no
    ])
  ])
  if test "$ac_cv_type_rlim_t" = "no" ; then
      AC_DEFINE(rlim_t, int,
          [Define to 'int' if <sys/resource.h> doesn't define it for us])
  fi
])

dnl the list of build variables which are available for customization on a
dnl per module subdir basis (to be inserted into modules.mk with a "MOD_"
dnl prefix, i.e. MOD_CFLAGS etc.). Used in APACHE_MODPATH_{INIT,FINISH}.
define(mod_buildvars, [CFLAGS CXXFLAGS CPPFLAGS LDFLAGS LIBS INCLUDES])
dnl
dnl APACHE_MODPATH_INIT(modpath)
AC_DEFUN([APACHE_MODPATH_INIT],[
  current_dir=$1
  modpath_current=modules/$1
  modpath_static=
  modpath_shared=
  for var in mod_buildvars; do
    eval MOD_$var=
  done
  test -d $1 || $srcdir/build/mkdir.sh $modpath_current
  > $modpath_current/modules.mk
])dnl
dnl
AC_DEFUN([APACHE_MODPATH_FINISH],[
  echo "DISTCLEAN_TARGETS = modules.mk" >> $modpath_current/modules.mk
  echo "static = $modpath_static" >> $modpath_current/modules.mk
  echo "shared = $modpath_shared" >> $modpath_current/modules.mk
  for var in mod_buildvars; do
    if eval val=\"\$MOD_$var\"; test -n "$val"; then
      echo "MOD_$var = $val" >> $modpath_current/modules.mk
    fi
  done
  if test ! -z "$modpath_static" -o ! -z "$modpath_shared"; then
    MODULE_DIRS="$MODULE_DIRS $current_dir"
  else
    MODULE_CLEANDIRS="$MODULE_CLEANDIRS $current_dir"
  fi
  APACHE_FAST_OUTPUT($modpath_current/Makefile)
])dnl
dnl
dnl APACHE_MODPATH_ADD(name[, shared[, objects [, ldflags[, libs]]]])
AC_DEFUN([APACHE_MODPATH_ADD],[
  if test -z "$3"; then
    objects="mod_$1.lo"
  else
    objects="$3"
  fi

  if test -z "$module_standalone"; then
    if test -z "$2"; then
      # The filename of a convenience library must have a "lib" prefix:
      libname="libmod_$1.la"
      BUILTIN_LIBS="$BUILTIN_LIBS $modpath_current/$libname"
      modpath_static="$modpath_static $libname"
      cat >>$modpath_current/modules.mk<<EOF
$libname: $objects
	\$(MOD_LINK) $objects $5
EOF
      if test ! -z "$5"; then
        APR_ADDTO(AP_LIBS, [$5])
      fi
    else
      apache_need_shared=yes
      libname="mod_$1.la"
      shobjects=`echo $objects | sed 's/\.lo/.slo/g'`
      modpath_shared="$modpath_shared $libname"
      cat >>$modpath_current/modules.mk<<EOF
$libname: $shobjects
	\$(SH_LINK) -rpath \$(libexecdir) -module -avoid-version $4 $objects $5
EOF
    fi
  fi
])dnl

dnl
dnl APACHE_MPM_MODULE(name[, shared[, objects[, config[, path[, libs]]]]])
dnl
dnl Provide information for building the MPM.  (Enablement is handled using
dnl --with-mpm/--enable-mpms-shared.)
dnl
dnl name     -- name of MPM, same as MPM directory name
dnl shared   -- "shared" to indicate shared module build, empty string otherwise
dnl objects  -- one or more .lo files to link into the MPM module (default: mpmname.lo)
dnl config   -- configuration logic to run if the MPM is enabled
dnl path     -- relative path to MPM (default: server/mpm/mpmname)
dnl libs     -- libs needed by this MPM
dnl
AC_DEFUN([APACHE_MPM_MODULE],[
    if ap_mpm_is_enabled $1; then
        if test -z "$3"; then
            objects="$1.lo"
        else
            objects="$3"
        fi

        if test -z "$5"; then
            mpmpath="server/mpm/$1"
        else
            mpmpath=$5
        fi

        dnl VPATH support
        test -d $mpmpath || $srcdir/build/mkdir.sh $mpmpath

        APACHE_FAST_OUTPUT($mpmpath/Makefile)

        if test -z "$2"; then
            APR_ADDTO(AP_LIBS, [$6])
            libname="lib$1.la"
            cat >$mpmpath/modules.mk<<EOF
$libname: $objects
	\$(MOD_LINK) $objects
DISTCLEAN_TARGETS = modules.mk
static = $libname
shared =
EOF
        else
            apache_need_shared=yes
            libname="mod_mpm_$1.la"
            shobjects=`echo $objects | sed 's/\.lo/.slo/g'`
            cat >$mpmpath/modules.mk<<EOF
$libname: $shobjects
	\$(SH_LINK) -rpath \$(libexecdir) -module -avoid-version $objects $6
DISTCLEAN_TARGETS = modules.mk
static =
shared = $libname
EOF
            MPM_MODULES="$MPM_MODULES mpm_$1"
            # add default MPM to LoadModule list
            if test $1 = $default_mpm; then
                ENABLED_MPM_MODULE="mpm_$1"
            fi
        fi
        $4
    fi
])dnl

dnl
dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config[, prereq_module]]]]])
dnl
dnl default is one of:
dnl   yes    -- enabled by default. user must explicitly disable.
dnl   no     -- disabled under default, most, all. user must explicitly enable.
dnl   most   -- disabled by default. enabled explicitly or with most or all.
dnl   static -- enabled as static by default, must be explicitly changed.
dnl   ""     -- disabled under default, most. enabled explicitly or with all.
dnl             XXX: The arg must really be empty here. Passing an empty shell
dnl             XXX: variable doesn't work for some reason. This should be
dnl             XXX: fixed.
dnl
dnl basically: yes/no is a hard setting. "most" means follow the "most"
dnl            setting. otherwise, fall under the "all" setting.
dnl            explicit yes/no always overrides, except if the user selects
dnl            "reallyall".
dnl
dnl prereq_module is a module (without the "mod_" prefix) that must be enabled
dnl   if the current module is enabled.  If the current module is built
dnl   statically, prereq_module must be built statically, too.  If these
dnl   conditions are not fulfilled, configure will abort if the current module
dnl   has been enabled explicitly. Otherwise, configure will disable the
dnl   current module.
dnl   prereq_module's APACHE_MODULE() statement must have been processed
dnl   before the current APACHE_MODULE() statement.
dnl
AC_DEFUN([APACHE_MODULE],[
  AC_MSG_CHECKING(whether to enable mod_$1)
  define([optname],[--]ifelse($5,yes,disable,enable)[-]translit($1,_,-))dnl
  AC_ARG_ENABLE(translit($1,_,-),APACHE_HELP_STRING(optname(),$2),force_$1=$enableval,enable_$1=ifelse($5,,maybe-all,$5))
  undefine([optname])dnl
  _apmod_extra_msg=""
  dnl If the module was not explicitly requested, allow it to disable itself if
  dnl its pre-reqs fail.
  case "$enable_$1" in
    yes|static|shared)
      _apmod_required="yes"
      ;;
    *)
      _apmod_required="no"
      ;;
  esac
  if test "$enable_$1" = "static" -o "$enable_$1" = "shared"; then
    :
  elif test "$enable_$1" = "yes"; then
    enable_$1=$module_default
  elif test "$enable_$1" = "few"; then
    if test "$module_selection" = "few" -o "$module_selection" = "most" -o \
            "$module_selection" = "all" -o "$module_selection" = "reallyall"
    then
      enable_$1=$module_default
    else
      enable_$1=no
    fi
    _apmod_extra_msg=" ($module_selection)"
  elif test "$enable_$1" = "most"; then
    if test "$module_selection" = "most" -o "$module_selection" = "all" -o \
            "$module_selection" = "reallyall"
    then
      enable_$1=$module_default
    else
      enable_$1=no
    fi
    _apmod_extra_msg=" ($module_selection)"
  elif test "$enable_$1" = "all" -o "$enable_$1" = "maybe-all"; then
    if test "$module_selection" = "all" -o "$module_selection" = "reallyall"
    then
      enable_$1=$module_default
      _apmod_extra_msg=" ($module_selection)"
    else
      enable_$1=no
    fi
  elif test "$enable_$1" = "reallyall" -o "$enable_$1" = "no" ; then
    if test "$module_selection" = "reallyall" -a "$force_$1" != "no" ; then
      enable_$1=$module_default
      _apmod_extra_msg=" ($module_selection)"
    else
      enable_$1=no
    fi
  else
    enable_$1=no
  fi
  if test "$enable_$1" != "no"; then
    dnl If we plan to enable it, allow the module to run some autoconf magic
    dnl that may disable it because of missing dependencies.
    ifelse([$6$7],,:,
           [AC_MSG_RESULT([checking dependencies])
            ifelse([$7],,:,[m4_foreach([prereq],[$7],
                           [if test "$enable_[]prereq" = "no" ; then
                              enable_$1=no
                              AC_MSG_WARN("mod_[]prereq is disabled but required for mod_$1")
                            elif test "$enable_$1" = "static" && test "$enable_[]prereq" != "static" ; then
                              enable_$1=$enable_[]prereq
                              AC_MSG_WARN("building mod_$1 shared because mod_[]prereq is built shared")
                            el])se])
            ifelse([$6],,:,[  $6])
            ifelse([$7],,:,[fi])
            AC_MSG_CHECKING(whether to enable mod_$1)
            if test "$enable_$1" = "no"; then
              if test "$_apmod_required" = "no"; then
                _apmod_extra_msg=" (disabled)"
              else
                AC_MSG_ERROR([mod_$1 has been requested but can not be built due to prerequisite failures])
              fi
            fi])
  fi
  AC_MSG_RESULT($enable_$1$_apmod_extra_msg)
  if test "$enable_$1" != "no"; then
    case "$enable_$1" in
    static*)
      MODLIST="$MODLIST ifelse($4,,$1,$4)"
      if test "$1" = "so"; then
          sharedobjs=yes
      fi
      shared="";;
    *)
      sharedobjs=yes
      shared=yes
      DSO_MODULES="$DSO_MODULES $1"
      if test "$5" = "yes" ; then
        ENABLED_DSO_MODULES="${ENABLED_DSO_MODULES},$1"
      fi
      ;;
    esac
    define([modprefix], [MOD_]translit($1, [a-z-], [A-Z_]))
    APACHE_MODPATH_ADD($1, $shared, $3,, [\$(]modprefix[_LDADD)])
    APACHE_SUBST(modprefix[_LDADD])
    undefine([modprefix])
  fi
])dnl

dnl
dnl APACHE_ENABLE_MODULES
dnl
AC_DEFUN([APACHE_ENABLE_MODULES],[
  module_selection=most
  module_default=shared

  dnl Check whether we have DSO support.
  dnl If "yes", we build shared modules by default.
  APR_CHECK_APR_DEFINE(APR_HAS_DSO)

  if test $ac_cv_define_APR_HAS_DSO = "no"; then
    AC_MSG_WARN([Missing DSO support - building static modules by default.])
    module_default=static
  fi


  AC_ARG_ENABLE(modules,
  APACHE_HELP_STRING(--enable-modules=MODULE-LIST,Space-separated list of modules to enable | "all" | "most" | "few" | "none" | "reallyall"),[
    if test "$enableval" = "none"; then
       module_default=no
       module_selection=none
    else
      for i in $enableval; do
        if test "$i" = "all" -o "$i" = "most" -o "$i" = "few" -o "$i" = "reallyall"
        then
          module_selection=$i
        else
          i=`echo $i | sed 's/-/_/g'`
          eval "enable_$i=shared"
        fi
      done
    fi
  ])
  
  AC_ARG_ENABLE(mods-shared,
  APACHE_HELP_STRING(--enable-mods-shared=MODULE-LIST,Space-separated list of shared modules to enable | "all" | "most" | "few" | "reallyall"),[
    for i in $enableval; do
      if test "$i" = "all" -o "$i" = "most" -o "$i" = "few" -o "$i" = "reallyall"
      then
        module_selection=$i
        module_default=shared
      else
        i=`echo $i | sed 's/-/_/g'`
    	eval "enable_$i=shared"
      fi
    done
  ])
  
  AC_ARG_ENABLE(mods-static,
  APACHE_HELP_STRING(--enable-mods-static=MODULE-LIST,Space-separated list of static modules to enable | "all" | "most" | "few" | "reallyall"),[
    for i in $enableval; do
      if test "$i" = "all" -o "$i" = "most" -o "$i" = "few" -o "$i" = "reallyall"; then
        module_selection=$i
        module_default=static
      else
        i=`echo $i | sed 's/-/_/g'`
    	eval "enable_$i=static"
      fi
    done
  ])
])

AC_DEFUN([APACHE_REQUIRE_CXX],[
  if test -z "$apache_cxx_done"; then
    AC_PROG_CXX
    AC_PROG_CXXCPP
    apache_cxx_done=yes
  fi
])

dnl
dnl APACHE_CHECK_OPENSSL
dnl
dnl Configure for OpenSSL, giving preference to
dnl "--with-ssl=<path>" if it was specified.
dnl
AC_DEFUN([APACHE_CHECK_OPENSSL],[
  AC_CACHE_CHECK([for OpenSSL], [ac_cv_openssl], [
    dnl initialise the variables we use
    ac_cv_openssl=no
    ap_openssl_found=""
    ap_openssl_base=""
    ap_openssl_libs=""
    ap_openssl_mod_cflags=""
    ap_openssl_mod_ldflags=""

    dnl Determine the OpenSSL base directory, if any
    AC_MSG_CHECKING([for user-provided OpenSSL base directory])
    AC_ARG_WITH(ssl, APACHE_HELP_STRING(--with-ssl=PATH,OpenSSL installation directory), [
      dnl If --with-ssl specifies a directory, we use that directory
      if test "x$withval" != "xyes" -a "x$withval" != "x"; then
        dnl This ensures $withval is actually a directory and that it is absolute
        ap_openssl_base="`cd $withval ; pwd`"
      fi
    ])
    if test "x$ap_openssl_base" = "x"; then
      AC_MSG_RESULT(none)
    else
      AC_MSG_RESULT($ap_openssl_base)
    fi

    dnl Run header and version checks
    saved_CPPFLAGS="$CPPFLAGS"
    saved_LIBS="$LIBS"
    saved_LDFLAGS="$LDFLAGS"

    dnl Before doing anything else, load in pkg-config variables
    if test -n "$PKGCONFIG"; then
      saved_PKG_CONFIG_PATH="$PKG_CONFIG_PATH"
      if test "x$ap_openssl_base" != "x"; then
        if test -f "${ap_openssl_base}/lib/pkgconfig/openssl.pc"; then
          dnl Ensure that the given path is used by pkg-config too, otherwise
          dnl the system openssl.pc might be picked up instead.
          PKG_CONFIG_PATH="${ap_openssl_base}/lib/pkgconfig${PKG_CONFIG_PATH+:}${PKG_CONFIG_PATH}"
          export PKG_CONFIG_PATH
        elif test -f "${ap_openssl_base}/lib64/pkgconfig/openssl.pc"; then
          dnl Ensure that the given path is used by pkg-config too, otherwise
          dnl the system openssl.pc might be picked up instead.
          PKG_CONFIG_PATH="${ap_openssl_base}/lib64/pkgconfig${PKG_CONFIG_PATH+:}${PKG_CONFIG_PATH}"
          export PKG_CONFIG_PATH
        fi
      fi
      AC_ARG_ENABLE(ssl-staticlib-deps,APACHE_HELP_STRING(--enable-ssl-staticlib-deps,[link mod_ssl with dependencies of OpenSSL's static libraries (as indicated by "pkg-config --static"). Must be specified in addition to --enable-ssl.]), [
        if test "$enableval" = "yes"; then
          PKGCONFIG_LIBOPTS="--static"
        fi
      ])
      ap_openssl_libs="`$PKGCONFIG $PKGCONFIG_LIBOPTS --libs-only-l --silence-errors openssl`"
      if test $? -eq 0; then
        ap_openssl_found="yes"
        pkglookup="`$PKGCONFIG --cflags-only-I openssl`"
        APR_ADDTO(CPPFLAGS, [$pkglookup])
        APR_ADDTO(MOD_CFLAGS, [$pkglookup])
        APR_ADDTO(ab_CFLAGS, [$pkglookup])
        pkglookup="`$PKGCONFIG $PKGCONFIG_LIBOPTS --libs-only-L openssl`"
        APR_ADDTO(LDFLAGS, [$pkglookup])
        APR_ADDTO(MOD_LDFLAGS, [$pkglookup])
        pkglookup="`$PKGCONFIG $PKGCONFIG_LIBOPTS --libs-only-other openssl`"
        APR_ADDTO(LDFLAGS, [$pkglookup])
        APR_ADDTO(MOD_LDFLAGS, [$pkglookup])
      fi
      PKG_CONFIG_PATH="$saved_PKG_CONFIG_PATH"
    fi

    dnl fall back to the user-supplied directory if not found via pkg-config
    if test "x$ap_openssl_base" != "x" -a "x$ap_openssl_found" = "x"; then
      APR_ADDTO(CPPFLAGS, [-I$ap_openssl_base/include])
      APR_ADDTO(MOD_CFLAGS, [-I$ap_openssl_base/include])
      APR_ADDTO(ab_CFLAGS, [-I$ap_openssl_base/include])
      APR_ADDTO(LDFLAGS, [-L$ap_openssl_base/lib])
      APR_ADDTO(MOD_LDFLAGS, [-L$ap_openssl_base/lib])
      if test "x$ap_platform_runtime_link_flag" != "x"; then
        APR_ADDTO(LDFLAGS, [$ap_platform_runtime_link_flag$ap_openssl_base/lib])
        APR_ADDTO(MOD_LDFLAGS, [$ap_platform_runtime_link_flag$ap_openssl_base/lib])
      fi
    fi

    AC_MSG_CHECKING([for OpenSSL version >= 0.9.8a])
    AC_TRY_COMPILE([#include <openssl/opensslv.h>],[
#if !defined(OPENSSL_VERSION_NUMBER)
#error "Missing OpenSSL version"
#endif
#if OPENSSL_VERSION_NUMBER < 0x0090801f
#error "Unsupported OpenSSL version " OPENSSL_VERSION_TEXT
#endif],
      [AC_MSG_RESULT(OK)
       ac_cv_openssl=yes],
      [AC_MSG_RESULT(FAILED)])

    if test "x$ac_cv_openssl" = "xyes"; then
      ap_openssl_libs="${ap_openssl_libs:--lssl -lcrypto} `$apr_config --libs`"
      APR_ADDTO(MOD_LDFLAGS, [$ap_openssl_libs])
      APR_ADDTO(LIBS, [$ap_openssl_libs])
      APR_SETVAR(ab_LIBS, [$MOD_LDFLAGS])
      APACHE_SUBST(ab_CFLAGS)
      APACHE_SUBST(ab_LIBS)

      dnl Run library and function checks
      liberrors=""
      AC_CHECK_HEADERS([openssl/engine.h])
      AC_CHECK_FUNCS([SSL_CTX_new], [], [liberrors="yes"])
      AC_CHECK_FUNCS([OPENSSL_init_ssl])
      AC_CHECK_FUNCS([ENGINE_init ENGINE_load_builtin_engines RAND_egd])
      if test "x$liberrors" != "x"; then
        AC_MSG_WARN([OpenSSL libraries are unusable])
      fi
    else
      AC_MSG_WARN([OpenSSL version is too old])
    fi

    dnl restore
    CPPFLAGS="$saved_CPPFLAGS"
    LIBS="$saved_LIBS"
    LDFLAGS="$saved_LDFLAGS"

    dnl cache MOD_LDFLAGS, MOD_CFLAGS
    ap_openssl_mod_cflags=$MOD_CFLAGS
    ap_openssl_mod_ldflags=$MOD_LDFLAGS
  ])
  if test "x$ac_cv_openssl" = "xyes"; then
    AC_DEFINE(HAVE_OPENSSL, 1, [Define if OpenSSL is available])
    APR_ADDTO(MOD_LDFLAGS, [$ap_openssl_mod_ldflags])
    APR_ADDTO(MOD_CFLAGS, [$ap_openssl_mod_cflags])
  fi
])

AC_DEFUN([APACHE_CHECK_SYSTEMD], [
dnl Check for systemd support for listen.c's socket activation.
case $host in
*-linux-*)
   if test -n "$PKGCONFIG" && $PKGCONFIG --exists libsystemd; then
      SYSTEMD_LIBS=`$PKGCONFIG --libs libsystemd`
   elif test -n "$PKGCONFIG" && $PKGCONFIG --exists libsystemd-daemon; then
      SYSTEMD_LIBS=`$PKGCONFIG --libs libsystemd-daemon`
   else
      AC_CHECK_LIB(systemd-daemon, sd_notify, SYSTEMD_LIBS="-lsystemd-daemon")
   fi
   if test -n "$SYSTEMD_LIBS"; then
      AC_CHECK_HEADERS(systemd/sd-daemon.h)
      if test "${ac_cv_header_systemd_sd_daemon_h}" = "no" || test -z "${SYSTEMD_LIBS}"; then
        AC_MSG_WARN([Your system does not support systemd.])
      else
        AC_DEFINE(HAVE_SYSTEMD, 1, [Define if systemd is supported])
      fi
   fi
   ;;
esac
])

dnl
dnl APACHE_EXPORT_ARGUMENTS
dnl Export (via APACHE_SUBST) the various path-related variables that
dnl apache will use while generating scripts like autoconf and apxs and
dnl the default config file.

AC_DEFUN([APACHE_SUBST_EXPANDED_ARG],[
  APR_EXPAND_VAR(exp_$1, [$]$1)
  APACHE_SUBST(exp_$1)
  APR_PATH_RELATIVE(rel_$1, [$]exp_$1, ${prefix})
  APACHE_SUBST(rel_$1)
])

AC_DEFUN([APACHE_EXPORT_ARGUMENTS],[
  APACHE_SUBST_EXPANDED_ARG(exec_prefix)
  APACHE_SUBST_EXPANDED_ARG(bindir)
  APACHE_SUBST_EXPANDED_ARG(sbindir)
  APACHE_SUBST_EXPANDED_ARG(libdir)
  APACHE_SUBST_EXPANDED_ARG(libexecdir)
  APACHE_SUBST_EXPANDED_ARG(mandir)
  APACHE_SUBST_EXPANDED_ARG(sysconfdir)
  APACHE_SUBST_EXPANDED_ARG(datadir)
  APACHE_SUBST_EXPANDED_ARG(installbuilddir)
  APACHE_SUBST_EXPANDED_ARG(errordir)
  APACHE_SUBST_EXPANDED_ARG(iconsdir)
  APACHE_SUBST_EXPANDED_ARG(htdocsdir)
  APACHE_SUBST_EXPANDED_ARG(manualdir)
  APACHE_SUBST_EXPANDED_ARG(cgidir)
  APACHE_SUBST_EXPANDED_ARG(includedir)
  APACHE_SUBST_EXPANDED_ARG(localstatedir)
  APACHE_SUBST_EXPANDED_ARG(runtimedir)
  APACHE_SUBST_EXPANDED_ARG(logfiledir)
  APACHE_SUBST_EXPANDED_ARG(proxycachedir)
])

dnl 
dnl APACHE_CHECK_APxVER({apr|apu}, major, minor, 
dnl                     [actions-if-ok], [actions-if-not-ok])
dnl
dnl Checks for APR or APR-util of given major/minor version or later; 
dnl if so, runs actions-if-ok; otherwise runs actions-if-not-ok if given.
dnl If the version is not satisfactory and actions-if-not-ok is not
dnl given, then an error is printed and the configure script is aborted.
dnl
dnl The first argument must be [apr] or [apu].
dnl
AC_DEFUN([APACHE_CHECK_APxVER], [
define(ap_ckver_major, translit($1, [apru], [APRU])[_MAJOR_VERSION])
define(ap_ckver_minor, translit($1, [apru], [APRU])[_MINOR_VERSION])
define(ap_ckver_cvar, [ap_cv_$1ver$2$3])
define(ap_ckver_name, ifelse([$1],[apr],[APR],[APR-util]))

ap_ckver_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="$CPPFLAGS `$[$1]_config --includes`"

AC_CACHE_CHECK([for ap_ckver_name version $2.$3.0 or later], ap_ckver_cvar, [
AC_EGREP_CPP([good], [
#include <$1_version.h>
#if ]ap_ckver_major[ > $2 || (]ap_ckver_major[ == $2 && ]ap_ckver_minor[ >= $3)
good
#endif
], [ap_ckver_cvar=yes], [ap_ckver_cvar=no])])

if test "$ap_ckver_cvar" = "yes"; then
  ifelse([$4],[],[:],[$4])
else
  ifelse([$5],[],[AC_MSG_ERROR([ap_ckver_name version $2.$3.0 or later is required])], [$5])
fi

CPPFLAGS="$ap_ckver_CPPFLAGS"

undefine([ap_ckver_major])
undefine([ap_ckver_minor])
undefine([ap_ckver_cvar])
undefine([ap_ckver_name])
])

dnl
dnl APACHE_CHECK_VOID_PTR_LEN
dnl
dnl Checks if the size of a void pointer is at least as big as a "long" 
dnl integer type.
dnl
AC_DEFUN([APACHE_CHECK_VOID_PTR_LEN], [

AC_CACHE_CHECK([for void pointer length], [ap_cv_void_ptr_lt_long],
[AC_TRY_RUN([
int main(void)
{
    return sizeof(void *) < sizeof(long); 
}], [ap_cv_void_ptr_lt_long=no], [ap_cv_void_ptr_lt_long=yes], 
    [ap_cv_void_ptr_lt_long=yes])])

if test "$ap_cv_void_ptr_lt_long" = "yes"; then
    AC_MSG_ERROR([Size of "void *" is less than size of "long"])
fi
])

dnl
dnl APACHE_CHECK_APR_HAS_LDAP
dnl
dnl Check if APR_HAS_LDAP is 1
dnl Unfortunately, we can't use APR_CHECK_APR_DEFINE (because it only includes apr.h)
dnl or APR_CHECK_DEFINE (because it only checks for defined'ness and not for 0/1).
dnl
AC_DEFUN([APACHE_CHECK_APR_HAS_LDAP], [
  AC_CACHE_CHECK([for ldap support in apr/apr-util],ac_cv_APR_HAS_LDAP,[
    apache_old_cppflags="$CPPFLAGS"
    CPPFLAGS="$CPPFLAGS $INCLUDES"
    AC_EGREP_CPP(YES_IS_DEFINED, [
#include <apr_ldap.h>
#if APR_HAS_LDAP
YES_IS_DEFINED
#endif
    ], ac_cv_APR_HAS_LDAP=yes, ac_cv_APR_HAS_LDAP=no)
    CPPFLAGS="$apache_old_cppflags"
  ])
])

dnl
dnl APACHE_ADD_GCC_CFLAG
dnl
dnl Check if compiler is gcc and supports flag. If yes, add to NOTEST_CFLAGS.
dnl NOTEST_CFLAGS is merged lately, thus it won't accumulate in CFLAGS here.
dnl Also, AC_LANG_PROGRAM() itself is known to trigger [-Wstrict-prototypes]
dnl with some autoconf versions, so we force -Wno-strict-prototypes for the
dnl check to avoid spurious failures when adding flags like -Werror.
dnl
AC_DEFUN([APACHE_ADD_GCC_CFLAG], [
  define([ap_gcc_ckvar], [ac_cv_gcc_]translit($1, [-:.=], [____]))
  if test "$GCC" = "yes"; then
    AC_CACHE_CHECK([whether gcc accepts $1], ap_gcc_ckvar, [
      save_CFLAGS="$CFLAGS"
      CFLAGS="$CFLAGS $1 -Wno-strict-prototypes"
      AC_COMPILE_IFELSE([AC_LANG_PROGRAM()],
        [ap_gcc_ckvar=yes], [ap_gcc_ckvar=no])
      CFLAGS="$save_CFLAGS"
    ])
    if test "$]ap_gcc_ckvar[" = "yes" ; then
       APR_ADDTO(NOTEST_CFLAGS,[$1])
    fi
  fi
  undefine([ap_gcc_ckvar])
])
