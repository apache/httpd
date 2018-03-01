
APACHE_MODPATH_INIT(lua)

dnl CHECK_LUA_PATH(PREFIX, INCLUDE-PATH, LIB-PATH, LIB-NAME)
dnl
dnl Checks for a specific version of the Lua libraries. Use CHECK_LUA instead,
dnl which will call this macro.
dnl
dnl Sets LUA_CFLAGS and LUA_LIBS, and breaks from its containing loop, if the
dnl check succeeds.
AC_DEFUN([CHECK_LUA_PATH], [dnl
    AC_MSG_CHECKING([for lua.h in $1/$2])
    if test -f $1/$2/lua.h; then
        AC_MSG_RESULT([yes])
        save_CFLAGS=$CFLAGS
        save_LDFLAGS=$LDFLAGS
        CFLAGS="$CFLAGS"
        LDFLAGS="-L$1/$3 $LDFLAGS $lib_m"
        AC_CHECK_LIB($4, luaL_newstate, [
            LUA_LIBS="-L$1/$3 -l$4 $lib_m"
            if test "x$ap_platform_runtime_link_flag" != "x"; then
               APR_ADDTO(LUA_LIBS, [$ap_platform_runtime_link_flag$1/$3])
            fi
            LUA_CFLAGS="-I$1/$2"
        ])
        CFLAGS=$save_CFLAGS
        LDFLAGS=$save_LDFLAGS

        if test -n "${LUA_LIBS}"; then
            break
        fi
    else
        AC_MSG_RESULT([no])
    fi
])

dnl Check for Lua 5.3/5.2/5.1 Libraries
dnl CHECK_LUA(ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND])
dnl Sets:
dnl  LUA_CFLAGS
dnl  LUA_LIBS
AC_DEFUN([CHECK_LUA],
[dnl

AC_ARG_WITH(
    lua,
    [AC_HELP_STRING([--with-lua=PATH],[Path to the Lua 5.3/5.2/5.1 prefix])],
    lua_path="$withval",
    :)

dnl # Determine lua lib directory
if test -z "$lua_path"; then
    test_paths=". /usr/local /usr"
else
    test_paths="${lua_path}"
fi

if test -n "$PKGCONFIG" -a -z "$lua_path" \
   && $PKGCONFIG --atleast-version=5.1 lua; then
  LUA_LIBS="`$PKGCONFIG --libs lua`"
  LUA_CFLAGS="`$PKGCONFIG --cflags lua`"
  LUA_VERSION="`$PKGCONFIG --modversion lua`"
  AC_MSG_NOTICE([using Lua $LUA_VERSION configuration from pkg-config])
else
  AC_CHECK_LIB(m, pow, lib_m="-lm")
  AC_CHECK_LIB(m, sqrt, lib_m="-lm")
  for x in $test_paths ; do
    CHECK_LUA_PATH([${x}], [include/lua-5.3], [lib/lua-5.3], [lua-5.3])
    CHECK_LUA_PATH([${x}], [include/lua5.3], [lib], [lua5.3])
    CHECK_LUA_PATH([${x}], [include/lua53], [lib/lua53], [lua])

    CHECK_LUA_PATH([${x}], [include], [lib], [lua])

    CHECK_LUA_PATH([${x}], [include/lua-5.2], [lib/lua-5.2], [lua-5.2])
    CHECK_LUA_PATH([${x}], [include/lua5.2], [lib], [lua5.2])
    CHECK_LUA_PATH([${x}], [include/lua52], [lib/lua52], [lua])

    CHECK_LUA_PATH([${x}], [include/lua-5.1], [lib/lua-5.1], [lua-5.1])
    CHECK_LUA_PATH([${x}], [include/lua5.1], [lib], [lua5.1])
    CHECK_LUA_PATH([${x}], [include/lua51], [lib/lua51], [lua])
  done
fi

AC_SUBST(LUA_LIBS)
AC_SUBST(LUA_CFLAGS)

if test -z "${LUA_LIBS}"; then
  AC_MSG_WARN([*** Lua 5.3 5.2 or 5.1 library not found.])
  ifelse([$2], ,
    enable_lua="no"
    if test -z "${lua_path}"; then
        AC_MSG_WARN([Lua 5.3 5.2 or 5.1 library is required])
    else
        AC_MSG_ERROR([Lua 5.3 5.2 or 5.1 library is required])
    fi,
    $2)
else
  AC_MSG_NOTICE([using '${LUA_LIBS}' for Lua Library])
  AC_ARG_ENABLE(luajit,APACHE_HELP_STRING(--enable-luajit,Enable LuaJit Support),
  [
    if test "$enableval" = "yes"; then
      APR_ADDTO(MOD_CPPFLAGS, ["-DAP_ENABLE_LUAJIT"])
    fi
  ])
  ifelse([$1], , , $1) 
fi 
])

lua_objects="lua_apr.lo lua_config.lo mod_lua.lo lua_request.lo lua_vmprep.lo lua_dbd.lo lua_passwd.lo"

APACHE_MODULE(lua, Apache Lua Framework, $lua_objects, , , [
  CHECK_LUA()
  if test "x$enable_lua" != "xno" ; then
    APR_ADDTO(MOD_INCLUDES, [$LUA_CFLAGS])
    APR_ADDTO(MOD_LUA_LDADD, [$LUA_LIBS $CRYPT_LIBS])
  fi
])

APR_ADDTO(INCLUDES, [-I\$(top_srcdir)/$modpath_current])

APACHE_MODPATH_FINISH
