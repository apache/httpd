
APACHE_MODPATH_INIT(lua)

dnl Check for Lua 5.1 Libraries
dnl CHECK_LUA(ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND])
dnl Sets:
dnl  LUA_CFLAGS
dnl  LUA_LIBS
AC_DEFUN([CHECK_LUA],
[dnl

AC_ARG_WITH(
    lua,
    [AC_HELP_STRING([--with-lua=PATH],[Path to the Lua 5.1 prefix])],
    lua_path="$withval",
    :)

dnl # Determine lua lib directory
if test -z $lua_path; then
    test_paths=". /usr/local /usr"
else
    test_paths="${lua_path}"
fi

AC_CHECK_LIB(m, pow, lib_m="-lm")
AC_CHECK_LIB(m, sqrt, lib_m="-lm")
for x in $test_paths ; do
  if test "x$x" == "x."; then
    AC_CHECK_HEADER(lua.h,[
        save_CFLAGS=$CFLAGS
        save_LDFLAGS=$LDFLAGS
        CFLAGS="$CFLAGS"
        LDFLAGS="$LDFLAGS $lib_m"
        AC_CHECK_LIB(lua5.1, luaL_newstate, [
            LUA_LIBS="-llua5.1 $lib_m"
        ],[
            AC_CHECK_LIB(lua-5.1, luaL_newstate, [
                LUA_LIBS="-llua-5.1 $lib_m"
            ],[
                AC_CHECK_LIB(lua, luaL_newstate, [
                    LUA_LIBS="-llua $lib_m"
                ])
            ])
        ])
        LUA_CFLAGS=
        CFLAGS=$save_CFLAGS
        LDFLAGS=$save_LDFLAGS
        break
    ])
  else
    AC_MSG_CHECKING([for lua.h in ${x}/include/lua5.1])
    if test -f ${x}/include/lua5.1/lua.h; then
        AC_MSG_RESULT([yes])
        save_CFLAGS=$CFLAGS
        save_LDFLAGS=$LDFLAGS
        CFLAGS="$CFLAGS"
        LDFLAGS="-L$x/lib $LDFLAGS $lib_m"
        AC_CHECK_LIB(lua5.1, luaL_newstate, [
            LUA_LIBS="-L$x/lib -llua5.1 $lib_m"
            LUA_CFLAGS="-I$x/include/lua5.1"
            ])
        CFLAGS=$save_CFLAGS
        LDFLAGS=$save_LDFLAGS
        break
    else
        AC_MSG_RESULT([no])
    fi
    AC_MSG_CHECKING([for lua.h in ${x}/include/lua51])
    if test -f ${x}/include/lua51/lua.h; then
        AC_MSG_RESULT([yes])
        save_CFLAGS=$CFLAGS
        save_LDFLAGS=$LDFLAGS
        CFLAGS="$CFLAGS"
        LDFLAGS="-L$x/lib/lua51 $LDFLAGS $lib_m"
        AC_CHECK_LIB(lua, luaL_newstate, [
            LUA_LIBS="-L$x/lib/lua51 -llua $lib_m"
            LUA_CFLAGS="-I$x/include/lua51"
            ])
        CFLAGS=$save_CFLAGS
        LDFLAGS=$save_LDFLAGS
        break
    else
        AC_MSG_RESULT([no])
    fi
    AC_MSG_CHECKING([for lua.h in ${x}/include])
    if test -f ${x}/include/lua.h; then
        AC_MSG_RESULT([yes])
        save_CFLAGS=$CFLAGS
        save_LDFLAGS=$LDFLAGS
        CFLAGS="$CFLAGS"
        LDFLAGS="-L$x/lib $LDFLAGS $lib_m"
        AC_CHECK_LIB(lua, luaL_newstate, [
            LUA_LIBS="-L$x/lib -llua $lib_m"
            LUA_CFLAGS="-I$x/include"
            ])
        CFLAGS=$save_CFLAGS
        LDFLAGS=$save_LDFLAGS
        break
    else
        AC_MSG_RESULT([no])
    fi
  fi
done

AC_SUBST(LUA_LIBS)
AC_SUBST(LUA_CFLAGS)

if test -z "${LUA_LIBS}"; then
  AC_MSG_NOTICE([*** Lua 5.1 library not found.])
  ifelse([$2], , AC_MSG_ERROR([Lua 5.1 library is required]), $2)
else
  AC_MSG_NOTICE([using '${LUA_LIBS}' for Lua Library])
  AC_ARG_ENABLE(luajit,
    APACHE_HELP_STRING(--enable-luajit,Enable LuaJit Support),
    APR_ADDTO(CPPFLAGS, ["-DAP_ENABLE_LUAJIT"]))
  ifelse([$1], , , $1) 
fi 
])

lua_objects="lua_apr.lo lua_config.lo mod_lua.lo lua_request.lo lua_vmprep.lo"

APACHE_MODULE(lua, Apache Lua Framework, $lua_objects, , no, [
  CHECK_LUA()
  APR_ADDTO(INCLUDES, ["$LUA_CFLAGS"])
  MOD_LUA_LDADD="$LUA_LIBS"
])

APACHE_MODPATH_FINISH
