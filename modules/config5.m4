AC_MSG_CHECKING(for extra modules)
AC_ARG_WITH(module,
  APACHE_HELP_STRING(--with-module=module-type:module-file,
                     Enable module-file in the modules/<module-type> directory.),
  [
    modtype=`echo $withval | sed -e's/\(.*\):.*/\1/'`
    pkg=`echo $withval | sed -e's/.*:\(.*\)/\1/'`
    modfilec=`echo $pkg | sed -e 's;^.*/;;'`
    modfileo=`echo $pkg | sed -e 's;^.*/;;' -e 's;\.c$;.o;'`

    if test "x$withval" != "xmodules/$modtype/$modfilec"; then
        cp $pkg modules/$modtype/$modfilec
    fi
    module=`echo $pkg | sed -e 's;.*/mod_\(.*\).c;\1;'`
    objects="mod_$module.lo"
    libname="mod_$module.la"
    modpath_current="modules/$modtype"
    BUILTIN_LIBS="$BUILTIN_LIBS $modpath_current/$libname"
    if test ! -s "$modpath_current/modules.mk"; then
      cat >>$modpath_current/modules.mk<<EOF
$libname: $objects
	\$(MOD_LINK) $objects
DISTCLEAN_TARGETS = modules.mk
static = $libname
shared =
EOF
    else
      cat >>$modpath_current/modules.mk.tmp<<EOF
$libname: $objects
	\$(MOD_LINK) $objects
EOF
      cat $modpath_current/modules.mk >> $modpath_current/modules.mk.tmp
      rm $modpath_current/modules.mk
      mv $modpath_current/modules.mk.tmp $modpath_current/modules.mk
      sed -e "s/\(static =.*\)/\1 $libname/" $modpath_current/modules.mk > $modpath_current/modules.mk.tmp
      rm $modpath_current/modules.mk
      mv $modpath_current/modules.mk.tmp $modpath_current/modules.mk
    fi
    MODLIST="$MODLIST $module"
  AC_MSG_RESULT(added $withval)
  ],
  [ AC_MSG_RESULT(no extra modules) 
  ])
