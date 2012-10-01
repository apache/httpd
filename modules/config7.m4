AC_MSG_CHECKING(for extra modules)
AC_ARG_WITH(module,
  APACHE_HELP_STRING(--with-module=module-type:module-file,
                     Enable module-file in the modules/<module-type> directory.),
  [
    withval=`echo $withval | sed -e 's/,/ /g'`
    for mod in $withval
    do
      modtype=`echo $mod | sed -e's/\(.*\):.*/\1/'`
      pkg=`echo $mod | sed -e's/.*:\(.*\)/\1/'`
      modfilec=`echo $pkg | sed -e 's;^.*/;;'`
      modfileo=`echo $pkg | sed -e 's;^.*/;;' -e 's;\.c$;.o;'`
      modpath_current="modules/$modtype"
      if test "x$mod" != "x$modpath_current/$modfilec"; then
        if test ! -d "$modpath_current"; then
          mkdir $modpath_current
          echo 'include $(top_srcdir)/build/special.mk' > $modpath_current/Makefile.in
        fi
        cp $pkg $modpath_current/$modfilec
      fi
      module=`echo $pkg | sed -e 's;\(.*/\).*mod_\(.*\).c;\2;'`
      objects="mod_$module.lo"
      # The filename of a convenience library must have a "lib" prefix:
      libname="libmod_$module.la"
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
      EXTRA_MODLIST="$EXTRA_MODLIST $modtype:$modfilec"
      MODULE_DIRS="$MODULE_DIRS $modtype"
      APACHE_FAST_OUTPUT($modpath_current/Makefile)
    done
    if test ! -z "$EXTRA_MODLIST"; then
      AC_MSG_RESULT(added:$EXTRA_MODLIST)
    fi
  ],
  [ AC_MSG_RESULT(none) 
  ])
