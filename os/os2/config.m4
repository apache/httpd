if test "$OS" = "os2" ; then
  CFLAGS="$CFLAGS -DOS2 -O2"
  LDFLAGS="$LDFLAGS -Zexe"
fi
