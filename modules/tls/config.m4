AC_MSG_CHECKING(for SSL library)
APACHE_MODPATH_INIT(tls)

tls_objs="mod_tls.lo openssl_state_machine.lo"

APACHE_MODULE(tls, TLS/SSL support, $tls_objs, , no, [
  AC_ARG_WITH(ssl,   [ --with-ssl      use a specific SSL library installation ],
  [
      searchfile="$withval/inc/ssl.h"
      if test -f $searchfile ; then
          INCLUDES="$INCLUDES -I$withval/inc"
          LIBS="$LIBS -L$withval -lsslc"
          ssl_lib="SSLC"
      else
          searchfile="$withval/ssl/ssl.h"
          if test -f $searchfile ; then
              INCLUDES="$INCLUDES -I$withval/include"
              LIBS="$LIBS -L$withval -lssl -lcrypto"
              ssl_lib="OpenSSL"
          else
              AC_MSG_ERROR(no - Unable to locate $withval/inc/ssl.h)
          fi
      fi
      AC_MSG_RESULT(found $ssl_lib)
  ],[
      AC_MSG_ERROR(--with-ssl not given)
  ] ) ] )

APACHE_MODPATH_FINISH
