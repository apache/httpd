APACHE_MODPATH_INIT(tls)

tls_objs="mod_tls.lo openssl_state_machine.lo"

APACHE_MODULE(tls, TLS/SSL support, $tls_objs, , no, [
  AC_MSG_CHECKING(for TLS/SSL library)
  AC_ARG_WITH(tls,   [  --with-tls=DIR          use a specific TLS/SSL library],
  [
      searchfile="$withval/inc/ssl.h"
      if test -f $searchfile ; then
          APR_ADDTO(INCLUDES, [-I$withval/inc])
          APR_ADDTO(LIBS, [-L$withval -lsslc])
          ssl_lib="SSLC"
      else
          searchfile="$withval/ssl/ssl.h"
          if test -f $searchfile ; then
              APR_ADDTO(INCLUDES, [-I$withval/include])
              APR_ADDTO(LIBS, [-L$withval -lssl -lcrypto])
              ssl_lib="OpenSSL"
          else
              searchfile="$withval/openssl/ssl.h"
              if test -f $searchfile ; then
                  APR_ADDTO(INCLUDES, [-I$withval/openssl])
                  APR_ADDTO(LIBS, [-L$withval -lssl -lcrypto])
                  ssl_lib="OpenSSL"
              else
                  searchfile="$withval/include/openssl/ssl.h"
                  if test -f $searchfile ; then
                      APR_ADDTO(INCLUDES, [-I$withval/include])
                      APR_ADDTO(LIBS, [-L$withval/lib -lssl -lcrypto])
                      ssl_lib="OpenSSL"
                  else
                      AC_MSG_ERROR(no - Unable to locate $withval/inc/ssl.h)
                  fi
              fi
          fi
      fi
      AC_MSG_RESULT(found $ssl_lib)
  ],[
      AC_MSG_ERROR(--with-tls not given)
  ] ) ] )

APACHE_MODPATH_FINISH
