APACHE_MODPATH_INIT(tls)

tls_objs="mod_tls.lo openssl_state_machine.lo"

APACHE_MODULE(tls, TLS/SSL support, $tls_objs, , no, [
  AC_MSG_CHECKING(for TLS/SSL library)
  AC_ARG_WITH(tls,   [  --with-tls=DIR          use a specific TLS/SSL library],
  [
      if test x"$withval" = x"yes"; then
          # FreeBSD has OpenSSL in /usr/{include,lib}
          for dir in  /usr /usr/local/openssl /usr/local/ssl
          do
              if test -d $dir && test -f $dir/lib/libcrypto.a; then
                  withval=$dir
                  break
              fi
          done
          if test x"$withval" = x"yes"; then
              AC_MSG_ERROR(Use --with-tls=DIR to specify the location of your SSL installation)
          fi
      fi
      ssl_lib=unknown
      for params in \
        "OpenSSL|/include/openssl|/lib|-lssl -lcrypto" \
	"SSLC|/inc||-lsslc"
      do
          prod=`IFS="|"; set -- $params; echo $1`
          incdir=`IFS="|"; set -- $params; echo $2`
          libdir=`IFS="|"; set -- $params; echo $3`
          libs=`IFS="|"; set -- $params; echo $4`
          searchfile="${withval}${incdir}/ssl.h"
          if test -f ${searchfile} ; then
              APR_ADDTO(INCLUDES, [-I${withval}${incdir}])
              APR_ADDTO(LIBS, [-L${withval}${libdir} ${libs}])
              ssl_lib="${prod}"
              break
          fi
      done
      if test x"${ssl_lib}" = x"unknown"; then
        AC_MSG_ERROR(--with-tls given but no appropriate lib found)
      else
        AC_MSG_RESULT(found $ssl_lib)
      fi
  ],[
      AC_MSG_ERROR(--with-tls not given)
  ] ) ] )

APACHE_MODPATH_FINISH
