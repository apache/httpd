dnl Licensed to the Apache Software Foundation (ASF) under one or more
dnl contributor license agreements.  See the NOTICE file distributed with
dnl this work for additional information regarding copyright ownership.
dnl The ASF licenses this file to You under the Apache License, Version 2.0

APACHE_MODPATH_INIT(random)

dnl mod_random - Cryptographically secure random token generation module
dnl Uses OpenSSL for HMAC-SHA256 signatures
random_objs="dnl
mod_random.lo dnl
mod_random_config.lo dnl
mod_random_encode.lo dnl
mod_random_crypto.lo dnl
mod_random_token.lo"

dnl Hook module into Autoconf (--enable-random option)
APACHE_MODULE(random, [Cryptographically secure random token generation], $random_objs, , most, [
    APACHE_CHECK_OPENSSL
    if test "$ac_cv_openssl" = "yes" ; then
        if test "x$enable_random" = "xshared"; then
           # Export only the module structure symbol
           APR_ADDTO(MOD_RANDOM_LDADD, [-export-symbols-regex random_module])
        fi
        APR_ADDTO(MOD_RANDOM_LDADD, [$OPENSSL_LIBS])
        APR_ADDTO(INCLUDES, [$OPENSSL_INCLUDES])
    else
        enable_random=no
    fi
])

dnl Ensure other modules can pick up mod_random.h if needed
APR_ADDTO(INCLUDES, [-I\$(top_srcdir)/$modpath_current])

APACHE_MODPATH_FINISH
