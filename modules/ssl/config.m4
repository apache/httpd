dnl ## ====================================================================
dnl ## The Apache Software License, Version 1.1
dnl ##  
dnl ## Copyright (c) 2000-2001 The Apache Software Foundation.  All rights
dnl ## reserved.
dnl ##
dnl ## Redistribution and use in source and binary forms, with or without
dnl ## modification, are permitted provided that the following conditions
dnl ## are met:
dnl ##
dnl ## 1. Redistributions of source code must retain the above copyright
dnl ##    notice, this list of conditions and the following disclaimer.
dnl ##
dnl ## 2. Redistributions in binary form must reproduce the above copyright
dnl ##    notice, this list of conditions and the following disclaimer in
dnl ##    the documentation and/or other materials provided with the
dnl ##    distribution.
dnl ##
dnl ## 3. The end-user documentation included with the redistribution,
dnl ##    if any, must include the following acknowledgment:
dnl ##       "This product includes software developed by the
dnl ##        Apache Software Foundation (http://www.apache.org/)."
dnl ##    Alternately, this acknowledgment may appear in the software itself,
dnl ##    if and wherever such third-party acknowledgments normally appear.
dnl ##
dnl ## 4. The names "Apache" and "Apache Software Foundation" must
dnl ##    not be used to endorse or promote products derived from this
dnl ##    software without prior written permission. For written
dnl ##    permission, please contact apache@apache.org.
dnl ##
dnl ## 5. Products derived from this software may not be called "Apache",
dnl ##    nor may "Apache" appear in their name, without prior written
dnl ##    permission of the Apache Software Foundation.
dnl ##
dnl ## THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
dnl ## WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
dnl ## OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
dnl ## DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
dnl ## ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
dnl ## SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
dnl ## LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
dnl ## USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
dnl ## ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
dnl ## OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
dnl ## OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
dnl ## SUCH DAMAGE.
dnl ## ====================================================================

dnl #  start of module specific part
APACHE_MODPATH_INIT(ssl)

dnl #  list of module object files
ssl_objs="mod_ssl.lo"
ssl_objs="$ssl_objs ssl_engine_config.lo"

dnl #  hook module into the Autoconf mechanism (--enable-ssl option)
APACHE_MODULE(ssl, [SSL/TLS support (mod_ssl)], $ssl_objs, , no, [

    dnl #  hook into Autoconf mechanism (--with-ssl[=DIR] option)
    AC_MSG_CHECKING(for SSL/TLS toolkit base)
    ssltk_base="SYSTEM"
    AC_ARG_WITH(ssl, [  --with-ssl[=DIR]        SSL/TLS toolkit (OpenSSL)], [
        if test ".$withval" != .yes -a ".$withval" != .; then
            ssltk_base="$withval"
            if test ! -d $ssltk_base; then
                AC_MSG_ERROR([invalid SSL/TLS toolkit base directory $ssltk_base])
            fi
        fi
    ])
    AC_MSG_RESULT($ssltk_base)
    
    dnl #   determine SSL/TLS toolkit frontend (openssl binary)
    AC_MSG_CHECKING(for SSL/TLS toolkit frontend)
    ssltk_frontend=""
    if test ".$ssltk_base" = .SYSTEM; then
        for p in . `echo $PATH | sed -e 's/:/ /g'`; do
            if test -f "$p/openssl"; then
                ssltk_frontend="$p/openssl"
                break
            fi
        done
        if test ".$ssltk_frontend" = .; then
            AC_MSG_ERROR(['openssl' not found in $PATH])
        fi
    else
        if test -f "$ssltk_base/bin/openssl"; then
            ssltk_frontend="$ssltk_base/bin/openssl"
        else
            AC_MSG_ERROR(['openssl' not found in $ssltk_base/bin/])
        fi
    fi
    AC_MSG_RESULT($ssltk_frontend)

    dnl #   determine SSL/TLS toolkit version
    AC_MSG_CHECKING(for SSL/TLS toolkit version)
    ssltk_version="`$ssltk_frontend version`"
    case "$ssltk_version" in
        *0.9.[[6789]]* ) ;;
        * ) AC_MSG_ERROR([SSL/TLS toolkit version $ssltk_version not supported]) ;;
    esac
    AC_MSG_RESULT($ssltk_version)

    dnl #   determine SSL/TLS toolkit include directory
    AC_MSG_CHECKING(for SSL/TLS toolkit includes)
    ssltk_incdir=""
    if test ".$ssltk_base" = .SYSTEM; then
        for p in . /usr/include /usr/include/ssl/ /usr/local/include /usr/local/include/ssl; do
            if test -f "$p/openssl/ssl.h"; then
                ssltk_incdir="$p"
                break
            fi
        done
        if test ".$ssltk_incdir" = .; then
            AC_MSG_ERROR([OpenSSL headers not found])
        fi
    else
        if test -f "$ssltk_base/include/openssl/ssl.h"; then
            ssltk_incdir="$ssltk_base/include"
        else
            AC_MSG_ERROR([OpenSSL headers not found under $ssltk_base])
        fi
    fi
    AC_MSG_RESULT($ssltk_incdir)

    dnl #   determine SSL/TLS toolkit library directory
    AC_MSG_CHECKING(for SSL/TLS toolkit libraries)
    ssltk_libdir=""
    if test ".$ssltk_base" = .SYSTEM; then
        for p in . /lib /usr/lib /usr/local/lib; do
            if test -f "$p/libssl.a" -o -f "$p/libssl.so"; then
                ssltk_libdir="$p"
                break
            fi
        done
        if test ".$ssltk_libdir" = .; then
            AC_MSG_ERROR([OpenSSL libraries not found])
        fi
    else
        if test -f "$ssltk_base/libssl.a" -o -f "$ssltk_base/libssl.so"; then
            ssltk_libdir="$ssltk_base"
        elif test -f "$ssltk_base/lib/libssl.a" -o -f "$ssltk_base/lib/libssl.so"; then
            ssltk_libdir="$ssltk_base/lib"
        else
            AC_MSG_ERROR([OpenSSL libraries not found under $ssltk_base])
        fi
    fi
    AC_MSG_RESULT($ssltk_libdir)

    dnl #  annotate the Apache build environment with determined information
    if test ".$ssltk_incdir" != "./usr/include"; then
        INCLUDES="$INCLUDES -I$ssltk_incdir"
    fi
    if test ".$ssltk_libdir" != "./usr/lib"; then
        LIBS="$LIBS -L$ssltk_libdir -lssl -lcrypto"
    fi
])

dnl #  end of module specific part
APACHE_MODPATH_FINISH

