dnl ## ====================================================================
dnl ## The Apache Software License, Version 1.1
dnl ##  
dnl ## Copyright (c) 2000-2002 The Apache Software Foundation.  All rights
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
ssl_objs="dnl
mod_ssl.lo dnl
ssl_engine_config.lo dnl
ssl_engine_dh.lo dnl
ssl_engine_init.lo dnl
ssl_engine_io.lo dnl
ssl_engine_kernel.lo dnl
ssl_engine_log.lo dnl
ssl_engine_mutex.lo dnl
ssl_engine_pphrase.lo dnl
ssl_engine_rand.lo dnl
ssl_engine_vars.lo dnl
ssl_expr.lo dnl
ssl_expr_eval.lo dnl
ssl_expr_parse.lo dnl
ssl_expr_scan.lo dnl
ssl_scache.lo dnl
ssl_scache_dbm.lo dnl
ssl_scache_shmcb.lo dnl
ssl_scache_shmht.lo dnl
ssl_util.lo dnl
ssl_util_ssl.lo dnl
ssl_util_table.lo dnl
"
dnl #  hook module into the Autoconf mechanism (--enable-ssl option)
APACHE_MODULE(ssl, [SSL/TLS support (mod_ssl)], $ssl_objs, , no, [
    APACHE_CHECK_SSL_TOOLKIT
    AC_CHECK_FUNCS(SSL_set_state)
    AC_CHECK_FUNCS(SSL_set_cert_store)
])

dnl #  end of module specific part
APACHE_MODPATH_FINISH

