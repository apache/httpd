# ====================================================================
# The Apache Software License, Version 1.1
#
# Copyright (c) 2000 The Apache Software Foundation.  All rights
# reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# 3. The end-user documentation included with the redistribution,
#    if any, must include the following acknowledgment:
#       "This product includes software developed by the
#        Apache Software Foundation (http://www.apache.org/)."
#    Alternately, this acknowledgment may appear in the software itself,
#    if and wherever such third-party acknowledgments normally appear.
#
# 4. The names "Apache" and "Apache Software Foundation" must
#    not be used to endorse or promote products derived from this
#    software without prior written permission. For written
#    permission, please contact apache@apache.org.
#
# 5. Products derived from this software may not be called "Apache",
#    nor may "Apache" appear in their name, without prior written
#    permission of the Apache Software Foundation.
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
# ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
# USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
# ====================================================================
#
# This software consists of voluntary contributions made by many
# individuals on behalf of the Apache Software Foundation.  For more
# information on the Apache Software Foundation, please see
# <http://www.apache.org/>.
#
# The build environment was provided by Sascha Schumann.
#

include $(BUILD_BASE)/generated_lists

TOUCH_FILES = mkinstalldirs install-sh missing

LT_TARGETS = ltconfig ltmain.sh config.guess config.sub

config_h_in = include/ap_config_auto.h.in
apr_private.h_in = lib/apr/include/apr_private.h.in
apr_configure = lib/apr/configure
mm_configure = lib/apr/shmem/unix/mm/configure

APACHE_TARGETS = $(TOUCH_FILES) $(LT_TARGETS) configure $(config_h_in)

APR_TARGETS = $(apr_configure) $(apr_private.h_in) $(mm_configure)

targets = .deps aclocal.m4 $(APACHE_TARGETS) $(APR_TARGETS)

all: $(targets)

.deps:
	touch $@

libtool_m4 = $(libtool_prefix)/share/aclocal/libtool.m4

aclocal.m4: acinclude.m4 lib/apr/threads.m4 $(libtool_m4)
	@echo rebuilding $@
	@cat acinclude.m4 $(libtool_m4) > $@

$(LT_TARGETS):
	libtoolize $(AMFLAGS) --force

$(config_h_in): configure
# explicitly remove target since autoheader does not seem to work 
# correctly otherwise (timestamps are not updated)
	@echo rebuilding $@
	@rm -f $@
	autoheader

$(TOUCH_FILES):
	touch $(TOUCH_FILES)

configure: aclocal.m4 configure.in $(config_m4_files)
	@echo rebuilding $@
	rm -f config.cache
	autoconf

$(apr_private.h_in): $(apr_configure) lib/apr/acconfig.h
	@echo rebuilding $@
	@rm -f $@
	(cd lib/apr && autoheader)

$(apr_configure): lib/apr/aclocal.m4 lib/apr/configure.in lib/apr/threads.m4
	@echo rebuilding $@
	(cd lib/apr && autoconf)

$(mm_configure): lib/apr/shmem/unix/mm/configure.in
	@echo rebuilding $@
	(cd lib/apr/shmem/unix/mm && autoconf)
