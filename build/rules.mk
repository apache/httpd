# ====================================================================
# Copyright (c) 1995-2000 The Apache Software Foundation.  All rights reserved.
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
# 3. All advertising materials mentioning features or use of this
#    software must display the following acknowledgment:
#    "This product includes software developed by the Apache Software Foundatio
#
#    for use in the Apache HTTP server project (http://www.apache.org/)."
#
# 4. The names "Apache Server" and "Apache Software Foundation" must not be use
# to
#    endorse or promote products derived from this software without
#    prior written permission. For written permission, please contact
#    apache@apache.org.
#
# 5. Products derived from this software may not be called "Apache"
#    nor may "Apache" appear in their names without prior written
#    permission of the Apache Software Foundation.
#
# 6. Redistributions of any form whatsoever must retain the following
#    acknowledgment:
#    "This product includes software developed by the Apache Software Foundatio
#
#    for use in the Apache HTTP server project (http://www.apache.org/)."       #
# THIS SOFTWARE IS PROVIDED BY THE Apache Software Foundation ``AS IS'' AND ANY
# EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE Apache Software Foundation OR
# ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
# OF THE POSSIBILITY OF SUCH DAMAGE.
# ====================================================================
#
# This software consists of voluntary contributions made by many
# individuals on behalf of the Apache Software Foundation and was originally based
# on public domain software written at the National Center for
# Supercomputing Applications, University of Illinois, Urbana-Champaign.
# For more information on the Apache Software Foundation and the Apache HTTP server
# project, please see <http://www.apache.org/>.
#
#
#
# The build environment was provided by Sascha Schumann.
#

include $(DEPTH)/config_vars.mk


SHLIB_SUFFIX = so
COMPILE = $(CC) $(DEFS) $(INCLUDES) $(EXTRA_INCLUDES) $(CPPFLAGS) $(CFLAGS) $(EXTRA_CFLAGS)
LTCOMPILE = $(LIBTOOL) --mode=compile $(CC) $(DEFS) $(INCLUDES) $(EXTRA_INCLUDES) $(CPPFLAGS) $(CFLAGS) $(EXTRA_CFLAGS)
CCLD = $(CC)
LINK = $(LIBTOOL) --mode=link $(CCLD) $(LTFLAGS) $(CFLAGS) $(EXTRA_CFLAGS) $(LDFLAGS) -o $@
mkinstalldirs = $(abs_srcdir)/helpers/mkdir.sh
INSTALL = $(abs_srcdir)/helpers/install.sh -c
INSTALL_DATA = $(INSTALL) -m 644
INSTALL_PROGRAM = $(INSTALL) -m 755
SHLIBTOOL = $(SHELL) $(DEPTH)/shlibtool --silent
APACHE_COMPILE = $(COMPILE) -c $< && touch $@
APACHE_SH_COMPILE = $(SHLIBTOOL) --mode=compile $(CC) $(DEFS) $(INCLUDES) $(EXTRA_INCLUDES) $(CPPFLAGS) $(CFLAGS) $(EXTRA_CFLAGS) -c $< && touch $@
SHLINK = $(SHLIBTOOL) --mode=link $(CCLD) $(CFLAGS) $(EXTRA_CFLAGS) $(LDFLAGS) -o $@

DEFS = -DHAVE_CONFIG_H -I. -I$(srcdir) -I$(DEPTH)

top_srcdir   = $(topsrcdir)
top_builddir = $(DEPTH)

.SUFFIXES:
.SUFFIXES: .S .c .lo .o .s .y .l .slo

.c.o:
	$(COMPILE) -c $<

.s.o:
	$(COMPILE) -c $<

.S.o:
	$(COMPILE) -c $<

.c.lo:
	$(APACHE_COMPILE)

.s.lo:
	$(APACHE_COMPILE)

.S.lo:
	$(APACHE_COMPILE)

.c.slo:
	$(APACHE_SH_COMPILE)
	
.y.c:
	$(YACC) $(YFLAGS) $< && mv y.tab.c $*.c
	if test -f y.tab.h; then \
	if cmp -s y.tab.h $*.h; then rm -f y.tab.h; else mv y.tab.h $*.h; fi; \
	else :; fi

.l.c:
	$(LEX) $(LFLAGS) $< && mv $(LEX_OUTPUT_ROOT).c $@


all: all-recursive
install: install-recursive

distclean-recursive depend-recursive clean-recursive all-recursive install-recursive:
	@otarget=`echo $@|sed s/-recursive//`; \
	if test '$(NO_RECURSION)' != "$$otarget"; then \
		list='$(SUBDIRS)'; for i in $$list; do \
			target="$$otarget"; \
			echo "Making $$target in $$i"; \
			if test "$$i" = "."; then \
				ok=yes; \
				target="$$target-p"; \
			fi; \
			if test ! -f $$i/.deps; then touch $$i/.deps; fi; \
			(cd $$i && $(MAKE) $$target) || exit 1; \
		done; \
		if test "$$otarget" = "all" && test -z '$(targets)'; then ok=yes; fi;\
		if test "$$ok" != "yes"; then $(MAKE) "$$otarget-p" || exit 1; fi;\
	fi

all-p: $(targets)
install-p: $(targets) $(install_targets)
	@if test -n '$(PROGRAMS)'; then \
		test -d $(bindir) || $(mkinstalldirs) $(bindir); \
		for i in "$(PROGRAMS)"; do \
			$(INSTALL_PROGRAM) $$i $(bindir); \
		done; \
	fi

distclean-p depend-p clean-p:

depend: depend-recursive
	test "`echo *.c`" = '*.c' || perl $(top_srcdir)/build/mkdep.perl $(CPP) $(INCLUDES) $(EXTRA_INCLUDES) *.c > .deps

clean: clean-recursive clean-x

clean-x:
	rm -f $(targets) *.slo *.lo *.la *.o $(CLEANFILES)
	rm -rf .libs

distclean: distclean-recursive clean-x
	rm -f config.cache config.log config.status config_vars.mk libtool \
	stamp-h Makefile shlibtool .deps $(DISTCLEANFILES)

include $(srcdir)/.deps

.PHONY: all-recursive clean-recursive install-recursive \
$(install_targets) install all clean depend depend-recursive shared \
distclean-recursive distclean clean-x all-p install-p distclean-p \
depend-p clean-p $(phony_targets)
