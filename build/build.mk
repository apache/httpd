# Copyright (c) 1999, 2000 Sascha Schumann. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY SASCHA SCHUMANN ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO
# EVENT SHALL SASCHA SCHUMANN BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
##############################################################################
# $Id: build.mk,v 1.4 2000/02/07 17:16:57 dreid Exp $ 
#
# Makefile to generate build tools
#

STAMP = buildmk.stamp

all: $(STAMP) generated_lists
	@$(MAKE) AMFLAGS=$(AMFLAGS) -s -f build/build2.mk

generated_lists:
	@echo config_m4_files = `find . -name config.m4` > $@
	@n=`helpers/PrintPath libtool`; echo libtool_prefix = `dirname $$n`/.. >> $@

$(STAMP): build/buildcheck.sh
	@build/buildcheck.sh && touch $(STAMP)

snapshot:
	distname='$(DISTNAME)'; \
	if test -z "$$distname"; then \
		distname='apache2-snapshot'; \
	fi; \
	cd ..; \
	myname=`basename \`pwd\`` ; \
	cd .. && cp -rp $$myname $$distname; \
	cd $$distname/src; \
	find . -type l -exec rm {} \; ; \
	$(MAKE) AMFLAGS=--copy -f build/build.mk; \
	cd ../..; \
	tar cf $$distname.tar $$distname; \
	rm -rf $$distname $$distname.tar.*; \
	bzip2 -9 $$distname.tar; \
	bzip2 -t $$distname.tar.bz2

cvsclean:
	@for i in `find . -name .cvsignore`; do \
		(cd `dirname $$i` 2>/dev/null && rm -rf `cat .cvsignore` *.o *.a || true); \
	done
	@rm -f $(SUBDIRS) 2>/dev/null || true

.PHONY: generated_lists snapshot cvsclean
