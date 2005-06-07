# Copyright 2000-2004 The Apache Software Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#
# The build environment was provided by Sascha Schumann.

all: all-recursive

include $(builddir)/modules.mk
TARGETS = $(static)
SHARED_TARGETS = $(shared)
INSTALL_TARGETS = install-modules

install-modules:
	@test -d $(DESTDIR)$(libexecdir) || $(MKINSTALLDIRS) $(DESTDIR)$(libexecdir)
	@builtin='$(BUILTIN_LIBS)'; \
	has_mod_so=`echo $$builtin|sed 's/^.*libmod_so.*$$/has_mod_so/'`; \
	if [ "x$$has_mod_so" = "xhas_mod_so" ]; then \
		list='$(shared)'; \
		for i in $$list; do \
			$(top_srcdir)/build/instdso.sh SH_LIBTOOL='$(SH_LIBTOOL)' $$i $(DESTDIR)$(libexecdir); \
		done; \
	fi	

include $(top_builddir)/build/rules.mk

