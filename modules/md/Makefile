top_srcdir   = /Users/jim/src/asf/code/dev/httpd-git-trunk
top_builddir = /Users/jim/src/asf/code/dev/httpd-git-trunk
srcdir       = /Users/jim/src/asf/code/dev/httpd-git-trunk/modules/md
builddir     = /Users/jim/src/asf/code/dev/httpd-git-trunk/modules/md
VPATH        = /Users/jim/src/asf/code/dev/httpd-git-trunk/modules/md
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#
#   standard stuff
#


LTLIBRARY_NAME    = libmd.la
LTLIBRARY_SOURCES = \
	md_acme.c \
	md_acme_acct.c \
	md_acme_authz.c \
	md_acme_drive.c \
	md_core.c \
	md_curl.c \
	md_crypt.c \
	md_http.c \
	md_json.c \
	md_jws.c \
	md_log.c \
	md_reg.c \
	md_store.c \
	md_store_fs.c \
	md_util.c


LTLIBRARY_DEPENDENCIES = md.h


a2md_OBJECTS = \
	md_cmd_main.c \
	md_cmd_acme.c \
	md_cmd_reg.c \
	md_cmd_store.c

a2md: $(a2md_OBJECTS) $(LTLIBRARY_NAME)
	$(LINK) $(a2md_LTFLAGS) $(a2md_OBJECTS) -lmd $(A2MD_LDADD) $(AP_LIBS)

# top be installed in bin dir
bin_PROGRAMS = a2md

TARGETS = $(bin_PROGRAMS)

local-shared-build: $(LTLIBRARY_NAME) $(SHARED_TARGETS) a2md

include $(top_srcdir)/build/library.mk
include $(top_srcdir)/build/special.mk
