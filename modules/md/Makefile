top_srcdir   = /Users/sei/projects/httpd/trunk-md
top_builddir = /Users/sei/projects/httpd/trunk-md
srcdir       = /Users/sei/projects/httpd/trunk-md/modules/md
builddir     = /Users/sei/projects/httpd/trunk-md/modules/md
VPATH        = /Users/sei/projects/httpd/trunk-md/modules/md
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

local-shared-build: $(LTLIBRARY_NAME) $(SHARED_TARGETS)


include $(top_srcdir)/build/library.mk
include $(top_srcdir)/build/special.mk
