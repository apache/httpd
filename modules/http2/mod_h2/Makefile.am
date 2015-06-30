# Copyright 2015 greenbytes GmbH (https://www.greenbytes.de)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
SUBDIRS =

ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES    = mod_h2.la

mod_h2_la_CPPFLAGS = -std=c99 -D_GNU_SOURCE -Werror
mod_h2_la_LDFLAGS  = -module

OBJECTS = \
    h2_alpn.c \
    h2_alt_svc.c \
    h2_config.c \
    h2_conn.c \
    h2_conn_io.c \
    h2_ctx.c \
    h2_from_h1.c \
    h2_h2.c \
    h2_io.c \
    h2_io_set.c \
    h2_mplx.c \
    h2_request.c \
    h2_response.c \
    h2_session.c \
    h2_stream.c \
    h2_stream_set.c \
    h2_task.c \
    h2_task_input.c \
    h2_task_output.c \
    h2_task_queue.c \
    h2_to_h1.c \
    h2_upgrade.c \
    h2_util.c \
    h2_worker.c \
    h2_workers.c \
    mod_h2.c

HFILES = \
    h2_alpn.h \
    h2_alt_svc.h \
    h2_config.h \
    h2_conn.h \
    h2_conn_io.h \
    h2_ctx.h \
    h2_from_h1.h \
    h2_h2.h \
    h2_io.h \
    h2_io_set.h \
    h2_mplx.h \
    h2_private.h \
    h2_request.h \
    h2_response.h \
    h2_session.h \
    h2_stream.h \
    h2_stream_set.h \
    h2_task.h \
    h2_task_input.h \
    h2_task_output.h \
    h2_task_queue.h \
    h2_to_h1.h \
    h2_upgrade.h \
    h2_util.h \
    h2_version.h \
    h2_worker.h \
    h2_workers.h \
    mod_h2.h


mod_h2_la_SOURCES = $(HFILES) $(OBJECTS)

all: mod_h2.la

install-libLTLIBRARIES:
	@: # override

install-exec-local: mod_h2.la
	$(MKDIR_P) $(DESTDIR)/@LIBEXEC_DIR@
	$(APXS) -i -S LIBEXECDIR=$(DESTDIR)/@LIBEXEC_DIR@ -n h2 mod_h2.la


