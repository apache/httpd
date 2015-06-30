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

NGHTTP2_VERSION = 1.0.5
NGHTTP2_DIR     = nghttp2-$(NGHTTP2_VERSION)
NGHTTP2_TAR     = $(NGHTTP2_DIR).tar.gz
NGHTTP2_URL     = https://github.com/tatsuhiro-t/nghttp2/releases/download/v$(NGHTTP2_VERSION)/$(NGHTTP2_TAR)

NGHTTP2_CONF_ENV=
NGHTTP2_DEPS    =
NGHTTP2_CONF    = --prefix=$(BLD_PREFIX) --enable-app

ZLIB_VERSION    = 1.2.8
ZLIB_DIR        = zlib-$(ZLIB_VERSION)
ZLIB_TAR        = $(ZLIB_DIR).tar.gz
ZLIB_URL        = http://zlib.net/$(ZLIB_TAR)

LIBEV_VERSION    = 4.19
LIBEV_DIR        = libev-$(LIBEV_VERSION)
LIBEV_TAR        = $(LIBEV_DIR).tar.gz
LIBEV_URL        = http://dist.schmorp.de/libev/$(LIBEV_TAR)
LIBEV_CONF_ENV   += PKG_CONFIG_PATH=$(BLD_PREFIX)/lib/pkgconfig \
    LDFLAGS=-L$(BLD_PREFIX)/lib CFLAGS=-I$(BLD_PREFIX)/include

LIBEVENT_VERSION = 2.0.22-stable
LIBEVENT_DIR     = libevent-$(LIBEVENT_VERSION)
LIBEVENT_TAR     = $(LIBEVENT_DIR).tar.gz
LIBEVENT_URL     = https://github.com/libevent/libevent/releases/download/release-2.0.22-stable/$(LIBEVENT_TAR)
LIBEVENT_CONF_ENV += PKG_CONFIG_PATH=$(BLD_PREFIX)/lib/pkgconfig \
    LDFLAGS=-L$(BLD_PREFIX)/lib CFLAGS=-I$(BLD_PREFIX)/include

GEN             = gen
INST_DIR        = ../install
BLD_PREFIX      = $(shell dirname $$PWD)/install

CURL_OPTS       = --progress-bar

OS              = $(shell uname -s)


NGHTTP2_CONF_ENV += PKG_CONFIG_PATH=$(BLD_PREFIX)/lib/pkgconfig \
    LDFLAGS=-L$(BLD_PREFIX)/lib CFLAGS=-I$(BLD_PREFIX)/include


# For OS X, we drag our own zlib in as the one installed is not
# recognized by nghttp2 configure.
# On other OS, we expect a proper zlib/zlib-dev installation
#
ifeq ($(OS),Darwin)
    # we need our own zlib
    NGHTTP2_DEPS  += $(INST_DIR)/.zlib-installed $(INST_DIR)/.libev-installed
else
ifneq (,$(wildcard $(INST_DIR)/lib/pkgconfig/openssl.pc))
    NGHTTP2_DEPS  += $(INST_DIR)/.libevent-installed
endif
endif

all: install

dirs:
	@mkdir -p $(GEN)/build

clean:
	@rm -rf $(GEN)/$(NGHTTP2_DIR)

distclean:
	@rm -rf $(GEN)

distdir:
	@mkdir -p $(distdir)
	@tar cf - Makefile patches | (cd $(distdir) && tar xf - )

install:  $(INST_DIR)/.nghttp2-installed


################################################################################
# Install the local nghttp2
#
$(INST_DIR)/.nghttp2-installed:  $(GEN)/$(NGHTTP2_DIR)/.nghttp2-built
	@echo -n installing nghttp2 locally...
	@cd $(GEN)/$(NGHTTP2_DIR)/ && make install >> ../build.log
	@echo done.
	@touch $(INST_DIR)/.nghttp2-installed


################################################################################
# Build the local nghttp2
#
$(GEN)/$(NGHTTP2_DIR)/.nghttp2-built: \
		$(GEN)/$(NGHTTP2_DIR)/.nghttp2-configured
	@echo -n building nghttp2...
	@cd $(GEN)/$(NGHTTP2_DIR)/ && make >> ../build.log
	@echo done.
	@touch $(GEN)/$(NGHTTP2_DIR)/.nghttp2-built

################################################################################
# Configure the local nghttp2 sources
#
$(GEN)/$(NGHTTP2_DIR)/.nghttp2-configured: \
		$(NGHTTP2_DEPS) \
		$(GEN)/$(NGHTTP2_DIR)/.nghttp2-patched
	@echo -n configuring nghttp2...
	cd $(GEN)/$(NGHTTP2_DIR)/ && \
	$(NGHTTP2_CONF_ENV) ./configure $(NGHTTP2_CONF) >> ../build.log
	@echo done.
	@touch $(GEN)/$(NGHTTP2_DIR)/.nghttp2-configured

################################################################################
# Patch the local nghtp2 sources
#
$(GEN)/$(NGHTTP2_DIR)/.nghttp2-patched: \
		$(GEN)/$(NGHTTP2_DIR)/.nghttp2-extracted
	@touch $(GEN)/$(NGHTTP2_DIR)/.nghttp2-patched

################################################################################
# Extract nghttp2 source tree
#
$(GEN)/$(NGHTTP2_DIR)/.nghttp2-extracted: \
		$(GEN)/$(NGHTTP2_TAR)
	@rm -rf $(GEN)/$(NGHTTP2_DIR)
	@echo -n extracting nghttp2 packages...
	@cd $(GEN) && tar xfz $(NGHTTP2_TAR)
	@echo done.
	@touch $(GEN)/$(NGHTTP2_DIR)/.nghttp2-extracted

################################################################################
# Retrieve nghttp2 sources
#
$(GEN)/$(NGHTTP2_TAR):
	@mkdir -p $(GEN)
	curl $(CURL_OPTS) -L $(NGHTTP2_URL) > $(GEN)/$(NGHTTP2_TAR)


################################################################################
# Build + install a local libevent library (if needed)
#
$(INST_DIR)/.libevent-installed: \
		$(GEN)/$(LIBEVENT_DIR)/.libevent-built
	@echo -n installing libevent locally...
	@cd $(GEN)/$(LIBEVENT_DIR) && make install >> ../build.log
	@echo done.
	@touch $(INST_DIR)/.libevent-installed

$(GEN)/$(LIBEVENT_DIR)/.libevent-built: \
		$(GEN)/$(LIBEVENT_DIR)/.libevent-configured
	@echo -n building libevent locally...
	@cd $(GEN)/$(LIBEVENT_DIR) && make >> ../build.log
	@echo done.
	@touch $(GEN)/$(LIBEVENT_DIR)/.libevent-built

$(GEN)/$(LIBEVENT_DIR)/.libevent-configured: \
        	$(GEN)/$(LIBEVENT_DIR)/.libevent-extracted
	@echo -n configuring libevent...
	@cd $(GEN)/$(LIBEVENT_DIR) && $(LIBEVENT_CONF_ENV) ./configure --prefix=$(BLD_PREFIX) --with-sysroot=$(BLD_PREFIX)
	@echo done.
	@touch $(GEN)/$(LIBEVENT_DIR)/.libevent-configured

$(GEN)/$(LIBEVENT_DIR)/.libevent-extracted: \
        $(GEN)/$(LIBEVENT_TAR)
	@rm -rf $(GEN)/$(LIBEVENT_DIR)
	@echo -n downloading and extracting libevent...
	@cd gen; tar xfz $(LIBEVENT_TAR)
	@echo done.
	@touch $(GEN)/$(LIBEVENT_DIR)/.libevent-extracted

$(GEN)/$(LIBEVENT_TAR):
	@mkdir -p $(GEN)
	curl $(CURL_OPTS) -L $(LIBEVENT_URL) > $(GEN)/$(LIBEVENT_TAR)

################################################################################
# Build + install a local libev library (if needed)
#
$(INST_DIR)/.libev-installed: \
		$(GEN)/$(LIBEV_DIR)/.libev-built
	@echo -n installing libev locally...
	@cd $(GEN)/$(LIBEV_DIR) && make install >> ../build.log
	@echo done.
	@touch $(INST_DIR)/.libev-installed

$(GEN)/$(LIBEV_DIR)/.libev-built: \
		$(GEN)/$(LIBEV_DIR)/.libev-configured
	@echo -n building libev locally...
	@cd $(GEN)/$(LIBEV_DIR) && make >> ../build.log
	@echo done.
	@touch $(GEN)/$(LIBEV_DIR)/.libev-built

$(GEN)/$(LIBEV_DIR)/.libev-configured: $(GEN)/$(LIBEV_TAR)
	@rm -rf $(GEN)/$(LIBEV_DIR)
	@cd $(GEN) && tar xfz $(LIBEV_TAR)
	@echo -n configuring libev...
	@cd $(GEN)/$(LIBEV_DIR) && $(LIBEV_CONF_ENV) ./configure --prefix=$(BLD_PREFIX)
	@echo done.
	@touch $(GEN)/$(LIBEV_DIR)/.libev-configured

$(GEN)/$(LIBEV_TAR):
	@mkdir -p $(GEN)
	curl $(CURL_OPTS) -L $(LIBEV_URL) > $(GEN)/$(LIBEV_TAR)

################################################################################
# Build + install a local zlib library (if needed)
#
$(INST_DIR)/.zlib-installed: \
		$(GEN)/$(ZLIB_DIR)/.zlib-built
	@echo -n installing zlib locally...
	@cd $(GEN)/$(ZLIB_DIR) && make install >> ../build.log
	@echo done.
	@touch $(INST_DIR)/.zlib-installed

$(GEN)/$(ZLIB_DIR)/.zlib-built: \
		$(GEN)/$(ZLIB_DIR)/.zlib-configured
	@echo -n building zlib locally...
	@cd $(GEN)/$(ZLIB_DIR) && make >> ../build.log
	@echo done.
	@touch $(GEN)/$(ZLIB_DIR)/.zlib-built

$(GEN)/$(ZLIB_DIR)/.zlib-configured: $(GEN)/$(ZLIB_TAR)
	@rm -rf $(GEN)/$(ZLIB_DIR)
	@cd $(GEN) && tar xfz $(ZLIB_TAR)
	@echo -n configuring zlib...
	@cd $(GEN)/$(ZLIB_DIR) && ./configure --prefix=$(BLD_PREFIX)
	@echo done.
	@touch $(GEN)/$(ZLIB_DIR)/.zlib-configured

$(GEN)/$(ZLIB_TAR):
	@mkdir -p $(GEN)
	curl $(CURL_OPTS) -L $(ZLIB_URL) > $(GEN)/$(ZLIB_TAR)

