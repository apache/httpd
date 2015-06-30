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

HOST_NAME    = test.example.org
HOST2_NAME   = test-ser.example.org

HTTP_PORT    = 12345
HTTPS_PORT   = 12346

HTTP_AUTH    = $(HOST_NAME):$(HTTP_PORT)
HTTPS_AUTH   = $(HOST_NAME):$(HTTPS_PORT)
HTTPS_AUTH2  = $(HOST2_NAME):$(HTTPS_PORT)

GEN          = gen
INST_DIR     = ../install
BLD_PREFIX   = $(shell dirname $$PWD)/install

SUB_DIRS     = clients

CURL         = $(INST_DIR)/bin/curl
NGHTTP       = $(INST_DIR)/bin/nghttp
H2LOAD       = $(INST_DIR)/bin/h2load

PHP_CGI      = $(shell bash -c 'type -p php-cgi')

all: install

clean:
	@rm -rf $(GEN) $(INST_DIR)/.testdocs-setup $(INST_DIR)/.test-setup
	@make -C clients clean

distclean:
	@rm -rf $(GEN)
	$(foreach sd, $(SUB_DIRS), make -C $(sd) distclean; )

distdir:
	@mkdir -p $(distdir)
	@tar cf - Makefile bin conf htdocs clients/Makefile *.txt *.sh | (cd $(distdir) && tar xf - )
	@rm -f $(distdir)/conf/ssl/mod-h2.greebytes.de*
	@rm -f $(distdir)/conf/sites/mod-h2.greebytes.de.conf

start: $(INST_DIR)/.test-setup
	@$(INST_DIR)/bin/apachectl -k start

start-debug: $(INST_DIR)/.test-setup
	@$(INST_DIR)/bin/apachectl -k start -X

restart: $(INST_DIR)/.test-setup
	@echo -n shutting down httpd...
	@$(INST_DIR)/bin/apachectl -k stop
	@while true; do sleep 1; pkill -1 -U $(USER) httpd; test "$$?" != "0" && break; done   
	@echo done.
	@$(INST_DIR)/bin/apachectl -k restart

stop:
	@$(INST_DIR)/bin/apachectl -k stop


install:
	@make -C clients install

################################################################################
# Test the local httpd
#
test: \
		$(INST_DIR)/.test-setup \
		$(INST_DIR)/.curl-installed
	@rm -rf $(GEN)/tmp
	@mkdir -p $(GEN)/tmp
	@$(INST_DIR)/bin/apachectl restart
	@bash test_curl_altsvc.sh http://$(HTTP_AUTH) https://$(HTTPS_AUTH)
	@bash test_alt_host.sh https://$(HTTPS_AUTH)
	@bash test_nghttp_get.sh  https://$(HTTPS_AUTH)
	@bash test_nghttp_post.sh https://$(HTTPS_AUTH)
	@bash test_curl_get.sh    https://$(HTTPS_AUTH)
	@bash test_curl_post.sh   https://$(HTTPS_AUTH)
	@bash test_nghttp_get.sh  https://$(HTTPS_AUTH)/proxy
	@bash test_nghttp_post.sh https://$(HTTPS_AUTH)/proxy
	@bash test_curl_get.sh    https://$(HTTPS_AUTH)/proxy
	@bash test_curl_post.sh   https://$(HTTPS_AUTH)/proxy
	@bash test_nghttp_get.sh  https://$(HTTPS_AUTH)/rewrite
	@bash test_nghttp_post.sh https://$(HTTPS_AUTH)/rewrite
	@bash test_curl_get.sh    https://$(HTTPS_AUTH)/rewrite
	@bash test_curl_post.sh   https://$(HTTPS_AUTH)/rewrite
	@bash test_nghttp_get.sh  http://$(HTTP_AUTH)
	@bash test_nghttp_post.sh http://$(HTTP_AUTH)
	@bash test_curl_get.sh    http://$(HTTP_AUTH)
	@bash test_curl_post.sh   http://$(HTTP_AUTH)
	@bash test_nghttp_get.sh  http://$(HTTP_AUTH) direct
	@bash test_nghttp_post.sh http://$(HTTP_AUTH) direct
	@bash test_nghttp_get.sh  http://$(HTTP_AUTH)/proxy
	@bash test_nghttp_post.sh http://$(HTTP_AUTH)/proxy
	@bash test_curl_get.sh    http://$(HTTP_AUTH)/proxy
	@bash test_curl_post.sh   http://$(HTTP_AUTH)/proxy
	@bash test_nghttp_get.sh  http://$(HTTP_AUTH)/rewrite
	@bash test_nghttp_post.sh http://$(HTTP_AUTH)/rewrite
	@bash test_curl_get.sh    http://$(HTTP_AUTH)/rewrite
	@bash test_curl_post.sh   http://$(HTTP_AUTH)/rewrite
	@bash test_nghttp_get.sh  https://$(HTTPS_AUTH2)
	@bash test_nghttp_post.sh https://$(HTTPS_AUTH2)
	@bash test_curl_get.sh    https://$(HTTPS_AUTH2)
	@bash test_curl_post.sh   https://$(HTTPS_AUTH2)

################################################################################
# Load Test
#

$(GEN)/load-urls-1.txt: \
		load-urls-1.txt
	@mkdir -p $(GEN)/tmp
	@sed -e "s,SUBST_AUTH_SUBST,https://$(HTTPS_AUTH)," < load-urls-1.txt >$(GEN)/load-urls-1.txt

$(GEN)/load-urls-2.txt: \
		load-urls-1.txt
	@mkdir -p $(GEN)/tmp
	@sed -e "s,SUBST_AUTH_SUBST,http://$(HTTP_AUTH)," < load-urls-1.txt >$(GEN)/load-urls-2.txt

MAX_STREAMS = 100

loadtest: \
		$(INST_DIR)/.test-setup \
		$(INST_DIR)/.curl-installed \
        $(GEN)/load-urls-1.txt
	$(H2LOAD) -c 100 -t 10 -n 100000 -m $(MAX_STREAMS) https://$(HTTPS_AUTH)/index.html
	$(H2LOAD) -i $(GEN)/load-urls-1.txt -n 200000 -t 1 -m $(MAX_STREAMS) -c 8
	$(H2LOAD) -i $(GEN)/load-urls-1.txt -n 200000 -t 2 -m $(MAX_STREAMS) -c 8
	$(H2LOAD) -i $(GEN)/load-urls-1.txt -n 200000 -t 3 -m $(MAX_STREAMS) -c 8
	$(H2LOAD) -i $(GEN)/load-urls-1.txt -n 200000 -t 4 -m $(MAX_STREAMS) -c 8
	$(H2LOAD) -i $(GEN)/load-urls-1.txt -n 200000 -t 5 -m $(MAX_STREAMS) -c 8
	$(H2LOAD) -i $(GEN)/load-urls-1.txt -n 200000 -t 6 -m $(MAX_STREAMS) -c 8
	$(H2LOAD) -i $(GEN)/load-urls-1.txt -n 200000 -t 7 -m $(MAX_STREAMS) -c 8
	$(H2LOAD) -i $(GEN)/load-urls-1.txt -n 200000 -t 8 -m $(MAX_STREAMS) -c 8

xtest: \
		$(INST_DIR)/.test-setup \
		$(INST_DIR)/.curl-installed \
        $(GEN)/load-urls-1.txt
	@bash test_nghttp_post.sh https://$(HTTPS_AUTH)

################################################################################
# Switch mpm modules
#
mpm_worker: $(INST_DIR)/.testdocs-setup
	@test -L $(INST_DIR)/conf/mods-enabled/mpm_worker.load || \
        (rm -f $(INST_DIR)/conf/mods-enabled/mpm_*; \
        ln -s ../mods-available/mpm_worker.load $(INST_DIR)/conf/mods-enabled/ && \
        echo "mpm_worker configured, please restart.")

mpm_event: $(INST_DIR)/.testdocs-setup
	@test -L $(INST_DIR)/conf/mods-enabled/mpm_event.load || \
	    (rm -f $(INST_DIR)/conf/mods-enabled/mpm_*; \
	    ln -s ../mods-available/mpm_event.load $(INST_DIR)/conf/mods-enabled/ && \
	    echo "mpm_event configured, please restart.")

mpm_prefork: $(INST_DIR)/.testdocs-setup
	@test -L $(INST_DIR)/conf/mods-enabled/mpm_prefork.load || \
	    (rm -f $(INST_DIR)/conf/mods-enabled/mpm_*; \
	    ln -s ../mods-available/mpm_prefork.load $(INST_DIR)/conf/mods-enabled/ && \
	    echo "mpm_prefork configured, please restart.")


################################################################################
# Setup the local httpd for our tests
#
SETUP_FILES = $(wildcard conf/*.conf) \
    $(wildcard conf/mods-available/*.*) \
    $(wildcard conf/sites/*.conf) \
    $(wildcard bin/*)

$(INST_DIR)/.testdocs-setup: \
	$(wildcard conf/*) \
	$(wildcard htdocs/*/*)
	@echo -n setup htdocs locally...
	@cp -r htdocs/* $(INST_DIR)/htdocs
	@chmod +x $$(find $(INST_DIR)/htdocs/test.example.org/ -name "*.py" )
	@echo done.
	@touch $(INST_DIR)/.testdocs-setup

$(INST_DIR)/.test-setup: \
        Makefile \
		$(INST_DIR)/.httpd-installed \
		conf/*.conf \
        $(wildcard bin/*) \
        $(wildcard conf/mods-available/*.*) \
		$(wildcard conf/sites/*.conf) \
        $(INST_DIR)/conf/mods-enabled/h2.load \
		$(INST_DIR)/conf/ssl/test.example.org.key \
		$(INST_DIR)/conf/ssl/test.example.org.pem \
		$(INST_DIR)/conf/ssl/test-ser.example.org.key \
		$(INST_DIR)/conf/ssl/test-ser.example.org.pem \
		$(INST_DIR)/conf/ssl/noh2.example.org.key \
		$(INST_DIR)/conf/ssl/noh2.example.org.pem \
		$(INST_DIR)/.testdocs-setup
	@echo -n setup httpd locally...
	@mkdir -p $(INST_DIR)/conf/sites
	@mkdir -p $(INST_DIR)/conf/mods-enabled
	@mkdir -p $(INST_DIR)/conf/ssl
	@for file in $(SETUP_FILES); do \
		sed -e "s,SUBST_SERVER_ROOT_SUBST,$(BLD_PREFIX),g" \
			-e "s,SUBST_SERVER_NAME_SUBST,$(shell hostname -f),g" \
			-e "s,SUBST_PORT_HTTP_SUBST,$(HTTP_PORT),g" \
			-e "s,SUBST_PORT_HTTPS_SUBST,$(HTTPS_PORT),g" \
            -e "s,SUBST_PHP_CGI_SUBST,$(PHP_CGI),g" \
			< $$file > $(INST_DIR)/$$file; \
	done
	@for i in bin/*; do chmod +x $(INST_DIR)/$$i; done
	@cp conf/ssl/*.* $(INST_DIR)/conf/ssl
	@test -L $(INST_DIR)/conf/mods-enabled/mpm*load || ln -s ../mods-available/mpm_worker.load $(INST_DIR)/conf/mods-enabled/
	@echo done.
	@touch $(INST_DIR)/.test-setup

$(INST_DIR)/conf/ssl/test.example.org.key:
	@mkdir -p $(INST_DIR)/conf/ssl
	openssl genrsa -out $(INST_DIR)/conf/ssl/test.example.org.key 4096

$(INST_DIR)/conf/ssl/test.example.org.req: \
		$(INST_DIR)/conf/ssl/test.example.org.key \
        conf/ssl/test.example.org.x509.input
	openssl req -new -key $(INST_DIR)/conf/ssl/test.example.org.key \
		-out $(INST_DIR)/conf/ssl/test.example.org.req < conf/ssl/test.example.org.x509.input

$(INST_DIR)/conf/ssl/test.example.org.x509.input: \
        conf/ssl/test.example.org.x509.input
	cp conf/ssl/test.example.org.x509.input $(INST_DIR)/conf/ssl

$(INST_DIR)/conf/ssl/test.example.org.pem: \
		$(INST_DIR)/conf/ssl/test.example.org.key \
		$(INST_DIR)/conf/ssl/test.example.org.req \
		conf/ssl/extensions.conf \
		conf/ssl/test.example.org.x509.input
	openssl x509 -req -sha256 -days 1095 \
		-signkey $(INST_DIR)/conf/ssl/test.example.org.key \
		-in $(INST_DIR)/conf/ssl/test.example.org.req \
		-out $(INST_DIR)/conf/ssl/test.example.org.pem \
		-extfile conf/ssl/extensions.conf -extensions ssl_client < conf/ssl/noh2.example.org.x509.input

$(INST_DIR)/conf/ssl/test-ser.example.org.key:
	@mkdir -p $(INST_DIR)/conf/ssl
	openssl genrsa -out $(INST_DIR)/conf/ssl/test-ser.example.org.key 4096

$(INST_DIR)/conf/ssl/test-ser.example.org.x509.input: \
        conf/ssl/test-ser.example.org.x509.input
	cp conf/ssl/test-ser.example.org.x509.input $(INST_DIR)/conf/ssl

$(INST_DIR)/conf/ssl/test-ser.example.org.req: \
		$(INST_DIR)/conf/ssl/test-ser.example.org.key
	openssl req -new -key $(INST_DIR)/conf/ssl/test-ser.example.org.key \
		-out $(INST_DIR)/conf/ssl/test-ser.example.org.req < conf/ssl/test-ser.example.org.x509.input

$(INST_DIR)/conf/ssl/test-ser.example.org.pem: \
		$(INST_DIR)/conf/ssl/test-ser.example.org.key \
		$(INST_DIR)/conf/ssl/test-ser.example.org.req \
		conf/ssl/extensions.conf \
		conf/ssl/test-ser.example.org.x509.input
	openssl x509 -req -sha256 -days 1095 \
		-signkey $(INST_DIR)/conf/ssl/test-ser.example.org.key \
		-in $(INST_DIR)/conf/ssl/test-ser.example.org.req \
		-out $(INST_DIR)/conf/ssl/test-ser.example.org.pem \
		-extfile conf/ssl/extensions.conf -extensions ssl_client < conf/ssl/noh2.example.org.x509.input

$(INST_DIR)/conf/ssl/noh2.example.org.key:
	@mkdir -p $(INST_DIR)/conf/ssl
	openssl genrsa -out $(INST_DIR)/conf/ssl/noh2.example.org.key 4096

$(INST_DIR)/conf/ssl/noh2.example.org.x509.input: \
        conf/ssl/noh2.example.org.x509.input
	cp conf/ssl/noh2.example.org.x509.input $(INST_DIR)/conf/ssl

$(INST_DIR)/conf/ssl/noh2.example.org.req: \
		$(INST_DIR)/conf/ssl/noh2.example.org.key
	openssl req -new -key $(INST_DIR)/conf/ssl/noh2.example.org.key \
		-out $(INST_DIR)/conf/ssl/noh2.example.org.req < conf/ssl/noh2.example.org.x509.input

$(INST_DIR)/conf/ssl/noh2.example.org.pem: \
		$(INST_DIR)/conf/ssl/noh2.example.org.key \
		$(INST_DIR)/conf/ssl/noh2.example.org.req \
		conf/ssl/extensions.conf \
		conf/ssl/noh2.example.org.x509.input
	openssl x509 -req -sha256 -days 1095 \
		-signkey $(INST_DIR)/conf/ssl/noh2.example.org.key \
		-in $(INST_DIR)/conf/ssl/noh2.example.org.req \
		-out $(INST_DIR)/conf/ssl/noh2.example.org.pem \
		-extfile conf/ssl/extensions.conf -extensions ssl_client < conf/ssl/noh2.example.org.x509.input

$(INST_DIR)/conf/mods-available/h2.load:
	@mkdir -p $(INST_DIR)/conf/mods-available
	cp ../../setup/h2.load $(INST_DIR)/conf/mods-available

$(INST_DIR)/conf/mods-available/h2.conf:
	@mkdir -p $(INST_DIR)/conf/mods-available
	cp ../../setup/h2.conf $(INST_DIR)/conf/mods-available

$(INST_DIR)/conf/mods-enabled/h2.load: \
        $(INST_DIR)/conf/mods-available/h2.load \
        $(INST_DIR)/conf/mods-available/h2.conf
	@mkdir -p $(INST_DIR)/conf/mods-enabled
	@cd $(INST_DIR)/conf/mods-enabled && ln -sf ../mods-available/h2.* .


################################################################################
# Install the local httpd for our tests
#
$(INST_DIR)/.httpd-installed:
	@echo "you need to have httpd installed locally."
	@exit 1

################################################################################
# Install the local curl
#
$(INST_DIR)/.curl-installed:
	make -C clients
