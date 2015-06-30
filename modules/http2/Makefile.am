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
SUBDIRS         = @BUILD_SUBDIRS@
DIST_SUBDIRS    = mod_h2 sandbox setup

ACLOCAL_AMFLAGS = -I m4


dist_doc_DATA   = README


.PHONY: test loadtest start stop restart

start:
	make -C sandbox start

restart:
	make -C sandbox restart

stop:
	make -C sandbox stop

test:
	make -C sandbox test

loadtest:
	make -C sandbox loadtest

mpm_worker:
	make -C sandbox mpm_worker

mpm_event:
	make -C sandbox mpm_event

mpm_prefork:
	make -C sandbox mpm_prefork
