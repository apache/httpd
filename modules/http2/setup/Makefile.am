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

EXTRA_DIST = \
    h2.load \
    h2.conf \
    install-config.sh


ACLOCAL_AMFLAGS = -I m4

SYSCONF_DIR = @SYSCONF_DIR@

# overwrite install target
install:
	@bash install-config.sh $(SYSCONF_DIR) $(DESTDIR)
