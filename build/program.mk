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

PROGRAM_OBJECTS = $(PROGRAM_SOURCES:.c=.lo)
TOP=/home/ben/work/openssl-0.9.7

# XXX: I don't know how to work out the correct path for the real executable
TO_FINGERPRINT = $(PROGRAM_NAME:httpd=.libs/lt-httpd)
FINGERPRINT = $(TO_FINGERPRINT).sha1

$(PROGRAM_NAME): $(PROGRAM_DEPENDENCIES) $(PROGRAM_OBJECTS)
	$(PROGRAM_PRELINK)
	$(LINK) $(PROGRAM_LDFLAGS) $(PROGRAM_OBJECTS) $(PROGRAM_LDADD)
# blearg - force libtool to do its stupid magic
	-./$(PROGRAM_NAME) --help
	TOP=$(TOP) $(TOP)/fips/openssl_fips_fingerprint $(TOP)/libcrypto.a $(TO_FINGERPRINT) > $(FINGERPRINT)
