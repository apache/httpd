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

BEGIN {

  # fetch Apache version numbers from input file and writes them to STDOUT

  while ((getline < ARGV[1]) > 0) {
    if (match ($0, /^#define AP_SERVER_MAJORVERSION_NUMBER /)) {
      ver_major = $3;
    }
    else if (match ($0, /^#define AP_SERVER_MINORVERSION_NUMBER /)) {
      ver_minor = $3;
    }
    else if (match ($0, /^#define AP_SERVER_PATCHLEVEL_NUMBER/)) {
      ver_patch = $3;
    }
    else if (match ($0, /^#define AP_SERVER_DEVBUILD_BOOLEAN/)) {
      ver_devbuild = $3;
    }
  }
  ver_nlm = ver_major "," ver_minor "," ver_patch;
  ver_str = ver_major "." ver_minor "." ver_patch (ver_devbuild ? "-dev" : "");

  print "VERSION = " ver_nlm "";
  print "VERSION_STR = " ver_str "";

}


