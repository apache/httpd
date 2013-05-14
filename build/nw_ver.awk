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
  # fetch Apache version numbers from input file and write them to STDOUT

  while ((getline < ARGV[1]) > 0) {
    if (match ($0, /^#define AP_SERVER_COPYRIGHT \\/)) {
      if (((getline < ARGV[1]) > 0) && (split($0, c, "\"") == 3)) {
        copyright_str = c[2];
      }
    }
    else if (match ($0, /^#define AP_SERVER_MAJORVERSION_NUMBER /)) {
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

  if (ver_devbuild) {
    ver_dev = "-dev"
    if (ARGV[2]) {
      while ((getline < ARGV[2]) > 0) {
        if (match ($0, /^\/repos\/asf\/!svn\/ver\/[0-9]+\/httpd\/httpd\/(trunk|branches\/[0-9]\.[0-9]\.x)$/)) {
          gsub(/^\/repos\/asf\/!svn\/ver\/|\/httpd\/httpd\/(trunk|branches\/[0-9]\.[0-9]\.x)$/, "", $0)
          ver_dev = svn_rev = "-r" $0
        }
      }
    }
  }

  ver_nlm = ver_major "," ver_minor "," ver_patch;
  ver_str = ver_major "." ver_minor "." ver_patch ver_dev;

  print "VERSION = " ver_nlm "";
  print "VERSION_STR = " ver_str "";
  print "VERSION_MAJMIN = " ver_major ver_minor "";
  print "COPYRIGHT_STR = " copyright_str "";
  print "SVN_REVISION = " svn_rev "";

}


