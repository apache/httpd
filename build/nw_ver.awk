# Copyright 2002-2004 Apache Software Foundation
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

BEGIN {

  # fetch Apache version numbers from input file and writes them to STDOUT

  while ((getline < ARGV[1]) > 0) {
    if (match ($0, /^#define AP_SERVER_MAJORVERSION "[^"]+"/)) {
      ver_major = substr($3, 2, length($3) - 2);
    }
    else if (match ($0, /^#define AP_SERVER_MINORVERSION "[^"]+"/)) {
      ver_minor = substr($3, 2, length($3) - 2);
    }
    else if (match ($0, /^#define AP_SERVER_PATCHLEVEL/)) {
      ver_str_patch = substr($3, 2, length($3) - 2);
      if (match (ver_str_patch, /[0-9][0-9]*/)) {
         ver_patch = substr(ver_str_patch, RSTART, RLENGTH); 
      }
    }
  }
  ver = ver_major "," ver_minor "," ver_patch;
  ver_str = ver_major "." ver_minor "." ver_str_patch;

  print "VERSION = " ver "";
  print "VERSION_STR = " ver_str "";

}
