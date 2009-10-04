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
#
# Based on apr's make_export.awk, which is
# based on Ryan Bloom's make_export.pl

BEGIN {
    printf(" ("EXPPREFIX")\n")
}

# List of functions that we don't support, yet??
#/ap_some_name/{next}
/ap_mpm_pod_/{next}

/^[ \t]*AP([RU]|_CORE)?_DECLARE[^(]*[(][^)]*[)]([^ ]* )*[^(]+[(]/ {
    sub("[ \t]*AP([RU]|_CORE)?_DECLARE[^(]*[(][^)]*[)][ \t]*", "")
    sub("[(].*", "")
    sub("([^ ]* (^([ \t]*[(])))+", "")
    add_symbol($0)
    next
}

/^[ \t]*AP_DECLARE_HOOK[^(]*[(][^)]*/ {
    split($0, args, ",")
    symbol = args[2]
    sub("^[ \t]+", "", symbol)
    sub("[ \t]+$", "", symbol)
    add_symbol("ap_hook_" symbol)
    add_symbol("ap_hook_get_" symbol)
    add_symbol("ap_run_" symbol)
    next
}

/^[ \t]*AP[RU]?_DECLARE_EXTERNAL_HOOK[^(]*[(][^)]*/ {
    split($0, args, ",")
    symbol = args[4]
    sub("^[ \t]+", "", symbol)
    sub("[ \t]+$", "", symbol)
    add_symbol("ap_hook_" symbol)
    add_symbol("ap_hook_get_" symbol)
    add_symbol("ap_run_" symbol)
    next
}

/^[ \t]*APR_POOL_DECLARE_ACCESSOR[^(]*[(][^)]*[)]/ {
    sub("[ \t]*APR_POOL_DECLARE_ACCESSOR[^(]*[(]", "", $0)
    sub("[)].*$", "", $0)
    add_symbol("apr_" $0 "_pool_get")
    next
}

/^[ \t]*APR_DECLARE_INHERIT_SET[^(]*[(][^)]*[)]/ {
    sub("[ \t]*APR_DECLARE_INHERIT_SET[^(]*[(]", "", $0)
    sub("[)].*$", "", $0)
    add_symbol("apr_" $0 "_inherit_set")
    next
}

/^[ \t]*APR_DECLARE_INHERIT_UNSET[^(]*[(][^)]*[)]/ {
    sub("[ \t]*APR_DECLARE_INHERIT_UNSET[^(]*[(]", "", $0)
    sub("[)].*$", "", $0)
    add_symbol("apr_" $0 "_inherit_unset")
    next
}

/^[ \t]*(extern[ \t]+)?AP[RU]?_DECLARE_DATA .*;$/ {
    gsub(/[*;]/, "", $NF)
    gsub(/\[.*\]/, "", $NF)
    add_symbol($NF)
}

#END {
#    printf("\n\n#found: %d symbols.\n", found)
#}

function add_symbol(sym_name) {
    found++
    sub (" ", "", sym_name)
    printf(" %s,\n", sym_name)
}


