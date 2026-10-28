dnl Licensed to the Apache Software Foundation (ASF) under one or more
dnl contributor license agreements.  See the NOTICE file distributed with
dnl this work for additional information regarding copyright ownership.
dnl The ASF licenses this file to You under the Apache License, Version 2.0
dnl (the "License"); you may not use this file except in compliance with
dnl the License.  You may obtain a copy of the License at
dnl
dnl       http://www.apache.org/licenses/LICENSE-2.0
dnl
dnl Unless required by applicable law or agreed to in writing, software
dnl distributed under the License is distributed on an "AS IS" BASIS,
dnl WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
dnl See the License for the specific language governing permissions and
dnl limitations under the License.

dnl #  start of module specific part
APACHE_MODPATH_INIT(fcgid)

case $host in
    *mingw*)
        fcgid_platform_objs="fcgid_pm_win.lo fcgid_proc_win.lo fcgid_proctbl_win.lo"
        ;;
    *)
        fcgid_platform_objs="fcgid_pm_unix.lo fcgid_proc_unix.lo fcgid_proctbl_unix.lo fcgid_mutex_unix.lo"
        ;;
esac

dnl #  list of module object files
fcigd_objs="dnl
mod_fcgid.lo dnl
fcgid_bridge.lo dnl
fcgid_conf.lo dnl
fcgid_pm_main.lo dnl
fcgid_protocol.lo dnl
fcgid_spawn_ctl.lo dnl
fcgid_bucket.lo dnl
fcgid_filter.lo dnl
$fcgid_platform_objs dnl
"

APACHE_MODULE(fcgid, [FastCGI support (mod_fcgid)], $fcigd_objs, , no, [
    AC_CHECK_HEADERS(sys/file.h)
    AC_CHECK_HEADERS(sys/mman.h)
    AC_CHECK_HEADERS(sys/mutex.h)
    AC_CHECK_HEADERS(sys/shm.h)
    if test "x$enable_fcgid" = "xshared"; then
       # The only symbol which needs to be exported is the module
       # structure, so ask libtool to hide everything else:
       APR_ADDTO(MOD_FCGID_LDADD, [-export-symbols-regex fcgid_module])
    fi
])

dnl #  end of module specific part
APACHE_MODPATH_FINISH
