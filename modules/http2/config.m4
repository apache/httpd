dnl Licensed to the Apache Software Foundation (ASF) under one or more
dnl contributor license agreements.  See the NOTICE file distributed with
dnl this work for additional information regarding copyright ownership.
dnl The ASF licenses this file to You under the Apache License, Version 2.0
dnl (the "License"); you may not use this file except in compliance with
dnl the License.  You may obtain a copy of the License at
dnl
dnl      http://www.apache.org/licenses/LICENSE-2.0
dnl
dnl Unless required by applicable law or agreed to in writing, software
dnl distributed under the License is distributed on an "AS IS" BASIS,
dnl WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
dnl See the License for the specific language governing permissions and
dnl limitations under the License.

dnl #  start of module specific part
APACHE_MODPATH_INIT(http2)

dnl #  list of module object files
h2_objs="dnl
mod_h2.lo dnl
h2_alt_svc.lo dnl
h2_config.lo dnl
h2_conn.lo dnl
h2_conn_io.lo dnl
h2_ctx.lo dnl
h2_from_h1.lo dnl
h2_h2.lo dnl
h2_io.lo dnl
h2_io_set.lo dnl
h2_mplx.lo dnl
h2_request.lo dnl
h2_response.lo dnl
h2_session.lo dnl
h2_stream.lo dnl
h2_stream_set.lo dnl
h2_switch.lo dnl
h2_task.lo dnl
h2_task_input.lo dnl
h2_task_output.lo dnl
h2_task_queue.lo dnl
h2_to_h1.lo dnl
h2_util.lo dnl
h2_worker.lo dnl
h2_workers.lo dnl
"

dnl #  hook module into the Autoconf mechanism (--enable-h2 option)
APACHE_MODULE(h2, [HTTP/2 support (mod_h2)], $h2_objs, , most, [
    APACHE_CHECK_NGHTTP2
    if test "$ac_cv_nghttp2" = "yes" ; then
        if test "x$enable_ssl" = "xshared"; then
           # The only symbol which needs to be exported is the module
           # structure, so ask libtool to hide everything else:
           APR_ADDTO(MOD_H2_LDADD, [-export-symbols-regex h2_module])
        fi
    else
        enable_h2=no
    fi
])

dnl #  end of module specific part
APACHE_MODPATH_FINISH

