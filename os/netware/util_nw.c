/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "httpd.h"
#include "http_log.h"

#include <netware.h>
#include <nks/netware.h>

int nlmUnloadSignaled(int wait);
event_handle_t eh;
Warn_t ref;
Report_t dum;

AP_DECLARE(apr_status_t) ap_os_create_privileged_process(
    const request_rec *r,
    apr_proc_t *newproc, const char *progname,
    const char * const *args,
    const char * const *env,
    apr_procattr_t *attr, apr_pool_t *p)
{
    return apr_proc_create(newproc, progname, args, env, attr, p);
}

int  _NonAppCheckUnload( void )
{
        return nlmUnloadSignaled(1);
}

// down server event callback
void ap_down_server_cb(void *, void *)
{
        nlmUnloadSignaled(0);
    return;
}

// Required place holder event callback
void ap_dummy_cb(void *, void *)
{
    return;
}

// destroy callback resources
void ap_cb_destroy(void *)
{
  // cleanup down event notification
  UnRegisterEventNotification(eh);
  NX_UNWRAP_INTERFACE(ref);
  NX_UNWRAP_INTERFACE(dum);
}

int _NonAppStart
(
    void        *NLMHandle,
    void        *errorScreen,
    const char  *cmdLine,
    const char  *loadDirPath,
    size_t      uninitializedDataLength,
    void        *NLMFileHandle,
    int         (*readRoutineP)( int conn, void *fileHandle, size_t offset,
                    size_t nbytes, size_t *bytesRead, void *buffer ),
    size_t      customDataOffset,
    size_t      customDataSize,
    int         messageCount,
    const char  **messages
)
{
#pragma unused(cmdLine)
#pragma unused(loadDirPath)
#pragma unused(uninitializedDataLength)
#pragma unused(NLMFileHandle)
#pragma unused(readRoutineP)
#pragma unused(customDataOffset)
#pragma unused(customDataSize)
#pragma unused(messageCount)
#pragma unused(messages)

    // register for down server event
    rtag_t rt = AllocateResourceTag(NLMHandle, "Apache2 Down Server Callback",
                                    EventSignature);

    NX_WRAP_INTERFACE((void *)ap_down_server_cb, 2, (void **)&ref);
    NX_WRAP_INTERFACE((void *)ap_dummy_cb, 2, (void **)&dum);
    eh = RegisterForEventNotification(rt, EVENT_DOWN_SERVER,
                                      EVENT_PRIORITY_APPLICATION,
                                      ref, dum, NULL);

    // clean-up
    NXVmRegisterExitHandler(ap_cb_destroy, NULL);

}

