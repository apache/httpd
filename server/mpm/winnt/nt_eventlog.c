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

#define CORE_PRIVATE

#include "httpd.h"
#include "http_log.h"
#include "mpm_winnt.h"
#include "apr_strings.h"
#include "apr_lib.h"
#include "apr_portable.h"
#include "ap_regkey.h"

static const char *display_name  = NULL;
static HANDLE stderr_thread = NULL;
static HANDLE stderr_ready;

static DWORD WINAPI service_stderr_thread(LPVOID hPipe)
{
    HANDLE hPipeRead = (HANDLE) hPipe;
    HANDLE hEventSource;
    char errbuf[256];
    char *errmsg = errbuf;
    const char *errarg[9];
    DWORD errres;
    ap_regkey_t *regkey;
    apr_status_t rv;
    apr_pool_t *p;

    apr_pool_create_ex(&p, NULL, NULL, NULL);

    errarg[0] = "The Apache service named";
    errarg[1] = display_name;
    errarg[2] = "reported the following error:\r\n>>>";
    errarg[3] = errbuf;
    errarg[4] = NULL;
    errarg[5] = NULL;
    errarg[6] = NULL;
    errarg[7] = NULL;
    errarg[8] = NULL;

    /* What are we going to do in here, bail on the user?  not. */
    if ((rv = ap_regkey_open(&regkey, AP_REGKEY_LOCAL_MACHINE,
                             "SYSTEM\\CurrentControlSet\\Services\\"
                             "EventLog\\Application\\Apache Service",
                             APR_READ | APR_WRITE | APR_CREATE, p))
            == APR_SUCCESS)
    {
        DWORD dwData = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE |
                       EVENTLOG_INFORMATION_TYPE;

        /* The stock message file */
        ap_regkey_value_set(regkey, "EventMessageFile",
                            "%SystemRoot%\\System32\\netmsg.dll",
                            AP_REGKEY_EXPAND, p);

        ap_regkey_value_raw_set(regkey, "TypesSupported", &dwData,
                                sizeof(dwData), REG_DWORD, p);
        ap_regkey_close(regkey);
    }

    hEventSource = RegisterEventSourceW(NULL, L"Apache Service");

    SetEvent(stderr_ready);

    while (ReadFile(hPipeRead, errmsg, 1, &errres, NULL) && (errres == 1))
    {
        if ((errmsg > errbuf) || !apr_isspace(*errmsg))
        {
            ++errmsg;
            if ((*(errmsg - 1) == '\n')
                    || (errmsg >= errbuf + sizeof(errbuf) - 1))
            {
                while ((errmsg > errbuf) && apr_isspace(*(errmsg - 1))) {
                    --errmsg;
                }
                *errmsg = '\0';

                /* Generic message: '%1 %2 %3 %4 %5 %6 %7 %8 %9'
                 * The event code in netmsg.dll is 3299
                 */
                ReportEvent(hEventSource, EVENTLOG_ERROR_TYPE, 0,
                            3299, NULL, 9, 0, errarg, NULL);
                errmsg = errbuf;
            }
        }
    }

    if ((errres = GetLastError()) != ERROR_BROKEN_PIPE) {
        apr_snprintf(errbuf, sizeof(errbuf),
                     "Win32 error %lu reading stderr pipe stream\r\n",
                     GetLastError());

        ReportEvent(hEventSource, EVENTLOG_ERROR_TYPE, 0,
                    3299, NULL, 9, 0, errarg, NULL);
    }

    CloseHandle(hPipeRead);
    DeregisterEventSource(hEventSource);
    CloseHandle(stderr_thread);
    stderr_thread = NULL;
    apr_pool_destroy(p);
    return 0;
}


void mpm_nt_eventlog_stderr_flush(void)
{
    HANDLE cleanup_thread = stderr_thread;

    if (cleanup_thread) {
        HANDLE hErr = GetStdHandle(STD_ERROR_HANDLE);
        fclose(stderr);
        CloseHandle(hErr);
        WaitForSingleObject(cleanup_thread, 30000);
        CloseHandle(cleanup_thread);
    }
}


void mpm_nt_eventlog_stderr_open(const char *argv0, apr_pool_t *p)
{
    SECURITY_ATTRIBUTES sa;
    HANDLE hPipeRead = NULL;
    HANDLE hPipeWrite = NULL;
    DWORD  threadid;
    apr_file_t *eventlog_file;
    apr_file_t *stderr_file;

    display_name = argv0;

    /* Create a pipe to send stderr messages to the system error log.
     *
     * _dup2() duplicates the write handle inheritable for us.
     */
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = FALSE;
    CreatePipe(&hPipeRead, &hPipeWrite, NULL, 0);
    ap_assert(hPipeRead && hPipeWrite);

    stderr_ready = CreateEvent(NULL, FALSE, FALSE, NULL);
    stderr_thread = CreateThread(NULL, 0, service_stderr_thread,
                                 (LPVOID) hPipeRead, 0, &threadid);
    ap_assert(stderr_ready && stderr_thread);

    WaitForSingleObject(stderr_ready, INFINITE);

    if ((apr_file_open_stderr(&stderr_file, p) 
             == APR_SUCCESS)
     && (apr_os_file_put(&eventlog_file, &hPipeWrite, APR_WRITE, p)
             == APR_SUCCESS))
        apr_file_dup2(stderr_file, eventlog_file, p);

    /* The code above _will_ corrupt the StdHandle...
     * and we must do so anyways.  We set this up only
     * after we initialized the posix stderr API.
     */
    ap_open_stderr_log(p);
}
