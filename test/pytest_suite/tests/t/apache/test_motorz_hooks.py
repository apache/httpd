r"""mpm_motorz: suspend_connection / resume_connection hooks.

A connection that is parked between requests is not tied to a worker thread: the
next request may be run by another one.  mpm_common.h says the suspend hook runs
on the thread that was processing the connection and the resume hook on the
thread that will continue it, so a module that keeps per-thread state can follow
the connection.

A small module, built with apxs, logs both hooks and each request with the
thread it ran on.  For every connection the log must read
request, (suspend, resume, request)*, with each suspend on the thread of the
request before it and each resume on the thread of the request after it.
"""

import re
import socket
import subprocess
import sys
import threading
import time

import pytest

from apache_pytest.private_server import PrivateServer

MODULE_SOURCE = r'''
#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "mpm_common.h"
#include "apr_portable.h"
#include <string.h>

static unsigned long tid(void)
{
    return (unsigned long)(apr_uintptr_t)apr_os_thread_current();
}

static void hook_suspend(conn_rec *c, request_rec *r)
{
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf,
                 "HOOKTEST suspend c=%pp tid=%lu", c, tid());
}

static void hook_resume(conn_rec *c, request_rec *r)
{
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf,
                 "HOOKTEST resume c=%pp tid=%lu", c, tid());
}

static int hooks_handler(request_rec *r)
{
    if (strcmp(r->handler, "conn-hooks")) {
        return DECLINED;
    }
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf,
                 "HOOKTEST request c=%pp tid=%lu", r->connection, tid());
    ap_set_content_type(r, "text/plain");
    ap_rputs("ok\n", r);
    return OK;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_suspend_connection(hook_suspend, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_resume_connection(hook_resume, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(hooks_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(conn_hooks) = {
    STANDARD20_MODULE_STUFF, NULL, NULL, NULL, NULL, NULL, register_hooks
};
'''

EVENT = re.compile(r"HOOKTEST (suspend|resume|request) c=(\S+) tid=(\d+)")


def build_module(config, tmp_path):
    src = tmp_path / "mod_conn_hooks.c"
    src.write_text(MODULE_SOURCE)
    proc = subprocess.run(["perl", str(config.apxs), "-c", str(src)],
                          cwd=tmp_path, capture_output=True, text=True)
    so = tmp_path / ".libs" / "mod_conn_hooks.so"
    assert proc.returncode == 0 and so.exists(), proc.stdout + proc.stderr
    return so


def keepalive_requests(port, count, gap):
    with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
        for _ in range(count):
            s.sendall(b"GET /hooks HTTP/1.1\r\nHost: localhost\r\n\r\n")
            data = b""
            while not data.endswith(b"ok\n"):
                chunk = s.recv(4096)
                assert chunk, "connection closed"
                data += chunk
            time.sleep(gap)


@pytest.mark.skipif(sys.platform == "win32", reason="forking MPM")
def test_hooks_run_on_the_threads_that_hand_over_and_take_over(config, tmp_path):
    if config.info.mpm != "motorz":
        pytest.skip("motorz only")
    if config.apxs is None:
        pytest.skip("needs --apxs to build a module")

    so = build_module(config, tmp_path)
    extra = [f"LoadModule conn_hooks_module {so}",
             "<Location /hooks>", "    SetHandler conn-hooks", "</Location>",
             "KeepAliveTimeout 30"]
    (tmp_path / "srv").mkdir()
    with PrivateServer(config, tmp_path / "srv", extra=extra,
                       big_length=1024) as server:
        threads = [threading.Thread(target=keepalive_requests,
                                    args=(server.port, 25, 0.02))
                   for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        time.sleep(0.5)
        log = server.error_log()

    per_conn = {}
    for kind, conn, tid in EVENT.findall(log):
        per_conn.setdefault(conn, []).append((kind, tid))
    assert len(per_conn) >= 4, per_conn.keys()

    resumes = 0
    moved = 0
    for conn, events in per_conn.items():
        kinds = [k for k, _ in events]
        # request, then repeated suspend, resume, request; it may end parked.
        expected = ["request"]
        while len(expected) < len(kinds):
            expected += ["suspend", "resume", "request"]
        assert kinds == expected[:len(kinds)], f"{conn}: {kinds}"
        for (k1, t1), (k2, t2) in zip(events, events[1:]):
            if k1 == "request" and k2 == "suspend":
                assert t1 == t2, f"{conn}: suspended on another thread"
            if k1 == "resume" and k2 == "request":
                assert t1 == t2, f"{conn}: resumed on another thread"
            if k1 == "suspend" and k2 == "resume":
                resumes += 1
                moved += t1 != t2
    assert resumes >= 4 * 20, f"only {resumes} resumes were logged"
    assert moved > 0, "no connection ever moved to another thread; weak test"
