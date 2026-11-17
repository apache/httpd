r"""A connection that a handler suspends, and that the module then ends by
destroying the connection's pool instead of handing it back to the MPM.

The MPM must still count the connection as closed, or a child that stops
gracefully waits for it forever.  mpm_event does that from a cleanup of the
connection's pool, and the test runs under event too, as a check on the test
itself.  MotorZ must also run the resume_connection hooks for it (event does
that only when the transaction pool goes, which on trunk is not c->pool).

A small module, built with apxs, suspends the request, answers it later from a
thread of its own and then destroys the connection's pool.
"""

import os
import socket
import subprocess
import sys
import time

import pytest

from apache_pytest.private_server import PrivateServer, child_pids

MODULE_SOURCE = r'''
#include "httpd.h"
#include "http_config.h"
#include "http_connection.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "mpm_common.h"
#include "apr_strings.h"
#include "apr_thread_proc.h"
#include <string.h>

static apr_pool_t *thread_pool;

static void hook_resume(conn_rec *c, request_rec *r)
{
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf,
                 "SUSPENDTEST resume c=%pp", c);
}

static void * APR_THREAD_FUNC finish(apr_thread_t *thd, void *data)
{
    conn_rec *c = data;
    static const char reply[] =
        "HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nok\n";
    apr_size_t len = sizeof(reply) - 1;

    apr_sleep(apr_time_from_msec(300));
    apr_socket_send(ap_get_conn_socket(c), reply, &len);
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf,
                 "SUSPENDTEST ending c=%pp", c);
    /* The socket can belong to a parent of c->pool. */
    apr_socket_close(ap_get_conn_socket(c));
    apr_pool_destroy(c->pool);
    return NULL;
}

static int suspend_handler(request_rec *r)
{
    apr_thread_t *thd;
    apr_threadattr_t *attr;

    if (strcmp(r->handler, "suspend-test")) {
        return DECLINED;
    }
    apr_threadattr_create(&attr, thread_pool);
    apr_threadattr_detach_set(attr, 1);
    if (apr_thread_create(&thd, attr, finish, r->connection, thread_pool)) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    return SUSPENDED;
}

static void child_init(apr_pool_t *p, server_rec *s)
{
    thread_pool = p;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_resume_connection(hook_resume, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(suspend_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(child_init, NULL, NULL, APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(suspend_test) = {
    STANDARD20_MODULE_STUFF, NULL, NULL, NULL, NULL, NULL, register_hooks
};
'''


def build_module(config, tmp_path):
    src = tmp_path / "mod_suspend_test.c"
    src.write_text(MODULE_SOURCE)
    proc = subprocess.run(["perl", str(config.apxs), "-c", str(src)],
                          cwd=tmp_path, capture_output=True, text=True)
    so = tmp_path / ".libs" / "mod_suspend_test.so"
    assert proc.returncode == 0 and so.exists(), proc.stdout + proc.stderr
    return so


def get_suspended(port):
    with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
        s.sendall(b"GET /suspend HTTP/1.0\r\n\r\n")
        data = b""
        while chunk := s.recv(4096):
            data += chunk
    return data


def wait_gone(pids, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        alive = set()
        for pid in pids:
            try:
                os.kill(pid, 0)
                alive.add(pid)
            except ProcessLookupError:
                pass
            except PermissionError:
                alive.add(pid)
        if not alive:
            return alive
        time.sleep(0.1)
    return alive



@pytest.mark.skipif(sys.platform == "win32", reason="forking MPM")
def test_ended_suspended_connection_lets_the_child_stop(config, tmp_path):
    if config.info.mpm not in ("motorz", "event"):
        pytest.skip("needs an MPM that suspends connections")
    if config.apxs is None:
        pytest.skip("needs --apxs to build a module")

    so = build_module(config, tmp_path)
    extra = [f"LoadModule suspend_test_module {so}",
             "<Location /suspend>", "    SetHandler suspend-test", "</Location>",
             "GracefulShutdownTimeout 0"]
    (tmp_path / "srv").mkdir()
    with PrivateServer(config, tmp_path / "srv", extra=extra,
                       big_length=1024) as server:
        old = child_pids(server.proc.pid)
        assert old
        for _ in range(3):
            assert get_suspended(server.port).endswith(b"\r\n\r\nok\n")
        time.sleep(0.5)
        log = server.error_log()
        assert log.count("SUSPENDTEST ending") == 3, log
        if config.info.mpm == "motorz":
            assert log.count("SUSPENDTEST resume") == 3, log

        server.graceful()
        assert not wait_gone(old, 15), \
            "the old child kept waiting for the ended suspended connections"
        assert server.small_ok(10)
