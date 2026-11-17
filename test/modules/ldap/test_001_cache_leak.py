import http.client
import os
import sys

import pytest

from pyhttpd.conf import HttpdConf

# What mod_ldap logs when the per-URL cache is full and the purge
# frees nothing; expected here on every request, since LDAPCacheEntries 1
# makes the purge (which only removes entries older than LDAPCacheTTL)
# never effective within the life of this test.
CACHE_FULL_LOGNO = ["AH01323"]

REQUESTS_PER_PATH = 2000

# A real leak here is a few KB per request (three small caches); this
# is comfortably above allocator noise for an otherwise-idle process
# and comfortably below the multi-MB growth a real leak produces over
# REQUESTS_PER_PATH iterations.
LIMIT_KB = 4096


def _children_rss_kb(ppid):
    """Sum VmRSS (kB) across all direct children of the httpd main
    process. The main process itself does not serve requests."""
    total = 0
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat") as fd:
                fields = fd.read().split()
            if int(fields[3]) != ppid:
                continue
            with open(f"/proc/{entry}/status") as fd:
                for line in fd:
                    if line.startswith("VmRSS:"):
                        total += int(line.split()[1])
                        break
        except (FileNotFoundError, ProcessLookupError, IndexError, ValueError):
            continue
    return total


def _built_with_asan(env):
    """Whether httpd is AddressSanitizer instrumented: its quarantine and
    shadow memory grow RSS by far more than any leak this test looks for."""
    with open(os.path.join(env.bin_dir, "httpd"), "rb") as fd:
        return b"__asan_init" in fd.read()


# Class scoped, to outlast the error log check made after each test.
@pytest.fixture(scope='class')
def _expect_cache_full(env):
    env.httpd_error_log.add_ignored_lognos(CACHE_FULL_LOGNO)
    yield
    env.httpd_error_log.remove_ignored_lognos(CACHE_FULL_LOGNO)


# With LDAPCacheEntries 1, alternating requests for two AuthLDAPURLs
# always find the shared URL cache full: whichever URL was cached by
# the previous request is still there (LDAPCacheTTL has not elapsed),
# so util_ald_cache_insert() returns NULL for the other one every
# time. util_ald_create_caches() must free the three per-URL caches
# it just created in that case, not leak them. BZ 70319.
# The growth is read from /proc, hence Linux only.
@pytest.mark.skipif(not sys.platform.startswith("linux"),
                    reason="reads process memory from /proc")
@pytest.mark.usefixtures("_expect_cache_full")
class TestLdapCacheLeak:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        if _built_with_asan(env):
            pytest.skip("RSS growth is meaningless under AddressSanitizer")
        env.require(env.has_shared_module("ldap"), "mod_ldap not built",
                    dep="mod_ldap")
        env.require(env.has_shared_module("authnz_ldap"), "mod_authnz_ldap not built",
                    dep="mod_authnz_ldap")
        # Pin every request to a single worker process, so the RSS growth
        # measured below reflects that one process's heap and is not
        # confused by the MPM scaling up its number of children under load.
        mpm_pin = "StartServers 1\nServerLimit 1\nMaxRequestWorkers 16\n"
        if env.mpm_module in ("mpm_worker", "mpm_event"):
            mpm_pin += "ThreadsPerChild 16\nMinSpareThreads 1\nMaxSpareThreads 16\n"
        conf = HttpdConf(env, extras={
            'base': f"""
            LDAPSharedCacheSize 0
            LDAPCacheEntries 1
            {mpm_pin}
            """,
            f"test1.{env.http_tld}": """
            <Location /ldapcacheleak/a>
                AuthType Basic
                AuthName a
                AuthBasicProvider ldap
                AuthLDAPURL "ldap://127.0.0.1:1/dc=a?uid"
                Require valid-user
            </Location>
            <Location /ldapcacheleak/b>
                AuthType Basic
                AuthName b
                AuthBasicProvider ldap
                AuthLDAPURL "ldap://127.0.0.1:1/dc=b?uid"
                Require valid-user
            </Location>
            """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def test_ldap_001_01_cache_insert_failure_leak(self, env):
        host = f"test1.{env.http_tld}"
        conn = http.client.HTTPConnection(env.http_addr, env.http_port, timeout=10)
        try:
            # Warm-up: settle the connection and the allocator before
            # measuring, and confirm the cache-miss path is really hit.
            for path in ("a", "b", "a", "b"):
                conn.request("GET", f"/ldapcacheleak/{path}", headers={
                    "Host": host, "Authorization": "Basic dXNlcjpwdw==",
                })
                r = conn.getresponse()
                r.read()
                assert r.status == 500, r.status  # no real LDAP server

            main_pid = env.read_pid_file()
            before = _children_rss_kb(main_pid)

            for _ in range(REQUESTS_PER_PATH):
                for path in ("a", "b"):
                    conn.request("GET", f"/ldapcacheleak/{path}", headers={
                        "Host": host, "Authorization": "Basic dXNlcjpwdw==",
                    })
                    r = conn.getresponse()
                    r.read()
                    assert r.status == 500, r.status

            after = _children_rss_kb(main_pid)
        finally:
            conn.close()

        growth = after - before
        assert growth < LIMIT_KB, \
            f"{2 * REQUESTS_PER_PATH} requests grew httpd by {growth}kB"
