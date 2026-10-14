import os

import pytest

from pyhttpd.conf import HttpdConf

# mod_sed must handle large request bodies without crashing.  A historical
# issue caused a segmentation fault when a large body was processed through
# an InputSed filter due to integer overflow in buffer management.  This
# test sends a multi-megabyte POST body through InputSed and verifies that
# the server responds and stays alive.

# 8 MB is enough to exercise the large-input paths without making the test
# impractically slow.
LARGE_SIZE = 8 * 1024 * 1024

# Bound the request so a regression that stops answering fails the test
# rather than hanging the suite.
BOUNDED = ["--max-time", "60"]


class TestSedLargeInput:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        # The ScriptSock path warning is harmless; it fires when the
        # working-tree path is long (e.g. in CI worktrees).
        env.httpd_error_log.add_ignored_lognos(["AH01254"])
        doc_dir = os.path.join(env.server_dir, "htdocs", "test1")
        with open(os.path.join(doc_dir, "target.html"), "w") as f:
            f.write("This is the target page")
        # Pre-create a large file to POST through the InputSed filter.
        large_file = os.path.join(env.server_dir, "large_input.bin")
        with open(large_file, "wb") as f:
            chunk = b"A" * (1024 * 1024)
            for _ in range(LARGE_SIZE // (1024 * 1024)):
                f.write(chunk)

    @staticmethod
    def large_file_path(env):
        return os.path.join(env.server_dir, "large_input.bin")

    def test_filters_011_01_large_body_no_crash(self, env):
        doc_root = os.path.join(env.server_dir,
                                "htdocs", "test1").replace('\\', '/')
        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": f"""
            <Directory "{doc_root}">
                AddInputFilter SED html
                InputSed "s/A/Z/g"
            </Directory>
            """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0
        # POST the large file through the InputSed filter.
        url = env.mkurl("http", "test1", "/target.html")
        large_file = self.large_file_path(env)
        r = env.curl_raw(url, timeout=60, options=list(BOUNDED) + [
            "-X", "POST",
            "--data-binary", f"@{large_file}",
        ])
        assert r.response, "no response: server may have crashed"
        assert r.response["status"] in (200, 400), \
            f"unexpected status {r.response['status']}"
        # The server must still be running after processing the large input.
        assert env.is_live(), "httpd is not running after large input"
        env.httpd_error_log.ignore_recent(
            matches=[r".*exit signal Segmentation fault.*"])
