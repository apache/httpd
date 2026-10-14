import os
import random
import string

import pytest

from pyhttpd.conf import HttpdConf

# DeflateAlterETag controls how mod_deflate modifies the ETag header when
# compression is applied.  Three modes exist:
#   AddSuffix  -- append a compression tag, so compressed and plain ETags differ
#   NoChange   -- leave the ETag alone, so both representations share one
#   Remove     -- strip the ETag from compressed responses entirely


class TestDeflateAlterEtag:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        # The ScriptSock path warning is harmless; it fires when the
        # working-tree path is long (e.g. in CI worktrees).
        env.httpd_error_log.add_ignored_lognos(["AH01254"])
        # A document large enough that mod_deflate actually compresses it.
        doc_dir = os.path.join(env.server_dir, "htdocs", "test1")
        body = ''.join(random.choices(string.ascii_lowercase, k=8000))
        for name in ("etag1.html", "etag2.html", "etag3.html"):
            with open(os.path.join(doc_dir, name), "w") as f:
                f.write(f"<html><body>{body}</body></html>")

    def configure(self, env, alter_etag):
        doc_root = os.path.join(env.server_dir,
                                "htdocs", "test1").replace('\\', '/')
        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": f"""
            <Directory "{doc_root}">
                AddOutputFilterByType DEFLATE text/html
            </Directory>
            DeflateAlterETag {alter_etag}
            """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def get_etag(self, env, path, accept_gzip=False):
        url = env.mkurl("http", "test1", path)
        options = ["-H", "Cache-Control: no-cache"]
        if accept_gzip:
            options.extend(["-H", "Accept-Encoding: gzip"])
        r = env.curl_get(url, options=options)
        assert r.response, f"no response for {path}"
        assert r.response["status"] == 200, \
            f"status {r.response['status']} for {path}"
        return r.response["header"].get("etag")

    # AddSuffix: the compressed ETag gets a suffix, so it differs from the
    # plain one.
    def test_filters_010_01_addsuffix_etags_differ(self, env):
        self.configure(env, "AddSuffix")
        etag_plain = self.get_etag(env, "/etag1.html", accept_gzip=False)
        etag_gzip = self.get_etag(env, "/etag1.html", accept_gzip=True)
        assert etag_plain is not None, "plain response should have an ETag"
        assert etag_gzip is not None, "gzip response should have an ETag"
        assert etag_plain != etag_gzip, \
            (f"AddSuffix: ETags should differ between plain and compressed, "
             f"got {etag_plain} and {etag_gzip}")

    # NoChange: the ETag is left as-is, so both representations match.
    def test_filters_010_02_nochange_etags_match(self, env):
        self.configure(env, "NoChange")
        etag_plain = self.get_etag(env, "/etag2.html", accept_gzip=False)
        etag_gzip = self.get_etag(env, "/etag2.html", accept_gzip=True)
        assert etag_plain is not None, "plain response should have an ETag"
        assert etag_gzip is not None, "gzip response should have an ETag"
        assert etag_plain == etag_gzip, \
            (f"NoChange: ETags should be identical, "
             f"got {etag_plain} and {etag_gzip}")

    # Remove: the compressed response has no ETag at all.
    def test_filters_010_03_remove_etag_stripped(self, env):
        self.configure(env, "Remove")
        etag_plain = self.get_etag(env, "/etag3.html", accept_gzip=False)
        etag_gzip = self.get_etag(env, "/etag3.html", accept_gzip=True)
        assert etag_plain is not None, "plain response should have an ETag"
        assert etag_gzip is None, \
            f"Remove: gzip response should have no ETag, got {etag_gzip}"
