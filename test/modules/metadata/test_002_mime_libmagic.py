import os
import pytest

from pyhttpd.conf import HttpdConf
from .samples import write_samples


def get_type(env, path):
    """The Content-Type header of GET path on test1, or None."""
    r = env.curl_get(env.mkurl("http", "test1", path))
    assert r.response, "no response: server may have crashed"
    assert r.response["status"] == 200
    assert "content-encoding" not in r.response["header"]
    return r.response["header"].get("content-type")


class TestMimeLibmagic:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        if not env.has_libmagic_module:
            pytest.skip("mod_mime_libmagic is not built")
        write_samples(os.path.join(env.server_dir, "htdocs", "test1", "libmagic"))
        conf = HttpdConf(env, extras={
            'base': "MimeLibmagic On",
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    @pytest.mark.parametrize(["name", "ctype"], [
        ("html", "text/html"),
        ("html-doctype", "text/html"),
        ("text", "text/plain"),
        ("text-utf8", "text/plain"),
        ("text-latin1", "text/plain"),
        ("csrc", "text/x-c"),
        ("json", "application/json"),
        ("xml", "text/xml"),
        ("rfc822", "message/rfc822"),
        ("shell", "text/x-shellscript"),
        ("png", "image/png"),
        ("gif", "image/gif"),
        ("pdf", "application/pdf"),
        # no decompression support, the compressed file itself is typed
        ("gzip", "application/gzip"),
        # libmagic appends ", no program header" to the type
        ("elf", "application/x-executable"),
        # application/octet-stream from libmagic leaves the type unset
        ("binary", None),
        ("empty", "text/plain"),
    ])
    def test_metadata_002_01_types(self, env, name, ctype):
        assert get_type(env, f"/libmagic/{name}") == ctype

    # mod_mime's extension mapping wins over the content
    def test_metadata_002_02_extension(self, env):
        assert get_type(env, "/libmagic/png.txt") == "text/plain"


class TestMimeLibmagicCharset:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        if not env.has_libmagic_module:
            pytest.skip("mod_mime_libmagic is not built")
        write_samples(os.path.join(env.server_dir, "htdocs", "test1", "libmagic"))
        conf = HttpdConf(env, extras={
            'base': """
            MimeLibmagic On
            MimeLibmagicCharset On
            """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    @pytest.mark.parametrize(["name", "ctype"], [
        ("html", "text/html; charset=us-ascii"),
        ("text", "text/plain; charset=us-ascii"),
        ("text-utf8", "text/plain; charset=utf-8"),
        ("text-latin1", "text/plain; charset=iso-8859-1"),
        # only text types get a charset
        ("json", "application/json"),
        ("png", "image/png"),
        ("binary", None),
    ])
    def test_metadata_002_10_charset(self, env, name, ctype):
        assert get_type(env, f"/libmagic/{name}") == ctype
