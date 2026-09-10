import os
import re
import pytest

from pyhttpd.conf import HttpdConf


class TestMimeMagic:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        # A small magic file: one entry giving both a type and an
        # encoding, and one with a file(1)-style descriptive note in
        # place of the encoding.  The token-based text detection is left
        # to handle everything else.
        magic_file = os.path.join(env.gen_dir, "magic")
        with open(magic_file, "w") as f:
            f.write("0\tstring\tTESTMAGIC\tapplication/x-test-magic\tx-test-encoding\n")
            f.write("0\tstring\tTESTNOTE\tapplication/x-test-note (some note)\n")

        # Files without an extension, so mod_mime sets no type and
        # mod_mime_magic has to derive one from the content.
        doc_dir = os.path.join(env.server_dir, "htdocs", "test1", "magic")
        os.makedirs(doc_dir, exist_ok=True)
        # (a rule is only tested on files of at least 64 bytes)
        with open(os.path.join(doc_dir, "softmagic"), "wb") as f:
            f.write(b"TESTMAGIC" + b" and some more content" * 4 + b"\n")
        with open(os.path.join(doc_dir, "softnote"), "wb") as f:
            f.write(b"TESTNOTE" + b" and some more content" * 4 + b"\n")
        with open(os.path.join(doc_dir, "html-plain"), "wb") as f:
            f.write(b"<html>\n<body>hello</body>\n")
        # HTML token followed by an ESC byte.
        with open(os.path.join(doc_dir, "html-escape"), "wb") as f:
            f.write(b"<html>\n\x1b[1mhello\x1b[0m\n")

        conf = HttpdConf(env, extras={
            'base': f"""
            MimeMagicFile "{magic_file}"
            """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    # type and encoding from a magic file entry
    def test_metadata_001_01_softmagic(self, env):
        url = env.mkurl("http", "test1", "/magic/softmagic")
        r = env.curl_get(url)
        assert r.response, "no response: server may have crashed"
        assert r.response["status"] == 200
        assert r.response["header"]["content-type"] == "application/x-test-magic"
        assert r.response["header"]["content-encoding"] == "x-test-encoding"

    # type from the HTML token, no encoding
    def test_metadata_001_02_html(self, env):
        url = env.mkurl("http", "test1", "/magic/html-plain")
        r = env.curl_get(url)
        assert r.response, "no response: server may have crashed"
        assert r.response["status"] == 200
        assert r.response["header"]["content-type"] == "text/html"
        assert "content-encoding" not in r.response["header"]

    # type from the HTML token, escape sequences in the content
    def test_metadata_001_03_html_escapes(self, env):
        url = env.mkurl("http", "test1", "/magic/html-escape")
        r = env.curl_get(url)
        assert r.response, "no response: server may have crashed"
        assert r.response["status"] == 200
        assert r.response["header"]["content-type"] == "text/html"
        assert "content-encoding" not in r.response["header"]

    # type from a magic file entry followed by a descriptive note: the
    # type must end at the whitespace, and the note is not an encoding
    def test_metadata_001_04_softmagic_note(self, env):
        url = env.mkurl("http", "test1", "/magic/softnote")
        r = env.curl_get(url)
        assert r.response, "no response: server may have crashed"
        assert r.response["status"] == 200
        assert r.response["header"]["content-type"] == "application/x-test-note"
        assert "content-encoding" not in r.response["header"]
        assert env.httpd_error_log.scan_recent(
            re.compile(r'.*AH10623: .*ignoring invalid content encoding.*'))
        env.httpd_error_log.ignore_recent(lognos=["AH10623"])
