import os
import pytest

from pyhttpd.conf import HttpdConf


class TestMergeLanguage:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        # Create a file with two language extensions so mod_mime
        # populates r->content_languages with nelts == nalloc == 2.
        doc_dir = os.path.join(env.server_dir, "htdocs", "test1")
        with open(os.path.join(doc_dir, "doc.en.fr.html"), "w") as f:
            f.write("Hello World\n")

        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": """
            AddLanguage en .en
            AddLanguage fr .fr
            Header set Content-Language "de, es"
            """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    # Requesting a file with two language extensions while mod_headers
    # adds two non-matching Content-Language tokens should not crash.
    # The merge loop in merge_response_headers must refresh its pointer
    # to r->content_languages->elts after apr_array_push reallocates.
    def test_core_006_01(self, env):
        url = env.mkurl("http", "test1", "/doc.en.fr.html")
        r = env.curl_get(url)
        assert r.response, "no response: server may have crashed"
        assert r.response["status"] == 200
        cl = r.response["header"]["content-language"]
        for lang in ["en", "fr", "de", "es"]:
            assert lang in cl, f"expected '{lang}' in Content-Language: {cl}"
