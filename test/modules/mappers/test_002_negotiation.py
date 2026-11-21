import os
import textwrap

import pytest

from pyhttpd.conf import HttpdConf


class TestNegotiationTypeMap:

    @pytest.fixture(autouse=True, scope='class')
    @classmethod
    def _class_scope(cls, env):
        doc_dir = os.path.join(env.server_docs_dir, "typemap")
        os.makedirs(doc_dir, exist_ok=True)
        with open(os.path.join(doc_dir, "page.html"), "w") as f:
            f.write("negotiated variant\n")
        # A Description: whose first continuation line fills the 8 KiB
        # header buffer, followed by more continuation lines which
        # begin with '#'.
        first = "Description: x\n"
        filler = " " + "A" * (8190 - len(first)) + "#\n"
        with open(os.path.join(doc_dir, "long.var"), "w", newline="\n") as f:
            f.write("URI: page.html\n")
            f.write("Content-Type: text/html\n")
            f.write(first + filler + " #\n" * 512 + "\n")
        domain = f"typemap.{env.http_tld}"
        conf = HttpdConf(env, extras={
            'base': textwrap.dedent(f"""
            <Directory "{doc_dir}">
                AddHandler type-map .var
            </Directory>
            """),
        })
        conf.add_vhost(domains=[domain], port=env.http_port,
                       doc_root="htdocs/typemap")
        conf.install()
        assert env.apache_restart() == 0

    def test_negotiation_002_01_typemap_long_continuation(self, env):
        """Continuation lines in a type map after the header line buffer
        is full must not be written past the end of the buffer.  Before
        the fix each one wrote a byte further past the stack buffer in
        read_type_map(), crashing the child."""
        r = env.curl_get(env.mkurl("http", "typemap", "/long.var"))
        assert r.exit_code == 0, f"curl failed: {r}"
        assert r.response["status"] == 200
        assert r.response["body"].decode() == "negotiated variant\n"
