import os

import pytest

from pyhttpd.conf import HttpdConf


class TestSetEnvIf:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        doc_dir = os.path.join(env.server_dir, "htdocs", "test1")
        os.makedirs(doc_dir, exist_ok=True)
        with open(os.path.join(doc_dir, "setenvif.shtml"), "w") as f:
            for name in ["SEI_FIRST", "SEI_EXPR", "SEI_LITERAL", "SEI_REGEX"]:
                f.write(f'{name}=[<!--#echo var="{name}" -->]\n')
        # Two rules on the same header with a SetEnvIfExpr between them:
        # the second X-A rule must still be matched against X-A, not
        # against the string the expression's regex was applied to.
        conf = HttpdConf(env, extras={
            'base': f"""
            SetEnvIf X-A foo SEI_FIRST=1
            SetEnvIfExpr "req('X-B') =~ /(.+)/" SEI_EXPR=$1
            SetEnvIf X-A bar SEI_LITERAL=1
            SetEnvIf X-A ^bar$ SEI_REGEX=1
            <Directory "{doc_dir}">
                Options +Includes
                AddType text/html .shtml
                AddOutputFilter INCLUDES .shtml
            </Directory>
            """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def test_metadata_005_01_expr_between_header_rules(self, env):
        url = env.mkurl("http", "test1", "/setenvif.shtml")
        r = env.curl_get(url, options=[
            "-H", "X-A: foo-" + "x" * 64,
            "-H", "X-B: bar",
        ])
        assert r.response, "no response: server may have crashed"
        assert r.response["status"] == 200
        body = r.response["body"].decode("utf-8")
        assert "SEI_FIRST=[1]" in body
        assert "SEI_EXPR=[bar]" in body
        # X-A does not contain "bar", only X-B does
        assert "SEI_LITERAL=[(none)]" in body
        assert "SEI_REGEX=[(none)]" in body
