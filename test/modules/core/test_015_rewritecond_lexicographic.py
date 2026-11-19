import pytest

from pyhttpd.conf import HttpdConf


class TestRewriteCondLexicographic:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": """
            RewriteEngine on
            RewriteCond %{QUERY_STRING} >B
            RewriteRule ^/gt$ - [F]
            RewriteCond %{QUERY_STRING} <B
            RewriteRule ^/lt$ - [F]
            RewriteCond %{QUERY_STRING} >=B
            RewriteRule ^/ge$ - [F]
            RewriteCond %{QUERY_STRING} <=B
            RewriteRule ^/le$ - [F]
            RewriteCond %{QUERY_STRING} >b [NC]
            RewriteRule ^/gtnc$ - [F]
            """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    # The RewriteRule answers 403 if the RewriteCond is true. Otherwise the
    # request is for a file that does not exist, so it is a 404.
    @pytest.mark.parametrize(["path", "query", "expected"], [
        ("gt", "AAA", False),
        ("gt", "B", False),
        ("gt", "BB", True),
        ("gt", "C", True),
        ("lt", "A", True),
        ("lt", "AAA", True),
        ("lt", "B", False),
        ("lt", "BB", False),
        ("ge", "AAA", False),
        ("ge", "B", True),
        ("ge", "BB", True),
        ("le", "AAA", True),
        ("le", "B", True),
        ("le", "BB", False),
        ("gtnc", "AAA", False),
        ("gtnc", "BB", True),
    ])
    def test_core_015_01(self, env, path, query, expected):
        r = env.curl_get(env.mkurl("http", "test1", f"/{path}?{query}"))
        assert r.response, "no response"
        assert r.response["status"] == (403 if expected else 404)
