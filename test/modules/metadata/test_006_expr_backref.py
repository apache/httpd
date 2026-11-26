import pytest

from pyhttpd.conf import HttpdConf

# An expression that evaluates to true without evaluating a capturing regex
# (short-circuited by '||', regex without captures, '!~' non-match) must not
# expand $N / %N backreferences from the offsets of a previous match: they
# are empty in mod_setenvif (SetEnvIfExpr), and those of the last matching
# RewriteCond in mod_rewrite (RewriteCond expr).
EXPR = "req('X-Match') == 'skip' || req('X-Match') =~ m#^(.+)$#"
NOCAP = "req('X-Match') =~ m#^.+$#"
NEG = "req('X-Match') !~ m#^(zzz)$#"
# a value much longer than X-Short, so that %1 taken with X-Long's offsets
# but X-Short's string would not equal X-Long
LONG = "long-" + "x" * 200


class TestExprBackref:

    @pytest.fixture(autouse=True, scope='class')
    @classmethod
    def _class_scope(cls, env):
        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": f"""
            RewriteEngine On
            RewriteCond expr "{EXPR}"
            RewriteRule ^/rewrite$ /redir/-%1- [R=302,L]

            # a previous capturing RewriteCond, then an expr one that is
            # true without captures: %1 must still be the previous capture
            RewriteCond %{{HTTP:X-Prev}} ^(.+)$
            RewriteCond expr "{EXPR}"
            RewriteRule ^/rewrite-prev$ /redir/-%1- [R=302,L]

            RewriteCond expr "{NOCAP}"
            RewriteRule ^/rewrite-nocap$ /redir/-%1- [R=302,L]

            RewriteCond expr "{NEG}"
            RewriteRule ^/rewrite-neg$ /redir/-%1- [R=302,L]

            # an expr with captures, then a regex RewriteCond on a different
            # (longer) string, then an expr true without captures: %1 must be
            # the regex condition's capture of its own string
            RewriteCond expr "req('X-Short') =~ m#^(.+)$#"
            RewriteCond %{{HTTP:X-Long}} ^(.+)$
            RewriteCond expr "%{{REQUEST_METHOD}} == 'GET'"
            RewriteRule ^/rewrite-mixed$ /redir/-%1- [R=302,L]

            RewriteCond expr "req('X-Short') =~ m#^(.+)$#"
            RewriteCond %{{HTTP:X-Long}} ^(.+)$
            RewriteCond expr "{EXPR}"
            RewriteRule ^/rewrite-mixed-short-circuit$ /redir/-%1- [R=302,L]

            # a regex SetEnvIf first, leaving captures in the match vector
            SetEnvIf X-Prev "^(.+)$" PREV=[$1]
            SetEnvIfExpr "{EXPR}" "CAPTURE=[$1]"
            SetEnvIfExpr "{NOCAP}" "NOCAP=[$1]"
            SetEnvIfExpr "{NEG}" "NEG=[$1]"
            # $1 used inside the condition itself
            SetEnvIfExpr "({EXPR}) && $1 == 'foo'" "INCOND=[$1]"
            Header always set X-Prev-Env "%{{PREV}}e"
            Header always set X-Capture "%{{CAPTURE}}e"
            Header always set X-Nocap "%{{NOCAP}}e"
            Header always set X-Neg "%{{NEG}}e"
            Header always set X-Incond "%{{INCOND}}e"

            # Header edit* with patterns matching the empty string
            Header always set X-Edit "abc"
            Header always edit* X-Edit "x*" "-"
            Header always set X-Edit-Anchor "abc"
            Header always edit* X-Edit-Anchor "^" ">"
            Header always set X-Edit-Opt "abc"
            Header always edit* X-Edit-Opt "(b)?" "[$1]"
            """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def get(self, env, path, headers):
        options = []
        for k, v in headers.items():
            options += ['-H', f'{k}: {v}']
        r = env.curl_get(env.mkurl("http", "test1", path), options=options)
        assert r.response, f"no response: {r.stderr}"
        return r

    @pytest.mark.parametrize("path, value, expected", [
        ("/rewrite", "skip", "--"),
        ("/rewrite", "foo", "-foo-"),
        ("/rewrite-prev", "skip", "-previous-"),
        ("/rewrite-prev", "foo", "-foo-"),
        ("/rewrite-nocap", "foo", "--"),
        ("/rewrite-neg", "foo", "--"),
    ], ids=["short-circuit", "match", "prev-short-circuit", "prev-match",
            "no-captures", "negated"])
    def test_metadata_006_01_rewrite(self, env, path, value, expected):
        r = self.get(env, path, {"X-Match": value, "X-Prev": "previous"})
        assert r.response["status"] == 302
        location = r.response["header"]["location"]
        assert location.endswith(f"/redir/{expected}"), location

    @pytest.mark.parametrize("path", [
        "/rewrite-mixed", "/rewrite-mixed-short-circuit",
    ])
    def test_metadata_006_04_rewrite_mixed(self, env, path):
        r = self.get(env, path, {"X-Short": "ab", "X-Long": LONG,
                                 "X-Match": "skip"})
        assert r.response["status"] == 302
        location = r.response["header"]["location"]
        assert location.endswith(f"/redir/-{LONG}-"), location

    @pytest.mark.parametrize("value, expected", [
        # (for '!~', mod_setenvif deliberately sets the literal value when
        # the regex did not match, see the comment in match_headers())
        ("skip", {"x-capture": "[]", "x-nocap": "[]", "x-neg": "[$1]",
                  "x-prev-env": "[previous]", "x-incond": "(null)"}),
        ("foo", {"x-capture": "[foo]", "x-nocap": "[]", "x-neg": "[$1]",
                 "x-prev-env": "[previous]", "x-incond": "[foo]"}),
    ], ids=["short-circuit", "match"])
    def test_metadata_006_02_setenvif(self, env, value, expected):
        r = self.get(env, "/", {"X-Match": value, "X-Prev": "previous"})
        for name, val in expected.items():
            assert r.response["header"][name] == val, name

    def test_metadata_006_03_header_edit_empty(self, env):
        r = self.get(env, "/", {})
        h = r.response["header"]
        # (unlike Perl's /g and mod_substitute, mod_headers does not try a
        # final empty match once the whole value has been consumed)
        assert h["x-edit"] == "-a-b-c"
        assert h["x-edit-anchor"] == ">abc"
        assert h["x-edit-opt"] == "[]a[b][]c"
