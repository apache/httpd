import os

import pytest

from pyhttpd.backport import not_backported, skip_not_backported
from pyhttpd.conf import HttpdConf

# Patterns that can match the empty string must not loop forever (or until
# SubstituteMaxLineLength is hit) in do_pattmatch(). Expected results follow
# the same convention as mod_headers' edit* and pcre2_substitute(): after an
# empty match, a non-empty match is tried at the same position, otherwise one
# character is copied and matching continues after it. Matching resumes
# within the whole line, so ^, $, \b and lookarounds keep their meaning.
CASES = {
    # name: (pattern, replacement, flags, input, expected)
    'star_dash_flatten': ('x*', '-', 'f', 'abc', '-a-b-c-'),
    'star_dash_quick': ('x*', '-', 'q', 'abc', '-a-b-c-'),
    'star_empty_flatten': ('b*', '', 'f', 'abc', 'ac'),
    'star_empty_quick': ('b*', '', 'q', 'abc', 'ac'),
    'optional_group_flatten': ('(b)?', '[$1]', 'f', 'abc', '[]a[b][]c[]'),
    'optional_group_quick': ('(b)?', '[$1]', 'q', 'abc', '[]a[b][]c[]'),
    'anchor_start_flatten': ('^', '>', 'f', 'abc', '>abc'),
    'anchor_start_quick': ('^', '>', 'q', 'abc', '>abc'),
    'anchor_start_lines': ('^', '>', 'f', 'ab\ncd', '>ab\n>cd'),
    'anchor_end_flatten': ('$', '<', 'f', 'abc', 'abc<'),
    # (httpd compiles regexes with DOLLAR_ENDONLY: $ only matches at the
    # very end of the line, i.e. after the newline)
    'anchor_end_lines': ('$', '<', 'q', 'ab\ncd', 'ab\n<cd<'),
    'anchor_nonempty': ('^a', 'X', 'f', 'aaa', 'Xaa'),
    'word_boundary': ('\\b', '|', 'f', 'ab cd', '|ab| |cd|'),
    'lookahead': ('(?=c)', '-', 'q', 'abc', 'ab-c'),
    'lookbehind': ('(?<=a)', '-', 'f', 'aba', 'a-ba-'),
    # (same as Perl: an empty match is allowed right after a non-empty one)
    'mixed_empty_nonempty': ('b*', '-', 'f', 'abbc', '-a--c-'),
}

# Without the change, most of these loop until "Line too long" is logged,
# and star_empty_* loop forever.
WHAT = "mod_substitute empty matches"
SKIP = skip_not_backported("gh-1096", WHAT, backported_in="2.4.72")
MARKS = {
    'anchor_nonempty': not_backported("gh-1096", WHAT, backported_in="2.4.72"),
    'lookbehind': (),
}
PARAMS = [pytest.param(name, id=name, marks=MARKS.get(name, SKIP))
          for name in CASES]


class TestSubstituteEmptyMatch:

    @pytest.fixture(autouse=True, scope='class')
    @classmethod
    def _class_scope(cls, env):
        doc_dir = os.path.join(env.server_dir, "htdocs", "test1")
        for name, (_, _, _, text, _) in CASES.items():
            with open(os.path.join(doc_dir, f"{name}.html"), "w",
                      newline="") as f:
                f.write(text)

    def configure(self, env, pattern, repl, flags):
        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": f"""
            <Location "/">
                AddOutputFilterByType SUBSTITUTE text/html
                Substitute "s/{pattern}/{repl}/{flags}"
            </Location>
            """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    @pytest.mark.parametrize("name", PARAMS)
    def test_filters_010_01(self, env, name):
        pattern, repl, flags, _, expected = CASES[name]
        self.configure(env, pattern, repl, flags)
        r = env.curl_get(env.mkurl("http", "test1", f"/{name}.html"),
                         options=['--max-time', '10'])
        assert r.response, f"{name}: no response (hang?): {r.stderr}"
        assert r.response["status"] == 200, f"{name}: status {r.response['status']}"
        body = r.response["body"].decode()
        assert body == expected, f"{name}: body {body!r}, expected {expected!r}"
