"""mod_info must show the right "In file:" label for directives expanded
from a mod_macro <Macro>.

use_macro() built the "macro 'X' (...) used on line N of ..." label in the
temporary configuration pool, and ap_build_config_sub() keeps only a pointer
to it as the directive's filename. The temporary pool is destroyed once the
configuration is read, so /server-info?config printed empty or garbled
labels for some of those directives. PR 70378.
"""

import re

import pytest

from pyhttpd.conf import HttpdConf


class TestMacroInfoFilename:

    USES = 300

    @pytest.fixture(autouse=True, scope='class')
    @classmethod
    def _class_scope(cls, env):
        conf = HttpdConf(env)
        conf.add([
            "<Location /server-info>",
            "  SetHandler server-info",
            "  Require local",
            "</Location>",
            "<Macro TestMacroInfo>",
            "  Header set X-Macro-Info v",
            "</Macro>",
        ])
        conf.add(["Use TestMacroInfo"] * cls.USES)
        conf.install()
        assert env.apache_restart() == 0

    def test_core_018_01_macro_labels_intact(self, env):
        url = f"http://127.0.0.1:{env.http_port}/server-info?config"
        r = env.curl_get(url)
        assert r.response["status"] == 200, f"{r}"
        body = r.response["body"].decode("latin-1")
        labels = re.findall(r"In file: (.*?)</strong>", body)
        # mod_macro lower-cases the name; mod_info escapes the quotes
        good = re.compile(r"^macro 'testmacroinfo' \(defined on line \d+ of "
                          r"&quot;.+&quot;\) used on line \d+ of &quot;.+&quot;$")
        used = [lab for lab in labels if good.match(lab)]
        assert len(used) == self.USES, \
            f"{self.USES - len(used)} macro labels missing or garbled: {labels[:3]}"
