import os
import re

import pytest

from .env import CoreTestEnv


@pytest.mark.skipif(condition=not os.path.isfile(CoreTestEnv().apxs),
                    reason="apxs not available")
class TestApxsDuplicates:

    OTHER = "LoadModule other_module modules/mod_other.so"
    ACTIVE = "LoadModule foo_module modules/mod_foo.so"
    COMMENTED = "#LoadModule foo_module modules/mod_foo.so"
    # the entries of the module in the file, in order
    LAYOUTS = {
        "active-commented": ["active", "commented"],
        "commented-active": ["commented", "active"],
        "active-active": ["active", "active"],
        "commented-commented": ["commented", "commented"],
        "active-between-commented": ["commented", "other", "active", "other",
                                     "commented"],
    }

    def _lines(self, content):
        active = re.findall(r"^[ \t]*LoadModule\s+foo_module\s", content, re.M)
        disabled = re.findall(r"^[ \t]*#\s*LoadModule\s+foo_module\s", content,
                              re.M)
        return len(active), len(disabled)

    # apxs -A disables every active entry of the module, without adding,
    # removing or touching any other line, and gives the same result again
    @pytest.mark.parametrize("layout", list(LAYOUTS))
    def test_core_011_01(self, env, tmp_path, layout):
        entries = [{"active": self.ACTIVE, "commented": self.COMMENTED,
                    "other": self.OTHER}[e] for e in self.LAYOUTS[layout]]
        target = env.get_apxs_var("TARGET")
        conf = tmp_path / f"{target}.conf"
        conf.write_text("\n".join(["# start", self.OTHER] + entries
                                  + ["# end", ""]))
        total = sum(self._lines(conf.read_text()))
        results = []
        for _ in range(2):
            r = env.run([env.apxs, "-S", f"SYSCONFDIR={tmp_path}", "-e", "-A",
                         "-n", "foo", "mod_foo.so"])
            assert r.exit_code == 0, f"{r.stdout}{r.stderr}"
            content = conf.read_text()
            assert self._lines(content)[0] == 0, content
            assert sum(self._lines(content)) == total, content
            assert content.count(self.OTHER) == 1 + self.LAYOUTS[layout].count("other")
            assert "# start" in content and "# end" in content
            results.append(content)
        assert results[0] == results[1]
