import os
import re

import pytest

from .env import CoreTestEnv


@pytest.mark.skipif(condition=not os.path.isfile(CoreTestEnv().apxs),
                    reason="apxs not available")
class TestApxsLoadModule:

    OTHER = "LoadModule other_module modules/mod_other.so"
    LINES = {
        "active": "LoadModule foo_module modules/mod_foo.so",
        "commented": "#LoadModule foo_module modules/mod_foo.so",
    }
    # where the line of the module is in the file
    LAYOUTS = {
        "first": "{m}\n{o}\n# end\n",
        "middle": "{o}\n{m}\n# end\n",
        "last": "{o}\n{m}\n",
        "last-no-newline": "{o}\n{m}",
    }

    # apxs -A/-a must find the LoadModule line wherever it is in the file,
    # edit it in place and give the same result when run again
    @pytest.mark.parametrize("layout", list(LAYOUTS))
    @pytest.mark.parametrize("initial", list(LINES))
    @pytest.mark.parametrize(["opt", "enabled"], [["-A", False], ["-a", True]])
    def test_core_010_01(self, env, tmp_path, layout, initial, opt, enabled):
        target = env.get_apxs_var("TARGET")
        conf = tmp_path / f"{target}.conf"
        conf.write_text(self.LAYOUTS[layout].format(m=self.LINES[initial],
                                                    o=self.OTHER))
        for _ in range(2):
            r = env.run([env.apxs, "-S", f"SYSCONFDIR={tmp_path}", "-e", opt,
                         "-n", "foo", "mod_foo.so"])
            assert r.exit_code == 0, f"{r.stdout}{r.stderr}"
            content = conf.read_text()
            active = re.findall(r"^LoadModule\s+foo_module\s", content, re.M)
            disabled = re.findall(r"^#LoadModule\s+foo_module\s", content, re.M)
            assert len(active) + len(disabled) == 1, content
            assert (len(active) == 1) == enabled, content
            assert self.OTHER in content
