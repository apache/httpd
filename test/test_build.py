"""Self-test for pyhttpd/build.py: one httpd under test for the whole session,
whichever way it was named, and what is learned about it."""
import os

import pytest

from pyhttpd.build import current, parse_loadmodules, resolve_build
from pyhttpd.env import HttpdTestEnv


@pytest.fixture
def subprocess_run(pytester, monkeypatch):
    monkeypatch.setenv("PYTHONPATH", os.path.dirname(os.path.abspath(__file__)))
    pytester.makepyfile("def test_nothing():\n    pass\n")

    def run(*args):
        return pytester.runpytest_subprocess("-p", "pyhttpd.plugin",
                                             "-p", "no:cacheprovider", *args)
    return run


@pytest.mark.parametrize("option", ["--apxs", "--httpd"])
def test_unusable_target_is_a_usage_error(subprocess_run, tmp_path, option):
    # and not a run against the build of config.ini instead
    result = subprocess_run(f"{option}={tmp_path / 'nonexistent'}")
    assert result.ret == pytest.ExitCode.USAGE_ERROR
    result.stderr.fnmatch_lines(["*httpd under test:*nonexistent*no such file*"])


def test_the_session_has_one_target(pytestconfig):
    info = resolve_build(pytestconfig)
    if info is None:
        pytest.skip("no httpd build to test against")
    assert current() is info
    # an environment created at import time, without the pytest config,
    # tests that httpd too, not the one config.ini names
    env = HttpdTestEnv()
    assert os.path.realpath(os.path.join(env.bin_dir, "httpd")) == \
        os.path.realpath(info.httpd)
    assert env.get_httpd_version().startswith(info.version_str)
    if info.source != "config.ini":
        assert os.path.realpath(env.libexec_dir) == os.path.realpath(info.libexecdir)


def test_static_modules_count_as_available(pytestconfig):
    info = resolve_build(pytestconfig)
    if info is None:
        pytest.skip("no httpd build to test against")
    # mod_so is always compiled in, never a DSO
    assert "mod_so.c" in info.static_modules
    assert HttpdTestEnv.has_shared_module("so")


def test_loadmodule_lines(tmp_path):
    (tmp_path / "conf.d").mkdir()
    (tmp_path / "httpd.conf").write_text(
        'LoadModule a_module modules/mod_a.so\n'
        '#LoadModule b_module modules/mod_b.so\n'
        'LoadModule c_module "/opt/my modules/mod_c.so"\n'
        'IncludeOptional conf.d/*.conf\n'
        'Include "conf.d/missing.conf"\n')
    (tmp_path / "conf.d" / "d.conf").write_text(
        'loadmodule d_module modules/mod_d.so\n'
        'Include httpd.conf\n')              # a loop is followed once
    found = {(d.symbol, d.so, d.active)
             for d in parse_loadmodules(tmp_path / "httpd.conf", tmp_path)}
    assert found == {
        ("a_module", str(tmp_path / "modules/mod_a.so"), True),
        ("b_module", str(tmp_path / "modules/mod_b.so"), False),
        ("c_module", "/opt/my modules/mod_c.so", True),
        ("d_module", str(tmp_path / "modules/mod_d.so"), True),
    }
