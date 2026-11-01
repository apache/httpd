"""Renewal failures keep their diagnostics without hiding test failures."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from modules.md.md_env import MDTestEnv
from pyhttpd.log import HttpdErrorLog

from modules.md import test_702_auto as auto


def test_renewal_failure_preserves_diagnostics(tmp_path):
    env = MDTestEnv.__new__(MDTestEnv)
    env._gen_dir = str(tmp_path)
    env._server_dir = str(tmp_path / "apache")
    env._store_dir = str(tmp_path / "store")
    env.set_current_test_name("test_renewal[http/01]")
    logs = Path(env.server_dir) / "logs"
    logs.mkdir(parents=True)
    (logs / "error_log").write_text("renewal error\n")
    env._error_log = HttpdErrorLog(str(logs / "error_log"))
    conf = Path(env.server_dir) / "conf"
    conf.mkdir()
    (conf / "httpd.conf").write_text("MDPortMap 80:12345\n")
    (tmp_path / "pebble.log").write_text("challenge failed\n")
    staging = Path(env.store_stagings()) / "example.org"
    staging.mkdir(parents=True)
    (staging / "job.json").write_text('{"errors": 1}')
    (staging / "privkey.pem").write_text("private key -- must not be copied")
    statuses = {"example.org": {"renewal": {"errors": 1}}}

    env.save_renewal_failure(["example.org"], statuses)
    env.httpd_error_log.clear_log()
    env.clear_store()

    dest = tmp_path / "failed-tests" / "test_renewal_http_01_"
    assert (dest / "error_log").read_text() == "renewal error\n"
    assert (dest / "pebble.log").read_text() == "challenge failed\n"
    assert json.loads((dest / "md-status.json").read_text()) == statuses
    assert json.loads((dest / "example.org-job.json").read_text()) == {"errors": 1}
    assert not list(dest.rglob("*.pem"))


def test_await_completion_keeps_failure_status(monkeypatch):
    calls = []
    status = {"renewal": {"errors": 1}}
    env = SimpleNamespace(
        get_md_status=lambda *args, **kwargs: status,
        save_renewal_failure=lambda names, statuses: calls.append((names, statuses)),
    )
    times = iter([0, 0, 60])
    monkeypatch.setattr("modules.md.md_env.time.time", lambda: next(times))
    monkeypatch.setattr("modules.md.md_env.time.sleep", lambda duration: None)
    assert not MDTestEnv.await_completion(env, ["example.org"])
    assert calls == [(["example.org"], {"example.org": status})]


def test_await_completion_preserves_client_failure(monkeypatch):
    calls = []

    def get_md_status(*args, **kwargs):
        raise AssertionError("curl failed")

    env = SimpleNamespace(
        get_md_status=get_md_status,
        save_renewal_failure=lambda names, statuses: calls.append((names, statuses)),
    )
    with pytest.raises(AssertionError, match="curl failed"):
        MDTestEnv.await_completion(env, ["example.org"])
    assert calls == [(["example.org"], {})]


def test_store_reset_stops_the_previous_server():
    calls = []
    env = SimpleNamespace(
        apache_stop=lambda: calls.append("stop") or 0,
        clear_store=lambda: calls.append("clear"),
        get_request_domain=lambda request: "example.org",
    )
    test = auto.TestAutov2()
    auto.TestAutov2._method_scope.__wrapped__(test, env, None)
    assert calls == ["stop", "clear"]


@pytest.mark.parametrize("method", ["test_md_702_010", "test_md_702_011"])
def test_expected_challenge_errors_handled_before_completion_failure(monkeypatch, method):
    calls = []

    class Conf:
        def __init__(self, *args, **kwargs):
            pass

        def __getattr__(self, name):
            return lambda *args: None

    def await_completion(names):
        assert calls == ["ignored"]
        return False

    monkeypatch.setattr(auto, "MDConf", Conf)
    env = SimpleNamespace(
        http_port=5002, https_port=5001, apachectl_stderr="",
        apache_restart=lambda: 0,
        await_error=lambda domain: {"renewal": {"errors": 1}},
        check_md=lambda domains: None,
        await_completion=await_completion,
        httpd_error_log=SimpleNamespace(
            ignore_recent=lambda **kwargs: calls.append("ignored")),
    )
    test = auto.TestAutov2()
    test.test_domain = "example.org"
    with pytest.raises(AssertionError):
        getattr(test, method)(env)
    assert calls == ["ignored"]
