"""Self-test for pyhttpd/instance.py: starting, stopping and restarting a bare
httpd. Needs a built httpd (--apxs, --httpd or the build's config.ini), but no
module beyond the MPM, and uses a free port and a temporary directory."""
import os
import subprocess
import time
from pathlib import Path

import pytest

from pyhttpd.build import resolve_build
from pyhttpd.instance import (HttpdInstance, HttpdStartError, free_port,
                              pid_alive, port_open, read_pid)


@pytest.fixture(scope="module")
def build(pytestconfig):
    info = resolve_build(pytestconfig)
    if info is None or info.prefix is None:
        pytest.skip("no httpd build to test against")
    return info


def _module_lines(build):
    """LoadModule lines for what a bare server needs, for the modules that
    are not compiled in."""
    static = subprocess.run([str(build.httpd), "-l"], capture_output=True,
                            text=True).stdout
    mpm = os.environ.get("MPM", "event")
    lines = []
    for name in (f"mpm_{mpm}", "unixd", "authz_core"):
        so = Path(build.prefix) / "modules" / f"mod_{name}.so"
        if f"mod_{name}.c" in static:
            continue
        if so.is_file():
            lines.append(f"LoadModule {name}_module {so}")
    return lines


@pytest.fixture
def server(build, tmp_path):
    port = free_port()
    conf = tmp_path / "httpd.conf"
    conf.write_text("\n".join([
        f'ServerRoot "{tmp_path}"',
        "ServerName localhost",
        f"Listen 127.0.0.1:{port}",
        f'PidFile "{tmp_path}/httpd.pid"',
        f'ErrorLog "{tmp_path}/error_log"',
        "LogLevel warn",
        *_module_lines(build),
        "StartServers 1",
        "ThreadsPerChild 5",
        ""]))
    inst = HttpdInstance(build.httpd, ["-f", str(conf)], ports=[port],
                         error_log=tmp_path / "error_log",
                         pid_files=[tmp_path / "httpd.pid"],
                         stderr_file=tmp_path / "stderr")
    yield inst, tmp_path, conf
    inst.stop()


def _children(parent):
    out = subprocess.run(["ps", "-A", "-o", "pid=,ppid="], capture_output=True,
                         text=True).stdout
    return {int(a) for a, b in (ln.split() for ln in out.splitlines() if ln.strip())
            if int(b) == parent}


def test_start_stop(server):
    inst, _, _ = server
    assert not inst.is_running() and inst.pid == 0
    inst.start()
    assert inst.is_running() and inst.pid > 0
    assert inst.all_ports_open()
    pid = inst.pid
    assert inst.stop() is True
    assert not pid_alive(pid)
    assert not port_open(inst.ports[0])


def test_stop_is_idempotent(server):
    inst, _, _ = server
    assert inst.stop() is True          # never started
    inst.start()
    assert inst.stop() is True
    assert inst.stop() is True          # already stopped


def test_stop_reaps_children(server):
    inst, _, _ = server
    inst.start()
    children = _children(inst.pid)
    assert children, "the MPM has started no children"
    inst.stop()
    assert not any(pid_alive(c) for c in children)


def test_bad_config_reports_the_error(server):
    inst, _, conf = server
    conf.write_text(conf.read_text() + "\nNoSuchDirective on\n")
    with pytest.raises(HttpdStartError) as e:
        inst.start()
    assert "NoSuchDirective" in e.value.stderr
    assert e.value.returncode != 0
    assert not inst.is_running()
    assert not port_open(inst.ports[0])


def test_bad_config_found_by_configtest_first(server):
    inst, _, conf = server
    inst.configtest_first = True
    conf.write_text(conf.read_text() + "\nNoSuchDirective on\n")
    with pytest.raises(HttpdStartError) as e:
        inst.start()
    assert "NoSuchDirective" in e.value.stderr


def test_start_replaces_a_stale_server(server):
    inst, tmp_path, _ = server
    inst.start()
    stale = inst.pid
    # a server from an earlier run: known only by its pid file
    inst.proc.poll()
    other = HttpdInstance(inst.httpd, inst.args, ports=inst.ports,
                          error_log=tmp_path / "error_log",
                          pid_files=[tmp_path / "httpd.pid"],
                          stderr_file=tmp_path / "stderr2")
    assert read_pid(tmp_path / "httpd.pid") == stale
    other.start()
    try:
        # a real stale server is somebody else's child, reaped by init;
        # this one is ours and is a zombie until we wait for it
        assert inst.proc.wait(timeout=10) is not None
        assert not pid_alive(stale)
        assert other.is_running()
    finally:
        other.stop()
        inst.proc = None


def test_graceful_restart_keeps_the_parent(server):
    inst, _, _ = server
    inst.start()
    parent, children = inst.pid, _children(inst.pid)
    assert inst.restart(graceful=True)
    assert inst.pid == parent and inst.all_ports_open()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and children & _children(parent):
        time.sleep(0.1)        # the old generation drains
    assert not (children & _children(parent))


def test_hard_restart_serves_again(server):
    inst, tmp_path, _ = server
    inst.start()
    before = (tmp_path / "error_log").read_text().count("resuming normal operations")
    assert inst.restart(graceful=False)
    after = (tmp_path / "error_log").read_text().count("resuming normal operations")
    assert after == before + 1
    assert inst.all_ports_open()


def test_restart_without_server(server):
    inst, _, _ = server
    assert inst.restart() is False


def test_graceful_stop(server):
    inst, _, _ = server
    inst.start()
    pid = inst.pid
    assert inst.graceful_stop() is True
    assert not pid_alive(pid)


def test_stderr_of_a_good_start_is_available(server):
    inst, _, _ = server
    inst.start()
    assert isinstance(inst.stderr_text(), str)
