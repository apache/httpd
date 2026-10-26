r"""mpm_motorz: the default ServerLimit is the larger of 16 and twice StartServers,
capped at the compile-time maximum, and must not overflow for a huge StartServers.

Each case runs `httpd -t` on the generated test config plus one StartServers.
"""

import subprocess

import pytest

MAX_SERVER_LIMIT = 200000


def configtest(server, tmp_path, start_servers):
    conf = tmp_path / "startservers.conf"
    conf.write_text(
        f'Include "{server.config.vars["t_conf_file"]}"\n'
        f"StartServers {start_servers}\n")
    argv = [a for a in server.args() if a != "-DFOREGROUND"]
    argv[argv.index("-f") + 1] = str(conf)
    return subprocess.run([*argv, "-t"], capture_output=True, text=True)


@pytest.mark.parametrize("start_servers", [
    MAX_SERVER_LIMIT // 2,          # twice this is exactly the maximum
    MAX_SERVER_LIMIT // 2 + 1,      # twice this is just over it
    MAX_SERVER_LIMIT,
    MAX_SERVER_LIMIT + 1,
    1073741824,                     # twice this overflows a 32-bit int
    2147483647,
])
def test_default_server_limit_does_not_overflow(server, tmp_path, start_servers):
    if server.config.info.mpm != "motorz":
        pytest.skip("motorz only")
    r = configtest(server, tmp_path, start_servers)
    assert r.returncode == 0 and "Syntax OK" in r.stderr, r.stderr
    assert "ServerLimit of -" not in r.stderr, r.stderr
    warning = (f"StartServers of {start_servers} exceeds ServerLimit of "
               f"{MAX_SERVER_LIMIT}, decreasing to {MAX_SERVER_LIMIT}")
    if start_servers > MAX_SERVER_LIMIT:
        assert warning in r.stderr, r.stderr
    else:
        assert "exceeds ServerLimit" not in r.stderr, r.stderr
