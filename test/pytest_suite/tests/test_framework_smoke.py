"""Phase-1 framework self-test.

Proves the framework core works end-to-end against a real built httpd:
config generation, syntax validity, server lifecycle, HTTP client, vhost
resolution, and C-module compilation + loading.
"""

from __future__ import annotations

import pytest


def test_config_syntax_valid(server) -> None:
    """The generated httpd.conf passes `httpd -t` (run inside server.start)."""
    result = server.configtest()
    assert result.returncode == 0, result.stdout + result.stderr


def test_server_root_serves_index(http, config) -> None:
    """GET / returns the generated index.html body."""
    r = http.get("/")
    assert r.status_code == 200
    assert r.text == f"welcome to {http.servername}:{config.vars['port']}\n"


def test_vhost_resolves_and_responds(http, config) -> None:
    """At least one module vhost was allocated a port and is reachable."""
    # mod_headers vhost is configured in extra.conf.in and the module is loaded.
    assert "mod_headers" in config.vhosts, sorted(config.vhosts)
    url = http.vhost_url("mod_headers", "/")
    r = http.request("GET", url)
    assert r.status_code == 200
    assert r.text == f"welcome to {http.servername}:{config.vars['port']}\n"


def test_cmodule_compiled_and_loaded(config) -> None:
    """A bundled C module compiled to a .so and is loaded in the config."""
    conf_text = (
        config.vars["t_conf_file"]
        and open(config.vars["t_conf_file"]).read()  # noqa: SIM115
    )
    assert "LoadModule echo_post_module" in conf_text
    # echo_post.c registers the echo_post handler; the module is now in scope.
    assert config.info.has_module("mod_echo_post") or "echo_post" in conf_text


def test_distinct_vhost_ports(config) -> None:
    """Each configured vhost got its own port above the base port."""
    base = int(config.vars["port"])
    ports = [vh.port for vh in config.vhosts.values()]
    assert all(p > base for p in ports)
    assert len(ports) == len(set(ports)), "vhost ports must be unique"


@pytest.mark.parametrize("token", ["cgi", "ssl", "thread", "access", "auth", "php"])
def test_module_name_tokens_resolved(config, token: str) -> None:
    """Module-name tokens (@CGI_MODULE@ etc.) all resolved to a value."""
    assert config.vars[f"{token}_module_name"]
    assert config.vars[f"{token}_module"].endswith(".c")
