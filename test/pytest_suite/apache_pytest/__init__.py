"""Pytest-based test framework for Apache httpd (migration from Apache::Test).

Phase 1: server lifecycle, config generation, C-module compilation, HTTP client.
Phase 2: test-facing API (t_cmp, need_* markers) used by the translated tests.
"""

from .client import TestClient
from .cmodules import clean_modules, compile_all
from .config import TestConfig
from .probe import HttpdInfo, probe
from .server import HttpdServer
from .testapi import (
    need_cgi,
    need_lwp,
    need_min_apache_version,
    need_module,
    need_php,
    need_ssl,
    t_cmp,
)

__all__ = [
    "HttpdInfo",
    "HttpdServer",
    "TestClient",
    "TestConfig",
    "clean_modules",
    "compile_all",
    "need_cgi",
    "need_lwp",
    "need_min_apache_version",
    "need_module",
    "need_php",
    "need_ssl",
    "probe",
    "t_cmp",
]
