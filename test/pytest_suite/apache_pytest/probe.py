"""Compatibility re-export: the probe now lives in :mod:`pyhttpd.build`."""

from pyhttpd.build import (  # noqa: F401
    HttpdInfo,
    LoadDirective,
    parse_inherited_take1,
    parse_loadmodules,
    probe,
    probe_defines_and_mpm,
    probe_static_modules,
    probe_version,
)
