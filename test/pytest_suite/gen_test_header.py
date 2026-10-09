#!/usr/bin/env python3
"""Generate apache_httpd_test.h for CMake builds.

Calls the same generate_header() from apache_pytest/cmodules.py that
the Unix/apxs build uses, but without importing the full apache_pytest
package (which requires httpx and other test dependencies).
"""
import sys
import types
from pathlib import Path

# Stub out the apache_pytest package so cmodules.py can be loaded
# without pulling in httpx and other test-only dependencies.
pkg = types.ModuleType('apache_pytest')
pkg.__path__ = [str(Path(__file__).parent / 'apache_pytest')]
sys.modules['apache_pytest'] = pkg

probe = types.ModuleType('apache_pytest.probe')

class _HttpdInfo:
    pass

probe.HttpdInfo = _HttpdInfo
sys.modules['apache_pytest.probe'] = probe

from apache_pytest.cmodules import generate_header  # noqa: E402

if __name__ == '__main__':
    if len(sys.argv) > 1:
        dest = Path(sys.argv[1])
    else:
        dest = Path(__file__).parent / 'c-modules' / 'apache_httpd_test.h'
    generate_header(dest)
