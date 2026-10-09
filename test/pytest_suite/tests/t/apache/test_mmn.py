r"""Translated from t/apache/mmn.t -- ap_mmn.h self-consistency check.

Verifies the human-readable comment ("YYYYMMDD.N (x.y.z)") and the
#define MODULE_MAGIC_NUMBER_MAJOR/MINOR in the installed ap_mmn.h agree. Not an
HTTP test -- reads the header from apxs -q INCLUDEDIR.
"""

import os
import re

import pytest

from apache_pytest import need_min_apache_version, t_cmp

_COMMENT = re.compile(r"^\s+[*]\s+(\d{8})[.](\d+)\s+\([\d.]+(?:-dev)?\)\s")
_MAJOR = re.compile(r"^#define\s+MODULE_MAGIC_NUMBER_MAJOR\s+(\d+)(?:\s|$)")
_MINOR = re.compile(r"^#define\s+MODULE_MAGIC_NUMBER_MINOR\s+(\d+)(?:\s|$)")


@need_min_apache_version("2")
def test_mmn(http):
    incdir = http.apxs("INCLUDEDIR")
    filename = os.path.join(incdir, "ap_mmn.h") if incdir else None
    if not filename or not os.path.isfile(filename):
        # Fall back to the source tree include/ directory.
        src_inc = os.path.join(http.vars("top_dir"), "..", "..", "include", "ap_mmn.h")
        if os.path.isfile(src_inc):
            filename = src_inc
        else:
            pytest.skip("ap_mmn.h not found (no apxs and not in source tree)")

    cmajor = cminor = major = minor = None
    with open(filename) as fh:
        for line in fh:
            if (m := _COMMENT.match(line)):
                cmajor, cminor = m.group(1), m.group(2)
            elif (m := _MAJOR.match(line)):
                major = m.group(1)
            elif (m := _MINOR.match(line)):
                minor = m.group(1)

    assert t_cmp(major, cmajor), "MODULE_MAGIC_NUMBER_MAJOR matches comment"
    assert t_cmp(minor, cminor), "MODULE_MAGIC_NUMBER_MINOR matches comment"
