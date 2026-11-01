"""Parameter-level expectations must cover the no-digits cache parsing."""
import pytest
from pyhttpd import backport

from modules.core import test_012_config_off_t as off_t


@pytest.mark.parametrize("directive", [d for d in off_t.DIRECTIVES
                                       if d.startswith("Cache")])
@pytest.mark.parametrize("value", ["abc", "abc123", "k", "+", "-"])
def test_cache_no_digits_expectations(directive, value):
    marks = next(m.args[1] for m in
                 off_t.TestConfigOffT.test_core_012_002.pytestmark
                 if m.name == "parametrize")
    case = next(c for c in marks if c.values == (directive, value))
    assert len(case.marks) == 1
    mark = case.marks[0].mark
    assert mark.name == "not_backported"
    assert backport.lacks_change("2.4.70", **mark.kwargs)
    assert not backport.lacks_change("2.5.1", **mark.kwargs)
