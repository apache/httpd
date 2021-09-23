#
# mod-h2 test suite
# check that our test infrastructure is sane
#
import pytest


class TestStore:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        env.setup_data_1k_1m()
        yield

    def test_000_00(self):
        assert 1 == 1

