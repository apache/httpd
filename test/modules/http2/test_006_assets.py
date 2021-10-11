import pytest

from .env import H2Conf


class TestStore:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        H2Conf(env).add_vhost_test1().install()
        assert env.apache_restart() == 0

    # single page without any assets
    def test_h2_006_01(self, env):
        url = env.mkurl("https", "test1", "/001.html")
        r = env.nghttp().assets(url,  options=["-Haccept-encoding: none"])
        assert 0 == r.exit_code
        assert 1 == len(r.assets)
        assert r.assets == [
            {"status": 200, "size": "251", "path": "/001.html"}
        ]

    # single image without any assets
    def test_h2_006_02(self, env):
        url = env.mkurl("https", "test1", "/002.jpg")
        r = env.nghttp().assets(url,  options=["-Haccept-encoding: none"])
        assert 0 == r.exit_code
        assert 1 == len(r.assets)
        assert r.assets == [
            {"status": 200, "size": "88K", "path": "/002.jpg"}
        ]
        
    # gophertiles, yea!
    def test_h2_006_03(self, env):
        # create the tiles files we originally had checked in
        exp_assets = [
            {"status": 200, "size": "10K", "path": "/004.html"},
            {"status": 200, "size": "742", "path": "/004/gophertiles.jpg"},
        ]
        for i in range(2, 181):
            with open(f"{env.server_docs_dir}/test1/004/gophertiles_{i:03d}.jpg", "w") as fd:
                fd.write("0123456789\n")
            exp_assets.append(
                {"status": 200, "size": "11", "path": f"/004/gophertiles_{i:03d}.jpg"},
            )

        url = env.mkurl("https", "test1", "/004.html")
        r = env.nghttp().assets(url, options=["-Haccept-encoding: none"])
        assert 0 == r.exit_code
        assert 181 == len(r.assets)
        assert r.assets == exp_assets
            
    # page with js and css
    def test_h2_006_04(self, env):
        url = env.mkurl("https", "test1", "/006.html")
        r = env.nghttp().assets(url, options=["-Haccept-encoding: none"])
        assert 0 == r.exit_code
        assert 3 == len(r.assets)
        assert r.assets == [
            {"status": 200, "size": "543", "path": "/006.html"},
            {"status": 200, "size": "216", "path": "/006/006.css"},
            {"status": 200, "size": "839", "path": "/006/006.js"}
        ]

    # page with image, try different window size
    def test_h2_006_05(self, env):
        url = env.mkurl("https", "test1", "/003.html")
        r = env.nghttp().assets(url, options=["--window-bits=24", "-Haccept-encoding: none"])
        assert 0 == r.exit_code
        assert 2 == len(r.assets)
        assert r.assets == [
            {"status": 200, "size": "316", "path": "/003.html"},
            {"status": 200, "size": "88K", "path": "/003/003_img.jpg"}
        ]
