from .md_env import MDTestEnv
from pyhttpd.conf import HttpdConf


class MDConf(HttpdConf):

    def __init__(self, env: MDTestEnv, text=None, std_ports=True,
                 local_ca=True, std_vhosts=True, proxy=False,
                 admin=None):
        super().__init__(env=env)

        if admin is None:
            admin = f"admin@{env.http_tld}"
        if len(admin.strip()):
            self.add_admin(admin)
        self.add([
            "MDRetryDelay 1s",  # speed up testing a little
        ])
        if local_ca:
            self.add([
                f"MDCertificateAuthority {env.acme_url}",
                f"MDCertificateAgreement accepted",
                f"MDCACertificateFile {env.server_dir}/acme-ca.pem",
                "",
                ])
        if std_ports:
            self.add(f"MDPortMap 80:{env.http_port} 443:{env.https_port}")
            if env.ssl_module == "mod_tls":
                self.add(f"TLSListen {env.https_port}")
        self.add([
            "<Location /server-status>",
            "    SetHandler server-status",
            "</Location>",
            "<Location /md-status>",
            "    SetHandler md-status",
            "</Location>",
        ])
        if std_vhosts:
            self.add_vhost_test1()
        if proxy:
            self.add([
                f"Listen {self.env.proxy_port}",
                f"<VirtualHost *:{self.env.proxy_port}>",
                "    ProxyRequests On",
                "    ProxyVia On",
                "    # be totally open",
                "    AllowCONNECT 0-56535",
                "    <Proxy *>",
                "       # No require or other restrictions, this is just a test server",
                "    </Proxy>",
                "</VirtualHost>",
            ])
        if text is not None:
            self.add(text)

    def add_drive_mode(self, mode):
        self.add("MDRenewMode \"%s\"\n" % mode)

    def add_renew_window(self, window):
        self.add("MDRenewWindow %s\n" % window)

    def add_private_key(self, key_type, key_params):
        self.add("MDPrivateKeys %s %s\n" % (key_type, " ".join(map(lambda p: str(p), key_params))))

    def add_admin(self, email):
        self.add(f"ServerAdmin mailto:{email}")

    def add_md(self, domains):
        dlist = " ".join(domains)    # without quotes
        self.add(f"MDomain {dlist}\n")

    def start_md(self, domains):
        dlist = " ".join([f"\"{d}\"" for d in domains])  # with quotes, #257
        self.add(f"<MDomain {dlist}>\n")
        
    def end_md(self):
        self.add("</MDomain>\n")

    def start_md2(self, domains):
        self.add("<MDomainSet %s>\n" % " ".join(domains))

    def end_md2(self):
        self.add("</MDomainSet>\n")
