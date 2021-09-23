import os


class HttpdConf(object):

    def __init__(self, env, path=None):
        self.env = env
        self._lines = []
        self._has_ssl_vhost = False

    def install(self):
        if not self._has_ssl_vhost:
            self.add_vhost_test1()
        self.env.install_test_conf(self._lines)

    def add(self, line):
        if isinstance(line, list):
            self._lines.extend(line)
        else:
            self._lines.append(line)
        return self

    def add_vhost(self, port, name, aliases=None, doc_root="htdocs", with_ssl=True):
        self.start_vhost(port, name, aliases, doc_root, with_ssl)
        self.end_vhost()
        return self

    def start_vhost(self, port, name, aliases=None, doc_root="htdocs", with_ssl=True):
        server_domain = f"{name}.{self.env.http_tld}"
        lines = [
            f"<VirtualHost *:{port}>",
            f"    ServerName {server_domain}"
        ]
        if aliases:
            lines.extend([
                f"    ServerAlias {alias}.{self.env.http_tld}" for alias in aliases])
        lines.append(f"    DocumentRoot {doc_root}")
        if with_ssl:
            self._has_ssl_vhost = True
            lines.append("    SSLEngine on")
            for cred in self.env.get_credentials_for_name(server_domain):
                lines.extend([
                    f"SSLCertificateFile {cred.cert_file}",
                    f"SSLCertificateKeyFile {cred.pkey_file}",
                ])
        return self.add(lines)
                  
    def end_vhost(self):
        self.add("</VirtualHost>")
        return self

    def add_proxies(self, host, proxy_self=False, h2proxy_self=False):
        if proxy_self or h2proxy_self:
            self.add("      ProxyPreserveHost on")
        if proxy_self:
            self.add(f"""
                ProxyPass /proxy/ http://127.0.0.1:{self.env.http_port}/
                ProxyPassReverse /proxy/ http://{host}.{self.env.http_tld}:{self.env.http_port}/
            """)
        if h2proxy_self:
            self.add(f"""
                ProxyPass /h2proxy/ h2://127.0.0.1:{self.env.https_port}/
                ProxyPassReverse /h2proxy/ https://{host}.{self.env.http_tld}:self.env.https_port/
            """)
        return self
    
    def add_vhost_test1(self, proxy_self=False, h2proxy_self=False, extras=None):
        domain = f"test1.{self.env.http_tld}"
        if extras and 'base' in extras:
            self.add(extras['base'])
        self.start_vhost(
            self.env.http_port, "test1", aliases=["www1"], doc_root="htdocs/test1", with_ssl=False
        ).add(
            "      Protocols h2c http/1.1"
        ).end_vhost()
        self.start_vhost(
            self.env.https_port, "test1", aliases=["www1"], doc_root="htdocs/test1", with_ssl=True)
        self.add(f"""
            Protocols h2 http/1.1
            <Location /006>
                Options +Indexes
                HeaderName /006/header.html
            </Location>
            {extras[domain] if extras and domain in extras else ""}
            """)
        self.add_proxies("test1", proxy_self, h2proxy_self)
        self.end_vhost()
        return self
        
    def add_vhost_test2(self):
        self.start_vhost(self.env.http_port, "test2", aliases=["www2"], doc_root="htdocs/test2", with_ssl=False)
        self.add("      Protocols http/1.1 h2c")
        self.end_vhost()
        self.start_vhost(self.env.https_port, "test2", aliases=["www2"], doc_root="htdocs/test2", with_ssl=True)
        self.add("""
            Protocols http/1.1 h2
            <Location /006>
                Options +Indexes
                HeaderName /006/header.html
            </Location>""")
        self.end_vhost()
        return self

    def add_vhost_cgi(self, proxy_self=False, h2proxy_self=False):
        if proxy_self:
            self.add_proxy_setup()
        if h2proxy_self:
            self.add("      SSLProxyEngine on")
            self.add("      SSLProxyCheckPeerName off")
        self.start_vhost(self.env.https_port, "cgi", aliases=["cgi-alias"], doc_root="htdocs/cgi", with_ssl=True)
        self.add("""
            Protocols h2 http/1.1
            SSLOptions +StdEnvVars
            AddHandler cgi-script .py
            <Location \"/.well-known/h2/state\">
                SetHandler http2-status
            </Location>""")
        self.add_proxies("cgi", proxy_self, h2proxy_self)
        self.add("      <Location \"/h2test/echo\">")
        self.add("          SetHandler h2test-echo")
        self.add("      </Location>")
        self.end_vhost()
        self.start_vhost(self.env.http_port, "cgi", aliases=["cgi-alias"], doc_root="htdocs/cgi", with_ssl=False)
        self.add("      AddHandler cgi-script .py")
        self.end_vhost()
        self.add("      LogLevel proxy:info")
        self.add("      LogLevel proxy_http:info")
        return self

    def add_vhost_noh2(self):
        self.start_vhost(self.env.https_port, "noh2", aliases=["noh2-alias"], doc_root="htdocs/noh2", with_ssl=True)
        self.add(f"""
            Protocols http/1.1
            SSLOptions +StdEnvVars""")
        self.end_vhost()
        self.start_vhost(self.env.http_port, "noh2", aliases=["noh2-alias"], doc_root="htdocs/noh2", with_ssl=False)
        self.add("      Protocols http/1.1")
        self.add("      SSLOptions +StdEnvVars")
        self.end_vhost()
        return self

    def add_proxy_setup(self):
        self.add("ProxyStatus on")
        self.add("ProxyTimeout 5")
        self.add("SSLProxyEngine on")
        self.add("SSLProxyVerify none")
        return self
