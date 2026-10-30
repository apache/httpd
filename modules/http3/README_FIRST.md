The module is experimental just for tests.
To build it you need openssl and nghttp3 installed.
```
./configure --enable-http3
```
To test use Firefox, Chrome or curl, Chrome is picky with the certicates.
```
LoadModule ssl_module     modules/mod_ssl.so
LoadModule http3_module   modules/mod_http3.so

EnableMMAP Off
Listen 4433 https
CoreDumpDirectory /tmp
H3MaxConnections 8000
H3HandshakeTimeout 30

<VirtualHost *:4433>
    ServerName localhost

    SSLEngine on
    SSLCertificateFile conf/localhost-fullchain.crt
    SSLCertificateKeyFile conf/localhost.key

    Protocols h3 h2 http/1.1

    H3CertificatePath     conf/localhost-fullchain.crt
    H3CertificateKeyPath  conf/localhost.key

    DocumentRoot htdocs
    <Directory htdocs>
        Require all granted
    </Directory>
</VirtualHost>
```
All the connections are going to single process for the moment, openssl QUIC is slow for the moment so DON'T use in production.                                                                                                                                                                                      
