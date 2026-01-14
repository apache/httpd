FROM apache-ech-server:latest

RUN mkdir -p /usr/local/apache2/htdocs/public \
             /usr/local/apache2/htdocs/private

RUN echo "<html><body><h1>Public Gateway</h1><p>ECH Failed</p></body></html>" \
    > /usr/local/apache2/htdocs/public/index.html

RUN echo "<html><head><title>It works! Apache httpd</title></head><body><h1>It works!</h1><p>ECH Decrypted Successfully</p></body></html>" \
    > /usr/local/apache2/htdocs/private/index.html

RUN chown -R daemon:daemon /usr/local/apache2/htdocs
