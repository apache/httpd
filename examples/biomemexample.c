#include <openssl/bio.h>
#include <openssl/ssl.h>

#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>

static char string[10] = "ABCDEFGH";

void init_OpenSSL()
{
	if(!SSL_library_init())
	{
		printf("OpenSSL initialization failed!\n");
		exit(1);
	}
	SSL_load_error_strings();
}
int sendreceive(SSL *ssl, BIO *ssl_r, BIO *ssl_w, int fdread, int fdwrite)
{
  char buf[4096];
  int error = SSL_ERROR_NONE;
  int n = 10;
  int pid = getpid();
  sleep(5);
  while(error == SSL_ERROR_NONE)
  {
    fflush(stdout);
    /* the sender */
    int ret = SSL_write(ssl, string, 10);
    printf("sendreceive: %d SSL_write %d\n", pid, ret);
    ret = BIO_read(ssl_w, buf, 4096);
    printf("sendreceive: BIO_read %d %d\n", error, ret);
    if (error != SSL_ERROR_NONE)
      break;
    write(fdwrite, buf, ret);

    /* the receiver */
    n = read(fdread, buf, 4096);
    if (n<=0) {
      printf("sendreceive: read failed %d\n", errno);
      break;
    }
    ret = BIO_write(ssl_r, buf, n);
    error = SSL_get_error(ssl, ret);
    printf("sendreceive: BIO_write %d %d\n", error, ret);
    if (error != SSL_ERROR_NONE)
      break;
    ret = SSL_read(ssl, buf, sizeof(buf));
    printf("sendreceive: %d SSL_read %d %d\n", pid, ret, SSL_get_error(ssl, ret));
    if (SSL_get_error(ssl, ret) == SSL_ERROR_WANT_READ) {
      printf("We need to retry...\n");
    }
    printf("sendreceive: received: %s send: %s SSL_read %d %d\n", buf, string, ret, SSL_get_error(ssl, ret));
/*
    ret = BIO_read(ssl_w, buf, 4096);
    error = SSL_get_error(ssl, ret);
    printf("sendreceive: BIO_read %d\n", error);
    if (error != SSL_ERROR_NONE)
      break;
    write(fdwrite, buf, ret);
 */
  }
  return 0;
}

int client(int fdread, int fdwrite)
{
	BIO *client_r = BIO_new(BIO_s_mem());
	BIO *client_w = BIO_new(BIO_s_mem());

	SSL *ssl_client;
	SSL_CTX *ctx_client;

	init_OpenSSL();

	ctx_client = SSL_CTX_new(TLS_client_method());
	SSL_CTX_set_verify(ctx_client, SSL_VERIFY_NONE, NULL);
	ssl_client = SSL_new(ctx_client);

	SSL_set_bio(ssl_client, client_r, client_w);
	SSL_set_connect_state(ssl_client);

	bool fin_client = false;
	char buf[4096];
	int n;
        int error = SSL_ERROR_NONE;
	while(!fin_client)
	{
		fflush(stdout);
                if (!SSL_is_init_finished(ssl_client)) {
                  printf("client: SSL_do_handshake\n");
		  fflush(stdout);
		  int ret = SSL_do_handshake(ssl_client);
                  error =  SSL_get_error(ssl_client, ret);
                  printf("client: SSL_do_handshake %d\n", error);
		  fflush(stdout);
                  /* trying something ... */
                  if (error == SSL_ERROR_NONE) {
                    printf("client: SSL_do_handshake DONE???\n");
		    fflush(stdout);
		    int ret = BIO_read(client_w, buf, 4096);
                    if (ret>0) {
                      write(fdwrite, buf, ret);
                      printf("client: SSL_do_handshake DONE %d %d\n", ret, SSL_get_error(ssl_client, ret));
		      fflush(stdout);
                      break; /* Done */
                    }
                  }
                }
		fflush(stdout);
                if (error == SSL_ERROR_WANT_READ) {
                  printf("client: SSL_ERROR_WANT_READ\n");
		  fflush(stdout);
		  int ret = BIO_read(client_w, buf, 4096);
                  if (ret>0) {
                    write(fdwrite, buf, ret);
                    printf("client SSL_ERROR_WANT_READ read %d\n", ret);
                    fflush(stdout);
                    continue;
                  }  else  {
                    error =  SSL_get_error(ssl_client, ret);
                    printf("client SSL_ERROR_WANT_READ error %d\n", error);
                    fflush(stdout);
                  }
                }
                if (error == SSL_ERROR_WANT_WRITE) {
                  printf("client SSL_ERROR_WANT_WRITE\n");
		  fflush(stdout);
                  n = read(fdread, buf, 4096);
                  if (n<=0) {
                    printf("read failed %d", errno);
                    break;
                  }
	          int ret = BIO_write(client_r, buf, n);
                  error =  SSL_get_error(ssl_client, ret);
                  printf("client SSL_ERROR_WANT_WRITE written %d\n", ret);
		  fflush(stdout);
                  continue;
                
                }
                printf("client: OOPS! %d\n", error);
                fd_set fdset;
                struct timeval tv;
                FD_ZERO(&fdset);
                FD_SET(fdread, &fdset);
                tv.tv_sec = 1;
                tv.tv_usec = 0;
                int err = select(fdread+1, &fdset, NULL, NULL, &tv);
                if (err > 0) {
                  n = read(fdread, buf, 4096);
                  if (n <=0)
                    break;
	          int ret = BIO_write(client_r, buf, n);
                  error = SSL_get_error(ssl_client, ret);
                  printf("client  received %d return %d\n", n, ret);
                }
                fin_client = SSL_is_init_finished(ssl_client);
        }
        printf("client done! %d\n", SSL_is_init_finished(ssl_client));

        sendreceive(ssl_client, client_r, client_w, fdread, fdwrite); 
	return 0;
}
int server(int fdread, int fdwrite)
{
	BIO *srv_r  = BIO_new(BIO_s_mem());
	BIO *srv_w = BIO_new(BIO_s_mem());
	
	SSL *ssl_srv;
	SSL_CTX *ctx_srv;

	init_OpenSSL();

	ctx_srv = SSL_CTX_new(TLS_server_method());
	SSL_CTX_set_verify(ctx_srv, SSL_VERIFY_NONE, NULL);
        /* set key / cert */
        SSL_CTX_use_certificate_file(ctx_srv, "/home/jfclere/CERTS/newcert.pem", SSL_FILETYPE_PEM);
        SSL_CTX_use_PrivateKey_file(ctx_srv, "/home/jfclere/CERTS/newkey.txt.pem", SSL_FILETYPE_PEM);
	ssl_srv = SSL_new(ctx_srv);

	SSL_set_bio(ssl_srv, srv_r, srv_w);
	SSL_set_accept_state(ssl_srv);

	bool fin_srv = false;
	char buf[4096];
	int n;
        int error = SSL_ERROR_NONE;
	while(!fin_srv)
	{
                if (!SSL_is_init_finished(ssl_srv)) {
                  printf("server SSL_do_handshake\n");
		  fflush(stdout);
		  int ret = SSL_do_handshake(ssl_srv);
                  error = SSL_get_error(ssl_srv, ret);
                  printf("server: SSL_do_handshake %d\n", error);
		  fflush(stdout);
                  if (error == SSL_ERROR_NONE) {
                    printf("server: SSL_do_handshake DONE???\n");
		    fflush(stdout);
		    int ret = BIO_read(srv_w, buf, 4096);
                    if (ret>0) {
                      write(fdwrite, buf, ret);
                      printf("server: SSL_do_handshake DONE %d %d\n", ret, SSL_get_error(ssl_srv, ret));
		      fflush(stdout);
                      break; /* Done */
                    }
                  }
                }
		fflush(stdout);
                if (error == SSL_ERROR_SSL) {
                    printf("server SSL_ERROR_SSL error\n");
		    fflush(stdout);
                    break;
                }
                if (error == SSL_ERROR_WANT_READ) {
                  printf("server SSL_ERROR_WANT_READ\n");
		  fflush(stdout);
		  n = BIO_read(srv_w, buf, 4096);
                  if (n<0) {
                    printf("server SSL_SSL_ERROR_WANT_READ error %d\n", SSL_get_error(ssl_srv, n));
	            fflush(stdout);
                    error = SSL_get_error(ssl_srv, n);
                  } else {
                    write(fdwrite, buf, n);
                    printf("server SSL_ERROR_WANT_READ read %d\n", n);
		    fflush(stdout);
                    continue;
                  }
                }
                if (error == SSL_ERROR_WANT_WRITE) {
                  printf("server SSL_ERROR_WANT_WRITE\n");
		  fflush(stdout);
                  n = read(fdread, buf, 4096);
                  if (n<=0) {
                    printf("failed %d\n", errno);
		    fflush(stdout);
                    break;
                  }
		  int ret = BIO_write(srv_r, buf, n);
                  if (ret>=0) {
                    printf("server  SSL_ERROR_WANT_WRITE written %d\n", ret);
	            fflush(stdout);
                    continue;
                  }
                  error = SSL_get_error(ssl_srv, ret);
                  printf("server  SSL_ERROR_WANT_WRITE %d return %d\n", n, ret);
	          fflush(stdout);
                }
                printf("server: OOPS! %d\n", error);
                fd_set fdset;
                struct timeval tv;
                FD_ZERO(&fdset);
                FD_SET(fdread, &fdset);
                tv.tv_sec = 1;
                tv.tv_usec = 0;
                int err = select(fdread+1, &fdset, NULL, NULL, &tv);
                if (err > 0) {
                  n = read(fdread, buf, 4096);
                  if (n <=0) {
                    printf("server received read error\n");
                    break;
                  }
	          int ret = BIO_write(srv_r, buf, n);
                  error = SSL_get_error(ssl_srv, ret);
                  printf("server received %d return %d\n", n, ret);
                } else {
                  printf("server select %d error???\n", err);
                }
                fin_srv = SSL_is_init_finished(ssl_srv);
		
	}
        printf("server done! %d\n", SSL_is_init_finished(ssl_srv));

        sendreceive(ssl_srv, srv_r, srv_w, fdread, fdwrite); 
	return 0;
}
int main()
{
       int     fd[2], df[2];
       pid_t   childpid;

       if (pipe(fd)==-1) {
               perror("pipe");
               exit(1);
       }
       if (pipe(df)==-1) {
               perror("pipe");
               exit(1);
       }
       
       if((childpid = fork()) == -1)
       {
               perror("fork");
               exit(1);
       }
       if (childpid == 0) {
         close(fd[1]);
         close(df[0]);
         strcpy(string, "abcdefgh");
         client(fd[0], df[1]);
       } else {
         close(fd[0]);
         close(df[1]);
         server(df[0], fd[1]);
       }
       printf("exited!");
}
