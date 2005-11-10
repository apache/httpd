
/*                          ZeusBench V1.01
                            ===============

This program is Copyright (C) Zeus Technology Limited 1996.

This program may be used and copied freely providing this copyright notice
is not removed.

This software is provided "as is" and any express or implied waranties,
including but not limited to, the implied warranties of merchantability and
fitness for a particular purpose are disclaimed.  In no event shall
Zeus Technology Ltd. be liable for any direct, indirect, incidental, special,
exemplary, or consequential damaged (including, but not limited to,
procurement of substitute good or services; loss of use, data, or profits;
or business interruption) however caused and on theory of liability.  Whether
in contract, strict liability or tort (including negligence or otherwise)
arising in any way out of the use of this software, even if advised of the
possibility of such damage.

     Written by Adam Twiss (adam@zeus.co.uk).  March 1996

Thanks to the following people for their input:
  Mike Belshe (mbelshe@netscape.com)
  Michael Campanella (campanella@stevms.enet.dec.com)

*/

/* -------------------- Notes on compiling ------------------------------

This should compile unmodified using gcc on HP-UX, FreeBSD, Linux,
IRIX, Solaris, AIX and Digital Unix (OSF).  On Solaris 2.x you will
need to compile with "-lnsl -lsocket" options.  If you have any
difficulties compiling then let me know.

On SunOS 4.x.x you may need to compile with -DSUNOS4 to add the following
two lines of code which appear not to exist in my SunOS headers */

#ifdef SUNOS4
extern char *optarg;
extern int optind, opterr, optopt;
#endif

/*  -------------------------------------------------------------------- */

/* affects include files on Solaris */
#define BSD_COMP

#include <sys/time.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <string.h>

/* ------------------- DEFINITIONS -------------------------- */

/* maximum number of requests on a time limited test */
#define MAX_REQUESTS 50000

/* good old state machine */
#define STATE_UNCONNECTED 0
#define STATE_CONNECTING  1
#define STATE_READ        2

#define CBUFFSIZE       512

struct connection
{
  int fd;
  int state;
  int read;       /* amount of bytes read */
  int bread;      /* amount of body read */
  int length;     /* Content-Length value used for keep-alive */
  char cbuff[CBUFFSIZE];  /* a buffer to store server response header */
  int cbx;                /* offset in cbuffer */
  int keepalive;          /* non-zero if a keep-alive request */
  int gotheader;          /* non-zero if we have the entire header in cbuff */
  struct timeval start, connect, done;
};

struct data
{
  int read;      /* number of bytes read */
  int ctime;     /* time in ms to connect */
  int time;      /* time in ms for connection */
};

#define min(a,b) ((a)<(b))?(a):(b)
#define max(a,b) ((a)>(b))?(a):(b)

/* --------------------- GLOBALS ---------------------------- */

int requests = 1;      /* Number of requests to make */
int concurrency = 1;   /* Number of multiple requests to make */
int tlimit = 0;        /* time limit in cs */
int keepalive = 0;     /* try and do keepalive connections */
char *machine;         /* Machine name */
char *file;            /* file name to use */
char server_name[80];  /* name that server reports */
int port = 80;         /* port to use */

int doclen = 0;        /* the length the document should be */
int totalread = 0;     /* total number of bytes read */
int totalbread = 0;    /* totoal amount of entity body read */
int done=0;            /* number of requests we have done */
int doneka=0;          /* number of keep alive connections done */
int good=0, bad=0;     /* number of good and bad requests */

/* store error cases */
int err_length = 0, err_conn = 0, err_except = 0;

struct timeval start, endtime;

/* global request (and its length) */
char request[512];
int reqlen;

/* one global throw-away buffer to read stuff into */
char buffer[4096];

struct connection *con;      /* connection array */
struct data *stats;          /* date for each request */

fd_set readbits, writebits;  /* bits for select */
struct sockaddr_in server;   /* server addr structure */

/* --------------------------------------------------------- */

/* simple little function to perror and exit */

static void err(char *s)
{
  perror(s);
  exit(errno);
}

/* --------------------------------------------------------- */

/* write out request to a connection - assumes we can write
   (small) request out in one go into our new socket buffer  */

void write_request(struct connection *c)
{
  gettimeofday(&c->connect,0);
  write(c->fd,request, reqlen);
  c->state = STATE_READ;
  FD_SET(c->fd, &readbits);
  FD_CLR(c->fd, &writebits);
}

/* --------------------------------------------------------- */

/* make an fd non blocking */

void nonblock(int fd)
{
  int i=1;
  ioctl(fd, FIONBIO, &i);
}

/* --------------------------------------------------------- */

/* returns the time in ms between two timevals */

int timedif(struct timeval a, struct timeval b)
{
  register int us,s;

  us = a.tv_usec - b.tv_usec;
  us /= 1000;
  s = a.tv_sec - b.tv_sec;
  s *= 1000;
  return s+us;
}

/* --------------------------------------------------------- */

/* calculate and output results and exit */

void output_results()
{
  int timetaken;

  gettimeofday(&endtime,0);
  timetaken = timedif(endtime, start);

  printf("\n---\n");
  printf("Server:                 %s\n", server_name);
  printf("Document Length:        %d\n", doclen);
  printf("Concurency Level:       %d\n", concurrency);
  printf("Time taken for tests:   %d.%03d seconds\n",
         timetaken/1000, timetaken%1000);
  printf("Complete requests:      %d\n", done);
  printf("Failed requests:        %d\n", bad);
  if(bad) printf("   (Connect: %d, Length: %d, Exceptions: %d)\n",
                 err_conn, err_length, err_except);
  if(keepalive) printf("Keep-Alive requests:    %d\n", doneka);
  printf("Bytes transferred:      %d\n", totalread);
  printf("HTML transferred:       %d\n", totalbread);

  /* avoid divide by zero */
  if(timetaken) {
    printf("Requests per seconds:   %.2f\n", 1000*(float)(done)/timetaken);
    printf("Transfer rate:          %.2f kb/s\n",
           (float)(totalread)/timetaken);
  }

  {
    /* work out connection times */
    int i;
    int totalcon=0, total=0;
    int mincon=9999999, mintot=999999;
    int maxcon=0, maxtot=0;

    for(i=0; i<requests; i++) {
      struct data s = stats[i];
      mincon = min(mincon, s.ctime);
      mintot = min(mintot, s.time);
      maxcon = max(maxcon, s.ctime);
      maxtot = max(maxtot, s.time);
      totalcon += s.ctime;
      total += s.time;
    }
    printf("\nConnnection Times (ms)\n");
    printf("           min   avg   max\n");
    printf("Connect: %5d %5d %5d\n",mincon, totalcon/requests, maxcon );
    printf("Total:   %5d %5d %5d\n", mintot, total/requests, maxtot);
    printf("---\n\n");
  }

  exit(0);
}

/* --------------------------------------------------------- */

/* start asnchronous non-blocking connection */

void start_connect(struct connection *c)
{
  c->read = 0;
  c->bread = 0;
  c->keepalive = 0;
  c->cbx = 0;
  c->gotheader = 0;

  c->fd = socket(AF_INET, SOCK_STREAM, 0);
  if(c->fd<0) err("socket");

  nonblock(c->fd);
  gettimeofday(&c->start,0);

  if(connect(c->fd, (struct sockaddr *) &server, sizeof(server))<0) {
    if(errno==EINPROGRESS) {
      c->state = STATE_CONNECTING;
      FD_SET(c->fd, &writebits);
      return;
    }
    else {
      close(c->fd);
      err_conn++;
      if(bad++>10) {
        printf("\nTest aborted after 10 failures\n\n");
        exit(1);
      }
      start_connect(c);
    }
  }

  /* connected first time */
  write_request(c);
}

/* --------------------------------------------------------- */

/* close down connection and save stats */

void close_connection(struct connection *c)
{
  if(c->read == 0 && c->keepalive) {
    /* server has legitiamately shut down an idle keep alive request */
    good--;  /* connection never happend */
  }
  else {
    if(good==1) {
      /* first time here */
      doclen = c->bread;
    } else if (c->bread!=doclen) {
      bad++;
      err_length++;
    }

    /* save out time */
    if(done < requests) {
      struct data s;
      gettimeofday(&c->done,0);
      s.read = c->read;
      s.ctime = timedif(c->connect, c->start);
      s.time = timedif(c->done, c->start);
      stats[done++] = s;
    }
  }

  close(c->fd);
  FD_CLR(c->fd, &readbits);
  FD_CLR(c->fd, &writebits);

  /* connect again */
  start_connect(c);
  return;
}

/* --------------------------------------------------------- */

/* read data from connection */

void read_connection(struct connection *c)
{
  int r;

  r=read(c->fd,buffer,sizeof(buffer));
  if(r==0 || (r<0 && errno!=EAGAIN)) {
    good++;
    close_connection(c);
    return;
  }

  if(r<0 && errno==EAGAIN) return;

  c->read += r;
  totalread += r;

  if(!c->gotheader) {
    char *s;
    int l=4;
    int space = CBUFFSIZE - c->cbx - 1; /* -1 to allow for 0 terminator */
    int tocopy = (space<r)?space:r;
    memcpy(c->cbuff+c->cbx, buffer, space);
    c->cbx += tocopy; space -= tocopy;
    c->cbuff[c->cbx] = 0; /* terminate for benefit of strstr */
    s = strstr(c->cbuff, "\r\n\r\n");
    /* this next line is so that we talk to NCSA 1.5 which blatantly breaks
       the http specifaction */
    if(!s) { s = strstr(c->cbuff,"\n\n"); l=2; }

    if(!s) {
       /* read rest next time */
      if(space)
        return;
      else {
        /* header is in invalid or too big - close connection */
        close(c->fd);
        if(bad++>10) {
          printf("\nTest aborted after 10 failures\n\n");
          exit(1);
        }
        FD_CLR(c->fd, &writebits);
        start_connect(c);
      }
    }
    else {
      /* have full header */
      if(!good) {
        /* this is first time, extract some interesting info */
        char *p, *q;
        p = strstr(c->cbuff, "Server:");
        q = server_name;
        if(p) { p+=8; while(*p>32) *q++ = *p++; }
        *q = 0;
      }

      c->gotheader = 1;
      *s = 0; /* terminate at end of header */
      if(keepalive &&
         (strstr(c->cbuff, "Keep-Alive")
          || strstr(c->cbuff, "keep-alive")))  /* for benefit of MSIIS */
        {
        char *cl;
        cl = strstr(c->cbuff, "Content-Length:");
        /* for cacky servers like NCSA which break the spec and send a
           lower case 'l' */
        if(!cl) cl = strstr(c->cbuff, "Content-length:");
        if(cl) {
          c->keepalive=1;
          c->length = atoi(cl+16);
        }
      }
      c->bread += c->cbx - (s+l-c->cbuff) + r-tocopy;
      totalbread += c->bread;
    }
  }
  else {
    /* outside header, everything we have read is entity body */
    c->bread += r;
    totalbread += r;
  }

  if(c->keepalive && (c->bread >= c->length)) {
    /* finished a keep-alive connection */
    good++; doneka++;
    /* save out time */
    if(good==1) {
      /* first time here */
      doclen = c->bread;
    } else if(c->bread!=doclen) { bad++; err_length++; }
    if(done < requests) {
      struct data s;
      gettimeofday(&c->done,0);
      s.read = c->read;
      s.ctime = timedif(c->connect, c->start);
      s.time = timedif(c->done, c->start);
      stats[done++] = s;
    }
    c->keepalive = 0; c->length = 0; c->gotheader=0; c->cbx = 0;
    c->read = c->bread = 0;
    write_request(c);
    c->start = c->connect; /* zero connect time with keep-alive */
  }
}

/* --------------------------------------------------------- */

/* run the tests */

int test()
{
  struct timeval timeout, now;
  fd_set sel_read, sel_except, sel_write;
  int i;

  {
    /* get server information */
    struct hostent *he;
    he = gethostbyname(machine);
    if (!he) err("gethostbyname");
    server.sin_family      = he->h_addrtype;
    server.sin_port        = htons(port);
    server.sin_addr.s_addr = ((unsigned long *)(he->h_addr_list[0]))[0];
  }

  con = malloc(concurrency*sizeof(struct connection));
  memset(con,0,concurrency*sizeof(struct connection));

  stats = malloc(requests * sizeof(struct data));

  FD_ZERO(&readbits);
  FD_ZERO(&writebits);

  /* setup request */
  sprintf(request,"GET %s HTTP/1.0\r\nUser-Agent: ZeusBench/1.0\r\n"
          "%sHost: %s\r\nAccept: */*\r\n\r\n", file,
          keepalive?"Connection: Keep-Alive\r\n":"", machine );

  reqlen = strlen(request);

  /* ok - lets start */
  gettimeofday(&start,0);

  /* initialise lots of requests */
  for(i=0; i<concurrency; i++) start_connect(&con[i]);

  while(done<requests) {
    int n;
    /* setup bit arrays */
    memcpy(&sel_except, &readbits, sizeof(readbits));
    memcpy(&sel_read, &readbits, sizeof(readbits));
    memcpy(&sel_write, &writebits, sizeof(readbits));

    /* check for time limit expiry */
    gettimeofday(&now,0);
    if(tlimit && timedif(now,start) > (tlimit*1000)) {
      requests=done;   /* so stats are correct */
      output_results();
    }

    /* Timeout of 30 seconds. */
    timeout.tv_sec=30; timeout.tv_usec=0;
    n=select(256, &sel_read, &sel_write, &sel_except, &timeout);
    if(!n) {
      printf("\nServer timed out\n\n");
      exit(1);
    }
    if(n<1) err("select");

    for(i=0; i<concurrency; i++) {
      int s = con[i].fd;
      if(FD_ISSET(s, &sel_except)) {
        bad++;
        err_except++;
        start_connect(&con[i]);
        continue;
      }
      if(FD_ISSET(s, &sel_read)) read_connection(&con[i]);
      if(FD_ISSET(s, &sel_write)) write_request(&con[i]);
    }
    if(done>=requests) output_results();
  }
  return 0;
}

/* ------------------------------------------------------- */

/* display usage information */

void usage(char *progname) {
  printf("\nZeusBench v1.0\n\n");
  printf("Usage: %s <machine> <file> [-k] [-n requests | -t timelimit (sec)]"
         "\n\t\t[-c concurrency] [-p port] \n",progname);
  printf("Filename should start with a '/' e.g. /index.html\n\n");
  exit(EINVAL);
}

/* ------------------------------------------------------- */

/* sort out command-line args and call test */

int main(int argc, char **argv) {
  int c;
  if (argc < 3) usage(argv[0]);

  machine = argv[1];
  file = argv[2];
  optind = 3;
  while ((c = getopt(argc,argv,"p:n:c:d:t:d:k"))>0) {
    switch(c) {
    case 'd':
      break;
    case 'n':
      requests = atoi(optarg);
      if(!requests) {
        printf("Invalid number of requests\n");
        exit(1);
      }
      break;
    case 'k':
      keepalive=1;
      break;
    case 'c':
      concurrency = atoi(optarg);
      break;
    case 'p':
      port = atoi(optarg);
      break;
    case 't':
      tlimit = atoi(optarg);
      requests = MAX_REQUESTS;  /* need to size data array on something */
      break;
    default:
      usage(argv[0]);
      break;
    }
  }
  test();
  return 0;
}






