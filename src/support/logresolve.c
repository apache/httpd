/***                                                                      ***\

    logresolve 1.0

    Tom Rathborne - tomr@uunet.ca - http://www.uunet.ca/~tomr/
    UUNET Canada, April 16, 1995

    Usage: logresolve [arguments] < access_log > new_log

    Arguments: if you give any arguments, statistics are printed to STDERR.

    Notes:

    To generate meaningful statistics from an HTTPD log file, it's good
    to have the domain name of each machine that accessed your site, but
    doing this on the fly can slow HTTPD down.

    Compiling NCSA HTTPD with the -DMINIMAL_DNS flag turns IP#->hostname
    resolution off. Before running your stats program, just run your log
    file through this program (logresolve) and all of your IP numbers will
    be resolved into hostnames (where possible).

    logresolve takes an HTTPD access log (in the COMMON log file format,
    or any other format that has the IP number/domain name as the first
    field for that matter), and outputs the same file with all of the
    domain names looked up. Where no domain name can be found, the IP
    number is left in.

    To minimize impact on your nameserver, logresolve has its very own
    internal hash-table cache. This means that each IP number will only
    be looked up the first time it is found in the log file. As noted
    above, giving any command-line arguments to logresolve (anything at
    all!) will give you some statistics on the log file and the cache,
    printed to STDERR.

\***                                                                      ***/

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>

/* maximum line length */
#define MAXLINE 1024

/* maximum length of an IP number as a string */
#define IPSTRLEN 16

/* number of buckets in cache hash table */
#define BUCKETS 256

/*
 * struct nsrec - record of nameservice for cache linked list
 * 
 * ipnum - IP number hostname - hostname noname - nonzero if IP number has no
 * hostname, i.e. hostname=IP number
 */

struct nsrec {
	unsigned char   ipnum[4];
	char           *hostname;
	int             noname;
	struct nsrec   *next;
}              *nscache[BUCKETS];

/*
 * statistics - obvious
 */

int             cachehits = 0;
int             cachesize = 0;
int             entries = 0;
int             resolves = 0;
int             withname = 0;
int             yucky = 0;
int             noname = 0;

/*
 * ipsame - takes two IP numbers and returns TRUE if they're the same
 */

int
ipsame(ipnum1, ipnum2)
	unsigned char   ipnum1[4];
	unsigned char   ipnum2[4];
{
	return (ipnum1[0] == ipnum2[0]
		&& ipnum1[1] == ipnum2[1]
		&& ipnum1[2] == ipnum2[2]
		&& ipnum1[3] == ipnum2[3]);
}

/*
 * ipbuild - makes an IP number char array from 4 integers
 */

ipbuild(ipnum, a, b, c, d)
	unsigned char   ipnum[4];
	unsigned int    a, b, c, d;
{
	ipnum[0] = a;
	ipnum[1] = b;
	ipnum[2] = c;
	ipnum[3] = d;
}

/*
 * ipstr - converts an IP number to a string
 */

char           *
ipstr(string, ipnum)
	char           *string;
	unsigned char   ipnum[4];
{
	sprintf(string, "%d.%d.%d.%d", ipnum[0], ipnum[1], ipnum[2], ipnum[3]);
	return (string);
}

/*
 * cgethost - gets hostname by IP address, caching, and adding unresolvable
 * IP numbers with their IP number as hostname, setting noname flag
 */

cgethost(string, ipnum)
	char           *string;
	unsigned char   ipnum[4];
{
	struct nsrec   *current;
	struct hostent *hostdata;

	current = nscache[((ipnum[0] + ipnum[1] + ipnum[2] + ipnum[3]) % BUCKETS)];

	while (current->next && !ipsame(ipnum, current->next->ipnum))
		current = current->next;

	if (!current->next) {
		cachesize++;
		current->next = (struct nsrec *) malloc(sizeof(struct nsrec));
		current = current->next;
		current->next = 0;
		current->noname = 0;

		current->ipnum[0] = ipnum[0];
		current->ipnum[1] = ipnum[1];
		current->ipnum[2] = ipnum[2];
		current->ipnum[3] = ipnum[3];

		if (hostdata = gethostbyaddr((const char *) ipnum, 4, AF_INET)) {
			current->hostname = (char *) malloc(strlen(hostdata->h_name) + 1);
			strcpy(current->hostname, hostdata->h_name);
		} else {
			noname++;
			current->noname = 1;
			current->hostname = (char *) malloc(IPSTRLEN);
			ipstr(current->hostname, current->ipnum);
		}
	} else {
		current = current->next;
		cachehits++;
	}
	strcpy(string, current->hostname);
}

/*
 * gets a line from stdin
 */

int
getline(s, n)
	char           *s;
	int             n;
{
	char           *cp;

	if (!fgets(s, n, stdin))
		return (1);
	if (cp = strchr(s, '\n'))
		*cp = '\0';
	return (0);
}

/*
 * prints various statistics to output
 */

stats(output)
	FILE           *output;
{
	int             i, ipstring[IPSTRLEN];
	struct nsrec   *current;

	fprintf(output, "logresolve Statistics:\n");

	fprintf(output, "Entries: %d\n", entries);
	fprintf(output, "    With name : %d\n", withname);
	fprintf(output, "    Resolves  : %d\n", resolves);
	fprintf(output, "    - Yucky   : %d\n", yucky);
	fprintf(output, "    - No name : %d\n", noname);
	fprintf(output, "Cache hits    : %d\n", cachehits);
	fprintf(output, "Cache size    : %d\n", cachesize);
	fprintf(output, "Cache buckets :     IP number * hostname\n");

	for (i = 0; i < BUCKETS; i++) {
		current = nscache[i];
		while (current->next) {
			ipstr(ipstring, current->next->ipnum);
			if (current->next->noname)
				fprintf(output, "         %3d  %15s ! %s\n", i, ipstring, current->next->hostname);
			else
				fprintf(output, "         %3d  %15s - %s\n", i, ipstring, current->next->hostname);
			current = current->next;
		}
	}
}


int
main(argc, argv)
	int             argc;
	char           *argv[];
{
	unsigned char   ipnum[4];
	char           *foo, *bar, hoststring[MAXLINE], ipstring[IPSTRLEN], line[MAXLINE],
	                nl[MAXLINE];
	int             i, ip;

	for (i = 0; i < BUCKETS; i++) {
		nscache[i] = (struct nsrec *) malloc(sizeof(struct nsrec));
		nscache[i]->next = 0;
		nscache[i]->noname = 0;
	}

	while (!getline(line, MAXLINE) && *line) {
		entries++;
		if ((*line < '0') || (*line > '9')) {
			printf("%s\n", line);
			withname++;
		} else {
			resolves++;
			ip = 1;
			strcpy(nl, line);
			foo = nl;
			bar = nl;
			for (i = 0; (i < 4) && ip; i++) {
				while (*bar != '.' && *bar != ' ')
					bar++;
				*bar = 0;
				ipnum[i] = atoi(foo);
				foo = ++bar;
				if (((*bar < '0') || (*bar > '9')) && i < 3)
					ip = 0;
			}
			if (ip) {
				cgethost(hoststring, ipnum);
				printf("%s %s\n", hoststring, bar);
			} else {
				yucky++;
				printf("%s\n", line);
			}
		}
	}

	if (--argc)
		stats(stderr);

	return (0);
}
-- end


