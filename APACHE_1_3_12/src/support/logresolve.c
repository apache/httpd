/*
 * logresolve 1.1
 *
 * Tom Rathborne - tomr@aceldama.com - http://www.aceldama.com/~tomr/
 * UUNET Canada, April 16, 1995
 *
 * Rewritten by David Robinson. (drtr@ast.cam.ac.uk)
 *
 * Usage: logresolve [-s filename] [-c] < access_log > new_log
 *
 * Arguments:
 *    -s filename     name of a file to record statistics
 *    -c              check the DNS for a matching A record for the host.
 *
 * Notes:
 *
 * To generate meaningful statistics from an HTTPD log file, it's good
 * to have the domain name of each machine that accessed your site, but
 * doing this on the fly can slow HTTPD down.
 *
 * Compiling NCSA HTTPD with the -DMINIMAL_DNS flag turns IP#->hostname
 * resolution off. Before running your stats program, just run your log
 * file through this program (logresolve) and all of your IP numbers will
 * be resolved into hostnames (where possible).
 *
 * logresolve takes an HTTPD access log (in the COMMON log file format,
 * or any other format that has the IP number/domain name as the first
 * field for that matter), and outputs the same file with all of the
 * domain names looked up. Where no domain name can be found, the IP
 * number is left in.
 *
 * To minimize impact on your nameserver, logresolve has its very own
 * internal hash-table cache. This means that each IP number will only
 * be looked up the first time it is found in the log file.
 *
 * The -c option causes logresolve to apply the same check as httpd
 * compiled with -DMAXIMUM_DNS; after finding the hostname from the IP
 * address, it looks up the IP addresses for the hostname and checks
 * that one of these matches the original address.
 */

#include "ap_config.h"
#include <sys/types.h>

#include <ctype.h>

#ifndef MPE
#ifndef BEOS
#include <arpa/inet.h>
#else
/* BeOS lacks the necessary files until we get the new networking */
#include <netinet/in.h>
#define NO_ADDRESS 4
#endif /* BEOS */
#endif /* MPE */

static void cgethost(struct in_addr ipnum, char *string, int check);
static int getline(char *s, int n);
static void stats(FILE *output);


/* maximum line length */
#define MAXLINE 1024

/* maximum length of a domain name */
#ifndef MAXDNAME
#define MAXDNAME 256
#endif

/* number of buckets in cache hash table */
#define BUCKETS 256

#if defined(NEED_STRDUP)
char *strdup (const char *str)
{
    char *dup;

    if (!(dup = (char *) malloc(strlen(str) + 1)))
	return NULL;
    dup = strcpy(dup, str);

    return dup;
}
#endif

/*
 * struct nsrec - record of nameservice for cache linked list
 * 
 * ipnum - IP number hostname - hostname noname - nonzero if IP number has no
 * hostname, i.e. hostname=IP number
 */

struct nsrec {
    struct in_addr ipnum;
    char *hostname;
    int noname;
    struct nsrec *next;
}    *nscache[BUCKETS];

/*
 * statistics - obvious
 */

#ifndef h_errno
extern int h_errno; /* some machines don't have this in their headers */
#endif

/* largeste value for h_errno */
#define MAX_ERR (NO_ADDRESS)
#define UNKNOWN_ERR (MAX_ERR+1)
#define NO_REVERSE  (MAX_ERR+2)

static int cachehits = 0;
static int cachesize = 0;
static int entries = 0;
static int resolves = 0;
static int withname = 0;
static int errors[MAX_ERR + 3];

/*
 * cgethost - gets hostname by IP address, caching, and adding unresolvable
 * IP numbers with their IP number as hostname, setting noname flag
 */

static void cgethost (struct in_addr ipnum, char *string, int check)
{
    struct nsrec **current, *new;
    struct hostent *hostdata;
    char *name;

    current = &nscache[((ipnum.s_addr + (ipnum.s_addr >> 8) +
			 (ipnum.s_addr >> 16) + (ipnum.s_addr >> 24)) % BUCKETS)];

    while (*current != NULL && ipnum.s_addr != (*current)->ipnum.s_addr)
	current = &(*current)->next;

    if (*current == NULL) {
	cachesize++;
	new = (struct nsrec *) malloc(sizeof(struct nsrec));
	if (new == NULL) {
	    perror("malloc");
	    fprintf(stderr, "Insufficient memory\n");
	    exit(1);
	}
	*current = new;
	new->next = NULL;

	new->ipnum = ipnum;

	hostdata = gethostbyaddr((const char *) &ipnum, sizeof(struct in_addr),
				 AF_INET);
	if (hostdata == NULL) {
	    if (h_errno > MAX_ERR)
		errors[UNKNOWN_ERR]++;
	    else
		errors[h_errno]++;
	    new->noname = h_errno;
	    name = strdup(inet_ntoa(ipnum));
	}
	else {
	    new->noname = 0;
	    name = strdup(hostdata->h_name);
	    if (check) {
		if (name == NULL) {
		    perror("strdup");
		    fprintf(stderr, "Insufficient memory\n");
		    exit(1);
		}
		hostdata = gethostbyname(name);
		if (hostdata != NULL) {
		    char **hptr;

		    for (hptr = hostdata->h_addr_list; *hptr != NULL; hptr++)
			if (((struct in_addr *) (*hptr))->s_addr == ipnum.s_addr)
			    break;
		    if (*hptr == NULL)
			hostdata = NULL;
		}
		if (hostdata == NULL) {
		    fprintf(stderr, "Bad host: %s != %s\n", name,
			    inet_ntoa(ipnum));
		    new->noname = NO_REVERSE;
		    free(name);
		    name = strdup(inet_ntoa(ipnum));
		    errors[NO_REVERSE]++;
		}
	    }
	}
	new->hostname = name;
	if (new->hostname == NULL) {
	    perror("strdup");
	    fprintf(stderr, "Insufficient memory\n");
	    exit(1);
	}
    }
    else
	cachehits++;

    /* size of string == MAXDNAME +1 */
    strncpy(string, (*current)->hostname, MAXDNAME);
    string[MAXDNAME] = '\0';
}

/*
 * prints various statistics to output
 */

static void stats (FILE *output)
{
    int i;
    char *ipstring;
    struct nsrec *current;
    char *errstring[MAX_ERR + 3];

    for (i = 0; i < MAX_ERR + 3; i++)
	errstring[i] = "Unknown error";
    errstring[HOST_NOT_FOUND] = "Host not found";
    errstring[TRY_AGAIN] = "Try again";
    errstring[NO_RECOVERY] = "Non recoverable error";
    errstring[NO_DATA] = "No data record";
    errstring[NO_ADDRESS] = "No address";
    errstring[NO_REVERSE] = "No reverse entry";

    fprintf(output, "logresolve Statistics:\n");

    fprintf(output, "Entries: %d\n", entries);
    fprintf(output, "    With name   : %d\n", withname);
    fprintf(output, "    Resolves    : %d\n", resolves);
    if (errors[HOST_NOT_FOUND])
	fprintf(output, "    - Not found : %d\n", errors[HOST_NOT_FOUND]);
    if (errors[TRY_AGAIN])
	fprintf(output, "    - Try again : %d\n", errors[TRY_AGAIN]);
    if (errors[NO_DATA])
	fprintf(output, "    - No data   : %d\n", errors[NO_DATA]);
    if (errors[NO_ADDRESS])
	fprintf(output, "    - No address: %d\n", errors[NO_ADDRESS]);
    if (errors[NO_REVERSE])
	fprintf(output, "    - No reverse: %d\n", errors[NO_REVERSE]);
    fprintf(output, "Cache hits      : %d\n", cachehits);
    fprintf(output, "Cache size      : %d\n", cachesize);
    fprintf(output, "Cache buckets   :     IP number * hostname\n");

    for (i = 0; i < BUCKETS; i++)
	for (current = nscache[i]; current != NULL; current = current->next) {
	    ipstring = inet_ntoa(current->ipnum);
	    if (current->noname == 0)
		fprintf(output, "  %3d  %15s - %s\n", i, ipstring,
			current->hostname);
	    else {
		if (current->noname > MAX_ERR + 2)
		    fprintf(output, "  %3d  %15s : Unknown error\n", i,
			    ipstring);
		else
		    fprintf(output, "  %3d  %15s : %s\n", i, ipstring,
			    errstring[current->noname]);
	    }
	}
}


/*
 * gets a line from stdin
 */

static int getline (char *s, int n)
{
    char *cp;

    if (!fgets(s, n, stdin))
	return (0);
    cp = strchr(s, '\n');
    if (cp)
	*cp = '\0';
    return (1);
}

int main (int argc, char *argv[])
{
    struct in_addr ipnum;
    char *bar, hoststring[MAXDNAME + 1], line[MAXLINE], *statfile;
    int i, check;

    check = 0;
    statfile = NULL;
    for (i = 1; i < argc; i++) {
	if (strcmp(argv[i], "-c") == 0)
	    check = 1;
	else if (strcmp(argv[i], "-s") == 0) {
	    if (i == argc - 1) {
		fprintf(stderr, "logresolve: missing filename to -s\n");
		exit(1);
	    }
	    i++;
	    statfile = argv[i];
	}
	else {
	    fprintf(stderr, "Usage: logresolve [-s statfile] [-c] < input > output\n");
	    exit(0);
	}
    }


    for (i = 0; i < BUCKETS; i++)
	nscache[i] = NULL;
    for (i = 0; i < MAX_ERR + 2; i++)
	errors[i] = 0;

    while (getline(line, MAXLINE)) {
	if (line[0] == '\0')
	    continue;
	entries++;
	if (!isdigit(line[0])) {	/* short cut */
	    puts(line);
	    withname++;
	    continue;
	}
	bar = strchr(line, ' ');
	if (bar != NULL)
	    *bar = '\0';
	ipnum.s_addr = inet_addr(line);
	if (ipnum.s_addr == 0xffffffffu) {
	    if (bar != NULL)
		*bar = ' ';
	    puts(line);
	    withname++;
	    continue;
	}

	resolves++;

	cgethost(ipnum, hoststring, check);
	if (bar != NULL)
	    printf("%s %s\n", hoststring, bar + 1);
	else
	    puts(hoststring);
    }

    if (statfile != NULL) {
	FILE *fp;
	fp = fopen(statfile, "w");
	if (fp == NULL) {
	    fprintf(stderr, "logresolve: could not open statistics file '%s'\n"
		    ,statfile);
	    exit(1);
	}
	stats(fp);
	fclose(fp);
    }

    return (0);
}
