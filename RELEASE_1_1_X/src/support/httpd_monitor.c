/*
 * ====================================================================
 * Copyright (c) 1995 The Apache Group.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Group" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * 5. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
 * IT'S CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Group and was originally based
 * on public domain software written at the National Center for
 * Supercomputing Applications, University of Illinois, Urbana-Champaign.
 * For more information on the Apache Group and the Apache HTTP server
 * project, please see <http://www.apache.org/>.


 * simple script to monitor the child Apache processes
 *   Usage:
 *      httpd_monitor -p pid_file -s sleep_time
 *                Will give you an update ever sleep_time seconds
 *                 using pid_file as the location of the PID file.
 *                If you choose 0, it might chew up lots of CPU time.
 *
 * Output explanation..
 *
 *  s = sleeping but "ready to go" child
 *  R = active child
 *  _ = dead child (no longer needed)
 *  t = just starting
 *
 *
 *  Jim Jagielski <jim@jaguNET.com>
 *   v1.0 Notes:
 *    This code is much more ugly and complicated than it
 *    needs to be.
 *
 *   v1.1:
 *    Minor fixes
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "scoreboard.h"
#include "httpd.h"

#define PIDFILE_OPT		"PidFile"
#define	SCORE_OPT		"ScoreBoardFile"
#define DEFAULT_SLEEPTIME	2
#define ASIZE			1024
#define MAX_PROC		40

int
main(argc, argv)
int argc;
char **argv;
{
    short_score scoreboard_image;
    FILE *afile;
    char conf_name[ASIZE];
    char pid_name[ASIZE];
    char score_name[ASIZE];
    char tbuf[ASIZE];
    char *ptmp;
    static char kid_stat[] = { '_', 's', 'R', 't' };
    char achar;
    long thepid;
    int score_fd;
    int sleep_time = DEFAULT_SLEEPTIME;
    int last_len = 0;
    int kiddies;
    int running, dead, total, loop;
    short got_config = 0;
    struct stat statbuf;
    time_t last_time = 0;
    extern char *optarg;
    extern int optind, opterr;
    void lookfor();

    int usage();

    /*
     * Handle the options. Using getopt() is most probably overkill,
     * but let's think about the future!
     */
    strcpy(conf_name, HTTPD_ROOT);
    while((achar = getopt(argc,argv,"s:d:f:")) != -1) {
	switch(achar) {
	  case 'd':
	    strcpy(conf_name, optarg);
	    break;
	  case 'f':
	    strcpy(conf_name, optarg);
	    got_config = 1;
	    break;
	  case 's':
	    sleep_time = atoi(optarg);
	    break;
	  case '?':
	    usage(argv[0]);
	}
    }

    /*
     * Now build the name of the httpd.conf file
     */
     if (!got_config) {
	 strcat(conf_name, "/");
	 strcat(conf_name, SERVER_CONFIG_FILE);
    }

    /*
     * Make sure we have the right file... Barf if not
     */
    if (!(afile = fopen(conf_name, "r"))) {
	perror("httpd_monitor");
	fprintf(stderr, "Can't open config file: %s\n", conf_name);
	exit(1);
    }
    /*
     * now scan thru the ConfigFile to look for the items that
     * interest us
     */
    lookfor(pid_name, score_name, afile);
    fclose(afile);

    /*
     * now open the PidFile and then the ScoreBoardFile
     */
    if (!(afile = fopen(pid_name, "r"))) {
	perror("httpd_monitor");
	fprintf(stderr, "Can't open PIDfile: %s\n", pid_name);
	exit(1);
    }
    fscanf(afile, "%ld", &thepid);
    fclose(afile);

    /*
     * Enough taters, time for the MEAT!
     */
    for(;;sleep(sleep_time)) {
	if (stat(score_name, &statbuf)) {
	    perror("httpd_monitor");
	    fprintf(stderr, "Can't stat scoreboard file: %s\n", score_name);
	    exit(1);
	}
	if (last_time == statbuf.st_mtime)
	    continue;	/* tricky ;) */
	last_time = statbuf.st_mtime;	/* for next time */
	if ((score_fd = open(score_name, 0)) == -1 ) {
	    perror("httpd_monitor");
	    fprintf(stderr, "Can't open scoreboard file: %s\n", score_name);
	    exit(1);
	}
	/*
	 * all that for _this_
	 */
	running = dead = total = 0;
	ptmp = tbuf;
	*ptmp = '\0';
	for(kiddies=0;kiddies<MAX_PROC; kiddies++) {
	    read(score_fd, (char *)&scoreboard_image, sizeof(short_score));
	    achar = kid_stat[(int)scoreboard_image.status];
	    if (scoreboard_image.pid != 0 && scoreboard_image.pid != thepid) {
		total++;
		if (achar == 'R')
		    running++;
		*ptmp = achar;
		*++ptmp = '\0';
	    }
	}
	close(score_fd);
	sprintf(ptmp, " (%d/%d)", running, total);
	for(loop=1;loop<=last_len;loop++)
	    putchar('\010');
	if (last_len > strlen(tbuf)) {
	    for(loop=1;loop<=last_len;loop++)
		putchar(' ');
	    for(loop=1;loop<=last_len;loop++)
		putchar('\010');
	}
	printf("%s", tbuf);
	fflush(stdout);
	last_len = strlen(tbuf);
    }	/* for */
}

int
usage(arg)
char *arg;
{
    printf("httpd_monitor: Usage\n");
    printf("  httpd_monitor [ -d config-dir] [ -s sleep-time ]\n");
    printf("    Defaults: config-dir = %s\n", HTTPD_ROOT);
    printf("              sleep-time = %d seconds\n", DEFAULT_SLEEPTIME);
    exit(0);
}

/*
 * This function uses some hard-wired knowledge about the
 * Apache httpd.conf file setup (basically names of the 3
 * parameters we are interested in)
 *
 * We basically scan thru the file and grab the 3 values we
 * need. This could be done better...
 */
void
lookfor(pidname, scorename, thefile)
char *pidname, *scorename;
FILE *thefile;
{
    char line[ASIZE], param[ASIZE], value[ASIZE];
    char sroot[ASIZE], pidfile[ASIZE], scorefile[ASIZE];

    *sroot = *pidfile  = *scorefile = '\0';
    while (!(feof(thefile))) {
	fgets(line, ASIZE-1, thefile);
	*value = '\0';	/* protect braindead sscanf() */
	sscanf(line, "%s %s", param, value);
	if (strcmp(param, "PidFile")==0 && *value)
	    strcpy(pidfile, value);
	if (strcmp(param, "ScoreBoardFile")==0 && *value)
	    strcpy(scorefile, value);
	if (strcmp(param, "ServerRoot")==0 && *value)
	    strcpy(sroot, value);
    }

    /*
     * We've reached EOF... we should have encountered the
     * ServerRoot line... if not, we bail out
     */
    if (!*sroot) {
	perror("httpd_monitor");
	fprintf(stderr, "Can't find ServerRoot!\n");
	exit(1);
    }

    /*
     * Not finding PidFile or ScoreBoardFile is OK, since
     * we have defaults for them
     */
    if (!*pidfile)
	strcpy(pidfile, DEFAULT_PIDLOG);
    if (!*scorefile)
	strcpy(scorefile, DEFAULT_SCOREBOARD);

    /*
     * Relative or absolute? Handle both
     */
    if (*pidfile == '/')
	strcpy(pidname, pidfile);
    else {
	strcpy(pidname, sroot);
	strcat(pidname, "/");
	strcat(pidname, pidfile);
    }
    if (*scorefile == '/')
	strcpy(scorename, scorefile);
    else {
	strcpy(scorename, sroot);
	strcat(scorename, "/");
	strcat(scorename, scorefile);
    }
}

