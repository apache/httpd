/*
** Original code by Rob McCool, robm@ncsa.uiuc.edu.
** 
** 06/28/95: Carlos Varela, cvarela@isr.co.jp
** 1.1 : Additional error message if password file not changed.
**       By default allows password addition, better feedback to "wizard".
**
*/

#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <sys/signal.h>
#include <stdlib.h>
#include <time.h>

#define USER_FILE "/usr/local/etc/httpd/conf/.htpasswd"
#define WIZARD "webmaster"

char *makeword(char *line, char stop);
char *fmakeword(FILE *f, char stop, int *len);
char x2c(char *what);
void unescape_url(char *url);
void plustospace(char *str);

char *crypt(char *pw, char *salt); /* why aren't these prototyped in include */


char *tn;

/* From local_passwd.c (C) Regents of Univ. of California blah blah */
static unsigned char itoa64[] =         /* 0 ... 63 => ascii - 64 */
        "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

to64(s, v, n)
  register char *s;
  register long v;
  register int n;
{
    while (--n >= 0) {
        *s++ = itoa64[v&0x3f];
        v >>= 6;
    }
}

void change_password(char *user, char *pw, FILE *f) {
    char *cpw, salt[3];

    (void)srand((int)time((time_t *)NULL));
    to64(&salt[0],rand(),2);
    cpw = crypt(pw,salt);
    free(pw);
    fprintf(f,"%s:%s\n",user,cpw);
}

void putline(FILE *f,char *l) {
    int x;

    for(x=0;l[x];x++) fputc(l[x],f);
    fputc('\n',f);
}

main(int argc, char *argv[]) {
    register int x;
    int cl,found,create;
    char *u,*t1,*t2,*p1,*p2,*user, command[256], line[256], l[256], w[256];
    FILE *tfp,*f;

    tn = NULL;

    printf("Content-type: text/html%c%c",10,10);

    if(strcmp(getenv("REQUEST_METHOD"),"POST")) {
        printf("This script should be referenced with a METHOD of POST.\n");
        printf("If you don't understand this, see this ");
        printf("<A HREF=\"http://www.ncsa.uiuc.edu/SDG/Software/Mosaic/Docs/fill-out-forms/overview.html\">forms overview</A>.%c",10);
        exit(1);
    }
    if(strcmp(getenv("CONTENT_TYPE"),"application/x-www-form-urlencoded")) {
        printf("This script can only be used to decode form results. \n");
        exit(1);
    }
    cl = atoi(getenv("CONTENT_LENGTH"));

    user=NULL;
    p1=NULL;
    p2=NULL;
    create=1;
    for(x=0;cl && (!feof(stdin));x++) {
        t1 = fmakeword(stdin,'&',&cl);
        t2 = makeword(t1,'=');
        unescape_url(t1);
        unescape_url(t2);
        if(!strcmp(t2,"user")) {
            if(!user)
                user = t1;
            else {
                printf("This script was accessed from the wrong form.\n");
                exit(1);
            }
        }
        else if(!strcmp(t2,"newpasswd1")) {
            if(!p1)
                p1 = t1;
            else {
                printf("This script was accessed from the wrong form.\n");
                exit(1);
            }
        }
        else if(!strcmp(t2,"newpasswd2")) {
            if(!p2)
                p2 = t1;
            else {
                printf("This script was accessed from the wrong form.\n");
                exit(1);
            }
        }
        else {
            printf("This script was accessed from the wrong form.\n");
            printf("Unrecognized directive %s.\n",t2);
            exit(1);
        }
        free(t2);
    }
    u=getenv("REMOTE_USER");
    if((strcmp(u,WIZARD)) && (strcmp(user,u))) {
            printf("<TITLE>User Mismatch</TITLE>");
            printf("<H1>User Mismatch</H1>");
            printf("The username you gave does not correspond with the ");
            printf("user you authenticated as.\n");
            exit(1);
        }
    if(strcmp(p1,p2)) {
        printf("<TITLE>Password Mismatch</TITLE>");
        printf("<H1>Password Mismatch</H1>");
        printf("The two copies of your password do not match. Please");
        printf(" try again.");
        exit(1);
    }

    tn = tmpnam(NULL);
    if(!(tfp = fopen(tn,"w"))) {
        fprintf(stderr,"Could not open temp file.\n");
        exit(1);
    }

    if(!(f = fopen(USER_FILE,"r"))) {
        fprintf(stderr,
                "Could not open passwd file for reading.\n",USER_FILE);
        exit(1);
    }

    found = 0;
    while(!(getline(line,256,f))) {
        if(found || (line[0] == '#') || (!line[0])) {
            putline(tfp,line);
            continue;
        }
        strcpy(l,line);
        getword(w,l,':');
        if(strcmp(user,w)) {
            putline(tfp,line);
            continue;
        }
        else {
            change_password(user,p1,tfp);
            found=1;
        }
    }
    if((!found) && (create))
        change_password(user,p1,tfp);
    fclose(f);
    fclose(tfp);
    sprintf(command,"cp %s %s",tn,USER_FILE);
    if (system(command)) {
	fprintf(stderr,
		"Could not overwrite passwd file.\n",USER_FILE);
	exit(1);
    }
    unlink(tn);
    if ((!found) && (create)) {
	printf("<TITLE>Successful Addition</TITLE>");
	printf("<H1>Successful Addition</H1>");
	printf("Your new user/password combination has been successfully added.<P>");
    } else {
	printf("<TITLE>Successful Change</TITLE>");
	printf("<H1>Successful Change</H1>");
	printf("Your password has been successfully changed.<P>");
    }
    exit(0);
}
