/*
 * htdigest.c: simple program for manipulating digest passwd file for Apache
 *
 * by Alexei Kosut, based on htpasswd.c, by Rob McCool
 */

#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <sys/signal.h>
#include <stdlib.h>
#include <time.h>

/* This is probably the easiest way to do it */
#include "../src/md5c.c"

#define LF 10
#define CR 13

#define MAX_STRING_LEN 256

char *tn;

char *strd(char *s) {
    char *d;

    d=(char *)malloc(strlen(s) + 1);
    strcpy(d,s);
    return(d);
}

void getword(char *word, char *line, char stop) {
    int x = 0,y;

    for(x=0;((line[x]) && (line[x] != stop));x++)
        word[x] = line[x];

    word[x] = '\0';
    if(line[x]) ++x;
    y=0;

    while((line[y++] = line[x++]));
}

int getline(char *s, int n, FILE *f) {
    register int i=0;

    while(1) {
        s[i] = (char)fgetc(f);

        if(s[i] == CR)
            s[i] = fgetc(f);

        if((s[i] == 0x4) || (s[i] == LF) || (i == (n-1))) {
            s[i] = '\0';
            return (feof(f) ? 1 : 0);
        }
        ++i;
    }
}

void putline(FILE *f,char *l) {
    int x;

    for(x=0;l[x];x++) fputc(l[x],f);
    fputc('\n',f);
}


void add_password(char *user, char *realm, FILE *f) {
    char *pw, *cpw;
    MD5_CTX context;
    unsigned char digest[16];
    char string[MAX_STRING_LEN];
    unsigned int i;

    pw = strd((char *) getpass("New password:"));
    if(strcmp(pw,(char *) getpass("Re-type new password:"))) {
        fprintf(stderr,"They don't match, sorry.\n");
        if(tn)
            unlink(tn);
        exit(1);
    }
    fprintf(f,"%s:%s:",user,realm);

    /* Do MD5 stuff */
    sprintf(string, "%s:%s:%s", user, realm, pw);

    MD5Init (&context);
    MD5Update (&context, string, strlen(string));
    MD5Final (digest, &context);

    for (i = 0; i < 16; i++)
        fprintf(f, "%02x", digest[i]);

    fprintf(f, "\n");
}

void usage() {
    fprintf(stderr,"Usage: htdigest [-c] passwordfile realm username\n");
    fprintf(stderr,"The -c flag creates a new file.\n");
    exit(1);
}

void interrupted() {
    fprintf(stderr,"Interrupted.\n");
    if(tn) unlink(tn);
    exit(1);
}

void main(int argc, char *argv[]) {
    FILE *tfp,*f;
    char user[MAX_STRING_LEN];
    char realm[MAX_STRING_LEN];
    char line[MAX_STRING_LEN];
    char l[MAX_STRING_LEN];
    char w[MAX_STRING_LEN];
    char x[MAX_STRING_LEN];
    char command[MAX_STRING_LEN];
    int found;

    tn = NULL;
    signal(SIGINT,(void (*)())interrupted);
    if(argc == 5) {
        if(strcmp(argv[1],"-c"))
            usage();
        if(!(tfp = fopen(argv[2],"w"))) {
            fprintf(stderr,"Could not open passwd file %s for writing.\n",
                    argv[2]);
            perror("fopen");
            exit(1);
        }
        printf("Adding password for %s in realm %s.\n",argv[4], argv[3]);
        add_password(argv[4],argv[3],tfp);
        fclose(tfp);
        exit(0);
    } else if(argc != 4) usage();

    tn = tmpnam(NULL);
    if(!(tfp = fopen(tn,"w"))) {
        fprintf(stderr,"Could not open temp file.\n");
        exit(1);
    }

    if(!(f = fopen(argv[1],"r"))) {
        fprintf(stderr,
                "Could not open passwd file %s for reading.\n",argv[1]);
        fprintf(stderr,"Use -c option to create new one.\n");
        exit(1);
    }
    strcpy(user,argv[3]);
    strcpy(realm,argv[2]);

    found = 0;
    while(!(getline(line,MAX_STRING_LEN,f))) {
        if(found || (line[0] == '#') || (!line[0])) {
            putline(tfp,line);
            continue;
        }
        strcpy(l,line);
        getword(w,l,':');
	getword(x,l,':');
        if(strcmp(user,w) || strcmp(realm,x)) {
            putline(tfp,line);
            continue;
        }
        else {
            printf("Changing password for user %s in realm %s\n",user,realm);
            add_password(user,realm,tfp);
            found = 1;
        }
    }
    if(!found) {
        printf("Adding user %s in realm %s\n",user,realm);
        add_password(user,realm,tfp);
    }
    fclose(f);
    fclose(tfp);
    sprintf(command,"cp %s %s",tn,argv[1]);
    system(command);
    unlink(tn);
}
