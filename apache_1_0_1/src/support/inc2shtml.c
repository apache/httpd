/*
 * inc2shtml: Convert httpd <1.1 style includes to 1.2 style
 * 
 * Rob McCool
 * 
 * Usage: inc2shtml [filename]
 * 
 * If filename is given, this program will open filename. If not, it will 
 * look on stdin. It will output the new shtml file on stdout.
 */


#include <stdio.h>
#ifdef sony_mips_bsd
#include <ctype.h>
#endif

#define MAX_STRING_LEN 256

void usage(char *argv0) {
    fprintf(stderr,"Usage: %s [filename]\n",argv0);
    fprintf(stderr,"If filename is given, this program will open filename.\n");
    fprintf(stderr,"If not, it will look on stdin for the inc file.\n");
    fprintf(stderr,
            "In either case, it will write the new shtml file on stdout.\n");
    exit(1);
}

void translate_tag(char *tag, FILE *fd) {
    char *tp = tag, *tp2;
    int url;

    url = (*tp == 'U' || *tp == 'u' ? 1 : 0);
        
    while(*tp++ != '\"');
    tp2 = tp + 1;
    while(*tp2 != '\"') ++tp2;
    *tp2 = '\0';
    if(*tp == '|') {
        fprintf(fd,"<!--#exec cmd=\"%s",++tp);
        if(url) fputs(" '$QUERY_STRING_UNESCAPED'",fd);
        fputs("\"-->",fd);
    } else
        fprintf(fd,"<!--#include virtual=\"%s\"-->",tp);
}

main(int argc, char *argv[]) {
    FILE *f;
    int c,x,p;
    char c2;
    char *lookfor = "<inc srv";

    switch(argc) {
      case 1:
        f = stdin;
        break;
      case 2:
        if(!(f = fopen(argv[1],"r"))) {
            perror("fopen");
            exit(1);
        }
        break;
      default:
        usage(argv[0]);
    }

    p=0;
    while(1) {
        c = fgetc(f);
        if(c == -1) {
            fflush(stdout);
            exit(0);
        }
        c2 = (char)c;
        if(isalpha((char)c))
            c = tolower((char)c);
        if(c == lookfor[p]) {
            if(!lookfor[++p]) {
                char tag[MAX_STRING_LEN];

                x=0;
                c = fgetc(f); /* get space */
                while(c != '>') {
                    tag[x++] = c;
                    c = fgetc(f);
                    if(c == -1) {
                        fputs("<inc srv ",stdout);
                        fputs(tag,stdout);
                        fflush(stdout);
                        exit(1);
                    }
                }
                tag[x] = '\0';
                translate_tag(tag,stdout);
                p = 0;
            }
        } 
        else {
            for(x=0;x<p;x++)
                fputc(lookfor[x],stdout);
            fputc(c2,stdout);
            p=0;
        }
    }
}
