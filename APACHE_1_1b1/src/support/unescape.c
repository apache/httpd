/*
 * Short program to unescape a URL string
 * 
 * Rob McCool
 * 
 */

#include <stdio.h>

void plustospace(char *str) {
    register int x;

    for(x=0;str[x];x++) if(str[x] == '+') str[x] = ' ';
}

char x2c(char *what) {
    register char digit;

    digit = ((what[0] >= 'A') ? ((what[0] & 0xdf) - 'A')+10 : (what[0] - '0'));
    digit *= 16;
    digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A')+10 : (what[1] - '0'));
    return(digit);
}

void unescape_url(char *url) {
    register int x,y;

    for(x=0;url[x];x++)
        if(url[x] == '%')
            url[x+1] = x2c(&url[x+1]);

    for(x=0,y=0;url[y];++x,++y) {
        if((url[x] = url[y]) == '%') {
            url[x] = url[y+1];
            y+=2;
	}
    }
    url[x] = '\0';
}

int ind(char *s, char c) {
    register int x;

    for(x=0;s[x];x++)
        if(s[x] == c) return x;

    return -1;
}

void escape_shell_cmd(char *cmd) {
    register int x,y,l;

    l=strlen(cmd);
    for(x=0;cmd[x];x++) {
        if(ind("&;`'|*?-~<>^()[]{}$\\",cmd[x]) != -1){
            for(y=l+1;y>x;y--)
                cmd[y] = cmd[y-1];
            l++; /* length has been increased */
            cmd[x] = '\\';
            x++; /* skip the character */
        }
    }
}

void usage(char *name) {
    fprintf(stderr,"Usage:\n%s [-e] url\n",name);
    fprintf(stderr,
"The -e switch automatically escapes shell characters like ^ and &\n");
    fprintf(stderr,"and url is the encoded url string\n");
    exit(1);
}

main(int argc, char *argv[]) {

    if((argc != 2) && (argc != 3))
        usage(argv[0]);
    else {
        char *t;

        t = (char *) malloc(sizeof(char) * (strlen(argv[argc-1])+1));
        strcpy(t,argv[argc-1]);
        plustospace(t);
        unescape_url(t);
        if(argc == 3) {
            if(strcmp(argv[1],"-e"))
                usage(argv[0]);
            escape_shell_cmd(t);
        }
        printf("%s",t);
    }
}
