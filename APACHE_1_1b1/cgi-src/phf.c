#include <stdio.h>
#ifndef NO_STDLIB_H
#include <stdlib.h>
#else
char *getenv();
#endif
#include <string.h>
#include "util.h"

#define	LF	10
#define HTML_BREAK	printf("<P>%c", LF);
typedef struct {
    char name[128];
    char val[128];
} entry;

typedef struct {
    char qfield[256];
    int  qlen;
    char qname[256];
} fields;

void getword(char *word, char *line, char stop);
char x2c(char *what);
void unescape_url(char *url);
void plustospace(char *str);
void send_fd(FILE *f, FILE *fd);
void send_doc(int which);

static fields idxfields[] = { {"Qalias", 32, "Alias"},
                             {"Qname", 256, "Name" },
                             {"Qemail", 128, "E-mail Address"},
                             {"Qnickname", 120, "Nickname"},
                             {"Qoffice_phone", 60, "Office Phone Number"},
                             {"Qcallsign", 16, "HAM Callsign"},
                             {"Qproxy", 64, "Proxy"},
                             {"Qhigh_school", 30, "High School"},
                             {"Qslip", 256, "SLIP Address"},
                             {NULL, 0, NULL}
                           };

static fields othersearchfields[] = { {"Qcurriculum", 64, "Curriculum"},
                             {"Qphone", 64, "Phone Number" },
                             {"Qaddress", 128, "Address"},
                             {"Qoffice_address", 128, "Office Address"},
                             {"Qhome_address", 128, "Home Address"},
                             {"Qpermanent_address", 128, "Permanent Address"},
                             {"Qpermanent_phone", 60, "Permanent Phone"},
                             {"Qdepartment", 64, "Department"},
                             {"Qtitle", 64, "Title"},
                             {"Qproject", 256, "Project"},
                             {"Qother", 256, "Other"},
                             {"Qbirthday", 24, "Birthday"},
                             {"Qcolleges", 120, "Colleges Attended"},
                             {"Qleft_uiuc", 24, "Date/Month Person left UIUC"},
                             {NULL, 0, NULL},
                           };

void send_doc(int which) {
    int x;

    printf("<TITLE>Form for CSO PH query</TITLE>%c", LF);
    printf("<H1>Form for CSO PH query</H1>%c", LF);
    printf("This form will send a PH query to the specified ph server.%c", LF);
    HTML_BREAK
    printf("<HR>%c", LF);

    printf("<FORM ACTION=\"http://%s:%s%s\">%c", getenv("SERVER_NAME"),
           getenv("SERVER_PORT"), getenv("SCRIPT_NAME"), LF);

    printf("PH Server:<INPUT TYPE=\"text\" NAME=\"Jserver\" VALUE=\"ns.uiuc.edu\" MAXLENGTH=\"256\">%c", LF);
    HTML_BREAK

    printf("<H3>At least one of these fields must be specified:</H3><UL>%c",LF);
    for(x=0; idxfields[x].qlen != 0; x++) 
        printf("<LI><INPUT TYPE=\"text\" NAME=\"%s\" MAXLENGTH=\"%d\">%s%c"
               ,idxfields[x].qfield, idxfields[x].qlen, idxfields[x].qname,LF);

    printf("</UL>%c", LF);

    if (!(which&0x10)) {
        printf("<A HREF=\"%s?Jform=%d\"><H3>Show additional fields to narrow query</H3></A>%c", getenv("SCRIPT_NAME"), (which | 0x10), LF);
        }
    else {
        printf("<H3>Additional fields to narrow query:</H3><UL>%c",LF);

        for(x=0; othersearchfields[x].qlen != 0; x++)
            printf("<LI><INPUT TYPE=\"text\" NAME=\"%s\" MAXLENGTH=\"%d\">%s%c"
                   ,othersearchfields[x].qfield, othersearchfields[x].qlen,
                   othersearchfields[x].qname,LF);

        printf("</UL>%c", LF);

        printf("<A HREF=\"%s?Jform=%d\">Show fewer query fields</A>%c", getenv("SCRIPT_NAME"), (which & 0x01), LF);
        }

    HTML_BREAK

    if (!(which & 0x01)) {
        printf("<A HREF=\"%s?Jform=%d\"><H3>Return more than default fields</H3></A>%c", getenv("SCRIPT_NAME"), (which | 0x01), LF);
        }
    else {
        printf("<H3>Fields to return:</H3><UL>%c", LF);

        for(x=0; idxfields[x].qlen != 0; x++) 
            printf("<LI><INPUT TYPE=\"checkbox\" NAME=\"return\" VALUE=\"%s\">%s%c", &(idxfields[x].qfield[1]), idxfields[x].qname, LF);

        for(x=0; othersearchfields[x].qlen != 0; x++)
            printf("<LI><INPUT TYPE=\"checkbox\" NAME=\"return\" VALUE=\"%s\">%s%c", &(othersearchfields[x].qfield[1]), othersearchfields[x].qname, LF);

        printf("</UL>%c", LF);

        printf("<A HREF=\"%s?Jform=%d\">Return default fields</A>%c", getenv("SCRIPT_NAME"), (which & 0x10), LF);
        }

    HTML_BREAK
    printf("<INPUT TYPE=\"submit\">%c", LF);
    printf("</FORM>%c", LF);

    printf("<HR>%c<ADDRESS>", LF);
    printf("Questions, comments to: <a href=\"http://www.ncsa.uiuc.edu/SDG/People/jbrowne/jbrowne.html\">Jim Browne</a>%c", LF);
    printf("</ADDRESS>%c", LF);
        
}

main(int argc, char *argv[]) {
    entry entries[64];
    register int x,m=0;
    char *cl;
    char returnstr[1024], typestr[4098], commandstr[8192], serverstr[256];
    int atleastonereturn = 0, atleastonequery = 0, which = 0;
    FILE *phfp;

    printf("Content-type: text/html%c%c",LF,LF);

    strcpy(returnstr, "return ");
    strcpy(typestr, " ");

    cl = getenv("QUERY_STRING");

    if((!cl) || (!cl[0])) {
        send_doc(0);
        exit(1);
    }

    for(x=0;cl[0] != '\0';x++) {
        m=x;
        getword(entries[x].val,cl,'&');
        plustospace(entries[x].val);
        unescape_url(entries[x].val);
        getword(entries[x].name,entries[x].val,'=');
    }

    for(x=0; x <= m; x++) {
/*      printf("%s = %s %c", entries[x].name, entries[x].val, LF); */

        if (!strcmp(entries[x].name, "return")) {
            strcat(returnstr, entries[x].val);
            strcat(returnstr, " ");
            atleastonereturn = 1;
            }
        else if ((entries[x].name[0] == 'Q') && strlen(entries[x].val)) {
            strcat(typestr, &(entries[x].name[1]));
            strcat(typestr, "=");
            strcat(typestr, entries[x].val);
            strcat(typestr, " ");
            atleastonequery = 1;
            }
        else if (!strcmp(entries[x].name, "Jserver")) 
            strcpy(serverstr, entries[x].val);
        else if (!strcmp(entries[x].name, "Jform")) 
            if (sscanf(entries[x].val, "%d", &which)) {
                send_doc(which);
                exit(1);
                }
            else exit(1);
        }       

    printf("<H1>Query Results</H1>%c", LF);
    HTML_BREAK

    if (!atleastonequery) printf("<B>You did not enter a query!</B>%c",LF);
    else {
        strcpy(commandstr, "/usr/local/bin/ph -m ");
        if (strlen(serverstr)) {
           strcat(commandstr, " -s ");
           /* RM 2/22/94 oops */
           escape_shell_cmd(serverstr);
           strcat(commandstr, serverstr);
           strcat(commandstr, " ");
           }
        escape_shell_cmd(typestr);
        strcat(commandstr, typestr);
        if (atleastonereturn) {
           escape_shell_cmd(returnstr);
           strcat(commandstr, returnstr);
        }

        printf("%s%c", commandstr, LF);
        printf("<PRE>%c", LF);

        phfp = popen(commandstr,"r");
        send_fd(phfp, stdout);

        printf("</PRE>%c", LF);
        }
}
