
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "util.h"

#include "tokens.h"

int opt_directives;

/* From lexer.c */
extern char *yytext;
extern char *token_buffer;
extern FILE *yyin;
extern int yylex(void);
extern void init_lex(void);
extern void done_lex(void);

static FILE *output_file = stdout;

static struct {
    char *old;
    char *new;
} map[1024];

int mapidx = 0;

static void process_token(int token, char *buf)
{
    int i;

    if (token == IDENTIFIER) {
        for (i = 0; map[i].old != NULL; i++) {
            if (strcmp(map[i].old, buf) == 0) {
                printf("Subst: %s -> %s\n", map[i].old, map[i].new);
                buf = map[i].new;
                break;
            }
        }
    }
    fputs(buf, output_file);
}

static void parse(void)
{
    int tk;

    while ((tk = yylex()) != 0)
        switch (tk) {
        case COMMENT:
        case DIRECTIVE:
        case STRING:
            process_token(tk, token_buffer);
            break;
        default:
            process_token(tk, yytext);
            break;
        }
}

static void process_file(char *filename)
{
    if (filename != NULL && strcmp(filename, "-") != 0) {
        if ((yyin = fopen(filename, "r")) == NULL)
            err(1, "%s", filename);
    }
    else
        yyin = stdin;

    init_lex();
    parse();
    done_lex();

    if (yyin != stdin)
        fclose(yyin);
}

/*
 * Output the program syntax then exit.
 */
static void usage(void)
{
    fprintf(stderr, "usage: csubst [-o file] [-s old:new] [file ...]\n");
    exit(1);
}

int main(int argc, char **argv)
{
    int c;
    char *cp;

    while ((c = getopt(argc, argv, "o:s:")) != -1)
        switch (c) {
            case 's':
                if ((cp = strchr(optarg, ':')) == NULL)
                    err(1, "invalid subst %s", optarg);
                *cp++ = '\0';
                map[mapidx].old = strdup(optarg);
                map[mapidx].new = strdup(cp);
                mapidx++;
                break;
            case 'o':
                if (output_file != stdout)
                    fclose(output_file);
                if ((output_file = fopen(optarg, "w")) == NULL)
                    err(1, "%s", optarg);
                break;
            case '?':
            default:
                usage();
                /* NOTREACHED */
        }
    argc -= optind;
    argv += optind;

    opt_directives = 1;
    map[mapidx].old = NULL;
    map[mapidx].new = NULL;

    if (argc < 1)
        process_file(NULL);
    else
        while (*argv)
            process_file(*argv++);
    if (output_file != stdout)
        fclose(output_file);

    return 0;
}
