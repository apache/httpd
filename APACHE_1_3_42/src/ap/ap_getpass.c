/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * ap_getpass.c: abstraction to provide for obtaining a password from the
 * command line in whatever way the OS supports.  In the best case, it's a
 * wrapper for the system library's getpass() routine; otherwise, we
 * use one we define ourselves.
 */

#include "ap_config.h"
#ifndef NETWARE
#include <sys/types.h>
#endif
#include <errno.h>
#include "ap.h"

#ifdef WIN32
#include <conio.h>
#endif

#ifndef CHARSET_EBCDIC
#define LF 10
#define CR 13
#else /* CHARSET_EBCDIC */
#define LF '\n'
#define CR '\r'
#endif /* CHARSET_EBCDIC */

#define MAX_STRING_LEN 256

#define ERR_OVERFLOW 5

#if defined(MPE) || defined(BEOS) || defined(BONE)
#include <termios.h>

char *
getpass(const char *prompt)
{
	static char		buf[MAX_STRING_LEN+1];	/* null byte at end */
	char			*ptr;
	sigset_t		sig, sigsave;
	struct termios	term, termsave;
	FILE			*fp,*outfp;
	int				c;

        if ((outfp = fp = fopen("/dev/tty", "w+")) == NULL) {
                outfp = stderr;
                fp = stdin;
        }

	sigemptyset(&sig);	/* block SIGINT & SIGTSTP, save signal mask */
	sigaddset(&sig, SIGINT);
	sigaddset(&sig, SIGTSTP);
	sigprocmask(SIG_BLOCK, &sig, &sigsave);

	tcgetattr(fileno(fp), &termsave);	/* save tty state */
	term = termsave;			/* structure copy */
	term.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
	tcsetattr(fileno(fp), TCSAFLUSH, &term);

	fputs(prompt, outfp);

	ptr = buf;
	while ( (c = getc(fp)) != EOF && c != '\n') {
		if (ptr < &buf[MAX_STRING_LEN])
			*ptr++ = c;
	}
	*ptr = 0;			/* null terminate */
	putc('\n', outfp);		/* we echo a newline */

						/* restore tty state */
	tcsetattr(fileno(fp), TCSAFLUSH, &termsave);

						/* restore signal mask */
	sigprocmask(SIG_SETMASK, &sigsave, NULL);
	if (fp != stdin) fclose(fp);

	return(buf);
}
#endif /* MPE */

#if defined(WIN32) || defined(NETWARE)
/*
 * Windows lacks getpass().  So we'll re-implement it here.
 */

static char *getpass(const char *prompt)
{
    static char password[MAX_STRING_LEN];
    int n = 0;

    fputs(prompt, stderr);
    
    while ((password[n] = _getch()) != '\r') {
        if (password[n] >= ' ' && password[n] <= '~') {
            n++;
            printf("*");
        }
	else {
            printf("\n");
            fputs(prompt, stderr);
            n = 0;
        }
    }
 
    password[n] = '\0';
    printf("\n");

    if (n > (MAX_STRING_LEN - 1)) {
        password[MAX_STRING_LEN - 1] = '\0';
    }

    return (char *) &password;
}
#endif

/*
 * Use the OS getpass() routine (or our own) to obtain a password from
 * the input stream.
 *
 * Exit values:
 *  0: Success
 *  5: Partial success; entered text truncated to the size of the
 *     destination buffer
 *
 * Restrictions: Truncation also occurs according to the host system's
 * getpass() semantics, or at position 255 if our own version is used,
 * but the caller is *not* made aware of it.
 */

API_EXPORT(int) ap_getpass(const char *prompt, char *pwbuf, size_t bufsiz)
{
    char *pw_got;
    int result = 0;

    pw_got = getpass(prompt);
    if (strlen(pw_got) > (bufsiz - 1)) {
	result = ERR_OVERFLOW;
    }
    ap_cpystrn(pwbuf, pw_got, bufsiz);
    return result;
}
