/* Apache Installer */

/*
 * 26/06/97 PCS 1.000 Initial version
 * 22/02/98 PCS 1.001 Used the excellent NTemacs to apply proper formating
 * 04/05/98 PCS 1.002 Copy conf files to *.conf.default, then to *.conf
 */

#include <windows.h>
#include <winsock.h>
#include <string.h>
#include <stdio.h>
#include <direct.h>

/* Global to store the instance handle */
HINSTANCE hInstance = NULL;

/*
 * MessageBox_error() is a helper function to display an error in a 
 * message box, optionally including a Win32 error message. If
 * the "opt" argument is value AP_WIN32ERROR then get the last Win32
 * error (with GetLastError()) and add it on to the end of
 * the output string. The output string is given as a printf-format
 * and replacement arguments. The hWnd, title and mb_opt fields are 
 * passed on to the Win32 MessageBox() call.
 *
 * We shouldn't use a fixed length buffer to build up the printf
 * text. Umm.
 */

#define AP_WIN32ERROR 1

int MessageBox_error(HWND hWnd, int opt, char *title, 
		     int mb_opt, char *fmt, ...)
{
    char buf[4000];
    va_list ap;

    va_start(ap, fmt);
    wvsprintf(buf, fmt, ap);
    va_end(ap);

    if (opt & AP_WIN32ERROR) {
	char *p;

	strcat(buf, "\r\r(");
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM,
		      NULL,
		      GetLastError(),
		      0,
		      buf + strlen(buf),
		      4000 - strlen(buf),
		      NULL);
	p = buf+strlen(buf)-1;
	while (*p == '\r' || *p == '\n')
	    p--;
	p++;
	*p = '\0';
	strcat(buf, ")");
    }

    return MessageBox(hWnd, buf, title, mb_opt);
}

/*
 * The next few functions handle expanding the @@ServerRoot@@ type
 * sequences found in the distribution files. The main entry point
 * is expandFile(), which is given a file to expand and the filename
 * to write the expanded file it. It reads a line at a time, and
 * if the line includes an "@@" sequence, calls expandLine() to
 * expand the sequences.
 *
 * expandLine() looks for @@ sequences in the line, and when it finds
 * one, looks for a corresponding entry in the replaceTable[]. If it
 * finds one it writes the replacement value from the table into
 * an output string.
 *
 * The helper function appendText() is used when expanding strings. It
 * is called to copy text into an output buffer. If the output buffer
 * is not big enough, it is expanded. This function also ensures that
 * the output buffer is null terminated after each append operation.
 *
 * A table is used of values to replace, rather than just hardcoding
 * the functionality, so we could replace additional values in the
 * future.  We also take care to ensure that the expanded line can be
 * arbitrary length (though at the moment the lines read from the
 * configuration files can only be up to 2000 characters).
 */

/*
 * Table of items to replace. The "value" elements are filled in at runtime
 * by FillInReplaceTable(). Note that the "tmpl" element is case
 * sensitive.
 */

typedef struct {
    char *tmpl;
    char *value;
} REPLACEITEM;
typedef REPLACEITEM *REPLACETABLE;

REPLACEITEM replaceHttpd[] = {
    { "@@ServerRoot@@", NULL },	/* ServerRoot directory (i.e. install dir) */
    { NULL, NULL }
};

/*
 * A relatively intelligent version of strcat, that expands the destination
 * buffer if needed.
 *
 * On entry, ppBuf points to the output buffer, pnPos points to the offset
 * of the current position within that buffer, and pnSize points to the
 * current size of *ppBuf. pSrc points to the string to copy into the buffer,
 * and nToCopy gives the number of characters to copy from pSrc.
 *
 * On exit, *ppBuf, *pnPos and *pnSize may have been updated if the output
 * buffer needed to be expanded. The output buffer will be null terminated.
 * Returns 0 on success, -1 on error. Does not report errors to the user.
 */

int appendText(char **ppBuf, int *pnPos, int *pnSize, char *pSrc, int nToCopy)
{
    char *pBuf = *ppBuf;	/* output buffer */
    int nPos = *pnPos;		/* current offset into pBuf */
    int nSize = *pnSize;	/* current size of pBuf */

    while (nPos + nToCopy >= nSize) {
	/* Not enough space, double size of output buffer. Note we use
	 * >= not > so that we have enough space for the NULL character
	 * in the output buffer */
	char *pBufNew;

	pBufNew = realloc(pBuf, nSize * 2);
	if (!pBufNew)
	    return -1;
	nSize *= 2;

	/* Update the max size and buffer pointer */
	*pnSize = nSize;
	*ppBuf = pBuf = pBufNew;
    }

    /* Ok, now we have enough space, copy the stuff */

    strncpy(pBuf+nPos, pSrc, nToCopy);
    nPos += nToCopy;
    *pnPos = nPos;		/* update current position */
    pBuf[nPos] = '\0';		/* append trailing NULL */

    return 0;
}

/*
 * Expand all the sequences in an input line. Returns a pointer to the
 * expanded line. The caller should free the returned data.
 * The replaceTable argument is a table of sequences to expand.
 *
 * Returns NULL on error. Does not report errors to the user.
 */

char *expandLine(char *in, REPLACETABLE replaceTable)
{
    REPLACEITEM *item;
    char *pos;			/* current position in input buffer */
    char *outbuf;		/* output buffer */
    int outbuf_size;		/* current size of output buffer */
    int outbuf_position;	/* current position in output buffer */
    char *start;		/* position to copy from in input buffer */

    /* Create an initial output buffer. Guess that twice the input size
     * is a good length, after expansion. Don't worry if we need more
     * though, appendText() will expand as needed.
     */
    outbuf_size = strlen(in) * 2;
    outbuf_position = 0;
    outbuf = malloc(outbuf_size);
    if (!outbuf)
      return NULL;

    start = in;			/* mark the start of uncopied data */
    pos = in;			/* current position in input buffer */

    while (1) {

	/* Look for '@@' sequence, or end of input */
	if (*pos && !(*pos == '@' && *(pos+1) == '@')) {
	    pos++;
	    continue;
	}

	if (!*pos) {
	    /* End of input string, copy the uncopied data */
	    if (appendText(&outbuf, &outbuf_position, &outbuf_size, 
			   start, pos-start) < 0) {
		return NULL;
	    }
	    break;
	}

	/* Found first @ of a possible token to replace. Look for end
	 * of the token
	 */
	for (item = replaceTable; item->tmpl; ++item) {
	    if (!strncmp(pos, item->tmpl, strlen(item->tmpl)))
		break;
	}

	if (item->tmpl) {
	    /* Found match. First copy the uncopied data from the input
	     * buffer (start through to pos-1), then copy the expanded
	     * value. */
	    if (appendText(&outbuf, &outbuf_position, &outbuf_size,
			   start, pos-start) < 0) {
		return NULL;
	    }
	    if (appendText(&outbuf, &outbuf_position, &outbuf_size,
			   item->value, strlen(item->value)) < 0) {
		return NULL;
	    }

	    /* Update current position to skip over the input buffer
	     * @@...@@ sequence, and update the "start" pointer to uncopied
	     * data
	     */
	    pos += strlen(item->tmpl);
	    start = pos;
	} 
	else {
	    /* The sequence did not exist in the replace table, so copy
	     * it as-is to the output.
	     */
	    pos++; 
	}
    }

    return outbuf;
}

/*
 * Some options to determine how we copy a file. Apart from OPT_NONE, these should
 * be OR'able
 */

typedef enum { 
    OPT_NONE = 0, 
    OPT_OVERWRITE = 1,	    /* Always overwrite destination file */
    OPT_EXPAND = 2,	    /* Expand any @@...@@ tokens in replaceHttpd */
    OPT_DELETESOURCE = 4,   /* Delete the source file after the copy */
    OPT_SILENT = 8,	    /* Don't tell use about failures */
} options_t;

/* 
 * Copy a file, expanding sequences from the replaceTable argument.
 * Returns 0 on success, -1 on error. Reports errors to user.
 */
#define MAX_INPUT_LINE 2000
int WINAPI ExpandConfFile(HWND hwnd, LPSTR szInst, LPSTR szinFile, LPSTR szoutFile, REPLACETABLE replaceTable, options_t options)
{
    char inFile[_MAX_PATH];
    char outFile[_MAX_PATH];
    char inbuf[MAX_INPUT_LINE];
    FILE *infp;
    FILE *outfp;

    sprintf(inFile, "%s\\%s", szInst, szinFile);
    sprintf(outFile, "%s\\%s", szInst, szoutFile);

    if (!(infp = fopen(inFile, "r"))) {
	MessageBox_error(hwnd, 
			 AP_WIN32ERROR,
			 "Installation Problem",
			 MB_OK | MB_ICONSTOP,
			 "Cannot read file %s", inFile);
	return -1;
    }
    if (! (options & OPT_OVERWRITE)) {
	/* Overwrite not allowed if file does not exist */
	if ((outfp = fopen(outFile, "r"))) {
	    if (! (options & OPT_SILENT)) {
		MessageBox_error(hwnd,
				 0,
				 "File not overwritten",
				 MB_OK | MB_ICONWARNING,
				 "Preserving existing file %s.\r\r"
				 "The new version of this file has been left in %s", 
				 outFile, inFile);
	    }
	    fclose(outfp);
	    fclose(infp);
	    return 0;
	}
	/* To get here, output file does not exist */
    }
    if (!(outfp = fopen(outFile, "w"))) {
	MessageBox_error(hwnd, 
			 AP_WIN32ERROR,
			 "Installation Problem",
			 MB_OK | MB_ICONSTOP,
			 "Cannot write to file %s", outFile);
	fclose(infp);
	return -1;
    }

    while (fgets(inbuf, MAX_INPUT_LINE, infp)) {
	char *pos;
	char *outbuf;

	/* Quickly look to see if this line contains any
	 * @@ tokens. If it doesn't, we don't need to bother
	 * called expandLine() or taking a copy of the input
	 * buffer.
	 */
	if (options & OPT_EXPAND) {
    	    for (pos = inbuf; *pos; ++pos)
		if (*pos == '@' && *(pos+1) == '@')
		    break;
	}

	if (options & OPT_EXPAND && *pos) {
	    /* The input line contains at least one '@@' sequence, so
	     * call expandLine() to expand any sequences we know about.
	     */
	    outbuf = expandLine(inbuf, replaceTable);
	    if (outbuf == NULL) {
		fclose(infp);
		fclose(outfp);
		MessageBox_error(hwnd,
				 0,
				 "Installation Problem",
				 MB_OK|MB_ICONSTOP,
				 "An error occurred during installation");
		return -1;
	    }
	}
	else {
	    outbuf = NULL;
	}

	/* If outbuf is NULL, we did not need to expand sequences, so
	 * just output the contents of the input buffer.
	 */
	fwrite(outbuf ? outbuf : inbuf, 1, 
	       strlen(outbuf ? outbuf : inbuf), outfp);

	if (outbuf)
	    free(outbuf);
    }
    fclose(infp);
    fclose(outfp);

    if (options & OPT_DELETESOURCE) {
	unlink(inFile);
    }

    return 0;
}

int FillInReplaceTable(HWND hwnd, REPLACETABLE table, char *szInst)
{
    REPLACEITEM *item;
    for (item = table; item->tmpl; ++item) {
	if (!strcmp(item->tmpl, "@@ServerRoot@@")) {
	    char *p;

#if NEED_SHORT_PATHS
	    int len;
	    len = GetShortPathName(szInst, NULL, 0);
	    if (len > 0) {
		item->value = (char*)malloc(len+1);
		GetShortPathName(szInst, item->value, len);
	    }
#else
	    if ((item->value = strdup(szInst)) == NULL)
	        return -1;
#endif
	    for (p = item->value; *p; p++)
	        if (*p == '\\') *p = '/';
	    continue;
	}
#if NEED_FQDN
	if (!strcmp(item->tmpl, "FQDN")) {
	    item->value = GetHostName(hwnd);
	    continue;
	}
#endif
    }
    return 0;
}

/*
 * actionTable[] contains things we do when this DLL is called by InstallShield
 * during the install. It is like a simple script, without us having to
 * worry about parsing, error checking, etc.
 *
 * Each item in the table is of type ACTIONITEM. The first element is the action 
 * to perform (e.g. CMD_COPY). The second and third elements are filenames
 * (e.g. for CMD_COPY, the first filename is the source and the second filename
 * is the destination). The final element of ACTIONITEM is a set of options
 * which apply to the current "command". For example, OPT_EXPAND on a CMD_COPY
 * line, tells the copy function to expand @@ServerRoot@@ tokens found in the
 * source file.
 *
 * The contents of this table are performed in order, top to bottom. This lets
 * us expand the files to the *.conf.default names, then copy to *.conf only
 * if the corresponding *.conf file does not already exist. If it does exist,
 * it is not overwritten.
 *
 * Return 1 on success, 0 on error.
 */

typedef enum {
    CMD_COPY = 0,
    CMD_RMDIR,
    CMD_RM,
    CMD_END
} cmd_t;

typedef struct {
    cmd_t command;
    char *in;
    char *out;
    options_t options;
} ACTIONITEM;
typedef ACTIONITEM *ACTIONTABLE;

ACTIONITEM actionTable[] = {
    /*
     * Installation of the configuraton files. These are installed into the ".tmp"
     * directory by the installer. We first move them to conf\*.default (overwriting
     * any *.default file from a previous install). The *.conf-dist-win files
     * are also expanded for any @@...@@ tokens. Then we copy the conf\*.default
     * file to corresponding conf\* file, unless that would overwrite an existing file.
     */
    { CMD_COPY, ".tmp\\mime.types", "conf\\mime.types.default",
	OPT_OVERWRITE|OPT_DELETESOURCE },
    { CMD_COPY, ".tmp\\magic", "conf\\magic.default",
	OPT_OVERWRITE|OPT_DELETESOURCE },
    { CMD_COPY, ".tmp\\httpd.conf-dist-win", "conf\\httpd.conf.default", 
	OPT_OVERWRITE|OPT_EXPAND|OPT_DELETESOURCE },
    { CMD_COPY, ".tmp\\srm.conf-dist-win", "conf\\srm.conf.default", 
	OPT_OVERWRITE|OPT_EXPAND|OPT_DELETESOURCE },
    { CMD_COPY, ".tmp\\access.conf-dist-win", "conf\\access.conf.default", 
	OPT_OVERWRITE|OPT_EXPAND|OPT_DELETESOURCE },

    /* Now copy to the 'live' files, unless they already exist */
    { CMD_COPY, "conf\\httpd.conf.default", "conf\\httpd.conf", OPT_NONE },
    { CMD_COPY, "conf\\srm.conf.default", "conf\\srm.conf", OPT_NONE },
    { CMD_COPY, "conf\\access.conf.default", "conf\\access.conf", OPT_NONE },
    { CMD_COPY, "conf\\magic.default", "conf\\magic", OPT_NONE },
    { CMD_COPY, "conf\\mime.types.default", "conf\\mime.types", OPT_NONE },

    { CMD_COPY, ".tmp\\highperformance.conf-dist", "conf\\highperformance.conf-dist", 
	OPT_EXPAND|OPT_OVERWRITE|OPT_DELETESOURCE },

    /* Move the default htdocs files into place, provided they don't already
     * exist.
     */
    { CMD_COPY, ".tmp\\index.html", "htdocs\\index.html", OPT_DELETESOURCE|OPT_SILENT },
    { CMD_RM, ".tmp\\index.html", NULL, OPT_SILENT },
    { CMD_COPY, ".tmp\\apache_pb.gif", "htdocs\\apache_pb.gif", OPT_DELETESOURCE|OPT_SILENT },
    { CMD_RM, ".tmp\\apache_pb.gif", NULL, OPT_SILENT },

    { CMD_RMDIR, ".tmp", NULL },

    { CMD_END, NULL, NULL, OPT_NONE }
};

/*
 * BeforeExit() is the DLL call from InstallShield. The arguments and
 * return value as defined by the installer. We are only interested
 * in the install directory, szInst. Return 0 on error and 1 on
 * success (!?).
 */

CHAR WINAPI BeforeExit(HWND hwnd, LPSTR szSrcDir, LPSTR szSupport, LPSTR szInst, LPSTR szRes)
{
    ACTIONITEM *pactionItem;
    int end = 0;

    FillInReplaceTable(hwnd, replaceHttpd, szInst);

    pactionItem = actionTable;
    while (!end) {
	switch(pactionItem->command) {
	case CMD_END:
	    end = 1;
	    break;
	case CMD_COPY:
	    if (ExpandConfFile(hwnd, szInst, 
			       pactionItem->in, 
			       pactionItem->out,
			       replaceHttpd,
			       pactionItem->options) < 0) {
		/* Error has already been reported to the user */
		return 0;
	    }
	    break;
	case CMD_RM: {
	    char inFile[MAX_INPUT_LINE];

	    sprintf(inFile, "%s\\%s", szInst, pactionItem->in);
	    if (unlink(inFile) < 0 && !(pactionItem->options & OPT_SILENT)) {
		MessageBox_error(hwnd, AP_WIN32ERROR, "Error during configuration",
		    MB_ICONHAND,
		    "Could not remove file %s", 
		    inFile);
		return 0;
	    }
	    break;
	}
	case CMD_RMDIR: {
	    char inFile[MAX_INPUT_LINE];

	    sprintf(inFile, "%s\\%s", szInst, pactionItem->in);
	    if (rmdir(inFile) < 0) {
		MessageBox_error(hwnd, AP_WIN32ERROR, "Error during configuration",
		    MB_ICONHAND,
		    "Could not delete temporary directory %s", 
		    inFile);
		return 0;
	    }
	    break;
	}
	default:
	    MessageBox_error(hwnd, 0, "Error during configuration",
		    MB_ICONHAND,
		    "An error has occurred during configuration\r"
		    "(Error: unknown command %d)", (int)pactionItem->command);
	    end = 1;
	    break;
	}
	pactionItem++;
    }
    return 1;
}


BOOL WINAPI DllMain(HINSTANCE hInstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
	hInstance = hInstDLL;
    return TRUE;
}
