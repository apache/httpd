/* ====================================================================
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
 *
 */

/*
 * mod_cern_meta.c
 * version 0.0.5
 * status beta
 * 
 * Andrew Wilson <Andrew.Wilson@cm.cf.ac.uk> 25.Jan.96
 *
 * Emulate the CERN HTTPD Meta file semantics.  Meta files are HTTP
 * headers that can be output in addition to the normal range of
 * headers for each file accessed.  They appear rather like the Apache
 * .asis files, and are able to provide a crude way of influencing
 * the Expires: header, as well as providing other curiosities.
 * There are many ways to manage meta information, this one was
 * chosen because there is already a large number of CERN users
 * who can exploit this module.  It should be noted that there are probably
 * more sensitive ways of managing the Expires: header specifically.
 *
 * The module obeys the following directives, which can only appear 
 * in the server's .conf files and not in any .htaccess file.
 *
 *  MetaDir <directory name>
 *      
 *    specifies the name of the directory in which Apache can find
 *    meta information files.  The directory is usually a 'hidden'
 *    subdirectory of the directory that contains the file being
 *    accessed.  eg:
 *
 *        # .meta files are in the *same* directory as the 
 *        # file being accessed
 *        MetaDir .
 *
 *    the default is to look in a '.web' subdirectory. This is the
 *    same as for CERN 3.+ webservers and behaviour is the same as 
 *    for the directive:
 *
 *        MetaDir .web
 *
 *  MetaSuffix <meta file suffix>
 *
 *    specifies the file name suffix for the file containing the
 *    meta information.  eg:
 *
 *       # our meta files are suffixed with '.cern_meta'
 *       MetaSuffix .cern_meta
 *
 *    the default is to look for files with the suffix '.meta'.  This
 *    behaviour is the same as for the directive:
 *
 *       MetaSuffix .meta
 *
 * When accessing the file
 *
 *   DOCUMENT_ROOT/somedir/index.html
 *
 * this module will look for the file
 *
 *   DOCUMENT_ROOT/somedir/.web/index.html.meta
 *
 * and will use its contents to generate additional MIME header 
 * information.
 *
 * For more information on the CERN Meta file semantics see:
 *
 *   http://www.w3.org/hypertext/WWW/Daemon/User/Config/General.html#MetaDir
 *
 * Change-log:
 * 29.Jan.96 pfopen/pfclose instead of fopen/fclose
 *           DECLINE when real file not found, we may be checking each
 *           of the index.html/index.shtml/index.htm variants and don't
 *           need to report missing ones as spurious errors. 
 * 31.Jan.96 log_error reports about a malformed .meta file, rather
 *           than a script error.
 *
 */

#include "httpd.h"
#include "http_config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include "util_script.h"
#include "http_log.h"

#define DEFAULT_METADIR		".web"
#define DEFAULT_METASUFFIX	".meta"

module cern_meta_module;

typedef struct {
	char *metadir;
	char *metasuffix;
} cern_meta_config;

void *create_cern_meta_config (pool *p, server_rec *dummy)
{
    cern_meta_config *new =
      (cern_meta_config *) palloc (p, sizeof(cern_meta_config)); 
 
    new->metadir = DEFAULT_METADIR;
    new->metasuffix = DEFAULT_METASUFFIX;
    
    return new;
}   

char *set_metadir (cmd_parms *parms, void *dummy, char *arg)
{       
    cern_meta_config *cmc ;

    cmc = get_module_config (parms->server->module_config,
                           &cern_meta_module); 
    cmc->metadir = arg;
    return NULL;
}

char *set_metasuffix (cmd_parms *parms, void *dummy, char *arg)
{       
    cern_meta_config *cmc ;

    cmc = get_module_config (parms->server->module_config,
                           &cern_meta_module); 
    cmc->metasuffix = arg;
    return NULL;
}

command_rec cern_meta_cmds[] = {
{ "MetaDir", set_metadir, NULL, RSRC_CONF, TAKE1,
    "the name of the directory containing meta files"},
{ "MetaSuffix", set_metasuffix, NULL, RSRC_CONF, TAKE1,
    "the filename suffix for meta files"},
{ NULL }
};  

int scan_meta_file(request_rec *r, FILE *f)
{
    char w[MAX_STRING_LEN];
    char *l;
    int p;

    while( fgets(w, MAX_STRING_LEN-1, f) != NULL ) {

	/* Delete terminal (CR?)LF */
	
	p = strlen(w);
	if (p > 0 && w[p-1] == '\n')
	{
	    if (p > 1 && w[p-2] == '\015') w[p-2] = '\0';
	    else w[p-1] = '\0';
	}

        if(w[0] == '\0') {
	    return OK;
	}
                                   
	/* if we see a bogus header don't ignore it. Shout and scream */
	
        if(!(l = strchr(w,':'))) {
	    log_reason ("malformed header in meta file", r->filename, r);
	    return SERVER_ERROR;
        }

        *l++ = '\0';
	while (*l && isspace (*l)) ++l;
	
        if(!strcasecmp(w,"Content-type")) {

	    /* Nuke trailing whitespace */
	    
	    char *endp = l + strlen(l) - 1;
	    while (endp > l && isspace(*endp)) *endp-- = '\0';
	    
	    r->content_type = pstrdup (r->pool, l);
	}
        else if(!strcasecmp(w,"Status")) {
            sscanf(l, "%d", &r->status);
            r->status_line = pstrdup(r->pool, l);
        }
        else {
	    table_set (r->headers_out, w, l);
        }
    }
    return OK;
}

int add_cern_meta_data(request_rec *r)
{
    char *metafilename;
    char *last_slash;
    char *real_file;
    char *scrap_book;
    struct stat meta_stat;
    FILE *f;   
    cern_meta_config *cmc ;
    int rv;

    cmc = get_module_config (r->server->module_config,
                           &cern_meta_module); 

    /* if ./.web/$1.meta exists then output 'asis' */

    if (r->finfo.st_mode == 0) {
	return DECLINED;
    };

    /* does uri end in a trailing slash? */
    if ( r->uri[strlen(r->uri) - 1] == '/' ) {
	return DECLINED;
    };

    /* what directory is this file in? */
    scrap_book = pstrdup( r->pool, r->filename );
    /* skip leading slash, recovered in later processing */
    scrap_book++;
    last_slash = strrchr( scrap_book, '/' );
    if ( last_slash != NULL ) {
	/* skip over last slash */
	real_file = last_slash;
	real_file++;
	*last_slash = '\0';
    } else {
	/* no last slash, buh?! */
        log_reason("internal error in mod_cern_meta", r->filename, r);
	/* should really barf, but hey, let's be friends... */
	return DECLINED;
    };

    metafilename = pstrcat(r->pool, "/", scrap_book, "/", cmc->metadir, "/", real_file, cmc->metasuffix, NULL);

    /*
     * stat can legitimately fail for a bewildering number of reasons,
     * only one of which implies the file isn't there.  A hardened
     * version of this module should test for all conditions, but later...
     */
    if (stat(metafilename, &meta_stat) == -1) {
	/* stat failed, possibly file missing */
	return DECLINED;
    };

    /*
     * this check is to be found in other Jan/96 Apache code, I've
     * not been able to find any corroboration in the man pages but
     * I've been wrong before so I'll put it in anyway.  Never
     * admit to being clueless...
     */
    if ( meta_stat.st_mode == 0 ) {
	/* stat failed, definately file missing */
	return DECLINED;
    };

    f = pfopen (r->pool, metafilename, "r");
    
    if (f == NULL) {
        log_reason("meta file permissions deny server access", metafilename, r);
        return FORBIDDEN;
    };

    /* read the headers in */
    rv = scan_meta_file(r, f);
    pfclose( r->pool, f );

    return rv;
}

module cern_meta_module = {
   STANDARD_MODULE_STUFF,
   NULL,			/* initializer */
   NULL,			/* dir config creater */
   NULL,			/* dir merger --- default is to override */
   create_cern_meta_config,	/* server config */
   NULL,			/* merge server configs */
   cern_meta_cmds,		/* command table */
   NULL,			/* handlers */
   NULL,			/* filename translation */
   NULL,			/* check_user_id */
   NULL,			/* check auth */
   NULL,			/* check access */
   NULL,			/* type_checker */
   add_cern_meta_data,		/* fixups */
   NULL,			/* logger */
};
