/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2003 The Apache Software Foundation.  All rights
 * reserved.
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
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 */

#include "apr.h"
#include "apr_file_io.h"
#include "apr_strings.h"
#include "apr_lib.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#define WANT_BASENAME_MATCH

#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_request.h"
#include "http_log.h"

/* mod_speling.c - by Alexei Kosut <akosut@organic.com> June, 1996
 *
 * This module is transparent, and simple. It attempts to correct
 * misspellings of URLs that users might have entered, namely by checking
 * capitalizations. If it finds a match, it sends a redirect.
 *
 * 08-Aug-1997 <Martin.Kraemer@Mch.SNI.De>
 * o Upgraded module interface to apache_1.3a2-dev API (more NULL's in
 *   speling_module).
 * o Integrated tcsh's "spelling correction" routine which allows one
 *   misspelling (character insertion/omission/typo/transposition).
 *   Rewrote it to ignore case as well. This ought to catch the majority
 *   of misspelled requests.
 * o Commented out the second pass where files' suffixes are stripped.
 *   Given the better hit rate of the first pass, this rather ugly
 *   (request index.html, receive index.db ?!?!) solution can be
 *   omitted.
 * o wrote a "kind of" html page for mod_speling
 *
 * Activate it with "CheckSpelling On"
 */

module AP_MODULE_DECLARE_DATA speling_module;

typedef struct {
    int enabled;
} spconfig;

/*
 * Create a configuration specific to this module for a server or directory
 * location, and fill it with the default settings.
 *
 * The API says that in the absence of a merge function, the record for the
 * closest ancestor is used exclusively.  That's what we want, so we don't
 * bother to have such a function.
 */

static void *mkconfig(apr_pool_t *p)
{
    spconfig *cfg = apr_pcalloc(p, sizeof(spconfig));

    cfg->enabled = 0;
    return cfg;
}

/*
 * Respond to a callback to create configuration record for a server or
 * vhost environment.
 */
static void *create_mconfig_for_server(apr_pool_t *p, server_rec *s)
{
    return mkconfig(p);
}

/*
 * Respond to a callback to create a config record for a specific directory.
 */
static void *create_mconfig_for_directory(apr_pool_t *p, char *dir)
{
    return mkconfig(p);
}

/*
 * Handler for the CheckSpelling directive, which is FLAG.
 */
static const char *set_speling(cmd_parms *cmd, void *mconfig, int arg)
{
    spconfig *cfg = (spconfig *) mconfig;

    cfg->enabled = arg;
    return NULL;
}

/*
 * Define the directives specific to this module.  This structure is referenced
 * later by the 'module' structure.
 */
static const command_rec speling_cmds[] =
{
    AP_INIT_FLAG("CheckSpelling", set_speling, NULL, OR_OPTIONS,
                 "whether or not to fix miscapitalized/misspelled requests"),
    { NULL }
};

typedef enum {
    SP_IDENTICAL = 0,
    SP_MISCAPITALIZED = 1,
    SP_TRANSPOSITION = 2,
    SP_MISSINGCHAR = 3,
    SP_EXTRACHAR = 4,
    SP_SIMPLETYPO = 5,
    SP_VERYDIFFERENT = 6
} sp_reason;

static const char *sp_reason_str[] =
{
    "identical",
    "miscapitalized",
    "transposed characters",
    "character missing",
    "extra character",
    "mistyped character",
    "common basename",
};

typedef struct {
    const char *name;
    sp_reason quality;
} misspelled_file;

/*
 * spdist() is taken from Kernighan & Pike,
 *  _The_UNIX_Programming_Environment_
 * and adapted somewhat to correspond better to psychological reality.
 * (Note the changes to the return values)
 *
 * According to Pollock and Zamora, CACM April 1984 (V. 27, No. 4),
 * page 363, the correct order for this is:
 * OMISSION = TRANSPOSITION > INSERTION > SUBSTITUTION
 * thus, it was exactly backwards in the old version. -- PWP
 *
 * This routine was taken out of tcsh's spelling correction code
 * (tcsh-6.07.04) and re-converted to apache data types ("char" type
 * instead of tcsh's NLS'ed "Char"). Plus it now ignores the case
 * during comparisons, so is a "approximate strcasecmp()".
 * NOTE that is still allows only _one_ real "typo",
 * it does NOT try to correct multiple errors.
 */

static sp_reason spdist(const char *s, const char *t)
{
    for (; apr_tolower(*s) == apr_tolower(*t); t++, s++) {
        if (*t == '\0') {
            return SP_MISCAPITALIZED;   /* exact match (sans case) */
	}
    }
    if (*s) {
        if (*t) {
            if (s[1] && t[1] && apr_tolower(*s) == apr_tolower(t[1])
		&& apr_tolower(*t) == apr_tolower(s[1])
		&& strcasecmp(s + 2, t + 2) == 0) {
                return SP_TRANSPOSITION;        /* transposition */
	    }
            if (strcasecmp(s + 1, t + 1) == 0) {
                return SP_SIMPLETYPO;   /* 1 char mismatch */
	    }
        }
        if (strcasecmp(s + 1, t) == 0) {
            return SP_EXTRACHAR;        /* extra character */
	}
    }
    if (*t && strcasecmp(s, t + 1) == 0) {
        return SP_MISSINGCHAR;  /* missing character */
    }
    return SP_VERYDIFFERENT;    /* distance too large to fix. */
}

static int sort_by_quality(const void *left, const void *rite)
{
    return (int) (((misspelled_file *) left)->quality)
        - (int) (((misspelled_file *) rite)->quality);
}

static int check_speling(request_rec *r)
{
    spconfig *cfg;
    char *good, *bad, *postgood, *url;
    apr_finfo_t dirent;
    int filoc, dotloc, urlen, pglen;
    apr_array_header_t *candidates = NULL;
    apr_dir_t          *dir;

    cfg = ap_get_module_config(r->per_dir_config, &speling_module);
    if (!cfg->enabled) {
        return DECLINED;
    }

    /* We only want to worry about GETs */
    if (r->method_number != M_GET) {
        return DECLINED;
    }

    /* We've already got a file of some kind or another */
    if (r->proxyreq || (r->finfo.filetype != 0)) {
        return DECLINED;
    }

    /* This is a sub request - don't mess with it */
    if (r->main) {
        return DECLINED;
    }

    /*
     * The request should end up looking like this:
     * r->uri: /correct-url/mispelling/more
     * r->filename: /correct-file/mispelling r->path_info: /more
     *
     * So we do this in steps. First break r->filename into two pieces
     */

    filoc = ap_rind(r->filename, '/');
    /*
     * Don't do anything if the request doesn't contain a slash, or
     * requests "/" 
     */
    if (filoc == -1 || strcmp(r->uri, "/") == 0) {
        return DECLINED;
    }

    /* good = /correct-file */
    good = apr_pstrndup(r->pool, r->filename, filoc);
    /* bad = mispelling */
    bad = apr_pstrdup(r->pool, r->filename + filoc + 1);
    /* postgood = mispelling/more */
    postgood = apr_pstrcat(r->pool, bad, r->path_info, NULL);

    urlen = strlen(r->uri);
    pglen = strlen(postgood);

    /* Check to see if the URL pieces add up */
    if (strcmp(postgood, r->uri + (urlen - pglen))) {
        return DECLINED;
    }

    /* url = /correct-url */
    url = apr_pstrndup(r->pool, r->uri, (urlen - pglen));

    /* Now open the directory and do ourselves a check... */
    if (apr_dir_open(&dir, good, r->pool) != APR_SUCCESS) {
        /* Oops, not a directory... */
        return DECLINED;
    }

    candidates = apr_array_make(r->pool, 2, sizeof(misspelled_file));

    dotloc = ap_ind(bad, '.');
    if (dotloc == -1) {
        dotloc = strlen(bad);
    }

    while (apr_dir_read(&dirent, APR_FINFO_DIRENT, dir) == APR_SUCCESS) {
        sp_reason q;

        /*
         * If we end up with a "fixed" URL which is identical to the
         * requested one, we must have found a broken symlink or some such.
         * Do _not_ try to redirect this, it causes a loop!
         */
        if (strcmp(bad, dirent.name) == 0) {
            apr_dir_close(dir);
            return OK;
        }

        /*
         * miscapitalization errors are checked first (like, e.g., lower case
         * file, upper case request)
         */
        else if (strcasecmp(bad, dirent.name) == 0) {
            misspelled_file *sp_new;

	    sp_new = (misspelled_file *) apr_array_push(candidates);
            sp_new->name = apr_pstrdup(r->pool, dirent.name);
            sp_new->quality = SP_MISCAPITALIZED;
        }

        /*
         * simple typing errors are checked next (like, e.g.,
         * missing/extra/transposed char)
         */
        else if ((q = spdist(bad, dirent.name)) != SP_VERYDIFFERENT) {
            misspelled_file *sp_new;

	    sp_new = (misspelled_file *) apr_array_push(candidates);
            sp_new->name = apr_pstrdup(r->pool, dirent.name);
            sp_new->quality = q;
        }

        /*
	 * The spdist() should have found the majority of the misspelled
	 * requests.  It is of questionable use to continue looking for
	 * files with the same base name, but potentially of totally wrong
	 * type (index.html <-> index.db).
	 * I would propose to not set the WANT_BASENAME_MATCH define.
         *      08-Aug-1997 <Martin.Kraemer@Mch.SNI.De>
         *
         * However, Alexei replied giving some reasons to add it anyway:
         * > Oh, by the way, I remembered why having the
         * > extension-stripping-and-matching stuff is a good idea:
         * >
         * > If you're using MultiViews, and have a file named foobar.html,
	 * > which you refer to as "foobar", and someone tried to access
	 * > "Foobar", mod_speling won't find it, because it won't find
	 * > anything matching that spelling. With the extension-munging,
	 * > it would locate "foobar.html". Not perfect, but I ran into
	 * > that problem when I first wrote the module.
	 */
        else {
#ifdef WANT_BASENAME_MATCH
            /*
             * Okay... we didn't find anything. Now we take out the hard-core
             * power tools. There are several cases here. Someone might have
             * entered a wrong extension (.htm instead of .html or vice
             * versa) or the document could be negotiated. At any rate, now
             * we just compare stuff before the first dot. If it matches, we
             * figure we got us a match. This can result in wrong things if
             * there are files of different content types but the same prefix
             * (e.g. foo.gif and foo.html) This code will pick the first one
             * it finds. Better than a Not Found, though.
             */
            int entloc = ap_ind(dirent.name, '.');
            if (entloc == -1) {
                entloc = strlen(dirent.name);
	    }

            if ((dotloc == entloc)
                && !strncasecmp(bad, dirent.name, dotloc)) {
                misspelled_file *sp_new;

		sp_new = (misspelled_file *) apr_array_push(candidates);
                sp_new->name = apr_pstrdup(r->pool, dirent.name);
                sp_new->quality = SP_VERYDIFFERENT;
            }
#endif
        }
    }
    apr_dir_close(dir);

    if (candidates->nelts != 0) {
        /* Wow... we found us a mispelling. Construct a fixed url */
        char *nuri;
	const char *ref;
        misspelled_file *variant = (misspelled_file *) candidates->elts;
        int i;

        ref = apr_table_get(r->headers_in, "Referer");

        qsort((void *) candidates->elts, candidates->nelts,
              sizeof(misspelled_file), sort_by_quality);

        /*
         * Conditions for immediate redirection: 
         *     a) the first candidate was not found by stripping the suffix 
         * AND b) there exists only one candidate OR the best match is not
	 *        ambiguous
         * then return a redirection right away.
         */
        if (variant[0].quality != SP_VERYDIFFERENT
	    && (candidates->nelts == 1
		|| variant[0].quality != variant[1].quality)) {

            nuri = ap_escape_uri(r->pool, apr_pstrcat(r->pool, url,
						     variant[0].name,
						     r->path_info, NULL));
	    if (r->parsed_uri.query)
		nuri = apr_pstrcat(r->pool, nuri, "?", r->parsed_uri.query, NULL);

            apr_table_setn(r->headers_out, "Location",
			  ap_construct_url(r->pool, nuri, r));

            ap_log_rerror(APLOG_MARK, APLOG_INFO, APR_SUCCESS,
			  r, 
			  ref ? "Fixed spelling: %s to %s from %s"
			      : "Fixed spelling: %s to %s",
			  r->uri, nuri, ref);

            return HTTP_MOVED_PERMANENTLY;
        }
        /*
         * Otherwise, a "[300] Multiple Choices" list with the variants is
         * returned.
         */
        else {
            apr_pool_t *p;
            apr_table_t *notes;
	    apr_pool_t *sub_pool;
	    apr_array_header_t *t;
	    apr_array_header_t *v;


            if (r->main == NULL) {
                p = r->pool;
                notes = r->notes;
            }
            else {
                p = r->main->pool;
                notes = r->main->notes;
            }

	    if (apr_pool_create(&sub_pool, p) != APR_SUCCESS)
		return DECLINED;

	    t = apr_array_make(sub_pool, candidates->nelts * 8 + 8,
			      sizeof(char *));
	    v = apr_array_make(sub_pool, candidates->nelts * 5,
			      sizeof(char *));

            /* Generate the response text. */

	    *(const char **)apr_array_push(t) =
			  "The document name you requested (<code>";
	    *(const char **)apr_array_push(t) = ap_escape_html(sub_pool, r->uri);
	    *(const char **)apr_array_push(t) =
			   "</code>) could not be found on this server.\n"
			   "However, we found documents with names similar "
			   "to the one you requested.<p>"
			   "Available documents:\n<ul>\n";

            for (i = 0; i < candidates->nelts; ++i) {
		char *vuri;
		const char *reason;

		reason = sp_reason_str[(int) (variant[i].quality)];
                /* The format isn't very neat... */
		vuri = apr_pstrcat(sub_pool, url, variant[i].name, r->path_info,
				  (r->parsed_uri.query != NULL) ? "?" : "",
				  (r->parsed_uri.query != NULL)
				      ? r->parsed_uri.query : "",
				  NULL);
		*(const char **)apr_array_push(v) = "\"";
		*(const char **)apr_array_push(v) = ap_escape_uri(sub_pool, vuri);
		*(const char **)apr_array_push(v) = "\";\"";
		*(const char **)apr_array_push(v) = reason;
		*(const char **)apr_array_push(v) = "\"";

		*(const char **)apr_array_push(t) = "<li><a href=\"";
		*(const char **)apr_array_push(t) = ap_escape_uri(sub_pool, vuri);
		*(const char **)apr_array_push(t) = "\">";
		*(const char **)apr_array_push(t) = ap_escape_html(sub_pool, vuri);
		*(const char **)apr_array_push(t) = "</a> (";
		*(const char **)apr_array_push(t) = reason;
		*(const char **)apr_array_push(t) = ")\n";

                /*
                 * when we have printed the "close matches" and there are
                 * more "distant matches" (matched by stripping the suffix),
                 * then we insert an additional separator text to suggest
                 * that the user LOOK CLOSELY whether these are really the
                 * files she wanted.
                 */
                if (i > 0 && i < candidates->nelts - 1
                    && variant[i].quality != SP_VERYDIFFERENT
                    && variant[i + 1].quality == SP_VERYDIFFERENT) {
		    *(const char **)apr_array_push(t) = 
				   "</ul>\nFurthermore, the following related "
				   "documents were found:\n<ul>\n";
                }
            }
	    *(const char **)apr_array_push(t) = "</ul>\n";

            /* If we know there was a referring page, add a note: */
            if (ref != NULL) {
                *(const char **)apr_array_push(t) =
			       "Please consider informing the owner of the "
			       "<a href=\"";
		*(const char **)apr_array_push(t) = ap_escape_uri(sub_pool, ref);
                *(const char **)apr_array_push(t) = "\">referring page</a> "
			       "about the broken link.\n";
	    }


            /* Pass our apr_table_t to http_protocol.c (see mod_negotiation): */
            apr_table_setn(notes, "variant-list", apr_array_pstrcat(p, t, 0));

	    apr_table_mergen(r->subprocess_env, "VARIANTS",
			    apr_array_pstrcat(p, v, ','));
	  
	    apr_pool_destroy(sub_pool);

            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
			 ref ? "Spelling fix: %s: %d candidates from %s"
			     : "Spelling fix: %s: %d candidates",
			 r->uri, candidates->nelts, ref);

            return HTTP_MULTIPLE_CHOICES;
        }
    }

    return OK;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_fixups(check_speling,NULL,NULL,APR_HOOK_LAST);
}

module AP_MODULE_DECLARE_DATA speling_module =
{
    STANDARD20_MODULE_STUFF,
    create_mconfig_for_directory,  /* create per-dir config */
    NULL,                       /* merge per-dir config */
    create_mconfig_for_server,  /* server config */
    NULL,                       /* merge server config */
    speling_cmds,               /* command apr_table_t */
    register_hooks		/* register hooks */
};
