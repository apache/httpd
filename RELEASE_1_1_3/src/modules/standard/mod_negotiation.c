
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
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
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
 * mod_negotiation.c: keeps track of MIME types the client is willing to
 * accept, and contains code to handle type arbitration.
 *
 * rst
 */

#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_core.h"
#include "http_log.h"

/* Commands --- configuring document caching on a per (virtual?)
 * server basis...
 */

typedef struct {
    array_header *language_priority;
} neg_dir_config;

module negotiation_module;

void *create_neg_dir_config (pool *p, char *dummy)
{
    neg_dir_config *new =
      (neg_dir_config *) palloc (p, sizeof (neg_dir_config));

    new->language_priority = make_array (p, 4, sizeof (char *));
    return new;
}

void *merge_neg_dir_configs (pool *p, void *basev, void *addv)
{
    neg_dir_config *base = (neg_dir_config *)basev;
    neg_dir_config *add = (neg_dir_config *)addv;
    neg_dir_config *new =
      (neg_dir_config *) palloc (p, sizeof (neg_dir_config));

    /* give priority to the config in the subdirectory */
    new->language_priority = append_arrays (p, add->language_priority,
					    base->language_priority);
    return new;
}

char *set_language_priority (cmd_parms *cmd, void *n, char *lang)
{
    array_header *arr = ((neg_dir_config *) n)->language_priority;
    char **langp = (char **) push_array (arr);

    *langp = pstrdup (arr->pool, lang);
    return NULL;
}

char *cache_negotiated_docs (cmd_parms *cmd, void *dummy, char *dummy2)
{
    void *server_conf = cmd->server->module_config;
    
    set_module_config (server_conf, &negotiation_module, "Cache");
    return NULL;
}

int do_cache_negotiated_docs (server_rec *s)
{
    return (get_module_config (s->module_config, &negotiation_module) != NULL);
}

command_rec negotiation_cmds[] = {
{ "CacheNegotiatedDocs", cache_negotiated_docs, NULL, RSRC_CONF, RAW_ARGS,
    NULL },
{ "LanguagePriority", set_language_priority, NULL, OR_FILEINFO, ITERATE,
    NULL },
{ NULL }
};

/*
 * TO DO --- error code 406.  Unfortunately, the specification for
 *           a 406 reply in the current draft standard is unworkable;
 *           we return 404 for these pending a workable spec. 
 */

/* Record of available info on a media type specified by the client
 * (we also use 'em for encodings and languages)
 */

typedef struct accept_rec {
    char *type_name;
    float quality;
    float max_bytes;
    float level;
} accept_rec;

/* Record of available info on a particular variant
 *
 * Note that a few of these fields are updated by the actual negotiation
 * code.  These are:
 *
 * quality --- initialized to the value of qs, and subsequently jiggered
 *             to reflect the client's preferences.  In particular, it
 *             gets zeroed out if the variant has an unacceptable content
 *             encoding, or if it is in a language which the client
 *             doesn't accept and some other variant *is* in a language
 *             the client accepts.
 *
 * level_matched --- initialized to zero.  Set to the value of level
 *             if the client actually accepts this media type at that
 *             level (and *not* if it got in on a wildcard).  See level_cmp
 *             below.
 */

typedef struct var_rec {
    request_rec *sub_req;	/* May be NULL (is, for map files) */
    char *type_name;
    char *file_name;
    char *content_encoding;
    char *content_language;
    float level;		/* Auxiliary to content-type... */
    float qs;
    float bytes;
    int lang_index;
    int is_pseudo_html;		/* text/html, *or* the INCLUDES_MAGIC_TYPEs */

    /* Above are all written-once properties of the variant.  The
     * three fields below are changed during negotiation:
     */
    
    float quality;	
    float level_matched;
    int mime_stars;
} var_rec;

/* Something to carry around the state of negotiation (and to keep
 * all of this thread-safe)...
 */

typedef struct {
    pool *pool;
    request_rec *r;
    char *dir_name;
    
    array_header *accepts;	/* accept_recs */
    array_header *accept_encodings;	/* accept_recs */
    array_header *accept_langs;	/* accept_recs */
    array_header *avail_vars;	/* available variants */
} negotiation_state;

/* A few functions to manipulate var_recs.
 * Cleaning out the fields...
 */

void clean_var_rec (var_rec *mime_info)
{
    mime_info->sub_req = NULL;
    mime_info->type_name = "";
    mime_info->file_name = "";
    mime_info->content_encoding = "";
    mime_info->content_language = "";

    mime_info->is_pseudo_html = 0;
    mime_info->level = 0.0;
    mime_info->level_matched = 0.0;
    mime_info->qs = 0.0;
    mime_info->quality = 0.0;
    mime_info->bytes = 0;
    mime_info->lang_index = -1;
    mime_info->mime_stars = 0;
}

/* Initializing the relevant fields of a variant record from the
 * accept_info read out of its content-type, one way or another.
 */

void set_mime_fields (var_rec *var, accept_rec *mime_info)
{
    var->type_name = mime_info->type_name;
    var->qs = mime_info->quality;
    var->quality = mime_info->quality; /* Initial quality is just qs */
    var->level = mime_info->level;

    var->is_pseudo_html = 
	(!strcmp (var->type_name, "text/html")
	 || !strcmp (var->type_name, INCLUDES_MAGIC_TYPE)
	 || !strcmp (var->type_name, INCLUDES_MAGIC_TYPE3));
}

/*****************************************************************
 *
 * Parsing (lists of) media types and their parameters, as seen in
 * HTTPD header lines and elsewhere.
 */

/*
 * Get a single mime type entry --- one media type and parameters;
 * enter the values we recognize into the argument accept_rec
 */

char *get_entry (pool *p, accept_rec *result, char *accept_line)
{
    result->quality = 1.0;
    result->max_bytes = 0.0;
    result->level = 0.0;
    
    /* Note that this handles what I gather is the "old format",
     *
     *    Accept: text/html text/plain moo/zot
     *
     * without any compatibility kludges --- if the token after the
     * MIME type begins with a semicolon, we know we're looking at parms,
     * otherwise, we know we aren't.  (So why all the pissing and moaning
     * in the CERN server code?  I must be missing something).
     */
    
    result->type_name = get_token (p, &accept_line, 0);
    str_tolower (result->type_name); /* You want case-insensitive,
				      * you'll *get* case-insensitive.
				      */
    

    /* KLUDGE!!! Default HTML to level 2.0 unless the browser
     * *explicitly* says something else.
     */
	
    if (!strcmp (result->type_name, "text/html")
	&& result->level == 0.0)
	result->level = 2.0;
    else if (!strcmp (result->type_name, INCLUDES_MAGIC_TYPE))
	result->level = 2.0;
    else if (!strcmp (result->type_name, INCLUDES_MAGIC_TYPE3))
	result->level = 3.0;

    while (*accept_line == ';') {
	/* Parameters ... */

	char *parm;
	char *cp;
	    
	++accept_line;
	parm = get_token (p, &accept_line, 1);

	/* Look for 'var = value' --- and make sure the var is in lcase. */
	
	for (cp = parm; *cp && !isspace(*cp) && *cp != '='; ++cp)
	    *cp = tolower(*cp);

	if (!*cp) continue;	/* No '='; just ignore it. */
	    
	*cp++ = '\0';		/* Delimit var */
	while (*cp && (isspace(*cp) || *cp == '='))
	    ++cp;

	if (*cp == '"') ++cp;
	
	if (parm[0] == 'q'
	    && (parm[1] == '\0' || (parm[1] == 's' && parm[2] == '\0')))
	    result->quality = atof(cp);
	else if (parm[0] == 'm' && parm[1] == 'x' &&
		 parm[2] == 'b' && parm[3] == '\0')
	    result->max_bytes = atof(cp);
	else if (parm[0] == 'l' && !strcmp (&parm[1], "evel"))
	    result->level = atof(cp);
    }

    if (*accept_line == ',') ++accept_line;

    return accept_line;
}
		 

/*****************************************************************
 *
 * Dealing with header lines ...
 */

array_header *do_header_line (pool *p, char *accept_line)
{
    array_header *accept_recs = make_array (p, 40, sizeof (accept_rec));
  
    if (!accept_line) return accept_recs;
    
    while (*accept_line) {
        accept_rec *new = (accept_rec *)push_array (accept_recs);
	accept_line = get_entry (p, new, accept_line);
    }

    return accept_recs;
}

/*****************************************************************
 *
 * Handling header lines from clients...
 */

negotiation_state *parse_accept_headers (request_rec *r)
{
    negotiation_state *new =
        (negotiation_state *)palloc (r->pool, sizeof (negotiation_state));
    table *hdrs = r->headers_in;

    new->pool = r->pool;
    new->r = r;
    new->dir_name = make_dirstr(r->pool, r->filename, count_dirs(r->filename));
    
    new->accepts = do_header_line (r->pool, table_get (hdrs, "Accept"));
    new->accept_encodings =
      do_header_line (r->pool, table_get (hdrs, "Accept-encoding"));
    new->accept_langs =
      do_header_line (r->pool, table_get (hdrs, "Accept-language"));
    new->avail_vars = make_array (r->pool, 40, sizeof (var_rec));

    return new;
}

/* Sometimes clients will give us no Accept info at all; this routine sets
 * up the standard default for that case, and also arranges for us to be
 * willing to run a CGI script if we find one.  (In fact, we set up to
 * dramatically prefer CGI scripts in cases where that's appropriate,
 * e.g., POST).
 */

void maybe_add_default_encodings(negotiation_state *neg, int prefer_scripts)
{
    accept_rec *new_accept = (accept_rec *)push_array (neg->accepts); 
  
    new_accept->type_name = CGI_MAGIC_TYPE;
    new_accept->quality = prefer_scripts ? 1e-20 : 1e20;
    new_accept->level = 0.0;
    new_accept->max_bytes = 0.0;

    if (neg->accepts->nelts > 1) return;
    
    new_accept = (accept_rec *)push_array (neg->accepts); 
    
    new_accept->type_name = "*/*";
    new_accept->quality = 1.0;
    new_accept->level = 0.0;
    new_accept->max_bytes = 0.0;
}

/*****************************************************************
 *
 * Parsing type-map files, in Roy's meta/http format augmented with
 * #-comments.
 */

/* Reading RFC822-style header lines, ignoring #-comments and
 * handling continuations.
 */

enum header_state { header_eof, header_seen, header_sep };

enum header_state get_header_line (char *buffer, int len, FILE *map)
{
    char *buf_end = buffer + len;
    char *cp;
    int c;
    
    /* Get a noncommented line */
    
    do {
	if (fgets(buffer, MAX_STRING_LEN, map) == NULL)
	    return header_eof;
    } while (buffer[0] == '#');
    
    /* If blank, just return it --- this ends information on this variant */
    
    for (cp = buffer; *cp && isspace (*cp); ++cp)
      continue;

    if (*cp == '\0') return header_sep;

    /* If non-blank, go looking for header lines, but note that we still
     * have to treat comments specially...
     */

    cp += strlen(cp);
    
    while ((c = getc(map)) != EOF)
    {
	if (c == '#') {
	    /* Comment line */
	    while ((c = getc(map)) != EOF && c != '\n')
	       continue;
	} else if (isspace(c)) {
	    /* Leading whitespace.  POSSIBLE continuation line
	     * Also, possibly blank --- if so, we ungetc() the final newline
	     * so that we will pick up the blank line the next time 'round.
	     */
	    
	    while (c != EOF && c != '\n' && isspace(c))
	        c = getc(map);

	    ungetc (c, map);
	    
	    if (c == '\n') return header_seen; /* Blank line */

	    /* Continuation */

	    while (cp < buf_end - 2 && (c = getc(map)) != EOF && c != '\n')
	        *cp++ = c;

	    *cp++ = '\n';
	    *cp = '\0';
	} else {

	    /* Line beginning with something other than whitespace */
	    
	    ungetc (c, map);
	    return header_seen;
	}
    }

    return header_seen;
}

/* Stripping out RFC822 comments */

void strip_paren_comments (char *hdr)
{
    /* Hmmm... is this correct?  In Roy's latest draft, (comments) can nest! */
  
    while (*hdr) {
	if (*hdr == '"') {
	    while (*++hdr && *hdr != '"')
		continue;
	    ++hdr;
	}
	else if (*hdr == '(') {
	    while (*hdr && *hdr != ')')	*hdr++ = ' ';
	    
	    if (*hdr) *hdr++ = ' ';
	}
	else ++hdr;
    }
}

/* Getting to a header body from the header */

char *lcase_header_name_return_body (char *header, request_rec *r)
{
    char *cp = header;
    
    while (*cp && *cp != ':')
        *cp++ = tolower(*cp);
    
    if (!*cp) {
	log_reason ("Syntax error in type map --- no ':'", r->filename, r);
	return NULL;
    }

    do ++cp; while (*cp && isspace (*cp));

    if (!*cp) {
	log_reason ("Syntax error in type map --- no header body",
		    r->filename, r);
	return NULL;
    }

    return cp;
}

int read_type_map (negotiation_state *neg, char *map_name)
{
    request_rec *r = neg->r;
    FILE *map = pfopen (neg->pool, map_name, "r");

    char buffer[MAX_STRING_LEN];
    enum header_state hstate;
    struct var_rec mime_info;
    
    if (map == NULL) {
        log_reason("cannot access type map file", map_name, r);
	return FORBIDDEN;
    }

    clean_var_rec (&mime_info);
    
    do {
	hstate = get_header_line (buffer, MAX_STRING_LEN, map);
	
	if (hstate == header_seen) {
	    char *body = lcase_header_name_return_body (buffer, neg->r);
	    
	    if (body == NULL) return SERVER_ERROR;
	    
	    strip_paren_comments (body);
	    
	    if (!strncmp (buffer, "uri:", 4)) {
	        mime_info.file_name = get_token (neg->pool, &body, 0);
	    }
	    else if (!strncmp (buffer, "content-type:", 13)) {
		struct accept_rec accept_info;
		
		get_entry (neg->pool, &accept_info, body);
		set_mime_fields (&mime_info, &accept_info);
	    }
	    else if (!strncmp (buffer, "content-length:", 15)) {
		mime_info.bytes = atoi(body);
	    }
	    else if (!strncmp (buffer, "content-language:", 17)) {
		mime_info.content_language = get_token (neg->pool, &body, 0);
		str_tolower (mime_info.content_language);
	    }
	    else if (!strncmp (buffer, "content-encoding:", 17)) {
		mime_info.content_encoding = get_token (neg->pool, &body, 0);
		str_tolower (mime_info.content_encoding);
	    }
	} else {
	    if (mime_info.quality > 0) {
	        void *new_var = push_array (neg->avail_vars);
		memcpy (new_var, (void *)&mime_info, sizeof (var_rec));
	    }
	    
	    clean_var_rec(&mime_info);
	}
    } while (hstate != header_eof);
    
    pfclose (neg->pool, map);
    return OK;
}

/*****************************************************************
 *
 * Same, except we use a filtered directory listing as the map...
 */

int read_types_multi (negotiation_state *neg)
{
    request_rec *r = neg->r;
    
    char *filp;
    int prefix_len;
    DIR *dirp;
    struct DIR_TYPE *dir_entry;
    struct var_rec mime_info;
    struct accept_rec accept_info;
    void *new_var;

    clean_var_rec (&mime_info);

    if (!(filp = strrchr (r->filename, '/'))) return DECLINED; /* Weird... */

    ++filp;
    prefix_len = strlen (filp);

    dirp = opendir (neg->dir_name); /* Not pool protected; sigh... */

    if (dirp == NULL) {
        log_reason("cannot read directory for multi", neg->dir_name, r);
	return FORBIDDEN;
    }

    while ((dir_entry = readdir (dirp))) {
	
        request_rec *sub_req;
      
	/* Do we have a match? */
	
	if (strncmp (dir_entry->d_name, filp, prefix_len)) continue;
	if (dir_entry->d_name[prefix_len] != '.') continue;
	
	/* Yep.  See if it's something which we have access to, and 
	 * which has a known type and encoding (as opposed to something
	 * which we'll be slapping default_type on later).
	 */
	
	sub_req = sub_req_lookup_file (dir_entry->d_name, r);

	/* If it has a handler, we'll pretend it's a CGI script,
	 * since that's a good indication of the sort of thing it
	 * might be doing.
	 */
	if (sub_req->handler && !sub_req->content_type)
	  sub_req->content_type = CGI_MAGIC_TYPE;

	if (sub_req->status != 200 || !sub_req->content_type) continue;
	
	/* If it's a map file, we use that instead of the map
	 * we're building...
	 */

	if (((sub_req->content_type) &&
	     !strcmp (sub_req->content_type, MAP_FILE_MAGIC_TYPE)) || 
	    ((sub_req->handler) && 
	    !strcmp (sub_req->handler, "type-map"))) {
	    closedir(dirp);
	    
	    neg->avail_vars->nelts = 0;
	    return read_type_map (neg, sub_req->filename);
	}
	
	/* Have reasonable variant --- gather notes.
	 */
	
	mime_info.sub_req = sub_req;
	mime_info.file_name = pstrdup(neg->pool, dir_entry->d_name);
	mime_info.content_encoding = sub_req->content_encoding;
	mime_info.content_language = sub_req->content_language;
	
	get_entry (neg->pool, &accept_info, sub_req->content_type);
	set_mime_fields (&mime_info, &accept_info);
	
	new_var = push_array (neg->avail_vars);
	memcpy (new_var, (void *)&mime_info, sizeof (var_rec));
	    
	clean_var_rec(&mime_info);
    }

    closedir(dirp);
    return OK;
}


/*****************************************************************
 * And now for the code you've been waiting for... actually
 * finding a match to the client's requirements.
 */

/* Matching MIME types ... the star/star and foo/star commenting conventions
 * are implemented here.  (You know what I mean by star/star, but just
 * try mentioning those three characters in a C comment).  Using strcmp()
 * is legit, because everything has already been smashed to lowercase.
 *
 * Note also that if we get an exact match on the media type, we update
 * level_matched for use in level_cmp below...
 * 
 * We also give a value for mime_stars, which is used later. It should
 * be 1 for star/star, 2 for type/star and 3 for type/subtype.
 */

int mime_match (accept_rec *accept, var_rec *avail)
{
    char *accept_type = accept->type_name;
    char *avail_type = avail->type_name;
    int len = strlen(accept_type);
  
    if (accept_type[0] == '*')	{ /* Anything matches star/star */
        if (avail->mime_stars < 1)
	  avail->mime_stars = 1;
	return 1; 
    }
    else if ((accept_type[len - 1] == '*') &&
	     !strncmp (accept_type, avail_type, len - 2)) {
        if (avail->mime_stars < 2)
	  avail->mime_stars = 2;
	return 1;
    }
    else if (!strcmp (accept_type, avail_type)
	     || (!strcmp (accept_type, "text/html")
		 && (!strcmp(avail_type, INCLUDES_MAGIC_TYPE)
		     || !strcmp(avail_type, INCLUDES_MAGIC_TYPE3)))) {
	if (accept->level >= avail->level) {
	    avail->level_matched = avail->level;
	    avail->mime_stars = 3;
	    return 1;
	}
    }

    return OK;
}

/* This code implements a piece of the tie-breaking algorithm between
 * variants of equal quality.  This piece is the treatment of variants
 * of the same base media type, but different levels.  What we want to
 * return is the variant at the highest level that the client explicitly
 * claimed to accept.
 *
 * If all the variants available are at a higher level than that, or if
 * the client didn't say anything specific about this media type at all
 * and these variants just got in on a wildcard, we prefer the lowest
 * level, on grounds that that's the one that the client is least likely
 * to choke on.
 *
 * (This is all motivated by treatment of levels in HTML --- we only
 * want to give level 3 to browsers that explicitly ask for it; browsers
 * that don't, including HTTP/0.9 browsers that only get the implicit
 * "Accept: * / *" [space added to avoid confusing cpp --- no, that
 * syntax doesn't really work] should get HTML2 if available).
 *
 * (Note that this code only comes into play when we are choosing among
 * variants of equal quality, where the draft standard gives us a fair
 * bit of leeway about what to do.  It ain't specified by the standard;
 * rather, it is a choice made by this server about what to do in cases
 * where the standard does not specify a unique course of action).
 */

int level_cmp (var_rec *var1, var_rec *var2)
{
    /* Levels are only comparable between matching media types */

    if (var1->is_pseudo_html && !var2->is_pseudo_html)
	return 0;
    
    if (!var1->is_pseudo_html && strcmp (var1->type_name, var2->type_name))
	return 0;
    
    /* Take highest level that matched, if either did match. */
    
    if (var1->level_matched > var2->level_matched) return 1;
    if (var1->level_matched < var2->level_matched) return -1;

    /* Neither matched.  Take lowest level, if there's a difference. */

    if (var1->level < var2->level) return 1;
    if (var1->level > var2->level) return -1;

    /* Tied */

    return 0;
}

/* Finding languages.  Note that we only match the substring specified
 * by the Accept: line --- this is to allow "en" to match all subvariants
 * of English.
 *
 * Again, strcmp() is legit because we've ditched case already.
 */

int find_lang_index (array_header *accept_langs, char *lang)
{
    accept_rec *accs;
    int i;

    if (!lang)
	return -1;

    accs = (accept_rec *)accept_langs->elts;

    for (i = 0; i < accept_langs->nelts; ++i)
	if (!strncmp (lang, accs[i].type_name, strlen(accs[i].type_name)))
	    return i;
	    
    return -1;		
}

/* This function returns the priority of a given language
 * according to LanguagePriority.  It is used in case of a tie
 * between several languages.
 */

int find_default_index (neg_dir_config *conf, char *lang)
{
    array_header *arr;
    int nelts;
    char **elts;
    int i;

    if (!lang)
	return -1;

    arr = conf->language_priority;
    nelts = arr->nelts;
    elts = (char **) arr->elts;

    for (i = 0; i < nelts; ++i)
        if (!strcasecmp (elts[i], lang))
	    return i;

    return -1;
}

void find_lang_indexes (negotiation_state *neg)
{
    var_rec *var_recs = (var_rec*)neg->avail_vars->elts;
    int i;
    int found_any = 0;
    neg_dir_config *conf = NULL;
    int naccept = neg->accept_langs->nelts;

    if (naccept == 0)
	conf = (neg_dir_config *) get_module_config (neg->r->per_dir_config,
						     &negotiation_module);

    for (i = 0; i < neg->avail_vars->nelts; ++i)
	if (var_recs[i].quality > 0) {
	    int index;
	    if (naccept == 0)		/* Client doesn't care */
		index = find_default_index (conf,
					    var_recs[i].content_language);
	    else			/* Client has Accept-Language */
		index = find_lang_index (neg->accept_langs,
					 var_recs[i].content_language);

	    var_recs[i].lang_index = index;
	    if (index >= 0) found_any = 1;
	}

    /* If we have any variants in a language acceptable to the client,
     * blow away everything that isn't.
     */
    
    if (found_any)
	for (i = 0; i < neg->avail_vars->nelts; ++i) 
	    if (var_recs[i].lang_index < 0)
		var_recs[i].quality = 0;
}

/* Finding content encodings.  Note that we assume that the client
 * accepts the trivial encodings.  Strcmp() is legit because... aw, hell.
 */

int is_identity_encoding (char *enc)
{
    return (!enc || !enc[0] || !strcmp (enc, "7bit") || !strcmp (enc, "8bit")
	    || !strcmp (enc, "binary"));
}

int find_encoding (array_header *accept_encodings, char *enc)
{
    accept_rec *accs = (accept_rec *)accept_encodings->elts;
    int i;

    if (is_identity_encoding(enc)) return 1;

    for (i = 0; i < accept_encodings->nelts; ++i)
	if (!strcmp (enc, accs[i].type_name))
	    return 1;

    return 0;
}

void do_encodings (negotiation_state *neg)
{
    var_rec *var_recs = (var_rec*)neg->avail_vars->elts;
    int i;

    /* If no Accept-Encoding is present, everything is acceptable */

    if (!neg->accept_encodings->nelts)
	return;

    /* Lose any variant with an unacceptable content encoding */
    
    for (i = 0; i < neg->avail_vars->nelts; ++i)
	if (var_recs[i].quality > 0
	    && !find_encoding (neg->accept_encodings,
			       var_recs[i].content_encoding))
	    
	    var_recs[i].quality = 0;
}

/* Determining the content length --- if the map didn't tell us,
 * we have to do a stat() and remember for next time.
 *
 * Grump.  For shambhala, even the first stat here may well be
 * redundant (for multiviews) with a stat() done by the sub_req
 * machinery.  At some point, that ought to be fixed.
 */

int find_content_length(negotiation_state *neg, var_rec *variant)
{
    struct stat statb;

    if (variant->bytes == 0) {
        char *fullname = make_full_path (neg->pool, neg->dir_name,
					 variant->file_name);
	
	if (stat (fullname, &statb) >= 0) variant->bytes = statb.st_size;
    }

    return variant->bytes;
}

/* The main event. */

var_rec *best_match(negotiation_state *neg)
{
    int i, j;
    var_rec *best = NULL;
    float best_quality = 0.0;
    int levcmp;
    
    accept_rec *accept_recs = (accept_rec *)neg->accepts->elts;
    var_rec *avail_recs = (var_rec *)neg->avail_vars->elts;

    /* Nuke variants which are unsuitable due to a content encoding,
     * or possibly a language, which the client doesn't accept.
     * (If we haven't *got* a variant in a language the client accepts,
     * find_lang_indexes keeps 'em all, so we still wind up serving
     * something...).
     */
    
    do_encodings (neg);
    find_lang_indexes (neg);
    
    for (i = 0; i < neg->accepts->nelts; ++i) {

	accept_rec *type = &accept_recs[i];
	
	for (j = 0; j < neg->avail_vars->nelts; ++j) {
	    
	    var_rec *variant = &avail_recs[j];
	    float q = type->quality * variant->quality;
		
	    /* If we've already rejected this variant, don't waste time */
	    
	    if (q == 0.0) continue;	
	    
	    /* If media types don't match, forget it.
	     * (This includes the level check).
	     */
	    
	    if (!mime_match(type, variant)) continue;

	    /* Check maxbytes */
		
	    if (type->max_bytes > 0
		&& (find_content_length(neg, variant)
		    > type->max_bytes))
		continue;
		
	    /* If it lasted this far, consider it ---
	     * If better quality than our current best, take it.
	     * If equal quality, *maybe* take it.
	     *
	     * Note that the current http draft specifies no particular
	     * behavior for variants which tie in quality; the server
	     * can, at its option, return a 300 response listing all
	     * of them (and perhaps the others), or choose one of the
	     * tied variants by whatever means it likes.  This server
	     * breaks ties as follows, in order:
	     *
	     * By perferring non-wildcard entries to those with
	     * wildcards. The spec specifically says we should
	     * do this, and it makes a lot of sense.
	     *
	     * By order of languages in Accept-language, to give the
	     * client a way to specify a language preference.  I'd prefer
	     * to give this precedence over media type, but the standard
	     * doesn't allow for that.
	     *
	     * By level preference, as defined by level_cmp above.
	     *
	     * By order of Accept: header matched, so that the order in
	     * which media types are named by the client functions as a
	     * preference order, if the client didn't give us explicit
	     * quality values.
	     *
	     * Finally, by content_length, so that among variants which
	     * have the same quality, language and content_type (including
	     * level) we ship the one that saps the least bandwidth.
	     */
		
	    if (q > best_quality
		|| (q == best_quality
		    && ((variant->mime_stars > best->mime_stars)
			|| (variant->lang_index < best->lang_index
			    || (variant->lang_index == best->lang_index
				&& ((levcmp = level_cmp (variant, best)) == 1
				    || (levcmp == 0
					&& !strcmp (variant->type_name,
						    best->type_name)
					&& (find_content_length(neg, variant)
					    <
				find_content_length(neg, best)))))))))
	    {
		best = variant;
		best_quality = q;
	    }
	}
    }

    return best;
}

/****************************************************************
 *
 * Executive...
 */

int handle_map_file (request_rec *r)
{
    negotiation_state *neg = parse_accept_headers (r);
    var_rec *best;
    int res;
    
    char *udir;
    
    if ((res = read_type_map (neg, r->filename))) return res;
    
    maybe_add_default_encodings(neg, 0);
    
    if (!(best = best_match(neg))) {
      /* Should be a 406 */
      log_reason ("no acceptable variant", r->filename, r);
      return NOT_FOUND;
    }

    if (!do_cache_negotiated_docs(r->server)) r->no_cache = 1;
    udir = make_dirstr (r->pool, r->uri, count_dirs (r->uri));
    udir = escape_uri(r->pool, udir);
    internal_redirect (make_full_path (r->pool, udir, best->file_name), r);
    return OK;
}

int handle_multi (request_rec *r)
{
    negotiation_state *neg;
    var_rec *best;
    request_rec *sub_req;
    int res;
    
    if (r->finfo.st_mode != 0 || !(allow_options (r) & OPT_MULTI))
        return DECLINED;
    
    neg = parse_accept_headers (r);
    
    if ((res = read_types_multi (neg))) return res;
    
    maybe_add_default_encodings(neg,
				r->method_number != M_GET
				  || r->args || r->path_info);
    
    if (neg->avail_vars->nelts == 0) return DECLINED;
    
    if (!(best = best_match(neg))) {
      /* Should be a 406 */
      log_reason ("no acceptable variant", r->filename, r);
      return NOT_FOUND;
    }

    if (! (sub_req = best->sub_req)) {
        /* We got this out of a map file, so we don't actually have
	 * a sub_req structure yet.  Get one now.
	 */
      
        sub_req = sub_req_lookup_file (best->file_name, r);
	if (sub_req->status != 200) return sub_req->status;
    }
      
    /* BLETCH --- don't multi-resolve non-ordinary files */

    if (!S_ISREG(sub_req->finfo.st_mode)) return NOT_FOUND;
    
    /* Otherwise, use it. */
    
    if (!do_cache_negotiated_docs(r->server)) r->no_cache = 1;
    r->filename = sub_req->filename;
    r->handler = sub_req->handler;
    r->content_type = sub_req->content_type;
    r->content_encoding = sub_req->content_encoding;
    r->content_language = sub_req->content_language;
    r->finfo = sub_req->finfo;
    
    return OK;
}

handler_rec negotiation_handlers[] = {
{ MAP_FILE_MAGIC_TYPE, handle_map_file },
{ "type-map", handle_map_file },
{ NULL }
};

module negotiation_module = {
   STANDARD_MODULE_STUFF,
   NULL,			/* initializer */
   create_neg_dir_config,	/* dir config creater */
   merge_neg_dir_configs,	/* dir merger --- default is to override */
   NULL,			/* server config */
   NULL,			/* merge server config */
   negotiation_cmds,		/* command table */
   negotiation_handlers,	/* handlers */
   NULL,			/* filename translation */
   NULL,			/* check_user_id */
   NULL,			/* check auth */
   NULL,			/* check access */
   handle_multi,		/* type_checker */
   NULL,			/* fixups */
   NULL				/* logger */
};
