/* ====================================================================
 * Copyright (c) 1995-1997 The Apache Group.  All rights reserved.
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
 * http_mime.c: Sends/gets MIME headers for requests
 * 
 * Rob McCool
 * 
 */

#define MIME_PRIVATE

#include "httpd.h"
#include "http_config.h"

typedef struct {
    table *forced_types;	/* Additional AddTyped stuff */
    table *encoding_types;	/* Added with AddEncoding... */
    table *language_types;	/* Added with AddLanguage... */
    table *handlers;		/* Added with AddHandler...  */

    char *type;			/* Type forced with ForceType  */
    char *handler;		/* Handler forced with SetHandler */
} mime_dir_config;

module mime_module;

void *create_mime_dir_config (pool *p, char *dummy)
{
    mime_dir_config *new =
      (mime_dir_config *) palloc (p, sizeof(mime_dir_config));

    new->forced_types = make_table (p, 4);
    new->encoding_types = make_table (p, 4);
    new->language_types = make_table (p, 4);
    new->handlers = make_table (p, 4);

    new->type = NULL;
    new->handler = NULL;
    
    return new;
}

void *merge_mime_dir_configs (pool *p, void *basev, void *addv)
{
    mime_dir_config *base = (mime_dir_config *)basev;
    mime_dir_config *add = (mime_dir_config *)addv;
    mime_dir_config *new =
      (mime_dir_config *)palloc (p, sizeof(mime_dir_config));

    new->forced_types = overlay_tables (p, add->forced_types,
					base->forced_types);
    new->encoding_types = overlay_tables (p, add->encoding_types,
					  base->encoding_types);
    new->language_types = overlay_tables (p, add->language_types,
					  base->language_types);
    new->handlers = overlay_tables (p, add->handlers,
					  base->handlers);

    new->type = add->type ? add->type : base->type;
    new->handler = add->handler ? add->handler : base->handler;

    return new;
}

const char *add_type(cmd_parms *cmd, mime_dir_config *m, char *ct, char *ext)
{
    if (*ext == '.') ++ext;
    table_set (m->forced_types, ext, ct);
    return NULL;
}

const char *add_encoding(cmd_parms *cmd, mime_dir_config *m, char *enc,
			 char *ext)
{
    if (*ext == '.') ++ext;
    table_set (m->encoding_types, ext, enc);
    return NULL;
}

const char *add_language(cmd_parms *cmd, mime_dir_config *m, char *lang,
			 char *ext)
{
    if (*ext == '.') ++ext;
    table_set (m->language_types, ext, lang);
    return NULL;
}

const char *add_handler(cmd_parms *cmd, mime_dir_config *m, char *hdlr,
			char *ext)
{
    if (*ext == '.') ++ext;
    table_set (m->handlers, ext, hdlr);
    return NULL;
}

/* The sole bit of server configuration that the MIME module has is
 * the name of its config file, so...
 */

const char *set_types_config (cmd_parms *cmd, void *dummy, char *arg)
{
    set_module_config (cmd->server->module_config, &mime_module,
		       pstrdup (cmd->pool, arg));
    return NULL;
}

command_rec mime_cmds[] = {
{ "AddType", add_type, NULL, OR_FILEINFO, ITERATE2,
    "a mime type followed by one or more file extensions" },
{ "AddEncoding", add_encoding, NULL, OR_FILEINFO, ITERATE2,
    "an encoding (e.g., gzip), followed by one or more file extensions" },
{ "AddLanguage", add_language, NULL, OR_FILEINFO, ITERATE2,
    "a language (e.g., fr), followed by one or more file extensions" },
{ "AddHandler", add_handler, NULL, OR_FILEINFO, ITERATE2,
    "a handler name followed by one or more file extensions" },
{ "ForceType", set_string_slot, (void*)XtOffsetOf(mime_dir_config, type),
    OR_FILEINFO, TAKE1, "a media type" },
{ "SetHandler", set_string_slot, (void*)XtOffsetOf(mime_dir_config, handler),
    OR_FILEINFO, TAKE1, "a handler name" },
{ "TypesConfig", set_types_config, NULL, RSRC_CONF, TAKE1,
    "the MIME types config file" },
{ NULL }
};

/* Hash table  --- only one of these per daemon; virtual hosts can
 * get private versions through AddType...
 */

#define MIME_HASHSIZE 27
#define hash(i) (isalpha(i) ? (tolower(i)) - 'a' : 26)

static table *hash_buckets[MIME_HASHSIZE];

void init_mime (server_rec *s, pool *p)
{
    FILE *f;
    char l[MAX_STRING_LEN];
    int x;
    char *types_confname = get_module_config (s->module_config, &mime_module);

    if (!types_confname) types_confname = TYPES_CONFIG_FILE;

    types_confname = server_root_relative (p, types_confname);

    if(!(f = fopen(types_confname,"r"))) {
        perror("fopen");
        fprintf(stderr,"httpd: could not open mime types file %s\n",
                types_confname);
        exit(1);
    }

    for(x=0;x<27;x++) 
        hash_buckets[x] = make_table (p, 10);

    while(!(cfg_getline(l,MAX_STRING_LEN,f))) {
        const char *ll = l, *ct;
      
        if(l[0] == '#') continue;
        ct = getword_conf (p, &ll);

        while(ll[0]) {
            char *ext = getword_conf (p, &ll);
	    str_tolower (ext);	/* ??? */
	    table_set (hash_buckets[hash(ext[0])], ext, ct);
        }
    }
    fclose(f);
}

int find_ct(request_rec *r)
{
    const char *fn = strrchr(r->filename, '/');
    mime_dir_config *conf =
      (mime_dir_config *)get_module_config(r->per_dir_config, &mime_module);
    char *ext, *type, *orighandler = r->handler;

    if (S_ISDIR(r->finfo.st_mode)) {
        r->content_type = DIR_MAGIC_TYPE;
	return OK;
    }

    /* TM -- FIXME
     * 
     * if r->filename does not contain a '/', the following passes a null
     * pointer to getword, causing a SEGV ..
     */

    if(fn == NULL) fn = r->filename;

    /* Parse filename extensions, which can be in any order */
    while ((ext = getword(r->pool, &fn, '.')) && *ext) {
      int found = 0;

      /* Check for Content-Type */
      if ((type = table_get (conf->forced_types, ext))
	  || (type = table_get (hash_buckets[hash(*ext)], ext))) {
          r->content_type = type;
	  found = 1;
      }

      /* Check for Content-Language */
      if ((type = table_get (conf->language_types, ext))) {
	  char **new;

	  r->content_language = type; /* back compat. only */
	  if (!r->content_languages)
	      r->content_languages = make_array (r->pool, 2, sizeof(char*));
	  new = (char **)push_array (r->content_languages);
	  *new = type;
	  found = 1;
      }
	
      /* Check for Content-Encoding */
      if ((type = table_get (conf->encoding_types, ext))) {
	  if (!r->content_encoding)
	      r->content_encoding = type;
	  else
	      r->content_encoding = pstrcat(r->pool, r->content_encoding,
					    ", ", type, NULL);
	  found = 1;
      }

      /* Check for a special handler, but not for proxy request */
      if ((type = table_get (conf->handlers, ext)) && !r->proxyreq) {
	  r->handler = type;
	  found = 1;
      }

      /* This is to deal with cases such as foo.gif.bak, which we want
       * to not have a type. So if we find an unknown extension, we
       * zap the type/language/encoding and reset the handler
       */

      if (!found) {
	r->content_type = NULL;
	r->content_language = NULL;
	r->content_languages = NULL;
	r->content_encoding = NULL;
	r->handler = orighandler;
      }

    }

    /* Check for overrides with ForceType/SetHandler */

    if (conf->type && strcmp(conf->type, "none"))
        r->content_type = pstrdup(r->pool, conf->type);
    if (conf->handler && strcmp(conf->handler, "none"))
        r->handler = pstrdup(r->pool, conf->handler);

    if (!r->content_type) return DECLINED;

    return OK;
}


module mime_module = {
   STANDARD_MODULE_STUFF,
   init_mime,			/* initializer */
   create_mime_dir_config,
   merge_mime_dir_configs,
   NULL,			/* server config */
   NULL,			/* merge server config */
   mime_cmds,
   NULL,			/* handlers */
   NULL,			/* filename translation */
   NULL,			/* check_user_id */
   NULL,			/* check auth */
   NULL,			/* check access */
   find_ct,			/* type_checker */
   NULL,			/* fixups */
   NULL,			/* logger */
   NULL				/* header parser */
};
