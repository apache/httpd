
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
 * http_dir.c: Handles the on-the-fly html index generation
 * 
 * Rob McCool
 * 3/23/93
 * 
 * Adapted to Shambhala by rst.
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_request.h"
#include "http_protocol.h"
#include "http_log.h"
#include "http_main.h"
#include "util_script.h"

module dir_module;

/****************************************************************
 *
 * Handling configuration directives...
 */

#define FANCY_INDEXING 1	/* Indexing options */
#define ICONS_ARE_LINKS 2
#define SCAN_HTML_TITLES 4
#define SUPPRESS_LAST_MOD 8
#define SUPPRESS_SIZE 16
#define SUPPRESS_DESC 32

struct item {
    char *type;
    char *apply_to;
    char *apply_path;
    char *data;
};

typedef struct dir_config_struct {

    char *default_icon;
    char *index_names;
  
    array_header *icon_list, *alt_list, *desc_list, *ign_list;
    array_header *hdr_list, *rdme_list, *opts_list;
  
} dir_config_rec;

char c_by_encoding, c_by_type, c_by_path;

#define BY_ENCODING &c_by_encoding
#define BY_TYPE &c_by_type
#define BY_PATH &c_by_path

void push_item(array_header *arr, char *type, char *to, char *path, char *data)
{
    struct item *p = (struct item *)push_array(arr);

    if (!to) to = "";
    if (!path) path = "";
    
    p->type = type;
    p->data = data ? pstrdup(arr->pool, data): NULL;
    p->apply_path = pstrcat(arr->pool, path, "*", NULL);
    
    if((type == BY_PATH) && (!is_matchexp(to)))
        p->apply_to = pstrcat (arr->pool, "*", to, NULL);
    else if (to)
        p->apply_to = pstrdup (arr->pool, to);
    else
        p->apply_to = NULL;
}

char *add_alt(cmd_parms *cmd, void *d, char *alt, char *to)
{
    if (cmd->info == BY_PATH)
        if(!strcmp(to,"**DIRECTORY**"))
            to = "^^DIRECTORY^^";

    push_item(((dir_config_rec *)d)->alt_list, cmd->info, to, cmd->path, alt);
    return NULL;
}

char *add_icon(cmd_parms *cmd, void *d, char *icon, char *to)
{
    char *iconbak = pstrdup (cmd->pool, icon);

    if(icon[0] == '(') {
        char *alt = getword (cmd->pool, &iconbak, ',');
        iconbak[strlen(iconbak) - 1] = '\0'; /* Lose closing paren */
        add_alt(cmd, d, &alt[1], to);
    }
    if(cmd->info == BY_PATH) 
        if(!strcmp(to,"**DIRECTORY**"))
            to = "^^DIRECTORY^^";

    push_item(((dir_config_rec *)d)->icon_list, cmd->info, to, cmd->path,
	      iconbak);
    return NULL;
}

char *add_desc(cmd_parms *cmd, void *d, char *desc, char *to)
{
    push_item(((dir_config_rec *)d)->desc_list, cmd->info, to, cmd->path,desc);
    return NULL;
}

char *add_ignore(cmd_parms *cmd, void *d, char *ext) {
    push_item(((dir_config_rec *)d)->ign_list, 0, ext, cmd->path, NULL);
    return NULL;
}

char *add_header(cmd_parms *cmd, void *d, char *name) {
    push_item(((dir_config_rec *)d)->hdr_list, 0, NULL, cmd->path, name);
    return NULL;
}

char *add_readme(cmd_parms *cmd, void *d, char *name) {
    push_item(((dir_config_rec *)d)->rdme_list, 0, NULL, cmd->path, name);
    return NULL;
}


char *add_opts_int(cmd_parms *cmd, void *d, int opts) {
    push_item(((dir_config_rec *)d)->opts_list, (char*)opts, NULL,
	      cmd->path, NULL);
    return NULL;
}

char *fancy_indexing (cmd_parms *cmd, void *d, int arg)
{
    return add_opts_int (cmd, d, arg? FANCY_INDEXING : 0);
}

char *add_opts(cmd_parms *cmd, void *d, char *optstr) {
    char *w;
    int opts = 0;

    while(optstr[0]) {
        w = getword_conf(cmd->pool, &optstr);
        if(!strcasecmp(w,"FancyIndexing"))
            opts |= FANCY_INDEXING;
        else if(!strcasecmp(w,"IconsAreLinks"))
            opts |= ICONS_ARE_LINKS;
        else if(!strcasecmp(w,"ScanHTMLTitles"))
            opts |= SCAN_HTML_TITLES;
        else if(!strcasecmp(w,"SuppressLastModified"))
            opts |= SUPPRESS_LAST_MOD;
        else if(!strcasecmp(w,"SuppressSize"))
            opts |= SUPPRESS_SIZE;
        else if(!strcasecmp(w,"SuppressDescription"))
            opts |= SUPPRESS_DESC;
        else if(!strcasecmp(w,"None"))
            opts = 0;
	else
	    return "Invalid directory indexing option";
    }
    return add_opts_int(cmd, d, opts);
}

#define DIR_CMD_PERMS OR_INDEXES

command_rec dir_cmds[] = {
{ "AddIcon", add_icon, BY_PATH, DIR_CMD_PERMS, ITERATE2,
    "an icon URL followed by one or more filenames" },
{ "AddIconByType", add_icon, BY_TYPE, DIR_CMD_PERMS, ITERATE2,
    "an icon URL followed by one or more MIME types" },
{ "AddIconByEncoding", add_icon, BY_ENCODING, DIR_CMD_PERMS, ITERATE2,
    "an icon URL followed by one or more content encodings" },
{ "AddAlt", add_alt, BY_PATH, DIR_CMD_PERMS, ITERATE2,
    "alternate descriptive text followed by one or more filenames" },
{ "AddAltByType", add_alt, BY_TYPE, DIR_CMD_PERMS, ITERATE2,
    "alternate descriptive text followed by one or more MIME types" },
{ "AddAltByEncoding", add_alt, BY_ENCODING, DIR_CMD_PERMS, ITERATE2,
    "alternate descriptive text followed by one or more content encodings" },
{ "IndexOptions", add_opts, NULL, DIR_CMD_PERMS, RAW_ARGS,
    "one or more index options" },
{ "IndexIgnore", add_ignore, NULL, DIR_CMD_PERMS, ITERATE,
    "one or more file extensions" },
{ "AddDescription", add_desc, BY_PATH, DIR_CMD_PERMS, ITERATE2,
    "Descriptive text followed by one or more filenames" },
{ "HeaderName", add_header, NULL, DIR_CMD_PERMS, TAKE1, "a filename" },
{ "ReadmeName", add_readme, NULL, DIR_CMD_PERMS, TAKE1, "a filename" },
{ "FancyIndexing", fancy_indexing, NULL, DIR_CMD_PERMS, FLAG, NULL },
{ "DefaultIcon", set_string_slot,
    (void*)XtOffsetOf(dir_config_rec, default_icon),
    DIR_CMD_PERMS, TAKE1, "an icon URL"},
{ "DirectoryIndex", set_string_slot,
    (void*)XtOffsetOf(dir_config_rec, index_names),
    DIR_CMD_PERMS, RAW_ARGS, NULL },
{ NULL }
};

void *create_dir_config (pool *p, char *dummy)
{
    dir_config_rec *new =
        (dir_config_rec *) pcalloc (p, sizeof(dir_config_rec));

    new->index_names = NULL;
    new->icon_list = make_array (p, 4, sizeof (struct item));
    new->alt_list = make_array (p, 4, sizeof (struct item));
    new->desc_list = make_array (p, 4, sizeof (struct item));
    new->ign_list = make_array (p, 4, sizeof (struct item));
    new->hdr_list = make_array (p, 4, sizeof (struct item));
    new->rdme_list = make_array (p, 4, sizeof (struct item));
    new->opts_list = make_array (p, 4, sizeof (struct item));
    
    return (void *)new;
}

void *merge_dir_configs (pool *p, void *basev, void *addv)
{
    dir_config_rec *new=(dir_config_rec*)pcalloc (p, sizeof(dir_config_rec));
    dir_config_rec *base = (dir_config_rec *)basev;
    dir_config_rec *add = (dir_config_rec *)addv;

    new->default_icon = add->default_icon?add->default_icon:base->default_icon;
    new->index_names = add->index_names? add->index_names: base->index_names;

    new->alt_list = append_arrays (p, add->alt_list, base->alt_list);
    new->ign_list = append_arrays (p, add->ign_list, base->ign_list);
    new->hdr_list = append_arrays (p, add->hdr_list, base->hdr_list);
    new->desc_list = append_arrays (p, add->desc_list, base->desc_list);
    new->icon_list = append_arrays (p, add->icon_list, base->icon_list);
    new->rdme_list = append_arrays (p, add->rdme_list, base->rdme_list);
    new->opts_list = append_arrays (p, add->opts_list, base->opts_list);
    
    return new;
}

/****************************************************************
 *
 * Looking things up in config entries...
 */

/* Structure used to hold entries when we're actually building an index */

struct ent {
    char *name;
    char *icon;
    char *alt;
    char *desc;
    size_t size;
    time_t lm;
    struct ent *next;
};

char *find_item(request_rec *r, array_header *list, int path_only) {
    char *content_type = r->content_type;
    char *content_encoding = r->content_encoding;
    char *path = r->filename;

    struct item *items = (struct item *)list->elts;
    int i;

    for (i = 0; i < list->nelts; ++i) {
        struct item *p = &items[i];
      
        /* Special cased for ^^DIRECTORY^^ and ^^BLANKICON^^ */
        if((path[0] == '^') || (!strcmp_match(path,p->apply_path))) {
            if(!*(p->apply_to))
                return p->data;
            else if(p->type == BY_PATH || path[0] == '^') {
                if(!strcmp_match(path,p->apply_to))
                    return p->data;
            } else if(!path_only) {
                if(!content_encoding) {
                    if(p->type == BY_TYPE) {
                        if(content_type && !strcmp_match(content_type,p->apply_to))
                            return p->data;
                    }
                } else {
                    if(p->type == BY_ENCODING) {
                        if(!strcmp_match(content_encoding,p->apply_to))
                            return p->data;
                    }
                }
            }
        }
    }
    return NULL;
}

#define find_icon(d,p,t) find_item(p,d->icon_list,t)
#define find_alt(d,p,t) find_item(p,d->alt_list,t)
#define find_desc(d,p) find_item(p,d->desc_list,0)
#define find_header(d,p) find_item(p,d->hdr_list,0)
#define find_readme(d,p) find_item(p,d->rdme_list,0)

char *find_default_icon (dir_config_rec *d, char *bogus_name)
{
    request_rec r;

    /* Bleah.  I tried to clean up find_item, and it lead to this bit
     * of ugliness.   Note that the fields initialized are precisely
     * those that find_item looks at...
     */
    
    r.filename = bogus_name;
    r.content_type = r.content_encoding = NULL;

    return find_item (&r, d->icon_list, 1);
}

int ignore_entry(dir_config_rec *d, char *path) {
    array_header *list = d->ign_list;
    struct item *items = (struct item *)list->elts;
    char *tt;
    int i;

    if((tt=strrchr(path,'/')) == NULL)
      tt=path;
    else {
      tt++;
    }

    for (i = 0; i < list->nelts; ++i) {
        struct item *p = &items[i];
	char *ap;

	if((ap=strrchr(p->apply_to,'/')) == NULL)
	  ap=p->apply_to;
	else
	  ap++;

        if(!strcmp_match(path,p->apply_path) && !strcmp_match(tt,ap))
	   return 1;
    }
    return 0;
}

int find_opts(dir_config_rec *d, request_rec *r) {
    char *path = r->filename;
    array_header *list = d->opts_list;
    struct item *items = (struct item *)list->elts;
    int i;

    for (i = 0; i < list->nelts; ++i) {
        struct item *p = &items[i];
	
        if(!strcmp_match(path,p->apply_path))
            return (int)p->type;
    }
    return 0;
}

/*****************************************************************
 *
 * Actually generating output
 */


int insert_readme(char *name, char *readme_fname, int rule, request_rec *r) {
    char *fn;
    FILE *f;
    struct stat finfo;
    int plaintext=0;

    fn = make_full_path(r->pool, name, readme_fname);
    fn = pstrcat(r->pool, fn, ".html", NULL);
    if(stat(fn,&finfo) == -1) {
        /* A brief fake multiviews search for README.html */
        fn[strlen(fn)-5] = '\0';
        if(stat(fn,&finfo) == -1)
            return 0;
        plaintext=1;
        if(rule) rputs("<HR>\n", r);
        rputs("<PRE>\n", r);
    }
    else if (rule) rputs("<HR>\n", r);
    if(!(f = pfopen(r->pool,fn,"r")))
        return 0;
    if (!plaintext)
	send_fd(f, r);
    else
    {
	char buf[IOBUFSIZE+1];
	int i, n, c, ch;
	while (!feof(f))
	{
	    do n = fread(buf, sizeof(char), IOBUFSIZE, f);
	    while (n == -1 && ferror(f) && errno == EINTR);
	    if (n == -1 || n == 0) break;
	    buf[n] = '\0';
	    c = 0;
	    while (c < n)
	    {
		for (i=c; i < n; i++)
		    if (buf[i] == '<' || buf[i] == '>' || buf[i] == '&') break;
		ch = buf[i];
		buf[i] = '\0';
		rputs(&buf[c], r);
		if (ch == '<') rputs("&lt;", r);
		else if (ch == '>') rputs("&gt;", r);
		else if (ch == '&') rputs("&amp;", r);
		c = i + 1;
	    }
	}
    }
    pfclose(r->pool, f);
    if(plaintext)
        rputs("</PRE>\n", r);
    return 1;
}


char *find_title(request_rec *r) {
    char titlebuf[MAX_STRING_LEN], *find = "<TITLE>";
    FILE *thefile = NULL;
    int x,y,n,p;

    if (r->content_type && !strcmp(r->content_type,"text/html") && !r->content_encoding) {
        if(!(thefile = pfopen(r->pool, r->filename,"r")))
            return NULL;
        n = fread(titlebuf,sizeof(char),MAX_STRING_LEN - 1,thefile);
        titlebuf[n] = '\0';
        for(x=0,p=0;titlebuf[x];x++) {
            if(toupper(titlebuf[x]) == find[p]) {
                if(!find[++p]) {
                    if((p = ind(&titlebuf[++x],'<')) != -1)
                        titlebuf[x+p] = '\0';
                    /* Scan for line breaks for Tanmoy's secretary */
                    for(y=x;titlebuf[y];y++)
                        if((titlebuf[y] == CR) || (titlebuf[y] == LF))
                            titlebuf[y] = ' ';
		    pfclose (r->pool, thefile);
                    return pstrdup(r->pool, &titlebuf[x]);
                }
            } else p=0;
        }
	pfclose(r->pool, thefile);
    }
    return NULL;
}

struct ent *make_dir_entry(char *name, int dir_opts,
			   dir_config_rec *d, request_rec *r)
{
    struct ent *p;

    if((name[0] == '.') && (!name[1]))
        return(NULL);

    if (ignore_entry(d, make_full_path (r->pool, r->filename, name)))
        return(NULL);

    p=(struct ent *)pcalloc(r->pool, sizeof(struct ent));
    p->name = pstrdup (r->pool, name);
    p->size = -1;
    p->icon = NULL;
    p->alt = NULL;
    p->desc = NULL;
    p->lm = -1;

    if(dir_opts & FANCY_INDEXING) {
        request_rec *rr = sub_req_lookup_file (name, r);
	
	if (rr->finfo.st_mode != 0) {
            p->lm = rr->finfo.st_mtime;
            if(S_ISDIR(rr->finfo.st_mode)) {
                if(!(p->icon = find_icon(d,rr,1)))
                    p->icon = find_default_icon(d,"^^DIRECTORY^^");
                if(!(p->alt = find_alt(d,rr,1)))
                    p->alt = "DIR";
                p->size = -1;
		p->name = pstrcat (r->pool, name, "/", NULL);
            }
            else {
                p->icon = find_icon(d, rr, 0);
                p->alt = find_alt(d, rr, 0);
                p->size = rr->finfo.st_size;
            }
        }
	
        p->desc = find_desc(d, rr);
	
        if((!p->desc) && (dir_opts & SCAN_HTML_TITLES))
            p->desc = pstrdup (r->pool, find_title(rr));

	destroy_sub_req (rr);
    }
    return(p);
}

char *terminate_description(dir_config_rec *d, char *desc, int dir_opts) {
    int maxsize = 23;
    register int x;
    
    if(dir_opts & SUPPRESS_LAST_MOD) maxsize += 17;
    if(dir_opts & SUPPRESS_SIZE) maxsize += 7;

    for(x=0;desc[x] && maxsize;x++) {
        if(desc[x] == '<') {
            while(desc[x] != '>') {
                if(!desc[x]) {
                    maxsize = 0;
                    break;
                }
                ++x;
            }
        }
        else --maxsize;
    }
    if(!maxsize) {
        desc[x-1] = '>';	/* Grump. */
	desc[x] = '\0';		/* Double Grump! */
    }
    return desc;
}

void output_directories(struct ent **ar, int n,
			dir_config_rec *d, request_rec *r, int dir_opts)
{
    int x, len;
    char *name = r->uri;
    char *tp;
    pool *scratch = make_sub_pool (r->pool);
    
    if(name[0] == '\0') name = "/";

    if(dir_opts & FANCY_INDEXING) {
        rputs("<PRE>", r);
        if((tp = find_default_icon(d,"^^BLANKICON^^")))
            rvputs(r, "<IMG SRC=\"", escape_html(scratch, tp),
		   "\" ALT=\"     \"> ", NULL);
        rputs("Name                   ", r);
        if(!(dir_opts & SUPPRESS_LAST_MOD))
            rputs("Last modified     ", r);
        if(!(dir_opts & SUPPRESS_SIZE))
            rputs("Size  ", r);
        if(!(dir_opts & SUPPRESS_DESC))
            rputs("Description", r);
        rputs("\n<HR>\n", r);
    }
    else {
        rputs("<UL>", r);
    }
        
    for(x=0;x<n;x++) {
	char *anchor = NULL, *t = NULL, *t2 = NULL;
	
	clear_pool (scratch);
	
        if((!strcmp(ar[x]->name,"../")) || (!strcmp(ar[x]->name,".."))) {
            char *t = make_full_path (scratch, name, "../");
            getparents(t);
            if(t[0] == '\0') t = "/";
	    anchor = pstrcat (scratch, "<A HREF=\"",
			      escape_html(scratch, os_escape_path(scratch, t, 0)),
			      "\">", NULL);
	    t2 = "Parent Directory</A>       ";
        }
        else {
	    t = ar[x]->name;
	    len = strlen(t);
            if(len > 23) {
		t2 = pstrdup(scratch, t);
		t2[21] = '.';
		t2[22] = '.';
                t2[23] = '\0';
		t2 = escape_html(scratch, t2);
		t2 = pstrcat(scratch, t2, "</A>", NULL);
            } else 
	    {
		char buff[24]="                       ";
		t2 = escape_html(scratch, t);
		buff[23-len] = '\0';
		t2 = pstrcat(scratch, t2, "</A>", buff, NULL);
	    }
	    anchor = pstrcat (scratch, "<A HREF=\"",
			      escape_html(scratch, os_escape_path(scratch, t, 0)),
			      "\">", NULL);
        }

        if(dir_opts & FANCY_INDEXING) {
            if(dir_opts & ICONS_ARE_LINKS)
                rputs(anchor, r);
            if((ar[x]->icon) || d->default_icon) {
                rvputs(r, "<IMG SRC=\"", 
		       escape_html(scratch, ar[x]->icon ?
				   ar[x]->icon : d->default_icon),
		       "\" ALT=\"[", (ar[x]->alt ? ar[x]->alt : "   "),
		       "]\">", NULL);
            }
            if(dir_opts & ICONS_ARE_LINKS) 
                rputs("</A>", r);

            rvputs(r," ", anchor, t2, NULL);
            if(!(dir_opts & SUPPRESS_LAST_MOD)) {
                if(ar[x]->lm != -1) {
		    char time[MAX_STRING_LEN];
                    struct tm *ts = localtime(&ar[x]->lm);
                    strftime(time,MAX_STRING_LEN,"%d-%b-%y %H:%M  ",ts);
		    rputs(time, r);
                }
                else {
                    rputs("                 ", r);
                }
            }
            if(!(dir_opts & SUPPRESS_SIZE)) {
                send_size(ar[x]->size,r);
                rputs("  ", r);
            }
            if(!(dir_opts & SUPPRESS_DESC)) {
                if(ar[x]->desc) {
                    rputs(terminate_description(d, ar[x]->desc, dir_opts), r);
                }
            }
        }
        else
            rvputs(r, "<LI> ", anchor," ", t2, NULL);
        rputc('\n', r);
    }
    if(dir_opts & FANCY_INDEXING) {
        rputs("</PRE>", r);
    }
    else {
        rputs("</UL>", r);
    }
}


int dsortf(struct ent **s1,struct ent **s2)
{
    return(strcmp((*s1)->name,(*s2)->name));
}

    
int index_directory(request_rec *r, dir_config_rec *dir_conf)
{
    char *title_name = escape_html(r->pool, r->uri);
    char *title_endp;
    char *name = r->filename;
    
    DIR *d;
    struct DIR_TYPE *dstruct;
    int num_ent=0,x;
    struct ent *head,*p;
    struct ent **ar;
    char *tmp;
    int dir_opts = find_opts(dir_conf, r);

    if(!(d=opendir(name))) return FORBIDDEN;

    r->content_type = "text/html";
    
    soft_timeout ("send directory", r);
    send_http_header(r);

    if (r->header_only) {
	closedir (d);
	return 0;
    }

    /* Spew HTML preamble */
    
    title_endp = title_name + strlen(title_name) - 1;

    while (title_endp > title_name && *title_endp == '/')
	*title_endp-- = '\0';
    
    rvputs(r, "<HEAD><TITLE>Index of ", title_name, "</TITLE></HEAD><BODY>\n",
	   NULL);

    if((!(tmp = find_header(dir_conf,r))) || (!(insert_readme(name,tmp,0,r))))
        rvputs(r, "<H1>Index of ", title_name, "</H1>\n", NULL);

    /* 
     * Since we don't know how many dir. entries there are, put them into a 
     * linked list and then arrayificate them so qsort can use them. 
     */
    head=NULL;
    while((dstruct=readdir(d))) {
        if((p = make_dir_entry(dstruct->d_name, dir_opts, dir_conf, r))) {
            p->next=head;
            head=p;
            num_ent++;
        }
    }
    ar=(struct ent **) palloc(r->pool, num_ent*sizeof(struct ent *));
    p=head;
    x=0;
    while(p) {
        ar[x++]=p;
        p = p->next;
    }
    
    qsort((void *)ar,num_ent,sizeof(struct ent *),
#ifdef ULTRIX_BRAIN_DEATH
          (int (*))dsortf);
#else
          (int (*)(const void *,const void *))dsortf);
#endif
     output_directories(ar, num_ent, dir_conf, r, dir_opts);
     closedir(d);

     if (dir_opts & FANCY_INDEXING)
         if((tmp = find_readme(dir_conf, r)))
             insert_readme(name,tmp,1,r);
     else {
         rputs("</UL>", r);
     }

     rputs("</BODY>", r);
     return 0;
}

/* The formal handler... */

int handle_dir (request_rec *r)
{
    dir_config_rec *d =
      (dir_config_rec *)get_module_config (r->per_dir_config, &dir_module);
    char *names_ptr = d->index_names ? d->index_names : DEFAULT_INDEX;
    int allow_opts = allow_options (r);

    if (r->uri[0] == '\0' || r->uri[strlen(r->uri)-1] != '/') {
	char* ifile;
	if (r->args != NULL)
        	ifile = pstrcat (r->pool, escape_uri(r->pool, r->uri),
			"/", "?", r->args, NULL);
	else
        	ifile = pstrcat (r->pool, escape_uri(r->pool, r->uri),
			 "/", NULL);

	table_set (r->headers_out, "Location",
		   construct_url(r->pool, ifile, r->server));
	return REDIRECT;
    }

    /* KLUDGE --- make the sub_req lookups happen in the right directory.
     * Fixing this in the sub_req_lookup functions themselves is difficult,
     * and would probably break virtual includes...
     */

    r->filename = pstrcat (r->pool, r->filename, "/", NULL);
    
    while (*names_ptr) {
          
	char *name_ptr = getword_conf (r->pool, &names_ptr);
	request_rec *rr = sub_req_lookup_uri (name_ptr, r);
           
	if (rr->status == 200 && rr->finfo.st_mode != 0) {
	    char* new_uri = escape_uri(r->pool, rr->uri);

	    if (rr->args != NULL)
		new_uri = pstrcat(r->pool, new_uri, "?", rr->args, NULL);
	    else if (r->args != NULL)
		new_uri = pstrcat(r->pool, new_uri, "?", r->args, NULL);
	
	    destroy_sub_req (rr);
	    internal_redirect (new_uri, r);
	    return OK;
	}

        destroy_sub_req (rr);
    }

    if (r->method_number != M_GET) return NOT_IMPLEMENTED;
    
    /* OK, nothing easy.  Trot out the heavy artillery... */

    if (allow_opts & OPT_INDEXES) 
        return index_directory (r, d);
    else
        return FORBIDDEN;
}


handler_rec dir_handlers[] = {
{ DIR_MAGIC_TYPE, handle_dir },
{ NULL }
};

module dir_module = {
   STANDARD_MODULE_STUFF,
   NULL,			/* initializer */
   create_dir_config,		/* dir config creater */
   merge_dir_configs,		/* dir merger --- default is to override */
   NULL,			/* server config */
   NULL,			/* merge server config */
   dir_cmds,			/* command table */
   dir_handlers,		/* handlers */
   NULL,			/* filename translation */
   NULL,			/* check_user_id */
   NULL,			/* check auth */
   NULL,			/* check access */
   NULL,			/* type_checker */
   NULL,			/* fixups */
   NULL				/* logger */
};
