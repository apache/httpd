/* copyright 1996 Robert S. Thau */

/*
 * mod_pics_simple... provide an easy way to set a default PICS label
 * across an entire hierarchy.  Note that if something tries to override,
 * then with the server in its current (1.0/1.1) condition, multiple labels
 * will be attached, which may confuse things.
 *
 * This defines a <PICS-label> sectioning directive.  If this occurs in any
 * config file:
 *
 *     <PICS-label>
 *     label-text...
 *     </PICS-label>
 *
 * the label-text will be output in a PICS-label header for all requests
 * in which the config file in question is in scope, save only that for nested
 * config files, the innermost <PICS-label> is the one that applies, and that
 * an *empty* PICS-label section turns the feature off (in case a CGI script
 * in an otherwise label-stamped hierarchy, say, wants to decide its own
 * labeling on the fly).
 *
 * This is controlled by AllowOverride FileInfo.
 */

#include "httpd.h"
#include "http_config.h"

extern module pics_simple_module;

static void *make_pics_simple_state (pool *p, char *d) {
    return pcalloc (p, sizeof (char *));
}

static char *pics_simple_section (cmd_parms *cmd, void *pksc) {
    char **pics_simple_ptr = (char**)pksc;
    char *stuff = "";
    char *endp;
    char buf[512];
    int seen_end = 0;

    while (fgets (buf, sizeof(buf), cmd->infile)) {
	if (!strcasecmp (buf, "</PICS-label>\n")) {
	    seen_end = 1;
	    break;
	}

	/* Strip off newlines to avoid doubling them in the eventual
	 * response header list...
	 */

	endp = buf + strlen(buf) - 1;
	if (*endp == '\n') *endp = '\0';
	
	stuff = pstrcat (cmd->temp_pool, stuff, buf, NULL);
    }

    if (!seen_end) return "Unterminated <PICS-label>";
    
    if (*stuff)
	*pics_simple_ptr = pstrdup (cmd->pool, stuff);
    else
	*pics_simple_ptr = NULL;
	
    return NULL;
}

static int pics_simple_fixup (request_rec *r) {
    char **stuff = (char **)get_module_config (r->per_dir_config,
					       &pics_simple_module);

    if (!*stuff) return DECLINED;

    table_set (r->headers_out, "PICS-label", *stuff);
    return DECLINED;
}

static command_rec pics_simple_cmds[] = {
    { "<PICS-label>", pics_simple_section, NULL, OR_FILEINFO, NO_ARGS,
      "a PICS label beginning on the *following* line, until </PICS-label>\n"
      "on a line of its own" },
    { NULL }
};

module pics_simple_module = {
   STANDARD_MODULE_STUFF,
   NULL,			/* initializer */
   make_pics_simple_state,	/* dir config creater */
   NULL,			/* dir merger --- default is to override */
   NULL,			/* server config */
   NULL,			/* merge server configs */
   pics_simple_cmds,		/* command table */
   NULL,			/* handlers */
   NULL,			/* filename translation */
   NULL,			/* check_user_id */
   NULL,			/* check auth */
   NULL,			/* check access */
   NULL,			/* type_checker */
   pics_simple_fixup,		/* fixups */
   NULL,			/* logger */
};

