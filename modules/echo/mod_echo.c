#include "httpd.h"
#include "http_config.h"
#include "http_connection.h"

API_VAR_EXPORT module echo_module;

typedef struct
    {
    int bEnabled;
    } EchoConfig;

static void *create_echo_server_config(pool *p,server_rec *s)
    {
    EchoConfig *pConfig=ap_pcalloc(p,sizeof *pConfig);

    pConfig->bEnabled=0;

    return pConfig;
    }

static const char *echo_on(cmd_parms *cmd, void *dummy, char *arg)
    {
    EchoConfig *pConfig=ap_get_module_config(cmd->server->module_config,
					     &echo_module);
    pConfig->bEnabled=1;

    return NULL;
    }

static int process_echo_connection(conn_rec *c)
    {
    char buf[1024];
    EchoConfig *pConfig=ap_get_module_config(c->base_server->module_config,
					     &echo_module);

    if(!pConfig->bEnabled)
	return DECLINED;

    for( ; ; )
	{
	int w;
	int r=ap_bread(c->client,buf,sizeof buf);
	if(r <= 0)
	    break;
	w=ap_bwrite(c->client,buf,r);
	if(w != r)
	    break;
	ap_bflush(c->client);
	}
    return OK;
    }

static const command_rec echo_cmds[] = {
{ "ProtocolEcho", echo_on, NULL, RSRC_CONF, RAW_ARGS,
  "Run an echo server on this host" },
{ NULL }
};

static void register_hooks()
    {
    ap_hook_process_connection(process_echo_connection,NULL,NULL,HOOK_MIDDLE);
    }

API_VAR_EXPORT module echo_module = {
    STANDARD20_MODULE_STUFF,
    NULL,			/* pre_command_line */
    NULL,			/* pre_config */
    NULL,			/* post_config */
    NULL,			/* open_logs */
    NULL, 			/* child_init */
    NULL,			/* create per-directory config structure */
    NULL,			/* merge per-directory config structures */
    create_echo_server_config,	/* create per-server config structure */
    NULL,			/* merge per-server config structures */
    echo_cmds,			/* command table */
    NULL,			/* handlers */
    NULL,			/* check auth */
    NULL,			/* check access */
    NULL,			/* type_checker */
    NULL,			/* pre-run fixups */
    register_hooks		/* register hooks */
};
