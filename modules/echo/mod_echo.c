#include "httpd.h"
#include "http_config.h"
#include "http_connection.h"

API_VAR_EXPORT module echo_module;

typedef struct
    {
    int bEnabled;
    } EchoConfig;

static void *create_echo_server_config(ap_context_t *p,server_rec *s)
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
	ap_ssize_t r, w;
        (void) ap_bread(c->client,buf,sizeof buf,&r);
	if(r <= 0)
	    break;
	(void) ap_bwrite(c->client,buf,r, &w);
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
    NULL,			/* create per-directory config structure */
    NULL,			/* merge per-directory config structures */
    create_echo_server_config,	/* create per-server config structure */
    NULL,			/* merge per-server config structures */
    echo_cmds,			/* command ap_table_t */
    NULL,			/* handlers */
    register_hooks		/* register hooks */
};
