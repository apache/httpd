/* Ben messing around... */

#include "httpd.h"
#include "http_config.h"
#include "apr_general.h"
#include "util_filter.h"
#include "apr_buckets.h"
#include "http_request.h"

#include <ctype.h>

static const char s_szCaseFilterName[]="CaseFilter";
module AP_MODULE_DECLARE_DATA case_filter_module;

typedef struct
    {
    int bEnabled;
    } CaseFilterConfig;

static void *CaseFilterCreateServerConfig(apr_pool_t *p,server_rec *s)
    {
    CaseFilterConfig *pConfig=apr_pcalloc(p,sizeof *pConfig);

    pConfig->bEnabled=0;

    return pConfig;
    }

static void CaseFilterInsertFilter(request_rec *r)
    {
    CaseFilterConfig *pConfig=ap_get_module_config(r->server->module_config,
						   &case_filter_module);

    if(!pConfig->bEnabled)
	return;

    ap_add_output_filter(s_szCaseFilterName,NULL,r,r->connection);
    }

static apr_status_t CaseFilterOutFilter(ap_filter_t *f,
					apr_bucket_brigade *pbbIn)
    {
    apr_bucket *pbktIn;
    apr_bucket_brigade *pbbOut;

    /* XXX: is this the most appropriate pool? */
    pbbOut=apr_brigade_create(f->r->pool);
    APR_BRIGADE_FOREACH(pbktIn,pbbIn)
	{
	const char *data;
	apr_size_t len;
	char *buf;
	apr_size_t n;
	apr_bucket *pbktOut;

	if(APR_BUCKET_IS_EOS(pbktIn))
	    {
            /* XXX: why can't I reuse pbktIn??? */
	    apr_bucket *pbktEOS=apr_bucket_eos_create();
	    APR_BRIGADE_INSERT_TAIL(pbbOut,pbktEOS);
	    continue;
	    }

	/* read */
	apr_bucket_read(pbktIn,&data,&len,APR_BLOCK_READ);

	/* write */
	buf=malloc(len);
	for(n=0 ; n < len ; ++n)
	    buf[n]=toupper(data[n]);

	pbktOut=apr_bucket_heap_create(buf,len,0);
	APR_BRIGADE_INSERT_TAIL(pbbOut,pbktOut);
	}

    /* XXX: is there any advantage to passing a brigade for each bucket? */
    return ap_pass_brigade(f->next,pbbOut);
    }

static const char *CaseFilterEnable(cmd_parms *cmd, void *dummy, int arg)
    {
    CaseFilterConfig *pConfig=ap_get_module_config(cmd->server->module_config,
						   &case_filter_module);
    pConfig->bEnabled=arg;

    return NULL;
    }

static const command_rec CaseFilterCmds[] = 
    {
    AP_INIT_FLAG("CaseFilter", CaseFilterEnable, NULL, RSRC_CONF,
                 "Run a case filter on this host"),
    { NULL }
    };

static void CaseFilterRegisterHooks(apr_pool_t *p)
    {
    ap_hook_insert_filter(CaseFilterInsertFilter,NULL,NULL,APR_HOOK_MIDDLE);
    ap_register_output_filter(s_szCaseFilterName,CaseFilterOutFilter,
			      AP_FTYPE_RESOURCE);
    }

module AP_MODULE_DECLARE_DATA case_filter_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    CaseFilterCreateServerConfig,
    NULL,
    CaseFilterCmds,
    CaseFilterRegisterHooks
};
