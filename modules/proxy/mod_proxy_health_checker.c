/*
 * Default httpd part of the health checker
 */
#define CORE_PRIVATE

#include "apr.h"
#include "apr_pools.h"

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"

#include "mod_proxy.h"
#include "slotmem.h"
#include "mod_proxy_health_checker.h"

static int healthck_pre_config(apr_pool_t *pconf, apr_pool_t *plog,
                              apr_pool_t *ptemp)
{
    slotmem_storage_method *checkstorage;
    const health_worker_method *worker_storage;
    ap_slotmem_t *myscore;
    
    checkstorage = ap_lookup_provider(SLOTMEM_STORAGE, "shared", "0");
    if (checkstorage) {
        health_checker_init_slotmem_storage(checkstorage);
    }
    worker_storage = ap_lookup_provider(PROXY_CKMETHOD, "default", "0");
    if (checkstorage && worker_storage) {
        checkstorage->ap_slotmem_create(&myscore, "proxy/checker", worker_storage->getentrysize(), 128, pconf);
        health_checker_init_slotmem(myscore);
    }
    return OK;
}

static int healthck_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                                apr_pool_t *ptemp, server_rec *s)
{
    const health_worker_method *worker_storage;
    worker_storage = ap_lookup_provider(PROXY_CKMETHOD, "default", "0");
    
    if (worker_storage) {
        while (s) {
            void *sconf = s->module_config;
            proxy_server_conf *conf;
            proxy_worker *worker;
            proxy_balancer *balancer;
            int i, j, k;

            conf = (proxy_server_conf *)ap_get_module_config(sconf, &proxy_module);
            worker = (proxy_worker *) conf->workers->elts;
            for (i = 0; i < conf->workers->nelts; i++) {
                const char *name = NULL;
                /* find the balancer if any */
                balancer = (proxy_balancer *)conf->balancers->elts;
                for (j = 0; j< conf->balancers->nelts; j++) {
                    proxy_worker *myworker = (proxy_worker *)balancer->workers->elts;
                    for (k = 0; k < balancer->workers->nelts; k++) {
                        if (myworker->id == worker->id) {
                            name = balancer->name;
                            break;
                        }
                        myworker++;
                    }
                    if (name)
                        break;
                }

                if (!name) {
                    /* No balancer */
                    name = "None";
                }
                worker_storage->add_entry(worker, name, worker->id);
                worker++;
            }

            /* XXX: Do we need something for reverse and forward */

            s = s->next;
        }
    }
    return OK;
}

static void ap_healthstore_register_hook(apr_pool_t *p)
{
    static const char * const prePos[] = { "mod_sharedmem.c", NULL };
    static const char * const postPos[] = { "mod_proxy.c", NULL };

    const health_worker_method *worker_storage = health_checker_get_storage();
    ap_register_provider(p, PROXY_CKMETHOD, "default", "0", worker_storage);
    ap_hook_pre_config(healthck_pre_config, NULL, prePos, APR_HOOK_MIDDLE);
    ap_hook_post_config(healthck_post_config, NULL, postPos, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA proxy_health_checker_module = {
    STANDARD20_MODULE_STUFF,
    NULL,       /* create per-directory config structure */
    NULL,       /* merge per-directory config structures */
    NULL,       /* create per-server config structure */
    NULL,       /* merge per-server config structures */
    NULL,       /* command apr_table_t */
    ap_healthstore_register_hook /* register hooks */
};
