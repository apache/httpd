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
    health_worker_method *worker_storage = health_checker_get_storage();
    ap_slotmem_t *myscore;
    
    checkstorage = ap_lookup_provider(SLOTMEM_STORAGE, "shared", "0");
    if (checkstorage) {
        health_checker_init_slotmem_storage(checkstorage);
    }
    if (checkstorage && worker_storage) {
        checkstorage->ap_slotmem_create(&myscore, "proxy/checker", worker_storage->getentrysize(), 128, pconf);
        health_checker_init_slotmem(myscore);
    }
    return OK;
}

/* XXX: Was to get ap_proxy_lb_workers()
static int healthck_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                                apr_pool_t *ptemp, server_rec *s)
{
    slotmem_storage_method *checkstorage = health_checker_get_slotmem_storage();
    health_worker_method *worker_storage = health_checker_get_storage();
    ap_slotmem_t *myscore;

    if (checkstorage && worker_storage) {
        checkstorage->ap_slotmem_create(&myscore, "proxy/checker", worker_storage->getentrysize(), ap_proxy_lb_workers(), pconf);
        health_checker_init_slotmem(myscore);
    }
    return OK;

}
 */

static void ap_healthstore_register_hook(apr_pool_t *p)
{
    static const char * const aszPre[] = { "mod_proxy.c", NULL };
    static const char * const aszPos[] = { "mod_sharedmem.c", NULL };

    health_worker_method *worker_storage = health_checker_get_storage();
    ap_register_provider(p, PROXY_CKMETHOD, "default", "0", worker_storage);
    ap_hook_pre_config(healthck_pre_config, NULL, aszPos, APR_HOOK_MIDDLE);
    /* XXX: Too late....
    ap_hook_post_config(healthck_post_config, aszPre, NULL, APR_HOOK_MIDDLE);
     */
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
