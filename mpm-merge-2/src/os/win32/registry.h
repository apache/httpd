/*
 * Declarations for users of the functions defined in registry.c
 */

extern int ap_registry_get_server_root(pool *p, char *dir, int size);
extern int ap_registry_set_server_root(char *dir);
extern int ap_registry_get_service_conf(pool *p, char *dir, int size, char *service_name);
extern int ap_registry_set_service_conf(char *dir, char *service_name);
