/*
 * Declarations for users of the functions defined in registry.c
 */

API_EXPORT(int) ap_registry_get_server_root(pool *p, char *dir, int size);
extern int ap_registry_set_server_root(char *dir);
API_EXPORT(int) ap_registry_get_service_conf(pool *p, char *dir, int size, char *display_name);
API_EXPORT(int) ap_registry_set_service_conf(char *dir, char *display_name);
