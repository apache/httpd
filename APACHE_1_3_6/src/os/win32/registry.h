/*
 * Declarations for users of the functions defined in registry.c
 */

extern int ap_registry_get_server_root(pool *p, char *dir, int size);
extern int ap_registry_set_server_root(char *dir);
