/*
 * Declarations for users of the functions defined in registry.c
 */

API_EXPORT(int) ap_registry_get_server_root(pool *p, char *dir, int size);
extern int ap_registry_set_server_root(char *dir);
extern int ap_registry_get_service_args(pool *p, int *argc, char ***argv, char *display_name);
extern int ap_registry_set_service_args(pool *p, int argc, char **argv, char *display_name);
