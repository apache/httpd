/*
 * Placeholder to force ApacheCore.dll creation with no LNK4001 error
 *
 * However, this isn't a bad place to store dynamic-only functions 
 * that determine which version of apr the application has loaded.
 * These functions are of (less?) importance to static-bound apps.
 *
 * We may also need this hook to play with dll-oriented thread-local
 * storage for modules on a per-thread DllMain() basis.
 */
