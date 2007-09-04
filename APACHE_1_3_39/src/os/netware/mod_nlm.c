/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "httpd.h"
#include "http_config.h"
#include <nwadv.h>

module MODULE_VAR_EXPORT nlm_module;
static int been_there_done_that = 0; /* Loaded the modules yet? */

static const char *load_module(cmd_parms *cmd, void *dummy, char *modname, char *filename)
{
    module *modp;
    int nlmHandle;
    const char *szModuleFile = ap_server_root_relative(cmd->pool, filename);

    if (been_there_done_that)
        return NULL;

	nlmHandle = FindNLMHandle(filename);

    if (nlmHandle == NULL) {
        spawnlp(P_NOWAIT, szModuleFile, NULL);
        nlmHandle = FindNLMHandle(filename);

        if (nlmHandle == NULL)
            return ap_pstrcat(cmd->pool, "Cannot load ", szModuleFile,
                              " into server", NULL);
    }

    modp = (module *) ImportSymbol(nlmHandle, modname);

    if (!modp)
        return ap_pstrcat(cmd->pool, "Can't find module ", modname,
                          " in file ", filename, NULL);
	
    ap_add_module(modp);

    if (modp->create_server_config)
        ((void**)cmd->server->module_config)[modp->module_index] =
         (*modp->create_server_config)(cmd->pool, cmd->server);

    if (modp->create_dir_config)
        ((void**)cmd->server->lookup_defaults)[modp->module_index] =
         (*modp->create_dir_config)(cmd->pool, NULL);

    return NULL;
}

static const char *load_file(cmd_parms *cmd, void *dummy, char *filename)
{
    if (been_there_done_that)
        return NULL;

    if (spawnlp(P_NOWAIT, ap_server_root_relative(cmd->pool, filename), NULL))
        return ap_pstrcat(cmd->pool, "Cannot load ", filename, " into server", NULL);

    return NULL;
}

void check_loaded_modules(server_rec *dummy, pool *p)
{
    if (been_there_done_that)
        return;

    been_there_done_that = 1;
}

command_rec nlm_cmds[] = {
{ "LoadModule", load_module, NULL, RSRC_CONF, TAKE2,
  "a module name, and the name of a file to load it from"},
{ "LoadFile", load_file, NULL, RSRC_CONF, ITERATE,
  "files or libraries to link into the server at runtime"},
{ NULL }
};

module nlm_module = {
   STANDARD_MODULE_STUFF,
   check_loaded_modules,  /* initializer */
   NULL,                  /* create per-dir config */
   NULL,                  /* merge per-dir config */
   NULL,                  /* server config */
   NULL,                  /* merge server config */
   nlm_cmds,              /* command table */
   NULL,                  /* handlers */
   NULL,                  /* filename translation */
   NULL,                  /* check_user_id */
   NULL,                  /* check auth */
   NULL,                  /* check access */
   NULL,                  /* type_checker */
   NULL,                  /* logger */
   NULL                   /* header parser */
};

