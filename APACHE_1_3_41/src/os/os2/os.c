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

/*
 * This file will include OS specific functions which are not inlineable.
 * Any inlineable functions should be defined in os-inline.c instead.
 */

#include "os.h"
#define INCL_DOS
#include <os2.h>
#include <stdio.h>
#include <string.h>

static int rc=0;
static char errorstr[20];

void ap_os_dso_init(void)
{
}



ap_os_dso_handle_t ap_os_dso_load(const char *module_name)
{
    HMODULE handle;

    rc = DosLoadModule(errorstr, sizeof(errorstr), module_name, &handle);

    if (rc == 0)
        return handle;

    return 0;
}



void ap_os_dso_unload(ap_os_dso_handle_t handle)
{
    DosFreeModule(handle);
}



void *ap_os_dso_sym(ap_os_dso_handle_t handle, const char *funcname)
{
    PFN func;
    
    rc = DosQueryProcAddr( handle, 0, funcname, &func );
    
    if (rc == 0)
        return func;

    return NULL;
}



const char *ap_os_dso_error(void)
{
    static char message[200];
    strcpy(message, ap_os_error_message(rc));
    strcat(message, " for module ");
    strcat(message, errorstr);
    return message;
}
