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

#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "httpd.h"
#include "http_config.h"

/* Possibly get rid of the macros we defined in httpd.h */
#if defined(strchr)
#undef strchr
#endif

#if defined (strrchr)
#undef strrchr
#endif

#if defined (strstr)
#undef strstr
#endif


#if defined(ap_strchr)
#undef ap_strchr
AP_DECLARE(char *) ap_strchr(char *s, int c);
#endif

AP_DECLARE(char *) ap_strchr(char *s, int c)
{
    return strchr(s,c);
}

#if defined(ap_strchr_c)
#undef ap_strchr_c
AP_DECLARE(const char *) ap_strchr_c(const char *s, int c);
#endif

AP_DECLARE(const char *) ap_strchr_c(const char *s, int c)
{
    return strchr(s,c);
}

#if defined(ap_strrchr)
#undef ap_strrchr
AP_DECLARE(char *) ap_strrchr(char *s, int c);
#endif

AP_DECLARE(char *) ap_strrchr(char *s, int c)
{
    return strrchr(s,c);
}

#if defined(ap_strrchr_c)
#undef ap_strrchr_c
AP_DECLARE(const char *) ap_strrchr_c(const char *s, int c);
#endif

AP_DECLARE(const char *) ap_strrchr_c(const char *s, int c)
{
    return strrchr(s,c);
}

#if defined(ap_strstr)
#undef ap_strstr
AP_DECLARE(char *) ap_strstr(char *s, const char *c);
#endif

AP_DECLARE(char *) ap_strstr(char *s, const char *c)
{
    return strstr(s,c);
}

#if defined(ap_strstr_c)
#undef ap_strstr_c
AP_DECLARE(const char *) ap_strstr_c(const char *s, const char *c);
#endif

AP_DECLARE(const char *) ap_strstr_c(const char *s, const char *c)
{
    return strstr(s,c);
}

#if defined(ap_get_module_config)
#undef ap_get_module_config
AP_DECLARE(void *) ap_get_module_config(const ap_conf_vector_t *cv,
                                        const module *m);
#endif

AP_DECLARE(void *) ap_get_module_config(const ap_conf_vector_t *cv,
                                        const module *m)
{
    return ((void **)cv)[m->module_index];
}

/**
 * Generic accessors for other modules to set at their own module-specific
 * data
 * @param conf_vector The vector in which the modules configuration is stored.
 *        usually r->per_dir_config or s->module_config
 * @param m The module to set the data for.
 * @param val The module-specific data to set
 * @deffunc void ap_set_module_config(ap_conf_vector_t *cv, const module *m, void *val)
 */
#if defined(ap_set_module_config)
#undef ap_set_module_config
AP_DECLARE(void) ap_set_module_config(ap_conf_vector_t *cv, const module *m,
                                      void *val);
#endif

AP_DECLARE(void) ap_set_module_config(ap_conf_vector_t *cv, const module *m,
                                      void *val)
{
    ((void **)cv)[m->module_index] = val;
}
