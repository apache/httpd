/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2004 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
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
