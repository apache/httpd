/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2003 The Apache Software Foundation.  All rights
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

/* modules.c --- major modules compiled into Apache for Win32.
 * Only insert an entry for a module if it must be compiled into
 * the core server
 */

#ifdef WIN32

#include "httpd.h"
#include "http_config.h"

extern module core_module;
extern module so_module;
extern module mime_module;
extern module access_module;
extern module auth_module;
extern module negotiation_module;
extern module includes_module;
extern module autoindex_module;
extern module dir_module;
extern module cgi_module;
extern module userdir_module;
extern module alias_module;
extern module env_module;
extern module config_log_module;
extern module asis_module;
extern module imap_module;
extern module action_module;
extern module setenvif_module;
extern module isapi_module;

module *ap_prelinked_modules[] = {
  &core_module,
  &so_module,
  &mime_module,
  &access_module,
  &auth_module,
  &negotiation_module,
  &includes_module,
  &autoindex_module,
  &dir_module,
  &cgi_module,
  &userdir_module,
  &alias_module,
  &env_module,
  &config_log_module,
  &asis_module,
  &imap_module,
  &action_module,
  &setenvif_module,
  &isapi_module,
  NULL
};
module *ap_preloaded_modules[] = {
  &core_module,
  &so_module,
  &mime_module,
  &access_module,
  &auth_module,
  &negotiation_module,
  &includes_module,
  &autoindex_module,
  &dir_module,
  &cgi_module,
  &userdir_module,
  &alias_module,
  &env_module,
  &config_log_module,
  &asis_module,
  &imap_module,
  &action_module,
  &setenvif_module,
  &isapi_module,
  NULL
};

#endif /* WIN32 */
