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
 */

#ifndef AP_CONFTREE_H
#define AP_CONFTREE_H

#include "ap_config.h"

/**
 * @package Config Tree Package
 */

typedef struct ap_directive_t ap_directive_t;

/**
 * Structure used to build the config tree.  The config tree only stores
 * the directives that will be active in the running server.  Directives
 * that contain other directions, such as <Directory ...> cause a sub-level
 * to be created, where the included directives are stored.  The closing
 * directive (</Directory>) is not stored in the tree.
 */
struct ap_directive_t {
    /** The current directive */
    const char *directive;
    /** The arguments for the current directive, stored as a space 
     *  separated list */
    const char *args;
    /** The next directive node in the tree
     *  @defvar ap_directive_t *next */
    struct ap_directive_t *next;
    /** The first child node of this directive 
     *  @defvar ap_directive_t *first_child */
    struct ap_directive_t *first_child;
    /** The parent node of this directive 
     *  @defvar ap_directive_t *parent */
    struct ap_directive_t *parent;

    /** directive's module can store add'l data here */
    void *data;

    /* ### these may go away in the future, but are needed for now */
    /** The name of the file this directive was found in */
    const char *filename;
    /** The line number the directive was on */
    int line_num;
};

/**
 * The root of the configuration tree
 * @defvar ap_directive_t *conftree
 */
AP_DECLARE_DATA extern ap_directive_t *ap_conftree;

/**
 * Add a node to the configuration tree.
 * @param parent The current parent node.  If the added node is a first_child,
                 then this is changed to the current node
 * @param current The current node
 * @param toadd The node to add to the tree
 * @param child Is the node to add a child node
 * @return the added node
 */
ap_directive_t *ap_add_node(ap_directive_t **parent, ap_directive_t *current, 
                            ap_directive_t *toadd, int child);

#endif
