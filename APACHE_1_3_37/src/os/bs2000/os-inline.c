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
 * This file contains functions which can be inlined if the compiler
 * has an "inline" modifier. Because of this, this file is both a
 * header file and a compilable module.
 *
 * Only inlineable functions should be defined in here. They must all
 * include the INLINE modifier. 
 *
 * If the compiler supports inline, this file will be #included as a
 * header file from os.h to create all the inline function
 * definitions. INLINE will be defined to whatever is required on
 * function definitions to make them inline declarations.
 *
 * If the compiler does not support inline, this file will be compiled
 * as a normal C file into libos.a (along with os.c). In this case
 * INLINE will _not_ be set so we can use this to test if we are
 * compiling this source file.  
 */

#ifndef INLINE
#define INLINE

/* Anything required only when compiling */
#include "ap_config.h"

#endif

INLINE int ap_os_is_path_absolute(const char *file)
{
  return (file && file[0] == '/' ? 1 : 0);
}
