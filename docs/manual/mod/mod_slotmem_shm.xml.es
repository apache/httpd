<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1829678 -->
<!-- Spanish Translation: Arturo Bernal <arturobernalg@gmail.com> -->

<!--
 Licensed to the Apache Software Foundation (ASF) under one or more
 contributor license agreements.  See the NOTICE file distributed with
 this work for additional information regarding copyright ownership.
 The ASF licenses this file to You under the Apache License, Version 2.0
 (the "License"); you may not use this file except in compliance with
 the License.  You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
-->

<modulesynopsis metafile="mod_slotmem_shm.xml.meta">

<name>mod_slotmem_shm</name>
<description>Proveedor de memoria compartida basado en slots.</description>
<status>Extension</status>
<sourcefile>mod_slotmem_shm.c</sourcefile>
<identifier>slotmem_shm_module</identifier>

<summary>
    <p><module>mod_slotmem_shm</module> es un proveedor de memoria que
    permite crear y acceder a un segmento de memoria compartida
    en el que los conjuntos de datos se organizan en "slots".
    </p>

    <p>Toda la memoria compartida se limpia y se vacía en cada
    reinicio, sea ordenado o no. Los propios datos se
    almacenan y se restauran en un archivo indicado mediante el parámetro
    <code>name</code> en las llamadas <code>create</code> y
    <code>attach</code>. Si no se especifica con una ruta absoluta, el
    archivo se creará en una ruta relativa a la especificada por la
    directiva <directive module="core">DefaultRuntimeDir</directive>.
    </p>

    <p><module>mod_slotmem_shm</module> proporciona las siguientes funciones de la API:
    </p>

<highlight language="c">
/* call the callback on all worker slots */
apr_status_t doall(ap_slotmem_instance_t *s, ap_slotmem_callback_fn_t *func, void *data, apr_pool_t *pool)

/* create a new slotmem with each item size is item_size. 'name' is used to generate a filename for the persistent
   store of the shared memory if configured. Values are:
      "none"                - Anonymous shared memory and no persistent store
      "file-name"           - [DefaultRuntimeDir]/file-name
      "/absolute-file-name" - Absolute file name */
apr_status_t create(ap_slotmem_instance_t **new, const char *name, apr_size_t item_size, unsigned int item_num, ap_slotmem_type_t type, apr_pool_t *pool)

/* attach to an existing slotmem. See 'create()' for description of 'name' parameter */
apr_status_t attach(ap_slotmem_instance_t **new, const char *name, apr_size_t *item_size, unsigned int *item_num, apr_pool_t *pool)

/* get the direct pointer to the memory associated with this worker slot */
apr_status_t dptr(ap_slotmem_instance_t *s, unsigned int item_id, void **mem)

/* get/read the memory from this slot to dest */
apr_status_t get(ap_slotmem_instance_t *s, unsigned int item_id, unsigned char *dest, apr_size_t dest_len)

/* put/write the data from src to this slot */
apr_status_t put(ap_slotmem_instance_t *slot, unsigned int item_id, unsigned char *src, apr_size_t src_len)

/* return the total number of slots in the segment */
unsigned int num_slots(ap_slotmem_instance_t *s)

/* return the total data size, in bytes, of a slot in the segment */
apr_size_t slot_size(ap_slotmem_instance_t *s)

/* grab or allocate the first free slot and mark as in-use (does not do any data copying) */
apr_status_t grab(ap_slotmem_instance_t *s, unsigned int *item_id)

/* forced grab or allocate the specified slot and mark as in-use (does not do any data copying) */
apr_status_t fgrab(ap_slotmem_instance_t *s, unsigned int item_id)

/* release or free a slot and mark as not in-use (does not do any data copying) */
apr_status_t release(ap_slotmem_instance_t *s, unsigned int item_id)
</highlight>

</summary>

</modulesynopsis>
