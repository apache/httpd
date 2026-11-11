<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1437838 -->
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

<modulesynopsis metafile="mod_dav_lock.xml.meta">

<name>mod_dav_lock</name>
<description>Módulo de bloqueo genérico para <module>mod_dav</module></description>
<status>Extension</status>
<sourcefile>mod_dav_lock.c</sourcefile>
<identifier>dav_lock_module</identifier>
<compatibility>Disponible en la versión 2.1 y posteriores</compatibility>

<summary>
    <p>Este módulo implementa una API de bloqueo genérica que puede usar
    cualquier proveedor backend de <module>mod_dav</module>. <em>Requiere</em>
    al menos el servicio de <module>mod_dav</module>. Pero sin un proveedor
    backend que lo use, es inútil y no debería cargarse en el servidor. Un
    módulo backend de ejemplo que sí utiliza <module>mod_dav_lock</module>
    es <a href="http://subversion.apache.org/">mod_dav_svn</a>, el módulo
    proveedor de subversion.</p>

    <p>Tenga en cuenta que <module>mod_dav_fs</module> <em>no</em> necesita
    este módulo de bloqueo genérico, porque usa su propia versión más
    especializada.</p>

    <p>Para que <module>mod_dav_lock</module> funcione, solo tiene que
    especificar la ubicación de la base de datos de bloqueos usando la
    directiva <directive module="mod_dav_lock">DavGenericLockDB</directive>
    descrita más abajo.</p>

    <note><title>Nota para desarrolladores</title>
      <p>Para obtener el puntero a la función del proveedor de bloqueo,
      tiene que usar la API <code>ap_lookup_provider</code> con los
      argumentos <code>dav-lock</code>, <code>generic</code>, y
      <code>0</code>.</p>
    </note>
</summary>
<seealso><module>mod_dav</module></seealso>

<directivesynopsis>
<name>DavGenericLockDB</name>
<description>Ubicación de la base de datos de bloqueos DAV</description>
<syntax>DavGenericLockDB <var>file-path</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context>
</contextlist>

<usage>
    <p>Use la directiva <directive>DavGenericLockDB</directive> para
    especificar la ruta completa a la base de datos de bloqueos, excluyendo
    la extensión. Si la ruta no es absoluta, se interpretará en relación con
    <directive module="core">ServerRoot</directive>. La implementación de
    <module>mod_dav_lock</module> usa una base de datos SDBM para hacer
    seguimiento de los bloqueos de los usuarios.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
      DavGenericLockDB var/DavLock
      </highlight>
    </example>

    <p>El directorio que contiene el archivo de base de datos de bloqueos debe tener
    permiso de escritura para el <directive module="mod_unixd">User</directive>
    y <directive module="mod_unixd" >Group</directive> con los que
    se está ejecutando Apache. Por razones de seguridad, debería crear un
    directorio para este fin en lugar de cambiar los permisos de
    un directorio existente. En el ejemplo anterior, Apache creará
    archivos en el directorio <code>var/</code> bajo el <directive
    module="core">ServerRoot</directive> con el nombre de archivo base
    <code>DavLock</code> y una extensión añadida por el servidor.</p>

</usage>
</directivesynopsis>

</modulesynopsis>
