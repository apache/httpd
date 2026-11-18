<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1906516 -->
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

<modulesynopsis metafile="mod_dav_fs.xml.meta">

<name>mod_dav_fs</name>
<description>Proveedor de sistema de archivos para <module>mod_dav</module></description>
<status>Extension</status>
<sourcefile>mod_dav_fs.c</sourcefile>
<identifier>dav_fs_module</identifier>

<summary>
    <p>Este módulo <em>requiere</em> el servicio de <module
    >mod_dav</module>. Actúa como módulo de soporte para <module
    >mod_dav</module> y proporciona acceso a los recursos ubicados en
    el sistema de archivos del servidor. El nombre formal de este proveedor es
    <code>filesystem</code>. Los proveedores de backend de <module>mod_dav</module>
    se invocan usando la directiva <directive module="mod_dav">Dav</directive>:</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
      Dav filesystem
      </highlight>
    </example>

    <p>Dado que <code>filesystem</code> es el proveedor por defecto para
    <module>mod_dav</module>, puede simplemente usar el valor
    <code>On</code> en su lugar.</p>
</summary>
<seealso><module>mod_dav</module></seealso>

<directivesynopsis>
<name>DavLockDB</name>
<description>Ubicación de la base de datos de bloqueos DAV</description>
<syntax>DavLockDB <var>file-path</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>Use la directiva <directive>DavLockDB</directive> para especificar
    la ruta completa a la base de datos de bloqueos, excluyendo la extensión. Si
    la ruta no es absoluta, se tomará en relación con <directive
    module="core">ServerRoot</directive>. La implementación de
    <module>mod_dav_fs</module> usa una base de datos SDBM para hacer
    seguimiento de los bloqueos de los usuarios.</p>

    <!-- XXX: someone should add that tool to the support directory...
    The utility <code>modules/dav/util/lockview</code> can be used from
    the server to display all locks in a lock database.</p> -->

    <example><title>Ejemplo</title>
    <highlight language="config">
      DavLockDB "var/DavLock"
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
    <code>DavLock</code> y la extensión que elija el servidor.</p>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>DavLockDiscovery</name>
<description>Activa el descubrimiento de bloqueos</description>
<syntax>DavLockDiscovery on|off</syntax>
<default>DavLockDiscovery on</default>
<contextlist><context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context>
</contextlist>
<compatibility>Disponible desde Apache 2.4.55 y posteriores.</compatibility>

<usage>
    <p><directive>DavLockDiscovery</directive> controla si la funcionalidad de
    descubrimiento de bloqueos está activada para el método <code>PROPFIND</code>.
    Cuando está desactivada, <code>PROPFIND</code> siempre devuelve una sección
    <code>lockdiscovery</code> vacía. Esto mejora el rendimiento
    si los clientes usan <code>PROPFIND</code> con mucha frecuencia.</p>
    <example><title>Ejemplo</title>
     <highlight language="config">
      DavLockDiscovery off
     </highlight>
    </example>
</usage>
</directivesynopsis>

</modulesynopsis>
