<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1744186 -->
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

<modulesynopsis metafile="mod_authn_dbm.xml.meta">

<name>mod_authn_dbm</name>
<description>Autenticación de usuarios usando archivos DBM</description>
<status>Extension</status>
<sourcefile>mod_authn_dbm.c</sourcefile>
<identifier>authn_dbm_module</identifier>
<compatibility>Disponible en Apache 2.1 y posteriores</compatibility>

<summary>
    <p>Este módulo proporciona a los front-ends de autenticación, como
    <module>mod_auth_digest</module> y <module>mod_auth_basic</module>,
    la posibilidad de autenticar usuarios buscándolos en archivos de
    contraseñas <dfn>dbm</dfn>. <module>mod_authn_file</module>
    ofrece una funcionalidad similar.</p>

    <p>Cuando se usa <module>mod_auth_basic</module> o
    <module>mod_auth_digest</module>, este módulo se invoca mediante
    <directive module="mod_auth_basic">AuthBasicProvider</directive> o
    <directive module="mod_auth_digest">AuthDigestProvider</directive>
    con el valor <code>dbm</code>.</p>
</summary>

<seealso><directive module="mod_authn_core">AuthName</directive></seealso>
<seealso><directive module="mod_authn_core">AuthType</directive></seealso>
<seealso>
  <directive module="mod_auth_basic">AuthBasicProvider</directive>
</seealso>
<seealso>
  <directive module="mod_auth_digest">AuthDigestProvider</directive>
</seealso>
<seealso><program>htpasswd</program></seealso>
<seealso><program>htdbm</program></seealso>
<seealso><a href="../misc/password_encryptions.html">Formatos de contraseña</a></seealso>

<directivesynopsis>
<name>AuthDBMUserFile</name>
<description>Establece el nombre de un archivo de base de datos que contiene la lista de usuarios y
contraseñas para la autenticación</description>
<syntax>AuthDBMUserFile <var>file-path</var></syntax>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>La directiva <directive>AuthDBMUserFile</directive> establece el
    nombre de un archivo DBM que contiene la lista de usuarios y contraseñas para la
    autenticación de usuarios. <var>File-path</var> es la ruta absoluta al
    archivo de usuarios.</p>

    <p>El archivo de usuarios se indexa por el nombre de usuario. El valor de un usuario es
    la contraseña cifrada, seguida opcionalmente de dos puntos y datos
    arbitrarios. Los dos puntos y los datos que los siguen serán ignorados por el
    servidor.</p>

    <note type="warning"><title>Seguridad:</title>
      <p>Asegúrese de que <directive>AuthDBMUserFile</directive> se almacena
      fuera del árbol de documentos del servidor web; <em>no</em> lo coloque en
      el directorio que protege. De lo contrario, los clientes podrán
      descargar el <directive>AuthDBMUserFile</directive>.</p>
    </note>

    <p>El formato de la contraseña cifrada depende del front-end de
    autenticación que se esté usando (por ejemplo, <module>mod_auth_basic</module> o
    <module>mod_auth_digest</module>). Consulte <a
    href="../misc/password_encryptions.html">Formatos de contraseña</a> para
    más información.</p>

    <p>Nota importante de compatibilidad: la implementación de
    <code>dbmopen</code> en los módulos de Apache lee la longitud de la cadena
    de los valores con hash a partir de las estructuras de datos DBM, en lugar de confiar
    en que la cadena termine con NULL. Algunas aplicaciones, como
    el servidor web de Netscape, confían en que la cadena termine
    con NULL, por lo que si tiene problemas al usar archivos DBM
    de forma intercambiable entre aplicaciones, puede que esta sea parte del
    problema.</p>

    <p>Apache incluye un script en perl llamado
    <program>dbmmanage</program>. Este programa puede usarse para crear y actualizar
    archivos de contraseñas en formato DBM para usar con este módulo. Otra
    herramienta para mantener los archivos DBM es el programa incluido
    <program>htdbm</program>.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthDBMType</name>
<description>Establece el tipo de archivo de base de datos que se usa para
almacenar las contraseñas</description>
<syntax>AuthDBMType default|SDBM|GDBM|NDBM|DB</syntax>
<default>AuthDBMType default</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>Establece el tipo de archivo de base de datos que se usa para almacenar las contraseñas.
    El tipo de base de datos por defecto se determina en tiempo de compilación. La
    disponibilidad de otros tipos de archivos de base de datos también depende de los
    <a href="../programs/configure.html#options">ajustes de tiempo de compilación</a>.</p>

    <p>Por ejemplo, para activar el soporte de Berkeley DB
    (correspondiente al tipo <code>db</code>), hay que añadir la
    opción <code>--with-berkeley-db</code> al configure de httpd
    para generar el DSO necesario.</p>

    <p>Es crucial que el programa que use para crear sus archivos de contraseñas
    esté configurado para usar el mismo tipo de base de datos.</p>
</usage>
</directivesynopsis>

</modulesynopsis>
