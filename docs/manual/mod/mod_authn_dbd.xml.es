<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1900526 -->
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

<modulesynopsis metafile="mod_authn_dbd.xml.meta">

<name>mod_authn_dbd</name>
<description>Autenticación de usuarios usando una base de datos SQL</description>
<status>Extension</status>
<sourcefile>mod_authn_dbd.c</sourcefile>
<identifier>authn_dbd_module</identifier>
<compatibility>Disponible en Apache 2.1 y posteriores</compatibility>

<summary>
    <p>Este módulo proporciona a los front-ends de autenticación como
    <module>mod_auth_digest</module> y <module>mod_auth_basic</module>
    la capacidad de autenticar usuarios buscándolos en tablas SQL.
    Una funcionalidad similar la proporciona, por ejemplo,
    <module>mod_authn_file</module>.</p>
    <p>Este módulo depende de <module>mod_dbd</module> para especificar
    el controlador de la base de datos backend y los parámetros de conexión, y
    para gestionar las conexiones a la base de datos.</p>

    <p>Cuando se usa <module>mod_auth_basic</module> o
    <module>mod_auth_digest</module>, este módulo se invoca mediante
    <directive module="mod_auth_basic">AuthBasicProvider</directive> o
    <directive module="mod_auth_digest">AuthDigestProvider</directive>
    con el valor <code>dbd</code>.</p>
</summary>

<seealso><directive module="mod_authn_core">AuthName</directive></seealso>
<seealso><directive module="mod_authn_core">AuthType</directive></seealso>
<seealso>
  <directive module="mod_auth_basic">AuthBasicProvider</directive>
</seealso>
<seealso>
  <directive module="mod_auth_digest">AuthDigestProvider</directive>
</seealso>
<seealso><directive module="mod_dbd">DBDriver</directive></seealso>
<seealso><directive module="mod_dbd">DBDParams</directive></seealso>
<seealso><a href="../misc/password_encryptions.html">Formatos de contraseña</a></seealso>

<section id="socache">
<title>Rendimiento y caché</title>
<p>Algunos usuarios de autenticación DBD en HTTPD 2.2/2.4 han informado de que
impone una carga problemática en la base de datos. Esto es más probable cuando
una página HTML contiene cientos de objetos (por ejemplo, imágenes, scripts, etc.)
cada uno de los cuales requiere autenticación. Los usuarios afectados (o preocupados)
por este tipo de problema deberían usar <module>mod_authn_socache</module>
para cachear las credenciales y quitar la mayor parte de la carga de la base de datos.</p>
</section>

<section id="example">
<title>Ejemplo de configuración</title>
<p>Este sencillo ejemplo muestra el uso de este módulo en el contexto de
los frameworks de Autenticación y DBD.</p>
<highlight language="config">
# configuración de mod_dbd
# ACTUALIZADO para incluir la caché de autenticación
DBDriver pgsql
DBDParams "dbname=apacheauth user=apache password=xxxxxx"

DBDMin  4
DBDKeep 8
DBDMax  20
DBDExptime 300

&lt;Directory "/usr/www/myhost/private"&gt;
  # configuración de mod_authn_core y mod_auth_basic
  # para mod_authn_dbd
  AuthType Basic
  AuthName "My Server"

  # Para cachear credenciales, ponga socache antes de dbd aquí
  AuthBasicProvider socache dbd

  # También necesario para la caché: ¡indique a la caché que cachee las búsquedas de dbd!
  AuthnCacheProvideFor dbd
  AuthnCacheContext my-server

  # configuración de mod_authz_core
  Require valid-user

  # consulta SQL de mod_authn_dbd para autenticar a un usuario
  AuthDBDUserPWQuery "SELECT password FROM authn WHERE user = %s"
&lt;/Directory&gt;
</highlight>
</section>

<section id="exposed">
<title>Exponer información de inicio de sesión</title>
<p>
Cada vez que se realiza una consulta al servidor de la base de datos, todos
los valores de columna de la primera fila devuelta por la consulta se colocan en el
entorno, usando variables de entorno con el prefijo "AUTHENTICATE_".
</p>
<p>Si, por ejemplo, una consulta a la base de datos devolviera el nombre de usuario, el nombre completo
y el número de teléfono de un usuario, un programa CGI tendrá acceso a
esta información sin necesidad de realizar una segunda consulta independiente a la base de datos
para obtener esta información adicional.</p>
<p>Esto tiene el potencial de simplificar drásticamente la codificación y
la configuración necesarias en algunas aplicaciones web.
</p>
</section>

<directivesynopsis>
<name>AuthDBDUserPWQuery</name>
<description>Consulta SQL para buscar la contraseña de un usuario</description>
<syntax>AuthDBDUserPWQuery <var>query</var></syntax>
<contextlist><context>directory</context>
</contextlist>

<usage>
    <p>La directiva <directive>AuthDBDUserPWQuery</directive> especifica una
    consulta SQL para buscar la contraseña de un usuario especificado. El ID del
    usuario se pasará como un único parámetro de tipo cadena cuando se ejecute la consulta
    SQL. Puede referenciarse dentro de la sentencia de la consulta usando
    un especificador de formato <code>%s</code>.</p>
    <highlight language="config">
AuthDBDUserPWQuery "SELECT password FROM authn WHERE user = %s"
</highlight>
    <p>El primer valor de columna de la primera fila devuelta por la sentencia
    de la consulta debería ser una cadena que contenga la contraseña cifrada.
    Las filas siguientes se ignorarán. Si no se devuelve ninguna fila, el usuario
    no se autenticará mediante <module>mod_authn_dbd</module>.</p>
    <p>Cualquier valor de columna adicional en la primera fila devuelta por
    la sentencia de la consulta se almacenará como variables de entorno con
    nombres de la forma <code>AUTHENTICATE_<var>COLUMN</var></code>.
    </p>
    <p>El formato de la contraseña cifrada depende de qué front-end de autenticación
    (por ejemplo, <module>mod_auth_basic</module> o
    <module>mod_auth_digest</module>) se esté usando. Consulte <a
    href="../misc/password_encryptions.html">Formatos de contraseña</a> para
    más información.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthDBDUserRealmQuery</name>
<description>Consulta SQL para buscar el hash de la contraseña de un usuario y un realm.
</description>
<syntax>AuthDBDUserRealmQuery <var>query</var></syntax>
<contextlist><context>directory</context>
</contextlist>

<usage>
    <p>La directiva <directive>AuthDBDUserRealmQuery</directive> especifica una
    consulta SQL para buscar la contraseña de un usuario y un realm especificados en un
    proceso de autenticación digest.
    El ID del usuario y el realm, en ese orden, se pasarán como parámetros de tipo cadena
    cuando se ejecute la consulta SQL. Pueden referenciarse
    dentro de la sentencia de la consulta usando especificadores de formato <code>%s</code>.</p>
    <highlight language="config">
AuthDBDUserRealmQuery "SELECT password FROM authn WHERE user = %s AND realm = %s"
</highlight>
    <p>El primer valor de columna de la primera fila devuelta por la sentencia
    de la consulta debería ser una cadena que contenga la contraseña cifrada.
    Las filas siguientes se ignorarán. Si no se devuelve ninguna fila, el usuario
    no se autenticará mediante <module>mod_authn_dbd</module>.</p>
    <p>Cualquier valor de columna adicional en la primera fila devuelta por
    la sentencia de la consulta se almacenará como variables de entorno con
    nombres de la forma <code>AUTHENTICATE_<var>COLUMN</var></code>.
    </p>
    <p>El formato de la contraseña cifrada depende de qué front-end de autenticación
    (por ejemplo, <module>mod_auth_basic</module> o
    <module>mod_auth_digest</module>) se esté usando. Consulte <a
    href="../misc/password_encryptions.html">Formatos de contraseña</a> para
    más información.</p>
</usage>
</directivesynopsis>

</modulesynopsis>
