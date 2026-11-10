<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1751352 -->
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

<modulesynopsis metafile="mod_authz_dbm.xml.meta">

<name>mod_authz_dbm</name>
<description>Autorización de grupos usando archivos DBM</description>
<status>Extension</status>
<sourcefile>mod_authz_dbm.c</sourcefile>
<identifier>authz_dbm_module</identifier>

<summary>
    <p>Este módulo proporciona funcionalidades de autorización para que a
       los usuarios autenticados se les pueda permitir o denegar el acceso a partes
       del sitio web según la pertenencia a un grupo. Una funcionalidad similar la
       proporciona <module>mod_authz_groupfile</module>.</p>
</summary>

<seealso><directive module="mod_authz_core">Require</directive></seealso>

<section id="requiredirectives"><title>Las directivas Require</title>

    <p>Las directivas <directive module="mod_authz_core">Require</directive>
    de Apache se usan durante la fase de autorización para asegurar que
    un usuario tiene permiso para acceder a un recurso. mod_authz_dbm extiende
    los tipos de autorización con <code>dbm-group</code>.</p>

    <p>Desde la versión 2.4.8, las <a href="../expr.html">expresiones</a> se admiten
    dentro de las directivas require de DBM.</p>

<section id="reqgroup"><title>Require dbm-group</title>

    <p>Esta directiva especifica la pertenencia a un grupo que se requiere para que
    el usuario obtenga acceso.</p>

    <highlight language="config">
      Require dbm-group admin
    </highlight>

</section>

<section id="reqfilegroup"><title>Require dbm-file-group</title>

    <p>Cuando se especifica esta directiva, el usuario debe ser miembro del grupo
    asignado al archivo al que se accede.</p>

    <highlight language="config">
      Require dbm-file-group
    </highlight>

</section>

</section>

<section id="examples">
<title>Ejemplo de uso</title>
<p><em>Tenga en cuenta que usar mod_authz_dbm le obliga a usar require <code>dbm-group</code>
en lugar de <code>group</code>:</em>
</p>
<highlight language="config">
&lt;Directory "/foo/bar"&gt;
  AuthType Basic
  AuthName "Secure Area"
  AuthBasicProvider dbm
  AuthDBMUserFile "site/data/users"
  AuthDBMGroupFile "site/data/users"
  Require dbm-group admin
&lt;/Directory&gt;
</highlight>
</section>

<directivesynopsis>
<name>AuthDBMGroupFile</name>
<description>Establece el nombre del archivo de base de datos que contiene la lista
de grupos de usuarios para la autorización</description>
<syntax>AuthDBMGroupFile <var>file-path</var></syntax>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>La directiva <directive>AuthDBMGroupFile</directive> establece el
    nombre de un archivo DBM que contiene la lista de grupos de usuarios para la
    autorización de usuarios. <var>File-path</var> es la ruta absoluta al
    archivo de grupos.</p>

    <p>El archivo de grupos está indexado por el nombre de usuario. El valor de
    un usuario es una lista separada por comas de los grupos a los que el usuario
    pertenece. No debe haber espacios en blanco dentro del valor, y
    nunca debe contener dos puntos.</p>

    <note type="warning"><title>Seguridad</title>
      <p>Asegúrese de que <directive>AuthDBMGroupFile</directive> se
      guarda fuera del árbol de documentos del servidor web. No lo
      <strong>coloque</strong> en el directorio que protege.
      De lo contrario, los clientes podrán descargar
      el archivo de <directive>AuthDBMGroupFile</directive> a menos que esté
      protegido de otra forma.</p>
    </note>

    <p>Combinando archivos DBM de grupos y contraseñas: en algunos casos es
    más fácil gestionar una única base de datos que contenga tanto los
    datos de contraseña como de grupo de cada usuario. Esto simplifica cualquier
    programa de soporte que deba escribirse: ahora solo tienen que
    encargarse de escribir y bloquear un único archivo DBM. Esto puede
    lograrse estableciendo primero que los archivos de grupo y contraseña
    apunten a la misma base DBM:</p>

    <highlight language="config">
AuthDBMGroupFile "/www/userbase"
AuthDBMUserFile "/www/userbase"
    </highlight>

    <p>La clave para la base DBM única es el nombre de usuario. El valor consiste
    en</p>

    <example>
      Contraseña cifrada : Lista de grupos [ : (ignorado) ]
    </example>

    <p>La sección de la contraseña contiene la contraseña
    cifrada como antes. A continuación le siguen dos puntos y la lista de grupos
    separada por comas. Opcionalmente pueden dejarse otros datos en el
    archivo DBM después de otros dos puntos; el módulo de autorización los
    ignora.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthzDBMType</name>
<description>Establece el tipo de archivo de base de datos que se usa para
almacenar la lista de grupos de usuarios</description>
<syntax>AuthzDBMType default|SDBM|GDBM|NDBM|DB</syntax>
<default>AuthzDBMType default</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>Establece el tipo de archivo de base de datos que se usa para almacenar la
    lista de grupos de usuarios.
    El tipo de base de datos por defecto se determina en tiempo de compilación. La
    disponibilidad de otros tipos de archivos de base de datos también depende de la
    <a href="../install.html#dbm">configuración en tiempo de compilación</a>.</p>

    <p>Es crucial que, sea cual sea el programa que use para crear sus archivos de
    grupos, esté configurado para usar el mismo tipo de base de datos.</p>
</usage>
</directivesynopsis>

</modulesynopsis>
