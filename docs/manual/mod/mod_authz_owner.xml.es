<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1673582 -->
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

<modulesynopsis metafile="mod_authz_owner.xml.meta">

<name>mod_authz_owner</name>
<description>Autorización basada en la propiedad del archivo</description>
<status>Extension</status>
<sourcefile>mod_authz_owner.c</sourcefile>
<identifier>authz_owner_module</identifier>

<summary>
    <p>Este módulo autoriza el acceso a archivos comparando el id de usuario usado
    para la autenticación HTTP (el id de usuario web) con el propietario o
    grupo del sistema de archivos del archivo solicitado. El nombre de usuario y la contraseña
    proporcionados deben haber sido ya verificados correctamente por un módulo de autenticación,
    como <module>mod_auth_basic</module> o
    <module>mod_auth_digest</module>. <module>mod_authz_owner</module>
    reconoce dos argumentos para la directiva <directive module="mod_authz_core"
    >Require</directive>, <code>file-owner</code> y
    <code>file-group</code>, como se indica a continuación:</p>

    <dl>
      <dt><code>file-owner</code></dt>
      <dd>El nombre de usuario web proporcionado debe coincidir con el nombre que el sistema
      asigna al propietario del archivo solicitado. Es decir, si el sistema operativo
      indica que el archivo solicitado pertenece a <code>jones</code>, entonces el
      nombre de usuario usado para acceder a él a través de la web debe ser también
      <code>jones</code>.</dd>

      <dt><code>file-group</code></dt>
      <dd>El nombre del grupo del sistema propietario del archivo debe estar presente
      en una base de datos de grupos, proporcionada, por ejemplo, por <module
      >mod_authz_groupfile</module> o <module>mod_authz_dbm</module>,
      y el nombre de usuario web debe ser miembro de ese grupo. Por ejemplo, si
      el sistema operativo indica que el archivo solicitado pertenece al grupo (del sistema)
      <code>accounts</code>, el grupo <code>accounts</code> debe
      aparecer en la base de datos de grupos y el nombre de usuario web usado en la petición
      debe ser miembro de ese grupo.</dd>
    </dl>

    <note><title>Nota</title>
      <p>Si <module>mod_authz_owner</module> se usa para autorizar
      un recurso que en realidad no está presente en el sistema de archivos
      (<em>i.e.</em> un recurso virtual), denegará el acceso.</p>

      <p>En particular, nunca autorizará los recursos de <a
      href="../content-negotiation.html#multiviews">negociación de contenido
      "MultiViews"</a>.</p>
    </note>
</summary>
<seealso><directive module="mod_authz_core">Require</directive></seealso>

<section id="examples"><title>Ejemplos de configuración</title>

    <section id="examples.file-owner"><title>Require file-owner</title>
      <p>Considere un sistema multiusuario que ejecuta el servidor web Apache, en el que
      cada usuario tiene sus propios archivos en <code
      >~/public_html/private</code>. Suponiendo que existe una única
      base de datos <directive module="mod_authn_dbm">AuthDBMUserFile</directive>
      que enumera todos sus nombres de usuario web, y que estos nombres de usuario coinciden
      con los nombres de usuario del sistema que realmente son propietarios de los archivos en el servidor, entonces
      la siguiente configuración permitiría que solo el propio usuario acceda a sus
      propios archivos. Al usuario <code>jones</code> no se le permitiría acceder a
      archivos en <code>/home/smith/public_html/private</code> a menos que
      pertenecieran a <code>jones</code> en lugar de a <code>smith</code>.</p>

      <highlight language="config">
&lt;Directory "/home/*/public_html/private"&gt;
    AuthType Basic
    AuthName "MyPrivateFiles"
    AuthBasicProvider dbm
    AuthDBMUserFile "/usr/local/apache2/etc/.htdbm-all"
    Require file-owner
&lt;/Directory&gt;
      </highlight>
    </section>

    <section id="examples.file-group"><title>Require file-group</title>
      <p>Considere un sistema similar al descrito anteriormente, pero con
      algunos usuarios que comparten sus archivos de proyecto en
      <code>~/public_html/project-foo</code>. Los archivos pertenecen al
      grupo del sistema <code>foo</code> y existe una única base de datos <directive
      module="mod_authz_dbm">AuthDBMGroupFile</directive> que
      contiene todos los nombres de usuario web y su pertenencia a grupos,
      <em>i.e.</em> deben ser al menos miembros de un grupo llamado
      <code>foo</code>. Así, si <code>jones</code> y <code>smith</code>
      son ambos miembros del grupo <code>foo</code>, ambos estarán
      autorizados a acceder a los directorios <code>project-foo</code> de
      cada uno.</p>

      <highlight language="config">
&lt;Directory "/home/*/public_html/project-foo"&gt;
    AuthType Basic
    AuthName "Project Foo Files"
    AuthBasicProvider dbm

    # base de datos combinada de usuarios/grupos
    AuthDBMUserFile  "/usr/local/apache2/etc/.htdbm-all"
    AuthDBMGroupFile "/usr/local/apache2/etc/.htdbm-all"

    Satisfy All
    Require file-group
&lt;/Directory&gt;
      </highlight>
    </section>
</section>

</modulesynopsis>
