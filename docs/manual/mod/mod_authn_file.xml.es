<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1421821 -->
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

<modulesynopsis metafile="mod_authn_file.xml.meta">

<name>mod_authn_file</name>
<description>Autenticación de usuarios mediante archivos de texto</description>
<status>Base</status>
<sourcefile>mod_authn_file.c</sourcefile>
<identifier>authn_file_module</identifier>

<summary>
    <p>Este módulo proporciona a los front-ends de autenticación como
    <module>mod_auth_digest</module> y <module>mod_auth_basic</module>
    la capacidad de autenticar usuarios buscándolos en archivos de contraseñas en texto plano.
    <module>mod_authn_dbm</module> ofrece una funcionalidad similar.</p>

    <p>Cuando se usa <module>mod_auth_basic</module> o
    <module>mod_auth_digest</module>, este módulo se invoca mediante la
    directiva <directive module="mod_auth_basic">AuthBasicProvider</directive> o
    <directive module="mod_auth_digest">AuthDigestProvider</directive>
    con el valor <code>file</code>.</p>
</summary>
<seealso>
  <directive module="mod_auth_basic">AuthBasicProvider</directive>
</seealso>
<seealso>
  <directive module="mod_auth_digest">AuthDigestProvider</directive>
</seealso>
<seealso><program>htpasswd</program></seealso>
<seealso><program>htdigest</program></seealso>
<seealso><a href="../misc/password_encryptions.html">Formatos de contraseña</a></seealso>

<directivesynopsis>
<name>AuthUserFile</name>
<description>Establece el nombre de un archivo de texto que contiene la lista de usuarios y
contraseñas para la autenticación</description>
<syntax>AuthUserFile <var>file-path</var></syntax>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>La directiva <directive>AuthUserFile</directive> establece el nombre
    de un archivo de texto que contiene la lista de usuarios y contraseñas para
    la autenticación de usuarios. <var>File-path</var> es la ruta al archivo
    de usuarios. Si no es absoluta, se trata como relativa a
    <directive module="core">ServerRoot</directive>.</p>

    <p>Cada línea del archivo de usuarios contiene un nombre de usuario seguido de
    dos puntos, seguido de la contraseña cifrada. Si el mismo ID de
    usuario se define varias veces, <module>mod_authn_file</module> usará
    la primera aparición para verificar la contraseña.</p>

    <p>El formato de la contraseña cifrada depende de qué front-end de
    autenticación se esté usando (por ejemplo, <module>mod_auth_basic</module> o
    <module>mod_auth_digest</module>). Vea <a
    href="../misc/password_encryptions.html">Formatos de contraseña</a> para
    más información.</p>

    <p>Para <module>mod_auth_basic</module>, use la utilidad <program>htpasswd</program>,
    que se instala como parte de la distribución binaria, o que
    puede encontrarse en <code>src/support</code>. Vea la
    <a href="../programs/htpasswd.html">página de manual</a> para más detalles.
    En resumen:</p>

    <p>Cree un archivo de contraseñas <code>Filename</code> con
    <code>username</code> como ID inicial. Se le pedirá
    la contraseña:</p>

    <example>
      htpasswd -c Filename username
    </example>

    <p>Añada o modifique <code>username2</code> en el archivo de contraseñas
    <code>Filename</code>:</p>

    <example>
      htpasswd Filename username2
    </example>

    <p>Tenga en cuenta que buscar en archivos de texto grandes es <em>muy</em>
    ineficiente; en su lugar debería usarse <directive
    module="mod_authn_dbm">AuthDBMUserFile</directive>.</p>

    <p>Para <module>mod_auth_digest</module>, use <program>htdigest</program>
    en su lugar. Tenga en cuenta que no se pueden mezclar datos de usuario para la autenticación Digest
    y la autenticación Basic en el mismo archivo.</p>

    <note type="warning"><title>Seguridad</title>
      <p>Asegúrese de que <directive>AuthUserFile</directive> se
      almacena fuera del árbol de documentos del servidor web. No
      lo coloque <strong>en ningún caso</strong> en el directorio que protege.
      De lo contrario, los clientes podrían descargar el
      <directive>AuthUserFile</directive>.</p>
    </note>
</usage>
</directivesynopsis>

</modulesynopsis>
