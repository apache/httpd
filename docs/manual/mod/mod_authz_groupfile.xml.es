<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933687 -->
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

<modulesynopsis metafile="mod_authz_groupfile.xml.meta">

<name>mod_authz_groupfile</name>
<description>Autorización de grupos usando archivos de texto plano</description>
<status>Base</status>
<sourcefile>mod_authz_groupfile.c</sourcefile>
<identifier>authz_groupfile_module</identifier>

<summary>
    <p>Este módulo proporciona capacidades de autorización para que se
    pueda permitir o denegar a los usuarios autenticados el acceso a
    partes del sitio web según su pertenencia a un grupo. <module
    >mod_authz_dbm</module> ofrece una funcionalidad similar.</p>
</summary>

<seealso><directive module="mod_authz_core">Require</directive></seealso>
<seealso><a href="mod_authz_core.html#authzresults">Estados de resultado de la autorización</a></seealso>

<section id="requiredirectives"><title>Las directivas Require</title>

    <p>Las directivas <directive module="mod_authz_core">Require</directive>
    de Apache se usan durante la fase de autorización para asegurar que
    un usuario tiene permitido el acceso a un recurso. mod_authz_groupfile extiende los
    tipos de autorización con <code>group</code> y <code>group-file</code>.
    </p>

    <p>Desde la versión 2.4.8, se admiten <a href="../expr.html">expresiones</a>
    dentro de las directivas require de groupfile.</p>

<section id="reqgroup"><title>Require group</title>

    <p>Esta directiva especifica la pertenencia a un grupo que se requiere para que
    el usuario obtenga acceso.</p>

    <highlight language="config">
      Require group admin
    </highlight>

</section>

<section id="reqfilegroup"><title>Require file-group</title>

    <p>Cuando se especifica esta directiva, se consultan los permisos
    del sistema de archivos sobre el archivo al que se accede. El usuario debe ser miembro de
    un grupo con el mismo nombre que el grupo propietario del archivo.
    Vea <module>mod_authz_owner</module> para más
    detalles.</p>

    <highlight language="config">
      Require file-group
    </highlight>

</section>

</section>

<directivesynopsis>
<name>AuthGroupFile</name>
<description>Establece el nombre de un archivo de texto que contiene la lista
de grupos de usuarios para la autorización</description>
<syntax>AuthGroupFile <var>file-path</var></syntax>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>La directiva <directive>AuthGroupFile</directive> establece el
    nombre de un archivo de texto que contiene la lista de grupos de usuarios para
    la autorización de usuarios. <var>File-path</var> es la ruta al archivo
    de grupos. Si no es absoluta, se trata como relativa a <directive
    module="core">ServerRoot</directive>.</p>

    <p>Cada línea del archivo de grupos contiene un nombre de grupo seguido de
    dos puntos, seguido de los nombres de los usuarios miembros separados por espacios.</p>

    <example><title>Ejemplo:</title>
      mygroup: bob joe anne
    </example>

    <p>Tenga en cuenta que buscar en archivos de texto grandes es <em>muy</em>
    ineficiente; <directive module="mod_authz_dbm"
    >AuthDBMGroupFile</directive> ofrece un rendimiento mucho mejor.</p>

    <note type="warning"><title>Seguridad</title>
      <p>Asegúrese de que <directive>AuthGroupFile</directive> se
      almacena fuera del árbol de documentos del servidor web; <em>no</em>
      lo coloque en el directorio que protege. De lo contrario, los clientes
      podrían descargar el <directive>AuthGroupFile</directive>.</p>
    </note>
</usage>
</directivesynopsis>

</modulesynopsis>
