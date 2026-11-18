<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1533749 -->
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

<modulesynopsis metafile="mod_env.xml.meta">

<name>mod_env</name>
<description>Modifica el entorno que se pasa a los scripts CGI y a las
páginas SSI</description>
<status>Base</status>
<sourcefile>mod_env.c</sourcefile>
<identifier>env_module</identifier>
<summary>
    <p>Este módulo permite controlar las variables de entorno internas que
    usan varios módulos del servidor HTTP Apache. Estas variables también se
    proporcionan a los scripts CGI como variables de entorno nativas del sistema, y están disponibles
    para su uso en páginas SSI. Las variables de entorno pueden pasarse desde el shell
    que invocó el proceso <program>httpd</program>. Alternativamente,
    las variables de entorno pueden definirse o eliminarse dentro del proceso de configuración.</p>
</summary>
<seealso><a href="../env.html">Variables de entorno</a></seealso>
<seealso><directive module="mod_setenvif">SetEnvIf</directive></seealso>

<directivesynopsis>
<name>PassEnv</name>
<description>Pasa variables de entorno desde el shell</description>
<syntax>PassEnv <var>env-variable</var> [<var>env-variable</var>]
...</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>
    <p>Especifica una o más variables de entorno nativas del sistema para hacerlas disponibles
    como variables de entorno internas, que están disponibles para los módulos del servidor HTTP Apache,
    así como propagadas a los scripts CGI y a las páginas SSI. Los valores proceden del
    entorno nativo del sistema operativo del shell que invocó el
    proceso <program>httpd</program>.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
      PassEnv LD_LIBRARY_PATH
      </highlight>
    </example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SetEnv</name>
<description>Define variables de entorno</description>
<syntax>SetEnv <var>env-variable</var> [<var>value</var>]</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>
    <p>Define una variable de entorno interna, que después está disponible para los módulos
    del servidor HTTP Apache, y se pasa a los scripts CGI y a las páginas SSI.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
      SetEnv SPECIAL_PATH /foo/bin
      </highlight>
    </example>

    <p> Si omite el argumento <var>value</var>, la variable se define con
    una cadena vacía.</p>

    <note><p>Las variables de entorno internas definidas por esta directiva se establecen
    <em>después</em> de que se ejecuten la mayoría de las directivas de procesamiento temprano de la petición, como el
    control de acceso y la asignación de URI a nombre de archivo. Si la variable de entorno que está
    definiendo está pensada como entrada para esta fase temprana de procesamiento, como la
    directiva <directive module="mod_rewrite">RewriteRule</directive>, en su lugar debería
    definir la variable de entorno con
    <directive module="mod_setenvif">SetEnvIf</directive>.</p>
    </note>

</usage>
<seealso><a href="../env.html">Variables de entorno</a></seealso>
</directivesynopsis>

<directivesynopsis>
<name>UnsetEnv</name>
<description>Elimina variables del entorno</description>
<syntax>UnsetEnv <var>env-variable</var> [<var>env-variable</var>]
...</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>
    <p>Elimina una o más variables de entorno internas de las que se pasan
    a los scripts CGI y a las páginas SSI.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
      UnsetEnv LD_LIBRARY_PATH
      </highlight>
    </example>
</usage>
</directivesynopsis>

</modulesynopsis>
