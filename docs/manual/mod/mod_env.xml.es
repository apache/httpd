<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1938506 -->
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

<directivesynopsis>
<name>SetEnvFromFile</name>
<description>Define variables de entorno a partir de un archivo</description>
<syntax>SetEnvFromFile <var>file-path</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>
<compatibility>Disponible en la versión 2.5.1 y posteriores.</compatibility>

<usage>
    <p>Define variables de entorno internas leídas de un archivo, que después están
    disponibles para los módulos del servidor HTTP Apache, y se pasan a los scripts CGI y a
    las páginas SSI. Esto es equivalente a una serie de directivas <directive
    module="mod_env">SetEnv</directive>, una por variable, pero mantiene
    los valores en un archivo independiente.</p>

    <p><var>file-path</var> es una ruta absoluta o una ruta relativa
    a <directive module="core">ServerRoot</directive>. El archivo se lee
    una vez cuando se procesa la configuración; los cambios en él solo surten efecto después de
    reiniciar el servidor.</p>

    <p>Cada línea del archivo tiene la forma <code>name=value</code>. Las líneas en blanco
    y las que comienzan por <code>#</code> se ignoran, y los espacios en blanco iniciales y
    finales se eliminan. Si una línea no contiene ningún <code>=</code>, la
    variable se define con una cadena vacía. Una línea que termine en barra invertida
    (<code>\</code>) continúa en la siguiente línea, igual que en los archivos de
    configuración principales.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
      SetEnvFromFile conf/app.env
      </highlight>
    </example>

    <example><title>Archivo de ejemplo (<code>conf/app.env</code>)</title>
    <highlight language="config">
      # Configuración de la aplicación
      APP_MODE=production
      SPECIAL_PATH=/foo/bin
      </highlight>
    </example>

    <note><p>Como con <directive module="mod_env">SetEnv</directive>, las
    variables se definen <em>después</em> de que se ejecuten la mayoría de las directivas de procesamiento temprano
    de la petición, como el control de acceso y la asignación de URI a nombre de archivo.</p>
    </note>

    <note type="warning"><title>Seguridad</title>
    <p>A diferencia de <directive module="mod_env">SetEnv</directive>, esta directiva
    lee el <em>contenido</em> de un archivo en el entorno interno, donde
    puede quedar expuesto a través de CGI, SSI, registros y otros consumidores. Para
    evitar que un autor no confiable divulgue el contenido de cualquier archivo
    legible por el servidor (por ejemplo, archivos de configuración o credenciales
    situados en otro lugar del host), <directive>SetEnvFromFile</directive>
    <strong>no</strong> está permitida en archivos <code>.htaccess</code>; solo puede
    usarse en la configuración principal del servidor.</p>
    </note>
</usage>
<seealso><a href="../env.html">Variables de entorno</a></seealso>
<seealso><directive module="mod_env">SetEnv</directive></seealso>
</directivesynopsis>

</modulesynopsis>
