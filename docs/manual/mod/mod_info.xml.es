<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1774505 -->
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

<modulesynopsis metafile="mod_info.xml.meta">

<name>mod_info</name>
<description>Proporciona una visión completa de la configuración
del servidor</description>
<status>Extension</status>
<sourcefile>mod_info.c</sourcefile>
<identifier>info_module</identifier>

<summary>
    <p>Para configurar <module>mod_info</module>, añada lo siguiente a su
    archivo <code>httpd.conf</code>.</p>

    <highlight language="config">
&lt;Location "/server-info"&gt;
    SetHandler server-info
&lt;/Location&gt;
    </highlight>

    <p>Puede que desee usar <module>mod_authz_host</module> dentro de la
    directiva <directive type="section" module="core">Location</directive>
    para limitar el acceso a la información de configuración de su
    servidor:</p>

    <highlight language="config">
&lt;Location "/server-info"&gt;
    SetHandler server-info
    Require host example.com
&lt;/Location&gt;
    </highlight>

    <p>Una vez configurada, la información del servidor se obtiene
    accediendo a <code>http://your.host.example.com/server-info</code></p>
</summary>

<section id="security"><title>Cuestiones de seguridad</title>
    <p>Una vez que <module>mod_info</module> se carga en el servidor, su
    capacidad de manejador está disponible en <em>todos</em> los archivos
    de configuración, incluidos los archivos por directorio (<em>por
    ejemplo</em>, <code>.htaccess</code>). Esto puede tener consecuencias
    relacionadas con la seguridad en su sitio.</p>

    <p>En particular, este módulo puede filtrar información sensible
    de las directivas de configuración de otros módulos de Apache, como
    rutas del sistema, nombres de usuario/contraseñas, nombres de bases de datos, etc. Por ello,
    este módulo <strong>solo</strong> debe
    usarse en un entorno controlado y siempre con precaución.</p>

    <p>Probablemente querrá usar <module>mod_authz_host</module>
    para limitar el acceso a la información de configuración de su servidor.</p>

    <example><title>Control de acceso</title>
    <highlight language="config">
&lt;Location "/server-info"&gt;
    SetHandler server-info
    # Permitir el acceso desde el propio servidor
    Require ip 127.0.0.1

    # Además, permitir el acceso desde la estación de trabajo local
    Require ip 192.168.1.17
&lt;/Location&gt;
      </highlight>
    </example>
</section>

<section id="queries"><title>Seleccionar la información mostrada</title>
    <p>Por defecto, la información del servidor incluye una lista de
    todos los módulos activados, y para cada módulo, una descripción de
    las directivas que entiende ese módulo, los hooks que implementa
    ese módulo, y las directivas relevantes de la configuración actual.</p>

    <p>Hay disponibles otras vistas de la información de configuración
    añadiendo una consulta a la petición <code>server-info</code>. Por
    ejemplo, <code>http://your.host.example.com/server-info?config</code>
    mostrará todas las directivas de configuración.</p>

    <dl>
        <dt><code>?&lt;module-name&gt;</code></dt>
            <dd>Solo la información relevante para el módulo indicado</dd>
        <dt><code>?config</code></dt>
            <dd>Solo las directivas de configuración, sin ordenar por módulo</dd>
        <dt><code>?hooks</code></dt>
            <dd>Solo la lista de hooks a los que está asociado cada módulo</dd>
        <dt><code>?list</code></dt>
            <dd>Solo una lista simple de los módulos activados</dd>
        <dt><code>?server</code></dt>
            <dd>Solo la información básica del servidor</dd>
        <dt><code>?providers</code></dt>
            <dd>Lista los proveedores disponibles en su servidor</dd>
    </dl>
</section>

<section id="startup"><title>Volcar la configuración en el arranque</title>
    <p>Si se establece la definición de configuración <code>-DDUMP_CONFIG</code>,
    <module>mod_info</module> volcará la configuración preanalizada a
    <code>stdout</code> durante el arranque del servidor.</p>

    <highlight language="sh">
    httpd -DDUMP_CONFIG -k start
    </highlight>

    <p>Preanalizada significa que directivas como
    <directive type="section" module="core">IfDefine</directive> y
    <directive type="section" module="core">IfModule</directive> se
    evalúan y las variables de entorno se sustituyen. Sin embargo, no
    representa el estado final de la configuración. En particular,
    no representa la fusión ni la sobrescritura que puede producirse
    con directivas repetidas.</p>

    <p>Esto es aproximadamente equivalente a la consulta <code>?config</code>.</p>
</section>

<section id="limitations"><title>Limitaciones conocidas</title>
    <p><module>mod_info</module> proporciona su información leyendo la
    configuración analizada, en lugar de leer el archivo de configuración
    original. Hay algunas limitaciones como resultado de la manera en que
    se crea el árbol de configuración analizado:</p>
    <ul>
      <li>Las directivas que se ejecutan inmediatamente en lugar de
          almacenarse en la configuración analizada no se listan. Entre ellas están
          <directive module="core">ServerRoot</directive>,
          <directive module="mod_so">LoadModule</directive>, y
          <directive module="mod_so">LoadFile</directive>.</li>
      <li>Las directivas que controlan el propio archivo de configuración, como
          <directive module="core">Include</directive>,
          <directive type="section" module="core">IfModule</directive> y
          <directive type="section" module="core">IfDefine</directive>, no se
          listan, pero sí las directivas de configuración incluidas.</li>
      <li>Los comentarios no se listan. (Esto puede considerarse una característica).</li>
      <li>Las directivas de configuración de los archivos <code>.htaccess</code> no
          se listan (ya que no forman parte de la configuración permanente del
          servidor).</li>
      <li>Las directivas de contenedor como
          <directive type="section" module="core">Directory</directive>
          se listan normalmente, pero <module>mod_info</module> no puede averiguar
          el número de línea del cierre
          <directive type="section" module="core" name="Directory">/Directory</directive>.</li>
      <li>Las directivas generadas por módulos de terceros, como <a href="http://perl.apache.org">mod_perl</a>,
          pueden no listarse.</li>
    </ul>
</section>

<directivesynopsis>
<name>AddModuleInfo</name>
<description>Añade información adicional a la información de módulo
mostrada por el manejador server-info</description>
<syntax>AddModuleInfo <var>module-name</var> <var>string</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>Esto permite mostrar el contenido de <var>string</var> como
    HTML interpretado, <strong>Información adicional</strong> para
    el módulo <var>module-name</var>. Ejemplo:</p>

    <highlight language="config">
AddModuleInfo mod_deflate.c 'See &lt;a \
    href="http://httpd.apache.org/docs/&httpd.docs;/mod/mod_deflate.html"&gt;\
    http://httpd.apache.org/docs/&httpd.docs;/mod/mod_deflate.html&lt;/a&gt;'
    </highlight>
</usage>

</directivesynopsis>
</modulesynopsis>
