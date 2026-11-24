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

<modulesynopsis metafile="mod_version.xml.meta">
<name>mod_version</name>
<description>Configuración dependiente de la versión</description>
<status>Extension</status>
<sourcefile>mod_version.c</sourcefile>
<identifier>version_module</identifier>

<summary>
    <p>Este módulo está diseñado para su uso en suites de pruebas y en redes
    grandes que tienen que gestionar distintas versiones de httpd y
    distintas configuraciones. Proporciona un nuevo contenedor, <directive
    type="section" module="mod_version">IfVersion</directive>, que
    permite una comprobación de versión flexible, incluyendo comparaciones
    numéricas y expresiones regulares.</p>

    <example><title>Ejemplos</title>
    <highlight language="config">
&lt;IfVersion 2.4.2&gt;
    # la versión actual de httpd es exactamente 2.4.2
&lt;/IfVersion&gt;

&lt;IfVersion >= 2.5&gt;
    # usar funcionalidades realmente nuevas :-)
&lt;/IfVersion&gt;
      </highlight>
    </example>

    <p>Vea a continuación más posibilidades.</p>
</summary>

<directivesynopsis type="section">
<name>IfVersion</name>
<description>contiene configuración dependiente de la versión</description>
<syntax>&lt;IfVersion [[!]<var>operator</var>] <var>version</var>&gt; ...
&lt;/IfVersion&gt;</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>All</override>

<usage>
    <p>La sección <directive type="section">IfVersion</directive> engloba
    directivas de configuración que solo se ejecutan si la versión de
    <program>httpd</program>
    cumple el criterio deseado. Para las comparaciones normales (numéricas), el
    argumento <var>version</var> tiene el formato
    <code><var>major</var>[.<var>minor</var>[.<var>patch</var>]]</code>, por ejemplo,
    <code>2.1.0</code> o <code>2.2</code>. <var>minor</var> y
    <var>patch</var> son opcionales. Si se omiten estos números, se
    consideran cero. Los siguientes <var>operator</var>es numéricos son
    posibles:</p>

    <table style="zebra" border="1">
    <tr><th><var>operator</var></th><th>descripción</th></tr>
    <tr><td><code>=</code> o <code>==</code></td>
        <td>la versión de httpd es igual</td></tr>
    <tr><td><code>&gt;</code></td>
        <td>la versión de httpd es mayor que</td></tr>
    <tr><td><code>&gt;=</code></td>
        <td>la versión de httpd es mayor o igual</td></tr>
    <tr><td><code>&lt;</code></td>
        <td>la versión de httpd es menor que</td></tr>
    <tr><td><code>&lt;=</code></td>
        <td>la versión de httpd es menor o igual</td></tr>
    </table>

    <example><title>Ejemplo</title>
    <highlight language="config">
&lt;IfVersion >= 2.3&gt;
    # esto solo ocurre en versiones mayores o
    # iguales a 2.3.0.
&lt;/IfVersion&gt;
      </highlight>
    </example>

    <p>Además de la comparación numérica, es posible comparar una
    <glossary ref="regex">expresión regular</glossary>
    con la versión de httpd. Hay dos formas de escribirla:</p>

    <table style="zebra" border="1">
    <tr><th><var>operator</var></th><th>descripción</th></tr>
    <tr><td><code>=</code> o <code>==</code></td>
        <td><var>version</var> tiene la forma
            <code>/<var>regex</var>/</code></td></tr>
    <tr><td><code>~</code></td>
        <td><var>version</var> tiene la forma
            <code><var>regex</var></code></td></tr>
    </table>

    <example><title>Ejemplo</title>
    <highlight language="config">
&lt;IfVersion = /^2.4.[01234]$/&gt;
    # por ejemplo, solución alternativa para versiones con errores
&lt;/IfVersion&gt;
      </highlight>
    </example>

    <p>Para invertir el significado, todos los operadores pueden ir precedidos de
    un signo de exclamación (<code>!</code>):</p>

    <highlight language="config">
&lt;IfVersion !~ ^2.4.[01234]$&gt;
    # no para esas versiones
&lt;/IfVersion&gt;
    </highlight>

    <p>Si se omite el <var>operator</var>, se asume que es
    <code>=</code>.</p>
</usage>
</directivesynopsis>

</modulesynopsis>
