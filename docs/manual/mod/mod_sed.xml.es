<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1901511 -->
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

<modulesynopsis metafile="mod_sed.xml.meta">

<name>mod_sed</name>
<description>Filtra el contenido de entrada (petición) y de salida (respuesta) usando la sintaxis de <code>sed</code></description>
<status>Experimental</status>
<sourcefile>mod_sed.c sed0.c sed1.c regexp.c regexp.h sed.h</sourcefile>
<identifier>sed_module</identifier>
<compatibility>Disponible en Apache 2.3 y posteriores</compatibility>

<summary>
<p>
<module>mod_sed</module> es un filtro de contenido en proceso. El filtro <module>mod_sed</module> implementa los comandos de edición
de <code>sed</code> implementados por el programa <code>sed</code> de
Solaris 10, tal como se describe en la <a href="http://www.gnu.org/software/sed/manual/sed.txt">página de
manual</a>. Sin embargo, a diferencia de <code>sed</code>, <module>mod_sed</module> no toma los datos de la
entrada estándar. En su lugar, el filtro actúa sobre los datos de la entidad enviados entre el cliente y el
servidor. <module>mod_sed</module> puede usarse como filtro de entrada o de salida. <module>mod_sed</module> es un
filtro de contenido, lo que significa que no puede usarse para modificar las cabeceras http del cliente o del
servidor.
</p>
<p>
El filtro de salida de <module>mod_sed</module> acepta un bloque de datos, ejecuta los scripts de <code>sed</code> sobre esos datos y genera la salida que se pasa al siguiente filtro de la cadena.
</p>

<p>
El filtro de entrada de <module>mod_sed</module> lee los datos del siguiente filtro de la cadena, ejecuta los scripts de <code>sed</code> y devuelve los datos generados al filtro que lo invocó en la cadena de filtros.
</p>

<p>
Tanto el filtro de entrada como el de salida solo procesan los datos si se detectan caracteres de salto de línea en el contenido. Al final de los datos, el resto se trata como la última línea. Las líneas de más de 8 MB de longitud provocan un error, en la versión 2.4.54 y posteriores.
</p>

</summary>

<section id="sampleconf"><title>Configuración de ejemplo</title>
    <example><title>Añadir un filtro de salida</title>
    <highlight language="config">
# En el siguiente ejemplo, el filtro sed cambiará la cadena
# "monday" por "MON" y la cadena "sunday" por "SUN" en los documentos html
# antes de enviarlos al cliente.
&lt;Directory "/var/www/docs/sed"&gt;
    AddOutputFilter Sed html
    OutputSed "s/monday/MON/g"
    OutputSed "s/sunday/SUN/g"
&lt;/Directory&gt;
    </highlight>
    </example>

    <example><title>Añadir un filtro de entrada</title>
    <highlight language="config">
# En el siguiente ejemplo, el filtro sed cambiará la cadena
# "monday" por "MON" y la cadena "sunday" por "SUN" en los datos POST
# enviados a PHP.
&lt;Directory "/var/www/docs/sed"&gt;
    AddInputFilter Sed php
    InputSed "s/monday/MON/g"
    InputSed "s/sunday/SUN/g"
&lt;/Directory&gt;
        </highlight>
    </example>
</section>
<section id="sed_commands"><title>Comandos de Sed</title>
    <p>
    Puede encontrar los detalles completos del comando <code>sed</code> en la
   <a href="http://www.gnu.org/software/sed/manual/sed.txt">página de manual
de sed</a>.
    </p>
    <dl>
        <dt><code>b</code></dt>
        <dd>Salta a la etiqueta especificada (similar a un goto).</dd>
        <dt><code>h</code></dt>
        <dd>Copia la línea actual al búfer de retención (hold buffer).</dd>
        <dt><code>H</code></dt>
        <dd>Añade la línea actual al búfer de retención.</dd>
        <dt><code>g</code></dt>
        <dd>Copia el búfer de retención a la línea actual.</dd>
        <dt><code>G</code></dt>
        <dd>Añade el búfer de retención a la línea actual.</dd>
        <dt><code>x</code></dt>
        <dd>Intercambia el contenido del búfer de retención y de la línea actual.</dd>
    </dl>
</section>

<directivesynopsis>
<name>OutputSed</name>
<description>Comando sed para filtrar el contenido de la respuesta</description>
<syntax>OutputSed <var>sed-command</var></syntax>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>

<usage>
    <p>La directiva <directive>OutputSed</directive> especifica el comando
    <code>sed</code> que se ejecutará sobre la respuesta.
    </p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>InputSed</name>
<description>Comando sed para filtrar los datos de la petición (normalmente datos <code>POST</code>)</description>
<syntax>InputSed <var>sed-command</var></syntax>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>

<usage>
    <p>La directiva <directive>InputSed</directive> especifica el comando <code>sed</code>
    que se ejecutará sobre los datos de la petición, por ejemplo, los datos <code>POST</code>.
    </p>
</usage>
</directivesynopsis>

</modulesynopsis>
