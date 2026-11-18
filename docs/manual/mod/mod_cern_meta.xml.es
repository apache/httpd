<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1936574 -->
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

<modulesynopsis metafile="mod_cern_meta.xml.meta">

<name>mod_cern_meta</name>
<description>Semántica de metaarchivos del httpd de CERN</description>
<status>Deprecated</status>
<sourcefile>mod_cern_meta.c</sourcefile>
<identifier>cern_meta_module</identifier>

<summary>
    <p>Emula la semántica de metaarchivos del CERN HTTPD. Los metaarchivos son cabeceras
    HTTP que pueden mostrarse además del rango habitual de
    cabeceras de cada archivo al que se accede. Se parecen bastante a los
    archivos .asis de Apache, y permiten una forma rudimentaria de
    influir en la cabecera Expires:, además de ofrecer otras
    curiosidades. Hay muchas formas de gestionar la información
    de meta, y esta se eligió porque ya existe un gran número de
    usuarios de CERN que pueden aprovechar este módulo.</p>

    <p>Hay más información disponible sobre la <a
    href="https://www.w3.org/Daemon/User/Config/General.html#MetaDir"
    >semántica de metaarchivos de CERN</a>.</p>
</summary>

<seealso><module>mod_headers</module></seealso>
<seealso><module>mod_asis</module></seealso>

<directivesynopsis>
<name>MetaFiles</name>
<description>Activa el procesamiento de metaarchivos de CERN</description>
<syntax>MetaFiles on|off</syntax>
<default>MetaFiles off</default>
<contextlist><context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context></contextlist>
<override>Indexes</override>

<usage>
    <p>Activa/desactiva el procesamiento de metaarchivos por directorio.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>MetaDir</name>
<description>Nombre del directorio en el que se encuentra la información de
metaarchivos al estilo de CERN</description>
<syntax>MetaDir <var>directory</var></syntax>
<default>MetaDir .web</default>
<contextlist><context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context></contextlist>
<override>Indexes</override>

<usage>
    <p>Especifica el nombre del directorio en el que Apache puede encontrar
    los archivos de información de meta. El directorio suele ser un subdirectorio
    'oculto' del directorio que contiene el archivo al que se
    accede. Establézcalo a "<code>.</code>" para buscar en el mismo directorio
    que el archivo:</p>

    <highlight language="config">
MetaDir .
    </highlight>

    <p>O, para establecerlo a un subdirectorio del directorio que contiene
    los archivos:</p>

    <highlight language="config">
MetaDir .meta
    </highlight>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>MetaSuffix</name>
<description>Sufijo del nombre del archivo que contiene la
información de meta al estilo de CERN</description>
<syntax>MetaSuffix <var>suffix</var></syntax>
<default>MetaSuffix .meta</default>
<contextlist><context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context></contextlist>
<override>Indexes</override>

<usage>
    <p>Especifica el sufijo del nombre del archivo que contiene la
    información de meta. Por ejemplo, los valores por defecto de las dos
    directivas harán que una petición a
    <code>DOCUMENT_ROOT/somedir/index.html</code> busque en
    <code>DOCUMENT_ROOT/somedir/.web/index.html.meta</code> y
    use su contenido para generar información de cabecera MIME
    adicional.</p>

    <example><title>Ejemplo:</title>
    <highlight language="config">
      MetaSuffix .meta
     </highlight>
    </example>
</usage>
</directivesynopsis>

</modulesynopsis>
