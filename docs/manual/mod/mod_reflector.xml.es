<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1673892 -->
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

<modulesynopsis metafile="mod_reflector.xml.meta">

<name>mod_reflector</name>
<description>Refleja el cuerpo de una petición como respuesta a través de la pila de filtros de salida.</description>
<status>Base</status>
<sourcefile>mod_reflector.c</sourcefile>
<identifier>reflector_module</identifier>
<compatibility>Versión 2.3 y posteriores</compatibility>

<summary>
    <p>Este módulo permite que los cuerpos de las peticiones se reflejen de vuelta al
    cliente, pasando en el proceso la petición a través de la pila de filtros
    de salida. Una cadena de filtros configurada adecuadamente puede usarse para transformar
    la petición en una respuesta. Este módulo puede usarse para convertir un filtro
    de salida en un servicio HTTP.</p>
</summary>

<section id="examples"><title>Ejemplos</title>
    <dl>
    <dt>Servicio de compresión</dt>
    <dd>Pasa el cuerpo de la petición a través del filtro DEFLATE para comprimir el
    cuerpo. Esta petición requiere una cabecera de petición Content-Encoding que contenga
    "gzip" para que el filtro devuelva datos comprimidos.
    <highlight language="config">
&lt;Location "/compress"&gt;
    SetHandler reflector
    SetOutputFilter DEFLATE
&lt;/Location&gt;
    </highlight>
    </dd>

    <dt>Servicio de reducción de resolución de imágenes</dt>
    <dd>Pasa el cuerpo de la petición a través de un filtro de reducción de resolución de imágenes, y refleja
    los resultados al solicitante.
    <highlight language="config">
&lt;Location "/downsample"&gt;
    SetHandler reflector
    SetOutputFilter DOWNSAMPLE
&lt;/Location&gt;
    </highlight>
    </dd>
    </dl>
</section>

<directivesynopsis>
<name>ReflectorHeader</name>
<description>Refleja una cabecera de entrada en las cabeceras de salida</description>
<syntax>ReflectorHeader <var>inputheader</var> <var>[outputheader]</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>Options</override>

<usage>
    <p>Esta directiva controla el reflejo de las cabeceras de la petición en la respuesta.
    El primer argumento es el nombre de la cabecera de la petición que se va a copiar. Si se especifica
    el segundo argumento opcional, se usará como el nombre de la cabecera de la
    respuesta; en caso contrario, se usará el nombre original de la cabecera de la petición.</p>
</usage>
</directivesynopsis>

</modulesynopsis>
