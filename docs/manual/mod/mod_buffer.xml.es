<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933748 -->
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

<modulesynopsis metafile="mod_buffer.xml.meta">

<name>mod_buffer</name>
<description>Soporte para el almacenamiento en búfer de las peticiones</description>
<status>Extension</status>
<sourcefile>mod_buffer.c</sourcefile>
<identifier>buffer_module</identifier>
<compatibility>Disponible en Apache 2.3 y posteriores</compatibility>

<summary>
    <p>Este módulo ofrece la posibilidad de almacenar en búfer las pilas de
    filtros de entrada y de salida.</p>

    <p>En determinadas circunstancias, los generadores de contenido pueden crear
    contenido en pequeños fragmentos. Para favorecer la reutilización de memoria, los fragmentos
    en memoria tienen siempre un tamaño de 8k, independientemente del tamaño del
    fragmento en sí. Cuando una petición genera muchos fragmentos pequeños,
    esto puede crear una huella de memoria grande mientras se procesa la
    petición, así como una cantidad de datos innecesariamente grande en la
    red. La incorporación de un búfer condensa la respuesta en la
    menor cantidad de fragmentos posible.</p>

    <p>Cuando httpd se usa delante de un generador de contenido costoso,
    almacenar en búfer la respuesta puede permitir que el backend termine
    de procesar y libere recursos antes, dependiendo de cómo esté
    diseñado el backend.</p>

    <p>El filtro buffer puede añadirse tanto a la pila de filtros de entrada
    como a la de salida, según corresponda, usando las directivas
    <directive module="core">SetInputFilter</directive>,
    <directive module="core">SetOutputFilter</directive>,
    <directive module="mod_mime">AddOutputFilter</directive> o
    <directive module="mod_filter">AddOutputFilterByType</directive>.</p>

      <example><title>Usar buffer con mod_include</title>
      <highlight language="config">
        AddOutputFilterByType INCLUDES;BUFFER text/html
        </highlight>
      </example>

    <note type="warning">Los filtros buffer leen la petición/respuesta en
        RAM y luego reempaquetan la petición/respuesta en la menor cantidad de
        buckets de memoria posible, a costa de tiempo de CPU. Cuando la
        petición/respuesta ya está empaquetada de forma eficiente, almacenarla
        en búfer podría hacer que la petición/respuesta sea más lenta que si
        no se usara ningún búfer en absoluto. Estos filtros deben usarse con
        cuidado, y solo cuando sea necesario.</note>

</summary>
<seealso><a href="../filter.html">Filtros</a></seealso>

<directivesynopsis>
<name>BufferSize</name>
<description>Tamaño máximo en bytes que almacenará en búfer el filtro buffer</description>
<syntax>BufferSize integer</syntax>
<default>BufferSize 131072</default>
<contextlist>
<context>directory</context>
<context>.htaccess</context>
</contextlist>

<usage>
    <p>La directiva <directive module="mod_buffer">BufferSize</directive>
    especifica la cantidad de datos en bytes que se almacenarán en búfer
    antes de leerse o escribirse en cada petición.
    El valor por defecto es 128 kilobytes.</p>
</usage>
</directivesynopsis>

</modulesynopsis>
