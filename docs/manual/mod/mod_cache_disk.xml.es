<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1330964 -->
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

<modulesynopsis metafile="mod_cache_disk.xml.meta">

<name>mod_cache_disk</name>
<description>Módulo de almacenamiento basado en disco para el filtro de caché HTTP.</description>
<status>Extension</status>
<sourcefile>mod_cache_disk.c</sourcefile>
<identifier>cache_disk_module</identifier>

<summary>
    <p><module>mod_cache_disk</module> implementa un gestor de almacenamiento
    basado en disco para <module>mod_cache</module>.</p>

    <p>Las cabeceras y los cuerpos de las respuestas cacheadas se almacenan por separado en
    disco, en una estructura de directorios derivada del hash md5 de la
    URL cacheada.</p>

    <p>Pueden almacenarse varias respuestas negociadas por contenido de forma concurrente,
    aunque este módulo todavía no admite el cacheo de contenido
    parcial.</p>

    <p>Las actualizaciones atómicas de la caché, tanto del archivo de cabeceras como del de cuerpo, se
    consiguen sin necesidad de bloqueos almacenando los números de dispositivo e inodo del
    archivo de cuerpo dentro del archivo de cabeceras. Esto tiene el efecto secundario de que
    las entradas de caché que se muevan manualmente a la caché serán ignoradas.</p>

    <p>Se proporciona la herramienta <program>htcacheclean</program> para listar las URL
    cacheadas, eliminar URL cacheadas, o mantener el tamaño de la caché de disco
    dentro de los límites de tamaño y/o inodos. La herramienta puede ejecutarse a demanda, o
    puede convertirse en demonio para ofrecer una supervisión continua del tamaño de los directorios.</p>

    <note><title>Nota:</title>
      <p><module>mod_cache_disk</module> requiere los servicios de
      <module>mod_cache</module>, que debe
      cargarse antes de mod_cache_disk.</p>
    </note>
    <note><title>Nota:</title>
      <p><module>mod_cache_disk</module> usa la funcionalidad sendfile para
      servir archivos desde la caché cuando la plataforma la admite, y
      cuando está activada mediante <directive module="core">EnableSendfile</directive>.
      Sin embargo, la configuración por directorio y en .htaccess de
      <directive module="core">EnableSendfile</directive> es ignorada por
      <module>mod_cache_disk</module>, ya que los ajustes correspondientes no están
      disponibles para el módulo cuando una petición se está sirviendo desde la
      caché.</p>
    </note>
</summary>
<seealso><module>mod_cache</module></seealso>
<seealso><module>mod_cache_socache</module></seealso>
<seealso><a href="../caching.html">Guía de caché</a></seealso>

<directivesynopsis>
<name>CacheRoot</name>
<description>El directorio raíz bajo el cual se almacenan los archivos de
caché</description>
<syntax>CacheRoot <var>directory</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive>CacheRoot</directive> define el nombre
    del directorio en disco que contendrá los archivos de caché. Si el módulo
    <module>mod_cache_disk</module> se ha cargado o compilado en el
    servidor Apache, esta directiva <em>debe</em> definirse. Si no se
    proporciona un valor para <directive>CacheRoot</directive>, se producirá
    un error al procesar el archivo de configuración. Las directivas
    <directive module="mod_cache_disk">CacheDirLevels</directive> y <directive
    module="mod_cache_disk">CacheDirLength</directive> definen
    la estructura de los directorios bajo el directorio raíz especificado.</p>

    <highlight language="config">
      CacheRoot c:/cacheroot
    </highlight>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>CacheDirLevels</name>
<description>El número de niveles de subdirectorios en la
caché.</description>
<syntax>CacheDirLevels <var>levels</var></syntax>
<default>CacheDirLevels 2</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive>CacheDirLevels</directive> establece el número
    de niveles de subdirectorios en la caché. Los datos cacheados se guardarán este
    número de niveles de directorio por debajo del directorio <directive module="mod_cache_disk"
    >CacheRoot</directive>.</p>
    <p>Un valor alto de <directive>CacheDirLevels</directive> combinado
    con un valor bajo de <directive>CacheDirLength</directive> dará lugar a
    una jerarquía relativamente profunda, con un número pequeño de subdirectorios en cada
    nivel.</p>

    <note>
      <p>El resultado de <directive>CacheDirLevels</directive>*
      <directive module="mod_cache_disk">CacheDirLength</directive> no debe
      ser superior a 20.</p>
    </note>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>CacheDirLength</name>
<description>El número de caracteres en los nombres de subdirectorio</description>
<syntax>CacheDirLength <var>length</var></syntax>
<default>CacheDirLength 2</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive>CacheDirLength</directive> establece el número
    de caracteres de cada nombre de subdirectorio en la jerarquía de la caché. Puede
    usarse junto con <directive>CacheDirLevels</directive> para
    determinar la estructura aproximada de la jerarquía de su caché.</p>
    <p>Un valor alto de <directive>CacheDirLength</directive> combinado
    con un valor bajo de <directive>CacheDirLevels</directive> dará lugar a
    una jerarquía relativamente plana, con un número grande de subdirectorios en cada
    nivel.</p>

    <note>
      <p>El resultado de <directive module="mod_cache_disk"
      >CacheDirLevels</directive>* <directive>CacheDirLength</directive>
      no debe ser superior a 20.</p>
    </note>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>CacheMinFileSize</name>
<description>El tamaño mínimo (en bytes) de un documento para que se coloque en la
caché</description>
<syntax>CacheMinFileSize <var>bytes</var></syntax>
<default>CacheMinFileSize 1</default>
<contextlist><context>server config</context>
  <context>virtual host</context>
  <context>directory</context>
  <context>.htaccess</context>
</contextlist>

<usage>
    <p>La directiva <directive>CacheMinFileSize</directive> establece el
    tamaño mínimo, en bytes, para que un documento se considere para su almacenamiento
    en la caché.</p>

    <highlight language="config">
      CacheMinFileSize 64
    </highlight>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>CacheMaxFileSize</name>
<description>El tamaño máximo (en bytes) de un documento para que se coloque en la
caché</description>
<syntax>CacheMaxFileSize <var>bytes</var></syntax>
<default>CacheMaxFileSize 1000000</default>
<contextlist><context>server config</context>
  <context>virtual host</context>
  <context>directory</context>
  <context>.htaccess</context>
</contextlist>

<usage>
    <p>La directiva <directive>CacheMaxFileSize</directive> establece el
    tamaño máximo, en bytes, para que un documento se considere para su almacenamiento en
    la caché.</p>

    <highlight language="config">
      CacheMaxFileSize 64000
    </highlight>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>CacheReadSize</name>
<description>El tamaño mínimo (en bytes) del documento que debe leerse y cachearse
  antes de enviar los datos aguas abajo</description>
<syntax>CacheReadSize <var>bytes</var></syntax>
<default>CacheReadSize 0</default>
<contextlist><context>server config</context>
    <context>virtual host</context>
    <context>directory</context>
    <context>.htaccess</context>
</contextlist>

<usage>
    <p>La directiva <directive>CacheReadSize</directive> establece la
    cantidad mínima de datos, en bytes, que deben leerse del backend antes de que los
    datos se envíen al cliente. El valor por defecto de cero hace que todos los datos leídos de
    cualquier tamaño se envíen aguas abajo al cliente inmediatamente a medida que llegan.
    Establecer este valor más alto hace que la caché de disco almacene en búfer al menos
    esta cantidad antes de enviar el resultado al cliente. Esto puede mejorar el
    rendimiento al cachear contenido de un proxy inverso.</p>

    <p>Esta directiva solo tiene efecto cuando los datos se están guardando en la
    caché, y no cuando se sirven desde la caché.</p>

    <highlight language="config">
      CacheReadSize 102400
    </highlight>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>CacheReadTime</name>
<description>El tiempo mínimo (en milisegundos) que debe transcurrir durante la lectura
  antes de enviar los datos aguas abajo</description>
<syntax>CacheReadTime <var>milliseconds</var></syntax>
<default>CacheReadTime 0</default>
<contextlist><context>server config</context>
  <context>virtual host</context>
  <context>directory</context>
  <context>.htaccess</context>
</contextlist>

<usage>
    <p>La directiva <directive>CacheReadTime</directive> establece la cantidad
    mínima de tiempo transcurrido que debe pasar antes de intentar enviar datos
    aguas abajo al cliente. Durante ese periodo de tiempo, los datos se almacenarán en búfer
    antes de enviar el resultado al cliente. Esto puede mejorar el rendimiento al
    cachear contenido de un proxy inverso.</p>

    <p>El valor por defecto de cero desactiva esta opción.</p>

    <p>Esta directiva solo tiene efecto cuando los datos se están guardando en la
    caché, y no cuando se sirven desde la caché. Se recomienda
    usar esta opción junto con la directiva
    <directive module="mod_cache_disk">CacheReadSize</directive> para
    asegurarse de que el servidor no almacene en búfer de forma excesiva si los datos llegan más
    rápido de lo esperado.</p>

    <highlight language="config">
      CacheReadTime 1000
    </highlight>
</usage>
</directivesynopsis>

</modulesynopsis>
