<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933457 -->
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

<modulesynopsis metafile="mod_cache_socache.xml.meta">

<name>mod_cache_socache</name>
<description>Módulo de almacenamiento basado en caché de objetos compartidos (socache) para
el filtro de caché HTTP.</description>
<status>Extension</status>
<sourcefile>mod_cache_socache.c</sourcefile>
<identifier>cache_socache_module</identifier>

<summary>
    <p><module>mod_cache_socache</module> implementa un gestor de almacenamiento basado en
    caché de objetos compartidos (socache) para <module>mod_cache</module>.</p>

    <p>Las cabeceras y los cuerpos de las respuestas cacheadas se combinan y se almacenan
    bajo una única clave en la caché de objetos compartidos. Hay disponibles
    <a href="../socache.html">varias implementaciones</a> de cachés de objetos
    compartidos entre las que elegir.</p>

    <p>Pueden almacenarse varias respuestas negociadas por contenido de forma concurrente,
    aunque este módulo todavía no admite el cacheo de contenido
    parcial.</p>

    <highlight language="config">
# Activar el cacheo
CacheSocache shmcb
CacheSocacheMaxSize 102400
&lt;Location "/foo"&gt;
    CacheEnable socache
&lt;/Location&gt;

# Recurrir a la caché de disco
CacheSocache shmcb
CacheSocacheMaxSize 102400
&lt;Location "/foo"&gt;
    CacheEnable socache
    CacheEnable disk
&lt;/Location&gt;
    </highlight>

    <note><title>Nota:</title>
      <p><module>mod_cache_socache</module> requiere los servicios de
      <module>mod_cache</module>, que debe cargarse antes que
      <module>mod_cache_socache</module>.</p>
    </note>
</summary>
<seealso><module>mod_cache</module></seealso>
<seealso><module>mod_cache_disk</module></seealso>
<seealso><a href="../caching.html">Guía de caché</a></seealso>

<directivesynopsis>
<name>CacheSocache</name>
<description>La implementación de caché de objetos compartidos que se usará</description>
<syntax>CacheSocache <var>type[:args]</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>
<compatibility>Disponible en Apache 2.4.5 y posteriores</compatibility>

<usage>
    <p>La directiva <directive>CacheSocache</directive> define el nombre de
    la implementación de caché de objetos compartidos que se usará, seguido de argumentos
    opcionales para dicha implementación. Hay disponibles <a href="../socache.html">varias
    implementaciones</a> de cachés de objetos compartidos entre las que
    elegir.</p>

    <highlight language="config">
      CacheSocache shmcb
    </highlight>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>CacheSocacheMaxTime</name>
<description>El tiempo máximo (en segundos) para que un documento se coloque en la
caché</description>
<syntax>CacheSocacheMaxTime <var>seconds</var></syntax>
<default>CacheSocacheMaxTime 86400</default>
<contextlist><context>server config</context>
  <context>virtual host</context>
  <context>directory</context>
  <context>.htaccess</context>
</contextlist>
<compatibility>Disponible en Apache 2.4.5 y posteriores</compatibility>

<usage>
    <p>La directiva <directive>CacheSocacheMaxTime</directive> establece el
    tiempo de vida de frescura máximo, en segundos, para que un documento se almacene en
    la caché. Este valor sobrescribe el tiempo de vida de frescura definido para el
    documento por el protocolo HTTP.</p>

    <highlight language="config">
      CacheSocacheMaxTime 86400
    </highlight>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>CacheSocacheMinTime</name>
<description>El tiempo mínimo (en segundos) para que un documento se coloque en la
caché</description>
<syntax>CacheSocacheMinTime <var>seconds</var></syntax>
<default>CacheSocacheMinTime 600</default>
<contextlist><context>server config</context>
  <context>virtual host</context>
  <context>directory</context>
  <context>.htaccess</context>
</contextlist>
<compatibility>Disponible en Apache 2.4.5 y posteriores</compatibility>

<usage>
    <p>La directiva <directive>CacheSocacheMinTime</directive> establece la
    cantidad de segundos más allá del tiempo de vida de frescura de la respuesta durante los
    cuales la respuesta debe mantenerse en la caché de objetos compartidos. Si una respuesta se
    almacena solo durante su tiempo de vida de frescura, no habrá oportunidad de
    revalidarla para que vuelva a ser fresca.</p>

    <highlight language="config">
      CacheSocacheMinTime 600
    </highlight>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>CacheSocacheMaxSize</name>
<description>El tamaño máximo (en bytes) de una entrada para que se coloque en la
caché</description>
<syntax>CacheSocacheMaxSize <var>bytes</var></syntax>
<default>CacheSocacheMaxSize 102400</default>
<contextlist><context>server config</context>
  <context>virtual host</context>
  <context>directory</context>
  <context>.htaccess</context>
</contextlist>
<compatibility>Disponible en Apache 2.4.5 y posteriores</compatibility>

<usage>
    <p>La directiva <directive>CacheSocacheMaxSize</directive> establece el
    tamaño máximo, en bytes, de las cabeceras y el cuerpo combinados de un documento
    para que se considere su almacenamiento en la caché. El valor debe ser de al
    menos 1024 bytes. Cuanto más grandes sean las cabeceras que
    se almacenan junto al cuerpo, más pequeño podrá ser este.</p>

    <p>El módulo <module>mod_cache_socache</module> solo intentará
    cachear respuestas que tengan una longitud de contenido explícita, o que sean
    lo bastante pequeñas como para escribirse de una sola vez. Esto se hace para permitir que el
    módulo <module>mod_cache_disk</module> tenga la oportunidad de cachear
    respuestas más grandes que las que puede cachear
    <module>mod_cache_socache</module>.</p>

    <highlight language="config">
      CacheSocacheMaxSize 102400
    </highlight>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>CacheSocacheReadSize</name>
<description>El tamaño mínimo (en bytes) del documento que debe leerse y cachearse
  antes de enviar los datos aguas abajo</description>
<syntax>CacheSocacheReadSize <var>bytes</var></syntax>
<default>CacheSocacheReadSize 0</default>
<contextlist><context>server config</context>
    <context>virtual host</context>
    <context>directory</context>
    <context>.htaccess</context>
</contextlist>
<compatibility>Disponible en Apache 2.4.5 y posteriores</compatibility>

<usage>
    <p>La directiva <directive>CacheSocacheReadSize</directive> establece la
    cantidad mínima de datos, en bytes, que deben leerse del backend antes de que los
    datos se envíen al cliente. El valor por defecto de cero hace que todos los datos leídos de
    cualquier tamaño se envíen aguas abajo al cliente inmediatamente a medida que llegan.
    Establecer este valor más alto hace que la caché de disco almacene en búfer al menos
    esta cantidad antes de enviar el resultado al cliente. Esto puede mejorar el
    rendimiento al cachear contenido de un proxy inverso lento.</p>

    <p>Esta directiva solo tiene efecto cuando los datos se están guardando en la
    caché, y no cuando se sirven desde la caché.</p>

    <highlight language="config">
      CacheSocacheReadSize 102400
    </highlight>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>CacheSocacheReadTime</name>
<description>El tiempo mínimo (en milisegundos) que debe transcurrir durante la lectura
  antes de enviar los datos aguas abajo</description>
<syntax>CacheSocacheReadTime <var>milliseconds</var></syntax>
<default>CacheSocacheReadTime 0</default>
<contextlist><context>server config</context>
  <context>virtual host</context>
  <context>directory</context>
  <context>.htaccess</context>
</contextlist>
<compatibility>Disponible en Apache 2.4.5 y posteriores</compatibility>

<usage>
    <p>La directiva <directive>CacheSocacheReadTime</directive> establece la cantidad
    mínima de tiempo transcurrido que debe pasar antes de intentar enviar datos
    aguas abajo al cliente. Durante ese periodo de tiempo, los datos se almacenarán en búfer
    antes de enviar el resultado al cliente. Esto puede mejorar el rendimiento al
    cachear contenido de un proxy inverso.</p>

    <p>El valor por defecto de cero desactiva esta opción.</p>

    <p>Esta directiva solo tiene efecto cuando los datos se están guardando en la
    caché, y no cuando se sirven desde la caché. Se recomienda
    usar esta opción junto con la directiva
    <directive module="mod_cache_socache">CacheSocacheReadSize</directive>
    para asegurarse de que el servidor no almacene en búfer de forma excesiva si los datos llegan más
    rápido de lo esperado.</p>

    <highlight language="config">
      CacheSocacheReadTime 1000
    </highlight>
</usage>
</directivesynopsis>

</modulesynopsis>
