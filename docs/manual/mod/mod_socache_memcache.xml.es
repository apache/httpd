<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933179 -->
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

<modulesynopsis metafile="mod_socache_memcache.xml.meta">

<name>mod_socache_memcache</name>
<description>Proveedor de caché de objetos compartidos basado en memcache.</description>
<status>Extension</status>
<sourcefile>mod_socache_memcache.c</sourcefile>
<identifier>socache_memcache_module</identifier>

<summary>
    <p><code>mod_socache_memcache</code> es un proveedor de caché de objetos compartidos
    que permite crear y acceder a una caché respaldada por el sistema de
    almacenamiento en caché de objetos de memoria distribuida de alto rendimiento
    <a href="http://memcached.org/">memcached</a>.
    </p>


    <p>El método "create" de este proveedor de caché de objetos compartidos requiere una
       lista separada por comas de especificaciones host/puerto de memcached. Si se usa
       este proveedor a través de la configuración de otro módulo (como
       <directive module="mod_ssl">SSLSessionCache</directive>), proporcione
       la lista de servidores como el parámetro opcional "arg".</p>

     <highlight language="config">
         SSLSessionCache memcache:memcache.example.com:12345,memcache2.example.com:12345
     </highlight>

    <p>Puede encontrar los detalles de otros proveedores de caché de objetos compartidos
    <a href="../socache.html">aquí</a>.
    </p>

</summary>

<directivesynopsis>
<name>MemcacheConnTTL</name>
<description>Tiempo de mantenimiento de conexiones inactivas</description>
<syntax>MemcacheConnTTL <em>num[units]</em></syntax>
<default>MemcacheConnTTL 15s</default>
<contextlist>
<context>server config</context>
<context>virtual host</context>
</contextlist>
<compatibility>Disponible en Apache 2.4.17 y posteriores</compatibility>

<usage>

    <p>Establece el tiempo durante el que se mantienen activas las conexiones
    inactivas con los servidores memcache (solo en plataformas con hilos).</p>

    <p>Los valores válidos para <directive>MemcacheConnTTL</directive> son tiempos
    de hasta una hora. 0 significa sin tiempo de espera.</p>

    <note><p>Este tiempo de espera se expresa por defecto en segundos, pero acepta
    sufijos para milisegundos (ms), segundos (s), minutos (min) y horas (h).
    </p></note>

    <p>Antes de Apache 2.4.17, este tiempo de espera estaba fijado en el código y su valor era de 600 useg.
    Por tanto, la configuración más cercana para igualar el comportamiento heredado es establecer
    <directive>MemcacheConnTTL</directive> a 1ms.</p>

    <example>
    <highlight language="config">
# Establece un tiempo de espera de 10 minutos
MemcacheConnTTL 10min
# Establece un tiempo de espera de 60 segundos
MemcacheConnTTL 60
    </highlight>
    </example>

</usage>
</directivesynopsis>

</modulesynopsis>
