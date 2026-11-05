<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1938833 -->
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

<modulesynopsis metafile="mod_socache_redis.xml.meta">

<name>mod_socache_redis</name>
<description>Proveedor de caché de objetos compartida basado en Redis.</description>
<status>Extension</status>
<sourcefile>mod_socache_redis.c</sourcefile>
<identifier>socache_redis_module</identifier>
<compatibility>Disponible en Apache 2.4.39 y posteriores</compatibility>

<summary>
    <p><module>mod_socache_redis</module> es un proveedor de caché de objetos compartida
    que permite crear y acceder a una caché respaldada por el
    sistema de caché de objetos de memoria distribuida de alto rendimiento
    <a href="https://redis.io/">Redis</a>.
    </p>


    <p>El método "create" de este proveedor de caché de objetos compartida requiere una
       lista separada por comas de especificaciones de host/puerto de memcached. Si se usa
       este proveedor a través de la configuración de otro módulo (como
       <directive module="mod_ssl">SSLSessionCache</directive>), proporcione
       la lista de servidores como el parámetro opcional "arg".</p>

    <highlight language="config">
        SSLSessionCache redis:redis.example.com:12345,redis2.example.com:12345
    </highlight>

    <p>Puede encontrar los detalles de otros proveedores de caché de objetos compartida
    <a href="../socache.html">aquí</a>.
    </p>

</summary>

<directivesynopsis>
<name>RedisConnPoolTTL</name>
<description>TTL usado para el pool de conexiones con los servidores Redis</description>
<syntax>RedisConnPoolTTL <em>num</em>[<em>units</em>]</syntax>
<default>RedisConnPoolTTL 15s</default>
<contextlist>
<context>server config</context>
<context>virtual host</context>
</contextlist>
<compatibility>Disponible en Apache 2.4.39 y posteriores</compatibility>

<usage>
    <p>Establece el tiempo durante el que se mantienen activas las conexiones
    inactivas con los servidores Redis (solo en plataformas con hilos).</p>

    <p>Los valores válidos para <directive>RedisConnPoolTTL</directive> son tiempos
    de hasta una hora. 0 significa sin tiempo de espera.</p>

    <note><p>Este tiempo de espera usa segundos por defecto, pero acepta
    sufijos para milisegundos (ms), segundos (s), minutos (min) y horas (h).
    </p></note>

    <example>
    <highlight language="config">
# Establece un tiempo de espera de 10 minutos
RedisConnPoolTTL 10min
# Establece un tiempo de espera de 60 segundos
RedisConnPoolTTL 60
    </highlight>
    </example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>RedisTimeout</name>
<description>Tiempo de espera de lectura/escritura usado en la conexión con los servidores Redis</description>
<syntax>RedisTimeout <em>num</em>[<em>units</em>]</syntax>
<default>RedisTimeout 5s</default>
<contextlist>
<context>server config</context>
<context>virtual host</context>
</contextlist>
<compatibility>Disponible en Apache 2.4.39 y posteriores</compatibility>

<usage>
    <p>Establece el tiempo de espera de lectura/escritura usado en la conexión con los
    servidores Redis.</p>

    <p>Los valores válidos para <directive>RedisTimeout</directive> son tiempos
    de hasta una hora. 0 significa sin tiempo de espera.</p>

    <p>El cliente de Redis tiene una granularidad de segundos completos para el
    tiempo de espera de lectura/escritura. Un valor positivo con una fracción de segundo se
    redondea al siguiente segundo.</p>

    <note><p>Este tiempo de espera usa segundos por defecto, pero acepta
    sufijos para milisegundos (ms), segundos (s), minutos (min) y horas (h).
    </p></note>

    <example>
    <highlight language="config">
# Establece un tiempo de espera de 10 minutos
RedisTimeout 10min
# Establece un tiempo de espera de 60 segundos
RedisTimeout 60
    </highlight>
    </example>
</usage>
</directivesynopsis>

</modulesynopsis>
