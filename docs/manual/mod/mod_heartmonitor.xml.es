<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933540 -->
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

<modulesynopsis metafile="mod_heartmonitor.xml.meta">

<name>mod_heartmonitor</name>
<description>Monitor centralizado para servidores de origen con mod_heartbeat</description>
<status>Experimental</status>
<sourcefile>mod_heartmonitor.c</sourcefile>
<identifier>heartmonitor_module</identifier>
<compatibility>Disponible en Apache 2.3 y posteriores</compatibility>

<summary>
<p>
<module>mod_heartmonitor</module> escucha los mensajes de estado del servidor generados
por servidores de origen con <module>mod_heartbeat</module> activado, y pone su estado
a disposición de <module>mod_lbmethod_heartbeat</module>. Esto permite que
<directive module="mod_proxy">ProxyPass</directive> use el <em>lbmethod</em> "heartbeat"
dentro de <directive module="mod_proxy">ProxyPass</directive>.
</p>

<p>Este módulo usa los servicios de <module>mod_slotmem_shm</module> cuando
está disponible, en lugar de almacenamiento en archivo plano. No se necesita
ninguna configuración para usar <module>mod_slotmem_shm</module>.</p>

    <note type="warning">
        Para usar <module>mod_heartmonitor</module>,
        <module>mod_status</module> y <module>mod_watchdog</module>
        deben ser módulos estáticos o, si son módulos dinámicos, deben
        cargarse antes de <module>mod_heartmonitor</module>.
    </note>

</summary>

<directivesynopsis>
<name>HeartbeatListen</name>
<description>Dirección multicast en la que escuchar las peticiones heartbeat entrantes</description>
<syntax>HeartbeatListen <var>addr:port</var></syntax>
<default>disabled</default>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>La directiva <directive>HeartbeatListen</directive> especifica la
    dirección multicast en la que el servidor escuchará la información de estado
    de los servidores con <module>mod_heartbeat</module> activado. Esta
    dirección normalmente corresponderá a una <directive
    module="mod_heartbeat">HeartbeatAddress</directive> configurada en un servidor de origen.
    </p>

    <highlight language="config">
    HeartbeatListen 239.0.0.1:27999
    </highlight>

    <p>Este módulo está inactivo hasta que se usa esta directiva.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>HeartbeatStorage</name>
<description>Ruta donde almacenar los datos de heartbeat cuando se usa almacenamiento en archivo plano</description>
<syntax>HeartbeatStorage <var>file-path</var></syntax>
<default>HeartbeatStorage logs/hb.dat</default>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>La directiva <directive>HeartbeatStorage</directive> especifica la
    ruta donde se almacenarán los datos de heartbeat. Este archivo plano se usa solo cuando
    <module>mod_slotmem_shm</module> no está cargado y
    <directive module="mod_heartmonitor">HeartbeatMaxServers</directive> está establecida a 0.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>HeartbeatMaxServers</name>
<description>Especifica el número máximo de servidores que enviarán
peticiones heartbeat a este servidor</description>
<syntax>HeartbeatMaxServers <var>number-of-servers</var></syntax>
<default>HeartbeatMaxServers 10</default>
<contextlist><context>server config</context></contextlist>
<compatibility>El valor 0 solo se admite a partir de la versión 2.4.55</compatibility>

<usage>
    <p>La directiva <directive>HeartbeatMaxServers</directive> especifica el
    número máximo de servidores que enviarán peticiones a este servidor
    de monitorización. Se usa para controlar el tamaño de la memoria compartida asignada
    para almacenar la información de heartbeat cuando se usa <module>mod_slotmem_shm</module>.</p>
    <p>Establezca este valor a <code>0</code> para usar almacenamiento en archivo plano en lugar
    de memoria compartida (es decir, sin cargar
    <module>mod_slotmem_shm</module>). Cuando se usa memoria compartida,
    el valor debe ser 10 o mayor.</p>
</usage>
</directivesynopsis>
</modulesynopsis>
