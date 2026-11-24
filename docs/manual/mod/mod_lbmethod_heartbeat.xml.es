<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1829613 -->
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

<modulesynopsis metafile="mod_lbmethod_heartbeat.xml.meta">

<name>mod_lbmethod_heartbeat</name>
<description>Algoritmo de balanceo de carga por conteo de tráfico heartbeat para <module
>mod_proxy_balancer</module></description>
<status>Experimental</status>
<sourcefile>mod_lbmethod_heartbeat.c</sourcefile>
<identifier>lbmethod_heartbeat_module</identifier>
<compatibility>Disponible en la versión 2.3 y posteriores</compatibility>

<summary>
<p><code>lbmethod=heartbeat</code> usa los servicios de <module
>mod_heartmonitor</module> para equilibrar la carga entre los servidores de origen que proporcionan
información heartbeat a través del módulo <module>mod_heartbeat</module>.</p>

<p>El algoritmo de balanceo de carga de este módulo favorece con el tiempo a los servidores con más
capacidad disponible (inactiva), pero no selecciona siempre el servidor con más capacidad
disponible. Los servidores que tienen 0 clientes activos se penalizan, bajo el
supuesto de que no están completamente inicializados.</p>
</summary>

<seealso><module>mod_proxy</module></seealso>
<seealso><module>mod_proxy_balancer</module></seealso>
<seealso><module>mod_heartbeat</module></seealso>
<seealso><module>mod_heartmonitor</module></seealso>

<directivesynopsis>
<name>HeartbeatStorage</name>
<description>Ruta donde leer los datos de heartbeat</description>
<syntax>HeartbeatStorage <var>file-path</var></syntax>
<default>HeartbeatStorage logs/hb.dat</default>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>La directiva <directive>HeartbeatStorage</directive> especifica la
    ruta donde leer los datos de heartbeat. Este archivo plano solo se usa cuando
    <module>mod_slotmem_shm</module> no está cargado.</p>
</usage>
</directivesynopsis>
</modulesynopsis>
