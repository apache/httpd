<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1839250 -->
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

<modulesynopsis metafile="mod_watchdog.xml.meta">
<name>mod_watchdog</name>
<description>proporciona infraestructura para que otros módulos ejecuten
    tareas periódicamente</description>
<status>Base</status>
<sourcefile>mod_watchdog.c</sourcefile>
<identifier>watchdog_module</identifier>
<compatibility>Disponible en Apache 2.3 y posteriores</compatibility>

<summary>
<p><module>mod_watchdog</module> define hooks programáticos para que otros módulos
ejecuten tareas periódicamente. Estos módulos pueden registrar manejadores para los
hooks de <module>mod_watchdog</module>. Actualmente, los siguientes módulos de la
distribución de Apache usan esta funcionalidad:</p>
<ul>
<li><module>mod_heartbeat</module></li>
<li><module>mod_heartmonitor</module></li>
<li><module>mod_md</module></li>
<li><module>mod_proxy_hcheck</module></li>
</ul>
<note type="warning">
Para permitir que un módulo use la funcionalidad de <module>mod_watchdog</module>,
<module>mod_watchdog</module> debe estar enlazado estáticamente al núcleo
del servidor o, si es un módulo dinámico, debe cargarse antes del módulo que lo invoca.
</note>
</summary>

<directivesynopsis>
<name>WatchdogInterval</name>
<description>Intervalo del watchdog en segundos</description>
<syntax>WatchdogInterval <var>time-interval</var>[s]</syntax>
<default>WatchdogInterval 1</default>
<contextlist><context>server config</context></contextlist>

<usage>
<p>Establece el intervalo con el que se ejecuta el hook watchdog_step. Por
defecto se ejecuta cada segundo.</p>
</usage>
</directivesynopsis>
</modulesynopsis>
