<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.en.xsl"?>
<!-- English Revision: 151405:396609 (outdated) -->

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

<modulesynopsis metafile="mpm_winnt.xml.meta">

<name>mpm_winnt</name>
<description>M&#243;dulo de multiprocesamiento optimizado para Windows
NT.</description>
<status>MPM</status>
<sourcefile>mpm_winnt.c</sourcefile>
<identifier>mpm_winnt_module</identifier>

<summary>
    <p>Este m&#243;dulo de multiprocesamiento (MPM) es el que viene por
    defecto para los sitemas operativos Windows NT. Crea un solo
    proceso de control que crea un solo proceso hijo que a su vez crea
    hebras para atender las peticiones que se produzcan.</p>
</summary>

<directivesynopsis location="mpm_common"><name>CoreDumpDirectory</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>PidFile</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>Listen</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ListenBacklog</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>MaxRequestsPerChild</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>MaxMemFree</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ScoreBoardFile</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>SendBufferSize</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ThreadLimit</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ThreadsPerChild</name>
</directivesynopsis>

<directivesynopsis>
<name>Win32DisableAcceptEx</name>
<description>Usa accept() en lugar de AcceptEx() para aceptar
conexiones de red</description>
<syntax>Win32DisableAcceptEx</syntax>
<default>AcceptEx() est&#225; activado por defecto. Use esta directiva para desactivarlo</default>
<contextlist><context>server config</context></contextlist>
<compatibility>Disponible en las versiones 2.0.49 y posteriores</compatibility>

<usage>
    <p><code>AcceptEx()</code> es una API WinSock v2 de Microsoft que
    ofrece algunas mejoras en el rendimiento sobre la API
    <code>accept()</code> de tipo BSD bajo ciertas
    condiciones. Algunos productos populares de Microsoft, sobre todo
    antivirus o aplicaciones para implemetar redes privadas virtuales,
    tienen errores de programaci&#243;n que interfieren con el
    funcionamiento de <code>AcceptEx()</code>. Si se encuentra con un
    mensaje de error parecido a este:</p>

    <example>
        [error] (730038)An operation was attempted on something that is
        not a socket.: winnt_accept: AcceptEx failed. Attempting to recover.
    </example>

    <p>debe usar esta directiva para desactivar el uso de <code>AcceptEx()</code>.</p>
</usage>
</directivesynopsis>

</modulesynopsis>


