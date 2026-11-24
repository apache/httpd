<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1935407 -->
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

<modulesynopsis metafile="mpmt_os2.xml.meta">

<name>mpmt_os2</name>
<description>MPM híbrido multiproceso y multihilo para OS/2</description>
<status>MPM</status>
<sourcefile>mpmt_os2.c</sourcefile>
<identifier>mpm_mpmt_os2_module</identifier>

<summary>
    <p>El servidor consiste en un proceso padre principal y un número pequeño
    y estático de procesos hijo.</p>

    <p>El trabajo del proceso padre es gestionar los procesos hijo. Esto
    implica crear hijos según sea necesario para garantizar que siempre haya
    <directive module="mpm_common">StartServers</directive> procesos
    aceptando conexiones.</p>

    <p>Cada proceso hijo consiste en un grupo de hilos trabajadores y un
    hilo principal que acepta conexiones y las pasa a los trabajadores a través de
    una cola de trabajo. El grupo de hilos trabajadores es dinámico, gestionado por un
    hilo de mantenimiento, de forma que el número de hilos inactivos se mantenga entre
    <directive module="mpm_common">MinSpareThreads</directive> y
    <directive module="mpm_common">MaxSpareThreads</directive>.</p>

</summary>
<seealso><a href="../mpm.html">Módulos de Multiproceso (MPMs)</a></seealso>
<seealso><a href="../bind.html">Configurar qué direcciones y puertos usa
Apache</a></seealso>

<directivesynopsis location="mod_unixd"><name>User</name>
</directivesynopsis>
<directivesynopsis location="mod_unixd"><name>Group</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>Listen</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ListenBacklog</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ReceiveBufferSize</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>SendBufferSize</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>MaxConnectionsPerChild</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>MaxSpareThreads</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>MinSpareThreads</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>PidFile</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>StartServers</name>
</directivesynopsis>

</modulesynopsis>
