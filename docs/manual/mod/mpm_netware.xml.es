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

<modulesynopsis metafile="mpm_netware.xml.meta">
<name>mpm_netware</name>
<description>Módulo multiproceso (MPM) que implementa un servidor web
    exclusivamente basado en hilos, optimizado para Novell NetWare</description>
<status>MPM</status>
<sourcefile>mpm_netware.c</sourcefile>
<identifier>mpm_netware_module</identifier>

<summary>
    <p>Este módulo multiproceso (MPM) implementa un servidor web
    exclusivamente basado en hilos, optimizado para Novell
    NetWare.</p>

    <p>El hilo principal es responsable de lanzar los hilos
    trabajadores hijos que escuchan las conexiones y las atienden cuando
    llegan. Apache HTTP Server siempre intenta mantener varios hilos trabajadores
    <dfn>de reserva</dfn> o inactivos, que están preparados para atender las
    peticiones entrantes. De este modo, los clientes no necesitan esperar a que
    se genere un nuevo hilo hijo antes de que se puedan atender
    sus peticiones.</p>

    <p>Las directivas <directive module="mpm_common">StartThreads</directive>,
    <directive module="mpm_common">MinSpareThreads</directive>,
    <directive module="mpm_common">MaxSpareThreads</directive> y
    <directive module="mpm_netware">MaxThreads</directive>
    regulan cómo el hilo principal crea hilos trabajadores para atender
    las peticiones. En general, Apache httpd se autorregula bastante bien, así que la mayoría
    de los sitios no necesitan modificar estas directivas respecto a sus valores
    por defecto. Los sitios con memoria limitada pueden necesitar reducir <directive
    module="mpm_netware">MaxThreads</directive> para evitar que el servidor
    se sobrecargue (generando y finalizando hilos inactivos). Encontrará más información
    sobre el ajuste de la creación de procesos en la documentación de
    <a href="../misc/perf-tuning.html">sugerencias de rendimiento</a>.</p>

    <p><directive module="mpm_common">MaxConnectionsPerChild</directive>
    controla con qué frecuencia el servidor recicla procesos, eliminando los
    antiguos y lanzando otros nuevos. En el sistema operativo NetWare se recomienda
    encarecidamente mantener esta directiva con el valor 0. Esto permite que los hilos
    trabajadores sigan atendiendo peticiones indefinidamente.</p>

</summary>
<seealso><a href="../mpm.html">Módulos multiproceso (MPM)</a></seealso>
<seealso><a href="../bind.html">Establecer qué direcciones y
    puertos usa Apache httpd</a>
</seealso>

<directivesynopsis location="mpm_common"><name>Listen</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ListenBacklog</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>MaxMemFree</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>MaxConnectionsPerChild</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ReceiveBufferSize</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>SendBufferSize</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>MaxSpareThreads</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>MinSpareThreads</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>StartThreads</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ThreadStackSize</name>
</directivesynopsis>

<directivesynopsis>
<name>MaxThreads</name>
<description>Establece el número máximo de hilos trabajadores</description>
<syntax>MaxThreads <var>number</var></syntax>
<default>MaxThreads 2048</default>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>La directiva <directive>MaxThreads</directive> establece el número máximo
    deseado de hilos trabajadores permitido. El valor por defecto es
    también el límite máximo fijado en la compilación. Por tanto, solo se puede reducir,
    por ejemplo:</p>

    <example>
      MaxThreads 512
    </example>
</usage>
</directivesynopsis>

</modulesynopsis>
