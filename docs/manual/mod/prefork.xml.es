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

<modulesynopsis metafile="prefork.xml.meta">

<name>prefork</name>
<description>Implementa un servidor web sin hilos y con prebifurcación (pre-forking)</description>
<status>MPM</status>
<sourcefile>prefork.c</sourcefile>
<identifier>mpm_prefork_module</identifier>

<summary>
    <p>Este Módulo de Multiproceso (MPM) implementa un servidor web sin hilos y
    con prebifurcación. Cada proceso del servidor puede responder a las peticiones
    entrantes, y un proceso padre gestiona el tamaño del grupo de servidores.
    Es apropiado para sitios que necesitan evitar
    el uso de hilos por compatibilidad con bibliotecas que no son seguras para hilos. También
    es el mejor MPM para aislar cada petición, de forma que un problema
    con una sola petición no afecte a ninguna otra.</p>

    <p>Este MPM se autorregula en gran medida, por lo que raramente es necesario
    ajustar sus directivas de configuración. Lo más importante es que
    <directive module="mpm_common">MaxRequestWorkers</directive> sea lo bastante grande
    para gestionar tantas peticiones simultáneas como espere recibir, pero
    lo bastante pequeña para garantizar que haya suficiente RAM física para todos los
    procesos.</p>

    <p>Cuando se compila como módulo DSO, puede cargarse con:</p>

    <highlight language="config">
LoadModule mpm_prefork_module modules/mod_mpm_prefork.so
    </highlight>

</summary>
<seealso><a href="../mpm.html">Módulos de Multiproceso (MPMs)</a></seealso>
<seealso><a href="../bind.html">Cómo establecer qué direcciones y puertos usa el
servidor Apache HTTP</a></seealso>

<section id="how-it-works"><title>Cómo funciona</title>
    <p>Un único proceso de control es responsable de lanzar los procesos hijo
    que escuchan las conexiones y las atienden cuando llegan. Apache httpd siempre intenta
    mantener varios procesos del servidor <dfn>de reserva</dfn> (spare) o
    inactivos, que están listos para atender las peticiones entrantes. De esta forma,
    los clientes no necesitan esperar a que se bifurque un nuevo proceso hijo
    antes de que sus peticiones puedan ser atendidas.</p>

    <p>Las directivas <directive module="mpm_common">StartServers</directive>,
    <directive module="prefork">MinSpareServers</directive>,
    <directive module="prefork">MaxSpareServers</directive> y
    <directive module="mpm_common">MaxRequestWorkers</directive> regulan cómo
    crea el proceso padre los procesos hijo para atender las peticiones. En general,
    Apache httpd se autorregula en gran medida, por lo que la mayoría de los sitios no necesitan
    ajustar estas directivas respecto a sus valores por defecto. Los sitios que
    necesitan atender más de 256 peticiones simultáneas pueden necesitar
    aumentar <directive module="mpm_common">MaxRequestWorkers</directive>,
    mientras que los sitios con memoria limitada pueden necesitar disminuir <directive
    module="mpm_common">MaxRequestWorkers</directive> para evitar que el servidor caiga en
    thrashing (intercambiar memoria a disco y viceversa). En la documentación sobre
    <a href="../misc/perf-tuning.html">sugerencias de rendimiento</a>
    se ofrece más información sobre el ajuste de la creación de procesos.</p>

    <p>Aunque el proceso padre normalmente se inicia como <code>root</code>
    en Unix para poder vincularse al puerto 80, los procesos hijo son
    lanzados por Apache httpd como un usuario con menos privilegios. Las directivas <directive
    module="mod_unixd">User</directive> y <directive
    module="mod_unixd">Group</directive> se usan para establecer
    los privilegios de los procesos hijo de Apache httpd. Los procesos hijo
    deben poder leer todo el contenido que se va a servir, pero
    deberían tener tan pocos privilegios adicionales como sea posible.</p>

    <p><directive module="mpm_common">MaxConnectionsPerChild</directive>
    controla con qué frecuencia el servidor recicla los procesos matando
    los antiguos y lanzando otros nuevos.</p>

    <p>Este MPM usa el mutex <code>mpm-accept</code> para serializar
    el acceso a las conexiones entrantes cuando está sujeto al problema del
    "rebaño atronador" (thundering herd) (en general, cuando hay múltiples sockets
    a la escucha). Los aspectos de implementación de este mutex se pueden configurar con la
    directiva <directive module="core">Mutex</directive>. La documentación sobre
    <a href="../misc/perf-tuning.html">sugerencias de rendimiento</a>
    contiene información adicional sobre este mutex.</p>
</section>

<directivesynopsis location="mpm_common"><name>CoreDumpDirectory</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>EnableExceptionHook</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>PidFile</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>Listen</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ListenBacklog</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>MaxRequestWorkers</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>MaxMemFree</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>MaxConnectionsPerChild</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ScoreBoardFile</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ReceiveBufferSize</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>SendBufferSize</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ServerLimit</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>StartServers</name>
</directivesynopsis>
<directivesynopsis location="mod_unixd"><name>User</name>
</directivesynopsis>
<directivesynopsis location="mod_unixd"><name>Group</name>
</directivesynopsis>

<directivesynopsis>
<name>MaxSpareServers</name>
<description>Número máximo de procesos hijo del servidor inactivos</description>
<syntax>MaxSpareServers <var>number</var></syntax>
<default>MaxSpareServers 10</default>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>La directiva <directive>MaxSpareServers</directive> establece el
    número máximo deseado de procesos hijo del servidor <em>inactivos</em>. Un
    proceso inactivo es aquel que no está atendiendo ninguna petición. Si hay
    más procesos inactivos que los indicados por <directive>MaxSpareServers</directive>, el
    proceso padre eliminará los procesos sobrantes.</p>

    <p>El ajuste de este parámetro solo debería ser necesario en sitios muy
    concurridos. Establecer este parámetro con un número grande casi
    siempre es una mala idea. Si intenta establecer el valor igual o inferior a
    <directive module="prefork">MinSpareServers</directive>, el servidor Apache HTTP
    lo ajustará automáticamente a <directive
    >MinSpareServers</directive><code> + 1</code>.</p>
</usage>
<seealso><directive module="prefork">MinSpareServers</directive></seealso>
<seealso><directive module="mpm_common">StartServers</directive></seealso>
<seealso><directive module="mpm_common">MaxSpareThreads</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>MinSpareServers</name>
<description>Número mínimo de procesos hijo del servidor inactivos</description>
<syntax>MinSpareServers <var>number</var></syntax>
<default>MinSpareServers 5</default>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>La directiva <directive>MinSpareServers</directive> establece el
    número mínimo deseado de procesos hijo del servidor <em>inactivos</em>. Un
    proceso inactivo es aquel que no está atendiendo ninguna petición. Si hay
    menos procesos inactivos que los indicados por <directive>MinSpareServers</directive>, el proceso
    padre crea nuevos procesos hijo: lanzará uno, esperará un segundo, luego lanzará
    dos, esperará un segundo, luego lanzará cuatro, y
    continuará exponencialmente hasta lanzar 32 procesos hijo por segundo. Se
    detendrá en cuanto satisfaga el valor establecido por <directive>MinSpareServers</directive>.</p>

    <p>El ajuste de este parámetro solo debería ser necesario en sitios muy
    concurridos. Establecer este parámetro con un número grande casi
    siempre es una mala idea.</p>
</usage>
<seealso><directive module="prefork">MaxSpareServers</directive></seealso>
<seealso><directive module="mpm_common">StartServers</directive></seealso>
<seealso><directive module="mpm_common">MinSpareThreads</directive></seealso>
</directivesynopsis>

</modulesynopsis>
