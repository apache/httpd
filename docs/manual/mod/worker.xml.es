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

<modulesynopsis metafile="worker.xml.meta">
<name>worker</name>
<description>Módulo de Multiproceso que implementa un servidor web híbrido
    multiproceso y multihilo</description>
<status>MPM</status>
<sourcefile>worker.c</sourcefile>
<identifier>mpm_worker_module</identifier>

<summary>
    <p>Este Módulo de Multiproceso (MPM) implementa un servidor híbrido
    multiproceso y multihilo. Al usar hilos para atender
    peticiones, es capaz de atender un gran número de peticiones con
    menos recursos del sistema que un servidor basado en procesos. Sin embargo,
    conserva gran parte de la estabilidad de un servidor basado en procesos
    manteniendo disponibles varios procesos, cada uno con muchos hilos.</p>

    <p>Las directivas más importantes usadas para controlar este MPM son
    <directive module="mpm_common">ThreadsPerChild</directive>, que
    controla el número de hilos que despliega cada proceso hijo, y
    <directive module="mpm_common">MaxRequestWorkers</directive>, que
    controla el número máximo total de hilos que pueden
    lanzarse.</p>

    <p>Cuando se compila como módulo DSO, puede cargarse con:</p>

    <highlight language="config">
LoadModule mpm_worker_module modules/mod_mpm_worker.so
    </highlight>

</summary>
<seealso><a href="../mpm.html">Módulos de Multiproceso (MPMs)</a></seealso>
<seealso><a href="../bind.html">Cómo establecer qué direcciones y puertos usa el servidor Apache HTTP</a></seealso>

<section id="how-it-works"><title>Cómo funciona</title>
    <p>Un único proceso de control (el padre) es responsable de lanzar los
    procesos hijo. Cada proceso hijo crea un número fijo de hilos de servidor
    según lo especificado en la directiva <directive
    module="mpm_common">ThreadsPerChild</directive>, así como
    un hilo escuchador que espera las conexiones y las pasa
    a un hilo de servidor para su procesamiento cuando llegan.</p>

    <p>El servidor Apache HTTP siempre intenta mantener un grupo de hilos de
    servidor <dfn>de reserva</dfn> (spare) o inactivos, que están listos para atender las peticiones
    entrantes. De esta forma, los clientes no necesitan esperar a que se creen nuevos
    hilos o procesos antes de que sus peticiones puedan ser
    atendidas. El número de procesos que se lanzarán inicialmente
    lo establece la directiva <directive module="mpm_common">StartServers</directive>.
    Durante su funcionamiento, el servidor evalúa el número total
    de hilos inactivos en todos los procesos, y bifurca o mata procesos para
    mantener este número dentro de los límites especificados por <directive
    module="mpm_common">MinSpareThreads</directive> y <directive
    module="mpm_common">MaxSpareThreads</directive>. Dado que este
    proceso se autorregula en gran medida, raramente es necesario modificar
    estas directivas respecto a sus valores por defecto. El número máximo de
    clientes que pueden atenderse simultáneamente (es decir, el número máximo
    total de hilos en todos los procesos) viene determinado por la
    directiva <directive module="mpm_common">MaxRequestWorkers</directive>.
    El número máximo de procesos hijo activos viene determinado por
    la directiva <directive module="mpm_common">MaxRequestWorkers</directive>
    dividida por la directiva <directive module="mpm_common">
    ThreadsPerChild</directive>.</p>

    <p>Dos directivas establecen límites estrictos sobre el número de procesos
    hijo activos y el número de hilos de servidor en un proceso hijo,
    y solo se pueden cambiar deteniendo completamente el servidor y
    volviéndolo a iniciar. <directive module="mpm_common">ServerLimit
    </directive> es un límite estricto sobre el número de procesos hijo
    activos, y debe ser mayor o igual que la
    directiva <directive module="mpm_common">MaxRequestWorkers</directive>
    dividida por la directiva <directive module="mpm_common">
    ThreadsPerChild</directive>.
    <directive module="mpm_common">ThreadLimit</directive> es un límite
    estricto del número de hilos de servidor, y debe ser mayor
    o igual que la directiva
    <directive module="mpm_common">ThreadsPerChild</directive>.</p>

    <p>Además del conjunto de procesos hijo activos, puede haber
    procesos hijo adicionales que se están terminando, pero en los que al
    menos un hilo de servidor todavía está gestionando una conexión de cliente
    existente. Pueden existir hasta <directive
    module="mpm_common">MaxRequestWorkers</directive> procesos en fase de terminación,
    aunque cabe esperar que el número real sea
    mucho menor. Este comportamiento se puede evitar deshabilitando la
    terminación de procesos hijo individuales, lo cual se consigue
    con lo siguiente:</p>

    <ul>
      <li>establecer el valor de <directive module="mpm_common">
      MaxConnectionsPerChild</directive> a cero</li>

      <li>establecer el valor de <directive module="mpm_common">
      MaxSpareThreads</directive> al mismo valor que
      <directive module="mpm_common">MaxRequestWorkers</directive></li>
    </ul>

    <p>Una configuración típica de los controles de proceso-hilo en
    el MPM <module>worker</module> podría ser la siguiente:</p>

    <highlight language="config">
ServerLimit         16
StartServers         2
MaxRequestWorkers  150
MinSpareThreads     25
MaxSpareThreads     75
ThreadsPerChild     25
    </highlight>

    <p>Aunque el proceso padre normalmente se inicia como <code>root</code>
    en Unix para poder vincularse al puerto 80, los procesos hijo y los hilos
    son lanzados por el servidor como un usuario con menos privilegios. Las directivas <directive
    module="mod_unixd">User</directive> y <directive
    module="mod_unixd">Group</directive> se usan para establecer
    los privilegios de los procesos hijo del servidor Apache HTTP. Los procesos hijo
    deben poder leer todo el contenido que se va a servir, pero
    deberían tener tan pocos privilegios adicionales como sea posible. Además,
    a menos que se use <program>suexec</program>,
    estas directivas también establecen los privilegios que heredarán
    los scripts CGI.</p>

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
<directivesynopsis location="mod_unixd"><name>Group</name>
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
<directivesynopsis location="mpm_common"><name>MaxSpareThreads</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>MinSpareThreads</name>
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
<directivesynopsis location="mpm_common"><name>ThreadLimit</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ThreadsPerChild</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ThreadStackSize</name>
</directivesynopsis>
<directivesynopsis location="mod_unixd"><name>User</name>
</directivesynopsis>

</modulesynopsis>
