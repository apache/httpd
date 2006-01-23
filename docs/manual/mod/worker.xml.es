<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.en.xsl"?>
<!-- English Revision: 106090:371662 (outdated) -->

<!--
 Copyright 2004 The Apache Software Foundation

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
-->

<modulesynopsis metafile="worker.xml.meta">
<name>worker</name>
<description>M&#243;dulo de MultiProcesamiento que implementa un
servidor web h&#237;brido multihebra-multiproceso</description>
<status>MPM</status>
<sourcefile>worker.c</sourcefile>
<identifier>mpm_worker_module</identifier>

<summary>
    <p>Este M&#243;dulo de MultiProcesamiento (MPM) implementa un
    servidor h&#237;brido multiproceso-multihebra.  Usando hebras para
    atender peticiones, el servidor puede servir un mayor n&#250;mero
    de peticiones con menos recursos de sistema que un servidor basado
    &#250;nicamente en procesos. No obtante, se mantiene casi por
    completo la estabilidad de un servidor basado en procesos
    manteniendo la capacidad multiproceso, pudiendo cada proceso tener
    muchas hebras.</p>

    <p>Las directivas m&#225;s importantes que se usan para controlar
    este MPM son <directive
    module="mpm_common">ThreadsPerChild</directive>, que controla el
    n&#250;mero de hebras que tiene cada proceso hijo y <directive
    module="mpm_common">MaxClients</directive>, que controla el
    n&#250;mero m&#225;ximo de hebras que pueden crearse.</p>
</summary>
<seealso><a href="../bind.html">Especificar las direcciones y los
puertos que usa Apache</a></seealso>

<section id="how-it-works"><title>C&#243;mo funciona</title> <p>Un
    solo proceso de control (el padre) es el responsable de crear los
    procesos hijo. Cada proceso hijo crea un n&#250;mero fijo de
    hebras del servidor de la forma que se especifica en la directiva
    <directive module="mpm_common">ThreadsPerChild</directive>,
    as&#237; como una hebra de escucha que escuchar&#225; si se
    producen peticiones y las pasar&#225; a una hebra del servidor
    para que la procese.</p>

    <p>Apache siempre intenta mantener en reserva cierto n&#250;mero
    de hebras <dfn>de sobra</dfn> o en espera, que est&#225;n
    preparadas para servir peticiones en el momento en que
    lleguen. As&#237;, los clientes no tienen que esperar a que se
    creen nuevas hebras o procesos para que sean atendidas sus
    peticiones. El n&#250;mero de procesos que se crean al principio
    est&#225; determinado por la directiva <directive
    module="mpm_common">StartServers</directive>. Despu&#233;s durante
    el funcionamiento del servidor, Apache calcula el n&#250;mero
    total de hebras en espera entre todos los procesos, y crea o
    elimina procesos para mantener ese n&#250;mero dentro de los
    l&#237;mites especificados en las directivas <directive
    module="mpm_common">MinSpareThreads</directive> y <directive
    module="mpm_common">MaxSpareThreads</directive>. Como este proceso
    est&#225; bastante autorregulado, no es muy habitual que sea
    necesario modificar los valores que estas directivas traen por
    defecto. El n&#250;mero m&#225;ximo de clientes que pueden ser
    servidos simult&#225;neamente (por ejemplo, el n&#250;mero
    m&#225;ximo de hebras entre todos los procesos) est&#225;
    determinado por la directiva <directive
    module="mpm_common">MaxClients</directive>.  El n&#250;mero
    m&#225;ximo de procesos hijo activos est&#225; determinado por el
    valor especificado en la directiva <directive
    module="mpm_common">MaxClients</directive> dividido por el valor
    especificado en la directiva <directive module="mpm_common">
    ThreadsPerChild</directive>.</p>

    <p>Hay dos directivas que establecen l&#237;mites estrictos al
    n&#250;mero de procesos hijo activos y al n&#250;mero de hebras
    del servidor en un proceso hijo, y puede cambiarse solo parando
    completamente el servidor y volviendo a iniciarlo. La directiva
    <directive module="mpm_common">ServerLimit </directive> marca el
    l&#237;mite estricto de procesos hijo activos posibles, y debe ser
    mayor o igual al valor de la directiva <directive
    module="mpm_common">MaxClients</directive> dividido por el valor
    de la directiva <directive module="mpm_common">
    ThreadsPerChild</directive>.  El valor de la directiva <directive
    module="mpm_common">ThreadLimit</directive> es el l&#237;mite
    estricto del n&#250;mero de hebras del servidor, y debe ser mayor
    o igual al valor de la directiva <directive
    module="mpm_common">ThreadsPerChild</directive>.  Si los valores
    de esas directivas no son los que vienen por defecto, deben
    aparecer antes que el resto de directivas del m&#243;dulo
    <module>worker</module>.</p>

    <p>Adem&#225;s del conjunto de procesos hijo activos, puede haber
    otros procesos hijo que est&#225;n terminando pero en los que al
    menos una hebra del servidor est&#225; todav&#237;a tratando una
    conexi&#243;n con un cliente.  Puede haber hasta <directive
    module="mpm_common">MaxClients</directive> procesos terminando,
    aunque el n&#250;mero real de estos procesos que puede esperarse
    es mucho menor. Este comportamiento puede evitarse desactivando la
    eliminaci&#243;n individual de procesos hijo, lo que se hace de la
    siguiente manera:</p>

    <ul>
      <li>fijar el valor de la directiva <directive module="mpm_common">
      MaxRequestsPerChild</directive> a cero</li>

      <li>fijar el valor de la directiva <directive
      module="mpm_common"> MaxSpareThreads</directive> al mismo valor
      que la directiva <directive
      module="mpm_common">MaxClients</directive></li>
    </ul>

    <p>Una configuraci&#243;n t&#237;pica del sistema de control de
    procesos y hebras del m&#243;dulo de MPM <module>worker</module>
    prodr&#237;a ser como sigue:</p>

    <example>
      ServerLimit         16<br />
      StartServers         2<br />
      MaxClients         150<br />
      MinSpareThreads     25<br />
      MaxSpareThreads     75<br />
      ThreadsPerChild     25
    </example>

    <p>Mientras que el proceso padre se inicia con privilegios de
    usuario <code>root</code> en Unix para usar el puerto de escucha
    80, los procesos hijo y las hebras se inician con menores
    privilegios de usuario. Las directivas <directive
    module="mpm_common">User</directive> y <directive
    module="mpm_common">Group</directive> se usan para determinar los
    privilegios con los que se iniciar&#225;n los procesos hijo. Los
    procesos hijo deben ser capaces de leer los contenidos que van a
    servir, pero solo los permisos extrictamente necesarios para
    cumplir su tarea. Adem&#225;s. a menos que se use <a
    href="../suexec.html">suexec</a>, los privilegios fijados en estas
    directivas son los que que van a heredar los scripts CGI.</p>

    <p>La directiva <directive
    module="mpm_common">MaxRequestsPerChild</directive> controla con
    qu&#233; frecuencia el servidor recicla los procesos eliminando
    los antiguos y creando nuevos.</p>
</section>

<directivesynopsis location="mpm_common"><name>AcceptMutex</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>CoreDumpDirectory</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>EnableExceptionHook</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>Group</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>PidFile</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>Listen</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ListenBacklog</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>LockFile</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>MaxClients</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>MaxMemFree</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>MaxRequestsPerChild</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>MaxSpareThreads</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>MinSpareThreads</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ScoreBoardFile</name>
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
<directivesynopsis location="mpm_common"><name>User</name>
</directivesynopsis>

</modulesynopsis>





