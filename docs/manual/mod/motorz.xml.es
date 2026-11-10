<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1939486 -->
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

<modulesynopsis metafile="motorz.xml.meta">
<name>motorz</name>
<description>Un módulo de multiprocesamiento (MPM) ligero, rápido y autocontenido,
basado en eventos, construido sobre el pollset y el pool de hilos de APR, especialmente adecuado como proxy inverso</description>
<status>MPM</status>
<sourcefile>motorz.c</sourcefile>
<identifier>mpm_motorz_module</identifier>

<summary>
    <p>El módulo de multiprocesamiento (MPM) <module>motorz</module> es una
    implementación asíncrona basada en eventos. Combina un pool fijo de
    procesos hijos al estilo de prefork con un núcleo de eventos construido sobre
    el pollset de <glossary>APR</glossary> y un pool de hilos compartido. Cada hijo
    ejecuta uno o varios hilos <dfn>poller</dfn> dedicados que vigilan sockets
    y temporizadores, despachando los eventos de E/S listos y los temporizadores vencidos a un
    pool de hilos trabajadores. Los trabajadores nunca hacen poll; solo procesan el
    trabajo de conexión/petición que se les empuja.</p>

    <p>El objetivo de diseño es un MPM rápido, eficiente, único y compacto que se ejecute en
    plataformas Unix modernas apoyándose en APR tanto como sea posible, sin dejar de
    soportar el manejo asíncrono de conexiones necesario para un keep-alive eficiente y
    HTTP/2.</p>

    <p>Para usar el MPM <module>motorz</module>, añada
      <code>--with-mpm=motorz</code> a los argumentos del script
      <program>configure</program> al compilar <program>httpd</program>, o
      compílelo como un módulo cargable con
      <code>--enable-mpms-shared=motorz</code>.</p>


    <p>Cuando se compila como un módulo DSO, puede cargarse con:</p>

    <highlight language="config">
LoadModule mpm_motorz_module modules/mod_mpm_motorz.so
    </highlight>

</summary>

<seealso><a href="../mpm.html">Módulos de multiprocesamiento (MPM)</a></seealso>
<seealso><a href="event.html">El MPM event</a></seealso>
<seealso><a href="worker.html">El MPM worker</a></seealso>
<seealso><a href="prefork.html">El MPM prefork</a></seealso>
<seealso><a href="../bind.html">Establecer qué direcciones y puertos usa Apache HTTP Server</a></seealso>

<section id="how-it-works"><title>Cómo funciona</title>
    <p><module>motorz</module> usa prefork como marco para la gestión de
    procesos y un núcleo de eventos para el manejo de conexiones. Un único proceso
    de control (el padre) lanza un número fijo de procesos hijos, tal y como establece
    la directiva <directive module="mpm_common">StartServers</directive>.
    A diferencia de <module>worker</module> y <module>event</module>, el número de
    hijos no varía con la carga: <module>motorz</module> mantiene un
    pool estático, reemplazando los hijos uno por uno a medida que terminan. La concurrencia
    dentro de un host se escala añadiendo hilos trabajadores
    (<directive module="mpm_common">ThreadsPerChild</directive>) y, cuando
    la ruta de poll/dispatch es el cuello de botella, hilos poller
    (<directive>PollersPerChild</directive>), en lugar de generando más
    procesos.</p>

    <p>Cada proceso hijo ejecuta:</p>
    <ul>
        <li><strong>Uno o varios hilos poller.</strong> Cada poller posee su
        propio pollset, su propio anillo de temporizadores (con un mutex de protección) y su
        propia lista de reciclaje de pool de transacciones sin bloqueos, de modo que los pollers nunca compiten
        entre sí. Un poller hace poll, despacha los eventos de E/S listos y los
        temporizadores vencidos al pool de trabajadores y (en el caso del poller que posee los
        sockets de escucha) acepta nuevas conexiones. El número de pollers se controla
        con <directive>PollersPerChild</directive>.</li>

        <li><strong>Un pool compartido de hilos trabajadores</strong>
        (<directive module="mpm_common">ThreadsPerChild</directive>) que ejecutan
        el procesamiento real de conexiones y peticiones que se les empuja. Los trabajadores
        nunca hacen poll.</li>

        <li><strong>Un supervisor</strong> (el hilo principal del hijo) que
        vigila <directive module="mpm_common">MaxConnectionsPerChild</directive>
        y la tubería de muerte / generación, indica a los pollers que se detengan
        progresivamente, y luego se une a ellos al salir.</li>
    </ul>

    <p>Una conexión se asigna a un poller en el momento de aceptarse (round-robin) y
    queda vinculada a él durante toda su vida: se rearma en, y expira en, el pollset
    y el anillo de temporizadores de ese poller. Usar varios pollers eleva el
    límite de rendimiento de un único hilo de poll, de modo que la aceptación, el despacho de eventos y
    la expiración de temporizadores escalan con <directive>PollersPerChild</directive> en lugar de quedar
    serializados en un único hilo.</p>

    <p>Aunque el proceso padre normalmente se inicia como <code>root</code> en
    Unix para poder enlazar al puerto 80, los procesos e hilos hijos son
    lanzados por el servidor como un usuario con menos privilegios. Las
    directivas <directive module="mod_unixd">User</directive> y
    <directive module="mod_unixd">Group</directive> se usan para establecer
    los privilegios de los procesos hijos de Apache HTTP Server. Los procesos
    hijos deben poder leer todo el contenido que se va a servir, pero
    deben tener tan pocos privilegios adicionales como sea posible.</p>

    <p><directive module="mpm_common">MaxConnectionsPerChild</directive>
    controla con qué frecuencia el servidor recicla procesos, retirando los antiguos
    y lanzando otros nuevos.</p>
</section>

<section id="async-connections"><title>Manejo asíncrono de conexiones</title>
    <p><module>motorz</module> se presenta a sí mismo como un MPM asíncrono. Cuando un
    trabajador termina la fase activa de una conexión (por ejemplo, una
    conexión HTTP keep-alive entre peticiones, o una conexión esperando
    más E/S), devuelve el socket a su poller en lugar de mantener ocupado un
    hilo trabajador de forma inactiva. El poller espera el siguiente evento en ese socket,
    acotado por el <directive module="mpm_common">Timeout</directive> configurado,
    y vuelve a despachar la conexión a un trabajador solo cuando hay trabajo que hacer.
    Esto libera a los hilos trabajadores de las conexiones keep-alive inactivas y es lo que
    permite un manejo eficiente de HTTP/2, donde la conexión maestra se devuelve
    al MPM entre peticiones.</p>

    <p>El cierre diferido (lingering close) también es no bloqueante: en lugar de bloquear un
    trabajador durante el tiempo de espera de cierre diferido, el socket en proceso de vaciado se devuelve
    al bucle de poll con un tiempo de espera de cierre diferido acotado, de modo que el trabajador
    vuelve al pool de inmediato.</p>

    <p>Se admite el uso de módulos que hacen una conexión completamente asíncrona (suspendiéndola
    y reanudándola más tarde); una conexión suspendida se aparca y
    se rearma en su poller propietario cuando se reanuda. Igual que en el MPM
    <module>event</module>, a un módulo que se registra para los hooks
    <code>suspend_connection</code> y <code>resume_connection</code> se le notifica en el hilo trabajador que aparca
    una conexión (entre peticiones, o mientras espera E/S o a que se vacíe la salida)
    y de nuevo en el hilo trabajador que la reanuda, que no tiene por qué ser
    el mismo hilo. Los callbacks genéricos de temporizador y poll de la interfaz del MPM
    (<code>ap_mpm_register_timed_callback()</code> y
    <code>ap_mpm_register_poll_callback()</code>) no se ofrecen: devuelven
    <code>APR_ENOTIMPL</code>, y un módulo tiene que lidiar con eso.</p>
</section>

<section id="graceful-stop"><title>Parada y reinicio ordenados</title>
    <p>Cuando se solicita a un hijo que se detenga de forma ordenada (un reinicio o parada
    ordenados, o al alcanzar <directive module="mpm_common">MaxConnectionsPerChild</directive>)
    deja de aceptar conexiones, cierra las conexiones keep-alive inactivas, y
    permite que todas las demás conexiones, incluidas las respuestas que aún se están escribiendo,
    terminen antes de salir. Una generación anterior conserva por tanto sus ranuras de
    proceso hasta que sus conexiones terminan, razón por la cual
    <directive module="mpm_common">ServerLimit</directive> debe dejar espacio para
    ambas generaciones. <directive module="mpm_common">GracefulShutdownTimeout</directive>
    acota cuánto tiempo espera el padre en una parada ordenada.</p>

    <p>Si cada ranura está ocupada por un hijo en proceso de vaciado, el padre no puede iniciar un
    sustituto, y mientras no tenga ningún hijo de la generación actual, nada
    acepta nuevas conexiones: estas esperan hasta que termina un hijo en proceso de vaciado. Esto
    requiere conexiones que sobreviven a varios reinicios consecutivos, como
    descargas largas. El padre registra "scoreboard is full" cuando esto ocurre; eleve
    <directive module="mpm_common">ServerLimit</directive>.</p>

    <p>Un hijo no impone un plazo propio mientras se vacía. A una
    conexión que todavía está escribiendo una respuesta, o que está esperando E/S para un
    módulo que la gestiona de forma asíncrona, se le da tiempo hasta que termina o hasta que
    expira el <directive module="mpm_common">Timeout</directive> configurado, de modo que un
    reinicio ordenado puede tardar tanto como la más larga de esas conexiones.</p>
</section>

<section id="scoreboard"><title>Scoreboard y mod_status</title>
    <p>Una conexión no está vinculada a un hilo, por lo que las ranuras por hilo del scoreboard
    representan a los hilos trabajadores. Un trabajador informa de la conexión que está
    procesando a través de su ranura y pone la ranura de nuevo en estado listo cuando termina
    con ella; una conexión aparcada en un poller (keep-alive, finalización de escritura,
    cierre diferido, esperando E/S) no ocupa ninguna ranura. Los recuentos de trabajadores
    ocupados e inactivos en <module>mod_status</module> reflejan por tanto los hilos
    trabajadores, igual que ocurre en los demás MPM con hilos.</p>
</section>

<section id="limitations"><title>Plataformas y limitaciones</title>
    <p><module>motorz</module> se ejecuta en plataformas tipo Unix cuyo APR admite
    hilos y que pueden usar un pollset seguro para hilos (kqueue, event ports o
    epoll). No está disponible en Windows, NetWare ni OS/2.</p>
    <ul>
      <li>La directiva <directive module="mpm_common">ThreadStackSize</directive>
      se ignora (se registra una advertencia): los hilos trabajadores proceden de
      un pool de hilos de APR, que no permite establecer su tamaño de pila.</li>
      <li>No hay mutex de aceptación. Los sockets de escucha son no bloqueantes y
      se sondean con poll, por lo que el poller que los posee en cada proceso hijo se despierta por
      cada nueva conexión. Se acepta un valor <code>Mutex accept</code>, pero
      no tiene efecto.</li>
      <li>No existen los controles
      <directive module="mpm_common">MinSpareThreads</directive>,
      <directive module="mpm_common">MaxSpareThreads</directive> ni
      <directive module="mpm_common">MaxRequestWorkers</directive>,
      como se ha descrito arriba.</li>
    </ul>
</section>

<section id="admission-control"><title>Control de admisión</title>
    <p>Para mantener a un hijo a salvo bajo sobrecarga, <module>motorz</module> aplica
    contrapresión sobre el listener. El poller que posee los sockets de escucha los
    elimina de su pollset y deja de aceptar, y los vuelve a añadir cuando
    hay espacio de nuevo, en dos situaciones:</p>
    <ul>
      <li>el pool de trabajadores está saturado, a juzgar por sus recuentos de hilos
          inactivos, pendientes y activos, con histéresis para evitar activar y
          desactivar repetidamente los listeners;</li>
      <li>el hijo mantiene tantas conexiones como permite
          <directive>AsyncRequestWorkerFactor</directive>. Las conexiones
          que están inactivas en keep-alive, esperando E/S o escribiendo una respuesta
          no usan ningún hilo trabajador, por lo que el pool de trabajadores por sí solo no puede
          limitarlas.</li>
    </ul>
    <p>Las conexiones que no se aceptan esperan en el backlog de escucha (vea
    <directive module="mpm_common">ListenBacklog</directive>). Otros usos de memoria,
    como la lectura de una petición grande, no se limitan por esto.</p>

    <note><title>ThreadsPerChild y el control de admisión</title>
    <p>Dado que la marca de bajo nivel del control de admisión es una fracción de
    <directive module="mpm_common">ThreadsPerChild</directive>, valores muy pequeños
    (en particular <code>ThreadsPerChild 1</code>) hacen que los listeners se
    reactiven solo cuando la cola de trabajo está completamente vacía, lo que degrada
    seriamente el rendimiento. Se recomienda encarecidamente un valor de
    <code>ThreadsPerChild</code> de al menos 4; el servidor registra una advertencia para
    un valor de 1.</p>
    </note>
</section>

<section id="relationship"><title>Relación con otros MPM</title>
    <p><module>motorz</module> usa prefork para la gestión de procesos y un pool de
    hilos de APR para los trabajadores, con pollers que despachan trabajo a ese pool. Esto
    es distinto del diseño listener/worker/fdqueue de <module>event</module>,
    en el que los propios hilos trabajadores vuelven a armar un pollset
    compartido y seguro para hilos.</p>

    <p>Que más pollers ayuden o no depende de la carga de trabajo. Si los hilos
    trabajadores son el cuello de botella de CPU&#8212;lo habitual para el procesamiento
    real de peticiones&#8212;los hilos poller no son el factor limitante, y un valor
    de <directive>PollersPerChild</directive> por encima de uno o dos aporta poco. El
    diseño de múltiples pollers elimina el límite <em>estructural</em> de un único
    hilo de <module>motorz</module>, pero el rendimiento por host sigue estando
    gobernado por la CPU de los trabajadores.</p>

    <note><title>Sin escalado dinámico de procesos</title>
    <p>A diferencia de <module>worker</module> y <module>event</module>,
    <module>motorz</module> no escala el número de procesos hijos con la
    carga. El pool de procesos es fijo, según
    <directive module="mpm_common">StartServers</directive>.
    <directive module="mpm_common">ServerLimit</directive> solo acota el
    número de ranuras de proceso, incluidas las que mantienen los hijos antiguos que
    todavía están terminando conexiones tras un reinicio ordenado; por defecto toma
    el mayor de 16 y el doble de
    <directive module="mpm_common">StartServers</directive> y, igual que
    <directive module="mpm_common">ThreadLimit</directive>, no puede cambiarse
    durante un reinicio. No existen los controles
    <directive module="mpm_common">MinSpareThreads</directive> /
    <directive module="mpm_common">MaxSpareThreads</directive> /
    <directive module="mpm_common">MaxRequestWorkers</directive>.
    Escale la concurrencia con
    <directive module="mpm_common">ThreadsPerChild</directive> (y, si la
    ruta de poll se satura, con <directive>PollersPerChild</directive>).</p>
    </note>
</section>

<directivesynopsis location="mpm_common"><name>CoreDumpDirectory</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>EnableExceptionHook</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>GracefulShutdownTimeout</name>
</directivesynopsis>
<directivesynopsis location="mod_unixd"><name>Group</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>Listen</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ListenBacklog</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>MaxConnectionsPerChild</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>MaxMemFree</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>PidFile</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ScoreBoardFile</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ServerLimit</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>SendBufferSize</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>StartServers</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ThreadLimit</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ThreadsPerChild</name>
</directivesynopsis>
<directivesynopsis location="mod_unixd"><name>User</name>
</directivesynopsis>

<directivesynopsis>
<name>AsyncRequestWorkerFactor</name>
<description>Limita las conexiones concurrentes por proceso</description>
<syntax>AsyncRequestWorkerFactor <var>factor</var></syntax>
<default>AsyncRequestWorkerFactor 2</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>motorz</module></modulelist>

<usage>
    <p>Esta directiva tiene el mismo significado que en el MPM
    <module>event</module>. Un <strong>proceso</strong> solo acepta nuevas conexiones mientras
    el número de conexiones que mantiene, sin contar las que están en cierre diferido, sea
    menor que:</p>

    <p class="indent"><strong>
        <directive module="mpm_common">ThreadsPerChild</directive> +
        (<directive>AsyncRequestWorkerFactor</directive> *
        <var>número de trabajadores inactivos</var>)
    </strong></p>

    <p>La mayoría de las conexiones que mantiene un hijo normalmente están inactivas y no usan
    ningún hilo trabajador, razón por la cual el límite es mayor que el número de
    hilos. Los valores por debajo de 1 se elevan a 1.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>PollersPerChild</name>
<description>Número de hilos poll por proceso hijo</description>
<syntax>PollersPerChild <var>number</var></syntax>
<default>PollersPerChild 0</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>motorz</module></modulelist>

<usage>
    <p>La directiva <directive>PollersPerChild</directive> establece el número de
    hilos poller creados en cada proceso hijo. Cada poller posee su propio
    pollset, anillo de temporizadores y lista de reciclaje de conexiones, y gestiona una porción de
    las conexiones del hijo. Como cada hilo poller acepta conexiones y
    despacha de forma independiente los eventos de E/S listos y los vencimientos de
    temporizadores al pool de trabajadores, añadir pollers eleva la tasa a la que un
    único proceso hijo puede gestionar estas operaciones en paralelo en lugar de
    serializarlas en un único hilo de poll.</p>

    <p>Un valor de <code>0</code> (el valor por defecto) significa <em>auto</em>: el número
    de pollers se deriva del número de CPU en línea, acotado a un máximo
    predefinido. En todos los casos, el número de pollers se limita de modo que nunca
    supere <directive module="mpm_common">ThreadsPerChild</directive> y nunca
    sea menor que uno.</p>

    <p>Dado que el despacho de eventos raramente es el cuello de botella en el procesamiento
    real de peticiones&#8212;normalmente lo es la CPU de los trabajadores&#8212;los valores por
    encima de uno o dos raramente mejoran el rendimiento. Elevar <directive>PollersPerChild</directive>
    es útil principalmente para cargas de trabajo dominadas por una rotación de conexiones muy alta o por
    un gran número de conexiones inactivas basadas en eventos, donde la propia ruta de poll/aceptación
    se convierte en el límite.</p>

    <note><title>Ejemplo</title>
    <highlight language="config">
StartServers       2
ThreadsPerChild   64
ThreadLimit       64
PollersPerChild    2
    </highlight>
    </note>
</usage>
</directivesynopsis>

</modulesynopsis>
