<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.en.xsl"?>
<!-- English Revision: 1807868 -->
<!-- Spanish Translation: Daniel Ferradal <dferradal@apache.org> -->

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

<modulesynopsis metafile="event.xml.meta">
<name>event</name>
<description>Una variante del MPM <module>worker</module> con el 
objetivo de consumir hilos sólo para conexiones con procesamiento 
activo</description>
<status>MPM</status>
<sourcefile>event.c</sourcefile>
<identifier>mpm_event_module</identifier>

<summary>
    <p>El Módulo de Multi-Proceso (MPM en inglés) <module>event</module> es, 
    como su nombre indica, una implementación asíncrona basada en eventos, 
    diseñada para permitir que se sirvan más peticiones simultáneamente 
    mediante la concesión de algo de trabajo de procesamiento a los hilos 
    "listeners" (de escucha), liberando a los hilos worker (trabajadores)
    para servir más peticiones.
    </p>

    <p>Para usar el MPM <module>event</module>, añada
      <code>--with-mpm=event</code> a los parámetros del script 
      <program>configure</program> cuando esté compilando
      <program>httpd</program>.</p>

</summary>

<seealso><a href="worker.html">El MPM worker</a></seealso>

<section id="event-worker-relationship">
    <title>Relación con el MPM Worker</title>
    <p><module>event</module> está basado en el MPM <module>worker</module>, que implmementa un servidor híbrido de multi-proceso multi-hilo. Un solo proceso (el padre) es responsable de lanzar procesos child (hijos). Cada proceso child crea un número fijo de hilos de servidor tal y como se especifica en la directiva 
    <directive module="mpm_common">ThreadsPerChild</directive>, así como un hilo listener que está en escucha para recibir conexiones y las pasa al hilo worker para procesamiento según van llegando.</p>

    <p>Las directivas de configuración en tiempo real son idénticas a aquellas facilitadas por <module>worker</module>, con la única diferencia de que event además tiene la directiva 
    <directive>AsyncRequestWorkerFactor</directive>.</p>
</section>

<section id="how-it-works"><title>Como Trabaja</title>
    <p>El objetivo original de este MPM era arreglar el 'problema del keep alive' en HTTP. Después de que un cliente completa su primera petición, puede mantener la conexión abierta, enviando más peticiones utilizando el mismo socket y ahorrando una cantidad significativa de tiempo en abrir nuevas conexiones TCP. Sin embargo, el Servidor Apache HTTP tradicionalmente mantiene un proceso/hilo child esperando a que le lleguen datos del cliente, lo cual tiene sus propias desventajas.
    Para resolver este problema, este MPM usa un hilo dedicado de tipo listener en cada proceso junto con un grupo de hilos worker, compartiendo colas específicas para esas peticiones en modo keep-alive (o, más sencillamente, "readable"), aquellos en modo terminando-escritura, y aquellos en proceso de cerrarse ("closing"). Un bucle de eventos, activado por el estado de disponibilidad del socket, ajusta estas colas y manda el trabajo al grupo de workers.
    </p>

    <p>Esta nueva arquitectura, haciendo uso de sockets no bloqueantes y características de kernel modernos expuestos por <glossary>APR</glossary> (como epoll de Linux), ya no necesita <code>mpm-accept</code> <directive module="core">Mutex</directive> configurado para evitar el problema de thundering herd (manada estruendosa).</p>

    <p>La cantidad total de conexiones que un solo bloque de proceso/hilo puede gestionar se regula con la directiva 
    <directive>AsyncRequestWorkerFactor</directive>.</p>

    <section id="async-connections"><title>Conexiones Async</title>
        <p>Las conexiones Async necesitarían un hilo worker fijo dedicado con los MPMs previos, pero no con event. La página de estado de 
        <module>mod_status</module> muestra columnas nuevas bajo la sección de conexiones Async:</p>
        <dl>
            <dt>Writing</dt>
            <dd>Mientras se envía la respuesta al cliente, puede ocurrir que el buffer de escritura TCP se llene porque la conexión es muy lenta. Generalmente en este caso un <code>write()</code> al socket devuelve <code>EWOULDBLOCK</code> o <code>EAGAIN</code>, para volver a estar disponible para escritura de nuevo después de un tiempo de inactividad. El worker que tiene en uso el socket podría ser capaz de liberar la tarea de espera al hilo listener, que a cambio la reasinará al primer hilo worker inactivo disponible una cuando se eleve un evento para el socket (por ejemplo, "el socket está ahora disponible para escritura"). Por favor compruebe la sección de Limitaciones para más información.
            </dd>

            <dt>Keep-alive</dt>
            <dd>La gestión de Keep Alive es la mejora más básica con el MPM worker. Cuando un hilo worker termina de vaciar la respuesta al cliente, puede descargar la carga de la gestion del socket al hilo listener, que a cambio esperará a cualquier evento del SO, como "el socket es legible". Si viene cualquier petición nueva del cliente, entonces el listener la enviará al primer hilo worker disponible. En cambio, si ocurre el
            <directive module="core">KeepAliveTimeout</directive> entonces el el listener cerrará el socket. En este método los hilos worker no son responsables de los socket inactivos y pueden reutilizarse para atender otras peticiones.</dd>

            <dt>Closing</dt>
            <dd>A veces el MPM necesita realizar un cierre prolongado, concretamente enviar de vuelta un error al cliente mientras éste está todavía transmitiendo datos a httpd. Enviar la respuesta y entonces cerrar la conexión inmediatamente no es la forma correcta de proceder puesto que el cliente (que todavía está intentando enviar el resto de la petición) obtendría un connection reset y no podría leer la respuesta de httpd. Así que en estos casos, httpd intenta leer el resto de la petición para permitir al cliente consumir la respuesta. El cierre prolongado tiene tiempo limitado pero puede llevar relativamente cierto tiempo, así que un hilo worker puede descargar este trabajo al listener.</dd>
        </dl>

        <p>Estas mejoras son válidas para ambas conexiones HTTP/HTTPS.</p>

        <p>Los estados de conexión indicados más arriba se gestionan por el hilo listener a través de colas dedicadas, que hasta la versión 2.4.27 se comprobaban cada 100ms para encontrar llegaban a configuración de timeout como 
        <directive module="mpm_common">Timeout</directive> y
        <directive module="core">KeepAliveTimeout</directive>. Esto era una solución sencilla y eficiente, pero presentaba un problema, el pollset forzaba un wake-up del hilo listener incluso si no había necesidad (por ejemplo aunque estuviera completamente inactivo), malgastando recursos. A partir de la versión 2.4.28 estas colas se gestionarán completamente a través de la lógica basada en eventos, no dependiendo ya de un polling activo. Los entornos con pocos recursos, como servidores embebidos, se beneficiarán de esta mejora.</p>

    </section>

    <section id="graceful-close"><title>Cierre de procesos graceful y uso de Scoreboard</title>

        <p>Este mpm mostró algunos cuellos de botella de escalabilidad en el pasado llevando al siguiente error: "<strong>scoreboard is full, not at MaxRequestWorkers</strong>".
        <directive module="mpm_common">MaxRequestWorkers</directive> limita el número de peticiones simultáneas que van a ser atendidas en un momento dado y también el número de procesos permitidos
        (<directive module="mpm_common">MaxRequestWorkers</directive> 
        / <directive module="mpm_common">ThreadsPerChild</directive>), mientras tanto el Scoreboard es una representación de todos los procesos que se están ejecutando y el estado de sus hilos worker. Si el scoreboard está lleno (de manera que todos los hilos tienen un estado que no es inactivo) pero el número de peticiones activas servidas no es 
        <directive module="mpm_common">MaxRequestWorkers</directive>, significa que algunos de ellos están bloqueando nuevas peticiones que podrían servirse pero que se están encolando en su lugar (hasta el límite impuesto por
        <directive module="mpm_common">ListenBacklog</directive>). La mayor parte de las veces los hilos están atascados en estado Graceful, concretamente están esperando a finalizar su trabajo con una conexión TCP para cerrar y liberar limpiamente un hueco en el scoreboard (por ejemplo gestionando peticiones que duran mucho, clientes lentos con conexiones con keep-alive activado). Dos escenarios son muy 
        comunes:</p>
        <ul>
            <li>Durante un <a href="../stopping.html#graceful">reinicio graceful</a>. El proceso padre manda una señal a los procesos hijo para completar su trabajo y terminar, mientras que éste recarga la configuración y abre nuevos procesos. Si los hijos que estaban activos previamente siguen ejecutándose durante un tiempo antes de parar, el scoreboard estaría parcialmente ocupado hasta que esos huecos se liberaran.
            </li>
            <li>Cuando la carga del servidor baja de manera que causa que httpd pare algunos procesos (por ejemplo debido a 
            <directive module="mpm_common">MaxSpareThreads</directive>), esto es particularmente problemático porque cuando la carga se incrementa de nuevo, httpd intentará arrancar nuevos procesos. Si el patrón se repite, el número de procesos puede incrementarse bastante, y se puede acabar con una mezcla de procesos antiguos intentando parar y nuevos intentando hacer algún trabajo.
            </li>
        </ul>

        <p>Desde la versión 2.4.24 en adelante, mpm-event es más inteligente y es capaz de gestionar los reinicios graceful mucho mejor. Algunas de las mejoras que trae son:</p>
        <ul>
            <li>Permitir el uso de todos los slots del scoreboard hasta 
            <directive module="mpm_common">ServerLimit</directive>.
            <directive module="mpm_common">MaxRequestWorkers</directive> y
            <directive module="mpm_common">ThreadsPerChild</directive> se usa para limitar la cantidad de procesos activos, mientras tanto
            <directive module="mpm_common">ServerLimit</directive> también tiene en cuenta los que están haciendo un cierre graceful para permitir slots adicionales cuando sea necesario. La idea es usar
            <directive module="mpm_common">ServerLimit</directive> para informar a httpd sobre cuántos procesos en total se toleran antes de impactar los recursos del sistema.
            </li>
            <li>Forzar cierre graceful de procesos para cerrar sus conexiones en estado keep-alive.</li>
            <li>Durante una parada graceful, si hay más hilos worker ejecutándose que conexiones abiertas para un proceso determinado, cerrar estos hilos para recuperar recursos más rápido (que podrían ser necesaios para nuevos procesos).</li>
            <li>Si el scoreboard está lleno, previene que más procesos se cierren de manera graceful debido a una redirección de carga hasta que los antiguos procesos hayan terminado (si no la situación sería peor una vez que la carga subiera de nuevo).</li>
        </ul>

        <p>El comportamiento descrito en el último punto se puede observar completamente a través de <module>mod_status</module> en la tabla de resumen de conexiones en dos nuevas columnas: "Slot" y "Stopping". La primera indica el PID y la última si el proceso está parando o no; el estado extra "Yes (old gen)" indica un proceso que todavía se está ejecutando después de un reinicio graceful.</p>
    </section>

    <section id="limitations"><title>Limitaciones</title>
        <p>La gestión de conexión mejorada podría no funcionar para ciertos filtros de conexión que se han declarado incompatibles con event. En estos casos, este MPM retornará al comportamiento del MPM 
        <module>worker</module> y reservará un hilo worker por conexión. Todos los módulos incluidos con el servidor son compatibles con el MPM event.
        </p>

        <p>Una restricción similar está actualmente presente para peticiones involucradas en un filtro de salida que necesita leer y/o modificar el cuerpo completo de la respuesta. Si la conexión al cliente se bloquea mientras el filtro está procesando los datos, y la cantidad de datos producidos por el filtro es demasiado grande para meterse en buffer de memoria, el hilo usado para esta petición no se libera mientras httpd espera hasta que los datos pendientes se envían al cliente.<br />

        Para ilustrar este punto podemos sopesar las dos situaciones siguientes:
        servir un elemento estático (como por ejemplo un fichero CSS) en contraposición con servir contenido extraido de un servidor FCGI/CGI o un servidor al que se accede con servidor proxy. El primero es predecible, a saber, el MPM event tiene completa visibilidad en el final del contenido y puede usar eventos: el hilo worker sirviendo la respuesta puede hacer un desalojo de los primeros bytes hasta que se devuelve <code>EWOULDBLOCK</code> o <code>EAGAIN</code>, delegando el resto al listener. Este a cambio espera a un evento en el socket, y delega el trabajo para hacer una desalojo del resto del contenido al primero hilo worker inactivo. Mientras tanto, en el último ejemplo (FCGI/CGI/proxied content) el MPM no puede predecir el final de la respuesta y un hilo worker tiene que terminar su trabajo antes de devolver el control al listener. La única alternativa es almacenar la respuesta en un buffer de memoria, pero no sería la opción más segura en pos de la estabilidad del servidor y uso de memoria.
        </p>

    </section>

    <section id="background"><title>Trasfondo</title>
        <p>El modelo event fue posible por la introducción de APIs en los sistemas operativos soportados:</p>
        <ul>
            <li>epoll (Linux) </li>
            <li>kqueue (BSD) </li>
            <li>event ports (Solaris) </li>
        </ul>
        <p>Antes de que estas APIs nuevas estuvieran disponibles, se tenían que usar las APIs tradicionales <code>select</code> y 
        <code>poll</code>.

        Esas APIs se volvían lentas si se usaban para gestionar muchas conexiones o la posibilidad de un grupo de muchas conexiones repentinas era alta.
        Las nuevas APIs permiten controlar muchas más conexiones y trabajan mucho mejor cuando el grupo de conexiones a controlar cambia frecuentemente. Así que estas APIs hicieron posible que se desarrollara el MPM event, que escala mucho mejor con el patrón típico HTTP de muchas conexiones inactivas.</p>

        <p>El MPM asume que la implementación subyacente de <code>apr_pollset</code> es razonablemente segura trabajando con hilos (threadsafe). Esto permite que el MPM evite un alto nivel de bloqueos, o tener que despertar el hilo listener para enviarle un socket keep-alive. Esto actualmente es sólo compatible con KQueue and EPoll.</p>
    </section>

</section>

<section id="requirements"><title>Requerimientos</title>
    <p>Este MPM depende de operaciones atómicas de comparar-y-cambiar de <glossary>APR</glossary> para sincronización de hilos. Si está compilando para una máquina x86 y no necesita soportar 386, o está compilando para SPARC y no necesita funcionar en chips pre-UltraSPARC, añada
    <code>--enable-nonportable-atomics=yes</code> a los parámetros del script 
    <program>configure</program>. Esto hará que APR implemente operaciones atómicas usando los opcode eficientes no disponibles en CPU's más antiguas.
    </p>

    <p>Este MPM no rinde bien en plataformas más antiguas que no tienen un buen sistema multihilo, pero el requerimiento de EPoll o KQueue hace esto irrelevante.</p>

    <ul>

      <li>Para usar este MPM en FreeBSD, se recomienda FreeBSD 5.3 o superior. Sin embargo, es posible ejecutar este MPM en FreeBSD 5.2.1 si usa
      <code>libkse</code> (vea <code>man libmap.conf</code>).</li>

      <li>Para NetBSD, como poco se recomienda la versión 2.0.</li>

      <li>Para Linux, se recomienda un kernel 2.6 kernel. También es necesario asegurarse de que su versión de <code>glibc</code> ha sido compilada con soporte para EPoll.</li>

    </ul>
</section>

<directivesynopsis location="mpm_common"><name>CoreDumpDirectory</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>EnableExceptionHook</name>
</directivesynopsis>
<directivesynopsis location="mod_unixd"><name>Group</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>Listen</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ListenBacklog</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>SendBufferSize</name>
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
<directivesynopsis location="mpm_common"><name>PidFile</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ScoreBoardFile</name>
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

<directivesynopsis>
<name>AsyncRequestWorkerFactor</name>
<description>Limita el número de conexiones concurrentes por 
    proceso</description>
<syntax>AsyncRequestWorkerFactor <var>factor</var></syntax>
<default>2</default>
<contextlist><context>server config</context> </contextlist>
<compatibility>Disponible en versión 2.3.13 y posterior</compatibility>

<usage>
    <p>El MPM event gestiona algunas conexiónes de manera asíncrona, donde hilos worker de petición están solo alojados por cortos periodos de tiempos según es necesario, y otras conexiones con un hilo worker de petición reservado por conexión. Esto puede llevar a situaciones donde todos los workers están trabajando y no hay ningun hilo worker disponible para gestionar nuevo trabajo en las conexiones asíncronas establecidas.</p>

    <p>Para mitigar este problema, el MPM event hace dos cosas:</p>
    <ul>
        <li>limita el número de conexiones aceptadas por proceso, dependiendo del número de hilos worker inactivos;</li>
        <li>si todos los workers están ocupados, cerrará conexiones en estado keep-alive incluso si el timeout no ha expirado. Esto permite que los respectivos clientes reconecten a diferentes procesos que pueden tener todavía hilos worker disponibles.</li>
    </ul>

    <p>Esta directiva puede usarse para afinar el límite de conexiones por-proceso. Un <strong>proceso</strong> solo aceptará conexiones nuevas si el número actual de conexiones (sin contar las que están en estado "closing") es menor que:</p>

    <p class="indent"><strong>
        <directive module="mpm_common">ThreadsPerChild</directive> +
        (<directive>AsyncRequestWorkerFactor</directive> *
        <var>número de workers inactivos</var>)
    </strong></p>

    <p>Una estimación del máximo de conexiones concurrentes entre todos los procesos dado un valor medio de hilos worker inactivos puede ser calculado con:
    </p>


    <p class="indent"><strong>
        (<directive module="mpm_common">ThreadsPerChild</directive> +
        (<directive>AsyncRequestWorkerFactor</directive> *
        <var>número de workers inactivos</var>)) *
        <directive module="mpm_common">ServerLimit</directive>
    </strong></p>

    <note><title>Example</title>
    <highlight language="config">

ThreadsPerChild = 10
ServerLimit = 4
AsyncRequestWorkerFactor = 2
MaxRequestWorkers = 40

workers_inactivos = 4 (media de todos los procesos para mantenerlo sencillo)

max_conexiones = (ThreadsPerChild + (AsyncRequestWorkerFactor * idle_workers)) * ServerLimit
                = (10 + (2 * 4)) * 4 = 72

    </highlight>
    </note>

    <p>Cuando todos los hilos worker están inactivos, entonces el máximo absoluto de conexiones concurrentes puede calcularse de una forma más sencilla::</p>

    <p class="indent"><strong>
        (<directive>AsyncRequestWorkerFactor</directive> + 1) *
        <directive module="mpm_common">MaxRequestWorkers</directive>
    </strong></p>


    <note><title>Example</title>
    <highlight language="config">

ThreadsPerChild = 10
ServerLimit = 4
MaxRequestWorkers = 40
AsyncRequestWorkerFactor = 2

    </highlight>

    <p>Si todoso los procesos tienen hilos inactivos entonces: </p>

    <highlight language="config">idle_workers = 10</highlight>

    <p>Podemos calcular el máximo absoluto de conexiones concurrentes de dos formas:</p>

    <highlight language="config">

max_connections = (ThreadsPerChild + (AsyncRequestWorkerFactor * idle_workers)) * ServerLimit
                = (10 + (2 * 10)) * 4 = 120

max_connections = (AsyncRequestWorkerFactor + 1) * MaxRequestWorkers
                = (2 + 1) * 40 = 120

    </highlight>
    </note>

    <p>Configurar <directive>AsyncRequestWorkerFactor</directive> requiere conocimiento sobre el tráfico que se recibe por httpd y cada caso de uso específico, así que cambiar el valor por defecto requiere comprobaciones y extracción de datos intensivas desde <module>mod_status</module>.</p>

    <p><directive module="mpm_common">MaxRequestWorkers</directive> se llamaba
    <directive>MaxClients</directive> antes de la versión 2.3.13. El valor de más arriba muestra que el nombre antiguo no describía de una manera certera su significado para el MPM event.</p>

    <p><directive>AsyncRequestWorkerFactor</directive> puede tomar valores numéricos no integrales, p. ej. "1.5".</p>

</usage>

</directivesynopsis>

</modulesynopsis>
