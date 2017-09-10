<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es" xml:lang="es"><head>
<meta content="text/html; charset=ISO-8859-1" http-equiv="Content-Type" />
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>event - Servidor HTTP Apache Versión 2.5</title>
<link href="../style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet" />
<link href="../style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size" />
<link href="../style/css/manual-print.css" rel="stylesheet" media="print" type="text/css" /><link rel="stylesheet" type="text/css" href="../style/css/prettify.css" />
<script src="../style/scripts/prettify.min.js" type="text/javascript">
</script>

<link href="../images/favicon.ico" rel="shortcut icon" /></head>
<body>
<div id="page-header">
<p class="menu"><a href="../mod/">Módulos</a> | <a href="../mod/quickreference.html">Directivas</a> | <a href="http://wiki.apache.org/httpd/FAQ">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa del sitio web</a></p>
<p class="apache">Versión 2.5 del Servidor HTTP Apache</p>
<img alt="" src="../images/feather.png" /></div>
<div class="up"><a href="./"><img title="&lt;-" alt="&lt;-" src="../images/left.gif" /></a></div>
<div id="path">
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs/">Documentación</a> &gt; <a href="../">Versión 2.5</a> &gt; <a href="./">Módulos</a></div>
<div id="page-content">
<div id="preamble"><h1>MPM de Apache event</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="../en/mod/event.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/mod/event.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="../fr/mod/event.html" hreflang="fr" rel="alternate" title="Français">&nbsp;fr&nbsp;</a></p>
</div>
<table class="module"><tr><th><a href="module-dict.html#Description">Descripción:</a></th><td>Una variante del MPM <code class="module"><a href="../mod/worker.html">worker</a></code> con el 
objetivo de consumir hilos sólo para conexiones con procesamiento 
activo</td></tr>
<tr><th><a href="module-dict.html#Status">Estado:</a></th><td>MPM</td></tr>
<tr><th><a href="module-dict.html#ModuleIdentifier">Identificador de Módulos:</a></th><td>mpm_event_module</td></tr>
<tr><th><a href="module-dict.html#SourceFile">Fichero de Código Fuente:</a></th><td>event.c</td></tr></table>
<h3>Resumen de contenidos</h3>

    <p>El Módulo de Multi-Proceso (MPM en inglés) <code class="module"><a href="../mod/event.html">event</a></code> es, 
    como su nombre indica, una implementación asíncrona basada en eventos, 
    diseñada para permitir que se sirvan más peticiones simultáneamente 
    mediante la concesión de algo de trabajo de procesamiento a los hilos 
    "listeners" (de escucha), liberando a los hilos worker (trabajadores)
    para servir más peticiones.
    </p>

    <p>Para usar el MPM <code class="module"><a href="../mod/event.html">event</a></code>, añada
      <code>--with-mpm=event</code> a los parámetros del script 
      <code class="program"><a href="../programs/configure.html">configure</a></code> cuando esté compilando
      <code class="program"><a href="../programs/httpd.html">httpd</a></code>.</p>

</div>
<div id="quickview"><h3>Temas</h3>
<ul id="topics">
<li><img alt="" src="../images/down.gif" /> <a href="#event-worker-relationship">Relación con el MPM Worker</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#how-it-works">Como Trabaja</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#requirements">Requerimientos</a></li>
</ul><h3 class="directives">Directivas</h3>
<ul id="toc">
<li><img alt="" src="../images/down.gif" /> <a href="#asyncrequestworkerfactor">AsyncRequestWorkerFactor</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#coredumpdirectory">CoreDumpDirectory</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#enableexceptionhook">EnableExceptionHook</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mod_unixd.html#group">Group</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#listen">Listen</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#listenbacklog">ListenBacklog</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#maxconnectionsperchild">MaxConnectionsPerChild</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#maxmemfree">MaxMemFree</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#maxrequestworkers">MaxRequestWorkers</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#maxsparethreads">MaxSpareThreads</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#minsparethreads">MinSpareThreads</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#pidfile">PidFile</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#scoreboardfile">ScoreBoardFile</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#sendbuffersize">SendBufferSize</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#serverlimit">ServerLimit</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#startservers">StartServers</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#threadlimit">ThreadLimit</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#threadsperchild">ThreadsPerChild</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#threadstacksize">ThreadStackSize</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mod_unixd.html#user">User</a></li>
</ul>
<h3>Bugfix checklist</h3><ul class="seealso"><li><a href="https://www.apache.org/dist/httpd/CHANGES_2.4">httpd changelog</a></li><li><a href="https://bz.apache.org/bugzilla/buglist.cgi?bug_status=__open__&amp;list_id=144532&amp;product=Apache%20httpd-2&amp;query_format=specific&amp;order=changeddate%20DESC%2Cpriority%2Cbug_severity&amp;component=mpm_event">Known issues</a></li><li><a href="https://bz.apache.org/bugzilla/enter_bug.cgi?product=Apache%20httpd-2&amp;component=mpm_event">Report a bug</a></li></ul><h3>Consulte también</h3>
<ul class="seealso">
<li><a href="worker.html">El MPM worker</a></li>
<li><a href="#comments_section">Comentarios</a></li></ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="event-worker-relationship" id="event-worker-relationship">Relación con el MPM Worker</a></h2>
    
    <p><code class="module"><a href="../mod/event.html">event</a></code> está basado en el MPM <code class="module"><a href="../mod/worker.html">worker</a></code>, que implmementa un servidor híbrido de multi-proceso multi-hilo. Un solo proceso (el padre) es responsable de lanzar procesos child (hijos). Cada proceso child crea un número fijo de hilos de servidor tal y como se especifica en la directiva 
    <code class="directive"><a href="../mod/mpm_common.html#threadsperchild">ThreadsPerChild</a></code>, así como un hilo listener que está en escucha para recibir conexiones y las pasa al hilo worker para procesamiento según van llegando.</p>

    <p>Las directivas de configuración en tiempo real son idénticas a aquellas facilitadas por <code class="module"><a href="../mod/worker.html">worker</a></code>, con la única diferencia de que event además tiene la directiva 
    <code class="directive">AsyncRequestWorkerFactor</code>.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="how-it-works" id="how-it-works">Como Trabaja</a></h2>
    <p>El objetivo original de este MPM era arreglar el 'problema del keep alive' en HTTP. Después de que un cliente completa su primera petición, puede mantener la conexión abierta, enviando más peticiones utilizando el mismo socket y ahorrando una cantidad significativa de tiempo en abrir nuevas conexiones TCP. Sin embargo, el Servidor Apache HTTP tradicionalmente mantiene un proceso/hilo child esperando a que le lleguen datos del cliente, lo cual tiene sus propias desventajas.
    Para resolver este problema, este MPM usa un hilo dedicado de tipo listener en cada proceso junto con un grupo de hilos worker, compartiendo colas específicas para esas peticiones en modo keep-alive (o, más sencillamente, "readable"), aquellos en modo terminando-escritura, y aquellos en proceso de cerrarse ("closing"). Un bucle de eventos, activado por el estado de disponibilidad del socket, ajusta estas colas y manda el trabajo al grupo de workers.
    </p>

    <p>Esta nueva arquitectura, haciendo uso de sockets no bloqueantes y características de kernel modernos expuestos por <a class="glossarylink" href="../glossary.html#apr" title="ver glosario">APR</a> (como epoll de Linux), ya no necesita <code>mpm-accept</code> <code class="directive"><a href="../mod/core.html#mutex">Mutex</a></code> configurado para evitar el problema de thundering herd (manada estruendosa).</p>

    <p>La cantidad total de conexiones que un solo bloque de proceso/hilo puede gestionar se regula con la directiva 
    <code class="directive">AsyncRequestWorkerFactor</code>.</p>

    <h3><a name="async-connections" id="async-connections">Conexiones Async</a></h3>
        <p>Las conexiones Async necesitarían un hilo worker fijo dedicado con los MPMs previos, pero no con event. La página de estado de 
        <code class="module"><a href="../mod/mod_status.html">mod_status</a></code> muestra columnas nuevas bajo la sección de conexiones Async:</p>
        <dl>
            <dt>Writing</dt>
            <dd>Mientras se envía la respuesta al cliente, puede ocurrir que el buffer de escritura TCP se llene porque la conexión es muy lenta. Generalmente en este caso un <code>write()</code> al socket devuelve <code>EWOULDBLOCK</code> o <code>EAGAIN</code>, para volver a estar disponible para escritura de nuevo después de un tiempo de inactividad. El worker que tiene en uso el socket podría ser capaz de liberar la tarea de espera al hilo listener, que a cambio la reasinará al primer hilo worker inactivo disponible una cuando se eleve un evento para el socket (por ejemplo, "el socket está ahora disponible para escritura"). Por favor compruebe la sección de Limitaciones para más información.
            </dd>

            <dt>Keep-alive</dt>
            <dd>La gestión de Keep Alive es la mejora más básica con el MPM worker. Cuando un hilo worker termina de vaciar la respuesta al cliente, puede descargar la carga de la gestion del socket al hilo listener, que a cambio esperará a cualquier evento del SO, como "el socket es legible". Si viene cualquier petición nueva del cliente, entonces el listener la enviará al primer hilo worker disponible. En cambio, si ocurre el
            <code class="directive"><a href="../mod/core.html#keepalivetimeout">KeepAliveTimeout</a></code> entonces el el listener cerrará el socket. En este método los hilos worker no son responsables de los socket inactivos y pueden reutilizarse para atender otras peticiones.</dd>

            <dt>Closing</dt>
            <dd>A veces el MPM necesita realizar un cierre prolongado, concretamente enviar de vuelta un error al cliente mientras éste está todavía transmitiendo datos a httpd. Enviar la respuesta y entonces cerrar la conexión inmediatamente no es la forma correcta de proceder puesto que el cliente (que todavía está intentando enviar el resto de la petición) obtendría un connection reset y no podría leer la respuesta de httpd. Así que en estos casos, httpd intenta leer el resto de la petición para permitir al cliente consumir la respuesta. El cierre prolongado tiene tiempo limitado pero puede llevar relativamente cierto tiempo, así que un hilo worker puede descargar este trabajo al listener.</dd>
        </dl>

        <p>Estas mejoras son válidas para ambas conexiones HTTP/HTTPS.</p>

        <p>Los estados de conexión indicados más arriba se gestionan por el hilo listener a través de colas dedicadas, que hasta la versión 2.4.27 se comprobaban cada 100ms para encontrar llegaban a configuración de timeout como 
        <code class="directive"><a href="../mod/mpm_common.html#timeout">Timeout</a></code> y
        <code class="directive"><a href="../mod/core.html#keepalivetimeout">KeepAliveTimeout</a></code>. Esto era una solución sencilla y eficiente, pero presentaba un problema, el pollset forzaba un wake-up del hilo listener incluso si no había necesidad (por ejemplo aunque estuviera completamente inactivo), malgastando recursos. A partir de la versión 2.4.28 estas colas se gestionarán completamente a través de la lógica basada en eventos, no dependiendo ya de un polling activo. Los entornos con pocos recursos, como servidores embebidos, se beneficiarán de esta mejora.</p>

    

    <h3><a name="graceful-close" id="graceful-close">Cierre de procesos graceful y uso de Scoreboard</a></h3>

        <p>Este mpm mostró algunos cuellos de botella de escalabilidad en el pasado llevando al siguiente error: "<strong>scoreboard is full, not at MaxRequestWorkers</strong>".
        <code class="directive"><a href="../mod/mpm_common.html#maxrequestworkers">MaxRequestWorkers</a></code> limita el número de peticiones simultáneas que van a ser atendidas en un momento dado y también el número de procesos permitidos
        (<code class="directive"><a href="../mod/mpm_common.html#maxrequestworkers">MaxRequestWorkers</a></code> 
        / <code class="directive"><a href="../mod/mpm_common.html#threadsperchild">ThreadsPerChild</a></code>), mientras tanto el Scoreboard es una representación de todos los procesos que se están ejecutando y el estado de sus hilos worker. Si el scoreboard está lleno (de manera que todos los hilos tienen un estado que no es inactivo) pero el número de peticiones activas servidas no es 
        <code class="directive"><a href="../mod/mpm_common.html#maxrequestworkers">MaxRequestWorkers</a></code>, significa que algunos de ellos están bloqueando nuevas peticiones que podrían servirse pero que se están encolando en su lugar (hasta el límite impuesto por
        <code class="directive"><a href="../mod/mpm_common.html#listenbacklog">ListenBacklog</a></code>). La mayor parte de las veces los hilos están atascados en estado Graceful, concretamente están esperando a finalizar su trabajo con una conexión TCP para cerrar y liberar limpiamente un hueco en el scoreboard (por ejemplo gestionando peticiones que duran mucho, clientes lentos con conexiones con keep-alive activado). Dos escenarios son muy 
        comunes:</p>
        <ul>
            <li>Durante un <a href="../stopping.html#graceful">reinicio graceful</a>. El proceso padre manda una señal a los procesos hijo para completar su trabajo y terminar, mientras que éste recarga la configuración y abre nuevos procesos. Si los hijos que estaban activos previamente siguen ejecutándose durante un tiempo antes de parar, el scoreboard estaría parcialmente ocupado hasta que esos huecos se liberaran.
            </li>
            <li>Cuando la carga del servidor baja de manera que causa que httpd pare algunos procesos (por ejemplo debido a 
            <code class="directive"><a href="../mod/mpm_common.html#maxsparethreads">MaxSpareThreads</a></code>), esto es particularmente problemático porque cuando la carga se incrementa de nuevo, httpd intentará arrancar nuevos procesos. Si el patrón se repite, el número de procesos puede incrementarse bastante, y se puede acabar con una mezcla de procesos antiguos intentando parar y nuevos intentando hacer algún trabajo.
            </li>
        </ul>

        <p>Desde la versión 2.4.24 en adelante, mpm-event es más inteligente y es capaz de gestionar los reinicios graceful mucho mejor. Algunas de las mejoras que trae son:</p>
        <ul>
            <li>Permitir el uso de todos los slots del scoreboard hasta 
            <code class="directive"><a href="../mod/mpm_common.html#serverlimit">ServerLimit</a></code>.
            <code class="directive"><a href="../mod/mpm_common.html#maxrequestworkers">MaxRequestWorkers</a></code> y
            <code class="directive"><a href="../mod/mpm_common.html#threadsperchild">ThreadsPerChild</a></code> se usa para limitar la cantidad de procesos activos, mientras tanto
            <code class="directive"><a href="../mod/mpm_common.html#serverlimit">ServerLimit</a></code> también tiene en cuenta los que están haciendo un cierre graceful para permitir slots adicionales cuando sea necesario. La idea es usar
            <code class="directive"><a href="../mod/mpm_common.html#serverlimit">ServerLimit</a></code> para informar a httpd sobre cuántos procesos en total se toleran antes de impactar los recursos del sistema.
            </li>
            <li>Forzar cierre graceful de procesos para cerrar sus conexiones en estado keep-alive.</li>
            <li>Durante una parada graceful, si hay más hilos worker ejecutándose que conexiones abiertas para un proceso determinado, cerrar estos hilos para recuperar recursos más rápido (que podrían ser necesaios para nuevos procesos).</li>
            <li>Si el scoreboard está lleno, previene que más procesos se cierren de manera graceful debido a una redirección de carga hasta que los antiguos procesos hayan terminado (si no la situación sería peor una vez que la carga subiera de nuevo).</li>
        </ul>

        <p>El comportamiento descrito en el último punto se puede observar completamente a través de <code class="module"><a href="../mod/mod_status.html">mod_status</a></code> en la tabla de resumen de conexiones en dos nuevas columnas: "Slot" y "Stopping". La primera indica el PID y la última si el proceso está parando o no; el estado extra "Yes (old gen)" indica un proceso que todavía se está ejecutando después de un reinicio graceful.</p>
    

    <h3><a name="limitations" id="limitations">Limitaciones</a></h3>
        <p>La gestión de conexión mejorada podría no funcionar para ciertos filtros de conexión que se han declarado incompatibles con event. En estos casos, este MPM retornará al comportamiento del MPM 
        <code class="module"><a href="../mod/worker.html">worker</a></code> y reservará un hilo worker por conexión. Todos los módulos incluidos con el servidor son compatibles con el MPM event.
        </p>

        <p>Una restricción similar está actualmente presente para peticiones involucradas en un filtro de salida que necesita leer y/o modificar el cuerpo completo de la respuesta. Si la conexión al cliente se bloquea mientras el filtro está procesando los datos, y la cantidad de datos producidos por el filtro es demasiado grande para meterse en buffer de memoria, el hilo usado para esta petición no se libera mientras httpd espera hasta que los datos pendientes se envían al cliente.<br />

        Para ilustrar este punto podemos sopesar las dos situaciones siguientes:
        servir un elemento estático (como por ejemplo un fichero CSS) en contraposición con servir contenido extraido de un servidor FCGI/CGI o un servidor al que se accede con servidor proxy. El primero es predecible, a saber, el MPM event tiene completa visibilidad en el final del contenido y puede usar eventos: el hilo worker sirviendo la respuesta puede hacer un desalojo de los primeros bytes hasta que se devuelve <code>EWOULDBLOCK</code> o <code>EAGAIN</code>, delegando el resto al listener. Este a cambio espera a un evento en el socket, y delega el trabajo para hacer una desalojo del resto del contenido al primero hilo worker inactivo. Mientras tanto, en el último ejemplo (FCGI/CGI/proxied content) el MPM no puede predecir el final de la respuesta y un hilo worker tiene que terminar su trabajo antes de devolver el control al listener. La única alternativa es almacenar la respuesta en un buffer de memoria, pero no sería la opción más segura en pos de la estabilidad del servidor y uso de memoria.
        </p>

    

    <h3><a name="background" id="background">Trasfondo</a></h3>
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
    

</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="requirements" id="requirements">Requerimientos</a></h2>
    <p>Este MPM depende de operaciones atómicas de comparar-y-cambiar de <a class="glossarylink" href="../glossary.html#apr" title="ver glosario">APR</a> para sincronización de hilos. Si está compilando para una máquina x86 y no necesita soportar 386, o está compilando para SPARC y no necesita funcionar en chips pre-UltraSPARC, añada
    <code>--enable-nonportable-atomics=yes</code> a los parámetros del script 
    <code class="program"><a href="../programs/configure.html">configure</a></code>. Esto hará que APR implemente operaciones atómicas usando los opcode eficientes no disponibles en CPU's más antiguas.
    </p>

    <p>Este MPM no rinde bien en plataformas más antiguas que no tienen un buen sistema multihilo, pero el requerimiento de EPoll o KQueue hace esto irrelevante.</p>

    <ul>

      <li>Para usar este MPM en FreeBSD, se recomienda FreeBSD 5.3 o superior. Sin embargo, es posible ejecutar este MPM en FreeBSD 5.2.1 si usa
      <code>libkse</code> (vea <code>man libmap.conf</code>).</li>

      <li>Para NetBSD, como poco se recomienda la versión 2.0.</li>

      <li>Para Linux, se recomienda un kernel 2.6 kernel. También es necesario asegurarse de que su versión de <code>glibc</code> ha sido compilada con soporte para EPoll.</li>

    </ul>
</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="AsyncRequestWorkerFactor" id="AsyncRequestWorkerFactor">AsyncRequestWorkerFactor</a> <a name="asyncrequestworkerfactor" id="asyncrequestworkerfactor">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Limita el número de conexiones concurrentes por 
    proceso</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>AsyncRequestWorkerFactor <var>factor</var></code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>2</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>MPM</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>event</td></tr>
<tr><th><a href="directive-dict.html#Compatibility">Compatibilidad:</a></th><td>Disponible en versión 2.3.13 y posterior</td></tr>
</table>
    <p>El MPM event gestiona algunas conexiónes de manera asíncrona, donde hilos worker de petición están solo alojados por cortos periodos de tiempos según es necesario, y otras conexiones con un hilo worker de petición reservado por conexión. Esto puede llevar a situaciones donde todos los workers están trabajando y no hay ningun hilo worker disponible para gestionar nuevo trabajo en las conexiones asíncronas establecidas.</p>

    <p>Para mitigar este problema, el MPM event hace dos cosas:</p>
    <ul>
        <li>limita el número de conexiones aceptadas por proceso, dependiendo del número de hilos worker inactivos;</li>
        <li>si todos los workers están ocupados, cerrará conexiones en estado keep-alive incluso si el timeout no ha expirado. Esto permite que los respectivos clientes reconecten a diferentes procesos que pueden tener todavía hilos worker disponibles.</li>
    </ul>

    <p>Esta directiva puede usarse para afinar el límite de conexiones por-proceso. Un <strong>proceso</strong> solo aceptará conexiones nuevas si el número actual de conexiones (sin contar las que están en estado "closing") es menor que:</p>

    <p class="indent"><strong>
        <code class="directive"><a href="../mod/mpm_common.html#threadsperchild">ThreadsPerChild</a></code> +
        (<code class="directive">AsyncRequestWorkerFactor</code> *
        <var>número de workers inactivos</var>)
    </strong></p>

    <p>Una estimación del máximo de conexiones concurrentes entre todos los procesos dado un valor medio de hilos worker inactivos puede ser calculado con:
    </p>


    <p class="indent"><strong>
        (<code class="directive"><a href="../mod/mpm_common.html#threadsperchild">ThreadsPerChild</a></code> +
        (<code class="directive">AsyncRequestWorkerFactor</code> *
        <var>número de workers inactivos</var>)) *
        <code class="directive"><a href="../mod/mpm_common.html#serverlimit">ServerLimit</a></code>
    </strong></p>

    <div class="note"><h3>Example</h3>
    <pre class="prettyprint lang-config">ThreadsPerChild = 10
ServerLimit = 4
AsyncRequestWorkerFactor = 2
MaxRequestWorkers = 40

workers_inactivos = 4 (media de todos los procesos para mantenerlo sencillo)

max_conexiones = (ThreadsPerChild + (AsyncRequestWorkerFactor * idle_workers)) * ServerLimit
                = (10 + (2 * 4)) * 4 = 72</pre>

    </div>

    <p>Cuando todos los hilos worker están inactivos, entonces el máximo absoluto de conexiones concurrentes puede calcularse de una forma más sencilla::</p>

    <p class="indent"><strong>
        (<code class="directive">AsyncRequestWorkerFactor</code> + 1) *
        <code class="directive"><a href="../mod/mpm_common.html#maxrequestworkers">MaxRequestWorkers</a></code>
    </strong></p>


    <div class="note"><h3>Example</h3>
    <pre class="prettyprint lang-config">ThreadsPerChild = 10
ServerLimit = 4
MaxRequestWorkers = 40
AsyncRequestWorkerFactor = 2</pre>


    <p>Si todoso los procesos tienen hilos inactivos entonces: </p>

    <pre class="prettyprint lang-config">idle_workers = 10</pre>


    <p>Podemos calcular el máximo absoluto de conexiones concurrentes de dos formas:</p>

    <pre class="prettyprint lang-config">max_connections = (ThreadsPerChild + (AsyncRequestWorkerFactor * idle_workers)) * ServerLimit
                = (10 + (2 * 10)) * 4 = 120

max_connections = (AsyncRequestWorkerFactor + 1) * MaxRequestWorkers
                = (2 + 1) * 40 = 120</pre>

    </div>

    <p>Configurar <code class="directive">AsyncRequestWorkerFactor</code> requiere conocimiento sobre el tráfico que se recibe por httpd y cada caso de uso específico, así que cambiar el valor por defecto requiere comprobaciones y extracción de datos intensivas desde <code class="module"><a href="../mod/mod_status.html">mod_status</a></code>.</p>

    <p><code class="directive"><a href="../mod/mpm_common.html#maxrequestworkers">MaxRequestWorkers</a></code> se llamaba
    <code class="directive">MaxClients</code> antes de la versión 2.3.13. El valor de más arriba muestra que el nombre antiguo no describía de una manera certera su significado para el MPM event.</p>

    <p><code class="directive">AsyncRequestWorkerFactor</code> puede tomar valores numéricos no integrales, p. ej. "1.5".</p>


</div>
</div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="../en/mod/event.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/mod/event.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="../fr/mod/event.html" hreflang="fr" rel="alternate" title="Français">&nbsp;fr&nbsp;</a></p>
</div><div class="top"><a href="#page-header"><img src="../images/up.gif" alt="top" /></a></div><div class="section"><h2><a id="comments_section" name="comments_section">Comentarios</a></h2><div class="warning"><strong>Notice:</strong><br />This is not a Q&amp;A section. Comments placed here should be pointed towards suggestions on improving the documentation or server, and may be removed again by our moderators if they are either implemented or considered invalid/off-topic. Questions on how to manage the Apache HTTP Server should be directed at either our IRC channel, #httpd, on Freenode, or sent to our <a href="http://httpd.apache.org/lists.html">mailing lists</a>.</div>
<script type="text/javascript"><!--//--><![CDATA[//><!--
var comments_shortname = 'httpd';
var comments_identifier = 'http://httpd.apache.org/docs/trunk/mod/event.html';
(function(w, d) {
    if (w.location.hostname.toLowerCase() == "httpd.apache.org") {
        d.write('<div id="comments_thread"><\/div>');
        var s = d.createElement('script');
        s.type = 'text/javascript';
        s.async = true;
        s.src = 'https://comments.apache.org/show_comments.lua?site=' + comments_shortname + '&page=' + comments_identifier;
        (d.getElementsByTagName('head')[0] || d.getElementsByTagName('body')[0]).appendChild(s);
    }
    else {
        d.write('<div id="comments_thread">Comments are disabled for this page at the moment.<\/div>');
    }
})(window, document);
//--><!]]></script></div><div id="footer">
<p class="apache">Copyright 2017 The Apache Software Foundation.<br />Licencia bajo los términos de la <a href="http://www.apache.org/licenses/LICENSE-2.0">Apache License, Version 2.0</a>.</p>
<p class="menu"><a href="../mod/">Módulos</a> | <a href="../mod/quickreference.html">Directivas</a> | <a href="http://wiki.apache.org/httpd/FAQ">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa del sitio web</a></p></div><script type="text/javascript"><!--//--><![CDATA[//><!--
if (typeof(prettyPrint) !== 'undefined') {
    prettyPrint();
}
//--><!]]></script>
</body></html>