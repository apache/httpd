<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1939477 -->
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

<modulesynopsis metafile="mpm_common.xml.meta">

<name>mpm_common</name>
<description>Un conjunto de directivas implementadas por
más de un módulo multiproceso (MPM)</description>
<status>MPM</status>

<directivesynopsis>
<name>CoreDumpDirectory</name>
<description>Directorio al que Apache HTTP Server intenta
cambiar antes de volcar un core</description>
<syntax>CoreDumpDirectory <var>directory</var></syntax>
<default>Vea el uso para conocer el valor por defecto</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>event</module><module>worker</module>
<module>prefork</module></modulelist>

<usage>
    <p>Esto controla el directorio al que Apache httpd intenta
    cambiar antes de volcar un core. Si su sistema operativo está configurado para
    crear archivos core en el directorio de trabajo del proceso que falla,
    <directive>CoreDumpDirectory</directive> es necesaria para cambiar el directorio
    de trabajo respecto al directorio <directive module="core">ServerRoot</directive> por
    defecto, que no debería tener permisos de escritura para el usuario con el que se ejecuta el servidor.</p>

    <p>Si desea un volcado de core para depuración, puede usar esta directiva para
    colocarlo en otra ubicación. Esta directiva no tiene efecto si su sistema
    operativo no está configurado para escribir archivos core en el directorio de trabajo
    de los procesos que fallan.</p>

    <note type="warning">
      <title>Nota de seguridad para sistemas Linux</title>

      <p>Usar esta directiva en Linux puede permitir que otros procesos del
      sistema (si se ejecutan con privilegios similares, como los scripts
      CGI) se adjunten a los procesos hijo de httpd mediante la llamada al sistema
      <code>ptrace</code>. Esto puede debilitar la protección frente a ciertos
      ataques de seguridad. No se recomienda usar esta directiva
      en sistemas de producción.</p>
    </note>

    <note><title>Volcados de core en Linux</title>
      <p>Si Apache httpd se inicia como root y cambia a otro usuario, el
      kernel de Linux <em>desactiva</em> los volcados de core aunque el directorio sea
      escribible por el proceso. Apache httpd (2.0.46 y posteriores) reactiva los volcados de core
      en Linux 2.4 y versiones posteriores, pero solo si configura explícitamente un <directive
      >CoreDumpDirectory</directive>.</p>
    </note>

    <note>
    <title>Volcados de core en BSD</title>
    <p>Para habilitar el volcado de core de ejecutables suid en sistemas BSD (como
    FreeBSD), establezca <code>kern.sugid_coredump</code> a 1.
    </p>
    </note>

    <note><title>Señales específicas</title>
      <p>El procesamiento de <directive>CoreDumpDirectory</directive> solo ocurre para
      un conjunto determinado de señales fatales: SIGFPE, SIGILL, SIGABRT,
      SIGSEGV y SIGBUS.</p>
      <p>En algunos sistemas operativos, SIGQUIT también produce un volcado de core pero
      no pasa por el procesamiento de <directive>CoreDumpDirectory</directive> o
      <directive>EnableExceptionHook</directive>, por lo que la ubicación del core
      la dicta completamente el sistema operativo.</p>
    </note>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>EnableExceptionHook</name>
<description>Habilita un hook que ejecuta manejadores de excepciones
después de un fallo</description>
<syntax>EnableExceptionHook On|Off</syntax>
<default>EnableExceptionHook Off</default>
<contextlist><context>server config</context></contextlist>
<modulelist>
<module>event</module><module>worker</module>
<module>prefork</module></modulelist>

<usage>
    <p>Por motivos de seguridad, esta directiva solo está disponible si el servidor se
    configuró con la opción <code>--enable-exception-hook</code>. Habilita
    un hook que permite que módulos externos se conecten y hagan algo
    después de que un proceso hijo falle.</p>

    <p>Ya existen dos módulos, <code>mod_whatkilledus</code> y
    <code>mod_backtrace</code>, que hacen uso de este hook. Consulte el
    sitio <a
    href="https://emptyhammock.com/projects/httpd/diag/"
    >EnableExceptionHook</a> de Jeff Trawick para obtener más información sobre ellos.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>GracefulShutdownTimeout</name>
<description>Especifica un tiempo límite tras el cual un servidor que se está
apagando de forma ordenada finalizará.</description>
<syntax>GracefulShutdownTimeout <var>seconds</var></syntax>
<default>GracefulShutdownTimeout 0</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>event</module><module>worker</module>
<module>prefork</module><module>motorz</module></modulelist>

<usage>
    <p><directive>GracefulShutdownTimeout</directive> especifica
    durante cuántos segundos, tras recibir una señal de "parada ordenada", un
    servidor debe seguir funcionando, atendiendo las conexiones existentes.</p>

    <p>Establecer este valor a cero significa que el servidor esperará
    indefinidamente hasta que todas las peticiones restantes se hayan atendido por completo.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>PidFile</name>
<description>Archivo donde el servidor registra el ID de proceso
del demonio</description>
<syntax>PidFile <var>filename</var></syntax>
<default>PidFile httpd.pid</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>event</module><module>worker</module>
<module>prefork</module><module>mpm_winnt</module>
<module>mpmt_os2</module>
</modulelist>

<usage>
    <p>La directiva <directive>PidFile</directive> establece el archivo en el
    que el servidor registra el id de proceso del demonio. Si el
    nombre de archivo no es absoluto, se asume que es relativo a
    <directive module="core">DefaultRuntimeDir</directive>.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
      PidFile /var/run/apache.pid
      </highlight>
    </example>

    <p>A menudo es útil poder enviar al servidor una señal,
    de forma que cierre y vuelva a abrir su <directive
    module="core">ErrorLog</directive> y su <directive
    module="mod_log_config">TransferLog</directive>, y
    vuelva a leer sus archivos de configuración. Esto se hace enviando una
    señal SIGHUP (kill -1) al id de proceso que figura en el
    <directive>PidFile</directive>.</p>

    <p>El <directive>PidFile</directive> está sujeto a las mismas
    advertencias sobre la ubicación de archivos de registro y <a
    href="../misc/security_tips.html#serverroot">seguridad</a>.</p>

    <note><title>Nota</title>
      <p>A partir de Apache HTTP Server 2, se recomienda usar únicamente el script <program>
      apachectl</program>, o el script de inicio que proporcione su sistema operativo,
      para (re)iniciar o detener el servidor.</p>
    </note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>Listen</name>
<description>Direcciones IP y puertos en los que escucha el
servidor</description>
<syntax>Listen [<var>IP-address</var>:]<var>portnumber</var> [<var>protocol</var>] [options=<var>flag</var>[,<var>flag..</var>]]</syntax>
<contextlist><context>server config</context></contextlist>
<modulelist><module>event</module><module>worker</module>
<module>prefork</module><module>mpm_winnt</module>
<module>mpm_netware</module><module>mpmt_os2</module>
</modulelist>
<compatibility>El argumento opcional <code>options=</code> está disponible en httpd 2.5.1 y posteriores.</compatibility>

<usage>
    <p>La directiva <directive>Listen</directive> indica a Apache httpd que
    escuche solo direcciones IP o puertos concretos; por defecto, responde a
    peticiones en todas las interfaces IP. <directive>Listen</directive>
    es ahora una directiva obligatoria. Si no está en el archivo de configuración, el
    servidor no arrancará. Esto es un cambio respecto a versiones anteriores
    de Apache httpd.</p>

    <p>La directiva <directive>Listen</directive> indica al servidor que
    acepte peticiones entrantes en el puerto especificado, o en la combinación
    de dirección y puerto indicada. Si solo se especifica un número de puerto, el servidor escucha en
    el puerto dado en todas las interfaces. Si también se indica una dirección
    IP junto con el puerto, el servidor escuchará en el puerto y la
    interfaz indicados.</p>

    <p>Se pueden usar varias directivas <directive>Listen</directive> para
    especificar un número de direcciones y puertos en los que escuchar. El servidor
    responderá a peticiones de cualquiera de las direcciones y puertos indicados.</p>

    <p>Por ejemplo, para hacer que el servidor acepte conexiones tanto en el
    puerto 80 como en el puerto 8000, use:</p>

    <highlight language="config">
Listen 80
Listen 8000
    </highlight>

    <p>Para hacer que el servidor acepte conexiones en dos interfaces y
    números de puerto específicos, use</p>

    <highlight language="config">
Listen 192.170.2.1:80
Listen 192.170.2.5:8000
    </highlight>

    <p>Las direcciones IPv6 deben ir rodeadas de corchetes, como en el
    siguiente ejemplo:</p>

    <highlight language="config">
      Listen [2001:db8::a00:20ff:fea7:ccea]:80
    </highlight>

    <p>En httpd 2.5.1 y posteriores, si se compila con APR 1.7.0 o posterior,
    se aceptan direcciones IPv6 literales con ámbito (o "zoned") en la
    directiva <directive>Listen</directive>, como en el siguiente
    ejemplo.</p>

    <highlight language="config">
      Listen [fe80::4bfe:88aa:5d42:64d0%eth2]:8081
    </highlight>

    <p>El argumento opcional <var>protocol</var> no es necesario en la mayoría de
       configuraciones. Si no se especifica, <code>https</code> es el valor por defecto para
       el puerto 443 y <code>http</code> el valor por defecto para el resto de puertos. El
       protocolo se usa para determinar qué módulo debe gestionar una petición, y
       para aplicar optimizaciones específicas del protocolo con la directiva
       <directive module="core">AcceptFilter</directive>.</p>

    <p>Solo necesita establecer el protocolo si está usando puertos no estándar.
       Por ejemplo, para ejecutar un sitio <code>https</code> en el puerto 8443:</p>

    <highlight language="config">
      Listen 192.170.2.1:8443 https
    </highlight>

    <p>El argumento opcional <var>options=flag,flag...</var> puede
    usarse para activar determinadas opciones de socket en el puerto de escucha.
    Estas opciones no son necesarias en la mayoría de configuraciones y deben
    usarse con cuidado. La disponibilidad de cada opción varía según el
    sistema operativo. Los <em>flag</em>s disponibles son:</p>

    <ul>
      <li><code>freebind</code>: Se activa la opción de socket
      <code>IP_FREEBIND</code>, lo que permite usar una directiva Listen con una
      dirección que aún no está disponible en el sistema. (Solo en Linux)</li>

      <li><code>reuseport</code>: Se activa la opción de socket
      <code>SO_REUSEPORT</code>, lo que permite que una directiva Listen se vincule a un puerto
      que ya puede estar en uso por otro proceso.</li>

      <li><code>v6only</code>: Se activa la opción de socket
      <code>IPV6_V6ONLY</code>, lo que permite que una directiva Listen se vincule a una
      dirección IPv6 sin aceptar también conexiones vía IPv4, ni entrar en
      conflicto con una directiva Listen que use una dirección IPv4 vinculada
      al mismo puerto. (Si el servidor se compila con las direcciones mapeadas
      a IPv4 <em>desactivadas</em>, este es el comportamiento por defecto y
      esta opción no tiene efecto.)</li>

      <li><code>multipathtcp</code>: Activa el uso de
      <a href="https://mptcp.dev">Multipath TCP (MPTCP)</a> para los
      sockets. Tenga en cuenta que esta opción está actualmente limitada a
      Linux.
      </li>
    </ul>

    <note><title>Condición de error</title>
      Varias directivas <directive>Listen</directive> para la misma dirección IP
      y puerto darán como resultado un mensaje de error <code>Address already in use</code>
      (dirección ya en uso).
    </note>

</usage>
<seealso><a href="../dns-caveats.html">Problemas de DNS</a></seealso>
<seealso><a href="../bind.html">Configurar las direcciones y puertos que
    usa Apache HTTP Server</a></seealso>
<seealso><a
href="https://cwiki.apache.org/confluence/display/httpd/CouldNotBindToAddress">Más
información sobre el mensaje de error <code>Address already in use</code>,
incluidas otras causas.</a></seealso>
</directivesynopsis>

<directivesynopsis>
<name>ListenCoresBucketsRatio</name>
<description>Ratio entre el número de núcleos de CPU (en línea) y el número de
buckets de listeners</description>
<syntax>ListenCoresBucketsRatio <var>ratio</var></syntax>
<default>ListenCoresBucketsRatio 0 (desactivado)</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>event</module><module>worker</module>
<module>prefork</module>
</modulelist>
<compatibility>Disponible en Apache HTTP Server 2.4.17, con un kernel que soporte
la opción de socket <code>SO_REUSEPORT</code> y que distribuya las nuevas
conexiones de forma uniforme entre los sockets de los procesos (o hilos) de
escucha que la usan (p. ej. Linux 3.9 y posteriores, pero no las
implementaciones actuales de <code>SO_REUSEPORT</code> en los *BSD.</compatibility>

<usage>
    <p>Se puede usar un <var>ratio</var> entre el número de núcleos de CPU (en línea) y
    el número de buckets de listeners para hacer que Apache HTTP Server cree
    <code>num_cpu_cores / ratio</code> buckets de escucha, cada uno con su
    propio socket(s) de <directive module="mpm_common">Listen</directive> en el mismo
    puerto(s), y que a continuación cada hijo gestione un único bucket (con distribución
    round-robin de los buckets en el momento de crear los hijos).</p>

    <note><title>Significado de núcleo de CPU "en línea"</title>
    <p>En Linux (y también en BSD) se puede activar o desactivar un núcleo de CPU si
    está configurado <a href="https://www.kernel.org/doc/Documentation/cpu-hotplug.txt">Hotplug</a>,
    por lo que <directive>ListenCoresBucketsRatio</directive> necesita
    tener en cuenta este parámetro al calcular el número de buckets a crear.</p>
    </note>

    <p><directive>ListenCoresBucketsRatio</directive> puede mejorar la
    escalabilidad cuando aceptar nuevas conexiones es, o se convierte en, el cuello de botella.
    En sistemas con un gran número de núcleos de CPU, se ha comprobado que activar esta
    funcionalidad mejora de forma significativa el rendimiento y reduce los
    tiempos de respuesta.</p>

    <p>Debe haber al menos el doble de núcleos de CPU que el
    <var>ratio</var> configurado para que esto esté activo. El <var>ratio</var>
    recomendado es <code>8</code>, por lo que deben estar disponibles al menos
    <code>16</code> núcleos en tiempo de ejecución cuando se use este valor.
    El <var>ratio</var> adecuado para obtener el máximo rendimiento debe calcularse
    para cada sistema concreto, probando varios valores y observando las variaciones en sus
    métricas de rendimiento clave.</p>

    <p>Esta directiva influye en el cálculo de los valores mínimos de
    <directive module="mpm_common">MinSpareThreads</directive> y
    <directive module="mpm_common">MaxSpareThreads</directive>.
    El número de procesos hijo debe ser múltiplo del número
    de buckets para aceptar conexiones de forma óptima.</p>

    <note>
    <title>Varios <directive>Listen</directive>ers o servidores Apache HTTP en
    la misma dirección IP y puerto</title>
    <p>Establecer la opción <code>SO_REUSEPORT</code> en el socket(s) de escucha
    permite, en consecuencia, que varios procesos (que comparten el mismo <code>EUID</code>,
    p. ej. <code>root</code>) se vinculen a la misma dirección IP y puerto,
    sin el error de vinculación que el sistema lanzaría habitualmente.</p>
    <p>Esto también significa que varias instancias de Apache httpd configuradas en la
    misma <code>IP:puerto</code> y con un <directive>ListenCoresBucketsRatio</directive>
    positivo arrancarían también sin error, y luego funcionarían con las conexiones entrantes
    distribuidas de forma uniforme entre ambas instancias (esto NO es una recomendación ni
    un uso sensato en ningún caso, sino solo un aviso de que esto evitaría detectar
    posibles problemas de este tipo).</p>
    <p>Dentro de la misma instancia, Apache httpd comprobará y fallará al arrancar si
    hay configuradas varias directivas <directive>Listen</directive> exactamente en la misma IP (o
    nombre de host) y puerto, evitando así la creación de buckets
    duplicados que serían inútiles y perjudicarían el rendimiento. Sin embargo,
    no puede (ni intentará con más esfuerzo) detectar todos los posibles casos de solapamiento
    (como un nombre de host que resuelve a una IP usada en otro lugar).</p>
    </note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ListenBackLog</name>
<description>Longitud máxima de la cola de conexiones pendientes</description>
<syntax>ListenBackLog <var>backlog</var></syntax>
<default>ListenBackLog 511</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>event</module><module>worker</module>
<module>prefork</module><module>mpm_winnt</module>
<module>mpm_netware</module><module>mpmt_os2</module>
</modulelist>

<usage>
    <p>La longitud máxima de la cola de conexiones pendientes.
    Por lo general no es necesario ni deseable ajustar esto; sin embargo, en algunos
    sistemas es conveniente aumentarlo cuando se sufre un ataque de
    inundación TCP SYN. Vea el parámetro backlog de la llamada al sistema
    <code>listen(2)</code>.</p>

    <p>A menudo, el sistema operativo limitará esto a un número menor.
    Esto varía de un sistema operativo a otro. Tenga en cuenta además que
    muchos sistemas operativos no usan exactamente el valor especificado como backlog,
    sino un número basado en él (pero normalmente mayor) que el
    establecido.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ListenTCPDeferAccept</name>
<description>Valor establecido para la opción de socket TCP_DEFER_ACCEPT, si está activada</description>
<syntax>ListenTCPDeferAccept <var>integer</var></syntax>
<default>ListenTCPDeferAccept 30</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>event</module><module>worker</module>
<module>prefork</module>
</modulelist>
<compatibility>Disponible en Apache HTTP Server 2.5.1 y posteriores</compatibility>

<usage>
    <p>El valor especificado aquí se establece como valor para la opción de socket
    <code>TCP_DEFER_ACCEPT</code> si está activada en el socket de escucha.
    Esto ocurre al ejecutarse en Linux y cuando <directive
    module="core">AcceptFilter</directive> está establecido a cualquier valor distinto de
    <code>none</code>. En cualquier otro caso, este valor se ignora.
    Para más detalles, consulte la página de manual de Linux
    <a href="http://man7.org/linux/man-pages/man7/tcp.7.html">
    tcp(7)</a>.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>MaxRequestWorkers</name>
<description>Número máximo de conexiones que se procesarán
simultáneamente</description>
<syntax>MaxRequestWorkers <var>number</var></syntax>
<default>Vea el uso para más detalles</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>event</module><module>worker</module>
<module>prefork</module>
</modulelist>

<usage>
    <p>La directiva <directive>MaxRequestWorkers</directive> establece el límite
    en el número de peticiones simultáneas que se atenderán. Cualquier
    intento de conexión que supere el límite de <directive>MaxRequestWorkers</directive>
    normalmente se encolará, hasta un número basado en la directiva
    <directive module="mpm_common">ListenBacklog</directive>.
    Una vez que un proceso hijo queda libre al finalizar otra
    petición, la conexión se atenderá.</p>

    <p>Para servidores sin hilos (<em>i.e.</em>, <module>prefork</module>),
    <directive>MaxRequestWorkers</directive> se traduce en el número
    máximo de procesos hijo que se lanzarán para atender peticiones.
    El valor por defecto es <code>256</code>; para aumentarlo, también debe elevar
    <directive module="mpm_common">ServerLimit</directive>.</p>

    <p>Para servidores con hilos e híbridos (<em>e.g.</em> <module>event</module>
    o <module>worker</module>), <directive>MaxRequestWorkers</directive> restringe
    el número total de hilos disponibles para atender clientes.
    Para los MPM con hilos e híbridos, el valor por defecto es <code>16</code> (<directive
    module="mpm_common">ServerLimit</directive>) multiplicado por el valor de
    <code>25</code> (<directive module="mpm_common"
    >ThreadsPerChild</directive>). Por lo tanto, para aumentar <directive
    >MaxRequestWorkers</directive> a un valor que requiera más de 16 procesos,
    también debe elevar <directive module="mpm_common"
    >ServerLimit</directive>.</p>

    <p>Para los MPM con hilos e híbridos, <directive>MaxRequestWorkers</directive>
    debe ser al menos tan grande como
    <directive module="mpm_common">ThreadsPerChild</directive>, y
    debería ser un múltiplo entero de
    <directive module="mpm_common">ThreadsPerChild</directive>. Si no
    lo es, el servidor lo redondeará hacia abajo al múltiplo más cercano al
    arrancar y registrará una advertencia.</p>

    <example><title>Advertencia: MaxRequestWorkers demasiado bajo</title>
    WARNING: MaxRequestWorkers of 10 is less than ThreadsPerChild
    of 25, increasing to 25. MaxRequestWorkers must be at least as
    large as the number of threads in a single server.
    </example>

    <example><title>Advertencia: MaxRequestWorkers no es múltiplo de ThreadsPerChild</title>
    WARNING: MaxRequestWorkers of 90 is not an integer multiple of
    ThreadsPerChild of 25, decreasing to nearest multiple 75, for a
    maximum of 3 servers.
    </example>

    <p><directive>MaxRequestWorkers</directive> se llamaba
    <directive>MaxClients</directive> antes de la versión 2.3.13. El nombre antiguo sigue
    siendo compatible.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>MaxMemFree</name>
<description>Cantidad máxima de memoria que el asignador principal puede
mantener sin llamar a <code>free()</code></description>
<syntax>MaxMemFree <var>KBytes</var></syntax>
<default>MaxMemFree 2048</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>event</module><module>worker</module>
<module>prefork</module><module>mpm_winnt</module>
<module>mpm_netware</module>
</modulelist>

<usage>
    <p>La directiva <directive>MaxMemFree</directive> establece el
    número máximo de KBytes libres que cada asignador puede mantener
    sin llamar a <code>free()</code>. En los MPM con hilos, cada
    hilo tiene su propio asignador. Cuando se establece
    a cero, el límite se considera ilimitado.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>MaxConnectionsPerChild</name>
<description>Límite en el número de conexiones que un proceso hijo
atenderá durante su vida</description>
<syntax>MaxConnectionsPerChild <var>number</var></syntax>
<default>MaxConnectionsPerChild 0</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>event</module><module>worker</module>
<module>prefork</module><module>mpm_winnt</module>
<module>mpm_netware</module><module>mpmt_os2</module>
</modulelist>
<compatibility>Disponible en Apache HTTP Server 2.3.9 y posteriores. El nombre antiguo
<code>MaxRequestsPerChild</code> sigue siendo compatible.</compatibility>

<usage>
    <p>La directiva <directive>MaxConnectionsPerChild</directive> establece
    el límite en el número de conexiones que un proceso hijo
    atenderá. Tras
    <directive>MaxConnectionsPerChild</directive> conexiones, el proceso
    hijo terminará. Si <directive>MaxConnectionsPerChild</directive> es
    <code>0</code>, el proceso nunca expirará.</p>

    <p>Establecer <directive>MaxConnectionsPerChild</directive> a un valor
    distinto de cero limita la cantidad de memoria que un proceso puede consumir
    por fugas de memoria (accidentales).</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>MaxSpareThreads</name>
<description>Número máximo de hilos inactivos</description>
<syntax>MaxSpareThreads <var>number</var></syntax>
<default>Vea el uso para más detalles</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>event</module><module>worker</module>
<module>mpm_netware</module><module>mpmt_os2</module>
</modulelist>

<usage>
    <p>Número máximo de hilos inactivos. Los distintos MPM tratan esta
    directiva de forma diferente.</p>

    <p>Para <module>worker</module> y <module>event</module>, el valor por defecto es
    <code>MaxSpareThreads 250</code>. Estos MPM gestionan los hilos inactivos
    a nivel de todo el servidor. Si hay demasiados hilos inactivos en el
    servidor, se eliminan procesos hijo hasta que el número de hilos
    inactivos sea menor que este número. Pueden crearse procesos/hilos
    adicionales si <directive module="mpm_common">ListenCoresBucketsRatio</directive>
    está activado.</p>

    <p>Para <module>mpm_netware</module> el valor por defecto es
    <code>MaxSpareThreads 100</code>. Como este MPM ejecuta un único
    proceso, el recuento de hilos inactivos también es a nivel de todo el servidor.</p>

    <p><module>mpmt_os2</module> funciona de forma
    similar a <module>mpm_netware</module>. Para
    <module>mpmt_os2</module> el valor por defecto es <code>10</code>.</p>

    <note><title>Restricciones</title>
      <p>El rango del valor de <directive>MaxSpareThreads</directive>
      está restringido. Apache httpd corregirá automáticamente el valor indicado
      según las siguientes reglas:</p>
      <ul>
        <li><module>mpm_netware</module> requiere que el valor sea mayor que
        <directive module="mpm_common">MinSpareThreads</directive>.</li>

        <li>Para <module>worker</module> y <module>event</module>, el valor
        debe ser mayor o igual que la suma de <directive module="mpm_common">
        MinSpareThreads</directive> y <directive module="mpm_common">
	ThreadsPerChild</directive>.</li>
      </ul>
    </note>
</usage>
<seealso><directive module="mpm_common">MinSpareThreads</directive></seealso>
<seealso><directive module="mpm_common">StartServers</directive></seealso>
<seealso><directive module="prefork">MaxSpareServers</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>MinSpareThreads</name>
<description>Número mínimo de hilos inactivos disponibles para gestionar
picos de peticiones</description>
<syntax>MinSpareThreads <var>number</var></syntax>
<default>Vea el uso para más detalles</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>event</module><module>worker</module>
<module>mpm_netware</module><module>mpmt_os2</module>
</modulelist>

<usage>
    <p>Número mínimo de hilos inactivos para gestionar picos de peticiones.
    Los distintos MPM tratan esta directiva de forma diferente.</p>

    <p><module>worker</module> y <module>event</module> usan un valor por defecto de
    <code>MinSpareThreads 75</code> y gestionan los hilos inactivos a nivel de todo el
    servidor. Si no hay suficientes hilos inactivos en el servidor, se crean procesos
    hijo hasta que el número de hilos inactivos sea mayor
    que <var>number</var>. Pueden crearse procesos/hilos
    adicionales si <directive module="mpm_common">ListenCoresBucketsRatio</directive>
    está activado.</p>

    <p><module>mpm_netware</module> usa un valor por defecto de
    <code>MinSpareThreads 10</code> y, al ser un MPM de un único
    proceso, lo registra a nivel de todo el servidor.</p>

    <p><module>mpmt_os2</module> funciona de forma
    similar a <module>mpm_netware</module>. Para
    <module>mpmt_os2</module> el valor por defecto es <code>5</code>.</p>

    <p>El valor de <directive>MinSpareThreads</directive> debe ser al
    menos 1. Los valores menores que 1 se aumentarán automáticamente a 1
    y se registrará una advertencia.</p>
</usage>
<seealso><directive module="mpm_common">MaxSpareThreads</directive></seealso>
<seealso><directive module="mpm_common">StartServers</directive></seealso>
<seealso><directive module="prefork">MinSpareServers</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>ScoreBoardFile</name>
<description>Ubicación del archivo usado para almacenar los datos de
coordinación de los procesos hijo</description>
<syntax>ScoreBoardFile <var>file-path</var></syntax>
<default>ScoreBoardFile apache_runtime_status</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>event</module><module>worker</module>
<module>prefork</module><module>mpm_winnt</module>
</modulelist>

<usage>
    <p>Apache HTTP Server usa un scoreboard para comunicarse entre su proceso
    padre y sus procesos hijo. Algunas arquitecturas necesitan un archivo para facilitar
    esta comunicación. Si no se especifica el archivo, Apache httpd primero
    intenta crear el scoreboard completamente en memoria (usando memoria
    compartida anónima) y, si eso falla, intentará crear el archivo en
    disco (usando memoria compartida basada en archivo). Especificar esta directiva hace
    que Apache httpd cree siempre el archivo en disco.</p>

    <p>Si <var>file-path</var> no es una ruta absoluta, la ubicación especificada
    será relativa al valor de
    <directive module="core">DefaultRuntimeDir</directive>.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
      ScoreBoardFile /var/run/apache_runtime_status
      </highlight>
    </example>

    <p>La memoria compartida basada en archivo es útil para aplicaciones de
    terceros que necesitan acceso directo al scoreboard.</p>

    <p>Si usa un <directive>ScoreBoardFile</directive>, puede
    obtener mejor velocidad colocándolo en un disco RAM. Pero tenga
    cuidado de atender las mismas advertencias sobre la ubicación de archivos de registro
    y <a href="../misc/security_tips.html">seguridad</a>.</p>
</usage>
<seealso><a href="../stopping.html">Detener y reiniciar
Apache HTTP Server</a></seealso>
</directivesynopsis>

<directivesynopsis>
<name>ReceiveBufferSize</name>
<description>Tamaño del búfer de recepción TCP</description>
<syntax>ReceiveBufferSize <var>bytes</var></syntax>
<default>ReceiveBufferSize 0</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>event</module><module>worker</module>
<module>prefork</module><module>mpm_winnt</module>
<module>mpm_netware</module><module>mpmt_os2</module>
</modulelist>

<usage>
    <p>El servidor establecerá el tamaño del búfer de recepción TCP al número de
    bytes especificado.</p>

    <p>Si se establece al valor <code>0</code>, el servidor usará el
    valor por defecto del SO. Si se establece a un valor distinto de cero, debe ser al menos
    <code>512</code>.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SendBufferSize</name>
<description>Tamaño del búfer TCP</description>
<syntax>SendBufferSize <var>bytes</var></syntax>
<default>SendBufferSize 0</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>event</module><module>worker</module>
<module>prefork</module><module>mpm_winnt</module>
<module>mpm_netware</module><module>mpmt_os2</module>
</modulelist>

<usage>
    <p>Establece el tamaño del búfer de envío TCP del servidor al número de bytes
    especificado. A menudo es útil establecerlo por encima del valor por defecto
    estándar del SO en conexiones de alta velocidad y alta latencia
    (<em>i.e.</em>, de unos 100ms, como las líneas transcontinentales rápidas).</p>

    <p>Si se establece al valor <code>0</code>, el servidor usará el
    valor por defecto proporcionado por su SO. Si se establece a un valor distinto de cero,
    debe ser al menos <code>512</code>.</p>

    <p>Puede ser necesario configurar más a fondo su sistema operativo para obtener
    mejor rendimiento en conexiones de alta velocidad y alta latencia.</p>

    <note> <p> En algunos sistemas operativos, los cambios en el comportamiento TCP resultantes
    de un <directive>SendBufferSize</directive> mayor pueden no apreciarse a menos que
    <directive module="core">EnableSendfile</directive> esté establecido a OFF. Esta
    interacción se aplica solo a archivos estáticos.</p> </note>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>ServerLimit</name>
<description>Límite superior en el número configurable de procesos</description>
<syntax>ServerLimit <var>number</var></syntax>
<default>Vea el uso para más detalles</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>event</module><module>worker</module>
<module>prefork</module><module>motorz</module>
</modulelist>

<usage>
    <p>Para el MPM <module>motorz</module>, esta directiva establece el número de
    slots de proceso, que debe cubrir <directive
    module="mpm_common">StartServers</directive> más los procesos antiguos que
    siguen terminando conexiones tras un reinicio ordenado; por defecto es el mayor
    de 16 y el doble de
    <directive module="mpm_common">StartServers</directive>.</p>

    <p>Para el MPM <module>prefork</module>, esta directiva establece el
    valor máximo configurado para <directive
    module="mpm_common">MaxRequestWorkers</directive> durante la vida del
    proceso Apache httpd. Para los MPM <module>worker</module> y <module>event
    </module>, esta directiva, combinada con <directive
    module="mpm_common">ThreadLimit</directive>, establece
    el valor máximo configurado para <directive
    module="mpm_common">MaxRequestWorkers</directive> durante la vida del
    proceso Apache httpd. Para el MPM <module>event</module>, esta directiva
    también define cuántos procesos de servidor antiguos pueden seguir ejecutándose y terminar de
    procesar las conexiones abiertas.
    Cualquier intento de cambiar esta directiva durante un reinicio se ignorará, pero
    <directive module="mpm_common">MaxRequestWorkers</directive> puede modificarse
    durante un reinicio.</p>

    <p>Hay que tener especial cuidado al usar esta directiva. Si
    <directive>ServerLimit</directive> se establece a un valor mucho más alto
    de lo necesario, se asignará memoria compartida adicional sin usar. Si
    tanto <directive>ServerLimit</directive> como <directive
    module="mpm_common">MaxRequestWorkers</directive> se establecen a valores
    más altos de los que el sistema puede gestionar, Apache httpd puede no arrancar o el
    sistema puede volverse inestable.</p>

    <p>Con el MPM <module>prefork</module>, use esta directiva solo
    si necesita establecer <directive
    module="mpm_common">MaxRequestWorkers</directive> por encima de 256 (valor por defecto).
    No establezca el valor de esta directiva más alto de lo que
    pueda querer establecer para <directive
    module="mpm_common">MaxRequestWorkers</directive>.</p>

    <p>Con <module>worker</module>, use esta directiva solo si sus
    valores de <directive module="mpm_common">MaxRequestWorkers
    </directive> y <directive module="mpm_common">ThreadsPerChild</directive>
    requieren más de 16 procesos de servidor (valor por defecto). No establezca
    el valor de esta directiva más alto que el número de procesos de servidor
    requeridos por lo que pueda querer para <directive
    module="mpm_common">MaxRequestWorkers </directive> y <directive
    module="mpm_common">ThreadsPerChild</directive>.</p>

    <p>Con <module>event</module>, aumente esta directiva si el número de
    procesos definido por sus valores de <directive
    module="mpm_common">MaxRequestWorkers</directive> y <directive
    module="mpm_common">ThreadsPerChild</directive>, más el
    número de procesos en proceso de cierre ordenado, es mayor de 16 procesos de
    servidor (valor por defecto).</p>

    <note><title>Nota</title>
      <p>Hay un límite estricto de <code>ServerLimit 20000</code> incorporado
      en el servidor (para el MPM <module>prefork</module>, 200000). Esto está
      pensado para evitar efectos indeseados causados por errores de tecleo. Para aumentarlo
      aún más allá de este límite, deberá modificar el valor de
      MAX_SERVER_LIMIT en el archivo fuente del mpm y recompilar el servidor.</p>
    </note>

    <p>El valor de <directive>ServerLimit</directive> debe ser al menos
    1. Los valores menores que 1 se aumentarán automáticamente a 1 y se
    registrará una advertencia.</p>
</usage>
<seealso><a href="../stopping.html">Detener y reiniciar Apache HTTP Server</a></seealso>
</directivesynopsis>

<directivesynopsis>
<name>StartServers</name>
<description>Número de procesos de servidor hijo creados al arrancar</description>
<syntax>StartServers <var>number</var></syntax>
<default>Vea el uso para más detalles</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>event</module><module>worker</module>
<module>prefork</module><module>mpmt_os2</module>
</modulelist>

<usage>
    <p>La directiva <directive>StartServers</directive> establece el
    número de procesos de servidor hijo creados al arrancar. Como el número
    de procesos se controla dinámicamente según la carga (vea
    <directive module="mpm_common">MinSpareThreads</directive>,
    <directive module="mpm_common">MaxSpareThreads</directive>,
    <directive module="prefork">MinSpareServers</directive>, <directive
    module="prefork">MaxSpareServers</directive>),
    normalmente hay poca razón para ajustar este parámetro.</p>

    <p>El valor por defecto difiere de un MPM a otro. <module>worker</module> y
    <module>event</module> usan por defecto <code>StartServers 3</code>; <module>
    prefork</module> usa por defecto <code>5</code>; <module>mpmt_os2</module>
    usa por defecto <code>2</code>.</p>

    <p>El valor de <directive>StartServers</directive> debe ser al menos
    1. Los valores menores que 1 se aumentarán automáticamente a 1 y se
    registrará una advertencia. En <module>mpmt_os2</module>, también se
    acepta un valor de 0; los valores menores que 0 se aumentarán a 1.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>StartThreads</name>
<description>Número de hilos creados al arrancar</description>
<syntax>StartThreads <var>number</var></syntax>
<default>Vea el uso para más detalles</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>mpm_netware</module></modulelist>

<usage>
    <p>Número de hilos creados al arrancar. Como el
    número de hilos se controla dinámicamente según la
    carga (vea
    <directive module="mpm_common">MinSpareThreads</directive>,
    <directive module="mpm_common">MaxSpareThreads</directive>,
    <directive module="prefork">MinSpareServers</directive>, <directive
    module="prefork">MaxSpareServers</directive>),
    normalmente hay poca razón para ajustar este
    parámetro.</p>

    <p>Para <module>mpm_netware</module> el valor por defecto es
    <code>StartThreads 50</code> y, al existir un único
    proceso, este es el número total de hilos creados al arrancar para
    atender peticiones.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ThreadLimit</name>
<description>Establece el límite superior en el número configurable de hilos
por proceso hijo</description>
<syntax>ThreadLimit <var>number</var></syntax>
<default>Vea el uso para más detalles</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>event</module><module>worker</module>
<module>mpm_winnt</module>
</modulelist>

<usage>
    <p>Esta directiva establece el valor máximo configurado para <directive
    module="mpm_common">ThreadsPerChild</directive> durante la vida
    del proceso Apache httpd. Cualquier intento de cambiar esta directiva
    durante un reinicio se ignorará, pero <directive
    module="mpm_common">ThreadsPerChild</directive> puede modificarse
    durante un reinicio hasta el valor de esta directiva.</p>

    <p>Hay que tener especial cuidado al usar esta directiva. Si
    <directive>ThreadLimit</directive> se establece a un valor mucho más alto
    que <directive module="mpm_common">ThreadsPerChild</directive>,
    se asignará memoria compartida adicional sin usar. Si tanto
    <directive>ThreadLimit</directive> como <directive
    module="mpm_common">ThreadsPerChild</directive> se establecen a valores
    más altos de los que el sistema puede gestionar, Apache httpd puede no arrancar o el
    sistema puede volverse inestable. No establezca el valor de esta directiva
    más alto que el valor más alto que prevea establecer para <directive
    module="mpm_common">ThreadsPerChild</directive> en la
    ejecución actual de Apache httpd.</p>

    <p>El valor por defecto de <directive>ThreadLimit</directive> es
    <code>1920</code> cuando se usa con <module>mpm_winnt</module> y
    <code>64</code> cuando se usa con los demás.</p>

    <note><title>Nota</title>
      <p>Hay un límite estricto de <code>ThreadLimit 20000</code> (o
      <code>ThreadLimit 100000</code> con <module>event</module>,
      <code>ThreadLimit 15000</code> con <module>mpm_winnt</module>)
      incorporado en el servidor. Esto está pensado para evitar efectos indeseados
      causados por errores de tecleo. Para aumentarlo aún más allá de este límite,
      deberá modificar el valor de MAX_THREAD_LIMIT en el archivo fuente del mpm
      y recompilar el servidor.</p>
    </note>

    <p>El valor de <directive>ThreadLimit</directive> debe ser al menos
    1. Los valores menores que 1 se aumentarán automáticamente a 1 y se
    registrará una advertencia.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ThreadsPerChild</name>
<description>Número de hilos creados por cada proceso hijo</description>
<syntax>ThreadsPerChild <var>number</var></syntax>
<default>Vea el uso para más detalles</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>event</module><module>worker</module>
<module>mpm_winnt</module>
</modulelist>

<usage>
    <p>Esta directiva establece el número de hilos creados por cada
    proceso hijo. El hijo crea estos hilos al arrancar y
    nunca crea más. Si se usa un MPM como <module>mpm_winnt</module>,
    donde solo hay un proceso hijo, este número debería ser lo bastante alto
    como para gestionar toda la carga del servidor. Si se usa un MPM
    como <module>worker</module>, donde hay varios procesos hijo,
    el número <em>total</em> de hilos debería ser lo bastante alto para gestionar
    la carga habitual del servidor.</p>

    <p>El valor por defecto de <directive>ThreadsPerChild</directive> es
    <code>64</code> cuando se usa con <module>mpm_winnt</module> y
    <code>25</code> cuando se usa con los demás.</p>

    <p>El valor de <directive>ThreadsPerChild</directive> no puede superar el
    valor de <directive module="mpm_common">ThreadLimit</directive>. Si se configura
    un valor más alto, se reducirá automáticamente al arrancar
    y se registrará una advertencia. La relación entre estas 2 directivas
    se explica en <directive module="mpm_common">ThreadLimit</directive>.</p>

    <p>El valor de <directive>ThreadsPerChild</directive> debe ser al
    menos 1. Los valores menores que 1 se aumentarán automáticamente a 1
    y se registrará una advertencia.</p>

    <p>El valor de <directive module="mpm_common">MaxRequestWorkers</directive>
    debe ser un múltiplo entero de <directive>ThreadsPerChild</directive>.
    Vea <directive module="mpm_common">MaxRequestWorkers</directive> para más
    detalles.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ThreadStackSize</name>
<description>El tamaño en bytes de la pila usada por los hilos que gestionan
las conexiones de los clientes</description>
<syntax>ThreadStackSize <var>size</var></syntax>
<default>65536 en NetWare; varía en otros sistemas operativos</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>event</module><module>worker</module>
<module>mpm_winnt</module><module>mpm_netware</module>
<module>mpmt_os2</module>
</modulelist>

<usage>
    <p>La directiva <directive>ThreadStackSize</directive> establece el
    tamaño de la pila (para datos automáticos) de los hilos que gestionan las
    conexiones de clientes e invocan a los módulos que ayudan a procesar esas conexiones.
    En la mayoría de los casos, el tamaño de pila por defecto del sistema operativo es
    razonable, pero hay algunas condiciones en las que puede ser necesario
    ajustarlo:</p>

    <ul>
      <li>En plataformas con un tamaño de pila de hilo por defecto relativamente pequeño
      (p. ej., HP-UX), Apache httpd puede fallar al usar algunos módulos de terceros
      que usan una cantidad relativamente grande de almacenamiento de datos automáticos. Esos
      mismos módulos pueden haber funcionado bien en otras plataformas donde el
      tamaño de pila por defecto es mayor. Este tipo de fallo se
      resuelve estableciendo <directive>ThreadStackSize</directive> a un
      valor más alto que el valor por defecto del sistema operativo. Este tipo de
      ajuste solo es necesario si el proveedor del módulo de terceros
      especifica que es necesario, o si el diagnóstico de un fallo de Apache httpd
      indica que el tamaño de pila del hilo era demasiado pequeño.</li>

      <li>En plataformas donde el tamaño de pila de hilo por defecto es
      significativamente mayor de lo necesario para la configuración
      del servidor web, se podrá alcanzar un mayor número de hilos por
      proceso hijo si se establece <directive>ThreadStackSize</directive>
      a un valor menor que el valor por defecto del sistema operativo. Este tipo
      de ajuste solo debería hacerse en un entorno de pruebas que permita
      ejercitar todo el procesamiento del servidor web, ya que puede
      haber peticiones poco frecuentes que requieran más pila para procesarse.
      El tamaño mínimo de pila necesario depende en gran medida de los módulos
      usados, pero cualquier cambio en la configuración del servidor web puede invalidar
      la configuración actual de <directive>ThreadStackSize</directive>.</li>

      <li>En Linux, esta directiva solo puede usarse para aumentar el tamaño de pila
      por defecto, ya que la llamada al sistema subyacente usa el valor como un
      tamaño de pila <em>mínimo</em>. El límite flexible (a menudo grande) para
      <code>ulimit -s</code> (8MB si es ilimitado) se usa como tamaño de pila
      por defecto.</li>
    </ul>

    <note>Se recomienda no reducir <directive>ThreadStackSize</directive>
    salvo que se necesite un número alto de hilos por proceso hijo. En algunas
    plataformas (incluyendo Linux), un valor de 128000 ya es demasiado bajo y
    provoca fallos con algunos módulos comunes.</note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AcceptErrorsNonFatal</name>
<description>Trata algunos errores al aceptar una nueva conexión como no fatales
para el proceso httpd.</description>
<syntax>AcceptErrorsNonFatal ON</syntax>
<default>OFF (ECONNREFUSED, ECONNABORTED, ECONNRESET provocan la salida del
         proceso)</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>event</module><module>worker</module>
<module>prefork</module>
</modulelist>
<compatibility>2.5.1 y posteriores</compatibility>

<usage>
    <p><directive>AcceptErrorsNonFatal</directive> altera el comportamiento del
    servidor ante algunos errores poco frecuentes que pueden ocurrir al aceptar una nueva
    conexión de cliente. Por defecto, el proceso hijo que gestiona una petición
    saldrá de forma ordenada cuando ocurra casi cualquier error de socket durante la
    llamada al sistema accept(). Esto es para garantizar que un proceso hijo
    potencialmente inestable no intente aceptar más conexiones nuevas.</p>

    <p>Con <directive>AcceptErrorsNonFatal</directive> establecido a "ON",
    el proceso <em>no</em> empezará a terminar si el error de accept() es
    ECONNREFUSED, ECONNABORTED o ECONNRESET.</p>

    <note>Algunos componentes de software de cortafuegos de terceros pueden inyectar errores
    en el procesamiento de accept(), usando códigos de retorno no especificados por el
    sistema operativo.</note>
</usage>
</directivesynopsis>

</modulesynopsis>
