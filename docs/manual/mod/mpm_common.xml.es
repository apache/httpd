<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 328032:421174 (outdated) -->

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
<description>Es una colecci&#243;n de directivas que est&#225;n implementadas
en m&#225;s de un m&#243;dulo de multiprocesamiento (MPM)</description>
<status>MPM</status>

<directivesynopsis>
<name>AcceptMutex</name>
<description>M&#233;todo que usa Apache para serializar m&#250;ltiples procesos
hijo que aceptan peticiones en las conexiones de red</description>
<syntax>AcceptMutex Default|<var>method</var></syntax>
<default>AcceptMutex Default</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>leader</module><module>perchild</module>
<module>prefork</module><module>threadpool</module><module>worker</module>
</modulelist>

<usage>
    <p>Las directivas <directive>AcceptMutex</directive> determinan el
    m&#233;todo que usa Apache para serializar m&#250;ltiples procesos
    hijo que aceptan peticiones en las conexiones de red. En las
    versiones de Apache anteriores a la 2.0, el m&#233;todo era
    seleccionable solo cuando se compilaba el servidor. El mejor
    m&#233;todo a usar depende mucho de la arquitectura y de la
    plataforma que use. Si desea m&#225;s informaci&#243;n, consulte
    la documentanci&#243;n sobre <a
    href="../misc/perf-tuning.html">ajustes para conseguir un mejor
    rendimiento</a>.</p>

    <p>Si el valor especificado en esta directiva es
    <code>Default</code>, entonces se usar&#225; el m&#233;todo
    seleccionado cuando se compil&#243; el servidor. M&#225;s abajo
    puede encontrar una lista con otros m&#233;todos. Tenga en cuenta
    que no todos los m&#233;todos est&#225;n disponibles en todas las
    plataformas. Si el m&#233;todo especificado no est&#225;
    disponible, se escribir&#225; un mensaje en el log de errores con
    una lista de los m&#233;todos que puede usar.</p>

    <dl>
      <dt><code>flock</code></dt> <dd>usa la llamada al sistema
      <code>flock(2)</code> para bloquear el fichero especificado en
      la directiva <directive module="mpm_common"
      >LockFile</directive>.</dd>

      <dt><code>fcntl</code></dt> <dd>usa la llamada al sistema
      <code>fcntl(2)</code> para bloquear el fichero especificado en
      la directiva <directive module="mpm_common"
      >LockFile</directive>.</dd>

      <dt><code>posixsem</code></dt> <dd>usa sem&#225;foros
      compatibles con POSIX para implementar el mutex.</dd>

      <dt><code>pthread</code></dt>
      <dd>Usa mutexes POSIX implementados seg&#250;n la
      especificaci&#243;n de hebras POSIX (PThreads).</dd>

      <dt><code>sysvsem</code></dt>
      <dd>usa sem&#225;foros de tipo SySV para implementar el mutex.</dd>
    </dl>

    <p>Si quiere ver cu&#225;l es el m&#233;todo por defecto que se
    seleccion&#243; para usar en su sistema al compilar, especifique
    el valor <code>debug</code> en la directiva <directive
    module="core">LogLevel</directive>. El valor por defecto de la
    directiva <directive >AcceptMutex</directive> aparecer&#225;
    escrito en el <directive module="core">ErrorLog</directive>.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>BS2000Account</name>
<description>Define la cuenta sin privilegios en m&#225;quinas
BS2000</description>
<syntax>BS2000Account <var>account</var></syntax>
<contextlist><context>server config</context></contextlist>
<modulelist><module>perchild</module><module>prefork</module></modulelist>
<compatibility>Solo disponible en m&#225;quinas BS2000</compatibility>

<usage>
    <p>La directiva <directive>BS2000Account</directive> est&#225;
    disponible solo en hosts BS2000. Debe usarse para definir el
    n&#250;mero de cuenta del usuario sin privilegios del servidor
    Apache (que se configur&#243; usando la directiva <directive
    module="mpm_common">User</directive>). Esto es un requerimiento
    del subsistema POSIX BS2000 (@@@@@ para reemplazar el entorno de
    tareas BS2000 subyaciente haciendo un sub-LOGON) para prevenir que
    scripts CGI accedan a recursos de la cuenta con privilegios con la
    que se suele iniciar el servidor, normalmente
    <code>SYSROOT</code>.</p>

    <note><title>Nota</title> 
      <p>La directiva
      <code>BS2000Account</code> solamente puede usarse una vez.</p>
    </note>
</usage>
<seealso><a href="../platform/ebcdic.html">Apache EBCDIC port</a></seealso>
</directivesynopsis>

<directivesynopsis>
<name>CoreDumpDirectory</name>
<description>Directorio al que Apache intenta cambiarse antes de
realizar un volcado de memoria</description>
<syntax>CoreDumpDirectory <var>directory</var></syntax>
<default>Consulte la secci&#243;n de uso para ver el valor por defecto</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>beos</module><module>leader</module>
<module>mpm_winnt</module><module>perchild</module><module>prefork</module>
<module>threadpool</module><module>worker</module></modulelist>

<usage>
    <p>Esta directiva controla el directorio al cual intenta cambiarse
    Apache antes de realizar un volcado de memoria. Por defecto, el
    volcado de memoria se hace en el directorio especificado en la
    directiva <directive module="core">ServerRoot</directive>, sin
    embargo, como el usuario con el que se est&#225; ejecutando Apache
    podr&#237;a no tener permisos para escribir en ese directorio, los
    volcados de memoria muchas veces no se hacen en ning&#250;n
    sitio. Si quiere que el volcado se memoria se guarde para analizar
    los fallos posteriormente, puede usar esta directiva para
    especificar un directorio diferente.</p>

    <note><title>Volcados de memoria en Linux</title> <p>Si Apache se
      inicia como usuario root y despu&#233;s se cambia el usuario con
      el se est&#225; ejecutando, el kernel de Linux
      <em>desactiva</em> los volcados de memoria, incluso si se ha
      especificado un directorio en el que se puede escribir para
      realizar este proceso. Apache (en las versiones 2.0.46 y
      posteriores) reactiva los volcados de memoria en los sistemas
      con versiones Linux 2.4 y posteriores, pero solamente si se ha
      configurado expl&#237;citamente la directiva
      <directive>CoreDumpDirectory</directive>.</p>
    </note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>EnableExceptionHook</name>
<description>Activa un hook que inicia handlers de excepci&#243;n
despu&#233;s de un error irrecuperable</description>
<syntax>EnableExceptionHook On|Off</syntax>
<default>EnableExceptionHook Off</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>leader</module><module>perchild</module>
<module>prefork</module><module>threadpool</module>
<module>worker</module></modulelist>
<compatibility>Disponible en las versiones de Apache 2.0.49 y posteriores</compatibility>

<usage>
    <p>Por razones de seguridad esta directiva est&#225; disponible
    solamente si el servidor ha sido configurado con la opci&#243;n
    <code>--enable-exception-hook</code>. Esto activa un hook que
    permite que se conecten m&#243;dulos externos y que realicen
    alguna acci&#243;n despu&#233;s de que un proceso hijo sufra un
    error irrecuperable.</p>
    
    <p>Hay otros dos m&#243;dulos, <code>mod_whatkilledus</code> y
    <code>mod_backtrace</code> que usan este hook. Por favor, consulte
    el siguiente enlace, <a
    href="http://www.apache.org/~trawick/exception_hook.html"
    >EnableExceptionHook</a> perteneciente al sitio web de Jeff
    Trawick para obtener m&#225;s informaci&#243;n sobre el tema.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>Group</name>
<description>Grupo con el que el servidor atender&#225; las
peticiones</description>
<syntax>Group <var>unix-group</var></syntax>
<default>Group #-1</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>beos</module><module>leader</module>
<module>mpmt_os2</module><module>perchild</module><module>prefork</module>
<module>threadpool</module><module>worker</module></modulelist>
<compatibility>Solamente puede usarse en global server config a partir de la versi&#243;n de Apache 2.0</compatibility>

<usage>
    <p>La directiva <directive>Group</directive> determina el grupo
    con el que el servidor atender&#225; las peticiones. Para usar
    esta directiva, el servidor debe haber sido iniciado con el
    usuario <code>root</code>. Si inicia el servidor con un usuario
    que no sea root, el servidor no podr&#225; cambiarse al grupo
    especificado, en lugar de esto continuar&#225; ejecut&#225;ndose
    con el grupo del usuario que lo inici&#243;. <var>Unix-group</var>
    debe tomar un de los siguiente valores:</p>

    <dl>
      <dt>El nombre de un grupo</dt>
      <dd>Se refiere al grupo que lleva el nombre que se especifica.</dd>

      <dt><code>#</code> seguido del n&#250;mero de un grupo.</dt>
      <dd>Se refiere al grupo asociado a ese n&#250;mero.</dd>
    </dl>

    <example><title>Por ejemplo</title>
      Group www-group
    </example>

    <p>Se recomienda que cree un nuevo grupo espec&#237;ficamente para
    ejecutar el servidor. Algunos administradores usan el ususario
    <code>nobody</code>, pero esto no es siempre posible ni
    aconsejable.</p>

    <note type="warning"><title>Seguridad</title> <p>No ponga el valor
      <code>root</code> en la directiva <directive>Group</directive>
      (o en la directiva <directive
      module="mpm_common">User</directive>) a menos que sepa
      exactamente lo que est&#225; haciendo y los peligros que
      conlleva.</p>
    </note>

    <p>Importante: El uso de esta directiva en <directive
    module="core" type="section">VirtualHost</directive> no est&#225;
    permitido ya. Para configurar su servidor para
    <program>suexec</program> use la directiva <directive
    module="mod_suexec">SuexecUserGroup</directive>.</p>

    <note><title>Nota</title> <p>Aunque la directiva
      <directive>Group</directive> est&#225; presente en los
      m&#243;dulos MPM <module>beos</module> y
      <module>mpmt_os2</module>, no est&#225;n operativas y solamente
      est&#225;n presentes por razones de compatibilidad.</p>
    </note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>PidFile</name> 
<description>Fichero en el que el servidor guarda
el ID del proceso demonio de escucha (daemon)</description>
<syntax>PidFile <var>filename</var></syntax> 
<default>PidFile logs/httpd.pid</default> 
<contextlist><context>server config</context></contextlist>
<modulelist><module>beos</module><module>leader</module>
<module>mpm_winnt</module><module>mpmt_os2</module>
<module>perchild</module><module>prefork</module>
<module>threadpool</module><module>worker</module></modulelist>

<usage>
    <p>La directiva <directive>PidFile</directive> especifica el
    fichero en el que el servidor guarda el ID del proceso demonio de
    escucha (daemon). Si el nombre del fichero especificado no es una
    ruta absoluta, entonces se asume que es relativa al directorio
    especificado en <directive
    module="core">ServerRoot</directive>.</p>

    <example><title>Ejemplo</title>
      PidFile /var/run/apache.pid
    </example>

    <p>Con frecuencia es &#250;til tener la posibilidad de enviar al
    servidor una se&#241;al, de manera que cierre y vuelva a abrir el
    <directive module="core">ErrorLog</directive> y el <directive
    module="mod_log_config">TransferLog</directive>, y vuelva a leer
    los ficheros de configuraci&#243;n. Esto es lo que ocurre cuando
    se env&#237;a la se&#241;al SIGHUP (kill -1) al ID del proceso que
    aparece en <directive>PidFile</directive>.</p>

    <p>El <directive>PidFile</directive> est&#225; sujeto a las mismas
    advertencias que se hicieron para los ficheros log sobre su
    ubicaci&#243;n y sobre su <a
    href="../misc/security_tips.html#serverroot">seguridad</a>.</p>

    <note><title>Nota</title> <p>Se recomienda que para Apache 2 se
      use solamente el script <program>apachectl</program> para
      (re-)iniciar o parar el servidor.</p>
    </note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>Listen</name>
<description>Direcciones IP y puertos en los que escucha el servidor</description>
<syntax>Listen [<var>IP-address</var>:]<var>portnumber</var></syntax>
<contextlist><context>server config</context></contextlist>
<modulelist><module>beos</module><module>leader</module>
<module>mpm_netware</module><module>mpm_winnt</module>
<module>mpmt_os2</module><module>perchild</module>
<module>prefork</module><module>threadpool</module><module>worker</module>
</modulelist>
<compatibility>Directiva de uso obligatorio en Apache 2.0</compatibility>

<usage>
    <p>La directiva <directive>Listen</directive> indica las
    direcciones IP y los puertos en los que debe escuchar Apache; por
    defecto, el servidor responde a las peticiones que se reciban en
    cualquier direcci&#243;n IP de las interfaces de red. El uso de
    <directive>Listen</directive> es ahora obligatorio. Si no
    est&#225; en el fichero de configuraci&#243;n, el servidor no
    podr&#225; iniciarse. Esto supone un cambio respecto a las
    versiones anteriores de Apache.</p>

    <p>La directiva <directive>Listen</directive> le especifica al
    servidor los puertos o las combinaciones de direcciones y puertos
    cuyas peticiones debe aceptar. Si solamente se especifica un
    n&#250;mero de puerto, el servidor escuchar&#225; en ese puerto,
    en todas las interfaces de red. Si se especifica una
    direcci&#243;n IP y un puerto, el servidor escuchar&#225;
    solamente en esa direcci&#243;n IP y en ese puerto.</p>

    <p>Se pueden usar varias directivas <directive>Listen</directive>
    para especificar varias direcciones y puertos de escucha. El
    servidor responder&#225; a peticiones de cualquiera de esas
    direcciones y puertos.</p>

    <p>Por ejemplo, para hacer que el servidor acepte conexiones en
    los puertos 80 y 8000, use:</p>

    <example>
      Listen 80<br />
      Listen 8000
    </example>

    <p>Para hacer que el servidor acepte conexiones en dos direcciones
    y puertos difrentes, use </p>

    <example>
      Listen 192.170.2.1:80<br />
      Listen 192.170.2.5:8000
    </example>

    <p>Las direcciones IPv6 deben escribirse entre corchetes, como en
    el siguiente ejemplo:</p>

    <example>
      Listen [2001:db8::a00:20ff:fea7:ccea]:80
    </example>

    <note><title>Condici&#243;n de error</title> Varias directivas
      <directive>Listen</directive> para la misma direcci&#243;n IP y
      el mismo puerto tendr&#225;n como resultado un mensaje de error
      del tipo <code>Direcci&#243;n actualmente en uso</code>.
    </note>
</usage>
<seealso><a href="../dns-caveats.html">Problemas con DNS</a></seealso>
<seealso><a href="../bind.html">Especificaci&#243;n de las direcciones y puertos que usa Apache</a></seealso>
</directivesynopsis>

<directivesynopsis>
<name>ListenBackLog</name>
<description>Longitud m&#225;xima de la cola de conexiones en espera</description>
<syntax>ListenBacklog <var>backlog</var></syntax>
<default>ListenBacklog 511</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>beos</module><module>leader</module>
<module>mpm_netware</module><module>mpm_winnt</module>
<module>mpmt_os2</module><module>perchild</module><module>prefork</module>
<module>threadpool</module><module>worker</module></modulelist>

<usage>
    <p>Longitud m&#225;xima de la cola de conexiones en espera. En
    general, no es necesario ni deseable hacer ninguna
    modificaci&#243;n, pero en algunos sistemas es beneficioso
    incrementar esta longitud cuando se est&#225; sufriendo un ataque
    TCP SYN flood. Consulte la informaci&#243;n sobre el
    par&#225;metro backlog de la llamada al sistema
    <code>listen(2)</code>.</p>

    <p>Este n&#250;mero estar&#225; la mayor parte de las veces
    limitado a un valor a&#250;n menor por el sistema operativo. Esto
    var&#237;a de un sistema operativo a otro. Tenga en cuenta
    tambi&#233;n que muchos sistemas operativos no usan exactamente lo
    que se especifica en el backlog, sino que usan un n&#250;mero
    basado en el valor especificado (aunque normalmente mayor).</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>LockFile</name>
<description>Ubicaci&#243;n del fichero de lock de serializaci&#243;n de aceptacio&#243;n de peticiones</description>
<syntax>LockFile <var>filename</var></syntax>
<default>LockFile logs/accept.lock</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>leader</module><module>perchild</module>
<module>prefork</module><module>threadpool</module><module>worker</module>
</modulelist>

<usage>
    <p>La directiva <directive>LockFile</directive> especifica la ruta
    al archivo de lock (lockfile) que se utiliza cuando la directiva
    <directive module="mpm_common">AcceptMutex</directive> tiene valor
    <code>fcntl</code> o <code>flock</code>. En principio no se debe
    modificar el valor por defecto de esta directiva. La raz&#243;n
    principal para moficiarlo es que el directorio de
    <code>logs</code> est&#233; montado en NFS, porque <strong>el
    archivo de lock debe almacenarse en un disco local</strong>. El
    PID del proceso principal del servidor se a&#241;ade
    autom&#225;ticamente al nombre del fichero.</p>

    <note type="warning"><title>Seguridad</title> <p>Es aconsejable
      <em>no</em> poner este fichero en un directorio en el que tenga
      permisos de escritura todos los usuarios como
      <code>/var/tmp</code> porque alguien podr&#237;a provocar un
      ataque de denegaci&#243;n de servicio y evitar que el servidor
      se inicie creando un archivo de lock con el mismo nombre que el
      que el servidor intentar&#225; crear.</p>
    </note>
</usage>
<seealso><directive module="mpm_common">AcceptMutex</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>MaxClients</name>
<description>N&#250;mero m&#225;ximo de procesos hijo que ser&#225;n creados para
atender peticiones</description>
<syntax>MaxClients <var>number</var></syntax>
<default>Consulte la secci&#243;n de uso para obtener m&#225;s informaci&#243;n</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>beos</module><module>leader</module>
<module>prefork</module><module>threadpool</module><module>worker</module>
</modulelist>

<usage>
    <p>La directiva <directive>MaxClients</directive> especifica el
    l&#237;mite de peticiones simult&#225;neas que ser&#225;n
    atendidas. Cualquier intento de conexi&#243;n por encima del
    l&#237;mite <directive>MaxClients</directive> se pondr&#225; en
    cola, hasta llegar a un l&#237;mite basado en el valor de la
    directiva <directive
    module="mpm_common">ListenBacklog</directive>. Una vez que un
    proceso hijo termina de atender una petici&#243;n y queda libre, se
    atender&#225; una conexi&#243;n en cola.</p>

    <p>En servidores que no usan hebras (por ejemplo,
    <module>prefork</module>), el valor especificado en
    <directive>MaxClients</directive> se traduce en el n&#250;mero
    m&#225;ximo de procesos hijo que se crear&#225;n para atender
    peticiones. El valor por defecto es <code>256</code>; para
    incrementarlo, debe incrementar tambi&#233;n el valor especificado
    en la directiva <directive
    module="mpm_common">ServerLimit</directive>.</p>

    <p>En servidores que usan hebras y en servidores h&#237;bridos
    (por ejemplo, <module>beos</module> o <module>worker</module>)
    <directive>MaxClients</directive> limita el n&#250;mero total de
    hebras que van a estar disponibles para servir clientes. El valor
    por defecto para <module>beos</module> es <code>50</code>. Para
    MPMs h&#237;bridos el valor por defecto es <code>16</code>
    (<directive module="mpm_common">ServerLimit</directive>)
    multiplicado por <code>25</code> (<directive module="mpm_common"
    >ThreadsPerChild</directive>). Por lo tanto, si va a usar en
    <directive >MaxClients</directive> un valor que requiera m&#225;s
    de 16 procesos deber&#225; tambi&#233;n incrementar el valor de la
    directiva <directive
    module="mpm_common">ServerLimit</directive>.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>MaxMemFree</name>
<description>Cantidad m&#225;xima de memoria que el asignador principal puede tomar sin hacer una llamada a <code>free()</code></description>
<syntax>MaxMemFree <var>KBytes</var></syntax>
<default>MaxMemFree 0</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>beos</module><module>leader</module>
<module>mpm_netware</module><module>prefork</module>
<module>threadpool</module><module>worker</module><module>mpm_winnt</module></modulelist>

<usage>
    <p>La directiva <directive>MaxMemFree</directive> especifica el
    n&#250;mero m&#225;ximo de kbytes libres que el asignador de memoria
    principal puede tomar sin hacer una llamada al sistema
    <code>free()</code>. Cuando no se especifica ning&#250;n valor en esta
    directiva, o cuando se especifica el valor cero, no existir&#225; tal
    l&#237;mite.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>MaxRequestsPerChild</name>
<description>L&#237;mite en el n&#250;mero de peticiones que un proceso hijo puede
atender durante su vida</description>
<syntax>MaxRequestsPerChild <var>number</var></syntax>
<default>MaxRequestsPerChild 10000</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>leader</module><module>mpm_netware</module>
<module>mpm_winnt</module><module>mpmt_os2</module>
<module>perchild</module><module>prefork</module>
<module>threadpool</module><module>worker</module></modulelist>

<usage>
    <p>La directiva <directive>MaxRequestsPerChild</directive>
    especifica el n&#250;mero m&#225;ximo de peticiones que un proceso hijo
    atender&#225; durante su existencia. Despu&#233;s de atender
    <directive>MaxRequestsPerChild</directive> peticiones, el proceso
    hijo se eliminar&#225;. Si el valor especificado en esta directiva
    <directive>MaxRequestsPerChild</directive> es <code>0</code>, no
    habr&#225; l&#237;mite.</p>

    <note><title>Diferentes valores por defecto</title> 
      <p>El valor por defecto para los m&#243;dulos
      <module>mpm_netware</module> y <module>mpm_winnt</module> es
      <code>0</code>.</p>
    </note>

    <p>Especificar en la directiva
    <directive>MaxRequestsPerChild</directive> un valor distinto de
    cero tiene dos ventajas:</p>

    <ul>
      <li>limita la cantidad de memoria que un proceso puede consumir
      en caso de que haya un fuga (accidental) de memoria;</li>

      <li>establece un l&#237;mite finito a la vida de los procesos, lo que
      ayuda a reducir el n&#250;mero existente de procesos cuando se reduce
      la carga de trabajo en el servidor.</li>
    </ul>

    <note><title>Nota</title> 
      <p>Para las peticiones <directive
      module="core">KeepAlive</directive>, solamente la primera petici&#243;n
      cuenta para este l&#237;mite. De hecho, en ese caso lo que se
      limita es el n&#250;mero de <em>conexiones</em> por proceso hijo.</p>
    </note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>MaxSpareThreads</name>
<description>N&#250;mero m&#225;ximo de hebras en espera</description>
<syntax>MaxSpareThreads <var>number</var></syntax>
<default>Consulte la secci&#243;n de uso para obtener m&#225;s informaci&#243;n</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>beos</module><module>leader</module>
<module>mpm_netware</module><module>mpmt_os2</module>
<module>perchild</module><module>threadpool</module><module>worker</module>
</modulelist>

<usage>
    <p>N&#250;mero m&#225;ximo de hebras en espera. Los diferentes MPMs tienen
    diferentes comportamientos respecto a esta directiva.</p>

    <p>En el m&#243;dulo <module>perchild</module> el valor por
    defecto usado es <code>MaxSpareThreads 10</code>. Este MPM
    monitoriza el n&#250;mero de hebras en espera por proceso hijo. Si
    hay demasiadas hebras en espera en un proceso hijo, el servidor
    empezar&#225; a eliminar las hebras de sobra.</p>

    <p>En los m&#243;dulos <module>worker</module>,
    <module>leader</module> y <module >threadpool</module> el valor
    por defecto usado es <code>MaxSpareThreads 250</code>. Estos MPMs
    monitorizan el n&#250;mero del hebras en espera en servidor en
    conjunto. Si hay demasiadas hebras en espera en el servidor, se
    eliminan algunos procesos hijo hasta que el n&#250;mero de hebras
    en espera se ajuste al l&#237;mite especificado.</p>

    <p>En el m&#243;dulo <module>mpm_netware</module> el valor por
    defecto usado es <code>MaxSpareThreads 100</code>. Como este MPM
    ejecuta &#250;nico proceso, las hebras en espera se calculan
    tambi&#233;n en base al servidor en conjunto.</p>

    <p>Los m&#243;dulos <module>beos</module> y <module>mpmt_os2</module>
    funcionan de manera similar a <module>mpm_netware</module>. El
    valor por defecto para <module>beos</module> es
    <code>MaxSpareThreads 50</code>. Para <module>mpmt_os2</module> el
    valor por defecto es <code>10</code>.</p>

    <note><title>Restricciones</title> 
      <p>El rango de valores que puede tomar
      <directive>MaxSpareThreads</directive> est&#225; acotado. Apache
      corregir&#225; autom&#225;ticamente el valor especificado de
      acuerdo con las siguientes reglas:</p>
      <ul>
        <li>Si usa el m&#243;dulo <module>perchild</module> el valor
        especificado en la directiva
        <directive>MaxSpareThreads</directive> tiene que ser menor o
        igual al valor especificado en <directive
        module="mpm_common">ThreadLimit</directive>.</li>

        <li><module>mpm_netware</module> necesita que el valor de esta
        directiva sea mayor que el valor de la directiva <directive
        module="mpm_common">MinSpareThreads</directive>.</li>

        <li>En los m&#243;dulos <module>leader</module>,
        <module>threadpool</module> y <module>worker</module> el valor
        especificado tiene que ser mayor o igual a la suma de los
        valores especificados en las directivas <directive
        module="mpm_common">MinSpareThreads</directive> y <directive
        module="mpm_common">ThreadsPerChild</directive>.</li>
      </ul>
    </note>
</usage>
<seealso><directive module="mpm_common">MinSpareThreads</directive></seealso>
<seealso><directive module="mpm_common">StartServers</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>MinSpareThreads</name>
<description>N&#250;mero m&#237;nimo de hebras en espera para atender picos de
demanda en las peticiones</description>
<syntax>MinSpareThreads <var>number</var></syntax>
<default>Consulte la secci&#243;n de uso para obtener m&#225;s informaci&#243;n</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>beos</module><module>leader</module>
<module>mpm_netware</module><module>mpmt_os2</module>
<module>perchild</module><module>threadpool</module><module>worker</module>
</modulelist>

<usage>
    <p>N&#250;mero m&#237;nimo de hebras en espera para atender picos
    de demanda en las peticiones. Los diferentes MPMs tratan esta
    directiva de forma diferente.</p>

    <p>El m&#243;dulo <module>perchild</module> usa por defecto
    <code>MinSpareThreads 5</code> y calcula el n&#250;mero de hebras
    en espera en base al n&#250;mero de procesos hijo. Si no hay
    suficientes hebras en espera en un proceso hijo, el servidor
    empezar&#225; a crear nuevas hebras dentro de ese proceso hijo. De
    esta manera, si especifica en la directiva <directive
    module="perchild">NumServers</directive> el valor <code>10</code>
    y en la directiva <directive>MinSpareThreads</directive> un valor
    de <code>5</code>, tendr&#225; como m&#237;nimo 50 hebras en
    espera en su sistema.</p>

    <p>Los m&#243;dulos <module>worker</module>,
    <module>leader</module> y <module>threadpool</module> usan un
    valor por defecto <code>MinSpareThreads 75</code> y calculan el
    n&#250;mero de hebras en espera en el servidor en conjunto. Si no
    hay suficientes hebras en espera en el servidor, entonces se crean
    procesos hijo hasta que el n&#250;mero de hebras en espera sea
    suficiente.</p>

    <p>El m&#243;dulo <module>mpm_netware</module> usa un valor por defecto
    <code>MinSpareThreads 10</code> y como es un MPM que trabaja con
    un &#250;nico proceso, calcula el n&#250;mero de hebras en espera en base al
    n&#250;mero total que hay en el servidor.</p>

    <p>Los m&#243;dulos <module>beos</module> y <module>mpmt_os2</module>
    funcionan de modo similar a como lo hace el m&#243;dulo
    <module>mpm_netware</module>. El valor por defecto que usa
    <module>beos</module> es <code>MinSpareThreads 1</code>.
    <module>mpmt_os2</module> usa por defecto el valor
    <code>5</code>.</p>
</usage>
<seealso><directive module="mpm_common">MaxSpareThreads</directive></seealso>
<seealso><directive module="mpm_common">StartServers</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>ScoreBoardFile</name>
<description>Ubicaci&#243;n del fichero que almacena los datos necesarios para
coordinar el funcionamiento de los procesos hijo del servidor </description>
<syntax>ScoreBoardFile <var>file-path</var></syntax>
<default>ScoreBoardFile logs/apache_status</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>beos</module><module>leader</module>
<module>mpm_winnt</module><module>perchild</module><module>prefork</module>
<module>threadpool</module><module>worker</module></modulelist>

<usage>
    <p>Apache usa un marcador para que los procesos hijo se
    comuniquen con sus procesos padre.  Algunas arquitecturas
    necesitan un archivo para facilitar esta comunicaci&#243;n. Si no
    se especifica ning&#250;n fichero, Apache intenta en primer lugar
    crear el marcador en memoria (usando memoria compartida
    an&#243;nima) y, si esto falla, intentar&#225; crear el fichero en
    disco (usando memoria compartida basada en ficheros). Si se especifica un
    valor en esta directiva, Apache crear&#225; directamente el
    archivo en disco.</p>

    <example><title>Ejemplo</title>
      ScoreBoardFile /var/run/apache_status
    </example>

    <p>El uso de memoria compartida basada en ficheros es &#250;til
    para aplicaciones de terceras partes que necesitan acceso directo
    al marcador.</p>

    <p>Si usa la directiva <directive>ScoreBoardFile</directive>,
    puede mejorar la velocidad del servidor poniendo el fichero en
    memoria RAM. Pero tenga cuidado y siga las mismas recomendaciones
    acerca del lugar donde se almacenan los ficheros log y su <a
    href="../misc/security_tips.html">seguridad</a>.</p>
</usage>
<seealso><a href="../stopping.html">Parar y reiniciar
Apache</a></seealso>
</directivesynopsis>

<directivesynopsis>
<name>SendBufferSize</name>
<description>Tama&#241;o del buffer TCP</description>
<syntax>SendBufferSize <var>bytes</var></syntax>
<default>SendBufferSize 0</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>beos</module><module>leader</module>
<module>mpm_netware</module><module>mpm_winnt</module>
<module>mpmt_os2</module><module>perchild</module><module>prefork</module>
<module>threadpool</module><module>worker</module></modulelist>

<usage>
    <p>El servidor fijar&#225; el tama&#241;o del buffer TCP en los
    bytes que se especifiquen en esta directiva. Incrementar este
    valor por encima de los valores est&#225;ndar del sistema
    operativo es muy &#250;til en situaciones de alta velocidad y gran
    latencia (por ejemplo, 100ms o as&#237;, como en el caso de
    conexiones intercontinentales de gran capacidad).</p>

    <p>Si se especifica el valor <code>0</code>, el servidor usar&#225; el
    valor por defecto del sistema operativo.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ServerLimit</name>
<description>L&#237;mite superior del n&#250;mero configurable de procesos</description>
<syntax>ServerLimit <var>number</var></syntax>
<default>Consulte la secci&#243;n de uso para obtener m&#225;s informaci&#243;n</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>leader</module><module>perchild</module>
<module>prefork</module><module>threadpool</module><module>worker</module>
</modulelist>

<usage>
   <p>En el m&#243;dulo MPM <module>prefork</module>, esta directiva
    significa el valor m&#225;ximo que se puede especificar en la
    directiva <directive module="mpm_common">MaxClients</directive>
    sobre el tiempo de vida de un proceso de Apache.  En el
    m&#243;dulo MPM <module>worker</module>, esta diretiva en
    combinaci&#243;n con la directiva <directive
    module="mpm_common">ThreadLimit</directive> significa el valor
    m&#225;ximo que puede especificarse en la directiva <directive
    module="mpm_common">MaxClients</directive> sobre el tiempo de vida
    de un proceso de Apache. Los intententos de cambiar el valor de
    esta directiva durante el reinicio del servidor ser&#225;n
    ignorados. El valor de <directive
    module="mpm_common">MaxClients</directive> s&#237; que puede
    modificarse durante el reinicio.</p>

    <p>Cuando se usa esta directiva hay que tener especial cuidado.
    Si en la directiva <directive>ServerLimit</directive> se
    especifica un valor mucho m&#225;s alto de lo necesario, se reservar&#225;
    memoria compartida que no ser&#225; usada.  Si ambas directivas
    <directive>ServerLimit</directive> y <directive
    module="mpm_common">MaxClients</directive> tienen especificados
    valores mayores que los que el sistema puede manejar, Apache puede
    que no se inicie o que el sistema se vuelva inestable.</p>

    <p>Con el m&#243;dulo MPM <module>prefork</module>, use esta
    directiva solamente si necesita especificar en la directiva
    <directive module="mpm_common">MaxClients</directive> un valor
    mayor a 256 (el valor por defecto). No especifique un valor mayor
    del que vaya a especificar en la directiva <directive
    module="mpm_common">MaxClients</directive>.</p>

    <p>Con los m&#243;dulos <module>worker</module>,
    <module>leader</module> y <module>threadpool</module> use esta
    directiva solamente si los valores especificados en las directivas
    <directive module="mpm_common">MaxClients</directive> y <directive
    module="mpm_common">ThreadsPerChild</directive> precisan m&#225;s de 16
    procesos del servidor (valor por defecto). No especifique en esta
    directiva un valor mayor que el n&#250;mero de procesos del servidor
    requeridos por lo especificado en las directivas <directive
    module="mpm_common">MaxClients </directive> y <directive
    module="mpm_common">ThreadsPerChild</directive>.</p>

    <p>Con el MPM <module>perchild</module>, use esta directiva solo
    si tiene que especificar en la directiva <directive
    module="perchild">NumServers</directive> un valor mayor de 8 (el
    valor por defecto).</p>

    <note><title>Nota</title> 
      <p>Existe un l&#237;mite inviolable compilado en el servidor que es
      <code>ServerLimit 20000</code>. Con este l&#237;mite se intentan
      evitar las consecuencias que pueden tener los errores tipogr&#225;ficos.</p>
    </note>
</usage>
<seealso><a href="../stopping.html">Parar y reiniciar
Apache</a></seealso>
</directivesynopsis>

<directivesynopsis>
<name>StartServers</name>
<description>N&#250;mero de procesos hijo del servidor que se crean al
iniciar Apache</description>
<syntax>StartServers <var>number</var></syntax>
<default>Consulte la secci&#243;n de uso para obtener m&#225;s informaci&#243;n</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>leader</module><module>mpmt_os2</module>
<module>prefork</module><module>threadpool</module><module>worker</module>
</modulelist>

<usage>
    <p>La directiva <directive>StartServers</directive> especifica el
    n&#250;mero de procesos hijo que se crean al iniciar Apache. Como
    el n&#250;mero de procesos est&#225; controlado din&#225;micamente
    seg&#250;n la carga del servidor, no hay normalmente ninguna
    raz&#243;n para modificar el valor de este par&#225;metro.</p>

    <p>El valor por defecto cambia seg&#250;n el MPM de que se trate. Para
    <module>leader</module>, <module>threadpool</module> y
    <module>worker</module> el valor por defecto es <code>StartServers
    3</code>.  Para <module>prefork</module> el valor por defecto es
    <code>5</code> y para <module>mpmt_os2</module> es
    <code>2</code>.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>StartThreads</name>
<description>N&#250;mero de hebras que se crean al iniciar Apache</description>
<syntax>StartThreads <var>number</var></syntax>
<default>Consulte la secci&#243;n de uso para obtener m&#225;s informaci&#243;n</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>beos</module><module>mpm_netware</module>
<module>perchild</module></modulelist>

<usage>
    <p>N&#250;mero de hebras que se crean al iniciar Apache. Como el
    n&#250;mero de procesos est&#225; controlado din&#225;micamente
    seg&#250;n la carga del servidor, no hay normalmente ninguna
    raz&#243;n para modificar el valor de este par&#225;metro.</p>

    <p>En el m&#243;dulo <module>perchild</module> el valor por defecto es
    <code>StartThreads 5</code> y esta directiva controla el n&#250;mero de
    hebras por proceso al inicio.</p>

    <p>En el m&#243;dulo <module>mpm_netware</module> el valor por
    defecto es <code>StartThreads 50</code> y, como solamente hay un
    proceso, este es el n&#250;mero total de hebras creadas al iniciar
    el servidor para servir peticiones.</p>

    <p>En el m&#243;dulo <module>beos</module> el valor usado por
    defecto es <code>StartThreads 10</code>. En este caso tambi&#233;n
    representa el n&#250;mero total de hebras creadas al iniciar el
    servidor para servir peticiones.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ThreadLimit</name>
<description>Marca el l&#237;mite superior del n&#250;mero de hebras por
proceso hijo que pueden especificarse</description>
<syntax>ThreadLimit <var>number</var></syntax>
<default>Consulte la secci&#243;n de uso para obtener m&#225;s informaci&#243;n</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>leader</module><module>mpm_winnt</module>
<module>perchild</module><module>threadpool</module><module>worker</module>
</modulelist>
<compatibility>Disponible para <module>mpm_winnt</module> en las versiones de Apache
2.0.41 y posteriores</compatibility>

<usage>
    <p>Esta directiva determina el valor m&#225;ximo que puede especificarse
    en la directiva <directive
    module="mpm_common">ThreadsPerChild</directive> para el tiempo de
    vida de un proceso de Apache. Los intentos por modificar este
    valor durante un reinicio ser&#225;n ingnorados, pero el valor de la
    directiva <directive
    module="mpm_common">ThreadsPerChild</directive> puede modificarse
    durante un reinicio hasta un valor igual al de esta directiva.</p>

    <p>Cuando se usa esta directiva hay que poner especial
    atenci&#243;n. Si en la directiva
    <directive>ThreadLimit</directive> se especifica un valor mucho
    m&#225;s grande que en <directive
    module="mpm_common">ThreadsPerChild</directive>, se reservar&#225;
    memoria compartida en exceso que no ser&#225; usada.  Si tanto en
    <directive>ThreadLimit</directive> como en <directive
    module="mpm_common">ThreadsPerChild</directive> se especifican
    valores mayores de los que el sistema puede tratar, Apache
    podr&#237;a no iniciarse o su funcionamiento podr&#237;a volverse
    inestable. No especifique en esta directiva un valor mayor del
    mayor valor posible que piense que va a especificar en <directive
    module="mpm_common">ThreadsPerChild</directive> para la
    ejecuci&#243;n de Apache de ese momento.</p>

    <p>El valor por defecto de la directiva
    <directive>ThreadLimit</directive> es <code>1920</code> cuando se
    usa con <module>mpm_winnt</module> y <code>64</code> en otro caso.</p>

    <note><title>Nota</title> <p>Hay un l&#237;mite estricto compilado
      en el servidor: <code>ThreadLimit 20000</code> (o
      <code>ThreadLimit 15000</code> si usa
      <module>mpm_winnt</module>). Este l&#237;mite existe para evitar
      los efectos que pueden ser provocados por errores
      tipogr&#225;ficos.</p>
    </note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ThreadsPerChild</name>
<description>N&#250;mero de hebras creadas por cada proceso
hijo</description>
<syntax>ThreadsPerChild <var>number</var></syntax>
<default>Consulte la secci&#243;n de uso para obtener m&#225;s informaci&#243;n</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>leader</module><module>mpm_winnt</module>
<module>threadpool</module><module>worker</module></modulelist>

<usage>
    <p>Esta directiva especifica el n&#250;mero de hebras creadas por
    cada proceso hijo. El proceso hijo crea estas hebras al inicio y
    no vuelve a crear m&#225;s. Si se usa un MPM como
    <module>mpm_winnt</module>, en el que solamente hay un proceso
    hijo, este n&#250;mero deber&#237;a ser lo suficientemente grande
    como para atender toda la carga del servidor. Si se usa un
    m&#243;dulo MPM como <module>worker</module>, en el que hay
    m&#250;ltiples procesos hijo, el n&#250;mero <em>total</em> de
    hebras deber&#237;a ser lo suficientemente grande como para
    atender la carga en circustancias normales del servidor.</p>

    <p>El valor por defecto de la directiva
    <directive>ThreadsPerChild</directive> es <code>64</code> cuando
    se usa <module>mpm_winnt</module> y <code>25</code> en otro caso.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>User</name>
<description>Nombre de usuario con el que el servidor responder&#225; a las
peticiones</description>
<syntax>User <var>unix-userid</var></syntax>
<default>User #-1</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>leader</module><module>perchild</module>
<module>prefork</module><module>threadpool</module><module>worker</module>
</modulelist>
<compatibility>V&#225;lida solamente en global server config a partir
de la versi&#243;n de Apache 2.0</compatibility>

<usage>
    <p>La directiva <directive>User</directive> especifica el
    identificador de usuario con el que el servidor responder&#225; a
    las peticiones. Para usar esta directiva, el servidor debe haber
    sido iniciado como <code>root</code>.  Si se inicia Apache con un
    usario distinto de root, no se podr&#225; cambiar a un usuario con
    menores privilegios, y el servidor continuar&#225; ejecut&#225;ndose
    con el usuario original. Si inicia el servidor como
    <code>root</code>, entonces es normal que el procedimiento padre
    siga ejecut&#225;ndose como root. <var>Unix-userid</var> puede tomar
    uno de los siguientes valores:</p>

    <dl>
      <dt>Un nombre de ususario</dt>
      <dd>Se refiere al usuario dado por su nombre.</dd>

      <dt># seguido por un n&#250;mero de usuario.</dt>
      <dd>Se refiere al usuario que corresponde a ese n&#250;mero.</dd>
    </dl>

    <p>El usuario debe no tener privilegios suficientes para acceder a
    ficheros que no deban ser visibles para el mundo exterior, y de
    igual manera, el usuario no debe ser capaz de ejecutar c&#243;digo que
    no sea susceptible de ser objeto de respuestas a peticiones
    HTTP. Se recomienda que especifique un nuevo usuario y un nuevo
    grupo solamente para ejecutar el servidor. Algunos
    administradores usan el usuario <code>nobody</code>, pero esto no
    es siempre deseable, porque el usuario <code>nobody</code> puede
    tener otras funciones en su sistema.</p>

    <note type="warning"><title>Seguriad</title>
      <p>No espcifique en la directiva <directive>User</directive> (o
      <directive module="mpm_common">Group</directive>) el valor
      <code>root</code> a no ser que sepa exactamente lo que est&#225;
      haciendo, y cu&#225;les son los peligros.</p>
    </note>

    <p>Con el MPM <module>perchild</module>, que est&#225;
    dise&#241;ado para ejecutar hosts virtuales por diferentes ID de
    usuario, la directiva <directive>User</directive> define el ID de
    usuario para el servidor principal y para el resto de las
    secciones <directive type="section"
    module="core">VirtualHost</directive> sin una directiva <directive
    module="perchild">AssignUserID</directive>.</p>

    <p>Nota especial: El uso de esta directiva en <directive
    module="core" type="section">VirtualHost</directive> no est&#225;
    ya soportado. Para configurar su servidor para
    <program>suexec</program> use <directive
    module="mod_suexec">SuexecUserGroup</directive>.</p>

    <note><title>Nota</title> 
     <p>Aunque la directiva <directive>User</directive> est&#225;
     presente en los MPMs <module>beos</module> y
     <module>mpmt_os2</module> MPMs, no est&#225; operativa y
     solamente est&#225; presente por razones de compatibilidad.</p>
    </note>
</usage>
</directivesynopsis>

</modulesynopsis>


