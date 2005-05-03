<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE manualpage SYSTEM "./style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="./style/manual.es.xsl"?>
<!-- English Revision: 151405:165672 (outdated) -->

<!--
 Copyright 2005 The Apache Software Foundation or it licensors,
                as applicable.

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

<manualpage metafile="logs.xml.meta">

  <title>Archivos de Registro (Log Files)</title>

  <summary>
    <p>Para administrar de manera efectiva un servidor web, es
    necesario tener registros de la actividad y el rendimiento del
    servidor as&#237; como de cualquier problema que haya podido
    ocurrir durante su operaci&#243;n. El servidor HTTP Apache ofrece
    capacidades muy amplias de registro de este tipo de
    informaci&#243;n. Este documento explica c&#243;mo configurar esas
    capacidades de registro, y c&#243;mo comprender qu&#233;
    informaci&#243;n contienen los ficheros de registro.</p>
  </summary>

  <section id="security">
    <title>Advertencia de seguridad</title>

    <p>Cualquiera que tenga permisos de escritura sobre el directorio
    en el que Apache est&#233; escribiendo un archivo de registro
    puede con casi toda seguridad tener acceso al identificador de
    usuario con el que se inici&#243; el servidor, normalmente
    root. <em>NO</em> le de a nadie permisos de escritura sobre el
    directorio en que se almacenan los ficheros de registro sin tener
    en cuenta las consecuencias; consulte los <a
    href="misc/security_tips.html">consejos de seguridad</a> para
    obtener m&#225;s informaci&#243;n.</p>

    <p>Adem&#225;s, los ficheros de registro pueden contener
    informaci&#243;n suministrada directamente por el cliente, sin
    sustituir. Es posible por tanto que clientes con malas intenciones
    inserten caracteres de control en los ficheros de registro. Por
    ello es necesario tener cuidado cuando se procesan los ficheros de
    registro originales.</p>
  </section>

  <section id="errorlog">
    <title>Registro de Errores (Error Log)</title>

    <related>
      <directivelist>
        <directive module="core">ErrorLog</directive>
        <directive module="core">LogLevel</directive>
      </directivelist>
    </related>

    <p>El registro de errores del servidor, cuyo nombre y
    ubicaci&#243;n se especifica en la directiva <directive
    module="core">ErrorLog</directive>, es el m&#225;s importante de
    todos los registros. Apache enviar&#225; cualquier
    informaci&#243;n de diagn&#243;stico y registrar&#225; cualquier
    error que encuentre al procesar peticiones al archivo de registro
    seleccionado. Es el primer lugar donde tiene que mirar cuando
    surja un problema al iniciar el servidor o durante su
    operaci&#243;n normal, porque con frecuencia encontrar&#225; en
    &#233;l informaci&#243;n detallada de qu&#233; ha ido mal y
    c&#243;mo solucionar el problema.</p>

    <p>El registro de errores se escribe normalmente en un fichero
    (cuyo nombre suele ser <code>error_log</code> en sistemas Unix y
    <code>error.log</code> en Windows y OS/2). En sistemas Unix
    tambi&#233;n es posible hacer que el servidor env&#237;e los
    mensajes de error al <code>syslog</code> o <a
    href="#piped">pasarlos a un programa</a>.</p>

    <p>El formato del registro de errores es relativamente libre y
    descriptivo. No obstante, hay cierta informaci&#243;n que se
    incluye en casi todas las entradas de un registro de errores. Por
    ejemplo, este es un mensaje t&#237;pico.</p>

    <example>
      [Wed Oct 11 14:32:52 2000] [error] [client 127.0.0.1]
      client denied by server configuration:
      /export/home/live/ap/htdocs/test
    </example>

    <p>El primer elemento de la entrada es la fecha y la hora del
    mensaje. El segundo elemento indica la gravedad del error que se
    ha producido. La directiva <directive
    module="core">LogLevel</directive> se usa para controlar los tipos
    de errores que se env&#237;an al registro de errores seg&#250;n su
    gravedad. La tercera parte contiene la direcci&#243;n IP del
    cliente que gener&#243; el error. Despu&#233;s de la direcci&#243;n
    IP est&#225; el mensaje de error propiamente dicho, que en este
    caso indica que el servidor ha sido configurado para denegar el
    acceso a ese cliente. El servidor reporta tambi&#233;n la ruta en
    el sistema de ficheros (en vez de la ruta en el servidor
    web) del documento solicitado.</p>

    <p>En el registro de errores puede aparecer una amplia variedad de
    mensajes diferentes. La mayor&#237;a tienen un aspecto similar al
    del ejemplo de arriba. El registro de errores tambi&#233;n
    contiene mensaje de depuraci&#243;n de scripts CGI. Cualquier
    informaci&#243;n escrita en el <code>stderr</code> por un script
    CGI se copiar&#225; directamente en el registro de errores.</p>

    <p>El registro de errores no se puede personalizar a&#241;adiendo
    o quitando informaci&#243;n. Sin embargo, las entradas del
    registro de errores que se refieren a determinadas peticiones
    tienen sus correspondientes entradas en el <a
    href="#accesslog">registro de acceso</a>. El ejemplo de arriba se
    corresponde con una entrada en el registro de acceso que
    tendr&#225; un c&#243;digo de estado 403. Como es posible
    personalizar el registro de acceso, puede obtener m&#225;s
    informaci&#243;n sobre los errores que se producen usando ese
    registro tambi&#233;n.</p>

    <p>Si hace pruebas, suele ser de utilidad monitorizar de forma
    continua el registro de errores para comprobar si ocurre
    alg&#250;n problema. En sistemas Unix, puede hacer esto
    usando:</p>

    <example>
      tail -f error_log
    </example>
  </section>

  <section id="accesslog">
    <title>Registro de Acceso (Access Log)</title>

    <related>
      <modulelist>
        <module>mod_log_config</module>
        <module>mod_setenvif</module>
      </modulelist>
      <directivelist>
        <directive module="mod_log_config">CustomLog</directive>
        <directive module="mod_log_config">LogFormat</directive>
        <directive module="mod_setenvif">SetEnvIf</directive>
      </directivelist>
    </related>

    <p>El servidor almacena en el registro de acceso informaci&#243;n
    sobre todas las peticiones que procesa. La ubicaci&#243;n del
    fichero de registro y el contenido que se registra se pueden
    modificar con la directiva <directive
    module="mod_log_config">CustomLog</directive>. Puede usar la
    directiva <directive module="mod_log_config">LogFormat</directive>
    para simplificar la selecci&#243;n de los contenidos que quiere
    que se incluyan en los registros. Esta secci&#243;n explica como
    configurar el servidor para que registre la informaci&#243;n que
    usted considere oportuno en el registro de acceso.</p>

    <p>Por supuesto, almacenar informaci&#243;n en el registro de
    acceso es solamente el principio en la gesti&#243;n de los
    registros. El siguiente paso es analizar la informaci&#243;n que
    contienen para producir estad&#237;sticas que le resulten de
    utilidad. Explicar el an&#225;lisis de los registros en general
    est&#225; fuera de los prop&#243;sitos de este documento, y no es
    propiamente una parte del trabajo del servidor web. Para m&#225;s
    informaci&#243;n sobre este tema, y para aplicaciones que analizan
    los registros, puede visitar
    <a
    href="http://dmoz.org/Computers/Software/Internet/Site_Management/Log_analysis/">
    Open Directory</a> o <a
    href="http://dir.yahoo.com/Computers_and_Internet/Software/Internet/World_Wide_Web/Servers/Log_Analysis_Tools/">
    Yahoo</a>.</p>

    <p>Diferentes versiones de Apache httpd han usado otros
    m&#243;dulos y directivas para controlar la informaci&#243;n que
    se almacena en el registro de acceso, incluyendo mod_log_referer,
    mod_log_agent, y la directiva <code>TransferLog</code>. Ahora la
    directiva <directive module="mod_log_config">CustomLog</directive>
    asume toda la funcionalidad que antes estaba repartida.</p>

    <p>El formato del registro de acceso es altamente configurable. El
    formato se especifica usando una cadena de caracteres de formato
    similar a las de printf(1) en lenguaje C. Hay algunos ejemplos en
    las siguientes secciones. Si quiere una lista completa de los
    posibles contenidos que se pueden incluir, consulte la
    documentaci&#243; sobre <a
    href="mod/mod_log_config.html#formats">las cadenas de caracteres
    de formato</a> del <module>mod_log_config</module>.</p>

    <section id="common">
      <title>Formato Com&#250;n de Registro (Common Log
      Format)</title>

      <p>Una configuraci&#243;n t&#237;pica del registro de acceso
      podr&#237;a tener un aspecto similar a este.</p>

      <example>
        LogFormat "%h %l %u %t \"%r\" %&gt;s %b" common<br />
         CustomLog logs/access_log common
      </example>

      <p>Con esto se define el <em>apodo (nickname)</em> <code>common</code> y se
      le lo asocia con un determinado formato. El formato consiste en
      una serie de directivas con tantos por ciento, cada una de las
      cuales le dice al servidor que registre una determinada
      informaci&#243;n en particular. El formato tambi&#233;n puede
      incluir caracteres literales, que se copiar&#225;n directamente
      en el registro. Si usa el caracter comillas (<code>"</code>)
      debe anteponerle una barra invertida para evitar que sea
      interpretado como el final la cadena de caracteres a
      registrar. El formato que especifique tambi&#233;n puede
      contener los caracteres de control especiales "<code>\n</code>"
      para salto de l&#237;nea y "<code>\t</code>" para tabulador.</p>

      <p>La directiva <directive
	  module="mod_log_config">CustomLog</directive> crea un nuevo
	  fichero de registro usando el <em>apodo</em> definido. El
	  nombre del fichero de registro de acceso se asume que es
	  relativo al valor especificado en <directive
	  module="core">ServerRoot</directive> a no ser que empiece
	  por una barra (/).</p>

      <p>La configuraci&#243;n de arriba escribir&#225; las entradas
      en el registro con el formato conocido como Formato Com&#250;n
      de Registro (CLF). Este formato est&#225;ndar lo pueden generar
      muchos servidores web diferentes y lo pueden leer muchos de los
      progrmas que analizan registros. Las entradas de un fichero de
      registro que respetan ese formato com&#250;n tienen una
      aparariencia parecida es esta:</p>

      <example>
        127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET
        /apache_pb.gif HTTP/1.0" 200 2326
      </example>

      <p>Cada una de las partes de la entrada se explican a
      continuaci#243;n.</p>

      <dl>
        <dt><code>127.0.0.1</code> (<code>%h</code>)</dt>

        <dd>Es la direcci&#243;n IP del cliente (host remoto) que hizo
        la petici&#243;n al servidor. Si la directiva <directive
        module="core">HostnameLookups</directive> tiene valor
        <code>On</code>, el servidor intentar&#225; determinar el
        nombre del host y registrar ese nombre en lugar de la
        direcci&#243;n IP. Sin embargo, no se recomienda que use esta
        configuraci&#243;n porque puede ralentizar significativamente
        las operaciones del servidor. En su lugar, es mejor usar un
        programa que realice esta tarea posteriormente sobre el
        registro, por ejemplo <program>logresolve</program>. Las
        direcciones IP que se registren no son necesariamente las
        direcciones de las m&#225;quinas de los usuarios finales. Si
        existe un servidor proxy entre el usuario final y el servidor,
        la direcci&#243;n que se registra es la del proxy.</dd>

        <dt><code>-</code> (<code>%l</code>)</dt>

        <dd>Un "gui&#243;n" siginifica que la informaci&#243;n que
        deber&#237;a ir en ese lugar no est&#225; disponible. En este
        caso, esa informaci&#243;n es la identidad RFC 1413 del
        cliente determinada por <code>identd</code> en la m&#225;quina
        del cliente. Esta informaci&#243;n es muy poco fiable y no
        deber&#237;a ser usada nunca excepto con clientes que
        est&#233;n sometidos a controles muy estrictos en redes
        internas. Apache httpd ni siquiera intenta recoger esa
        informaci&#243;n a menos que la directiva <directive
        module="core">IdentityCheck</directive> tenga valor
        <code>On</code>.</dd>

        <dt><code>frank</code> (<code>%u</code>)</dt>

        <dd>Este es el identificador de usuario de la persona que
        solicita el documento determinado por la autentificaci&#243;n
        HTTP. Normalmente ese mismo valor se pasa a los scripts CGI
        con la variable de entorno <code>REMOTE_USER</code>. Si el
        c&#243;digo de estado de la petici&#243;n (ver abajo) es 401,
        entonces no debe confiar en la veracidad de ese dato porque el
        usuario no ha sido a&#250;n autentificado. Si el documento no
        est&#225; protegido por contrase&#241;a, se mostrar&#225; un
        gui&#243;n "<code>-</code>" en esta entrada.</dd>

        <dt><code>[10/Oct/2000:13:55:36 -0700]</code>
        (<code>%t</code>)</dt>

        <dd>
          La hora a la que el servidor termin&#243; de procesar la
          petici&#243;n. El formato es:

          <p class="indent">
            <code>[d&#237;a/mes/a&#241;o:hora:minuto:segundo zona_horaria]<br />
             day = 2*digit<br />
             month = 3*letter<br />
             year = 4*digit<br />
             hour = 2*digit<br />
             minute = 2*digit<br />
             second = 2*digit<br />
             zone = (`+' | `-') 4*digit</code>
          </p>
          Es posible mostrar la hora de otra manera especificando
          <code>%{format}</code> en el formato a usar en el registro,
          donde <code>format</code> se sustituye como se har&#237;a al
          usar <code>strftime(3)</code> de la librer&#237;a
          est&#225;ndar de C.
        </dd>

        <dt><code>"GET /apache_pb.gif HTTP/1.0"</code>
        (<code>\"%r\"</code>)</dt>

        <dd>La l&#237;nea de la petici&#243;n del cliente se muestra
        entre dobles comillas. La l&#237;nea de petici&#243;n contiene
        mucha informaci&#243;n de utilidad. Primero, el m&#233;todo
        usado por el cliente es <code>GET</code>. Segundo, el cliente
        ha hecho una petici&#243;n al recurso
        <code>/apache_pb.gif</code>, y tercero, el cliente uso el
        protocolo <code>HTTP/1.0</code>. Tambi&#233;n es posible
        registrar una o m&#225;s partes de la l&#237;nea de
        petici&#243;n independientemente. Por ejemplo, el formato
        "<code>%m %U%q %H</code>" registrar&#225; el m&#233;todo, ruta,
        cadena de consulta y protocolo, teniendo exactamente el mismo
        resultado que "<code>%r</code>".</dd>

        <dt><code>200</code> (<code>%&gt;s</code>)</dt>

        <dd>Es el c&#243;digo de estado que el servidor env&#237;a de
        vuelta al cliente. Esta informaci&#243;n es muy valiosa,
        porque revela si la petici&#243;n fue respondida con
        &#233;xito por el servidor (los c&#243;digos que empiezan por
        2), una redirecci&#243;n (los c&#243;digos que empiezan por
        3), un error provocado por el cliente (los c&#243;digos que
        empiezan por 4), o un error en el servidor (los c&#243;digos
        que empiezan por 5). La lista completa de c&#243;digos de
        estado posibles puede consultarle en <a
        href="http://www.w3.org/Protocols/rfc2616/rfc2616.txt">la
        especificaci&#243;n de HTTP</a> (RFC2616 secci&#243;n
        10).</dd>

        <dt><code>2326</code> (<code>%b</code>)</dt>

        <dd>La &#250;ltima entrada indica el tama&#241;o del objeto
        retornado por el cliente, no inclu&#237;das las cabeceras de
        respuesta. Si no se respondi&#243; con ning&#250;n contenido
        al cliente, este valor mostrar&#225; valor
        "<code>-</code>". Para registrar "<code>0</code>" en ese caso,
        use <code>%B</code> en su lugar.</dd>
      </dl>
    </section>

    <section id="combined">
      <title>Formato de Registro Combinado (Combined Log Format)</title>

      <p>Otro formato usado a menudo es el llamado Formato de Registro
      Combinado. Este formato puede ser usado como sigue.</p>

      <example>
        LogFormat "%h %l %u %t \"%r\" %&gt;s %b \"%{Referer}i\"
        \"%{User-agent}i\"" combined<br />
         CustomLog log/access_log combined
      </example>

      <p>Es exactamente igual que Formato Com&#250;n de Registro, pero
      a&#241;ade dos campos. Cada campo adicional usa la directiva
      <code>%{<em>header</em>}i</code>, donde <em>header</em> puede
      ser cualquier cabecera de petici&#243;n HTTP. El registro de
      acceso cuando se usa este formato tendr&#225; este aspecto:</p>

      <example>
        127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET
        /apache_pb.gif HTTP/1.0" 200 2326
        "http://www.example.com/start.html" "Mozilla/4.08 [en]
        (Win98; I ;Nav)"
      </example>

      <p>Los campos adicionales son:</p>

      <dl>
        <dt><code>"http://www.example.com/start.html"</code>
        (<code>\"%{Referer}i\"</code>)</dt>

        <dd>La cabecera de petici&#243;n de HTTP "Referer"
        (sic). Muestra el servidor del que proviene el cliente. (Esta
        deber&#237;a ser la p&#225;gina que contiene un enlace o
        que contiene a <code>/apache_pb.gif</code>).</dd>

        <dt><code>"Mozilla/4.08 [en] (Win98; I ;Nav)"</code>
        (<code>\"%{User-agent}i\"</code>)</dt>

        <dd>La cabecera de petici&#243;n HTTP "User-Agent". Es la
        informaci&#243;n de identificaci&#243;n que el navegador del
        cliente incluye sobre s&#237; mismo.</dd>
      </dl>
    </section>

    <section id="multiple">
      <title>C&#243;mo usar varios registros de acceso</title>

      <p>Para crear varios registros de acceso solamente tiene que
      especificar varias directivas <directive
      module="mod_log_config">CustomLog</directive> en el fichero de
      configuraci&#243;n. Por ejemplo, las siguientes directivas
      crear&#225;n tres registros de acceso. El primero contendr&#225;
      la informaci&#243;n b&#225;sica en Formato Com&#250;n de
      Registro, mientras que el segundo y el tercero contendr&#225;n
      contendr&#225;n la informaci&#243;n de los "referer" y de los
      navegadores usados. Las dos &#250;ltimas l&#237;neas <directive
      module="mod_log_config">CustomLog</directive> muestran c&#243;mo
      reproducir el comportamiento de las directivas
      <code>ReferLog</code> y <code >AgentLog</code>.</p>

      <example>
        LogFormat "%h %l %u %t \"%r\" %&gt;s %b" common<br />
        CustomLog logs/access_log common<br />
        CustomLog logs/referer_log "%{Referer}i -&gt; %U"<br />
        CustomLog logs/agent_log "%{User-agent}i"
      </example>

      <p>Este ejemplo tambi&#233;n muestra que no es necesario definir un
      "apodo" con la directiva <directive
      module="mod_log_config">LogFormat</directive>. En lugar de esto,
      el formato de registro puede especificarse directamente en la
      directiva <directive
      module="mod_log_config">CustomLog</directive>.</p>
    </section>

    <section id="conditional">
      <title>Registro Condicional</title>

      <p>Algunas veces es m&#225;s conveniente excluir determinadas
      entradas del registro de acceso en funci&#243;n de las
      caracter&#237;sticas de la petici&#243;n del cliente. Puede
      hacer esto f&#225;cilmente con la ayuda de <a
      href="env.html">variables de entorno</a>. Primero, debe
      especificar una variable de entorno que indique que la
      petici&#243;n cumple determinadas condiciones. Esto se hace
      normalmente con <directive
      module="mod_setenvif">SetEnvIf</directive>. Entonces puede usar
      la cla&#250;sula <code>env=</code> de la directiva <directive
      module="mod_log_config">CustomLog</directive> para incluir o
      excluir peticiones en las que est&#233; presente la variable de
      entorno. Algunos ejemplos:</p>

      <example>
        # Marcar las peticiones de la interfaz loop-back<br />
        SetEnvIf Remote_Addr "127\.0\.0\.1" dontlog<br /> 
        # Marcar las peticiones del fichero robots.txt<br /> 
        SetEnvIf Request_URI "^/robots\.txt$" dontlog<br /> 
        # Registrar lo que quede<br />
        CustomLog logs/access_log common env=!dontlog
      </example>

      <p>Como otro ejemplo, considere registrar las peticiones de los
      angloparlantes en un fichero de registro, y el resto de
      peticiones en un fichero de registro diferente.</p>

      <example>
        SetEnvIf Accept-Language "en" english<br />
        CustomLog logs/english_log common env=english<br />
        CustomLog logs/non_english_log common env=!english
      </example>

      <p>Aunque acabamos de mostar que el registro condicional es muy
      potente y flexible, no es la &#250;nica manera de controlar los
      contenidos de los ficheros de registro. Los ficheros de registro
      son m&#225;s &#250;tiles cuanta m&#225;s informaci&#243;n sobre
      la actividad del servidor contengan. A menudo es m&#225;s
      f&#225;cil eliminar las peticiones que no le interesen
      procesando posteriormente los ficheros de registro
      originales.</p>
    </section>
  </section>

  <section id="rotation">
    <title>Rotaci&#243;n de los ficheros de registro</title>

    <p>Incluso en un servidor con una actividad moderada, la cantidad
    de informaci&#243;n almacenada en los ficheros de registro es muy
    grande. El registro de acceso crece normalmente en 1MB por cada
    10.000 peticiones. Por lo tanto, es necesario rotar
    peri&#243;dicamente los registros moviendo o borrando su
    contenido. Esto no se puede hacer con el servidor funcionando,
    porque Apache continuar&#225; escribiendo en el antiguo registro
    mientras que el archivo est&#233; abierto. En lugar de esto, el
    servidor debe ser <a href="stopping.html">reiniciado</a>
    despu&#233;s de mover o borrar los ficheros de registro para que
    se abran nuevos ficheros de registro.</p>

    <p>Usando un reinicio <em>graceful</em>, se le puede indicar al
    servidor que abra nuevos ficheros de registro sin perder ninguna
    petici&#243;n siendo servida o en espera de alg&#250;n cliente. Sin
    embargo, para hacer esto, el servidor debe continuar escribiendo
    en los ficheros de registro antiguos mientras termina de servir
    esas peticiones. Por lo tanto, es preciso esperar alg&#250;n
    tiempo despu&#233;s del reinicio antes de realizar ninguna
    operaci&#243;n sobre los antiguos ficheros de registro. Una
    situaci&#243;n t&#237;pica que simplemente rota los registros y
    comprime los registros antiguos para ahorrar espacio es:</p>

    <example>
      mv access_log access_log.old<br />
      mv error_log error_log.old<br />
      apachectl graceful<br />
      sleep 600<br />
      gzip access_log.old error_log.old
    </example>

    <p>Otra manera de realizar la rotaci&#243;n de los registros es
    usando <a href="#piped">ficheros de registro redireccionados
    (piped logs)</a> de la forma en que se explica en la siguiente
    secci&#243;n.</p>
  </section>

  <section id="piped">
    <title>Ficheros de registro redireccionados (Piped Logs)</title>

    <p>Apache httpd es capaz de escribir la informaci&#243;n del
    registro de acceso y errores mediante una redirecci&#243;n a otro
    proceso, en lugar de directamente a un fichero. Esta capacidad
    incrementa de forma muy importante la flexibilidad de registro,
    sin a&#241;adir c&#243;digo al servidor principal. Para escribir
    registros a una redirecci&#243;n, simplemente reemplace el nombre
    de fichero por el car&#225;cter "<code>|</code>", seguido por el
    nombre del ejecutable que deber&#237;a aceptar las entradas de
    registro por su canal de entrada est&#225;ndar. Apache
    iniciar&#225; el proceso de registro redireccionado cuando se
    inicie el servidor, y lo reiniciar&#225; si se produce alg&#250;n
    error irrecuperable durante su ejecuci&#243;n. (Esta &#250;ltima
    funcionalidad es la que hace que se llame a esta t&#233;cnica
    "registro redireccionado fiable".)</p>

    <p>Los procesos de registros son engendrados por el proceso padre
    de Apache httpd, y heredan el identificador de usuario de ese
    proceso. Esto significa que los programas a los que se
    redireccionan los registros se ejecutan normalmente como root. Es
    por ello que es muy importante que los programas sean simples y
    seguros.</p>

    <p>Un uso importante de los registros redireccionados es permitir
    la rotaci&#243;n de los registros sin tener que reiniciar el
    servidor. El servidor Apache HTTP incluye un programa simple
    llamado <program>rotatelogs</program> con este prop&#243;sito. Por
    ejemplo para rotar los registros cada 24 horas, puede usar:</p>

    <example>
      CustomLog "|/usr/local/apache/bin/rotatelogs
      /var/log/access_log 86400" common
    </example>

    <p>Tenga en cuenta que las comillas se usan para abarcar el
    comando entero que ser&#225; invocado por la
    redirecci&#243;n. Aunque estos ejemplos son para el registro de
    acceso, la misma t&#233;cnica se puede usar para el registro de
    errores.</p>

    <p>Otro programa para la rotaci&#243;n de los registros mucho
    m&#225;s flexible llamado <a
    href="http://www.cronolog.org/">cronolog</a> est&#225; disponible
    en un sitio web externo.</p>

    <p>Como ocurre con el registro condicional, la redirecci&#243;n de
    registros es una herramienta muy potente, pero no deben ser usados
    si hay disponible una soluci&#243;n m&#225;s simple de procesado
    posterior de los registros fuera de l&#237;nea.</p>
  </section>

  <section id="virtualhost">
    <title>Hosts Virtuales</title>

    <p>Cuando se est&#225; ejecutando un servidor con muchos <a
    href="vhosts/">hosts virtuales</a>, hay varias formas de abordar
    el asunto de los registros. Primero, es posible usar los registros
    de la misma manera que se usar&#237;an si hubiera solamente un
    host en el servidor. Simplemente poniendo las directivas que
    tienen que ver con los registros fuera de las secciones <directive
    module="core" type="section">VirtualHost</directive> en el
    contexto del servidor principal, puede almacenar toda la
    informaci&#243;n de todas las peticiones en los mismos registros
    de acceso y errores. Esta t&#233;cnica no permite una
    recolecci&#243;n f&#225;cil de las estad&#237;sticas individuales
    de cada uno de los hosts virtuales.</p>

    <p>Si una directiva <directive
    module="mod_log_config">CustomLog</directive> o <directive
    module="core">ErrorLog</directive> se pone dentro una secci&#243;n
    <directive module="core" type="section">VirtualHost</directive>,
    todas las peticiones de ese host virtual se registrar&#225;n
    solamente en el fichero especificado. Las peticiones de cualquier
    host virtual que no tenga directivas de registro espec&#237;ficas
    para &#233;l se registrar&#225;n en los registros del servidor
    principal. Esta t&#233;cnica es muy &#250;til si usa un
    peque&#241;o n&#250;mero de hosts virtuales, pero si usa un gran
    n&#250;mero de ellos, puede ser complicado de
    gestionar. Adem&#225;s, puede a menudo provocar problemas con <a
    href="vhosts/fd-limits.html"> descriptores de fichero
    insuficientes</a>.</p>

    <p>Para el registro de acceso, se puede llegar a un buen
    equilibrio. A&#241;adiendo informaci&#243;n del host virtual al
    formato de registro, es posible registrar las operaciones de todos
    los hosts en un &#250;nico registro, y posteriormente dividir el
    fichero con todos los registros en ficheros individualizados. Por
    ejemplo, considere las siguientes directivas.</p>

    <example>
      LogFormat "%v %l %u %t \"%r\" %&gt;s %b"
      comonvhost<br />
      CustomLog logs/access_log comonvhost
    </example>

    <p>El <code>%v</code> se usa para registrar el nombre del host
    virtual que est&#225; sirviendo la petici&#243;n. Puede usar un
    programa como <a href="programs/other.html">split-logfile</a> para
    procesar posteriormente el registro de acceso y dividirlo en
    ficheros independientes para cada host virtual.</p>
  </section>

  <section id="other">
    <title>Otros ficheros de registro</title>

    <related>
      <modulelist>
        <module>mod_cgi</module>
        <module>mod_rewrite</module>
      </modulelist>
      <directivelist>
        <directive module="mpm_common">PidFile</directive>
        <directive module="mod_rewrite">RewriteLog</directive>
        <directive module="mod_rewrite">RewriteLogLevel</directive>
        <directive module="mod_cgi">ScriptLog</directive>
        <directive module="mod_cgi">ScriptLogBuffer</directive>
        <directive module="mod_cgi">ScriptLogLength</directive>
      </directivelist>
    </related>

    <section id="pidfile">
      <title>Fichero PID (PID File)</title>

      <p>Al iniciar, Apache httpd guarda el identificador del proceso
      padre del servidor en el fichero
      <code>logs/httpd.pid</code>. Puede modificar el nombre de este
      fichero con la directiva <directive
      module="mpm_common">PidFile</directive>. El identificador del
      proceso puede usarlo el administrador para reiniciar y finalizar
      el demonio (daemon) mediante el env&#237;o de se&#241;ales al
      proceso padre; en Windows, use la opci&#243;n de l&#237;nea de
      comandos -k en su lugar.  Para m&#225;s informaci&#243;n al
      respecto, consulte la documentaci&#243;n sobre <a
      href="stopping.html">parar y reiniciar Apache</a>.</p>
    </section>

    <section id="scriptlog">
      <title>Registro de actividad de scripts (Script Log)</title>

      <p>Para ayudar a la detecci&#243;n de errores, la directiva
      <directive module="mod_cgi">ScriptLog</directive> permite
      guardar la entrada y la salida de los scripts CGI. Esta
      directiva solamente deber&#237;a usarla para hacer pruebas - no
      en servidores en producci&#243;n.  Puede encontrar m&#225;s
      informaci&#243;n al respecto en la documentaci&#243;n de <a
      href="mod/mod_cgi.html">mod_cgi</a>.</p>
    </section>

    <section id="rewritelog">
      <title>Registro de actividad de Rewrite (Rewrite Log)</title>

      <p>Cuando use las potentes y complejas funcionalidades de <a
      href="mod/mod_rewrite.html">mod_rewrite</a>, ser&#225; casi
      siempre necesario usar la direcitiva <directive
      module="mod_rewrite">RewriteLog</directive> para ayudar a la
      detecci&#243;n de errores. Este fichero de registro produce un
      an&#225;lisis detallado de c&#243;mo act&#250;a este
      m&#243;dulo sobre las peticiones. El nivel de detalle del
      registro se controla con la directiva <directive
      module="mod_rewrite">RewriteLogLevel</directive>.</p>
    </section>
  </section>
</manualpage>




