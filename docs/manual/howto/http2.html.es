<!DOCTYPE html SYSTEM "about:legacy-compat">
<html lang="es"><head><META http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<meta content="width=device-width, initial-scale=1" name="viewport">
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Gu&iacute;a HTTP/2 - Servidor HTTP Apache Versi&oacute;n 2.4</title>
<link href="../style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet">
<link href="../style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size">
<link href="../style/css/manual-print.css" rel="stylesheet" media="print" type="text/css"><link rel="stylesheet" type="text/css" href="../style/css/prettify.css">
<script src="../style/scripts/prettify.min.js">
</script>

<link href="../images/favicon.png" rel="shortcut icon"></head>
<body id="manual-page"><div id="page-header">
<p class="menu"><a href="../mod/">M&oacute;dulos</a> | <a href="../mod/quickreference.html">Directivas</a> | <a href="https://cwiki.apache.org/confluence/display/httpd/FAQ">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa del sitio web</a> | <a href="https://bz.apache.org/bugzilla/enter_bug.cgi?product=Apache%20httpd-2">Reportar un error</a></p>
<p class="apache">Versi&oacute;n 2.4 del Servidor HTTP Apache</p>
<img alt="" src="../images/feather.png"></div>
<div class="up"><a href="./"><img title="<-" alt="<-" src="../images/left.gif"></a></div>
<div id="path">
<a href="https://www.apache.org/">Apache</a> &gt; <a href="https://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="https://httpd.apache.org/docs/">Documentaci&oacute;n</a> &gt; <a href="../">Versi&oacute;n 2.4</a> &gt; <a href="./">How-To / Tutoriales</a></div><div id="page-content"><div id="preamble"><h1>Gu&iacute;a HTTP/2</h1>
<button aria-label="Toggle language list" class="lang-toggle"><svg xmlns="http://www.w3.org/2000/svg" stroke-width="2" stroke="currentColor" fill="none" viewBox="0 0 24 24" height="16" width="16"><circle r="10" cy="12" cx="12"/><line y2="12" x2="22" y1="12" x1="2"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></button>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="../en/howto/http2.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/howto/http2.html" title="Espa&ntilde;ol">&nbsp;es&nbsp;</a> |
<a href="../fr/howto/http2.html" hreflang="fr" rel="alternate" title="Fran&ccedil;ais">&nbsp;fr&nbsp;</a></p>
</div>
<div class="outofdate">Esta traducci&oacute;n podr&iacute;a estar
            obsoleta. Consulte la versi&oacute;n en ingl&eacute;s de la
            documentaci&oacute;n para comprobar si se han producido cambios
            recientemente.</div>

    <p>
        Esta es la gu&iacute;a para configurar HTTP/2 en Apache httpd. &Eacute;sta caracter&iacute;stica
        est&aacute; <em>lista en produci&oacute;n</em> as&iacute; que es de esperar que las interfaces
        y las directivas se mantengan consistentes en cada veri&oacute;n.
    </p>
  </div>
<div id="quickview"><ul id="toc"><li><img alt="" src="../images/down.gif"> <a href="#protocol">El protocolo HTTP/2</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#implementation">HTTP/2 en Apache httpd</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#building">Compilar httpd con soporte HTTP/2</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#basic-config">Configuraci&oacute;n b&aacute;sica</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#mpm-config">Configuraci&oacute;n MPM</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#clients">Clientes</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#tools">Herramientas &uacute;tiles para depurar HTTP/2</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#push">Server Push</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#earlyhints">"Early Hints"</a></li>
</ul><h3>Consulte tambi&eacute;n</h3><ul class="seealso"><li><code class="module"><a href="../mod/mod_http2.html">mod_http2</a></code></li></ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="protocol">El protocolo HTTP/2 <a title="Enlace permanente" href="#protocol" class="permalink">&para;</a></h2>
    

    <p>HTTP/2 es la evoluci&oacute;n del protocolo de la capa de aplicaci&oacute;n con m&aacute;s
    &eacute;xito, HTTP. Se centra en hacer un uso m&aacute;s eficiente de los recursos de red. 
    No cambia la caracter&iacute;stica fundamental de HTTP, la sem&aacute;ntica. Todav&iacute;a hay 
    olicitudes, respuestas, cabeceras y todo los elementos t&iacute;picos de HTTP/1. As&iacute; 
    que, si ya conoce HTTP/1, tambi&eacute;n conoce el 95% de HTTP/2.</p>
    
    <p>Se ha escrito mucho sobre HTTP/2 y de c&oacute;mo funciona. La norma m&aacute;s
    est&aacute;ndar es, por supuesto, su 
    <a href="https://tools.ietf.org/html/rfc7540">RFC 7540</a> 
    (<a href="http://httpwg.org/specs/rfc7540.html"> tambi&eacute;n disponible en un
    formato m&aacute;s legible, YMMV</a>). As&iacute; que, ah&iacute; encontrar&aacute; toda la especificaci&oacute;n 
    del protocolo.</p>

    <p>Pero, como con todos los RFC, no es ideal como primera lectura. Es mejor
    entender primero <em>qu&eacute;</em> se quiere hacer y despu&eacute;s leer el RFC sobre 
    <em>c&oacute;mo</em> hacerlo. Un documento mucho mejor con el que empezar es
    <a href="https://daniel.haxx.se/http2/">http2 explicado</a>
    por Daniel Stenberg, el autor de <a href="https://curl.haxx.se">curl</a>. 
    &iexcl;Tambi&eacute;n est&aacute; disponible cada vez en un mayor n&uacute;mero lenguajes!</p>
    
    <p>Si le parece demasiado largo, o no lo ha leido, hay algunos t&eacute;rminos
    y elementos a tener en cuenta cuando lea este documento:</p>
    <ul>
        <li>HTTP/2 es un <strong>protocolo binario</strong>, al contrario que 
        HTTP 1.1 que es texto plano. La intenci&oacute;n para HTTP 1.1 es que sea 
        legible (por ejemplo capturando el tr&aacute;fico de red) mientras que para 
        HTTP/2 no. M&aacute;s informaci&oacute;n en el FAQ oficial 
        <a href="https://http2.github.io/faq/#why-is-http2-binary">&iquest;Por qu&eacute; es 
            binario HTTP/2?</a></li>

        <li><strong>h2</strong> es HTTP/2 sobre TLS (negociaci&oacute;n de protocolo a 
        trav&eacute;s de ALPN).</li>

        <li><strong>h2c</strong> es HTTP/2 sobre TCP.</li>

        <li>Un <strong>frame</strong> es la unidad m&aacute;s peque&ntilde;a de comunicaci&oacute;n 
        dentro de una conexi&oacute;n HTTP/2, que consiste en una cabecera y una secuencia 
        de octetos de longitud variable estructurada de acuerdo con el tipo de 
        frame. M&aacute;s informaci&oacute;n en la documentaci&oacute;n oficial 
        <a href="http://httpwg.org/specs/rfc7540.html#FramingLayer">Secci&oacute;n de 
            Capa de Frame</a>.</li>

        <li>Un <strong>stream</strong> es un flujo bidireccional de frames dentro 
        de una conexi&oacute;n HTTP/2. El concepto correspondiente en HTTP 1.1 es un 
        intercambio de mensajes de solicitud/respuesta. M&aacute;s informaci&oacute;n en la 
        documentaci&oacute;n oficial 
        <a href="http://httpwg.org/specs/rfc7540.html#StreamsLayer">Secci&oacute;n Capa 
            de Stream</a>.</li>

        <li>
            HTTP/2 es capaz de llevar <strong>m&uacute;ltiples streams</strong> de datos
            sobre la misma conexi&oacute;n TCP, evitando la cl&aacute;sica solicitud lenta 
            "head-of-line blocking" de HTTP 1.1 y evitando generar m&uacute;ltiples conexiones
            TCP para cada solicitud/respuesta (KeepAlive parche&oacute; el problema en 
            HTTP 1.1 pero no lo resolvi&oacute; completamente).
      </li>
    </ul>
  </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="implementation">HTTP/2 en Apache httpd <a title="Enlace permanente" href="#implementation" class="permalink">&para;</a></h2>
    

    <p>
        El protocolo HTTP/2 se implementa con su propio m&oacute;dulo httpd, llamado 
        acertadamente <code class="module"><a href="../mod/mod_http2.html">mod_http2</a></code>. Incluye el set completo de 
        caracter&iacute;sticas descritas por el RFC 7540 y soporta HTTP/2 sobre texto 
        plano (http:), as&iacute; como conexiones seguras (https:). La variante de texto
        plano se llama '<code>h2c</code>', la segura '<code>h2</code>'. Para 
        <code>h2c</code> permite el modo <em>direct</em>
        y el <code>Upgrade:</code> a trav&eacute;s de una solicitud inicial HTTP/1.
    </p>
    
    <p>
        Una caracter&iacute;stica de HTTP/2 que ofrece capacidades nuevas para 
        desarrolladores de web es <a href="#push">Server Push</a>. Vea esa secci&oacute;n
         para saber como su aplicaci&oacute;n web puede hacer uso de ella.
     </p>
  </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="building">Compilar httpd con soporte HTTP/2 <a title="Enlace permanente" href="#building" class="permalink">&para;</a></h2>
    

    <p>
        <code class="module"><a href="../mod/mod_http2.html">mod_http2</a></code> usa la librer&iacute;a <a href="https://nghttp2.org">
        nghttp2</a>como su implementaci&oacute;n base. Para compilar 
        <code class="module"><a href="../mod/mod_http2.html">mod_http2</a></code> necesita al menos la versi&oacute;n 1.2.1 de 
        <code>libnghttp2</code> instalada en su sistema.
    </p>

    <p>
        Cuando usted ejecuta <code>./configure</code> en el c&oacute;digo fuente de 
        Apache HTTPD, necesita indicarle '<code>--enable-http2</code>' como una 
        opci&oacute;n adicional para activar la compilaci&oacute;n de este m&oacute;dulo. Si su 
        <code>libnghttp2</code> est&aacute; ubicado en una ruta no habitual (cualquiera que 
        sea en su sistema operativo), puede indicar su ubicaci&oacute;n con 
        '<code>--with-nghttp2=&lt;path&gt;</code>' para <code>./configure</code>.
    </p>

    <p>Aunque puede que eso sirva para la mayor&iacute;a, habr&aacute; quien prefiera un <code>nghttp2</code> compilado est&aacute;ticamente para este m&oacute;dulo. Para ellos existe la opci&oacute;n <code>--enable-nghttp2-staticlib-deps</code>. Funciona de manera muy similar a como uno debe enlazar openssl est&aacute;ticamente para <code class="module"><a href="../mod/mod_ssl.html">mod_ssl</a></code>.</p>

    <p>Hablando de SSL, necesita estar al tanto de que la mayor&iacute;a de los navegadores hablan HTTP/2 solo con URLs <code>https:</code>. As&iacute; que necesita un servidor con soporte SSL. Pero no solo eso, necesitar&aacute; una librer&iacute;a SSL que de soporte a la extensi&oacute;n <code>ALPN</code>. Si usa OpenSSL, necesita al menos la versi&oacute;n 1.0.2.</p>
  </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="basic-config">Configuraci&oacute;n b&aacute;sica <a title="Enlace permanente" href="#basic-config" class="permalink">&para;</a></h2>
    

    <p>Cuando tiene un <code>httpd</code> compilado con <code class="module"><a href="../mod/mod_http2.html">mod_http2</a></code> necesita una configuraci&oacute;n b&aacute;sica para activarlo. Lo primero, como con cualquier otro m&oacute;dulo de Apache, es que necesita cargarlo:</p>
    
    <pre class="prettyprint lang-config">LoadModule http2_module modules/mod_http2.so</pre>

    
    <p>La segunda directiva que necesita a&ntilde;adir a la configuraci&oacute;n de su servidor es:</p>

    <pre class="prettyprint lang-config">Protocols h2 http/1.1</pre>

    
    <p>Esto permite h2, la variante segura, para ser el protocolo preferido de las conexiones en su servidor. Cuando quiera habilitar todas las variantes de HTTP/2, entonces simplemente configure:</p>

    <pre class="prettyprint lang-config">Protocols h2 h2c http/1.1</pre>


    <p>Dependiendo de d&oacute;nde pone esta directiva, afecta a todas las conexiones o solo a las de ciertos host virtuales. La puede anidar, como en:</p>

    <pre class="prettyprint lang-config">Protocols http/1.1
&lt;VirtualHost ...&gt;
    ServerName test.example.org
    Protocols h2 http/1.1
&lt;/VirtualHost&gt;</pre>


    <p>Esto solo permite HTTP/1, excepto conexiones SSL hacia <code>test.example.org</code> que ofrecen HTTP/2.</p>

    <div class="note"><h3>Escoger un SSLCipherSuite seguro</h3>
     <p>Es necesario configurar <code class="directive"><a href="../mod/mod_ssl.html#sslciphersuite">SSLCipherSuite</a></code> con una suite segura de cifrado TLS. La versi&oacute;n actual de mod_http2 no fuerza ning&uacute;n cifrado pero la mayor&iacute;a de los clientes si lo hacen. Encaminar un navegador hacia un servidor con <code>h2</code> activado con una suite inapropiada de cifrados forzar&aacute; al navegador a rehusar e intentar conectar por HTTP 1.1. Esto es un error com&uacute;n cuando se configura httpd con HTTP/2 por primera vez, &iexcl;as&iacute; que por favor tenga en cuenta que debe evitar largas sesiones de depuraci&oacute;n! Si quiere estar seguro de la suite de cifrados que escoja, por favor evite los listados en la <a href="http://httpwg.org/specs/rfc7540.html#BadCipherSuites">Lista Negra de TLS para HTTP/2</a>.</p>
    </div>

    <p>El orden de los protocolos mencionados tambi&eacute;n es relevante. Por defecto, el primero es el protocolo preferido. Cuando un cliente ofrece m&uacute;ltiples opciones, la que est&eacute; m&aacute;s a la izquierda ser&aacute; la escogida. En</p>
    <pre class="prettyprint lang-config">Protocols http/1.1 h2</pre>

    
    <p>el protocolo preferido es HTTP/1 y siempre ser&aacute; seleccionado a menos que el cliente <em>s&oacute;lo</em> soporte h2. Puesto que queremos hablar HTTP/2 con clientes que lo soporten, el orden correcto es:</p>
    
    <pre class="prettyprint lang-config">Protocols h2 h2c http/1.1</pre>


    <p>Hay algo m&aacute;s respecto al orden: el cliente tambi&eacute;n tiene sus propias preferencias. Si quiere, puede configurar su servidor para seleccionar el protocolo preferido por el cliente:</p>

    <pre class="prettyprint lang-config">ProtocolsHonorOrder Off</pre>


    <p>Hace que el orden en que <em>usted</em> escribi&oacute; los Protocols sea irrelevante y s&oacute;lo el orden de preferencia del cliente ser&aacute; decisorio.</p>

    <p>Una &uacute;ltima cosa: cuando usted configura los protocolos no se comprueba si son correctos o est&aacute;n bien escritos. Puede mencionar protocolos que no existen, as&iacute; que no hay necesidad de proteger <code class="directive"><a href="../mod/core.html#protocols">Protocols</a></code> con ning&uacute;n <code class="directive"><a href="../mod/core.html#ifmodule">&lt;IfModule&gt;</a></code> de comprobaci&oacute;n.</p>

    <p>Para m&aacute;s consejos avanzados de configuraci&oacute;n, vea la <a href="../mod/mod_http2.html#dimensioning">
    secci&oacute;n de m&oacute;dulos sobre dimensionamiento</a> y <a href="../mod/mod_http2.html#misdirected">
    como gestionar multiples hosts con el mismo certificado</a>.</p>
  </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="mpm-config">Configuraci&oacute;n MPM <a title="Enlace permanente" href="#mpm-config" class="permalink">&para;</a></h2>
    
    
    <p>HTTP/2 est&aacute; soportado en todos los m&oacute;dulos de multi-proceso que se ofrecen con httpd. Aun as&iacute;, si usa el mpm <code class="module"><a href="../mod/prefork.html">prefork</a></code>, habr&aacute;  restricciones severas.</p>

    <p>En <code class="module"><a href="../mod/prefork.html">prefork</a></code>, <code class="module"><a href="../mod/mod_http2.html">mod_http2</a></code> solo procesar&aacute; una solicitud cada vez por conexi&oacute;n. Pero los clientes, como los navegadores, enviar&aacute;n muchas solicitudes al mismo tiempo. Si una de ellas tarda mucho en procesarse (o hace un sondeo que dura m&aacute;s de la cuenta), las otras solicitudes se quedar&aacute;n atascadas.</p>

    <p><code class="module"><a href="../mod/mod_http2.html">mod_http2</a></code> no evitar&aacute; este l&iacute;mite por defecto. El motivo es que <code class="module"><a href="../mod/prefork.html">prefork</a></code> hoy en d&iacute;a solo se escoge si ejecuta motores de proceso que no est&aacute;n preparados para multi-hilo, p.ej. fallar&aacute; con m&aacute;s de una solicitud.</p>

    <p>Si su configuraci&oacute;n lo soporta, hoy en d&iacute;a <code class="module"><a href="../mod/event.html">event</a></code> es el mejor mpm que puede usar.</p>
    
    <p>Si realmente est&aacute; obligado a usar <code class="module"><a href="../mod/prefork.html">prefork</a></code> y quiere multiples solicitudes, puede configurar la directiva <code class="directive"><a href="../mod/mod_http2.html#h2minworkers">H2MinWorkers</a></code> para hacerlo posible. Sin embargo, si esto falla, es bajo su cuenta y riesgo.</p>
  </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="clients">Clientes <a title="Enlace permanente" href="#clients" class="permalink">&para;</a></h2>
    
    
    <p>Casi todos los navegadores modernos dan soporte a HTTP/2, pero solo en conexiones SSL: Firefox (v43), Chrome (v45), Safari (since v9), iOS Safari (v9), Opera (v35), Chrome para Android (v49) e Internet Explorer (v11 en Windows10) (<a href="http://caniuse.com/#search=http2">Fuente</a>).</p>

    <p>Otros clientes, as&iacute; c&oacute;mo otros servidores, est&aacute;n listados en la 
    <a href="https://github.com/http2/http2-spec/wiki/Implementations">wiki de Implementaciones</a>, entre ellos, implementaciones para c, c++, common lisp, dart, erlang, haskell, java, nodejs, php, python, perl, ruby, rust, scala y swift.</p>

    <p>Muchos de las implementaciones de clientes que no son navegadores soportan HTTP/2 sobre texto plano, h2c. La m&aacute;s vers&aacute;til es <a href="https://curl.haxx.se">curl</a>.</p>
  </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="tools">Herramientas &uacute;tiles para depurar HTTP/2 <a title="Enlace permanente" href="#tools" class="permalink">&para;</a></h2>
    

    <p>La primera herramienta a mencionar es por supuesto <a href="https://curl.haxx.se">curl</a>. Por favor aseg&uacute;rese de que su versi&oacute;n soporta HTTP/2 comprobando sus <code>Caracter&iacute;sticas</code>:</p>
    <pre class="prettyprint lang-config">    $ curl -V
    curl 7.45.0 (x86_64-apple-darwin15.0.0) libcurl/7.45.0 OpenSSL/1.0.2d zlib/1.2.8 nghttp2/1.3.4
    Protocols: dict file ftp ftps gopher http https imap imaps ldap ldaps pop3 [...] 
    Features: IPv6 Largefile NTLM NTLM_WB SSL libz TLS-SRP <strong>HTTP2</strong>
    </pre>

    <div class="note"><h3>Notas sobre Mac OS homebrew</h3>
    brew install curl --with-openssl --with-nghttp2 
    </div>
    <p>Y para una inspecci&oacute;n en gran profundidad <a href="https://wiki.wireshark.org/HTTP2">wireshark</a>.</p>
    <p>El paquete <a href="https://nghttp2.org">nghttp2</a> tambi&eacute;n incluye clientes, tales como:</p>
    <ul>
        <li><a href="https://nghttp2.org/documentation/nghttp.1.html">nghttp
        </a> - util para visualizar la frames de HTTP/2 y tener una mejor idea de como funciona el protocolo.</li>
        <li><a href="https://nghttp2.org/documentation/h2load-howto.html">h2load</a> - &uacute;til para hacer un stress-test de su servidor.</li>
    </ul>

    <p>Chrome ofrece logs detallados de HTTP/2 en sus conexiones a trav&eacute;s de la <a href="chrome://net-internals/#http2">p&aacute;gina especial de net-internals</a>. Tambi&eacute;n hay una extensi&oacute;n interesante para <a href="https://chrome.google.com/webstore/detail/http2-and-spdy-indicator/mpbpobfflnpcgagjijhmgnchggcjblin?hl=en">Chrome</a> y <a href="https://addons.mozilla.org/en-us/firefox/addon/spdy-indicator/">Firefox</a> con la que visualizar cuando su navegador usa HTTP/2.</p>
  </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="push">Server Push <a title="Enlace permanente" href="#push" class="permalink">&para;</a></h2>
    
    
    <p>El protocolo HTTP/2 permite al servidor hacer PUSH de respuestas a un cliente que nunca las solicit&oacute;. El tono de la conversaci&oacute;n es: "Aqu&iacute; tiene una solicitud que nunca envi&oacute; y la respuesta llegar&aacute; pronto..."</p>

    <p>Pero hay restricciones: el cliente puede deshabilitar esta caracter&iacute;stica y el servidor entonces solo podr&aacute; hacer PUSH en una solicitud que hizo previamente del cliente.</p>

    <p>La intenci&oacute;n es permitir al servidor enviar recursos que el cliente seguramente vaya a necesitar, p. ej. un recurso css o javascript que pertenece a una p&aacute;gina html que el cliente solicit&oacute;, un grupo de im&aacute;genes a las que se hace referencia en un css, etc.</p>

    <p>La ventaja para el cliente es que ahorra tiempo para solicitudes que pueden tardar desde unos pocos milisegundos a medio segundo, dependiendo de la distancia entre el cliente y el servidor. La desventaja es que el cliente puede recibir cosas que ya tiene en su cache. Por supuesto que HTTP/2 soporta cancelaci&oacute;n previa de tales solicitudes, pero aun as&iacute; se malgastan recursos.</p>

    <p>Resumiendo: no hay una estrategia mejor sobre c&oacute;mo usar esta caracter&iacute;stica de HTTP/2 y todo el mundo est&aacute; experimentando con ella. As&iacute; que, &iquest;c&oacute;mo experimenta usted con ella en Apache httpd?</p>

    <p><code class="module"><a href="../mod/mod_http2.html">mod_http2</a></code> busca e inspecciona las cabeceras de respuesta 
    <code>Link</code> con cierto formato:</p>

    <pre class="prettyprint lang-config">Link &lt;/xxx.css&gt;;rel=preload, &lt;/xxx.js&gt;; rel=preload</pre>


    <p>
        Si la conexi&oacute;n soporta PUSH, estos dos recursos se enviar&aacute;n al cliente. 
        Como desarrollador web, puede configurar estas cabeceras o bien 
        directamente en la respuesta de su aplicaci&oacute;n o configurar su servidor con:
    </p>

    <pre class="prettyprint lang-config">&lt;Location /xxx.html&gt;
    Header add Link "&lt;/xxx.css&gt;;rel=preload"
    Header add Link "&lt;/xxx.js&gt;;rel=preload"
&lt;/Location&gt;</pre>


    <p>Si quiere usar enlaces con <code>preload</code> sin activar un PUSH, puede
    usar el par&aacute;metro <code>nopush</code>, como en:</p>

    <pre class="prettyprint lang-config">Link &lt;/xxx.css&gt;;rel=preload;nopush</pre>


    <p>o puede desactivar PUSH para su servidor por completo con la directiva </p>

    <pre class="prettyprint lang-config">H2Push Off</pre>


    <p>Y hay m&aacute;s:</p>

    <p>
        El m&oacute;dulo mantiene un registro de lo que se ha enviado con PUSH para cada
        conexi&oacute;n (hashes de URLs, b&aacute;sicamente) y no har&aacute; PUSH del mismo recurso dos
        veces. Cuando la conexi&oacute;n se cierra, la informaci&oacute;n es descartada.
    </p>

    <p>
        Hay gente pensando c&oacute;mo un cliente puede decirle al servidor lo que ya
        tiene, para evitar los PUSH de esos elementos, pero eso algo muy
        experimental ahora mismo.
    </p>

    <p>Otro borrador experimental que ha sido implementado en 
    <code class="module"><a href="../mod/mod_http2.html">mod_http2</a></code> es el <a href="https://tools.ietf.org/html/draft-ruellan-http-accept-push-policy-00"> Campo de Cabecera
    Accept-Push-Policy</a> en la que un cliente puede, para cada solicitud, definir 
    qu&eacute; tipo de PUSH acepta.</p>

    <p>
        Puede que PUSH no siempre lance la peticion/respuesta/funcionamiento que
        uno espera. Hay varios estudios sobre este tema en internet, que explican
        el beneficio y las debilidades de como diferentes funcionalidades del
        cliente y de la red influyen en el resultado.
        Por Ejemplo, que un servidor haga "PUSH" de recursos, no significa que el 
        navegador vaya a usar dichos datos.
    </p>
    <p>
        Lo m&aacute;s importante que influye en la respuesta que se env&iacute;a, es la solicitud
        que se simul&oacute;. La url de solicitud de un PUSH es dada por la aplicaci&oacute;n,
        pero &iquest;de donde vienen las cabeceras de la petici&oacute;n? por ejemplo si el PUSH
        pide una cabecera <code>accept-language</code> y si es as&iacute;, &iquest;con qu&eacute; valor?
    </p>
    <p>Httpd mirar&aacute; la petici&oacute;n original (la que origin&oacute; el PUSH) y copiar&aacute; las
        siguientes cabeceras a las peticiones PUSH:
        <code>user-agent</code>, <code>accept</code>, <code>accept-encoding</code>,
        <code>accept-language</code>, <code>cache-control</code>.
    </p>
    <p>
        Todas las otras cabeceras son ignorados. Las cookies tampoco ser&aacute;n copiadas.
        Impulsar los recursos que requieren una cookie para estar presente no
        funcionar&aacute;. Esto puede ser una cuesti&oacute;n de debate. Pero a menos que esto se
        discuta m&aacute;s claramente con el navegador, evitemos el exceso de precauci&oacute;n y
        no expongamos las cookies donde podr&iacute;an o no ser visibles.
    </p>

</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="earlyhints">"Early Hints" <a title="Enlace permanente" href="#earlyhints" class="permalink">&para;</a></h2>
    

    <p>Una alternativa de "Pushear" recursos es mandar una cabecera 
        <code>Link</code> al cliente antes que la respuesta est&eacute; lista. Esto usa
        una caracteristica de HTTP que se llama  "Early Hints" y est&aacute; descrita en
        la <a href="https://tools.ietf.org/html/rfc8297">RFC 8297</a>.</p>
    <p>Para poder usar esto, necesita habilitarlo explicitamente en el servidor 
    via</p>
    
    <pre class="prettyprint lang-config">H2EarlyHints on</pre>

    
    <p>(No est&aacute; habilitado por defecto ya q ue algunos navegadores m&aacute;s antiguos 
        se caen con dichas  respuestas.)
    </p>

    <p>si esta funcionalidad esta activada, puede usar la directiva 
        <code class="directive"><a href="../mod/mod_http2.html#h2pushresource">H2PushResource</a></code> para que lance 
        "Early hints" y recursos mediante push:
    </p>
    <pre class="prettyprint lang-config">&lt;Location /xxx.html&gt;
    H2PushResource /xxx.css
    H2PushResource /xxx.js
&lt;/Location&gt;</pre>

    <p>
        Esto lanzar&aacute; una respuesta <code>"103 Early Hints"</code> a un cliente 
        tan pronto como el servidor <em>comience</em> a procesar la solicitud. 
        Esto puede ser mucho antes que en el momento en que se determinaron los 
        primeros encabezados de respuesta, dependiendo de su aplicaci&oacute;n web.
    </p>

    <p>
        Si la directiva <code class="directive"><a href="../mod/mod_http2.html#h2push">H2Push</a></code> est&aacute; 
        habilitada, esto comenzar&aacute; el PUSH justo despu&eacute;s de la respuesta 103.
        Sin embargo, si la directiva <code class="directive"><a href="../mod/mod_http2.html#h2push">H2Push</a></code> est&aacute; dehabilitada, la respuesta 103 se le enviar&aacute; al cliente.
    </p>
  </div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="../en/howto/http2.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/howto/http2.html" title="Espa&ntilde;ol">&nbsp;es&nbsp;</a> |
<a href="../fr/howto/http2.html" hreflang="fr" rel="alternate" title="Fran&ccedil;ais">&nbsp;fr&nbsp;</a></p>
</div><div id="footer">
<p class="apache">Copyright 2026 The Apache Software Foundation.<br>Licencia bajo los t&eacute;rminos de la <a href="https://www.apache.org/licenses/LICENSE-2.0">Apache License, Version 2.0</a>.</p>
<p class="menu"><a href="../mod/">M&oacute;dulos</a> | <a href="../mod/quickreference.html">Directivas</a> | <a href="https://cwiki.apache.org/confluence/display/httpd/FAQ">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa del sitio web</a> | <a href="https://bz.apache.org/bugzilla/enter_bug.cgi?product=Apache%20httpd-2">Reportar un error</a></p></div><script><!--//--><![CDATA[//><!--
if (typeof(prettyPrint) !== 'undefined') {
    prettyPrint();
}
var langToggle = document.querySelector('.lang-toggle');
var topLang = document.querySelector('.toplang');
if (langToggle && topLang) {
    langToggle.addEventListener('click', function() { topLang.classList.toggle('open'); });
}
var qv = document.getElementById('quickview');
if (qv) {
    document.body.appendChild(qv);
    var qvBtn = document.createElement('button');
    qvBtn.className = 'qv-toggle';
    qvBtn.setAttribute('aria-label', 'Toggle page navigation');
    qvBtn.innerHTML = '&#9776;';
    document.body.appendChild(qvBtn);
    qvBtn.addEventListener('click', function() {
        var isOpen = qv.classList.toggle('open');
        if (isOpen) {
            qv.style.top = window.scrollY + 10 + 'px';
        }
    });
    window.addEventListener('scroll', function() { qv.classList.remove('open'); });
}
//--><!]]></script>
</body></html>