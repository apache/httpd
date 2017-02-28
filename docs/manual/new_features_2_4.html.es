<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es" xml:lang="es"><head>
<meta content="text/html; charset=ISO-8859-1" http-equiv="Content-Type" />
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Informaci&#243;n General sobre las Nuevas Caracter&#237;sticas en Apache HTTP Server 2.4 - Servidor HTTP Apache Versi&#243;n 2.5</title>
<link href="./style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet" />
<link href="./style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size" />
<link href="./style/css/manual-print.css" rel="stylesheet" media="print" type="text/css" /><link rel="stylesheet" type="text/css" href="./style/css/prettify.css" />
<script src="./style/scripts/prettify.min.js" type="text/javascript">
</script>

<link href="./images/favicon.ico" rel="shortcut icon" /></head>
<body id="manual-page"><div id="page-header">
<p class="menu"><a href="./mod/">M&#243;dulos</a> | <a href="./mod/quickreference.html">Directivas</a> | <a href="http://wiki.apache.org/httpd/FAQ">Preguntas Frecuentes</a> | <a href="./glossary.html">Glosario</a> | <a href="./sitemap.html">Mapa del sitio web</a></p>
<p class="apache">Versi&#243;n 2.5 del Servidor HTTP Apache</p>
<img alt="" src="./images/feather.png" /></div>
<div class="up"><a href="./"><img title="&lt;-" alt="&lt;-" src="./images/left.gif" /></a></div>
<div id="path">
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs/">Documentaci&#243;n</a> &gt; <a href="./">Versi&#243;n 2.5</a></div><div id="page-content"><div id="preamble"><h1>Informaci&#243;n General sobre las Nuevas Caracter&#237;sticas en Apache HTTP Server 2.4</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="./en/new_features_2_4.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/new_features_2_4.html" title="Espa&#241;ol">&nbsp;es&nbsp;</a> |
<a href="./fr/new_features_2_4.html" hreflang="fr" rel="alternate" title="Fran&#231;ais">&nbsp;fr&nbsp;</a> |
<a href="./tr/new_features_2_4.html" hreflang="tr" rel="alternate" title="T&#252;rk&#231;e">&nbsp;tr&nbsp;</a></p>
</div>

  <p>Este documento describe algunos de los principales cambios entre las  versiones
     2.2 y 2.4 del Servidor Apache HTTP. Para las nuevas caracter&#237;sticas desde
     versi&#243;n 2.0, consulte el  documento <a href="new_features_2_2.html"> 2.2 nuevas caracter&#237;sticas.</a></p>
</div>
<div id="quickview"><ul id="toc"><li><img alt="" src="./images/down.gif" /> <a href="#core">Mejoras en el Core</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#newmods">Nuevos M&#243;dulos</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#module">Mejoras de M&#243;dulos.</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#programs">Mejoras para el Programa</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#documentation">Documentaci&#243;n</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#developer">Cambios en los Desarrollos de M&#243;dulos</a></li>
</ul><h3>Consulte tambi&#233;n</h3><ul class="seealso"><li><a href="#comments_section">Comentarios</a></li></ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="core" id="core">Mejoras en el Core</a></h2>
    
    <dl>
      <dt>Cargas de  MPM en Tiempo de Ejecuci&#243;n</dt>
      <dd>M&#250;ltiples MPMs ahora se pueden <a href="mpm.html#dynamic"> construir 
      como m&#243;dulos din&#225;micos </a>de forma  que pueden ser cargados en tiempo de compilaci&#243;n.
      El MPM de elecci&#243;n se puede configurar en tiempo de ejecuci&#243;n a trav&#233;s 
      de <code class="directive"><a href="./mod/mod_so.html#loadmodule"> LoadModule </a></code>.</dd>

      <dt>Evento MPM</dt>
      <dd>El <a href="mod/event.html">Evento MPM</a> ya no es experimental, lo cu&#225;l ahora est&#225; totalmente soportado.</dd>

      <dt>Soporte As&#237;ncrono (Asynchronous)</dt>
      <dd>Mejor soporte para lectura y escritura as&#237;ncrona para soporte de MPM y
      otras plataformas.</dd>

      <dt>Configuraci&#243;n del Nivel de Log (LogLevel) por M&#243;dulo y Directorio</dt>
      <dd>El <code class="directive"><a href="./mod/core.html#loglevel">LogLevel</a></code>  puede ser configurado ahora 
      por m&#243;dulo y por directorio. Nuevos niveles de <code>trace1</code>
      a <code>trace8</code> se han a&#241;adido por encima de la etiqueta  de nivel de 
      registro de log <code>debug</code>.</dd>

      <dt>Secciones de Configuraci&#243;n por Petici&#243;n</dt>
      <dd><code class="directive"><a href="./mod/core.html#if">&lt;If&gt;</a></code>,
          <code class="directive"><a href="./mod/core.html#elseif">&lt;ElseIf&gt;</a></code>,
          y <code class="directive"><a href="./mod/core.html#else">&lt;Else&gt;</a></code> se pueden usar 
          para establecer los criterios de configuraci&#243;n por cada petici&#243;n.</dd>

      <dt>Analizador de Expresi&#243;n de Uso General</dt>
      <dd>Un nuevo analizador de expresiones permite especificar
          <a href="expr.html">condiciones complejas</a> utilizando una sintaxis com&#250;n
          en directivas como
          <code class="directive"><a href="./mod/mod_setenvif.html#setenvifexpr">SetEnvIfExpr</a></code>,
          <code class="directive"><a href="./mod/mod_rewrite.html#rewritecond">RewriteCond</a></code>,
          <code class="directive"><a href="./mod/mod_headers.html#header">Header</a></code>,
          <code class="directive"><a href="./mod/core.html#if">&lt;If&gt;</a></code>,
          entre otras.
      </dd>

      <dt>KeepAliveTimeout en Milisegundos</dt>
      <dd>Ahora es posible especificar <code class="directive"><a href="./mod/core.html#keepalivetimeout">KeepAliveTimeout</a></code> en milisegundos.
      </dd>

      <dt>Directiva NameVirtualHost</dt>
      <dd>Ya no es necesario y ahora est&#225; en desuso.</dd>

      <dt>Anular Configuraci&#243;n</dt>
      <dd>La nueva directiva <code class="directive"><a href="./mod/core.html#allowoverridelist">AllowOverrideList</a></code>
          permite un control m&#225;s exhaustivo de que directivas se permiten en los archivos <code>.htaccess</code>.</dd>

      <dt>Variables de los Archivos de Configuraci&#243;n</dt>
      <dd>Ahora es posible <code class="directive"><a href="./mod/core.html#definir">Definir</a></code>
          variables en la configuraci&#243;n, lo que permite una representaci&#243;n m&#225;s clara
          si el mismo valor se utiliza en muchos lugares en la configuraci&#243;n.
      </dd>

      <dt>Reducci&#243;n del Uso de Memoria</dt>
      <dd>A pesar de muchas de las nuevas caracter&#237;sticas, 2.4.x tiende a usar menos 
      	memoria que la versi&#243;n 2.2.x. </dd>

    </dl>
  </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="newmods" id="newmods">Nuevos M&#243;dulos</a></h2>
    
    <dl>
      <dt><code class="module"><a href="./mod/mod_proxy_fcgi.html">mod_proxy_fcgi</a></code></dt>
      <dd>Protocolo FastCGI backend para<code class="module"><a href="./mod/mod_proxy.html">mod_proxy</a></code></dd>

      <dt><code class="module"><a href="./mod/mod_proxy_scgi.html">mod_proxy_scgi</a></code></dt>
      <dd>Protocolo SCGI backend para <code class="module"><a href="./mod/mod_proxy.html">mod_proxy</a></code></dd>

      <dt><code class="module"><a href="./mod/mod_proxy_express.html">mod_proxy_express</a></code></dt>
      <dd>Proporciona una configuraci&#243;n masiva y din&#225;mica de proxys inversos para
      <code class="module"><a href="./mod/mod_proxy.html">mod_proxy</a></code></dd>

      <dt><code class="module"><a href="./mod/mod_remoteip.html">mod_remoteip</a></code></dt>
      <dd>Reemplaza la direcci&#243;n IP remota cliente aparente y nombre de host para la solicitud
      con la lista de direcciones IP presentada por un proxy o un balanceador de carga a trav&#233;s de
      las cabeceras de solicitud.</dd>

      <dt><code class="module"><a href="./mod/mod_heartmonitor.html">mod_heartmonitor</a></code>,
          <code class="module"><a href="./mod/mod_lbmethod_heartbeat.html">mod_lbmethod_heartbeat</a></code></dt>
      <dd>Permite a <code class="module"><a href="./mod/mod_proxy_balancer.html">mod_proxy_balancer</a></code> basar las decisiones del balanceo de 
      carga seg&#250;n el n&#250;mero de conexiones activas en los servidores de back-end.</dd>

      <dt><code class="module"><a href="./mod/mod_proxy_html.html">mod_proxy_html</a></code></dt>
      <dd>antiguamente un m&#243;dulo de terceros, esto apoya la fijaci&#243;n de enlaces HTML en un proxy inverso,
situaci&#243;n en la que el servidor genera URLs que no son v&#225;lidos para los clientes del proxy.</dd>

      <dt><code class="module"><a href="./mod/mod_sed.html">mod_sed</a></code></dt>
      <dd>Un reemplazo avanzado de <code class="module"><a href="./mod/mod_substitute.html">mod_substitute</a></code>, permite editar el 
      cuerpo de la respuesta con el poder lleno de sed.</dd>

      <dt><code class="module"><a href="./mod/mod_auth_form.html">mod_auth_form</a></code></dt>
      <dd>Habilitar la autenticaci&#243;n basada en formularios.</dd>

      <dt><code class="module"><a href="./mod/mod_session.html">mod_session</a></code></dt>
      <dd>Permite el uso de estado de sesi&#243;n para clientes, utilizando cookies o el 
      	almacenamiento en una base de datos.</dd>

      <dt><code class="module"><a href="./mod/mod_allowmethods.html">mod_allowmethods</a></code></dt>
      <dd>Nuevo m&#243;dulo para restringir ciertos m&#233;todos HTTP sin interferir con
      autenticaci&#243;n o autorizaci&#243;n.</dd>

      <dt><code class="module"><a href="./mod/mod_lua.html">mod_lua</a></code></dt>
      <dd>Embebe el lenguaje<a href="http://www.lua.org/">Lua</a> en httpd,
      para la configuraci&#243;n y las funciones l&#243;gicas de negocios peque&#241;os. (Experimental)</dd>

      <dt><code class="module"><a href="./mod/mod_log_debug.html">mod_log_debug</a></code></dt>
      <dd>Permite a&#241;adir mensajes de depuraci&#243;n personalizados en las diferentes fases del procesamiento de la solicitud.</dd>

      <dt><code class="module"><a href="./mod/mod_buffer.html">mod_buffer</a></code></dt>
      <dd>Proporciona almacenamiento en b&#250;fer para los filtros de entrada y salida de las pilas</dd>

      <dt><code class="module"><a href="./mod/mod_data.html">mod_data</a></code></dt>
      <dd>Convierte la respuesta del cuerpo en una direcci&#243;n URL de datos RFC2397</dd>

      <dt><code class="module"><a href="./mod/mod_ratelimit.html">mod_ratelimit</a></code></dt>
      <dd>Proporciona limitaci&#243;n de velocidad en el ancho de banda para los clientes</dd>

      <dt><code class="module"><a href="./mod/mod_request.html">mod_request</a></code></dt>
      <dd>Proporciona filtros para manejar y hacer el cuerpo de la petici&#243;n HTTP disponibles</dd>

      <dt><code class="module"><a href="./mod/mod_reflector.html">mod_reflector</a></code></dt>
      <dd>Proporciona Reflexi&#243;n del cuerpo de la petici&#243;n como una respuesta a trav&#233;s de la pila de filtro de salida.</dd>

      <dt><code class="module"><a href="./mod/mod_slotmem_shm.html">mod_slotmem_shm</a></code></dt>
      <dd>Proporciona un proveedor de memoria compartida basada en la ranura (ala the scoreboard).</dd>

      <dt><code class="module"><a href="./mod/mod_xml2enc.html">mod_xml2enc</a></code></dt>
      <dd>Anteriormente un m&#243;dulo de terceros, que apoya la internacionalizaci&#243;n en
      m&#243;dulos de filtro (markup-aware) basada en libxml2.</dd>

      <dt><code class="module"><a href="./mod/mod_macro.html">mod_macro</a></code> (disponible desde la versi&#243;n 2.4.5)</dt>
      <dd>Provee macros para los archivos de configuraci&#243;n</dd>

      <dt><code class="module"><a href="./mod/mod_proxy_wstunnel.html">mod_proxy_wstunnel</a></code> (disponible desde la versi&#243;n 2.4.5)</dt>
      <dd>Soporte a t&#250;neles web-socket.</dd>

      <dt><code class="module"><a href="./mod/mod_authnz_fcgi.html">mod_authnz_fcgi</a></code> (disponible desde la versi&#243;n 2.4.10)</dt>
      <dd>Habilitar aplicaciones autorizadas FastCGI para autenticar y/o autorizar a los clientes.</dd>

      <dt><code class="module"><a href="./mod/mod_http2.html">mod_http2</a></code> (disponible desde la versi&#243;n 2.4.17)</dt>
      <dd>Soporte para la capa HTTP/2</dd>

    </dl>
  </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="module" id="module">Mejoras de M&#243;dulos.</a></h2>
    
    <dl>
      <dt><code class="module"><a href="./mod/mod_ssl.html">mod_ssl</a></code></dt>

      <dd><code class="module"><a href="./mod/mod_ssl.html">mod_ssl</a></code> ahora puede ser configurado para utilizar un servidor 
      OCSP para comprobar el estado de validez de un certificado de cliente. La respuesta por 
      defecto es configurable, junto con la decisi&#243;n sobre si se debe preferir el "responder"
       designado en el certificado de cliente en s&#237;.</dd>

      <dd><code class="module"><a href="./mod/mod_ssl.html">mod_ssl</a></code> ahora tambi&#233;n es compatible con "OCSP stapling", 
      una respuesta de OCSP al inicial TLS "Handshake" con marca de tiempo 
      firmado por la CA , en el que el servidor obtiene de forma proactiva 
      una verificaci&#243;n OCSP de su certificado y transmite esa o la del cliente
       durante el  "Handshake".</dd>


      <dd><code class="module"><a href="./mod/mod_ssl.html">mod_ssl</a></code> Ahora se puede configurar para compartir los datos de 
      sesi&#243;n SSL entre servidores a trav&#233;s de memcached.</dd>

      <dd>Claves de cifrado de tipo EC (Curva El&#237;ptica en Ingl&#233;s) son ahora 
      	soportadas junto con RSA y DSA.</dd>

      <dd>Soporte de TLS-SRP (disponible en la versi&#243;n 2.4.4 y posteriores).</dd>

      <dt><code class="module"><a href="./mod/mod_proxy.html">mod_proxy</a></code></dt>

      <dd>La directiva <code class="directive"><a href="./mod/mod_proxy.html#proxypass">ProxyPass</a></code> 
      ahora est&#225; configurado de forma m&#225;s &#243;ptima dentro de un bloque
      <code class="directive"><a href="./mod/core.html#location">Location</a></code> o
      <code class="directive"><a href="./mod/core.html#locationmatch">LocationMatch</a></code>,
      y ofrece una ventaja de rendimiento significativa sobre la sintaxis tradicional
      de dos par&#225;metros cuando est&#225;n presentes en gran n&#250;mero.</dd>
      <dd>La direcci&#243;n de origen utilizada para solicitudes de proxy es ahora configurable.</dd>
      <dd>Soporte para sockets de dominio Unix en el backend (disponible en la versi&#243;n 2.4.7
      y posteriores).</dd>

      <dt><code class="module"><a href="./mod/mod_proxy_balancer.html">mod_proxy_balancer</a></code></dt>

      <dd>M&#225;s cambios en la configuraci&#243;n en tiempo de ejecuci&#243;n para BalancerMembers 
      	mediante el manager del balanceador.</dd>

      <dd>Se pueden agregar miembros adicionales a BalancerMembers en tiempo de ejecuci&#243;n 
      	mediante el manager del balanceador.</dd>

      <dd>Configuraci&#243;n de ejecuci&#243;n de un subconjunto de par&#225;metros Balancer</dd>

      <dd>BalancerMembers se puede establecer en "fuga" de modo que s&#243;lo responden a las 
      	sesiones problem&#225;ticas existentes, lo que les permite ser puestos con gracia fuera de l&#237;nea.</dd>

      <dd>Configuraci&#243;n del balanceador de carga pueden ser persistentes despu&#233;s de un reinicio.</dd>

      <dt><code class="module"><a href="./mod/mod_cache.html">mod_cache</a></code></dt>

      <dd>En el m&#243;dulo <code class="module"><a href="./mod/mod_cache.html">mod_cache</a></code> se puede a&#241;adir filtro de cache en determinado 
      punto en la cadena de filtro, para proveer mejor control de la cach&#233;</dd>

      <dd><code class="module"><a href="./mod/mod_cache.html">mod_cache</a></code> Puede cachear ahora peticiones de tipo HEAD.</dd>
      <dd>Siendo posible ahora las directivas <code class="module"><a href="./mod/mod_cache.html">mod_cache</a></code>
      ser configuradas por directorio en vez de por servidor.</dd>

      <dd>La URL base de las URLs cacheadas se pueden personalizar, 
      de tal forma que un cluster de cach&#233;s puede compartir el mismo
      prefijo URL de punto final.</dd>

      <dd><code class="module"><a href="./mod/mod_cache.html">mod_cache</a></code> ahora es capaz de servir a los datos en cach&#233; 
      antigua cuando un motor no est&#225; disponible (error 5xx).</dd>

      <dd><code class="module"><a href="./mod/mod_cache.html">mod_cache</a></code> ahora puede insertar HIT/MISS/REVALIDATE 
      en una cabecera de tipo X-Cache.</dd>

      <dt><code class="module"><a href="./mod/mod_include.html">mod_include</a></code></dt>
      <dd>Soporte al atributo 'onerror' dentro del elemento 'include', lo que permite
      mostar un documento de error cuando hay un error en vez de la cadena de error por defecto.
      </dd>

      <dt><code class="module"><a href="./mod/mod_cgi.html">mod_cgi</a></code>, <code class="module"><a href="./mod/mod_include.html">mod_include</a></code>,
          <code class="module"><a href="./mod/mod_isapi.html">mod_isapi</a></code>, ...</dt>
      <dd>La traducci&#243;n de cabeceras a variables de entorno es m&#225;s estricta que antes para mitigar 
      algunos de los posibles ataques de cross-site scripting, a trav&#233;s de la inyecci&#243;n de cabecera. 
      Las cabeceras que contienen car&#225;cteres no v&#225;lidos (incluyendo guiones bajos)
      son descartadas de forma silenciosa. <a href="env.html">Las variables de entorno en
      Apache</a> tienen algunos consejos en como trabajar con clientes con sistemas heredados rotos que 
      requieren de este tipo de cabeceras. (Esto afecta a todos los m&#243;dulos que 
      usan &#233;stas variables de entorno.)</dd>

      <dt><code class="module"><a href="./mod/mod_authz_core.html">mod_authz_core</a></code> Autorizaci&#243;n L&#243;gica de Contenedores</dt>

      <dd>Ahora puede ser especificada una l&#243;gica avanzada de autorizaci&#243;n, usando la directiva 
          <code class="directive"><a href="./mod/mod_authz_core.html#require">Require</a></code> y 
          las directivas de los contenedores asociados, tales como
          <code class="directive"><a href="./mod/mod_authz_core.html#requireall">&lt;RequireAll&gt;</a></code>.</dd>

      <dt><code class="module"><a href="./mod/mod_rewrite.html">mod_rewrite</a></code></dt>
      <dd><code class="module"><a href="./mod/mod_rewrite.html">mod_rewrite</a></code> a&#241;ade los flags <code>[QSD]</code>
          (Query String Discard) y <code>[END]</code> para las directivas
          <code class="directive"><a href="./mod/mod_rewrite.html#rewriterule">RewriteRule</a></code> para 
          simplificar escenarios de reescritura comunes.</dd>
      <dd>A&#241;ade la posibilidad de usar expresiones buleanas complejas en <code class="directive"><a href="./mod/mod_rewrite.html#rewritecond">RewriteCond</a></code>.</dd>
      <dd>Permite el uso de queris SQL como funciones de <code class="directive"><a href="./mod/mod_rewrite.html#rewritemap">RewriteMap</a></code>.</dd>

      <dt><code class="module"><a href="./mod/mod_ldap.html">mod_ldap</a></code>, <code class="module"><a href="./mod/mod_authnz_ldap.html">mod_authnz_ldap</a></code></dt>
      <dd><code class="module"><a href="./mod/mod_authnz_ldap.html">mod_authnz_ldap</a></code> agrega soporte a grupos anidados.</dd>
      <dd><code class="module"><a href="./mod/mod_ldap.html">mod_ldap</a></code> Incorpora
          <code class="directive"><a href="./mod/mod_ldap.html#ldapconnectionpoolttl">LDAPConnectionPoolTTL</a></code>,
          <code class="directive"><a href="./mod/mod_ldap.html#ldaptimeout">LDAPTimeout</a></code>, y otras mejoras
           en el manejo de los "timeouts" tiempo agotado de espera.
          Esto es especialmente &#250;til para escenarios en los que existe un firewall 
          en modo "Stateful" que desecha conexiones inactivas a un servidor LDAP.</dd>
      <dd><code class="module"><a href="./mod/mod_ldap.html">mod_ldap</a></code> Incorpora
          <code class="directive"><a href="./mod/mod_ldap.html#ldaplibrarydebug">LDAPLibraryDebug</a></code> para registrar informaci&#243;n de 
          depuraci&#243;n proporcionada por el conjunto de herramientas usadas por LDAP.</dd>

      <dt><code class="module"><a href="./mod/mod_info.html">mod_info</a></code></dt>
      <dd><code class="module"><a href="./mod/mod_info.html">mod_info</a></code> ahora puede volcar la configuraci&#243;n pre-procesada
      a la salida est&#225;ndar durante el inicio del servidor.</dd>

      <dt><code class="module"><a href="./mod/mod_auth_basic.html">mod_auth_basic</a></code></dt>
      <dd>Nuevo mecanismo gen&#233;rico para la autenticaci&#243;n b&#225;sica falsa (disponible en la versi&#243;n
      2.4.5 y posteriores).</dd>

    </dl>
  </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="programs" id="programs">Mejoras para el Programa</a></h2>
    
    <dl>
        <dt><code class="program"><a href="./programs/fcgistarter.html">fcgistarter</a></code></dt>
        <dd>Nuevo demonio FastCGI como utilidad de arranque</dd>

        <dt><code class="program"><a href="./programs/htcacheclean.html">htcacheclean</a></code></dt>
        <dd>Ahora las URLs cacheadas actualmente, pueden ser listadas, con meta-datos adicionales incluidos.</dd>
        <dd>Permite el borrado explicito y selectivo de URLs cacheadas.</dd>
        <dd>Los tama&#241;os de archivo ahora se pueden redondear hasta el tama&#241;o de bloque determinado,
        por lo que los l&#237;mites de tama&#241;o se asemeja m&#225;s estrechamente con el tama&#241;o real en el disco.</dd>
        <dd>El tama&#241;o de la cach&#233; ahora puede ser limitado por el n&#250;mero de i-nodos, 
        en vez de o como a&#241;adido, al limite del tama&#241;o del archivo en el disco.</dd>

        <dt><code class="program"><a href="./programs/rotatelogs.html">rotatelogs</a></code></dt>
        <dd>Ahora puede crear un enlace al propio fichero de log.</dd>
        <dd>Ahora puede invocar a un escript personalizado pos-rotate.</dd>

        <dt><code class="program"><a href="./programs/htpasswd.html">htpasswd</a></code>, <code class="program"><a href="./programs/htdbm.html">htdbm</a></code></dt>
        <dd>Soporta el algoritmo bcrypt (disponible en la versi&#243;n 2.4.4 y posteriores).
        </dd>
    </dl>
  </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="documentation" id="documentation">Documentaci&#243;n</a></h2>
    
    <dl>
        <dt>mod_rewrite</dt>
        <dd>La documentaci&#243;n de  <code class="module"><a href="./mod/mod_rewrite.html">mod_rewrite</a></code> ha sido reorganizada
        y casi escrita por completo, poniendo &#233;nfasis en ejemplos y modos de empleo
        m&#225;s comunes, as&#237; como ense&#241;arle que otras soluciones son m&#225;s apropiadas.

        La <a href="rewrite/">gu&#237;a del m&#243;dulo Rewrite</a> es ahora ahora es una 
        secci&#243;n de nivel superior con mucho m&#225;s detalle y una mejor organizaci&#243;n.</dd>

        <dt>mod_ssl</dt>
        <dd>La documentaci&#243;n del m&#243;dulo <code class="module"><a href="./mod/mod_ssl.html">mod_ssl</a></code> ha sido mejorada en gran medida,
        con m&#225;s ejemplos a nivel de la instalaci&#243;n inicial, adem&#225;s del enfoque t&#233;cnico anterior.</dd>

        <dt>Gu&#237;a de Cach&#233;s</dt>
        <dd>La <a href="caching.html">gu&#237;a de cach&#233;</a> ha sido reescrita para distinguir propiamente 
        entre la cach&#233; del RFC2616 HTTP/1.1 y sus caracter&#237;sticas
        aportadas por <code class="module"><a href="./mod/mod_cache.html">mod_cache</a></code>, y el caso general de cache de valor/clave
        aportado por la interfaz <a href="socache.html">socache</a>,
        as&#237; como cubrir temas espec&#237;ficos  como los mecanismos de cach&#233; aportados por el m&#243;dulo
        <code class="module"><a href="./mod/mod_file_cache.html">mod_file_cache</a></code>.</dd>

    </dl>
  </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="developer" id="developer">Cambios en los Desarrollos de M&#243;dulos</a></h2>
    
    <dl>
      <dt>A&#241;adido Hook de Comprobaci&#243;n de Configuraci&#243;n</dt>

      <dd>El nuevo Hook, <code>check_config</code>, ha sido a&#241;adido el cu&#225;l se ejecuta entre
      	  los hooks <code>pre_config</code> y <code>open_logs</code>.
      	  Tambi&#233;n se ejecuta antes del hook <code>test_config</code> cuando la opci&#243;n 
          <code>-t</code> se le pasa al <code class="program"><a href="./programs/httpd.html">httpd</a></code>. El hook <code>check_config</code>
          permite a los m&#243;dulos revisar los valores en las directivas de
          configuraciones de forma independiente y ajustarlos mientras 
          mensajes pueden seguir siendo logados a la consola.

          El usuario puede as&#237; ser alertado de problemas de mala 
          configuraci&#243;n antes de que la funci&#243;n hook <code>open_logs</code> 
          redireccione la salida de error por la consola
          al log de error.</dd>

      <dt>A&#241;adido un Analizador de Expresiones</dt>

      <dd>Ahora tenemos un analizador de expresiones de prop&#243;sito general, y su API est&#225;
      expuesta en <var>ap_expr.h</var>. Esto es una adaptaci&#243;n del que hab&#237;a anteriormente
      implementado en <code class="module"><a href="./mod/mod_ssl.html">mod_ssl</a></code>.</dd>

      <dt>Autorizaci&#243;n L&#243;gica de Contenedores</dt>

      <dd>Los m&#243;dulos de autorizaci&#243;n ahora se registran como un proveedor, mediante
      <code>ap_register_auth_provider()</code>, para soportar l&#243;gicas de autorizaci&#243;n avanzadas,
      como la directiva <code class="directive"><a href="./mod/mod_authz_core.html#requireall">&lt;RequireAll&gt;</a></code>.</dd>

      <dt>Interfaz de Almacenamiento en Cach&#233; de Objetos Peque&#241;os</dt>

      <dd>La cabecera <var>ap_socache.h</var> expone una interfaz basada en proveedor
      de objetos de datos para la captura de peque&#241;os, basado en la 
      aplicaci&#243;n anterior de cach&#233; de sesi&#243;n del m&#243;dulo <code class="module"><a href="./mod/mod_ssl.html">mod_ssl</a></code>.
      Los proveedores que utilizan una memoria compartida de b&#250;fer c&#237;clico, 
      archivos dbf basados en disco, y una memoria cach&#233; distribuida
      memcached est&#225;n soportados actualmente.</dd>

      <dt>A&#241;adido Hook de Estado de la Cach&#233;</dt>

      <dd>El m&#243;dulo <code class="module"><a href="./mod/mod_cache.html">mod_cache</a></code> ahora incluye un nuevo hook
      <code>cache_status</code>, que es llamado cuando las 
      decisiones de cach&#233; son conocidas. Se provee una implementaci&#243;n
      por defecto que a&#241;ade a la cabecera de la respuesta de forma
      opcional <code>X-Cache</code> y <code>X-Cache-Detail</code>.</dd>
    </dl>

    <p>La documentaci&#243;n de desarrolladores contiene una 
    <a href="developer/new_api_2_4.html">lista detallada de los cambios realizados
    en la API</a>.</p>
  </div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="./en/new_features_2_4.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/new_features_2_4.html" title="Espa&#241;ol">&nbsp;es&nbsp;</a> |
<a href="./fr/new_features_2_4.html" hreflang="fr" rel="alternate" title="Fran&#231;ais">&nbsp;fr&nbsp;</a> |
<a href="./tr/new_features_2_4.html" hreflang="tr" rel="alternate" title="T&#252;rk&#231;e">&nbsp;tr&nbsp;</a></p>
</div><div class="top"><a href="#page-header"><img src="./images/up.gif" alt="top" /></a></div><div class="section"><h2><a id="comments_section" name="comments_section">Comentarios</a></h2><div class="warning"><strong>Notice:</strong><br />This is not a Q&amp;A section. Comments placed here should be pointed towards suggestions on improving the documentation or server, and may be removed again by our moderators if they are either implemented or considered invalid/off-topic. Questions on how to manage the Apache HTTP Server should be directed at either our IRC channel, #httpd, on Freenode, or sent to our <a href="http://httpd.apache.org/lists.html">mailing lists</a>.</div>
<script type="text/javascript"><!--//--><![CDATA[//><!--
var comments_shortname = 'httpd';
var comments_identifier = 'http://httpd.apache.org/docs/trunk/new_features_2_4.html';
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
<p class="apache">Copyright 2017 The Apache Software Foundation.<br />Licencia bajo los t&#233;rminos de la <a href="http://www.apache.org/licenses/LICENSE-2.0">Apache License, Version 2.0</a>.</p>
<p class="menu"><a href="./mod/">M&#243;dulos</a> | <a href="./mod/quickreference.html">Directivas</a> | <a href="http://wiki.apache.org/httpd/FAQ">Preguntas Frecuentes</a> | <a href="./glossary.html">Glosario</a> | <a href="./sitemap.html">Mapa del sitio web</a></p></div><script type="text/javascript"><!--//--><![CDATA[//><!--
if (typeof(prettyPrint) !== 'undefined') {
    prettyPrint();
}
//--><!]]></script>
</body></html>