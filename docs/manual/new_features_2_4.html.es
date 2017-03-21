<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es" xml:lang="es"><head>
<meta content="text/html; charset=ISO-8859-1" http-equiv="Content-Type" />
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Información General sobre las Nuevas Características en Apache HTTP Server 2.4 - Servidor HTTP Apache Versión 2.5</title>
<link href="./style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet" />
<link href="./style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size" />
<link href="./style/css/manual-print.css" rel="stylesheet" media="print" type="text/css" /><link rel="stylesheet" type="text/css" href="./style/css/prettify.css" />
<script src="./style/scripts/prettify.min.js" type="text/javascript">
</script>

<link href="./images/favicon.ico" rel="shortcut icon" /></head>
<body id="manual-page"><div id="page-header">
<p class="menu"><a href="./mod/">Módulos</a> | <a href="./mod/quickreference.html">Directivas</a> | <a href="http://wiki.apache.org/httpd/FAQ">Preguntas Frecuentes</a> | <a href="./glossary.html">Glosario</a> | <a href="./sitemap.html">Mapa del sitio web</a></p>
<p class="apache">Versión 2.5 del Servidor HTTP Apache</p>
<img alt="" src="./images/feather.png" /></div>
<div class="up"><a href="./"><img title="&lt;-" alt="&lt;-" src="./images/left.gif" /></a></div>
<div id="path">
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs/">Documentación</a> &gt; <a href="./">Versión 2.5</a></div><div id="page-content"><div id="preamble"><h1>Información General sobre las Nuevas Características en Apache HTTP Server 2.4</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="./en/new_features_2_4.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/new_features_2_4.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="./fr/new_features_2_4.html" hreflang="fr" rel="alternate" title="Français">&nbsp;fr&nbsp;</a> |
<a href="./tr/new_features_2_4.html" hreflang="tr" rel="alternate" title="Türkçe">&nbsp;tr&nbsp;</a></p>
</div>
<div class="outofdate">Esta traducción podría estar
            obsoleta. Consulte la versión en inglés de la
            documentación para comprobar si se han producido cambios
            recientemente.</div>

  <p>Este documento describe algunos de los principales cambios entre las  versiones
     2.2 y 2.4 del Servidor Apache HTTP. Para las nuevas características desde
     versión 2.0, consulte el  documento <a href="new_features_2_2.html"> 2.2 nuevas características.</a></p>
</div>
<div id="quickview"><ul id="toc"><li><img alt="" src="./images/down.gif" /> <a href="#core">Mejoras en el Core</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#newmods">Nuevos Módulos</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#module">Mejoras de Módulos.</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#programs">Mejoras para el Programa</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#documentation">Documentación</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#developer">Cambios en los Desarrollos de Módulos</a></li>
</ul><h3>Consulte también</h3><ul class="seealso"><li><a href="#comments_section">Comentarios</a></li></ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="core" id="core">Mejoras en el Core</a></h2>
    
    <dl>
      <dt>Cargas de  MPM en Tiempo de Ejecución</dt>
      <dd>Múltiples MPMs ahora se pueden <a href="mpm.html#dynamic"> construir 
      como módulos dinámicos </a>de forma  que pueden ser cargados en tiempo de compilación.
      El MPM de elección se puede configurar en tiempo de ejecución a través 
      de <code class="directive"><a href="./mod/mod_so.html#loadmodule"> LoadModule </a></code>.</dd>

      <dt>Evento MPM</dt>
      <dd>El <a href="mod/event.html">Evento MPM</a> ya no es experimental, lo cuál ahora está totalmente soportado.</dd>

      <dt>Soporte Asíncrono (Asynchronous)</dt>
      <dd>Mejor soporte para lectura y escritura asíncrona para soporte de MPM y
      otras plataformas.</dd>

      <dt>Configuración del Nivel de Log (LogLevel) por Módulo y Directorio</dt>
      <dd>El <code class="directive"><a href="./mod/core.html#loglevel">LogLevel</a></code>  puede ser configurado ahora 
      por módulo y por directorio. Nuevos niveles de <code>trace1</code>
      a <code>trace8</code> se han añadido por encima de la etiqueta  de nivel de 
      registro de log <code>debug</code>.</dd>

      <dt>Secciones de Configuración por Petición</dt>
      <dd><code class="directive"><a href="./mod/core.html#if">&lt;If&gt;</a></code>,
          <code class="directive"><a href="./mod/core.html#elseif">&lt;ElseIf&gt;</a></code>,
          y <code class="directive"><a href="./mod/core.html#else">&lt;Else&gt;</a></code> se pueden usar 
          para establecer los criterios de configuración por cada petición.</dd>

      <dt>Analizador de Expresión de Uso General</dt>
      <dd>Un nuevo analizador de expresiones permite especificar
          <a href="expr.html">condiciones complejas</a> utilizando una sintaxis común
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
      <dd>Ya no es necesario y ahora está en desuso.</dd>

      <dt>Anular Configuración</dt>
      <dd>La nueva directiva <code class="directive"><a href="./mod/core.html#allowoverridelist">AllowOverrideList</a></code>
          permite un control más exhaustivo de que directivas se permiten en los archivos <code>.htaccess</code>.</dd>

      <dt>Variables de los Archivos de Configuración</dt>
      <dd>Ahora es posible <code class="directive"><a href="./mod/core.html#definir">Definir</a></code>
          variables en la configuración, lo que permite una representación más clara
          si el mismo valor se utiliza en muchos lugares en la configuración.
      </dd>

      <dt>Reducción del Uso de Memoria</dt>
      <dd>A pesar de muchas de las nuevas características, 2.4.x tiende a usar menos 
      	memoria que la versión 2.2.x. </dd>

    </dl>
  </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="newmods" id="newmods">Nuevos Módulos</a></h2>
    
    <dl>
      <dt><code class="module"><a href="./mod/mod_proxy_fcgi.html">mod_proxy_fcgi</a></code></dt>
      <dd>Protocolo FastCGI backend para<code class="module"><a href="./mod/mod_proxy.html">mod_proxy</a></code></dd>

      <dt><code class="module"><a href="./mod/mod_proxy_scgi.html">mod_proxy_scgi</a></code></dt>
      <dd>Protocolo SCGI backend para <code class="module"><a href="./mod/mod_proxy.html">mod_proxy</a></code></dd>

      <dt><code class="module"><a href="./mod/mod_proxy_express.html">mod_proxy_express</a></code></dt>
      <dd>Proporciona una configuración masiva y dinámica de proxys inversos para
      <code class="module"><a href="./mod/mod_proxy.html">mod_proxy</a></code></dd>

      <dt><code class="module"><a href="./mod/mod_remoteip.html">mod_remoteip</a></code></dt>
      <dd>Reemplaza la dirección IP remota cliente aparente y nombre de host para la solicitud
      con la lista de direcciones IP presentada por un proxy o un balanceador de carga a través de
      las cabeceras de solicitud.</dd>

      <dt><code class="module"><a href="./mod/mod_heartmonitor.html">mod_heartmonitor</a></code>,
          <code class="module"><a href="./mod/mod_lbmethod_heartbeat.html">mod_lbmethod_heartbeat</a></code></dt>
      <dd>Permite a <code class="module"><a href="./mod/mod_proxy_balancer.html">mod_proxy_balancer</a></code> basar las decisiones del balanceo de 
      carga según el número de conexiones activas en los servidores de back-end.</dd>

      <dt><code class="module"><a href="./mod/mod_proxy_html.html">mod_proxy_html</a></code></dt>
      <dd>antiguamente un módulo de terceros, esto apoya la fijación de enlaces HTML en un proxy inverso,
situación en la que el servidor genera URLs que no son válidos para los clientes del proxy.</dd>

      <dt><code class="module"><a href="./mod/mod_sed.html">mod_sed</a></code></dt>
      <dd>Un reemplazo avanzado de <code class="module"><a href="./mod/mod_substitute.html">mod_substitute</a></code>, permite editar el 
      cuerpo de la respuesta con el poder lleno de sed.</dd>

      <dt><code class="module"><a href="./mod/mod_auth_form.html">mod_auth_form</a></code></dt>
      <dd>Habilitar la autenticación basada en formularios.</dd>

      <dt><code class="module"><a href="./mod/mod_session.html">mod_session</a></code></dt>
      <dd>Permite el uso de estado de sesión para clientes, utilizando cookies o el 
      	almacenamiento en una base de datos.</dd>

      <dt><code class="module"><a href="./mod/mod_allowmethods.html">mod_allowmethods</a></code></dt>
      <dd>Nuevo módulo para restringir ciertos métodos HTTP sin interferir con
      autenticación o autorización.</dd>

      <dt><code class="module"><a href="./mod/mod_lua.html">mod_lua</a></code></dt>
      <dd>Embebe el lenguaje<a href="http://www.lua.org/">Lua</a> en httpd,
      para la configuración y las funciones lógicas de negocios pequeños. (Experimental)</dd>

      <dt><code class="module"><a href="./mod/mod_log_debug.html">mod_log_debug</a></code></dt>
      <dd>Permite añadir mensajes de depuración personalizados en las diferentes fases del procesamiento de la solicitud.</dd>

      <dt><code class="module"><a href="./mod/mod_buffer.html">mod_buffer</a></code></dt>
      <dd>Proporciona almacenamiento en búfer para los filtros de entrada y salida de las pilas</dd>

      <dt><code class="module"><a href="./mod/mod_data.html">mod_data</a></code></dt>
      <dd>Convierte la respuesta del cuerpo en una dirección URL de datos RFC2397</dd>

      <dt><code class="module"><a href="./mod/mod_ratelimit.html">mod_ratelimit</a></code></dt>
      <dd>Proporciona limitación de velocidad en el ancho de banda para los clientes</dd>

      <dt><code class="module"><a href="./mod/mod_request.html">mod_request</a></code></dt>
      <dd>Proporciona filtros para manejar y hacer el cuerpo de la petición HTTP disponibles</dd>

      <dt><code class="module"><a href="./mod/mod_reflector.html">mod_reflector</a></code></dt>
      <dd>Proporciona Reflexión del cuerpo de la petición como una respuesta a través de la pila de filtro de salida.</dd>

      <dt><code class="module"><a href="./mod/mod_slotmem_shm.html">mod_slotmem_shm</a></code></dt>
      <dd>Proporciona un proveedor de memoria compartida basada en la ranura (ala the scoreboard).</dd>

      <dt><code class="module"><a href="./mod/mod_xml2enc.html">mod_xml2enc</a></code></dt>
      <dd>Anteriormente un módulo de terceros, que apoya la internacionalización en
      módulos de filtro (markup-aware) basada en libxml2.</dd>

      <dt><code class="module"><a href="./mod/mod_macro.html">mod_macro</a></code> (disponible desde la versión 2.4.5)</dt>
      <dd>Provee macros para los archivos de configuración</dd>

      <dt><code class="module"><a href="./mod/mod_proxy_wstunnel.html">mod_proxy_wstunnel</a></code> (disponible desde la versión 2.4.5)</dt>
      <dd>Soporte a túneles web-socket.</dd>

      <dt><code class="module"><a href="./mod/mod_authnz_fcgi.html">mod_authnz_fcgi</a></code> (disponible desde la versión 2.4.10)</dt>
      <dd>Habilitar aplicaciones autorizadas FastCGI para autenticar y/o autorizar a los clientes.</dd>

      <dt><code class="module"><a href="./mod/mod_http2.html">mod_http2</a></code> (disponible desde la versión 2.4.17)</dt>
      <dd>Soporte para la capa HTTP/2</dd>

    </dl>
  </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="module" id="module">Mejoras de Módulos.</a></h2>
    
    <dl>
      <dt><code class="module"><a href="./mod/mod_ssl.html">mod_ssl</a></code></dt>

      <dd><code class="module"><a href="./mod/mod_ssl.html">mod_ssl</a></code> ahora puede ser configurado para utilizar un servidor 
      OCSP para comprobar el estado de validez de un certificado de cliente. La respuesta por 
      defecto es configurable, junto con la decisión sobre si se debe preferir el "responder"
       designado en el certificado de cliente en sí.</dd>

      <dd><code class="module"><a href="./mod/mod_ssl.html">mod_ssl</a></code> ahora también es compatible con "OCSP stapling", 
      una respuesta de OCSP al inicial TLS "Handshake" con marca de tiempo 
      firmado por la CA , en el que el servidor obtiene de forma proactiva 
      una verificación OCSP de su certificado y transmite esa o la del cliente
       durante el  "Handshake".</dd>


      <dd><code class="module"><a href="./mod/mod_ssl.html">mod_ssl</a></code> Ahora se puede configurar para compartir los datos de 
      sesión SSL entre servidores a través de memcached.</dd>

      <dd>Claves de cifrado de tipo EC (Curva Elíptica en Inglés) son ahora 
      	soportadas junto con RSA y DSA.</dd>

      <dd>Soporte de TLS-SRP (disponible en la versión 2.4.4 y posteriores).</dd>

      <dt><code class="module"><a href="./mod/mod_proxy.html">mod_proxy</a></code></dt>

      <dd>La directiva <code class="directive"><a href="./mod/mod_proxy.html#proxypass">ProxyPass</a></code> 
      ahora está configurado de forma más óptima dentro de un bloque
      <code class="directive"><a href="./mod/core.html#location">Location</a></code> o
      <code class="directive"><a href="./mod/core.html#locationmatch">LocationMatch</a></code>,
      y ofrece una ventaja de rendimiento significativa sobre la sintaxis tradicional
      de dos parámetros cuando están presentes en gran número.</dd>
      <dd>La dirección de origen utilizada para solicitudes de proxy es ahora configurable.</dd>
      <dd>Soporte para sockets de dominio Unix en el backend (disponible en la versión 2.4.7
      y posteriores).</dd>

      <dt><code class="module"><a href="./mod/mod_proxy_balancer.html">mod_proxy_balancer</a></code></dt>

      <dd>Más cambios en la configuración en tiempo de ejecución para BalancerMembers 
      	mediante el manager del balanceador.</dd>

      <dd>Se pueden agregar miembros adicionales a BalancerMembers en tiempo de ejecución 
      	mediante el manager del balanceador.</dd>

      <dd>Configuración de ejecución de un subconjunto de parámetros Balancer</dd>

      <dd>BalancerMembers se puede establecer en "fuga" de modo que sólo responden a las 
      	sesiones problemáticas existentes, lo que les permite ser puestos con gracia fuera de línea.</dd>

      <dd>Configuración del balanceador de carga pueden ser persistentes después de un reinicio.</dd>

      <dt><code class="module"><a href="./mod/mod_cache.html">mod_cache</a></code></dt>

      <dd>En el módulo <code class="module"><a href="./mod/mod_cache.html">mod_cache</a></code> se puede añadir filtro de cache en determinado 
      punto en la cadena de filtro, para proveer mejor control de la caché</dd>

      <dd><code class="module"><a href="./mod/mod_cache.html">mod_cache</a></code> Puede cachear ahora peticiones de tipo HEAD.</dd>
      <dd>Siendo posible ahora las directivas <code class="module"><a href="./mod/mod_cache.html">mod_cache</a></code>
      ser configuradas por directorio en vez de por servidor.</dd>

      <dd>La URL base de las URLs cacheadas se pueden personalizar, 
      de tal forma que un cluster de cachés puede compartir el mismo
      prefijo URL de punto final.</dd>

      <dd><code class="module"><a href="./mod/mod_cache.html">mod_cache</a></code> ahora es capaz de servir a los datos en caché 
      antigua cuando un motor no está disponible (error 5xx).</dd>

      <dd><code class="module"><a href="./mod/mod_cache.html">mod_cache</a></code> ahora puede insertar HIT/MISS/REVALIDATE 
      en una cabecera de tipo X-Cache.</dd>

      <dt><code class="module"><a href="./mod/mod_include.html">mod_include</a></code></dt>
      <dd>Soporte al atributo 'onerror' dentro del elemento 'include', lo que permite
      mostar un documento de error cuando hay un error en vez de la cadena de error por defecto.
      </dd>

      <dt><code class="module"><a href="./mod/mod_cgi.html">mod_cgi</a></code>, <code class="module"><a href="./mod/mod_include.html">mod_include</a></code>,
          <code class="module"><a href="./mod/mod_isapi.html">mod_isapi</a></code>, ...</dt>
      <dd>La traducción de cabeceras a variables de entorno es más estricta que antes para mitigar 
      algunos de los posibles ataques de cross-site scripting, a través de la inyección de cabecera. 
      Las cabeceras que contienen carácteres no válidos (incluyendo guiones bajos)
      son descartadas de forma silenciosa. <a href="env.html">Las variables de entorno en
      Apache</a> tienen algunos consejos en como trabajar con clientes con sistemas heredados rotos que 
      requieren de este tipo de cabeceras. (Esto afecta a todos los módulos que 
      usan éstas variables de entorno.)</dd>

      <dt><code class="module"><a href="./mod/mod_authz_core.html">mod_authz_core</a></code> Autorización Lógica de Contenedores</dt>

      <dd>Ahora puede ser especificada una lógica avanzada de autorización, usando la directiva 
          <code class="directive"><a href="./mod/mod_authz_core.html#require">Require</a></code> y 
          las directivas de los contenedores asociados, tales como
          <code class="directive"><a href="./mod/mod_authz_core.html#requireall">&lt;RequireAll&gt;</a></code>.</dd>

      <dt><code class="module"><a href="./mod/mod_rewrite.html">mod_rewrite</a></code></dt>
      <dd><code class="module"><a href="./mod/mod_rewrite.html">mod_rewrite</a></code> añade los flags <code>[QSD]</code>
          (Query String Discard) y <code>[END]</code> para las directivas
          <code class="directive"><a href="./mod/mod_rewrite.html#rewriterule">RewriteRule</a></code> para 
          simplificar escenarios de reescritura comunes.</dd>
      <dd>Añade la posibilidad de usar expresiones buleanas complejas en <code class="directive"><a href="./mod/mod_rewrite.html#rewritecond">RewriteCond</a></code>.</dd>
      <dd>Permite el uso de queris SQL como funciones de <code class="directive"><a href="./mod/mod_rewrite.html#rewritemap">RewriteMap</a></code>.</dd>

      <dt><code class="module"><a href="./mod/mod_ldap.html">mod_ldap</a></code>, <code class="module"><a href="./mod/mod_authnz_ldap.html">mod_authnz_ldap</a></code></dt>
      <dd><code class="module"><a href="./mod/mod_authnz_ldap.html">mod_authnz_ldap</a></code> agrega soporte a grupos anidados.</dd>
      <dd><code class="module"><a href="./mod/mod_ldap.html">mod_ldap</a></code> Incorpora
          <code class="directive"><a href="./mod/mod_ldap.html#ldapconnectionpoolttl">LDAPConnectionPoolTTL</a></code>,
          <code class="directive"><a href="./mod/mod_ldap.html#ldaptimeout">LDAPTimeout</a></code>, y otras mejoras
           en el manejo de los "timeouts" tiempo agotado de espera.
          Esto es especialmente útil para escenarios en los que existe un firewall 
          en modo "Stateful" que desecha conexiones inactivas a un servidor LDAP.</dd>
      <dd><code class="module"><a href="./mod/mod_ldap.html">mod_ldap</a></code> Incorpora
          <code class="directive"><a href="./mod/mod_ldap.html#ldaplibrarydebug">LDAPLibraryDebug</a></code> para registrar información de 
          depuración proporcionada por el conjunto de herramientas usadas por LDAP.</dd>

      <dt><code class="module"><a href="./mod/mod_info.html">mod_info</a></code></dt>
      <dd><code class="module"><a href="./mod/mod_info.html">mod_info</a></code> ahora puede volcar la configuración pre-procesada
      a la salida estándar durante el inicio del servidor.</dd>

      <dt><code class="module"><a href="./mod/mod_auth_basic.html">mod_auth_basic</a></code></dt>
      <dd>Nuevo mecanismo genérico para la autenticación básica falsa (disponible en la versión
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
        <dd>Los tamaños de archivo ahora se pueden redondear hasta el tamaño de bloque determinado,
        por lo que los límites de tamaño se asemeja más estrechamente con el tamaño real en el disco.</dd>
        <dd>El tamaño de la caché ahora puede ser limitado por el número de i-nodos, 
        en vez de o como añadido, al limite del tamaño del archivo en el disco.</dd>

        <dt><code class="program"><a href="./programs/rotatelogs.html">rotatelogs</a></code></dt>
        <dd>Ahora puede crear un enlace al propio fichero de log.</dd>
        <dd>Ahora puede invocar a un escript personalizado pos-rotate.</dd>

        <dt><code class="program"><a href="./programs/htpasswd.html">htpasswd</a></code>, <code class="program"><a href="./programs/htdbm.html">htdbm</a></code></dt>
        <dd>Soporta el algoritmo bcrypt (disponible en la versión 2.4.4 y posteriores).
        </dd>
    </dl>
  </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="documentation" id="documentation">Documentación</a></h2>
    
    <dl>
        <dt>mod_rewrite</dt>
        <dd>La documentación de  <code class="module"><a href="./mod/mod_rewrite.html">mod_rewrite</a></code> ha sido reorganizada
        y casi escrita por completo, poniendo énfasis en ejemplos y modos de empleo
        más comunes, así como enseñarle que otras soluciones son más apropiadas.

        La <a href="rewrite/">guía del módulo Rewrite</a> es ahora ahora es una 
        sección de nivel superior con mucho más detalle y una mejor organización.</dd>

        <dt>mod_ssl</dt>
        <dd>La documentación del módulo <code class="module"><a href="./mod/mod_ssl.html">mod_ssl</a></code> ha sido mejorada en gran medida,
        con más ejemplos a nivel de la instalación inicial, además del enfoque técnico anterior.</dd>

        <dt>Guía de Cachés</dt>
        <dd>La <a href="caching.html">guía de caché</a> ha sido reescrita para distinguir propiamente 
        entre la caché del RFC2616 HTTP/1.1 y sus características
        aportadas por <code class="module"><a href="./mod/mod_cache.html">mod_cache</a></code>, y el caso general de cache de valor/clave
        aportado por la interfaz <a href="socache.html">socache</a>,
        así como cubrir temas específicos  como los mecanismos de caché aportados por el módulo
        <code class="module"><a href="./mod/mod_file_cache.html">mod_file_cache</a></code>.</dd>

    </dl>
  </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="developer" id="developer">Cambios en los Desarrollos de Módulos</a></h2>
    
    <dl>
      <dt>Añadido Hook de Comprobación de Configuración</dt>

      <dd>El nuevo Hook, <code>check_config</code>, ha sido añadido el cuál se ejecuta entre
      	  los hooks <code>pre_config</code> y <code>open_logs</code>.
      	  También se ejecuta antes del hook <code>test_config</code> cuando la opción 
          <code>-t</code> se le pasa al <code class="program"><a href="./programs/httpd.html">httpd</a></code>. El hook <code>check_config</code>
          permite a los módulos revisar los valores en las directivas de
          configuraciones de forma independiente y ajustarlos mientras 
          mensajes pueden seguir siendo logados a la consola.

          El usuario puede así ser alertado de problemas de mala 
          configuración antes de que la función hook <code>open_logs</code> 
          redireccione la salida de error por la consola
          al log de error.</dd>

      <dt>Añadido un Analizador de Expresiones</dt>

      <dd>Ahora tenemos un analizador de expresiones de propósito general, y su API está
      expuesta en <var>ap_expr.h</var>. Esto es una adaptación del que había anteriormente
      implementado en <code class="module"><a href="./mod/mod_ssl.html">mod_ssl</a></code>.</dd>

      <dt>Autorización Lógica de Contenedores</dt>

      <dd>Los módulos de autorización ahora se registran como un proveedor, mediante
      <code>ap_register_auth_provider()</code>, para soportar lógicas de autorización avanzadas,
      como la directiva <code class="directive"><a href="./mod/mod_authz_core.html#requireall">&lt;RequireAll&gt;</a></code>.</dd>

      <dt>Interfaz de Almacenamiento en Caché de Objetos Pequeños</dt>

      <dd>La cabecera <var>ap_socache.h</var> expone una interfaz basada en proveedor
      de objetos de datos para la captura de pequeños, basado en la 
      aplicación anterior de caché de sesión del módulo <code class="module"><a href="./mod/mod_ssl.html">mod_ssl</a></code>.
      Los proveedores que utilizan una memoria compartida de búfer cíclico, 
      archivos dbf basados en disco, y una memoria caché distribuida
      memcached están soportados actualmente.</dd>

      <dt>Añadido Hook de Estado de la Caché</dt>

      <dd>El módulo <code class="module"><a href="./mod/mod_cache.html">mod_cache</a></code> ahora incluye un nuevo hook
      <code>cache_status</code>, que es llamado cuando las 
      decisiones de caché son conocidas. Se provee una implementación
      por defecto que añade a la cabecera de la respuesta de forma
      opcional <code>X-Cache</code> y <code>X-Cache-Detail</code>.</dd>
    </dl>

    <p>La documentación de desarrolladores contiene una 
    <a href="developer/new_api_2_4.html">lista detallada de los cambios realizados
    en la API</a>.</p>
  </div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="./en/new_features_2_4.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/new_features_2_4.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="./fr/new_features_2_4.html" hreflang="fr" rel="alternate" title="Français">&nbsp;fr&nbsp;</a> |
<a href="./tr/new_features_2_4.html" hreflang="tr" rel="alternate" title="Türkçe">&nbsp;tr&nbsp;</a></p>
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
<p class="apache">Copyright 2017 The Apache Software Foundation.<br />Licencia bajo los términos de la <a href="http://www.apache.org/licenses/LICENSE-2.0">Apache License, Version 2.0</a>.</p>
<p class="menu"><a href="./mod/">Módulos</a> | <a href="./mod/quickreference.html">Directivas</a> | <a href="http://wiki.apache.org/httpd/FAQ">Preguntas Frecuentes</a> | <a href="./glossary.html">Glosario</a> | <a href="./sitemap.html">Mapa del sitio web</a></p></div><script type="text/javascript"><!--//--><![CDATA[//><!--
if (typeof(prettyPrint) !== 'undefined') {
    prettyPrint();
}
//--><!]]></script>
</body></html>