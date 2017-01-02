<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es" xml:lang="es"><head>
<meta content="text/html; charset=ISO-8859-1" http-equiv="Content-Type" />
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Información General sobre las Nuevas Características en Apache HTTP Server 2.2 - Servidor HTTP Apache Versión 2.5</title>
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
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs/">Documentación</a> &gt; <a href="./">Versión 2.5</a></div><div id="page-content"><div id="preamble"><h1>Información General sobre las Nuevas Características en Apache HTTP Server 2.2</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="./en/new_features_2_2.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/new_features_2_2.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="./fr/new_features_2_2.html" hreflang="fr" rel="alternate" title="Français">&nbsp;fr&nbsp;</a> |
<a href="./ko/new_features_2_2.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./pt-br/new_features_2_2.html" hreflang="pt-br" rel="alternate" title="Português (Brasil)">&nbsp;pt-br&nbsp;</a> |
<a href="./tr/new_features_2_2.html" hreflang="tr" rel="alternate" title="Türkçe">&nbsp;tr&nbsp;</a></p>
</div>

  <p>Este documento describe algunos de los principales cambios entre las versiones 2.0 y
   2.2 del Servidor Apache HTTP. Para las nuevas características desde la versión 1.3, 
   consulte <a href="new_features_2_0.html">2.0 nuevas características.</a>
  </p>
</div>
<div id="quickview"><ul id="toc"><li><img alt="" src="./images/down.gif" /> <a href="#core">Mejoras principales</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#module">Mejoras en Módulos</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#programs">Mejoras de Programas</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#developer">Cambios para desarrolladores de Módulos</a></li>
</ul><h3>Consulte también</h3><ul class="seealso"><li><a href="#comments_section">Comentarios</a></li></ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="core" id="core">Mejoras principales</a></h2>
    
    <dl>

      <dt>Autenticación y Autorización</dt>
      <dd>El paquete de los módulos de autenticación y autorización se han 
      refactorizado. El nuevo módulo mod_authn_alias (eliminados en las 
      versiones 2.3/2.4) puede simplificar de gran forma algunas configuraciones 
      de autenticación. Vea también el <a href="#module">cambio de nombres de 
      los módulos</a>, y <a href="#developer">los cambios para desarrolladores</a> 
      para más información sobre los cambios de como afectan a los usuarios, 
      y a los que desarrollan módulos.
      </dd>

      <dt>Caché</dt>
      <dd><code class="module"><a href="./mod/mod_cache.html">mod_cache</a></code>, <code class="module"><a href="./mod/mod_cache_disk.html">mod_cache_disk</a></code>, y
          mod_mem_cache (eliminados en las versiones 2.3/2.4) han sufrido muchos 
          cambios, y ahora se consideran en calidad de producción. 
          El programa <code class="program"><a href="./programs/htcacheclean.html">htcacheclean</a></code> se ha introducido
          para limpiar los setups de <code class="module"><a href="./mod/mod_cache_disk.html">mod_cache_disk</a></code>.
      </dd>

      <dt>Configuración</dt>
      <dd>La capa de la configuración por defecto, se ha simplificado y 
      modularizado. Se pueden utilizar fragmentos de configuración para 
      habilitar las funciones de uso común que ahora se incluyen con Apache, 
      y pueden ser fácilmente añadidos a la configuración del servidor
      principal.</dd>

      <dt>Detención con elegancia</dt>
      <dd>Los módulos <code class="module"><a href="./mod/prefork.html">prefork</a></code>, <code class="module"><a href="./mod/worker.html">worker</a></code> y
          <code class="module"><a href="./mod/event.html">event</a></code> MPMs(módulos de procesos múltiples) ahora 
          permiten a <code class="program"><a href="./programs/httpd.html">httpd</a></code> ser apagado/parado con elegancia
          mediante la señal 
          <a href="stopping.html#gracefulstop"><code>graceful-stop</code></a>.
          La directiva <code class="directive"><a href="./mod/mpm_common.html#gracefulshutdowntimeout">GracefulShutdownTimeout</a></code> se ha añadidos
          para especificar un tiempo opcional, tras el cual el 
          <code class="program"><a href="./programs/httpd.html">httpd</a></code> se parará independientemente del estado de
          cualquier petición que se esté sirviendo.</dd>

      <dt>Funcionalidad del Proxy</dt>
      <dd>El nuevo módulo <code class="module"><a href="./mod/mod_proxy_balancer.html">mod_proxy_balancer</a></code> proporciona un 
      servicio de balanceo de carga para el módulo <code class="module"><a href="./mod/mod_proxy.html">mod_proxy</a></code>.
      El nuevo módulo <code class="module"><a href="./mod/mod_proxy_ajp.html">mod_proxy_ajp</a></code> añade soporte para el
      <code>Protocolo  JServ versión 1.3 de Apache </code> usado por
          <a href="http://tomcat.apache.org/">Apache Tomcat</a>.</dd>

      <dt>Actualización de la Librería de Expresiones Regulares</dt>
      <dd>Se ha incluido la versión 5.0 de 
          <a href="http://www.pcre.org/">Librería de Expresiones Regulares 
          Compatibles Perl </a> (PCRE). El programa <code class="program"><a href="./programs/httpd.html">httpd</a></code> 
          puede ser configurado para que use una instalación en el sistema 
          de PCRE pasandole como parámetro <code>--with-pcre</code> 
          al configure.</dd>

      <dt>Filtrado Inteligente</dt>
      <dd><code class="module"><a href="./mod/mod_filter.html">mod_filter</a></code> introduce una configuración dinámica 
      a la cadena de filtro de salida. Habilita que los filtros sean insertados
      de forma condicional, basado en cualquier cabecera de petición o respuesta
      o una variable de entorno, y prescinde de las dependencias más problemáticas
      así como problemas de ordenación en la arquitectura 2.0.</dd>

      <dt>Soporte de Grandes Ficheros</dt>
      <dd><code class="program"><a href="./programs/httpd.html">httpd</a></code> es creado ahora con soporte para ficheros 
      mayores de 2GB en los sistemas Unix modernos de 32-bits. También el soporte
      para el manejo de cuerpos de respuesta &gt;2GB ha sido añadido.</dd>

      <dt>Eventos MPM</dt>
      <dd>El módulo <code class="module"><a href="./mod/event.html">event</a></code> MPM usa un hilo separado para el manejo
      de las peticiones Keep Alive y aceptar las conexiones. Las peticiones de 
      Keep Alive tradicionalmente han requerido un "worker" de httpd para su manejo.
      Este "worker" dedicado no puede ser utilizado otra vez hasta que el Keep Alive
      haya expirado su tiempo de conexión. 
      </dd>

      <dt>Soporte de Base de Datos SQL</dt>
      <dd>El módulo <code class="module"><a href="./mod/mod_dbd.html">mod_dbd</a></code>, junto con el framework
      <code>apr_dbd</code>, nos trae soporte directo de SQL para los módulos
      que lo necesitan. Es compatible con la agrupación de conexiones 
      en procesos MPM.</dd>

    </dl>
  </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="module" id="module">Mejoras en Módulos</a></h2>
    
    <dl>
      <dt>Autenticación y Autorización</dt>
      <dd>Los módulos en el directorio aaa se han renombrado y ofrecen mejor 
	      soporte para la autenticación implícita (digest).
	      Por ejemplo: 
	      <code>mod_auth</code> se ha dividido ahora en
	      <code class="module"><a href="./mod/mod_auth_basic.html">mod_auth_basic</a></code> y
	      <code class="module"><a href="./mod/mod_authn_file.html">mod_authn_file</a></code>; <code>mod_auth_dbm</code> ahora
	      se llama <code class="module"><a href="./mod/mod_authn_dbm.html">mod_authn_dbm</a></code>; <code>mod_access</code> ha 
	      sido renombrado a <code class="module"><a href="./mod/mod_authz_host.html">mod_authz_host</a></code>. También hay un nuevo 
	      módulo mod_authn_alias( ya eliminado en las versiones 2.3/2.4) para 
	      simplificar algunas configuraciones de autenticación.
      </dd>

      <dt><code class="module">mod_authnz_ldap</code></dt>
      <dd>Este módulo se ha traído de la versión 2.0 del módulo
          <code>mod_auth_ldap</code> a la versión 2.2 del framework de 
          <code>Autenticación/Autorización</code>. Las nuevas características 
          incluyen el uso de  valores de LDAP y filtros de búsqueda complejos 
          para la directiva 
          <code class="directive"><a href="./mod/mod_authz_core.html#require">Require</a></code>.</dd>

      <dt><code class="module"><a href="./mod/mod_authz_owner.html">mod_authz_owner</a></code></dt>
      <dd>Un nuevo módulo que autoriza el acceso a ficheros basándose en el 
      	propietario del fichero en el sistema operativo.
      </dd>

      <dt><code class="module"><a href="./mod/mod_version.html">mod_version</a></code></dt>
      <dd>Este nuevo módulo permite que se habiliten bloques de configuración  
      	dependiendo de la versión del servidor.
      </dd>

      <dt><code class="module"><a href="./mod/mod_info.html">mod_info</a></code></dt>
      <dd>Se ha añadido un nuevo argumento al <code>config</code> que muestra
      las configuraciones de las directivas que se le pasan a Apache, incluyendo
      los nombres de los ficheros y en que linea se encuentra dicha configuración.
      Este módulo además muestra en orden todas las peticiones de hooks y información 
      adicional a la hora de compilar, similar a <code>httpd -V</code>.</dd>

      <dt><code class="module"><a href="./mod/mod_ssl.html">mod_ssl</a></code></dt>
      
      <dd>Se ha añadido soporte para el 
         <a href="http://www.ietf.org/rfc/rfc2817.txt">RFC 2817</a>, que permite
         conexiones para que se actualicen de texto plano al cifrado TLS.</dd>

      <dt><code class="module"><a href="./mod/mod_imagemap.html">mod_imagemap</a></code></dt>
      <dd><code>mod_imap</code> Se ha renombrado a 
          <code class="module"><a href="./mod/mod_imagemap.html">mod_imagemap</a></code> para evitar confusión en el usuario.
      </dd>
    </dl>

  </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="programs" id="programs">Mejoras de Programas</a></h2>
    
    <dl>
      <dt><code class="program"><a href="./programs/httpd.html">httpd</a></code></dt>
      <dd>Se ha añadido una nueva opción en la línea de comandos <code>-M</code>,
      dicha opción lista todos los módulos que se cargan basándose en la 
      configuración actual. A diferencia de la opción <code>-l</code>, esta lista
      incluye los DSOs cargados mediante el módulo<code class="module"><a href="./mod/mod_so.html">mod_so</a></code>.
  	  </dd>

      <dt><code class="program"><a href="./programs/httxt2dbm.html">httxt2dbm</a></code></dt>
      <dd>Un nuevo programa para generar archivos dbm desde archivos de texto 
      	como entrada, para su uso en
        <code class="directive"><a href="./mod/mod_rewrite.html#rewritemap">RewriteMap</a></code>
          con el mapa de tipo <code>dbm</code>.</dd>
    </dl>
  </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="developer" id="developer">Cambios para desarrolladores de Módulos</a></h2>
    
    <dl>
      <dt><a class="glossarylink" href="./glossary.html#apr" title="ver glosario">APR</a> 1.0 API</dt>

      <dd>Apache 2.2 usa la API de APR. Todas las funciones  y símbolos obsoletas
      se han eliminado de <code>APR</code> y
          <code>APR-Util</code>. Para mas detalles sobre dichos cambios
          vaya a la 
          <a href="http://apr.apache.org/">página de APR</a>.</dd>

      <dt>Autenticación y Autorización</dt>
      <dd>El paquete de módulos de autenticación y autorización se han renombrado 
          como se muestra en las siguientes líneas:
          <ul>
          <li><code>mod_auth_*</code>  -&gt; Módulos que implementan un mecanismo de 
          autenticación por HTTP.</li>
          <li><code>mod_authn_*</code> -&gt; Módulos que proporcionan un backend
           proveedor de autenticación.</li>
          <li><code>mod_authz_*</code> -&gt; Módulos que implementan autorización 
          (o acceso)</li>
          <li><code>mod_authnz_*</code> -&gt; Módulo que implementa ambas opciones
          autenticación &amp; autorización</li>
          </ul>
          Hay un nuevo esquema de proveedor de la autenticación en el backend 
          lo que facilita en gran medida la construcción de nuevos motores 
          de autenticación.
          </dd>

      <dt>Registro de errores de Conexión</dt>

      <dd>Una nueva función <code>ap_log_cerror</code> ha sido añadida para 
      registrar los errores que ocurren en la conexión del cliente. Cuando se
      registra el error, el mensaje incluye la dirección IP del cliente.</dd>

      <dt>Añadido Hooks para la configuración de Test</dt>

      <dd>Un nuevo hook, <code>test_config</code> se ha añadido para ayudar a 
      los módulos que necesitan ejecutar sólo código especial cuando el usuario 
      pasa como parámetro <code>-t</code> a <code class="program"><a href="./programs/httpd.html">httpd</a></code>.</dd>

      <dt>Configuración de tamaño de pila para los procesos MPM's</dt>

      <dd>Una nueva directiva, <code class="directive"><a href="./mod/mpm_common.html#threadstacksize">ThreadStackSize</a></code> se ha añadido para configurar 
          el tamaño de la pila de  todos los hilos de MPMs. Esta directiva
          es requerida por algún módulo de terceros en plataformas que tienen
          por defecto una pila con un tamaño pequeño.</dd>

      <dt>Manejo de protocolo para los filtros de salida</dt>

      <dd>En el pasado, cada filtro ha sido responsable de garantizar
       que genera las cabeceras de respuesta correctas donde les afecta.  
       Los filtros ahora delegan la administración común del protocolo
       a los módulos 
       <code class="module"><a href="./mod/mod_filter.html">mod_filter</a></code>, usando llamadas a
       <code>ap_register_output_filter_protocol</code> ó
       <code>ap_filter_protocol</code>.</dd>

      <dt>Monitor de hooks añadido</dt>
      <dd>Monitor hook habilita a los módulos a ejecutar tareas regulares
        o programadas en el proceso padre (raíz).</dd>

      <dt>Cambio de expresiones regulares en la API</dt>

      <dd>La cabecera <code>pcreposix.h</code> ya no esta disponible;
      se ha cambiado por la nueva <code>ap_regex.h</code>. La 
      implementación POSIX.2 de <code>regex.h</code> expuesta por la cabecera 
      antigua, está ahora disponible en el espacio de nombre con <code>ap_</code>
      en la cabecera <code>ap_regex.h</code>. llama a <code>regcomp</code>,
      <code>regexec</code> y así sucesivamente pueden ser sustituidos por 
      llamadas a <code>ap_regcomp</code>, <code>ap_regexec</code>.</dd>

      <dt>DBD Framework (API de base de datos SQL)</dt>

      <dd><p>Con Apache 1.x y 2.0, algunos módulos que requieren un 
      	backend de SQL deben tomar la responsabilidad de gestionar por sí 
      	mismos. Aparte de reinventar la rueda, esto puede llegar a ser
      	ineficiente, por ejemplo cuando varios módulos cada uno mantiene su propia conexión.
      	</p>

      <p>Las versiones de Apache posteriores a la 2.1 proporciona la API de <code>ap_dbd</code> 
      para el manejo de las conexiones a las bases de datos (incluyendo estrategia 
      optimizadas para los hilos o no de MPMs), mientras que las versiones de 
      APR 1.2 y posteriores proporciona la API <code>apr_dbd</code> para 
      interactuar con la base de datos.</p>

      <p>Los nuevos módulos DEBEN usar estas APIs para todas las operaciones en 
      	bases de datos SQL. Aplicaciones existentes DEBEN ser actualizadas para 
      	que lo usen cuando sea posible, de forma transparente o como opción recomendada
      	para sus usuarios.</p>
      </dd>
    </dl>
  </div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="./en/new_features_2_2.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/new_features_2_2.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="./fr/new_features_2_2.html" hreflang="fr" rel="alternate" title="Français">&nbsp;fr&nbsp;</a> |
<a href="./ko/new_features_2_2.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./pt-br/new_features_2_2.html" hreflang="pt-br" rel="alternate" title="Português (Brasil)">&nbsp;pt-br&nbsp;</a> |
<a href="./tr/new_features_2_2.html" hreflang="tr" rel="alternate" title="Türkçe">&nbsp;tr&nbsp;</a></p>
</div><div class="top"><a href="#page-header"><img src="./images/up.gif" alt="top" /></a></div><div class="section"><h2><a id="comments_section" name="comments_section">Comentarios</a></h2><div class="warning"><strong>Notice:</strong><br />This is not a Q&amp;A section. Comments placed here should be pointed towards suggestions on improving the documentation or server, and may be removed again by our moderators if they are either implemented or considered invalid/off-topic. Questions on how to manage the Apache HTTP Server should be directed at either our IRC channel, #httpd, on Freenode, or sent to our <a href="http://httpd.apache.org/lists.html">mailing lists</a>.</div>
<script type="text/javascript"><!--//--><![CDATA[//><!--
var comments_shortname = 'httpd';
var comments_identifier = 'http://httpd.apache.org/docs/trunk/new_features_2_2.html';
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