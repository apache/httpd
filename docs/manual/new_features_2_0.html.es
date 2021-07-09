<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es" xml:lang="es"><head>
<meta content="text/html; charset=ISO-8859-1" http-equiv="Content-Type" />
<meta content="noindex, nofollow" name="robots" />
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Visi&#243;n general de las nuevas funcionalidades de Apache
2.0 - Servidor HTTP Apache</title>
<link href="./style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet" />
<link href="./style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size" />
<link href="./style/css/manual-print.css" rel="stylesheet" media="print" type="text/css" />
<link href="./images/favicon.ico" rel="shortcut icon" /><link href="http://httpd.apache.org/docs/current/new_features_2_0.html" rel="canonical" /></head>
<body id="manual-page"><div id="page-header">
<p class="menu"><a href="./mod/">M&#243;dulos</a> | <a href="./mod/directives.html">Directivas</a> | <a href="./faq/">Preguntas Frecuentes</a> | <a href="./glossary.html">Glosario</a> | <a href="./sitemap.html">Mapa de este sitio web</a></p>
<p class="apache">Versi&#243;n 2.0 del Servidor HTTP Apache</p>
<img alt="" src="./images/feather.gif" /></div>
<div class="up"><a href="./"><img title="&lt;-" alt="&lt;-" src="./images/left.gif" /></a></div>
<div id="path">
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs/">Documentaci&#243;n</a> &gt; <a href="./">Versi&#243;n 2.0</a></div><div id="page-content"><div class="retired"><h4>Please note</h4>
            <p>This document refers to the <strong>2.0</strong> version of Apache httpd, which <strong>is no longer maintained</strong>. Upgrade, and refer to the current version of httpd instead, documented at:</p>
        <ul><li><a href="http://httpd.apache.org/docs/current/">Current release version of Apache HTTP Server documentation</a></li></ul><p>You may follow <a href="http://httpd.apache.org/docs/current/new_features_2_0.html">this link</a> to go to the current version of this document.</p></div><div id="preamble"><h1>Visi&#243;n general de las nuevas funcionalidades de Apache
2.0</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="./de/new_features_2_0.html" hreflang="de" rel="alternate" title="Deutsch">&nbsp;de&nbsp;</a> |
<a href="./en/new_features_2_0.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/new_features_2_0.html" title="Espa&#241;ol">&nbsp;es&nbsp;</a> |
<a href="./fr/new_features_2_0.html" hreflang="fr" rel="alternate" title="Fran&#231;ais">&nbsp;fr&nbsp;</a> |
<a href="./ja/new_features_2_0.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/new_features_2_0.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./ru/new_features_2_0.html" hreflang="ru" rel="alternate" title="Russian">&nbsp;ru&nbsp;</a> |
<a href="./tr/new_features_2_0.html" hreflang="tr" rel="alternate" title="T&#252;rk&#231;e">&nbsp;tr&nbsp;</a></p>
</div>

  <p>Este documento describe algunas de las diferencias m&#225;s
  importantes que existen entre las versiones 1.3 y 2.0 del Servidor
  HTTP Apache.</p>
</div>
<div id="quickview"><ul id="toc"><li><img alt="" src="./images/down.gif" /> <a href="#core">Principales Mejoras</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#module">Mejoras en los m&#243;dulos</a></li>
</ul><h3>Consulte tambi&#233;n</h3><ul class="seealso"><li><a href="upgrading.html">Migrar su instalaci&#243;n de la
versi&#243;n 1.3 a la 2.0</a></li></ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="core" id="core">Principales Mejoras</a></h2>
    

    <dl>
      <dt>Hebrado en Unix</dt>

      <dd>En los sistemas Unix que soportan hebras POSIX, la nueva
      versi&#243;n de Apache puede ejecutarse en modo h&#237;brido
      multiproceso-multihebra. Esto mejora la escalabilidad para
      muchas aunque no para todas las configuraciones.</dd>

      <dt>Nuevo sistema de configuraci&#243;n y compilaci&#243;n</dt>

      <dd>El sistema de configuraci&#243;n y compilaci&#243;n ha sido
      escrito de nuevo desde cero para basarlo en
      <code>autoconf</code> y <code>libtool</code>.  Esto hace que el
      sistema de configuraci&#243;n de Apache se parezca ahora
      m&#225;s al de otros proyectos Open Source.</dd>

      <dt>Soporte Multiprotocolo</dt>

      <dd>La nueva versi&#243;n tiene la infraestructura necesaria
      para servir distintos protocolos. Por ejemplo, se ha escrito el
      m&#243;dulo <code class="module"><a href="./mod/mod_echo.html">mod_echo</a></code>.</dd>

      <dt>Soporte mejorado para las plataformas que no son tipo Unix</dt>

      <dd>La versi&#243;n 2.0 de Apache es m&#225;s r&#225;pida y
      m&#225;s estable en sistemas que no son tipo Unix, tales como
      BeOS, OS/2 y Windows, que la versi&#243;n antigua. Con la
      introducci&#243;n de <a href="mpm.html">m&#243;dulos de
      multiprocesamiento</a> (MPMs) espec&#237;ficos para cada
      plataforma y del Apache Portable Runtime (APR), estas
      plataformas tienen ahora implementada su propia API nativa,
      evitando las capas de emulaci&#243;n POSIX que provocan
      problemas y un bajo rendimiento.</dd>

      <dt>Nueva interfaz de programaci&#243;n (API) de Apache</dt>

      <dd>La API para los m&#243;dulos ha cambiado significativamente
      en la nueva versi&#243;n. Muchos de los problemas de
      ordenci&#243;n y prioridad de m&#243;dulos de la versi&#243;n
      1.3 deben haber desaparecido. Apache 2.0 hace automaticamente
      mucho de lo que es necesario, y la ordenaci&#243;n de
      m&#243;dulos se hace ahora por hooks, lo que ofrece una mayor
      flexibilidad. Tambi&#233;n se han a&#241;adido nuevas llamadas
      que ofrecen capacidades adicionales sin tener que parchear el
      n&#250;cleo del servidor Apache.</dd>

      <dt>Soporte de IPv6</dt>

      <dd>En los sitemas que soportan IPv6 con la libreria Apache
      Portable Runtime, Apache soporta IPv6 listening sockets por
      defecto. Adem&#225;s, las directivas <code class="directive"><a href="./mod/mpm_common.html#listen">Listen</a></code>, <code class="directive"><a href="./mod/core.html#namevirtualhost">NameVirtualHost</a></code>, y <code class="directive"><a href="./mod/core.html#virtualhost">VirtualHost</a></code> soportan direcciones IPv6
      num&#233;ricas (por ejemplo, "<code>Listen
      [2001:db8::1]:8080</code>").</dd>

      <dt>Filtros</dt>

      <dd>Los m&#243;dulos de Apache pueden ahora escribirse para que
      se comporten como filtros que act&#250;an sobre el flujo de
      contenidos tal y como salen del servidor o tal y como son
      recibidos por el servidor. Esto permite, por ejemplo, que el
      resultado de un script CGI sea analizado por las directivas
      Server Side Include usando el filtro <code>INCLUDES</code> del
      m&#243;dulo <code class="module"><a href="./mod/mod_include.html">mod_include</a></code>. El m&#243;dulo
      <code class="module"><a href="./mod/mod_ext_filter.html">mod_ext_filter</a></code> permite que programas externos
      act&#250;en como filtros casi del mismo modo que los CGIs pueden
      actuar como handlers.</dd>

      <dt>Mensajes de error en diferentes idiomas</dt>

      <dd>Los mensajes de error que se env&#237;an a los navegadores
      est&#225;n ahora disponibles en diferentes idiomas, usando
      documentos SSI. Estos mensajes pueden personalizarse por el
      administrador del sitio web para conseguir un look and feel
      coherente con el resto de los contenidos.</dd>

      <dt>Configuraci&#243;n simplificada</dt>

      <dd>Muchas directivas que pod&#237;an inducir a confusi&#243;n
      han sido simplificadas. Las directivas <code>Port</code> y
      <code>BindAddress</code> han desaparecido; para configurar la
      direcci&#243;n IP en la que escucha el servidor ahora se usa
      &#250;nicamente la directiva <code class="directive"><a href="./mod/mpm_common.html#listen">Listen</a></code>; la directiva <code class="directive"><a href="./mod/core.html#servername">ServerName</a></code> especifica el nombre del
      servidor y el n&#250;mero del puerto solo para redirecionamiento
      y reconocimento de host virtual.</dd>

      <dt>Soporte de Unicode Nativo para Windows NT</dt>

      <dd>Apache 2.0 en Windows NT usa ahora utf-8 para la
      codificaci&#243;n de los nombres de fichero. Estos se mapean
      directamente al sistema de ficheros Unicode subyanciente,
      suministrando soporte para diferentes idiomas para todas
      instalaciones en Windows NT, includidos Windows 2000 y Windows
      XP. <em>Este soporte no se extiende a Windows 95, 98 o ME, que
      contin&#250;an usando la codificaci&#243;n que tenga la
      m&#225;quina local para el acceso al sistema de
      archivos.</em></dd>

      <dt>Actulizaci&#243;n de la librer&#237;a de expresiones
      regulares (regular expressions)</dt>

      <dd>Apache 2.0 incluye la <a href="http://www.pcre.org/">Librer&#237;a de expresiones
      regulares compatibles de/con Perl</a> (PCRE).  Ahora, cuando se
      eval&#250;an las expresiones tipo, se usa siempre la potente
      sintaxis de Perl 5.</dd>

    </dl>
  </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="module" id="module">Mejoras en los m&#243;dulos</a></h2>
    

    <dl>
      <dt><code class="module"><a href="./mod/mod_ssl.html">mod_ssl</a></code></dt>

      <dd>M&#243;dulo nuevo en Apache 2.0. Este m&#243;dulo es una
      interfaz para los protocolos de encriptado SSL/TLS de
      OpenSSL.</dd>

      <dt><code class="module"><a href="./mod/mod_dav.html">mod_dav</a></code></dt>

      <dd>M&#243;dulo nuevo en Apache 2.0. Este m&#243;dulo implementa
      la especificaci&#243;n del HTTP Distributed Authoring and
      Versioning (DAV) para colgar y mantener contenidos web.</dd>

      <dt><code class="module"><a href="./mod/mod_deflate.html">mod_deflate</a></code></dt>

      <dd>M&#243;dulo nuevo en Apache 2.0.  Este m&#243;dulo permite
      soportar nevagadores que requieren que el contenido sea
      comprimido antes de ser servido, ahorrando ancho de banda.</dd>

      <dt><code class="module"><a href="./mod/mod_auth_ldap.html">mod_auth_ldap</a></code></dt>

      <dd>M&#243;dulo nuevo en Apache 2.0.41. Este m&#243;dulo permite
      que se pueda usar una base de datos LDAP para almacenar las
      credenciales en la autentificaci&#243;n b&#225;sica HTTP.  El
      m&#243;dulo de acompa&#241;amiento, <code class="module"><a href="./mod/mod_ldap.html">mod_ldap</a></code>
      ofrece connection pooling y cache de resultados.</dd>

      <dt><code class="module"><a href="./mod/mod_auth_digest.html">mod_auth_digest</a></code></dt>

      <dd>Incluye soporte adicional para cache de sesiones entre
      procesos usando memoria compartida.</dd>

      <dt><code class="module"><a href="./mod/mod_charset_lite.html">mod_charset_lite</a></code></dt>

      <dd>M&#243;dulo nuevo en Apache 2.0. Este m&#243;dulo
      experimental permite for traducci&#243;n o recodificaci&#243;n
      de sets de caracteres.</dd>

      <dt><code class="module"><a href="./mod/mod_file_cache.html">mod_file_cache</a></code></dt>

      <dd>M&#243;dulo nuevo en Apache 2.0. Este m&#243;dulo incluye la
      funcionalidad que <code>mod_mmap_static</code> ten&#237;a en
      Apache 1.3, e incorpora nuevas capacidades de cacheado.</dd>

      <dt><code class="module"><a href="./mod/mod_headers.html">mod_headers</a></code></dt>

      <dd>Este m&#243;dulo es mucho m&#225;s flexible en Apache
      2.0. Ahora puede modificar las cabeceras de las peticiones
      usadas por <code class="module"><a href="./mod/mod_proxy.html">mod_proxy</a></code>, y puede fijar
      condicionalmente cabeceras de respuesta.</dd>

      <dt><code class="module"><a href="./mod/mod_proxy.html">mod_proxy</a></code></dt>

      <dd>El m&#243;dulo proxy ha sido completamente reescrito para
      aprovechar la nueva infraestructura de filtros y para
      implementar de una manera m&#225;s fiable un proxy que cumpla
      con requerimientos de la especificaci&#243;n
      HTTTP/1.1. Adem&#225;s, se han incorporado nuevas secciones de
      configuraci&#243;n a la directiva <code class="directive"><a href="./mod/mod_proxy.html#proxy">&lt;Proxy&gt;</a></code> que hacen mas f&#225;cil (e
      internamente m&#225;s r&#225;pido) el control de los sitios web
      que usan proxys; las configuraciones de sobrecarga
      <code>&lt;Directory "proxy:..."&gt;</code> no se soportan. El
      m&#243;dulo est&#225; ahora dividido en m&#243;dulos
      espec&#237;ficos para cada protocolo, incluidos
      <code>proxy_connect</code>, <code>proxy_ftp</code> y
      <code>proxy_http</code>.</dd>

      <dt><code class="module"><a href="./mod/mod_negotiation.html">mod_negotiation</a></code></dt>

      <dd>La nueva directiva <code class="directive"><a href="./mod/mod_negotiation.html#forcelanguagepriority">ForceLanguagePriority</a></code> se puede usar para asegurarse
      de que el cliente recibe siempre solo un documento, en lugar de
      obtener una respuesta de tipo NOT ACCEPTABLE o MULTIPLE
      CHOICES. Adem&#225;s, los algoritmos de negociaci&#243;n y
      MultiView han sido modificados para ofrecer resultados m&#225;s
      consistentes y se ha incluido a nuevo tipo de correspondecia de
      tipos (type map).</dd>

      <dt><code class="module"><a href="./mod/mod_autoindex.html">mod_autoindex</a></code></dt>

      <dd>Ahora pueden configurarse listados de directorios
      autoindexados para usar tablas HTML, darles formato de forma
      m&#225;s sencilla, y permitir control detallado del
      ordenamiento, incluidos ordenamiento por versi&#243;n, y
      filtrado usando caracteres comodines de los listados de
      directorios.</dd>

      <dt><code class="module"><a href="./mod/mod_include.html">mod_include</a></code></dt>

      <dd>Estas nuevas directivas permiten cambiar las etiquetas por
      defecto de comienzo y final para elementos SSI y permiten que la
      configuraci&#243;n de errores y el formato de la hora y la fecha
      se hagan en el fichero de configuraci&#243;n pricipal en lugar
      de en el documento SSI. Los resultados del an&#225;lisis y la
      agrupaci&#243;n de las expresiones tipo (ahora basadas en la
      sintaxis de Perl 5) pueden ser devueltos usando las variables
      <code>$0</code> .. <code>$9</code> del m&#243;dulo
      <code class="module"><a href="./mod/mod_include.html">mod_include</a></code>.</dd>

      <dt><code class="module"><a href="./mod/mod_auth_dbm.html">mod_auth_dbm</a></code></dt>

      <dd>Ahora se soportan varias clases de bases de datos de tipo
      DBM usando la directiva <code class="directive"><a href="./mod/mod_auth_dbm.html#authdbmtype">AuthDBMType</a></code>.</dd>

    </dl>
  </div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="./de/new_features_2_0.html" hreflang="de" rel="alternate" title="Deutsch">&nbsp;de&nbsp;</a> |
<a href="./en/new_features_2_0.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/new_features_2_0.html" title="Espa&#241;ol">&nbsp;es&nbsp;</a> |
<a href="./fr/new_features_2_0.html" hreflang="fr" rel="alternate" title="Fran&#231;ais">&nbsp;fr&nbsp;</a> |
<a href="./ja/new_features_2_0.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/new_features_2_0.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./ru/new_features_2_0.html" hreflang="ru" rel="alternate" title="Russian">&nbsp;ru&nbsp;</a> |
<a href="./tr/new_features_2_0.html" hreflang="tr" rel="alternate" title="T&#252;rk&#231;e">&nbsp;tr&nbsp;</a></p>
</div><div id="footer">
<p class="apache">Copyright 2013 The Apache Software Foundation.<br />Licencia bajo los t&#233;rminos de la <a href="http://www.apache.org/licenses/LICENSE-2.0">Apache License, Version 2.0</a>.</p>
<p class="menu"><a href="./mod/">M&#243;dulos</a> | <a href="./mod/directives.html">Directivas</a> | <a href="./faq/">Preguntas Frecuentes</a> | <a href="./glossary.html">Glosario</a> | <a href="./sitemap.html">Mapa de este sitio web</a></p></div>
</body></html>