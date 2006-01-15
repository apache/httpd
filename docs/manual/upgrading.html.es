<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es" xml:lang="es"><head><!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Pasar a usar Apache 2.0 si ahora usa Apache 1.3 - Servidor HTTP Apache</title>
<link href="./style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet" />
<link href="./style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size" />
<link href="./style/css/manual-print.css" rel="stylesheet" media="print" type="text/css" />
<link href="./images/favicon.ico" rel="shortcut icon" /></head>
<body id="manual-page"><div id="page-header">
<p class="menu"><a href="./mod/">Módulos</a> | <a href="./mod/directives.html">Directivas</a> | <a href="./faq/">Preguntas Frecuentes</a> | <a href="./glossary.html">Glosario</a> | <a href="./sitemap.html">Mapa de este sitio web</a></p>
<p class="apache">Versión 2.0 del Servidor HTTP Apache</p>
<img alt="" src="./images/feather.gif" /></div>
<div class="up"><a href="./"><img title="&lt;-" alt="&lt;-" src="./images/left.gif" /></a></div>
<div id="path">
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs/">Documentación</a> &gt; <a href="./">Versión 2.0</a></div><div id="page-content"><div id="preamble"><h1>Pasar a usar Apache 2.0 si ahora usa Apache 1.3</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="./de/upgrading.html" hreflang="de" rel="alternate" title="Deutsch">&nbsp;de&nbsp;</a> |
<a href="./en/upgrading.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/upgrading.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="./fr/upgrading.html" hreflang="fr" rel="alternate" title="Français">&nbsp;fr&nbsp;</a> |
<a href="./ja/upgrading.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/upgrading.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./ru/upgrading.html" hreflang="ru" rel="alternate" title="Russian">&nbsp;ru&nbsp;</a></p>
</div>

  <p>Este documento recoge infomación crítica sobre el
  proceso de actulización de la versión de Apache que
  usa. Se trata de pequeños comentarios. Puede encontrar más
  información tanto en <a href="new_features_2_0.html">Nuevas
  funcionalidades</a>, como en el archivo
  <code>src/CHANGES</code>.</p>
</div>
<div id="quickview"><ul id="toc"><li><img alt="" src="./images/down.gif" /> <a href="#compile-time">Cambios en el proceso de configuración y
    compilación</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#run-time">Cambios en el proceso de configuración inicial del
    servidor</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#misc">Cambios de menor importancia</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#third-party">Módulos de terceras partes</a></li>
</ul><h3>Consulte también</h3><ul class="seealso"><li><a href="new_features_2_0.html">Visión general de las
nuevas funcionalidades de Apache 2.0</a></li></ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="compile-time" id="compile-time">Cambios en el proceso de configuración y
    compilación</a></h2>
    

    <ul>
      <li>Apache usa ahora <code>autoconf</code> y
      <code>libtool</code> <a href="install.html"> en el proceso de
      compilación</a>.  Este sistema es parecido aunque no igual
      al sistema APACI de Apache 1.3.</li>

      <li>Además de la selección de módulos habitual
      que puede hacer al compilar, en Apache 2.0 la mayor parte del
      procesamiento de las petición es llevada a cabo por <a href="mpm.html">módulos de multiprocesamiento</a>
      (MPMs).</li>
    </ul>
  </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="run-time" id="run-time">Cambios en el proceso de configuración inicial del
    servidor</a></h2>
    

    <ul>
      <li>Muchas directivas que pertenecían al core (núcleo)
      del servidor en Apache 1.3 se encuentran ahora en distintos
      módulos de multiprocesamiento. Si desea que el nuevo
      servidor de comporte de la forma más parecida posible a
      como lo hacía Apache 1.3, debe usar el módulo de
      multiprocesamiento <code class="module"><a href="./mod/prefork.html">prefork</a></code>. Otros módulos
      de multiprocesamiento tienen diferentes directivas para
      controlar la creación de procesos y el procesamiento de
      peticiones.</li>

      <li>El <a href="mod/mod_proxy.html">módulo proxy</a> ha
      sido remodelado para ponerlo al día con la
      especificación HTTP/1.1.  Entre los cambios más
      importantes está el que ahora el control de acceso al proxy
      está dentro de un bloque <code class="directive"><a href="./mod/mod_proxy.html#proxy">&lt;Proxy&gt;</a></code> en lugar de en un bloque
      <code>&lt;Directory proxy:&gt;</code>.</li>

      <li>El procesamiento de <code>PATH_INFO</code> (la
      información que aparece detrás de un nombre de fichero
      válido) ha cambiado en algunos módulos. Los
      módulos que fueron previamente implementados como un handler
      pero que ahora son implementados como un filtro puede que no
      acepten peticiones que incluyan <code>PATH_INFO</code>. Filtros
      como <a href="mod/mod_include.html">INCLUDES</a> o <a href="http://www.php.net/">PHP</a> están implementados
      sobre el handler principal (core handler), y por tanto
      rechazarán peticiones con <code>PATH_INFO</code>. Puede
      usar la directiva <code class="directive"><a href="./mod/core.html#acceptpathinfo">AcceptPathInfo</a></code> para forzar al handler
      principal a aceptar peticiones con <code>PATH_INFO</code> y por
      tanto restaurar la posibilidad de usar <code>PATH_INFO</code> en
      server-side includes.</li>

      <li>La directiva <code class="directive"><a href="./mod/mod_negotiation.html#cachenegotiateddocs">CacheNegotiatedDocs</a></code> toma
      ahora como argumento <code>on</code> u <code>off</code>. Las
      instancias existentes de <code class="directive">CacheNegotiatedDocs</code> deben reemplazarse por
      <code>CacheNegotiatedDocs on</code>.</li>

      <li>
        La directiva <code class="directive"><a href="./mod/core.html#errordocument">ErrorDocument</a></code> no usa ya dobles
        comillas al principio del argumento para indicar el mensaje de
        texto a mostrar. En lugar de esto, ponga entre comillas todo
        el mensaje. Por ejemplo,

        <div class="example"><p><code>
          ErrorDocument 403 "Mensaje
        </code></p></div>
        debe sustituirse por

        <div class="example"><p><code>
          ErrorDocument 403 "Mensaje"
        </code></p></div>

        Si el segundo argumento no es una URL o una ruta válida a
        un archivo, será tratado como un mensaje de texto.
      </li>

      <li>Las directivas <code>AccessConfig</code> y
      <code>ResourceConfig</code> han desaparecido.  Las instancias
      existentes de estas directivas pueden ser sustituidas por
      directivas <code class="directive"><a href="./mod/core.html#include">Include</a></code> que
      tienen una funcionalidad equivalente. Si hacía uso de los
      valores por defecto de esas directivas sin incluirlas en los
      ficheros de configuración, puede que necesite añadir
      <code>Include conf/access.conf</code> e <code>Include
      conf/srm.conf</code> a su fichero <code>httpd.conf</code>. Para
      asegurar que Apache lee el fichero de configuración en el
      mismo orden que asumían las antiguas directivas, las
      directivas <code class="directive"><a href="./mod/core.html#include">Include</a></code> deben
      ser reemplazadas al final del fichero <code>httpd.conf</code>,
      con la de <code>srm.conf</code> precediendo a la de
      <code>access.conf</code>.</li>

      <li>Las directivas <code>BindAddress</code> y <code>Port</code>
      no existen ya. Las funcionalidades que ofrecían esas
      directivas están ahora cubiertas por la directiva
      <code class="directive"><a href="./mod/mpm_common.html#listen">Listen</a></code>, que es mucho
      más flexible.</li>

      <li>Otro uso de la directiva <code>Port</code> en Apache 1.3 era
      fijar el número de puerto que se usaba para URLs
      autoreferenciadas. La directiva equivalente en Apache 2.0 es la
      nueva directiva <code class="directive"><a href="./mod/core.html#servername">ServerName</a></code>:
      este cambio se ha introducido para permitir la
      especificación del nombre de host <em>y</em> del
      número de puerto para URLs autorreferenciadas en una sola
      directiva.</li>

      <li>La directiva <code>ServerType</code> ha dejado de existir.
      El método usado para servir peticiones está ahora
      determinado por la selección del módulo de
      multiprocesamiento. Actualmente no hay diseñado un
      módulo de multiprocesamiento que pueda ser ejecutado por
      inetd.</li>

      <li>Los módulos <code>mod_log_agent</code> y
      <code>mod_log_referer</code> que contenían las directivas
      <code>AgentLog</code>, <code>RefererLog</code> y
      <code>RefererIgnore</code> han desaparecido. Los registros de
      "agente" y de "referer" están disponibles todavía
      usando la directiva <code class="directive"><a href="./mod/mod_log_config.html#customlog">CustomLog</a></code> del módulo
      <code class="module"><a href="./mod/mod_log_config.html">mod_log_config</a></code>.</li>

      <li>Las directivas <code>AddModule</code> y
      <code>ClearModuleList</code> no están presentes en la nueva
      versión de Apache.  Estas directivas se usaban para
      asegurar que los módulos pudieran activarse en el orden
      correcto. La nueva API de Apache 2.0 permite a los módulos
      especificar explícitamente su orden de activación,
      eliminando la necesidad de las antiguas directivas.</li>

      <li>La directiva <code>FancyIndexing</code> se ha eliminado.  La
      funcionalidad que cubría está ahora disponible a
      través de la opción <code>FancyIndexing</code> de la
      directiva <code class="directive"><a href="./mod/mod_autoindex.html#indexoptions">IndexOptions</a></code>.</li>

      <li>La técnica de negociación de contenido MultiViews
      ofrecida por <code class="module"><a href="./mod/mod_negotiation.html">mod_negotiation</a></code> es ahora más
      estricta en su algoritmo de selección de ficheros y solo
      seleccionará ficheros <em>negociables</em>.  El antiguo
      comportamiento puede restaurarse usando la directiva <code class="directive"><a href="./mod/mod_mime.html#multiviewsmatch">MultiviewsMatch</a></code>.</li>

      <li>(<em>a partir de la versión 2.0.51</em>) <p>La
      funcionalidad de la directiva <code>ErrorHeader</code> se ha
      unido con la de la directiva <code class="directive"><a href="./mod/mod_headers.html#header">Header</a></code>, porque se estaba usando
      un término equivocado. Use</p>
 
      <div class="example"><p><code>
        Header always set foo bar
      </code></p></div>

      <p>en lugar de conseguir el comportamiento deseado.</p></li>

    </ul>
  </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="misc" id="misc">Cambios de menor importancia</a></h2>
    

    <ul>
      <li>El módulo <code class="module"><a href="./mod/mod_auth_digest.html">mod_auth_digest</a></code>, que era
      experimental en Apache 1.3, es ahora un módulo
      estándar.</li>

      <li>El módulo <code>mod_mmap_static</code>, que era
      experimental en Apache 1.3, ha sido sustituido por el
      módulo <code class="module"><a href="./mod/mod_file_cache.html">mod_file_cache</a></code>.</li>

      <li>La distribución de Apache ha sido reorganizada por
      completo para que no contenga a partir de ahora el directorio
      independiente <code>src</code>. En su lugar, el código
      fuente se ha organizado a partir del directorio principal de la
      distribución, y las intalaciones del servidor compilado
      deben hacerse en un directorio diferente.</li>
    </ul>
  </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="third-party" id="third-party">Módulos de terceras partes</a></h2>
    

    <p>La API de Apache 2.0 ha sufrido grandes cambios respecto a la
    versión 1.3. Los módulos que se diseñaron para la
    API de Apache 1.3 <strong>no</strong> funcionarán si no se
    hacen las modificaciones necasarias para adaptarlos a Apache 2.0.
    En la <a href="developer/">documentación para
    desarrolladores</a> puede encontrar información detallada
    sobre este asunto.</p>
  </div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="./de/upgrading.html" hreflang="de" rel="alternate" title="Deutsch">&nbsp;de&nbsp;</a> |
<a href="./en/upgrading.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/upgrading.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="./fr/upgrading.html" hreflang="fr" rel="alternate" title="Français">&nbsp;fr&nbsp;</a> |
<a href="./ja/upgrading.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/upgrading.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./ru/upgrading.html" hreflang="ru" rel="alternate" title="Russian">&nbsp;ru&nbsp;</a></p>
</div><div id="footer">
<p class="apache">Copyright 1995-2006 The Apache Software Foundation or its licensors, as applicable.<br />Licencia bajo los términos de la <a href="http://www.apache.org/licenses/LICENSE-2.0">Apache License, Version 2.0</a>.</p>
<p class="menu"><a href="./mod/">Módulos</a> | <a href="./mod/directives.html">Directivas</a> | <a href="./faq/">Preguntas Frecuentes</a> | <a href="./glossary.html">Glosario</a> | <a href="./sitemap.html">Mapa de este sitio web</a></p></div>
</body></html>