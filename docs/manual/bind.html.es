<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es" xml:lang="es"><head><!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Direcciones IP y puertos de escucha - Servidor HTTP Apache</title>
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
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs-project/">Documentación</a> &gt; <a href="./">Versión 2.0</a></div><div id="page-content"><div id="preamble"><h1>Direcciones IP y puertos de escucha</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="./en/bind.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/bind.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="./fr/bind.html" hreflang="fr" rel="alternate" title="Français">&nbsp;fr&nbsp;</a> |
<a href="./ja/bind.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/bind.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a></p>
</div>

    <p>Cómo configurar Apache para que escuche en direcciones IP
    y puertos específicos.</p>
  </div>
<div id="quickview"><ul id="toc"><li><img alt="" src="./images/down.gif" /> <a href="#overview">Introducción</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#ipv6">Consideraciones especiales para IPv6</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#virtualhost">Cómo funciona este mecanismo en hosts virtuales</a></li>
</ul><h3>Consulte también</h3><ul class="seealso"><li><a href="vhosts/">Hosts virtuales</a></li><li><a href="dns-caveats.html">Asuntos relacionados con DNS</a></li></ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="overview" id="overview">Introducción</a></h2>
    

    <table class="related"><tr><th>Módulos Relacionados</th><th>Directivas Relacionadas</th></tr><tr><td><ul><li><code class="module"><a href="./mod/core.html">core</a></code></li><li><code class="module"><a href="./mod/mpm_common.html">mpm_common</a></code></li></ul></td><td><ul><li><code class="directive"><a href="./mod/core.html#virtualhost">&lt;VirtualHost&gt;</a></code></li><li><code class="directive"><a href="./mod/mpm_common.html#listen">Listen</a></code></li></ul></td></tr></table>


    <p>Cuando Apache se inicia, comienza a esperar peticiones
    entrantes en determinados puertos y direcciones de la máquina
    en la que se está ejecutando. Sin embargo, si quiere que
    Apache escuche solamente en determinados puertos específicos,
    o solamente en determinadas direcciones, o en una combinación
    de ambos, debe especificarlo adecuadamente. Esto puede además
    combinarlo con la posibilidad de usar hosts virtuales,
    funcionalidad con la que un servidor Apache puede responder a
    peticiones en diferentes direcciones IP, diferentes nombres de
    hosts y diferentes puertos.</p>

    <p>La directiva <code class="directive"><a href="./mod/mpm_common.html#listen">Listen</a></code>
    le indica al servidor que acepte peticiones entrantes solamente en
    los puertos y en las combinaciones de puertos y direcciones que se
    especifiquen. Si solo se especifica un número de puerto en la
    directiva <code class="directive"><a href="./mod/mpm_common.html#listen">Listen</a></code> el
    servidor escuchará en ese puerto, en todas las interfaces de
    red de la máquina. Si se especifica una dirección IP y
    un puerto, el servidor escuchará solamente en la interfaz de
    red a la que pertenezca esa dirección IP y solamente en el
    puerto indicado. Se pueden usar varias directivas <code class="directive"><a href="./mod/mpm_common.html#listen">Listen</a></code> para
    especificar varias direcciones IP y puertos de escucha. El
    servidor responderá a las peticiones de todas las direcciones
    y puertos que se incluyan.</p>

    <p>Por ejemplo, para hacer que el servidor acepte conexiones tanto
    en el puerto 80 como en el puerto 8000, puede usar:</p>

    <div class="example"><p><code>
      Listen 80<br />
      Listen 8000
    </code></p></div>

    <p>Para hacer que el servidor acepte conexiones en dos interfaces
    de red y puertos específicos, use</p>

    <div class="example"><p><code>
      Listen 192.170.2.1:80<br />
      Listen 192.170.2.5:8000
    </code></p></div>

    <p>Las direcciones IPv6 deben escribirse entre corchetes, como en el siguiente ejemplo:</p>

    <div class="example"><p><code>
      Listen [2001:db8::a00:20ff:fea7:ccea]:80
    </code></p></div>
  </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="ipv6" id="ipv6">Consideraciones especiales para IPv6</a></h2>
    

    <p>Cada vez más plataformas implementan IPv6, y APR soporta
    IPv6 en la mayor parte de esas plataformas, permitiendo que Apache
    use sockets IPv6 y pueda tratar las peticiones que se envían
    con IPv6.</p>

    <p>Un factor de complejidad para los administradores de Apache es
    si un socket IPv6 puede tratar tanto conexiones IPv4 como
    IPv6. Para tratar conexiones IPv4 con sockets IPv6 se utiliza un
    traductor de direcciones IPv4-IPv6, cuyo uso está permitido
    por defecto en la mayor parte de las plataformas, pero que
    está desactivado por defecto en FreeBSD, NetBSD, y OpenBSD
    para cumplir con la política system-wide en esas
    palaformas. Pero incluso en los sistemas en los que no está
    permitido su uso por defecto, un parámetro especial de
    <code class="program"><a href="./programs/configure.html">configure</a></code> puede modificar ese
    comportamiento.</p>

    <p>Si quiere que Apache trate conexiones IPv4 y IPv6 con un
    mínimo de sockets, lo que requiere traducir direcciones IPv4
    a IPv6, especifique la opción de <code class="program"><a href="./programs/configure.html">configure</a></code>
    <code>--enable-v4-mapped</code> y use directivas <code class="directive"><a href="./mod/mpm_common.html#listen">Listen</a></code> genéricas de la
    siguiente forma:</p>

    <div class="example"><p><code>
      Listen 80
    </code></p></div>

    <p>Con <code>--enable-v4-mapped</code>, las directivas Listen en
    el fichero de configuración por defecto creado por Apache
    usarán ese formato. <code>--enable-v4-mapped</code> es el
    valor por defecto en todas las plataformas excepto en FreeBSD,
    NetBSD, y OpenBSD, de modo que esa es probablemente la manera en
    que su servidor Apache fue construido.</p>

    <p>Si quiere que Apache solo procese conexiones IPv4, sin tener en
    cuenta cuál es su plataforma o qué soporta APR, especifique
    una dirección IPv4 en todas las directivas <code class="directive"><a href="./mod/mpm_common.html#listen">Listen</a></code>, como en
    estos ejemplos:</p>

    <div class="example"><p><code>
      Listen 0.0.0.0:80<br />
      Listen 192.170.2.1:80
    </code></p></div>

    <p>Si quiere que Apache procese conexiones IPv4 y IPv6 en sockets
    diferentes (es decir, deshabilitar la conversión de
    direcciones IPv4 a IPv6), especifique la opción de
    <code class="program"><a href="./programs/configure.html">configure</a></code> <code>--disable-v4-mapped</code> y
    use directivas Listen específicas como en el siguiente ejemplo:</p>

    <div class="example"><p><code>
      Listen [::]:80<br />
      Listen 0.0.0.0:80
    </code></p></div>

    <p>Con <code>--disable-v4-mapped</code>, las directivas Listen en
    el fichero de configuración que Apache crea por defecto
    usarán ese formato. <code>--disable-v4-mapped</code> se usa
    por defecto en FreeBSD, NetBSD, y OpenBSD.</p>

  </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="virtualhost" id="virtualhost">Cómo funciona este mecanismo en hosts virtuales</a></h2>
    

    <p><code class="directive"><a href="./mod/mpm_common.html#listen">Listen</a></code> no implementa
    hosts virtuales. Solo le dice al servidor
    principal en qué direcciones y puertos tiene que escuchar. Si no
    se usan directivas <code class="directive"><a href="./mod/core.html#virtualhost">&lt;VirtualHost&gt;</a></code>, el servidor se comporta de
    la misma manera con todas las peticiones que se acepten. Sin
    embargo, <code class="directive"><a href="./mod/core.html#virtualhost">&lt;VirtualHost&gt;</a></code> puede usarse para
    especificar un comportamiento diferente en una o varias
    direcciones y puertos. Para implementar un host virtual, hay que
    indicarle primero al servidor que escuche en aquellas direcciones y
    puertos a usar. Entonces se debe crear un una sección
    <code class="directive"><a href="./mod/core.html#virtualhost">&lt;VirtualHost&gt;</a></code>
    en una dirección y puerto específicos para determinar
    el comportamiento de ese host virtual. Tenga en cuenta que si se
    especifica en una sección <code class="directive"><a href="./mod/core.html#virtualhost">&lt;VirtualHost&gt;</a></code> una dirección y puerto
    en los que el servidor no está escuchando, ese host virtual no
    podrá ser accedido.</p>
  </div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="./en/bind.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/bind.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="./fr/bind.html" hreflang="fr" rel="alternate" title="Français">&nbsp;fr&nbsp;</a> |
<a href="./ja/bind.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/bind.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a></p>
</div><div id="footer">
<p class="apache">Copyright 1995-2005 The Apache Software Foundation or its licensors, as applicable.<br />Licencia bajo los términos de la <a href="http://www.apache.org/licenses/LICENSE-2.0">Apache License, Version 2.0</a>.</p>
<p class="menu"><a href="./mod/">Módulos</a> | <a href="./mod/directives.html">Directivas</a> | <a href="./faq/">Preguntas Frecuentes</a> | <a href="./glossary.html">Glosario</a> | <a href="./sitemap.html">Mapa de este sitio web</a></p></div>
</body></html>