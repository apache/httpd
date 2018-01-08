<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es" xml:lang="es"><head>
<meta content="text/html; charset=ISO-8859-1" http-equiv="Content-Type" />
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Mapeo de Direcciones y Puertos. - Servidor HTTP Apache Versión 2.5</title>
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
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs/">Documentación</a> &gt; <a href="./">Versión 2.5</a></div><div id="page-content"><div id="preamble"><h1>Mapeo de Direcciones y Puertos.</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="./de/bind.html" hreflang="de" rel="alternate" title="Deutsch">&nbsp;de&nbsp;</a> |
<a href="./en/bind.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/bind.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="./fr/bind.html" hreflang="fr" rel="alternate" title="Français">&nbsp;fr&nbsp;</a> |
<a href="./ja/bind.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/bind.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./tr/bind.html" hreflang="tr" rel="alternate" title="Türkçe">&nbsp;tr&nbsp;</a></p>
</div>

    <p>Configurando Apache HTTP Server para que escuche en una dirección y puertos específicos.</p>
  </div>
<div id="quickview"><ul id="toc"><li><img alt="" src="./images/down.gif" /> <a href="#overview">Visión General</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#ipv6">Consideraciones especiales con IPv6</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#protocol">Especificar el Protocolo en el Listen</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#virtualhost">Como Funciona en los Hosts Virtuales</a></li>
</ul><h3>Consulte también</h3><ul class="seealso"><li><a href="vhosts/">Hosts Virtuales</a></li><li><a href="dns-caveats.html">Problemas de DNS</a></li><li><a href="#comments_section">Comentarios</a></li></ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="overview" id="overview">Visión General</a></h2>
    

    <table class="related"><tr><th>Módulos Relacionados</th><th>Directivas Relacionadas</th></tr><tr><td><ul><li><code class="module"><a href="./mod/core.html">core</a></code></li><li><code class="module"><a href="./mod/mpm_common.html">mpm_common</a></code></li></ul></td><td><ul><li><code class="directive"><a href="./mod/core.html#virtualhost">&lt;VirtualHost&gt;</a></code></li><li><code class="directive"><a href="./mod/mpm_common.html#listen">Listen</a></code></li></ul></td></tr></table>


    <p>Cuando httpd se ejecuta, se mapea a una dirección y un puerto en la
    máquina local, y espera a recibir peticiones. Por defecto, escucha en 
    todas las direcciones de la máquina. Ahora bien, se le puede especificar 
    que escuche en un determinado puerto, o en una sola dirección IP especifica, 
    o una combinación de ambos. A menudo esto se combina con la característica
    de los <a href="vhosts/">Hosts virtuales</a>, que determina como responde el 
    <code>httpd</code> a diferentes direcciones IP, nombres de máquinas y puertos.</p>

    <p>La directiva <code class="directive"><a href="./mod/mpm_common.html#listen">Listen</a></code>
     le dice al servidor que acepte peticiones en el puerto o puertos que
     se le especifiquen al servidor, o a combinaciones de direcciones y 
     puertos. Si sólo se especifica el número del puerto en la directiva
     <code class="directive"><a href="./mod/mpm_common.html#listen">Listen</a></code>, el servidor escuchará en 
     ese puerto pero en todas las interfaces de red.
     Si además del puerto se le especifica una dirección IP, el servidor escuchará 
     en el puerto y en la interfaz de red asociado a la dirección IP 
     que se le ha especificado en la directiva. Se pueden especificar 
     múltiples directivas <code class="directive"><a href="./mod/mpm_common.html#listen">Listen</a></code> para 
     especificar un determinado número de IP´s y puertos por donde el servidor escuchará.
     El servidor por tanto, responderá a las peticiones en cualquiera de las IP´s y puertos
     listados en la directiva.</p>

    <p>Por ejemplo, para hacer que el servidor escuche en ambos puertos 80 y 8080 en todas 
    	sus interfaces de red, se usa lo siguiente:</p>

    <div class="example"><pre class="prettyprint lang-config">Listen 80
Listen 8000</pre>
</div>

    <p>Para hacer que el servidor acepte peticiones en el puerto 80 en una sola interfaz de red, usaremos:</p>

    <div class="example"><pre class="prettyprint lang-config">Listen 192.0.2.1:80
Listen 192.0.2.5:8000</pre>
</div>

    <p>Las direcciones IPv6 debrán ir entre '[ ]' corchetes como en el siguiente ejemplo:</p>

    <div class="example"><pre class="prettyprint lang-config">Listen [2001:db8::a00:20ff:fea7:ccea]:80</pre>
</div>

    <div class="warning"><p>Si se superponen directivas de tipo <code class="directive"><a href="./mod/mpm_common.html#listen">Listen</a></code>, dará como resultado un error fatal
    que impedirá que se inicie el servidor.</p>

    <div class="example"><p><code>
      (48)Address already in use: make_sock: could not bind to address [::]:80
    </code></p></div>

    <p>Puede mirar el <a href="http://wiki.apache.org/httpd/CouldNotBindToAddress">articulo de la wiki</a>
    de consejos para solucionar problemas relacionados.</p>

</div>

  </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="ipv6" id="ipv6">Consideraciones especiales con IPv6</a></h2>
    

    <p>Un creciente número de plataformas implementan ya IPv6, y 
    <a class="glossarylink" href="./glossary.html#apr" title="ver glosario">APR</a> soporta IPv6 en la mayoría de estas plataformas, 
    permitiendo así a httpd asignar sockets IPv6, y manejar las respuestas 
    enviadas a través de IPv6.</p>

    <p>Un factor bastante complejo para un administrador del httpd 
    es si un socket IPv6 puede o no manejar tanto conexiones IPv6 
    como IPv4. El manejo por httpd de conexiones IPv4 con socket IPv6 
    se debe al mapeo de direcciones IPv4 sobre IPv6, que 
    está permitido por defecto en muchas plataformas, pero no lo está 
    en sistemas FreeBSD, NetBSD y Open BSD, con el fin de que en estas 
    plataformas, cumpla con la política del sistema.
    En los sistemas que no está permitido el mapeo por defecto, 
    existe un parámetro de <code class="program"><a href="./programs/configure.html">configure</a></code> especial 
    para cambiar éste comportamiento para httpd.</p>

    <p>Por otro lado, en algunas plataformas, como Linux y True64, la 
    <strong>única</strong> forma para el manejo de IPv4 e IPv6 al mismo 
    tiempo es mediante direcciones mapeadas.
    Si quieres que <code>httpd</code> maneje amos tipos de conexiones IPv4 e IPv6
    con el mínimo de sockets, hay que especificar la opción 
    <code>--enable-v4-mapped</code> al <code class="program"><a href="./programs/configure.html">configure</a></code>.</p>

    <p><code>--enable-v4-mapped</code> es la opción que está estipulada por defecto
    en todos los sistemas menos en FreeBSD, NetBSD y Open BSD, por 
    lo que es probablemente como se compiló su httpd.</p>

    <p>Si lo que quiere es manejar sólo conexiones IPv4, independientemente de 
    lo que soporten <a class="glossarylink" href="./glossary.html#apr" title="ver glosario">APR</a> y su plataforma, especifique 
    una dirección IPv4 por cada directiva 
    <code class="directive"><a href="./mod/mpm_common.html#listen">Listen</a></code>, como en el siguiente 
    ejemplo:</p>

    <div class="example"><pre class="prettyprint lang-config">Listen 0.0.0.0:80
Listen 192.0.2.1:80</pre>
</div>

    <p>Si en cambio, su plataforma lo soporta, y lo que quiere es que su httpd 
    soporte tanto conexiones IPv4 como IPv6 en diferentes sockets (ejemplo.: para 
    deshabilitar mapeo de direcciones IPv4), especifique la opción 
    <code>--disable-v4-mapped</code> al <code class="program"><a href="./programs/configure.html">configure</a></code>. <code>--disable-v4-mapped</code> es la opción por defecto 
    en FreeBSD, NetBSD y OpenBSD.</p>
  </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="protocol" id="protocol">Especificar el Protocolo en el Listen</a></h2>
    
    <p>El segundo argumento en la directiva <code class="directive"><a href="./mod/mpm_common.html#listen">Listen</a></code>
    el <var>protocolo</var> que es opcional no es algo que se requiera en las configuraciones.
    Si éste argumento no se especifica, <code>https</code> es el protocolo 
    usado por defecto en el puerto 443 y <code>http</code>  para el resto.
    El protocolo se utiliza para determinar que módulo deberá manejar la petición,
    y se le aplicarán optimizaciones específicas del protocolo con la directiva
    <code class="directive"><a href="./mod/core.html#acceptfilter">AcceptFilter</a></code>.</p>

    <p>Sólo necesitará especificar el protocolo si no está escuchando en un puerto
    de los que son estándares, por ejemplo si ejecuta un sitio web <code>https</code> en el puerto 8443:</p>

    <div class="example"><pre class="prettyprint lang-config">Listen 192.170.2.1:8443 https</pre>
</div>
  </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="virtualhost" id="virtualhost">Como Funciona en los Hosts Virtuales</a></h2>
    

    <p> La directiva <code class="directive"><a href="./mod/mpm_common.html#listen">Listen</a></code> no implementa los
    Hosts Virtuales - solo le dice al servidor en que direcciones 
    y puertos debe escuchar. Si no hay directiva 
    <code class="directive"><a href="./mod/core.html#virtualhost">&lt;VirtualHost&gt;</a></code>
    en uso, el servidor se comportará de la misma manera para todas las 
    peticiones aceptadas. Ahora bien,
    <code class="directive"><a href="./mod/core.html#virtualhost">&lt;VirtualHost&gt;</a></code>
    puede ser usado para especificar un comportamiento diferente en una o 
    varias direcciones o puertos.
    Para implementar los Hosts Virtuales, antes se le tiene que decir al servidor
    que direcciones y puertos van a ser usados. 
    Después de esto, se deberá especificar una sección de la directiva
    <code class="directive"><a href="./mod/core.html#virtualhost">&lt;VirtualHost&gt;</a></code> 
    especificando direcciones y puertos que se van a usar en el Host Virtual
    Note que si se configura un 
    <code class="directive"><a href="./mod/core.html#virtualhost">&lt;VirtualHost&gt;</a></code>
    para una dirección y puerto en el que el servidor no está escuchando,
    no se podrá acceder al Host Virtual.</p>
  </div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="./de/bind.html" hreflang="de" rel="alternate" title="Deutsch">&nbsp;de&nbsp;</a> |
<a href="./en/bind.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/bind.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="./fr/bind.html" hreflang="fr" rel="alternate" title="Français">&nbsp;fr&nbsp;</a> |
<a href="./ja/bind.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/bind.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./tr/bind.html" hreflang="tr" rel="alternate" title="Türkçe">&nbsp;tr&nbsp;</a></p>
</div><div class="top"><a href="#page-header"><img src="./images/up.gif" alt="top" /></a></div><div class="section"><h2><a id="comments_section" name="comments_section">Comentarios</a></h2><div class="warning"><strong>Notice:</strong><br />This is not a Q&amp;A section. Comments placed here should be pointed towards suggestions on improving the documentation or server, and may be removed again by our moderators if they are either implemented or considered invalid/off-topic. Questions on how to manage the Apache HTTP Server should be directed at either our IRC channel, #httpd, on Freenode, or sent to our <a href="http://httpd.apache.org/lists.html">mailing lists</a>.</div>
<script type="text/javascript"><!--//--><![CDATA[//><!--
var comments_shortname = 'httpd';
var comments_identifier = 'http://httpd.apache.org/docs/trunk/bind.html';
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