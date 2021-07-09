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
<title>Documentaci&#243;n sobre Hosting Virtual en Apache - Servidor HTTP Apache</title>
<link href="../style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet" />
<link href="../style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size" />
<link href="../style/css/manual-print.css" rel="stylesheet" media="print" type="text/css" />
<link href="../images/favicon.ico" rel="shortcut icon" /><link href="http://httpd.apache.org/docs/current/vhosts/index.html" rel="canonical" /></head>
<body id="manual-page"><div id="page-header">
<p class="menu"><a href="../mod/">M&#243;dulos</a> | <a href="../mod/directives.html">Directivas</a> | <a href="../faq/">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa de este sitio web</a></p>
<p class="apache">Versi&#243;n 2.0 del Servidor HTTP Apache</p>
<img alt="" src="../images/feather.gif" /></div>
<div class="up"><a href="../"><img title="&lt;-" alt="&lt;-" src="../images/left.gif" /></a></div>
<div id="path">
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs/">Documentaci&#243;n</a> &gt; <a href="../">Versi&#243;n 2.0</a></div><div id="page-content"><div class="retired"><h4>Please note</h4>
            <p>This document refers to the <strong>2.0</strong> version of Apache httpd, which <strong>is no longer maintained</strong>. Upgrade, and refer to the current version of httpd instead, documented at:</p>
        <ul><li><a href="http://httpd.apache.org/docs/current/">Current release version of Apache HTTP Server documentation</a></li></ul><p>You may follow <a href="http://httpd.apache.org/docs/current/vhosts/">this link</a> to go to the current version of this document.</p></div><div id="preamble"><h1>Documentaci&#243;n sobre Hosting Virtual en Apache</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="../de/vhosts/" hreflang="de" rel="alternate" title="Deutsch">&nbsp;de&nbsp;</a> |
<a href="../en/vhosts/" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/vhosts/" title="Espa&#241;ol">&nbsp;es&nbsp;</a> |
<a href="../ja/vhosts/" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="../ko/vhosts/" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="../ru/vhosts/" hreflang="ru" rel="alternate" title="Russian">&nbsp;ru&nbsp;</a> |
<a href="../tr/vhosts/" hreflang="tr" rel="alternate" title="T&#252;rk&#231;e">&nbsp;tr&nbsp;</a></p>
</div>


    <p>El t&#233;rmino <cite>Hosting Virtual</cite> se refiere a hacer
    funcionar m&#225;s de un sitio web (tales como
    <code>www.company1.com</code> y <code>www.company2.com</code>) en
    una sola m&#225;quina. Los sitios web virtuales pueden estar "<a href="ip-based.html">basados en direcciones IP</a>", lo que
    significa que cada sitio web tiene una direcci&#243;n IP diferente, o
    "<a href="name-based.html">basados en nombres diferentes</a>", lo
    que significa que con una sola direcci&#243;n IP est&#225;n funcionando
    sitios web con diferentes nombres (de dominio). El hecho de que est&#233;n
    funcionando en la misma m&#225;quina f&#237;sica pasa completamente
    desapercibido para el usuario que visita esos sitios web.</p>

    <p>Apache fue uno de los primeros servidores web en soportar
    hosting virtual basado en direcciones IP. Las versiones 1.1 y
    posteriores de Apache soportan hosting virtual (vhost) basado tanto
    en direcciones IP como basado en nombres. &#201;sta &#250;ltima variante de
    hosting virtual se llama algunas veces <em>basada en host</em> o
    <em>hosting virtual no basado en IP</em>.</p>

    <p>M&#225;s abajo se muestra un listado de documentos que explican en
    detalle c&#243;mo funciona el hosting virtual en las versiones de
    Apache 1.3 y posteriores.</p>

</div>
<div id="quickview"><ul id="toc"><li><img alt="" src="../images/down.gif" /> <a href="#support">Soporte de Hosting Virtual</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#directives">Directivas de configuraci&#243;n</a></li>
</ul><h3>Consulte tambi&#233;n</h3><ul class="seealso"><li><code class="module"><a href="../mod/mod_vhost_alias.html">mod_vhost_alias</a></code></li><li><a href="name-based.html">Hosting virtual basado en nombres</a></li><li><a href="ip-based.html">Hosting virtual basado en IPs</a></li><li><a href="examples.html">Ejemplo de Hosting Virtual</a></li><li><a href="fd-limits.html">L&#237;mites de descriptores de ficheros</a></li><li><a href="mass.html">Hosting virtual masivo</a></li><li><a href="details.html">Detalles del proceso de selecci&#243;n de
host virtual</a></li></ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="support" id="support">Soporte de Hosting Virtual</a></h2>

    <ul>
      <li><a href="name-based.html">Hosting virtual basado en
      nombres</a> (M&#225;s de un sitio web con una sola direcci&#243;n IP)</li>
      <li><a href="ip-based.html">Hosting virtual basado en IPs</a>
      (Una direcci&#243;n IP para cada sitio web)</li>
      <li><a href="examples.html">Ejemplos t&#237;picos de
      configuraci&#243;n para usar hosting virtual</a></li>
      <li><a href="fd-limits.html">L&#237;mites a los descriptores de
      ficheros</a> (o, <em>demasiados ficheros de registro</em>)</li>
      <li><a href="mass.html">Configuraci&#243;n din&#225;mica de
      Hosting virtual masivo</a></li>
      <li><a href="details.html">Discusi&#243;n en profundidad sobre el
      proceso de selecci&#243;n de hosting virtual</a></li>
    </ul>

</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="directives" id="directives">Directivas de configuraci&#243;n</a></h2>

    <ul>
      <li><code class="directive"><a href="../mod/core.html#virtualhost">&lt;VirtualHost&gt;</a></code></li>
      <li><code class="directive"><a href="../mod/core.html#namevirtualhost">NameVirtualHost</a></code></li>
      <li><code class="directive"><a href="../mod/core.html#servername">ServerName</a></code></li>
      <li><code class="directive"><a href="../mod/core.html#serveralias">ServerAlias</a></code></li>
      <li><code class="directive"><a href="../mod/core.html#serverpath">ServerPath</a></code></li>
    </ul>

    <p>Si est&#225; tratando de solucionar problemas de
    configuraci&#243;n de su hosting virtual, puede que le sea de
    utilidad usar la opci&#243;n de l&#237;nea de comandos de Apache
    <code>-S</code>. Es decir, el siguiente comando:</p>

    <div class="example"><p><code>
    /usr/local/apache2/bin/httpd -S
    </code></p></div>

    <p>Este comando le devolver&#225; una descripci&#243;n de
    c&#243;mo Apache analiza e interpreta el fichero de
    configuraci&#243;n. Para saber si contiene errores de
    configuraci&#243;n, es conveniente que examine con atenci&#243;n
    las direcciones IP y los nombres de servidor que est&#225;
    usando. (Consulte la documentaci&#243;n sobre el programa
    <code class="program"><a href="../programs/httpd.html">httpd</a></code> para obtener informaci&#243;n sobre otras
    opciones de l&#237;nea de comandos)</p>

</div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="../de/vhosts/" hreflang="de" rel="alternate" title="Deutsch">&nbsp;de&nbsp;</a> |
<a href="../en/vhosts/" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/vhosts/" title="Espa&#241;ol">&nbsp;es&nbsp;</a> |
<a href="../ja/vhosts/" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="../ko/vhosts/" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="../ru/vhosts/" hreflang="ru" rel="alternate" title="Russian">&nbsp;ru&nbsp;</a> |
<a href="../tr/vhosts/" hreflang="tr" rel="alternate" title="T&#252;rk&#231;e">&nbsp;tr&nbsp;</a></p>
</div><div id="footer">
<p class="apache">Copyright 2013 The Apache Software Foundation.<br />Licencia bajo los t&#233;rminos de la <a href="http://www.apache.org/licenses/LICENSE-2.0">Apache License, Version 2.0</a>.</p>
<p class="menu"><a href="../mod/">M&#243;dulos</a> | <a href="../mod/directives.html">Directivas</a> | <a href="../faq/">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa de este sitio web</a></p></div>
</body></html>