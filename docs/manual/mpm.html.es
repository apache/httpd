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
<title>M&#243;dulos de MultiProcesamiento (MPMs) - Servidor HTTP Apache</title>
<link href="./style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet" />
<link href="./style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size" />
<link href="./style/css/manual-print.css" rel="stylesheet" media="print" type="text/css" />
<link href="./images/favicon.ico" rel="shortcut icon" /><link href="http://httpd.apache.org/docs/current/mpm.html" rel="canonical" /></head>
<body id="manual-page"><div id="page-header">
<p class="menu"><a href="./mod/">M&#243;dulos</a> | <a href="./mod/directives.html">Directivas</a> | <a href="./faq/">Preguntas Frecuentes</a> | <a href="./glossary.html">Glosario</a> | <a href="./sitemap.html">Mapa de este sitio web</a></p>
<p class="apache">Versi&#243;n 2.0 del Servidor HTTP Apache</p>
<img alt="" src="./images/feather.gif" /></div>
<div class="up"><a href="./"><img title="&lt;-" alt="&lt;-" src="./images/left.gif" /></a></div>
<div id="path">
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs/">Documentaci&#243;n</a> &gt; <a href="./">Versi&#243;n 2.0</a></div><div id="page-content"><div class="retired"><h4>Please note</h4>
            <p>This document refers to the <strong>2.0</strong> version of Apache httpd, which <strong>is no longer maintained</strong>. Upgrade, and refer to the current version of httpd instead, documented at:</p>
        <ul><li><a href="http://httpd.apache.org/docs/current/">Current release version of Apache HTTP Server documentation</a></li></ul><p>You may follow <a href="http://httpd.apache.org/docs/current/mpm.html">this link</a> to go to the current version of this document.</p></div><div id="preamble"><h1>M&#243;dulos de MultiProcesamiento (MPMs)</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="./de/mpm.html" hreflang="de" rel="alternate" title="Deutsch">&nbsp;de&nbsp;</a> |
<a href="./en/mpm.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/mpm.html" title="Espa&#241;ol">&nbsp;es&nbsp;</a> |
<a href="./ja/mpm.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/mpm.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./ru/mpm.html" hreflang="ru" rel="alternate" title="Russian">&nbsp;ru&nbsp;</a> |
<a href="./tr/mpm.html" hreflang="tr" rel="alternate" title="T&#252;rk&#231;e">&nbsp;tr&nbsp;</a></p>
</div>

<p>Este documento explica que son los M&#243;dulos de
Multiprocesamiento y como los usa Apache.</p>
</div>
<div id="quickview"><ul id="toc"><li><img alt="" src="./images/down.gif" /> <a href="#introduction">Introducci&#243;n</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#choosing">C&#243;mo Elegir un MPM</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#defaults">MPM por defecto</a></li>
</ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="introduction" id="introduction">Introducci&#243;n</a></h2>

    <p>Apache est&#225; dise&#241;ado para ser un servidor web potente
    y flexible que pueda funcionar en la m&#225;s amplia variedad de
    plataformas y entornos. Las diferentes plataformas y los
    diferentes entornos, hacen que a menudo sean necesarias diferentes
    caracter&#237;sticas o funcionalidades, o que una misma
    caracter&#237;stica o funcionalidad sea implementada de diferente
    manera para obtener una mayor eficiencia. Apache se ha adaptado
    siempre a una gran variedad de entornos a trav&#233;s de su
    dise&#241;o modular. Este dise&#241;o permite a los
    administradores de sitios web elegir que funcionalidades van a ser
    incluidas en el servidor seleccionando que m&#243;dulos se van a
    usar, ya sea al compilar o al ejecutar el servidor.</p>

    <p>Apache 2.0 extiende este dise&#241;o modular hasta las
    funcionalidades m&#225;s b&#225;sicas de un servidor web. El
    servidor viene con una serie de M&#243;dulos de MultiProcesamiento
    que son los responsables de conectar con los puertos de red de la
    m&#225;quina, acceptar las peticiones, y generar los procesos hijo
    que se encargan de servirlas.</p>

    <p>La extensi&#243;n del dise&#241;o modular a este nivel del
    servidor ofrece dos beneficios importantes:</p>

    <ul>
      <li>Apache puede soportar de una forma m&#225;s f&#225;cil y
      eficiente una amplia variedad de sistemas operativos. En
      concreto, la versi&#243;n de Windows de Apache es mucho m&#225;s
      eficiente, porque el m&#243;dulo <code class="module"><a href="./mod/mpm_winnt.html">mpm_winnt</a></code>
      puede usar funcionalidades nativas de red en lugar de usar la
      capa POSIX como hace Apache 1.3. Este beneficio se extiende
      tambi&#233;n a otros sistemas operativos que implementan sus
      respectivos MPMs.</li>

      <li>El servidor puede personalizarse mejor para las necesidades
      de cada sitio web. Por ejemplo, los sitios web que necesitan
      m&#225;s que nada escalibildad pueden usar un MPM hebrado como
      <code class="module"><a href="./mod/worker.html">worker</a></code>, mientras que los sitios web que
      requieran por encima de otras cosas estabilidad o compatibilidad
      con software antiguo pueden usar
      <code class="module"><a href="./mod/prefork.html">prefork</a></code>. Adem&#225;s, se pueden configurar
      funcionalidades especiales como servir diferentes hosts con
      diferentes identificadores de usuario
      (<code class="module"><a href="./mod/perchild.html">perchild</a></code>).</li>
    </ul>

    <p>A nivel de usuario, los m&#243;dulos de multiprocesamiento
    (MPMs) son como cualquier otro m&#243;dulo de Apache. La
    diferencia m&#225;s importante es que solo un MPM puede estar
    cargado en el servidor en un determinado momento. La lista de MPMs
    disponibles est&#225; en la <a href="mod/">secci&#243;n de
    &#237;ndice de m&#243;dulos</a>.</p>

</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="choosing" id="choosing">C&#243;mo Elegir un MPM</a></h2>

    <p>Los m&#243;dulos de multiprocesamiento que se van a usar
    posteriormente deben elegirse durante el proceso de
    configuraci&#243;n, y deben ser compilados en el servidor. Los
    compiladores son capaces de optimizar muchas funciones si se usan
    hebras, pero solo si se sabe que se est&#225;n usando hebras.</p>

    <p>Para elegir el m&#243;dulo de multiprocesamiento deseado, use
    el argumento <code>--with-mpm= <em>NAME</em></code> con el script
    <code class="program"><a href="./programs/configure.html">configure</a></code>. <em>NAME</em> es el nombre del MPM
    deseado.</p>

    <p>Una vez que el servidor ha sido compilado, es posible
    determinar que m&#243;dulos de multiprocesamiento ha sido elegido
    usando <code>./httpd -l</code>. Este comando lista todos los
    m&#243;dulos compilados en el servidor, incluido en MPM.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="defaults" id="defaults">MPM por defecto</a></h2>

<p>En la siguiente tabla se muestran los m&#243;dulos de
multiprocesamiento por defecto para varios sistemas operativos.  Estos
ser&#225;n los m&#243;dulos de multiprocesamiento seleccionados si no
se especifica lo contrario al compilar.</p>

<table>

<tr><td>BeOS</td><td><code class="module"><a href="./mod/beos.html">beos</a></code></td></tr>
<tr><td>Netware</td><td><code class="module"><a href="./mod/mpm_netware.html">mpm_netware</a></code></td></tr>
<tr><td>OS/2</td><td><code class="module"><a href="./mod/mpmt_os2.html">mpmt_os2</a></code></td></tr>
<tr><td>Unix</td><td><code class="module"><a href="./mod/prefork.html">prefork</a></code></td></tr>
<tr><td>Windows</td><td><code class="module"><a href="./mod/mpm_winnt.html">mpm_winnt</a></code></td></tr>
</table>
</div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="./de/mpm.html" hreflang="de" rel="alternate" title="Deutsch">&nbsp;de&nbsp;</a> |
<a href="./en/mpm.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/mpm.html" title="Espa&#241;ol">&nbsp;es&nbsp;</a> |
<a href="./ja/mpm.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/mpm.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./ru/mpm.html" hreflang="ru" rel="alternate" title="Russian">&nbsp;ru&nbsp;</a> |
<a href="./tr/mpm.html" hreflang="tr" rel="alternate" title="T&#252;rk&#231;e">&nbsp;tr&nbsp;</a></p>
</div><div id="footer">
<p class="apache">Copyright 2013 The Apache Software Foundation.<br />Licencia bajo los t&#233;rminos de la <a href="http://www.apache.org/licenses/LICENSE-2.0">Apache License, Version 2.0</a>.</p>
<p class="menu"><a href="./mod/">M&#243;dulos</a> | <a href="./mod/directives.html">Directivas</a> | <a href="./faq/">Preguntas Frecuentes</a> | <a href="./glossary.html">Glosario</a> | <a href="./sitemap.html">Mapa de este sitio web</a></p></div>
</body></html>