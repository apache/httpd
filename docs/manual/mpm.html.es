<!DOCTYPE html SYSTEM "about:legacy-compat">
<html lang="es"><head><META http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<meta content="width=device-width, initial-scale=1" name="viewport">
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>M&oacute;dulos de MultiProcesamiento (MPMs) - Servidor HTTP Apache Versi&oacute;n 2.4</title>
<link href="./style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet">
<link href="./style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size">
<link href="./style/css/manual-print.css" rel="stylesheet" media="print" type="text/css"><link rel="stylesheet" type="text/css" href="./style/css/prettify.css">
<script src="./style/scripts/prettify.min.js">
</script>

<link href="./images/favicon.png" rel="shortcut icon"></head>
<body id="manual-page"><div id="page-header">
<p class="menu"><a href="./mod/">M&oacute;dulos</a> | <a href="./mod/quickreference.html">Directivas</a> | <a href="https://cwiki.apache.org/confluence/display/httpd/FAQ">Preguntas Frecuentes</a> | <a href="./glossary.html">Glosario</a> | <a href="./sitemap.html">Mapa del sitio web</a> | <a href="https://bz.apache.org/bugzilla/enter_bug.cgi?product=Apache%20httpd-2">Reportar un error</a></p>
<p class="apache">Versi&oacute;n 2.4 del Servidor HTTP Apache</p>
<img alt="" src="./images/feather.png"></div>
<div class="up"><a href="./"><img title="<-" alt="<-" src="./images/left.gif"></a></div>
<div id="path">
<a href="https://www.apache.org/">Apache</a> &gt; <a href="https://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="https://httpd.apache.org/docs/">Documentaci&oacute;n</a> &gt; <a href="./">Versi&oacute;n 2.4</a></div><div id="page-content"><div id="preamble"><h1>M&oacute;dulos de MultiProcesamiento (MPMs)</h1>
<button aria-label="Toggle language list" class="lang-toggle"><svg xmlns="http://www.w3.org/2000/svg" stroke-width="2" stroke="currentColor" fill="none" viewBox="0 0 24 24" height="16" width="16"><circle r="10" cy="12" cx="12"/><line y2="12" x2="22" y1="12" x1="2"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></button>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="./de/mpm.html" hreflang="de" rel="alternate" title="Deutsch">&nbsp;de&nbsp;</a> |
<a href="./en/mpm.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/mpm.html" title="Espa&ntilde;ol">&nbsp;es&nbsp;</a> |
<a href="./fr/mpm.html" hreflang="fr" rel="alternate" title="Fran&ccedil;ais">&nbsp;fr&nbsp;</a> |
<a href="./ja/mpm.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/mpm.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./tr/mpm.html" hreflang="tr" rel="alternate" title="T&uuml;rk&ccedil;e">&nbsp;tr&nbsp;</a> |
<a href="./zh-cn/mpm.html" hreflang="zh-cn" rel="alternate" title="Simplified Chinese">&nbsp;zh-cn&nbsp;</a></p>
</div>

<p>Este documento describe que es un M&oacute;dulo de Multiprocesamiento y
como los usa Apache.</p>
</div>
<div id="quickview"><ul id="toc"><li><img alt="" src="./images/down.gif"> <a href="#introduction">Introducci&oacute;n</a></li>
<li><img alt="" src="./images/down.gif"> <a href="#defaults">MPM por defecto</a></li>
</ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section">
<h2 id="introduction">Introducci&oacute;n <a title="Enlace permanente" href="#introduction" class="permalink">&para;</a></h2>

    <p>Apache est&aacute; dise&ntilde;ado para ser un servidor web potente
    y flexible que pueda funcionar en la m&aacute;s amplia variedad de
    plataformas y entornos. Las diferentes plataformas y los
    diferentes entornos, hacen que a menudo sean necesarias diferentes
    caracter&iacute;sticas o funcionalidades, o que una misma
    caracter&iacute;stica o funcionalidad sea implementada de diferente
    manera para obtener una mayor eficiencia. Apache se ha adaptado
    siempre a una gran variedad de entornos a trav&eacute;s de su
    dise&ntilde;o modular. Este dise&ntilde;o permite a los
    administradores de sitios web elegir que caracter&iacute;sticas van
    a ser incluidas en el servidor seleccionando que m&oacute;dulos se
    van a cargar, ya sea al compilar o en tiempo de ejecuci&oacute;n.</p>

    <p>Apache 2.0 extiende este dise&ntilde;o modular hasta las
    funciones m&aacute;s b&aacute;sicas de un servidor web. El servidor
    viene con una serie de M&oacute;dulos de MultiProcesamiento que son
    responsables de conectar con los puertos de red de la
    m&aacute;quina, aceptar las peticiones, y generar los procesos hijo
    que se encargan de servirlas.</p>

    <p>La extensi&oacute;n del dise&ntilde;o modular a este nivel del
    servidor ofrece dos beneficios importantes:</p>

    <ul>
      <li>Apache puede soportar de una forma m&aacute;s f&aacute;cil y
      eficiente una amplia variedad de sistemas operativos. En
      concreto, la versi&oacute;n de Windows de Apache es mucho m&aacute;s
      eficiente, porque el m&oacute;dulo <code class="module"><a href="./mod/mpm_winnt.html">mpm_winnt</a></code>
      puede usar funcionalidades nativas de red en lugar de usar la
      capa POSIX como hace Apache 1.3. Este beneficio se extiende
      tambi&eacute;n a otros sistemas operativos que implementan sus
      respectivos MPMs.</li>

      <li>El servidor puede personalizarse mejor para las necesidades
      de cada sitio web. Por ejemplo, los sitios web que necesitan
      m&aacute;s que nada escalabilidad pueden usar un proceso MPM como
      <code class="module"><a href="./mod/worker.html">worker</a></code>, mientras que los sitios web que
      requieran por encima de otras cosas estabilidad o compatibilidad
      con software antiguo pueden usar
      <code class="module"><a href="./mod/prefork.html">prefork</a></code>.
      </li>
    </ul>

    <p>A nivel de usuario, los MPMs son como cualquier otro
    m&oacute;dulo de Apache. La diferencia m&aacute;s importante es que
    solo un MPM puede estar cargado en el servidor en un determinado
    momento. La lista de MPMs disponibles est&aacute; en la <a href="mod/">secci&oacute;n &iacute;ndice de M&oacute;dulos</a>.</p>

</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section">
<h2 id="defaults">MPM por defecto <a title="Enlace permanente" href="#defaults" class="permalink">&para;</a></h2>

<p>En la siguiente tabla se muestran los MPMs por defecto para varios
sistemas operativos.  Estos ser&aacute;n los MPM seleccionados si no se
especifica lo contrario al compilar.</p>

<table class="bordered"><tr><td>Netware</td><td><code class="module"><a href="./mod/mpm_netware.html">mpm_netware</a></code></td></tr>
<tr class="odd"><td>OS/2</td><td><code class="module"><a href="./mod/mpmt_os2.html">mpmt_os2</a></code></td></tr>
<tr><td>Unix</td><td><code class="module"><a href="./mod/prefork.html">prefork</a></code>, <code class="module"><a href="./mod/worker.html">worker</a></code>, or
    <code class="module"><a href="./mod/event.html">event</a></code>, depending on platform capabilities</td></tr>
<tr class="odd"><td>Windows</td><td><code class="module"><a href="./mod/mpm_winnt.html">mpm_winnt</a></code></td></tr>
</table>

<div class="note"><p>aqu&iacute;, 'Unix' se usa para designar a los sistemas operativos "Unix-like", como
Linux, BSD, Solaris, Mac OS X, etc.</p></div>

<p>En el caso de los Unix, la decisi&oacute;n de que MPM se va a instalar
  depende de dos pregunas:</p>
<p>1. &iquest;Nos permite el Sistema Operativo hilos?</p>
<p>2. -&iquest;Nos permite el sistema operativo soporte a pila de hilos seguros 
  (Especificamente, las funciones kqueue y epoll)?</p>
</div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="./de/mpm.html" hreflang="de" rel="alternate" title="Deutsch">&nbsp;de&nbsp;</a> |
<a href="./en/mpm.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/mpm.html" title="Espa&ntilde;ol">&nbsp;es&nbsp;</a> |
<a href="./fr/mpm.html" hreflang="fr" rel="alternate" title="Fran&ccedil;ais">&nbsp;fr&nbsp;</a> |
<a href="./ja/mpm.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/mpm.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./tr/mpm.html" hreflang="tr" rel="alternate" title="T&uuml;rk&ccedil;e">&nbsp;tr&nbsp;</a> |
<a href="./zh-cn/mpm.html" hreflang="zh-cn" rel="alternate" title="Simplified Chinese">&nbsp;zh-cn&nbsp;</a></p>
</div><div id="footer">
<p class="apache">Copyright 2026 The Apache Software Foundation.<br>Licencia bajo los t&eacute;rminos de la <a href="https://www.apache.org/licenses/LICENSE-2.0">Apache License, Version 2.0</a>.</p>
<p class="menu"><a href="./mod/">M&oacute;dulos</a> | <a href="./mod/quickreference.html">Directivas</a> | <a href="https://cwiki.apache.org/confluence/display/httpd/FAQ">Preguntas Frecuentes</a> | <a href="./glossary.html">Glosario</a> | <a href="./sitemap.html">Mapa del sitio web</a> | <a href="https://bz.apache.org/bugzilla/enter_bug.cgi?product=Apache%20httpd-2">Reportar un error</a></p></div><script><!--//--><![CDATA[//><!--
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