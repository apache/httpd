<!DOCTYPE html SYSTEM "about:legacy-compat">
<html lang="es"><head><META http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<meta content="width=device-width, initial-scale=1" name="viewport">
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>El Servidor Apache y Programas de Soporte - Servidor HTTP Apache Versi&oacute;n 2.4</title>
<link href="../style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet">
<link href="../style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size">
<link href="../style/css/manual-print.css" rel="stylesheet" media="print" type="text/css"><link rel="stylesheet" type="text/css" href="../style/css/prettify.css">
<script src="../style/scripts/prettify.min.js">
</script>

<link href="../images/favicon.png" rel="shortcut icon"></head>
<body id="manual-page" class="no-sidebar"><div id="page-header">
<p class="menu"><a href="../mod/">M&oacute;dulos</a> | <a href="../mod/quickreference.html">Directivas</a> | <a href="https://cwiki.apache.org/confluence/display/httpd/FAQ">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa del sitio web</a> | <a href="https://bz.apache.org/bugzilla/enter_bug.cgi?product=Apache%20httpd-2">Reportar un error</a></p>
<p class="apache">Versi&oacute;n 2.4 del Servidor HTTP Apache</p>
<img alt="" src="../images/feather.png"></div>
<div class="up"><a href="../"><img title="<-" alt="<-" src="../images/left.gif"></a></div>
<div id="path">
<a href="https://www.apache.org/">Apache</a> &gt; <a href="https://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="https://httpd.apache.org/docs/">Documentaci&oacute;n</a> &gt; <a href="../">Versi&oacute;n 2.4</a></div><div id="page-content"><div id="preamble"><h1>El Servidor Apache y Programas de Soporte</h1>
<button aria-label="Toggle language list" class="lang-toggle"><svg xmlns="http://www.w3.org/2000/svg" stroke-width="2" stroke="currentColor" fill="none" viewBox="0 0 24 24" height="16" width="16"><circle r="10" cy="12" cx="12"/><line y2="12" x2="22" y1="12" x1="2"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></button>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="../en/programs/" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/programs/" title="Espa&ntilde;ol">&nbsp;es&nbsp;</a> |
<a href="../fr/programs/" hreflang="fr" rel="alternate" title="Fran&ccedil;ais">&nbsp;fr&nbsp;</a> |
<a href="../ko/programs/" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="../tr/programs/" hreflang="tr" rel="alternate" title="T&uuml;rk&ccedil;e">&nbsp;tr&nbsp;</a> |
<a href="../zh-cn/programs/" hreflang="zh-cn" rel="alternate" title="Simplified Chinese">&nbsp;zh-cn&nbsp;</a></p>
</div>

    <p>Esta p&aacute;gina contiene toda la documentaci&oacute;n sobre los programas
    ejecutables incluidos en el servidor Apache.</p>
</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="index">&Iacute;ndice <a title="Enlace permanente" href="#index" class="permalink">&para;</a></h2>

    <dl>
      <dt><code class="program"><a href="../programs/httpd.html">httpd</a></code></dt>

      <dd>Servidor Apache del Protocolo de Transmisi&oacute;n de
      Hipertexto (HTTP)</dd>

      <dt><code class="program"><a href="../programs/apachectl.html">apachectl</a></code></dt>

      <dd>Interfaz de control del servidor HTTP Apache </dd>

      <dt><code class="program"><a href="../programs/ab.html">ab</a></code></dt>

      <dd>Herramienta de benchmarking del Servidor HTTP Apache</dd>

      <dt><code class="program"><a href="../programs/apxs.html">apxs</a></code></dt>

      <dd>Herramienta de Extensi&oacute;n de Apache</dd>

      <dt><code class="program"><a href="../programs/configure.html">configure</a></code></dt>

      <dd>Configuraci&oacute;n de la estructura de directorios de Apache</dd>

      <dt><code class="program"><a href="../programs/dbmmanage.html">dbmmanage</a></code></dt>

      <dd>Crea y actualiza los archivos de autentificaci&oacute;n de usuarios
      en formato DBM para autentificaci&oacute;n b&aacute;sica</dd>

      <dt><code class="program"><a href="../programs/fcgistarter.html">fcgistarter</a></code></dt>

      <dd>Ejecuta un programa FastCGI.</dd>

      <dt><code class="program"><a href="../programs/htcacheclean.html">htcacheclean</a></code></dt>

      <dd>Vac&iacute;a la cach&eacute; del disco.</dd>

      <dt><code class="program"><a href="../programs/htdigest.html">htdigest</a></code></dt>

      <dd>Crea y actualiza los ficheros de autentificaci&oacute;n de usuarios
      para autentificaci&oacute;n tipo digest</dd>

      <dt><code class="program"><a href="../programs/htdbm.html">htdbm</a></code></dt>

      <dd>Manipula la base de datos DBM de contrase&ntilde;as.</dd>

      <dt><code class="program"><a href="../programs/htpasswd.html">htpasswd</a></code></dt>

      <dd>Crea y actualiza los ficheros de autentificaci&oacute;n de usuarios
      para autentificaci&oacute;n tipo b&aacute;sica</dd>

      <dt><code class="program"><a href="../programs/httxt2dbm.html">httxt2dbm</a></code></dt>

      <dd>Crea ficheros dbm para que se usen con RewriteMap</dd>

      <dt><code class="program"><a href="../programs/logresolve.html">logresolve</a></code></dt>

      <dd>Resuelve los nombres de host para direcciones IP que est&aacute;n
      en los ficheros log de Apache</dd>

      <dt><code class="program"><a href="../programs/log_server_status.html">log_server_status</a></code></dt>

      <dd>Logea de forma peri&oacute;dica el estado del servidor.</dd>

      <dt><code class="program"><a href="../programs/rotatelogs.html">rotatelogs</a></code></dt>

      <dd>Renueva los logs de Apache sin tener que parar el servidor</dd>

      <dt><code class="program"><a href="../programs/split-logfile.html">split-logfile</a></code></dt>

      <dd>Divide un archivo de registro multi-host virtual en 
      	archivos de registro por host</dd>

      <dt><code class="program"><a href="../programs/suexec.html">suexec</a></code></dt>

      <dd>Programa para cambiar la identidad de
      	 usuario con la que se ejecuta un CGI</dd>
  </dl>
</div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="../en/programs/" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/programs/" title="Espa&ntilde;ol">&nbsp;es&nbsp;</a> |
<a href="../fr/programs/" hreflang="fr" rel="alternate" title="Fran&ccedil;ais">&nbsp;fr&nbsp;</a> |
<a href="../ko/programs/" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="../tr/programs/" hreflang="tr" rel="alternate" title="T&uuml;rk&ccedil;e">&nbsp;tr&nbsp;</a> |
<a href="../zh-cn/programs/" hreflang="zh-cn" rel="alternate" title="Simplified Chinese">&nbsp;zh-cn&nbsp;</a></p>
</div><div id="footer">
<p class="apache">Copyright 2026 The Apache Software Foundation.<br>Licencia bajo los t&eacute;rminos de la <a href="https://www.apache.org/licenses/LICENSE-2.0">Apache License, Version 2.0</a>.</p>
<p class="menu"><a href="../mod/">M&oacute;dulos</a> | <a href="../mod/quickreference.html">Directivas</a> | <a href="https://cwiki.apache.org/confluence/display/httpd/FAQ">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa del sitio web</a> | <a href="https://bz.apache.org/bugzilla/enter_bug.cgi?product=Apache%20httpd-2">Reportar un error</a></p></div><script><!--//--><![CDATA[//><!--
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