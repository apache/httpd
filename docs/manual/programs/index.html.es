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
<title>El Servidor Apache y Programas de Soporte - Servidor HTTP Apache</title>
<link href="../style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet" />
<link href="../style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size" />
<link href="../style/css/manual-print.css" rel="stylesheet" media="print" type="text/css" />
<link href="../images/favicon.ico" rel="shortcut icon" /><link href="http://httpd.apache.org/docs/current/programs/index.html" rel="canonical" /></head>
<body id="manual-page" class="no-sidebar"><div id="page-header">
<p class="menu"><a href="../mod/">M&#243;dulos</a> | <a href="../mod/directives.html">Directivas</a> | <a href="../faq/">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa de este sitio web</a></p>
<p class="apache">Versi&#243;n 2.0 del Servidor HTTP Apache</p>
<img alt="" src="../images/feather.gif" /></div>
<div class="up"><a href="../"><img title="&lt;-" alt="&lt;-" src="../images/left.gif" /></a></div>
<div id="path">
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs/">Documentaci&#243;n</a> &gt; <a href="../">Versi&#243;n 2.0</a></div><div id="page-content"><div class="retired"><h4>Please note</h4>
            <p>This document refers to the <strong>2.0</strong> version of Apache httpd, which <strong>is no longer maintained</strong>. Upgrade, and refer to the current version of httpd instead, documented at:</p>
        <ul><li><a href="http://httpd.apache.org/docs/current/">Current release version of Apache HTTP Server documentation</a></li></ul><p>You may follow <a href="http://httpd.apache.org/docs/current/programs/">this link</a> to go to the current version of this document.</p></div><div id="preamble"><h1>El Servidor Apache y Programas de Soporte</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="../en/programs/" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/programs/" title="Espa&#241;ol">&nbsp;es&nbsp;</a> |
<a href="../ko/programs/" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="../ru/programs/" hreflang="ru" rel="alternate" title="Russian">&nbsp;ru&nbsp;</a> |
<a href="../tr/programs/" hreflang="tr" rel="alternate" title="T&#252;rk&#231;e">&nbsp;tr&nbsp;</a></p>
</div>
<div class="outofdate">Esta traducci&#243;n podr&#237;a estar
            obsoleta. Consulte la versi&#243;n en ingl&#233;s de la
            documentaci&#243;n para comprobar si se han producido cambios
            recientemente.</div>
 
    <p>Esta p&#225;gina contiene toda la documentaci&#243;n sobre los programas
    ejecutables incluidos en el servidor Apache.</p>
</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="index" id="index">&#205;ndice</a></h2>

    <dl>
      <dt><code class="program"><a href="../programs/httpd.html">httpd</a></code></dt>

      <dd>Servidor Apache del Protocolo de Transmisi&#243;n de
      Hipertexto (HTTP)</dd>

      <dt><code class="program"><a href="../programs/apachectl.html">apachectl</a></code></dt>

      <dd>Interfaz de control del servidor HTTP Apache </dd>

      <dt><code class="program"><a href="../programs/ab.html">ab</a></code></dt>

      <dd>Herramienta de benchmarking del Servidor HTTP Apache</dd>

      <dt><code class="program"><a href="../programs/apxs.html">apxs</a></code></dt>

      <dd>Herramienta de Extensi&#243;n de Apache</dd>

      <dt><code class="program"><a href="../programs/configure.html">configure</a></code></dt>

      <dd>Configuraci&#243;n de la estructura de directorios de Apache</dd>

      <dt><code class="program"><a href="../programs/dbmmanage.html">dbmmanage</a></code></dt>

      <dd>Crea y actualiza los archivos de autentificaci&#243;n de usuarios
      en formato DBM para autentificaci&#243;n b&#225;sica</dd>

      <dt><code class="program"><a href="../programs/htdigest.html">htdigest</a></code></dt>

      <dd>Crea y actualiza los ficheros de autentificaci&#243;n de usuarios
      para autentificaci&#243;n tipo digest</dd>

      <dt><code class="program"><a href="../programs/htpasswd.html">htpasswd</a></code></dt>

      <dd>Crea y actualiza los ficheros de autentificaci&#243;n de usuarios
      para autentificaci&#243;n b&#225;sica</dd>

      <dt><code class="program"><a href="../programs/logresolve.html">logresolve</a></code></dt>

      <dd>Resuelve los nombres de host para direcciones IP que est&#233;n
      en los ficheros log de Apache</dd>

      <dt><code class="program"><a href="../programs/rotatelogs.html">rotatelogs</a></code></dt>

      <dd>Renueva los logs de Apache sin parar el servidor</dd>

      <dt><code class="program"><a href="../programs/suexec.html">suexec</a></code></dt>

      <dd>Switch User For Exec. Programa para cambiar la identidad de
      usuario con la que se ejecuta un CGI</dd>

      <dt><a href="other.html">Otros Programas</a></dt>
      <dd>Herramientas de soporte sin secci&#243;n propia en la
      documentaci&#243;n.</dd>
    </dl>
</div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="../en/programs/" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/programs/" title="Espa&#241;ol">&nbsp;es&nbsp;</a> |
<a href="../ko/programs/" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="../ru/programs/" hreflang="ru" rel="alternate" title="Russian">&nbsp;ru&nbsp;</a> |
<a href="../tr/programs/" hreflang="tr" rel="alternate" title="T&#252;rk&#231;e">&nbsp;tr&nbsp;</a></p>
</div><div id="footer">
<p class="apache">Copyright 2013 The Apache Software Foundation.<br />Licencia bajo los t&#233;rminos de la <a href="http://www.apache.org/licenses/LICENSE-2.0">Apache License, Version 2.0</a>.</p>
<p class="menu"><a href="../mod/">M&#243;dulos</a> | <a href="../mod/directives.html">Directivas</a> | <a href="../faq/">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa de este sitio web</a></p></div>
</body></html>