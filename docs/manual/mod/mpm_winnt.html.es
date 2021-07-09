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
<title>mpm_winnt - Servidor HTTP Apache</title>
<link href="../style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet" />
<link href="../style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size" />
<link href="../style/css/manual-print.css" rel="stylesheet" media="print" type="text/css" />
<link href="../images/favicon.ico" rel="shortcut icon" /><link href="http://httpd.apache.org/docs/current/mod/mpm_winnt.html" rel="canonical" /></head>
<body>
<div id="page-header">
<p class="menu"><a href="../mod/">M&#243;dulos</a> | <a href="../mod/directives.html">Directivas</a> | <a href="../faq/">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa de este sitio web</a></p>
<p class="apache">Versi&#243;n 2.0 del Servidor HTTP Apache</p>
<img alt="" src="../images/feather.gif" /></div>
<div class="up"><a href="./"><img title="&lt;-" alt="&lt;-" src="../images/left.gif" /></a></div>
<div id="path">
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs/">Documentaci&#243;n</a> &gt; <a href="../">Versi&#243;n 2.0</a> &gt; <a href="./">M&#243;dulos</a></div>
<div id="page-content">
<div class="retired"><h4>Please note</h4>
            <p>This document refers to the <strong>2.0</strong> version of Apache httpd, which <strong>is no longer maintained</strong>. Upgrade, and refer to the current version of httpd instead, documented at:</p>
        <ul><li><a href="http://httpd.apache.org/docs/current/">Current release version of Apache HTTP Server documentation</a></li></ul><p>You may follow <a href="http://httpd.apache.org/docs/current/mod/mpm_winnt.html">this link</a> to go to the current version of this document.</p></div><div id="preamble"><h1>MPM de Apache winnt</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="../de/mod/mpm_winnt.html" hreflang="de" rel="alternate" title="Deutsch">&nbsp;de&nbsp;</a> |
<a href="../en/mod/mpm_winnt.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/mod/mpm_winnt.html" title="Espa&#241;ol">&nbsp;es&nbsp;</a> |
<a href="../ja/mod/mpm_winnt.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a></p>
</div>
<div class="outofdate">Esta traducci&#243;n podr&#237;a estar
            obsoleta. Consulte la versi&#243;n en ingl&#233;s de la
            documentaci&#243;n para comprobar si se han producido cambios
            recientemente.</div>
<table class="module"><tr><th><a href="module-dict.html#Description">Descripci&#243;n:</a></th><td>M&#243;dulo de multiprocesamiento optimizado para Windows
NT.</td></tr>
<tr><th><a href="module-dict.html#Status">Estado:</a></th><td>MPM</td></tr>
<tr><th><a href="module-dict.html#ModuleIdentifier">Identificador de M&#243;dulos:</a></th><td>mpm_winnt_module</td></tr>
<tr><th><a href="module-dict.html#SourceFile">Fichero de C&#243;digo Fuente:</a></th><td>mpm_winnt.c</td></tr></table>
<h3>Resumen de contenidos</h3>

    <p>Este m&#243;dulo de multiprocesamiento (MPM) es el que viene por
    defecto para los sitemas operativos Windows NT. Crea un solo
    proceso de control que crea un solo proceso hijo que a su vez crea
    hebras para atender las peticiones que se produzcan.</p>
</div>
<div id="quickview"><h3 class="directives">Directivas</h3>
<ul id="toc">
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#coredumpdirectory">CoreDumpDirectory</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#listen">Listen</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#listenbacklog">ListenBacklog</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#maxmemfree">MaxMemFree</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#maxrequestsperchild">MaxRequestsPerChild</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#pidfile">PidFile</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#receivebuffersize">ReceiveBufferSize</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#scoreboardfile">ScoreBoardFile</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#sendbuffersize">SendBufferSize</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#threadlimit">ThreadLimit</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#threadsperchild">ThreadsPerChild</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#win32disableacceptex">Win32DisableAcceptEx</a></li>
</ul>
</div>

<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="Win32DisableAcceptEx" id="Win32DisableAcceptEx">Win32DisableAcceptEx</a> <a name="win32disableacceptex" id="win32disableacceptex">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripci&#243;n:</a></th><td>Usa accept() en lugar de AcceptEx() para aceptar
conexiones de red</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>Win32DisableAcceptEx</code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>AcceptEx() est&#225; activado por defecto. Use esta directiva para desactivarlo</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>MPM</td></tr>
<tr><th><a href="directive-dict.html#Module">M&#243;dulo:</a></th><td>mpm_winnt</td></tr>
<tr><th><a href="directive-dict.html#Compatibility">Compatibilidad:</a></th><td>Disponible en las versiones 2.0.49 y posteriores</td></tr>
</table>
    <p><code>AcceptEx()</code> es una API WinSock v2 de Microsoft que
    ofrece algunas mejoras en el rendimiento sobre la API
    <code>accept()</code> de tipo BSD bajo ciertas
    condiciones. Algunos productos populares de Microsoft, sobre todo
    antivirus o aplicaciones para implemetar redes privadas virtuales,
    tienen errores de programaci&#243;n que interfieren con el
    funcionamiento de <code>AcceptEx()</code>. Si se encuentra con un
    mensaje de error parecido a este:</p>

    <div class="example"><p><code>
        [error] (730038)An operation was attempted on something that is
        not a socket.: winnt_accept: AcceptEx failed. Attempting to recover.
    </code></p></div>

    <p>debe usar esta directiva para desactivar el uso de <code>AcceptEx()</code>.</p>

</div>
</div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="../de/mod/mpm_winnt.html" hreflang="de" rel="alternate" title="Deutsch">&nbsp;de&nbsp;</a> |
<a href="../en/mod/mpm_winnt.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/mod/mpm_winnt.html" title="Espa&#241;ol">&nbsp;es&nbsp;</a> |
<a href="../ja/mod/mpm_winnt.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a></p>
</div><div id="footer">
<p class="apache">Copyright 2013 The Apache Software Foundation.<br />Licencia bajo los t&#233;rminos de la <a href="http://www.apache.org/licenses/LICENSE-2.0">Apache License, Version 2.0</a>.</p>
<p class="menu"><a href="../mod/">M&#243;dulos</a> | <a href="../mod/directives.html">Directivas</a> | <a href="../faq/">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa de este sitio web</a></p></div>
</body></html>