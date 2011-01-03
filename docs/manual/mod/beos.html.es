<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es" xml:lang="es"><head><!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>beos - Servidor HTTP Apache</title>
<link href="../style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet" />
<link href="../style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size" />
<link href="../style/css/manual-print.css" rel="stylesheet" media="print" type="text/css" />
<link href="../images/favicon.ico" rel="shortcut icon" /></head>
<body>
<div id="page-header">
<p class="menu"><a href="../mod/">Módulos</a> | <a href="../mod/directives.html">Directivas</a> | <a href="../faq/">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa de este sitio web</a></p>
<p class="apache">Versión 2.2 del Servidor HTTP Apache</p>
<img alt="" src="../images/feather.gif" /></div>
<div class="up"><a href="./"><img title="&lt;-" alt="&lt;-" src="../images/left.gif" /></a></div>
<div id="path">
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs/">Documentación</a> &gt; <a href="../">Versión 2.2</a> &gt; <a href="./">Módulos</a></div>
<div id="page-content">
<div id="preamble"><h1>MPM de Apache beos</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="../de/mod/beos.html" hreflang="de" rel="alternate" title="Deutsch">&nbsp;de&nbsp;</a> |
<a href="../en/mod/beos.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/mod/beos.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="../ko/mod/beos.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a></p>
</div>
<div class="outofdate">Esta traducción podría estar
            obsoleta. Consulte la versión en inglés de la
            documentación para comprobar si se han producido cambios
            recientemente.</div>
<table class="module"><tr><th><a href="module-dict.html#Description">Descripción:</a></th><td>Este módulo de muiltiprocesamiento está
optimizado para BeOS.</td></tr>
<tr><th><a href="module-dict.html#Status">Estado:</a></th><td>MPM</td></tr>
<tr><th><a href="module-dict.html#ModuleIdentifier">Identificador de Módulos:</a></th><td>mpm_beos_module</td></tr>
<tr><th><a href="module-dict.html#SourceFile">Fichero de Código Fuente:</a></th><td>beos.c</td></tr></table>
<h3>Resumen de contenidos</h3>

    <p>Este módulo de muiltiprocesamiento (MMP)
      es el que usa por defecto para BeOS. Usa un
      único proceso de control que crea hebras para atender las
      peticiones.</p>
</div>
<div id="quickview"><h3 class="directives">Directivas</h3>
<ul id="toc">
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#coredumpdirectory">CoreDumpDirectory</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#group">Group</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#listen">Listen</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#listenbacklog">ListenBacklog</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#maxclients">MaxClients</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#maxmemfree">MaxMemFree</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#maxrequestsperthread">MaxRequestsPerThread</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#maxsparethreads">MaxSpareThreads</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#minsparethreads">MinSpareThreads</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#pidfile">PidFile</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#receivebuffersize">ReceiveBufferSize</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#scoreboardfile">ScoreBoardFile</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#sendbuffersize">SendBufferSize</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#startthreads">StartThreads</a></li>
<li><img alt="" src="../images/right.gif" /> <a href="mpm_common.html#user">User</a></li>
</ul>
<h3>Consulte también</h3>
<ul class="seealso">
<li><a href="../bind.html">Configurar las direcciones y los
puertos que usa Apache</a></li>
</ul></div>

<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="MaxRequestsPerThread" id="MaxRequestsPerThread">MaxRequestsPerThread</a> <a name="maxrequestsperthread" id="maxrequestsperthread">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Limita el número de peticiones que una hebra (thread) puede
atender durante su vida</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>MaxRequestsPerThread <var>number</var></code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>MaxRequestsPerThread 0</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>MPM</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>beos</td></tr>
</table>
    <p>La directiva <code class="directive">MaxRequestsPerThread</code> fija
    el número máximo de peticiones que una hebra del
    servidor puede atender durante su vida. Despues de atender
    <code class="directive">MaxRequestsPerThread</code> peticiones, la hebra
    termina. Si el límite fijado en <code class="directive">MaxRequestsPerThread</code> es <code>0</code>, entonces la
    hebra puede atender peticiones indefinidamente.</p>

    <p>Fijar la directiva <code class="directive">MaxRequestsPerThread</code>
    a un límite distinto de cero ofrece dos benefcios
    fundamentales:</p>

    <ul>
      <li>limita la cantidad de memoria que puede consumir una hebra
      si hay una filtración (accidental) de memoria;</li>

      <li>poniendo un límite a la vida de las hebras, se ayuda a
      reducir el número de hebras cuando se reduce la carga de
      trabajo en el servidor.</li>
    </ul>

    <div class="note"><h3>Nota:</h3> <p>Para peticiones <code class="directive"><a href="../mod/core.html#keepalive">KeepAlive</a></code>, solo la primera
      petición se tiene en cuenta para este límite. De hecho, en este
      caso el límite se impone sobre el número máximo
      de <em>conexiones</em> por hebra.</p>
    </div>

</div>
</div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="../de/mod/beos.html" hreflang="de" rel="alternate" title="Deutsch">&nbsp;de&nbsp;</a> |
<a href="../en/mod/beos.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/mod/beos.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="../ko/mod/beos.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a></p>
</div><div id="footer">
<p class="apache">Copyright 2011 The Apache Software Foundation.<br />Licencia bajo los términos de la <a href="http://www.apache.org/licenses/LICENSE-2.0">Apache License, Version 2.0</a>.</p>
<p class="menu"><a href="../mod/">Módulos</a> | <a href="../mod/directives.html">Directivas</a> | <a href="../faq/">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa de este sitio web</a></p></div>
</body></html>