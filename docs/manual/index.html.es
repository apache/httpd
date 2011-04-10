<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es" xml:lang="es"><head><!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Versión 2.2 de la documentación del
Servidor de HTTP Apache - Servidor HTTP Apache</title>
<link href="./style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet" />
<link href="./style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size" />
<link href="./style/css/manual-print.css" rel="stylesheet" media="print" type="text/css" />
<link href="./images/favicon.ico" rel="shortcut icon" /></head>
<body id="index-page">
<div id="page-header">
<p class="menu"><a href="./mod/">Módulos</a> | <a href="./mod/directives.html">Directivas</a> | <a href="./faq/">Preguntas Frecuentes</a> | <a href="./glossary.html">Glosario</a> | <a href="./sitemap.html">Mapa de este sitio web</a></p>
<p class="apache">Versión 2.2 del Servidor HTTP Apache</p>
<img alt="" src="./images/feather.gif" /></div>
<div class="up"><a href="http://httpd.apache.org/docs-project/"><img title="&lt;-" alt="&lt;-" src="./images/left.gif" /></a></div>
<div id="path">
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs/">Documentación</a></div>
<div id="page-content"><h1>Versión 2.2 de la documentación del
Servidor de HTTP Apache</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="./de/" hreflang="de" rel="alternate" title="Deutsch">&nbsp;de&nbsp;</a> |
<a href="./en/" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/" title="Español">&nbsp;es&nbsp;</a> |
<a href="./fr/" hreflang="fr" rel="alternate" title="Français">&nbsp;fr&nbsp;</a> |
<a href="./ja/" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./pt-br/" hreflang="pt-br" rel="alternate" title="Português (Brasil)">&nbsp;pt-br&nbsp;</a> |
<a href="./tr/" hreflang="tr" rel="alternate" title="Türkçe">&nbsp;tr&nbsp;</a> |
<a href="./zh-cn/" hreflang="zh-cn" rel="alternate" title="Simplified Chinese">&nbsp;zh-cn&nbsp;</a></p>
</div>
<div class="outofdate">Esta traducción podría estar
            obsoleta. Consulte la versión en inglés de la
            documentación para comprobar si se han producido cambios
            recientemente.</div>
<form method="get" action="http://www.google.com/search"><p><input name="as_q" value="" type="text" /> <input value="Buscar en Google" type="submit" /><input value="10" name="num" type="hidden" /><input value="es" name="hl" type="hidden" /><input value="ISO-8859-1" name="ie" type="hidden" /><input value="Google Search" name="btnG" type="hidden" /><input name="as_epq" value="Versión 2.2" type="hidden" /><input name="as_oq" value="" type="hidden" /><input name="as_eq" value="&quot;List-Post&quot;" type="hidden" /><input value="" name="lr" type="hidden" /><input value="i" name="as_ft" type="hidden" /><input value="" name="as_filetype" type="hidden" /><input value="all" name="as_qdr" type="hidden" /><input value="any" name="as_occt" type="hidden" /><input value="i" name="as_dt" type="hidden" /><input value="httpd.apache.org" name="as_sitesearch" type="hidden" /><input value="off" name="safe" type="hidden" /></p></form>
<table id="indextable"><tr><td class="col1"><div class="category"><h2><a name="release" id="release">Notas de la Versión</a></h2>
<ul><li><a href="new_features_2_0.html">Nuevas funcionalidades en
    Apache 2.0</a></li>
<li><a href="upgrading.html">Actualizarse a la versión 2.0 desde la 1.3</a></li>
<li><a href="license.html">Licencia Apache</a></li>
</ul>
</div><div class="category"><h2><a name="manual" id="manual">Manual de Referencia</a></h2>
<ul><li><a href="install.html">Compilación e Instalación</a></li>
<li><a href="invoking.html">Iniciar Apache</a></li>
<li><a href="stopping.html">Parar y reiniciar Apache</a></li>
<li><a href="mod/directives.html">Directivas para configurar la
ejecución</a></li>
<li><a href="mod/quickreference.html">Guía rápida de
    Referencia de Directivas</a></li>
<li><a href="mod/">Módulos</a></li>
<li><a href="mpm.html">Módulos de MultiProcesamiento (MPMs)</a></li>
<li><a href="filter.html">Filtros</a></li>
<li><a href="handler.html">Handlers</a></li>
<li><a href="programs/">El Servidor Apache y Programas de Soporte</a></li>
<li><a href="glossary.html">Glosario</a></li>
</ul>
</div></td><td><div class="category"><h2><a name="usersguide" id="usersguide">Guía del Usuario</a></h2>
<ul><li><a href="bind.html">Puertos de escucha</a></li>
<li><a href="configuring.html">Ficheros de Configuración</a></li>
<li><a href="sections.html">Secciones de Configuración</a></li>
<li><a href="content-negotiation.html">Negociación de Contenidos</a></li>
<li><a href="dso.html">Objetos Dinámicos Compartidos (DSO)</a></li>
<li><a href="env.html">Variables de Entorno</a></li>
<li><a href="logs.html">Archivos Log</a></li>
<li><a href="urlmapping.html">Mapear URLs a ubicaciones de un
    sistema de ficheros</a></li>
<li><a href="misc/perf-tuning.html">Ajustes para conseguir un mejor rendimiento</a></li>
<li><a href="misc/security_tips.html">Consejos de Seguridad</a></li>
<li><a href="server-wide.html">Configuración Básica de Apache</a></li>
<li><a href="ssl/">Encriptado SSL/TLS</a></li>
<li><a href="suexec.html">Ejecución de Suexec para CGIs</a></li>
<li><a href="rewrite/">Documentación adicional
    sobre mod_rewrite</a></li>
<li><a href="vhosts/">Hosting Virtual</a></li>
</ul>
</div></td><td class="col3"><div class="category"><h2><a name="howto" id="howto">How-To / Tutoriales</a></h2>
<ul><li><a href="howto/auth.html">Autentificación,
    Autorización, y Control de Acceso</a></li>
<li><a href="howto/cgi.html">CGI: Contenido Dinámico</a></li>
<li><a href="howto/htaccess.html">Archivos .htaccess</a></li>
<li><a href="howto/ssi.html">Server Side Includes (SSI)</a></li>
<li><a href="howto/public_html.html">Directorios web para cada
    usuario (public_html)</a></li>
</ul>
</div><div class="category"><h2><a name="platform" id="platform">Notas específicas sobre plataformas</a></h2>
<ul><li><a href="platform/windows.html">Microsoft Windows</a></li>
<li><a href="platform/netware.html">Novell NetWare</a></li>
<li><a href="platform/ebcdic.html">EBCDIC Port</a></li>
</ul>
</div><div class="category"><h2><a name="other" id="other">Documentación adicional</a></h2>
<ul><li><a href="faq/">Preguntas Más Frecuentes</a></li>
<li><a href="sitemap.html">Mapa de este sitio web</a></li>
<li><a href="developer/">Documentación para desarrolladores</a></li>
<li><a href="misc/">Otros documentos</a></li>
</ul>
</div></td></tr></table></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="./de/" hreflang="de" rel="alternate" title="Deutsch">&nbsp;de&nbsp;</a> |
<a href="./en/" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/" title="Español">&nbsp;es&nbsp;</a> |
<a href="./fr/" hreflang="fr" rel="alternate" title="Français">&nbsp;fr&nbsp;</a> |
<a href="./ja/" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./pt-br/" hreflang="pt-br" rel="alternate" title="Português (Brasil)">&nbsp;pt-br&nbsp;</a> |
<a href="./tr/" hreflang="tr" rel="alternate" title="Türkçe">&nbsp;tr&nbsp;</a> |
<a href="./zh-cn/" hreflang="zh-cn" rel="alternate" title="Simplified Chinese">&nbsp;zh-cn&nbsp;</a></p>
</div><div id="footer">
<p class="apache">Copyright 2011 The Apache Software Foundation.<br />Licencia bajo los términos de la <a href="http://www.apache.org/licenses/LICENSE-2.0">Apache License, Version 2.0</a>.</p>
<p class="menu"><a href="./mod/">Módulos</a> | <a href="./mod/directives.html">Directivas</a> | <a href="./faq/">Preguntas Frecuentes</a> | <a href="./glossary.html">Glosario</a> | <a href="./sitemap.html">Mapa de este sitio web</a></p></div>
</body></html>