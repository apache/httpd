<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es" xml:lang="es"><head><!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Filtros - Servidor HTTP Apache</title>
<link href="./style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet" />
<link href="./style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size" />
<link href="./style/css/manual-print.css" rel="stylesheet" media="print" type="text/css" />
<link href="./images/favicon.ico" rel="shortcut icon" /></head>
<body id="manual-page" class="no-sidebar"><div id="page-header">
<p class="menu"><a href="./mod/">Módulos</a> | <a href="./mod/directives.html">Directivas</a> | <a href="./faq/">Preguntas Frecuentes</a> | <a href="./glossary.html">Glosario</a> | <a href="./sitemap.html">Mapa de este sitio web</a></p>
<p class="apache">Versión 2.2 del Servidor HTTP Apache</p>
<img alt="" src="./images/feather.gif" /></div>
<div class="up"><a href="./"><img title="&lt;-" alt="&lt;-" src="./images/left.gif" /></a></div>
<div id="path">
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs/">Documentación</a> &gt; <a href="./">Versión 2.2</a></div><div id="page-content"><div id="preamble"><h1>Filtros</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="./en/filter.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/filter.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="./fr/filter.html" hreflang="fr" rel="alternate" title="Français">&nbsp;fr&nbsp;</a> |
<a href="./ja/filter.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/filter.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a></p>
</div>
<div class="outofdate">Esta traducción podría estar
            obsoleta. Consulte la versión en inglés de la
            documentación para comprobar si se han producido cambios
            recientemente.</div>

    <p>Este documento describe cómo usar filtros en Apache.</p>
  </div>
<div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="filters" id="filters">Filtros</a></h2>
    
    <table class="related"><tr><th>Módulos Relacionados</th><th>Directivas Relacionadas</th></tr><tr><td><ul><li><code class="module"><a href="./mod/mod_deflate.html">mod_deflate</a></code></li><li><code class="module"><a href="./mod/mod_ext_filter.html">mod_ext_filter</a></code></li><li><code class="module"><a href="./mod/mod_include.html">mod_include</a></code></li></ul></td><td><ul><li><code class="directive"><a href="./mod/mod_mime.html#addinputfilter">AddInputFilter</a></code></li><li><code class="directive"><a href="./mod/mod_mime.html#addoutputfilter">AddOutputFilter</a></code></li><li><code class="directive"><a href="./mod/mod_mime.html#removeinputfilter">RemoveInputFilter</a></code></li><li><code class="directive"><a href="./mod/mod_mime.html#removeoutputfilter">RemoveOutputFilter</a></code></li><li><code class="directive"><a href="./mod/mod_ext_filter.html#extfilterdefine">ExtFilterDefine</a></code></li><li><code class="directive"><a href="./mod/mod_ext_filter.html#extfilteroptions">ExtFilterOptions</a></code></li><li><code class="directive"><a href="./mod/core.html#setinputfilter">SetInputFilter</a></code></li><li><code class="directive"><a href="./mod/core.html#setoutputfilter">SetOutputFilter</a></code></li></ul></td></tr></table>

    <p>Un <em>filtro</em> es un proceso que se aplica a los datos que
    se reciben o se envían por el servidor. Los datos enviados
    por los clientes al servidor son procesados por <em>filtros de
    entrada</em> mientras que los datos enviados por el servidor se
    procesan por los <em>filtros de salida</em>. A los datos se les
    pueden aplicar varios filtros, y el orden en que se aplica cada
    filtro puede especificarse explícitamente.</p>

    <p>Los filtros se usan internamente por Apache para llevar a cabo
    funciones tales como chunking y servir peticiones de
    byte-range. Además, los módulos contienen filtros que se
    pueden seleccionar usando directivas de configuración al
    iniciar el servidor. El conjunto de filtros que se aplica a los
    datos puede manipularse con las directivas <code class="directive"><a href="./mod/core.html#setinputfilter">SetInputFilter</a></code>, <code class="directive"><a href="./mod/core.html#setoutputfilter">SetOutputFilter</a></code>, <code class="directive"><a href="./mod/mod_mime.html#addinputfilter">AddInputFilter</a></code>, <code class="directive"><a href="./mod/mod_mime.html#addoutputfilter">AddOutputFilter</a></code>, <code class="directive"><a href="./mod/mod_mime.html#removeinputfilter">RemoveInputFilter</a></code>, y <code class="directive"><a href="./mod/mod_mime.html#removeoutputfilter">RemoveOutputFilter</a></code>.</p>

    <p>Actualmente, vienen con la distribución de Apache los
    siguientes filtros seleccionables por el usuario.</p>

    <dl>
      <dt>INCLUDES</dt> 
      <dd>Server-Side Includes procesado por
      <code class="module"><a href="./mod/mod_include.html">mod_include</a></code></dd> 
      <dt>DEFLATE</dt> 
      <dd>Comprime los datos de salida antes de enviarlos al cliente
      usando el módulo
      <code class="module"><a href="./mod/mod_deflate.html">mod_deflate</a></code>
      </dd>
    </dl>

    <p>Además, el módulo <code class="module"><a href="./mod/mod_ext_filter.html">mod_ext_filter</a></code>
    permite definir programas externos como filtros.</p>
  </div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="./en/filter.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/filter.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="./fr/filter.html" hreflang="fr" rel="alternate" title="Français">&nbsp;fr&nbsp;</a> |
<a href="./ja/filter.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/filter.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a></p>
</div><div id="footer">
<p class="apache">Copyright 2008 The Apache Software Foundation.<br />Licencia bajo los términos de la <a href="http://www.apache.org/licenses/LICENSE-2.0">Apache License, Version 2.0</a>.</p>
<p class="menu"><a href="./mod/">Módulos</a> | <a href="./mod/directives.html">Directivas</a> | <a href="./faq/">Preguntas Frecuentes</a> | <a href="./glossary.html">Glosario</a> | <a href="./sitemap.html">Mapa de este sitio web</a></p></div>
</body></html>