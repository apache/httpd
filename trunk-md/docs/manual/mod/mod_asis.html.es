<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es" xml:lang="es"><head>
<meta content="text/html; charset=ISO-8859-1" http-equiv="Content-Type" />
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>mod_asis - Servidor HTTP Apache Versión 2.5</title>
<link href="../style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet" />
<link href="../style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size" />
<link href="../style/css/manual-print.css" rel="stylesheet" media="print" type="text/css" /><link rel="stylesheet" type="text/css" href="../style/css/prettify.css" />
<script src="../style/scripts/prettify.min.js" type="text/javascript">
</script>

<link href="../images/favicon.ico" rel="shortcut icon" /></head>
<body>
<div id="page-header">
<p class="menu"><a href="../mod/">Módulos</a> | <a href="../mod/quickreference.html">Directivas</a> | <a href="http://wiki.apache.org/httpd/FAQ">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa del sitio web</a></p>
<p class="apache">Versión 2.5 del Servidor HTTP Apache</p>
<img alt="" src="../images/feather.png" /></div>
<div class="up"><a href="./"><img title="&lt;-" alt="&lt;-" src="../images/left.gif" /></a></div>
<div id="path">
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs/">Documentación</a> &gt; <a href="../">Versión 2.5</a> &gt; <a href="./">Módulos</a></div>
<div id="page-content">
<div id="preamble"><h1>Módulo Apache mod_asis</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="../en/mod/mod_asis.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/mod/mod_asis.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="../fr/mod/mod_asis.html" hreflang="fr" rel="alternate" title="Français">&nbsp;fr&nbsp;</a> |
<a href="../ja/mod/mod_asis.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="../ko/mod/mod_asis.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a></p>
</div>
<table class="module"><tr><th><a href="module-dict.html#Description">Descripción:</a></th><td>Envía ficheros que contienen sus propias 
  cabeceras HTTP</td></tr>
<tr><th><a href="module-dict.html#Status">Estado:</a></th><td>Base</td></tr>
<tr><th><a href="module-dict.html#ModuleIdentifier">Identificador de Módulos:</a></th><td>asis_module</td></tr>
<tr><th><a href="module-dict.html#SourceFile">Fichero de Código Fuente:</a></th><td>mod_asis.c</td></tr></table>
<h3>Resumen de contenidos</h3>

    <p>Este módulo provee el handler <code>send-as-is</code>
      que hace que Apache HTTP Server envíe documentos sin añadir a ellos la 
      mayoría de las cabeceras típicas de HTTP.</p>

    <p>Esto se puede usar para enviar cualquier tipo de datos desde el servidor, 
      incluyendo redirecciones y otras respuestas HTTP especiales, sin 
      necesitar un script-cgi o un script nph.</p>

    <p>Por razones históricas, este módulo también procesará cualquier fichero
      con el tipo MIME <code>httpd/send-as-is</code>.</p>
</div>
<div id="quickview"><h3>Temas</h3>
<ul id="topics">
<li><img alt="" src="../images/down.gif" /> <a href="#usage">Uso</a></li>
</ul><h3 class="directives">Directivas</h3>
<p>Este módulo no suministra ninguna
            directiva.</p>
<h3>Bugfix checklist</h3><ul class="seealso"><li><a href="https://www.apache.org/dist/httpd/CHANGES_2.4">httpd changelog</a></li><li><a href="https://bz.apache.org/bugzilla/buglist.cgi?bug_status=__open__&amp;list_id=144532&amp;product=Apache%20httpd-2&amp;query_format=specific&amp;order=changeddate%20DESC%2Cpriority%2Cbug_severity&amp;component=mod_asis">Known issues</a></li><li><a href="https://bz.apache.org/bugzilla/enter_bug.cgi?product=Apache%20httpd-2&amp;component=mod_asis">Report a bug</a></li></ul><h3>Consulte también</h3>
<ul class="seealso">
<li><code class="module"><a href="../mod/mod_headers.html">mod_headers</a></code></li>
<li><code class="module"><a href="../mod/mod_cern_meta.html">mod_cern_meta</a></code></li>
<li><a href="../handler.html">Uso de Handler de Apache httpd</a></li>
<li><a href="#comments_section">Comentarios</a></li></ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="usage" id="usage">Uso</a></h2>

    <p>En el fichero de configuración del servidor, asociar ficheros con el 
      handler <code>send-as-is</code> <em>p. ej.</em></p>

    <pre class="prettyprint lang-config">AddHandler send-as-is asis</pre>


    <p>Los contenidos de cualquier fichero con la extensión <code>.asis</code> 
    se enviarán por Apache httpd al cliente sin apenas cambios. En particular, 
    las cabeceras HTTP provienen del propio fichero según las reglas de 
    <code class="module"><a href="../mod/mod_cgi.html">mod_cgi</a></code>, así que un fichero "asis" debe incluir cabeceras 
    válidas, y también puede usar la cabecera CGI 
    <code>Status:</code> para determinar el código de la respuesta HTTP. La 
    cabecera <code>Content-Length:</code> se insertará automáticamente, o si se 
    incluye en el fichero, será corregida por httpd.</p>

    <p>Aquí hay un ejemplo de un fichero cuyo contenido se envía 
      <em>as is</em> (tal cual) para decirle al cliente que 
      un fichero se ha redirigido.</p>

    <div class="example"><p><code>
      Status: 301 Y ahora donde he dejado esa URL<br />
      Location: http://xyz.example.com/foo/bar.html<br />
      Content-type: text/html<br />
      <br />
      &lt;html&gt;<br />
      &lt;head&gt;<br />
      &lt;title&gt;Excusas flojas'R'us&lt;/title&gt;<br />
      &lt;/head&gt;<br />
      &lt;body&gt;<br />
      &lt;h1&gt;La excepcionalmente maravillosa página de Fred's se ha movido a<br />
      &lt;a href="http://xyz.example.com/foo/bar.html"&gt;Joe's&lt;/a&gt;
      site.<br />
      &lt;/h1&gt;<br />
      &lt;/body&gt;<br />
      &lt;/html&gt;
    </code></p></div>

    <div class="note"><h3>Notas:</h3>
    <p>El servidor siempre añade una cabecera <code>Date:</code> y 
    <code>Server:</code> a los datos que se devuelven al cliente, de manera que 
    estos no deben incluirse en el fichero. El servidor <em>no</em> añade una 
    cabecera <code>Last-Modified</code> ; probablemente debería.</p>
    </div>
</div>
</div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="../en/mod/mod_asis.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/mod/mod_asis.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="../fr/mod/mod_asis.html" hreflang="fr" rel="alternate" title="Français">&nbsp;fr&nbsp;</a> |
<a href="../ja/mod/mod_asis.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="../ko/mod/mod_asis.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a></p>
</div><div class="top"><a href="#page-header"><img src="../images/up.gif" alt="top" /></a></div><div class="section"><h2><a id="comments_section" name="comments_section">Comentarios</a></h2><div class="warning"><strong>Notice:</strong><br />This is not a Q&amp;A section. Comments placed here should be pointed towards suggestions on improving the documentation or server, and may be removed again by our moderators if they are either implemented or considered invalid/off-topic. Questions on how to manage the Apache HTTP Server should be directed at either our IRC channel, #httpd, on Freenode, or sent to our <a href="http://httpd.apache.org/lists.html">mailing lists</a>.</div>
<script type="text/javascript"><!--//--><![CDATA[//><!--
var comments_shortname = 'httpd';
var comments_identifier = 'http://httpd.apache.org/docs/trunk/mod/mod_asis.html';
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
<p class="menu"><a href="../mod/">Módulos</a> | <a href="../mod/quickreference.html">Directivas</a> | <a href="http://wiki.apache.org/httpd/FAQ">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa del sitio web</a></p></div><script type="text/javascript"><!--//--><![CDATA[//><!--
if (typeof(prettyPrint) !== 'undefined') {
    prettyPrint();
}
//--><!]]></script>
</body></html>