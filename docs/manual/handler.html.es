<!DOCTYPE html SYSTEM "about:legacy-compat">
<html lang="es"><head><META http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<meta content="width=device-width, initial-scale=1" name="viewport">
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Uso de los Handlers en Apache - Servidor HTTP Apache Versi&oacute;n 2.4</title>
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
<a href="https://www.apache.org/">Apache</a> &gt; <a href="https://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="https://httpd.apache.org/docs/">Documentaci&oacute;n</a> &gt; <a href="./">Versi&oacute;n 2.4</a></div><div id="page-content"><div id="preamble"><h1>Uso de los Handlers en Apache</h1>
<button aria-label="Toggle language list" class="lang-toggle"><svg xmlns="http://www.w3.org/2000/svg" stroke-width="2" stroke="currentColor" fill="none" viewBox="0 0 24 24" height="16" width="16"><circle r="10" cy="12" cx="12"/><line y2="12" x2="22" y1="12" x1="2"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></button>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="./en/handler.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/handler.html" title="Espa&ntilde;ol">&nbsp;es&nbsp;</a> |
<a href="./fr/handler.html" hreflang="fr" rel="alternate" title="Fran&ccedil;ais">&nbsp;fr&nbsp;</a> |
<a href="./ja/handler.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/handler.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./tr/handler.html" hreflang="tr" rel="alternate" title="T&uuml;rk&ccedil;e">&nbsp;tr&nbsp;</a> |
<a href="./zh-cn/handler.html" hreflang="zh-cn" rel="alternate" title="Simplified Chinese">&nbsp;zh-cn&nbsp;</a></p>
</div>

    <p>Este documento describe el uso de los Handlers en Apache.</p>
  </div>
<div id="quickview"><ul id="toc"><li><img alt="" src="./images/down.gif"> <a href="#definition">&iquest;Qu&eacute; es un Handler?</a></li>
<li><img alt="" src="./images/down.gif"> <a href="#examples">Ejemplos</a></li>
<li><img alt="" src="./images/down.gif"> <a href="#programmer">Nota para programadores</a></li>
</ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section">
<h2 id="definition">&iquest;Qu&eacute; es un Handler? <a title="Enlace permanente" href="#definition" class="permalink">&para;</a></h2>
    
    <table class="related"><tr><th>M&oacute;dulos Relacionados</th><th>Directivas Relacionadas</th></tr><tr><td><ul><li><code class="module"><a href="./mod/mod_actions.html">mod_actions</a></code></li><li><code class="module"><a href="./mod/mod_asis.html">mod_asis</a></code></li><li><code class="module"><a href="./mod/mod_cgi.html">mod_cgi</a></code></li><li><code class="module"><a href="./mod/mod_imagemap.html">mod_imagemap</a></code></li><li><code class="module"><a href="./mod/mod_info.html">mod_info</a></code></li><li><code class="module"><a href="./mod/mod_mime.html">mod_mime</a></code></li><li><code class="module"><a href="./mod/mod_negotiation.html">mod_negotiation</a></code></li><li><code class="module"><a href="./mod/mod_status.html">mod_status</a></code></li></ul></td><td><ul><li><code class="directive"><a href="./mod/mod_actions.html#action">Action</a></code></li><li><code class="directive"><a href="./mod/mod_mime.html#addhandler">AddHandler</a></code></li><li><code class="directive"><a href="./mod/mod_mime.html#removehandler">RemoveHandler</a></code></li><li><code class="directive"><a href="./mod/core.html#sethandler">SetHandler</a></code></li></ul></td></tr></table>


    <p>Un "handler" es una representaci&oacute;n interna de Apache de
    una acci&oacute;n que se va a ejecutar cuando hay una llamada a un
    fichero. Generalmente, los ficheros tienen handlers
    impl&iacute;citos, basados en el tipo de fichero de que se
    trata. Normalmente, todos los ficheros son simplemente servidos
    por el servidor, pero algunos tipos de ficheros se tratan de forma
    diferente.</p>

    <p>Handlers pueden ser usados de manera explicita,
     bas&aacute;ndose en la extensi&oacute;n del fichero o en
    la ubicaci&oacute;n en la que est&eacute;, se pueden especificar handlers
    sin tener en cuenta el tipo de fichero que se trate. Esto es
    una ventaja por dos razones. Primero, es una soluci&oacute;n
    m&aacute;s elegante. Segundo, porque a un fichero se le pueden
    asignar tanto un tipo <strong>como</strong> un handler. (Consulte
    tambi&eacute;n la secci&oacute;n <a href="mod/mod_mime.html#multipleext">Ficheros y extensiones
    m&uacute;ltiples</a>.)</p>

    <p>Los Handlers pueden tanto ser compilados con el servidor
    como incluidos en un m&oacute;dulo, o a&ntilde;adidos con la
    directiva <code class="directive"><a href="./mod/mod_actions.html#action">Action</a></code>. Los
    handlers que vienen incluidos en el core con el servidor de la distribuci&oacute;n
    est&aacute;ndar de Apache son:</p>

    <ul>
      <li><strong>default-handler</strong>: Env&iacute;a el fichero
      usando el <code>default_handler()</code>, que es el handler
      usado por defecto para tratar contenido
      est&aacute;tico. (core)</li>

      <li><strong>send-as-is</strong>: Env&iacute;a el fichero con
      cabeceras HTTP tal y como es. (<code class="module"><a href="./mod/mod_asis.html">mod_asis</a></code>)</li>

      <li><strong>cgi-script</strong>: Trata el fichero como un sript
      CGI. (<code class="module"><a href="./mod/mod_cgi.html">mod_cgi</a></code>)</li>

      <li><strong>imap-file</strong>: Trata el fichero como un mapa de
      im&aacute;genes. (<code class="module"><a href="./mod/mod_imagemap.html">mod_imagemap</a></code>)</li>

      <li><strong>server-info</strong>: Extrae la informaci&oacute;n de
      configuraci&oacute;n del
      servidor. (<code class="module"><a href="./mod/mod_info.html">mod_info</a></code>)</li>

      <li><strong>server-status</strong>: Extrae el informe del estado
      del servidor. (<code class="module"><a href="./mod/mod_status.html">mod_status</a></code>)</li>

      <li><strong>type-map</strong>: Trata el fichero como una
      correspondencia de tipos para la negociaci&oacute;n de contenidos.
      (<code class="module"><a href="./mod/mod_negotiation.html">mod_negotiation</a></code>)</li> 
    </ul> 
  </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section">
<h2 id="examples">Ejemplos <a title="Enlace permanente" href="#examples" class="permalink">&para;</a></h2> 
      

      <h3 id="example1">Modificar contenido est&aacute;tico usando un script
      CGI</h3>
      

      <p>Las siguientes directivas hacen que cuando haya una
      petici&oacute;n de ficheros con la extensi&oacute;n
      <code>html</code> se lance el script CGI
      <code>footer.pl</code>.</p>

      <div class="example"><p><code>
        Action add-footer /cgi-bin/footer.pl<br>
        AddHandler add-footer .html
      </code></p></div>

      <p>En este caso, el script CGI es el responsable de enviar el
      documento originalmente solicitado (contenido en la variable de
      entorno <code>PATH_TRANSLATED</code>) y de hacer cualquier
      modificaci&oacute;n o a&ntilde;adido deseado.</p>

    
    <h3 id="example2">Archivos con cabeceras HTTP</h3>
      

      <p>Las siguientes directivas activan el handler
      <code>send-as-is</code>, que se usa para ficheros que contienen
      sus propias cabeceras HTTP. Todos los archivos en el directorio
      <code>/web/htdocs/asis/</code> ser&aacute;n procesados por el
      handler <code>send-as-is</code>, sin tener en cuenta su
      extension.</p>

      <pre class="prettyprint lang-config">&lt;Directory "/web/htdocs/asis"&gt;
    SetHandler send-as-is
&lt;/Directory&gt;</pre>


    
  </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section">
<h2 id="programmer">Nota para programadores <a title="Enlace permanente" href="#programmer" class="permalink">&para;</a></h2>
    

    <p>Para implementar las funcionalidades de los handlers, se ha
    hecho un a&ntilde;adido a la <a href="developer/API.html">API de
    Apache</a> que puede que quiera usar. Para ser m&aacute;s
    espec&iacute;ficos, se ha a&ntilde;adido un nuevo registro a la
    estructura <code>request_rec</code>:</p>

    <pre class="prettyprint lang-c">char *handler</pre>


    <p>Si quiere que su m&oacute;dulo llame a un handler , solo tiene
    que a&ntilde;adir <code>r-&gt;handler</code> al nombre del handler
    en cualquier momento antes de la fase <code>invoke_handler</code>
    de la petici&oacute;n. Los handlers se implementan siempre como se
    hac&iacute;a antes, aunque usando el nombre del handler en vez de un
    tipo de contenido. Aunque no es de obligado cumplimiento, la
    convenci&oacute;n de nombres para los handlers es que se usen
    palabras separadas por guiones, sin barras, de manera que no se
    invada el media type name-space.</p>
  </div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="./en/handler.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/handler.html" title="Espa&ntilde;ol">&nbsp;es&nbsp;</a> |
<a href="./fr/handler.html" hreflang="fr" rel="alternate" title="Fran&ccedil;ais">&nbsp;fr&nbsp;</a> |
<a href="./ja/handler.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/handler.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./tr/handler.html" hreflang="tr" rel="alternate" title="T&uuml;rk&ccedil;e">&nbsp;tr&nbsp;</a> |
<a href="./zh-cn/handler.html" hreflang="zh-cn" rel="alternate" title="Simplified Chinese">&nbsp;zh-cn&nbsp;</a></p>
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