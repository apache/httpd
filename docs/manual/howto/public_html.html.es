<!DOCTYPE html SYSTEM "about:legacy-compat">
<html lang="es"><head><META http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<meta content="width=device-width, initial-scale=1" name="viewport">
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Directorios web por usuario - Servidor HTTP Apache Versi&oacute;n 2.4</title>
<link href="../style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet">
<link href="../style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size">
<link href="../style/css/manual-print.css" rel="stylesheet" media="print" type="text/css"><link rel="stylesheet" type="text/css" href="../style/css/prettify.css">
<script src="../style/scripts/prettify.min.js">
</script>

<link href="../images/favicon.png" rel="shortcut icon"></head>
<body id="manual-page"><div id="page-header">
<p class="menu"><a href="../mod/">M&oacute;dulos</a> | <a href="../mod/quickreference.html">Directivas</a> | <a href="https://cwiki.apache.org/confluence/display/httpd/FAQ">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa del sitio web</a> | <a href="https://bz.apache.org/bugzilla/enter_bug.cgi?product=Apache%20httpd-2">Reportar un error</a></p>
<p class="apache">Versi&oacute;n 2.4 del Servidor HTTP Apache</p>
<img alt="" src="../images/feather.png"></div>
<div class="up"><a href="./"><img title="<-" alt="<-" src="../images/left.gif"></a></div>
<div id="path">
<a href="https://www.apache.org/">Apache</a> &gt; <a href="https://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="https://httpd.apache.org/docs/">Documentaci&oacute;n</a> &gt; <a href="../">Versi&oacute;n 2.4</a> &gt; <a href="./">How-To / Tutorials</a></div><div id="page-content"><div id="preamble"><h1>Directorios web por usuario</h1>
<button aria-label="Toggle language list" class="lang-toggle"><svg xmlns="http://www.w3.org/2000/svg" stroke-width="2" stroke="currentColor" fill="none" viewBox="0 0 24 24" height="16" width="16"><circle r="10" cy="12" cx="12"/><line y2="12" x2="22" y1="12" x1="2"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></button>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="../en/howto/public_html.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/howto/public_html.html" title="Espa&ntilde;ol">&nbsp;es&nbsp;</a> |
<a href="../fr/howto/public_html.html" hreflang="fr" rel="alternate" title="Fran&ccedil;ais">&nbsp;fr&nbsp;</a> |
<a href="../ja/howto/public_html.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="../ko/howto/public_html.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="../tr/howto/public_html.html" hreflang="tr" rel="alternate" title="T&uuml;rk&ccedil;e">&nbsp;tr&nbsp;</a></p>
</div>

	<p>En sistemas con m&uacute;ltiples usuarios, cada usuario puede tener un website 
    en su directorio home usando la directiva <code class="directive"><a href="../mod/mod_userdir.html#userdir">UserDir</a></code>. Los visitantes de una URL 
    <code>http://example.com/~username/</code> recibir&aacute;n el contenido del 
    directorio home del usuario "<code>username</code>", en el subdirectorio 
    especificado por la directiva <code class="directive"><a href="../mod/mod_userdir.html#userdir">UserDir</a></code>.</p>

	<p>Tenga en cuenta que, por defecto, el acceso a estos directorios 
    <strong>NO</strong> est&aacute; activado. Puede permitir acceso cuando usa 
    <code class="directive"><a href="../mod/mod_userdir.html#userdir">UserDir</a></code> quitando el comentario de la l&iacute;nea:</p>

    <pre class="prettyprint lang-config">#Include conf/extra/httpd-userdir.conf</pre>


    <p>En el fichero por defecto de configuraci&oacute;n <code>conf/httpd.conf</code>, 
    y adaptando el fichero <code>httpd-userdir.conf</code> seg&uacute;n sea necesario, 
    o incluyendo las directivas apropiadas en un bloque 
    <code class="directive"><a href="../mod/core.html#directory">&lt;Directory&gt;</a></code> dentro del fichero 
    principal de configuraci&oacute;n.</p>
</div>
<div id="quickview"><ul id="toc"><li><img alt="" src="../images/down.gif"> <a href="#related">Directorios web por usuario</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#userdir">Configurando la ruta del fichero con UserDir</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#redirect">Redirigiendo a URLs externas</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#enable">Restringiendo qu&eacute; usuarios pueden usar esta caracter&iacute;stica</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#cgi">Activando un directorio cgi para cada usuario</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#htaccess">Permitiendo a usuarios cambiar la configuraci&oacute;n</a></li>
</ul><h3>Consulte tambi&eacute;n</h3><ul class="seealso"><li><a href="../urlmapping.html">Mapeando URLs al sistema de ficheros</a></li></ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="related">Directorios web por usuario <a title="Enlace permanente" href="#related" class="permalink">&para;</a></h2>
    
    <table class="related"><tr><th>M&oacute;dulos Relacionados</th><th>Directivas Relacionadas</th></tr><tr><td><ul><li><code class="module"><a href="../mod/mod_userdir.html">mod_userdir</a></code></li></ul></td><td><ul><li><code class="directive"><a href="../mod/mod_userdir.html#userdir">UserDir</a></code></li><li><code class="directive"><a href="../mod/core.html#directorymatch">DirectoryMatch</a></code></li><li><code class="directive"><a href="../mod/core.html#allowoverride">AllowOverride</a></code></li></ul></td></tr></table>
    </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="userdir">Configurando la ruta del fichero con UserDir <a title="Enlace permanente" href="#userdir" class="permalink">&para;</a></h2>
    

    <p>La directiva <code class="directive"><a href="../mod/mod_userdir.html#userdir">UserDir</a></code>
    especifica un directorio del que cargar contenido por usuario. Esta directiva 
    puede tener muchas formas distintas.</p>

    <p>Si se especifica una ruta que no empieza con una barra ("/"), se asume que 
      va a ser una ruta de directorio relativa al directorio home del usuario 
      especificado. Dada &eacute;sta configuraci&oacute;n:</p>

    <pre class="prettyprint lang-config">UserDir public_html</pre>


    <p>La URL <code>http://example.com/~rbowen/file.html</code> se traducir&aacute; en 
    la ruta del fichero <code>/home/rbowen/public_html/file.html</code></p>

    <p>Si la ruta que se especifica comienza con una barra ("/"), la ruta del 
      directorio se construir&aacute; usando esa ruta, m&aacute;s el usuario especificado en la 
      configuraci&oacute;n:</p>

    <pre class="prettyprint lang-config">UserDir /var/html</pre>


    <p>La URL <code>http://example.com/~rbowen/file.html</code> se traducir&aacute; en 
    la ruta del fichero <code>/var/html/rbowen/file.html</code></p>

    <p>Si se especifica una ruta que contiene un asterisco (*), se usar&aacute; una ruta 
      en la que el asterisco se reemplaza con el nombre de usuario. Dada &eacute;sta configuraci&oacute;n:</p>

    <pre class="prettyprint lang-config">UserDir /var/www/*/docs</pre>


    <p>La URL <code>http://example.com/~rbowen/file.html</code> se traducir&aacute; en 
    la ruta del fichero <code>/var/www/rbowen/docs/file.html</code></p>

    <p>Tambi&eacute;n se pueden configurar m&uacute;ltiples directorios o rutas de directorios.</p>

    <pre class="prettyprint lang-config">UserDir public_html /var/html</pre>


    <p>Para la URL <code>http://example.com/~rbowen/file.html</code>,
    Apache buscar&aacute; <code>~rbowen</code>. Si no lo encuentra, Apache buscar&aacute;
    <code>rbowen</code> en <code>/var/html</code>. Si lo encuentra, la URL de m&aacute;s 
    arriba se traducir&aacute; en la ruta del fichero 
    <code>/var/html/rbowen/file.html</code></p>

  </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="redirect">Redirigiendo a URLs externas <a title="Enlace permanente" href="#redirect" class="permalink">&para;</a></h2>
    
    <p>La directiva <code class="directive"><a href="../mod/mod_userdir.html#userdir">UserDir</a></code> puede 
    usarse para redirigir solcitudes de directorios de usuario a URLs externas.</p>

    <pre class="prettyprint lang-config">UserDir http://example.org/users/*/</pre>


    <p>El ejemplo de aqu&iacute; arriba redirigir&aacute; una solicitud para
    <code>http://example.com/~bob/abc.html</code> hacia
    <code>http://example.org/users/bob/abc.html</code>.</p>
  </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="enable">Restringiendo qu&eacute; usuarios pueden usar esta caracter&iacute;stica <a title="Enlace permanente" href="#enable" class="permalink">&para;</a></h2>
    

    <p>Usando la sintaxis que se muestra en la documentaci&oacute;n de UserDir, usted 
      puede restringir a qu&eacute; usuarios se les permite usar esta funcionalidad:</p>

    <pre class="prettyprint lang-config">UserDir disabled root jro fish</pre>


    <p>La configuraci&oacute;n de aqu&iacute; arriba permitir&aacute; a todos los usuarios excepto a 
      los que se listan con la declaraci&oacute;n <code>disabled</code>. Usted puede, 
      del mismo modo, deshabilitar esta caracter&iacute;stica para todos excepto algunos 
      usuarios usando una configuraci&oacute;n como la siguiente:</p>

    <pre class="prettyprint lang-config">UserDir disabled
UserDir enabled rbowen krietz</pre>


    <p>Vea la documentaci&oacute;n de <code class="directive"><a href="../mod/mod_userdir.html#userdir">UserDir</a></code> para m&aacute;s 
    ejemplos.</p>

  </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="cgi">Activando un directorio cgi para cada usuario <a title="Enlace permanente" href="#cgi" class="permalink">&para;</a></h2>
  

   <p>Para dar a cada usuario su propio directorio cgi-bin, puede usar una directiva 
   	<code class="directive"><a href="../mod/core.html#directory">&lt;Directory&gt;</a></code>
   para activar cgi en un subdirectorio en particular del directorio home del usuario.</p>

    <pre class="prettyprint lang-config">&lt;Directory "/home/*/public_html/cgi-bin/"&gt;
    Options ExecCGI
    SetHandler cgi-script
&lt;/Directory&gt;</pre>


    <p>Entonces, asumiendo que <code>UserDir</code> est&aacute; configurado con la 
    declaraci&oacute;n <code>public_html</code>, un programa cgi <code>example.cgi</code> 
    podr&iacute;a cargarse de ese directorio as&iacute;:</p>

    <div class="example"><p><code>
    http://example.com/~rbowen/cgi-bin/example.cgi
    </code></p></div>

    </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="htaccess">Permitiendo a usuarios cambiar la configuraci&oacute;n <a title="Enlace permanente" href="#htaccess" class="permalink">&para;</a></h2>
    

    <p>Si quiere permitir que usuarios modifiquen la configuraci&oacute;n del servidor en 
    	su espacio web, necesitar&aacute;n usar ficheros <code>.htaccess</code> para hacer 
    	estos cambios. Aseg&uacute;rese de tener configurado <code class="directive"><a href="../mod/core.html#allowoverride">AllowOverride</a></code> con un valor suficiente que permita a 
    los usuarios modificar las directivas que quiera permitir. 
    Vea el <a href="htaccess.html">tutorial de .htaccess</a> para obtener detalles adicionales sobre c&oacute;mo funciona.</p>

  </div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="../en/howto/public_html.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/howto/public_html.html" title="Espa&ntilde;ol">&nbsp;es&nbsp;</a> |
<a href="../fr/howto/public_html.html" hreflang="fr" rel="alternate" title="Fran&ccedil;ais">&nbsp;fr&nbsp;</a> |
<a href="../ja/howto/public_html.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="../ko/howto/public_html.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="../tr/howto/public_html.html" hreflang="tr" rel="alternate" title="T&uuml;rk&ccedil;e">&nbsp;tr&nbsp;</a></p>
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