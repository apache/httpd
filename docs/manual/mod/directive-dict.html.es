<!DOCTYPE html SYSTEM "about:legacy-compat">
<html lang="es"><head><META http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<meta content="width=device-width, initial-scale=1" name="viewport">
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>T&eacute;rminos que se Usan para Describir Directivas - Servidor HTTP Apache Versi&oacute;n 2.4</title>
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
<a href="https://www.apache.org/">Apache</a> &gt; <a href="https://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="https://httpd.apache.org/docs/">Documentaci&oacute;n</a> &gt; <a href="../">Versi&oacute;n 2.4</a></div><div id="page-content"><div id="preamble"><h1>T&eacute;rminos que se Usan para Describir Directivas</h1>
<button aria-label="Toggle language list" class="lang-toggle"><svg xmlns="http://www.w3.org/2000/svg" stroke-width="2" stroke="currentColor" fill="none" viewBox="0 0 24 24" height="16" width="16"><circle r="10" cy="12" cx="12"/><line y2="12" x2="22" y1="12" x1="2"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></button>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="../en/mod/directive-dict.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/mod/directive-dict.html" title="Espa&ntilde;ol">&nbsp;es&nbsp;</a> |
<a href="../fr/mod/directive-dict.html" hreflang="fr" rel="alternate" title="Fran&ccedil;ais">&nbsp;fr&nbsp;</a> |
<a href="../ja/mod/directive-dict.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="../ko/mod/directive-dict.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="../tr/mod/directive-dict.html" hreflang="tr" rel="alternate" title="T&uuml;rk&ccedil;e">&nbsp;tr&nbsp;</a></p>
</div>
<div class="outofdate">Esta traducci&oacute;n podr&iacute;a estar
            obsoleta. Consulte la versi&oacute;n en ingl&eacute;s de la
            documentaci&oacute;n para comprobar si se han producido cambios
            recientemente.</div>

    <p>Este documento describe los t&eacute;rminos que se usan para describir
    cada <a href="directives.html">directiva de configuraci&oacute;n</a> de
    Apache.</p>
</div>
<div id="quickview"><ul id="toc"><li><img alt="" src="../images/down.gif"> <a href="#Description">Descripci&oacute;n</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#Syntax">Sintaxis</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#Default">Por defecto</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#Context">Contexto</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#Override">Override</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#Status">Estado</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#Module">M&oacute;dulo</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#Compatibility">Compatibilidad</a></li>
</ul><h3>Consulte tambi&eacute;n</h3><ul class="seealso"><li><a href="../configuring.html">Ficheros de Configuraci&oacute;n</a></li></ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="Description">Descripci&oacute;n <a title="Enlace permanente" href="#Description" class="permalink">&para;</a></h2>

    <p>Una breve descripci&oacute;n del prop&oacute;sito de la directiva.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="Syntax">Sintaxis <a title="Enlace permanente" href="#Syntax" class="permalink">&para;</a></h2>

    <p>Indica el formato de la directiva tal y como aparecer&iacute;a en un fichero de 
    configuraci&oacute;n. Esta sintaxis es muy espec&iacute;fica de cada directiva, y se 
    describe con detalle en la definici&oacute;n de la directiva. Generalmente, el 
    nombre de la directiva va seguido de una serie de uno o m&aacute;s par&aacute;metros 
    separados por un espacio. Si un par&aacute;metro contiene un espacio, &eacute;ste debe 
    especificarse entre comillas dobles. Los par&aacute;metros opcionales van 
    especificados entre corchetes. Donde un par&aacute;metro puede tener uno o m&aacute;s 
    valores, los valores posibles se separan con barras verticales "|". El Texto
    Literal se muestra con la fuente por defecto, mientras que los distintos 
    tipos de par&aacute;metros para los que una sustituci&oacute;n resulta necesaria son 
    <em>enfatizados</em>. Las directivas que pueden tomar una lista variada de 
    par&aacute;metros acaban en "..." indicando que el &uacute;ltimo par&aacute;metro se repite.</p>

    <p>Las Directivas usan un gran n&uacute;mero de diferentes tipos de par&aacute;metros. A 
    continuaci&oacute;n definimos algunos de los m&aacute;s comunes.</p>

    <dl>
      <dt><em>URL</em></dt>
      <dd>Un Localizador de Recursos Uniforme, incluye un esquema,
		  nombre de host, y un path opcional como en
      <code>http://www.example.com/path/to/file.html</code></dd>

      <dt><em>Ruta de URL</em></dt>
      <dd>La parte de una <em>url</em> que sigue al esquema y el
		  nombre de host como en <code>/path/to/file.html</code>. El
      <em>url-path</em> representa una vista-web de un recurso, en
      contraposici&oacute;n a una vista de sistema-de-ficheros.</dd>

      <dt><em>Ruta del Fichero</em></dt>
      <dd>La ruta a un fichero en el sistema de ficheros local que
		  comienza desde el directorio ra&iacute;z como en
      <code>/usr/local/apache/htdocs/path/to/file.html</code>.
      A menos que se especifique, una <em>ruta de fichero</em> que no comienza
      con una barra "/" se tratar&aacute; como una ruta relativa a <a href="core.html#serverroot">ServerRoot</a>.</dd>

      <dt><em>Ruta del Directorio</em></dt>

      <dd>La ruta a un directorio en el sistema de ficheros local que
      comienza con el directorio r&aacute;iz como en
      <code>/usr/local/apache/htdocs/path/to/</code>.</dd>

      <dt><em>Nombre del Fichero</em></dt>

      <dd>El nombre de un fichero sin ir acompa&ntilde;ado de informaci&oacute;n de la ruta
      como en <code>file.html</code>.</dd>

      <dt><em>regex</em></dt>

      <dd>Una <a class="glossarylink" href="../glossary.html#regex" title="ver glosario">
      expresi&oacute;n regular</a> compatible con Perl. La definici&oacute;n
      de directiva especificar&aacute; contra qu&eacute; se compara la
      <em>regex</em>.</dd>

      <dt><em>extensi&oacute;n</em></dt>

      <dd>En general, esta es la parte del <em>nombre de fichero</em>
      que sigue al &uacute;ltimo punto. Sin embargo, Apache reconoce m&uacute;ltiples
      extensiones de fichero, as&iacute; que si un <em>nombre de fichero</em>
      contiene m&aacute;s de un punto, cada parte separada por un punto del
      nombre de fichero despu&eacute;s del primer punto es una <em>extensi&oacute;n</em>.
      Por ejemplo, el <em>nombre de fichero</em> <code>file.html.en</code>
      contiene dos extensiones: <code>.html</code> y
      <code>.en</code>. Para las directivas de Apache, podr&aacute; especificar
      la <em>extensiones</em> con o sin el punto inicial. Adem&aacute;s, las 
      <em>extensiones</em> no son sensibles a may&uacute;sculas o min&uacute;sculas.</dd>

      <dt><em>Tipo MIME</em></dt>

      <dd>Un m&eacute;todo de describir el formato de un fichero que est&aacute; formado
      por un tipo de formato mayor y un tipo de formato menor, separados de
      de una barra como en <code>text/html</code>.</dd>

      <dt><em>Variable de Entorno</em></dt>

      <dd>El nombre de una <a href="../env.html">variable de entorno</a>
      definida en el proceso de configuraci&oacute;n de Apache. Tenga en cuenta
      que esto no es necesariamente lo mismo que la variable de entorno
      de un sistema operativo. Vea la <a href="../env.html">documentaci&oacute;n de variable de entorno</a> para
      m&aacute;s detalles.</dd>
    </dl>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="Default">Por defecto <a title="Enlace permanente" href="#Default" class="permalink">&para;</a></h2>

    <p>Si la directiva tiene un valor por defecto (<em>p.ej.</em>, si
    la omite de la configuraci&oacute;n completamente, el servidor Web Apache
    se comportar&aacute; como si la hubiera configurado con un valor en 
    particular), se describe aqu&iacute;. Si no tiene valor por defecto, esta 
    secci&oacute;n deber&iacute;a	indicar "<em>Ninguno</em>". Tenga en cuenta que el 
    valor por defecto listado aqu&iacute; no es necesariamente el mismo que el   
    valor que toma la directiva en el httpd.conf por defecto distribuido 
    con el servidor.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="Context">Contexto <a title="Enlace permanente" href="#Context" class="permalink">&para;</a></h2>

    <p>Esto indica d&oacute;nde se acepta la directiva en los ficheros de 
    configuraci&oacute;n. Es una lista separada por comas para uno o m&aacute;s de los 
    siguientes valores:</p>

    <dl>
      <dt>server config</dt>

      <dd>Esto indica que la directiva puede usarse en los ficheros de 
		  configuraci&oacute;n del servidor (<em>p.ej.</em>, <code>httpd.conf</code>),
		  pero <strong>not</strong> dentro de cualquier contenedor
      <code class="directive"><a href="../mod/core.html#virtualhost">&lt;VirtualHost&gt;</a></code>
      o <code class="directive"><a href="../mod/core.html#directory">&lt;Directory&gt;</a></code>. 
		  No se permite en ficheros <code>.htaccess</code> de ninguna 
		  manera.</dd>

      <dt>virtual host</dt>

      <dd>Este contexto significa que la directiva puede aparecer dentro de un
      contenedor <code class="directive"><a href="../mod/core.html#virtualhost">&lt;VirtualHost&gt;</a></code>
      en el fichero de configuraci&oacute;n del servidor.</dd>

      <dt>directory</dt>

      <dd>Una directiva marcada como v&aacute;lida en este contexto puede usarse dentro
      de contenedores <code class="directive"><a href="../mod/core.html#directory">&lt;Directory&gt;</a></code>, <code class="directive"><a href="../mod/core.html#location">&lt;Location&gt;</a></code>, <code class="directive"><a href="../mod/core.html#files">&lt;Files&gt;</a></code>, <code class="directive"><a href="../mod/core.html#if">&lt;If&gt;</a></code>,  <code class="directive"><a href="../mod/mod_proxy.html#proxy">&lt;Proxy&gt;</a></code> en los ficheros de
      configuraci&oacute;n del servidor, sujeta a las restricciones destacadas en
      las <a href="../sections.html">Secciones de Configuraci&oacute;n</a>.</dd>

      <dt>.htaccess</dt>

      <dd>Si una directiva es v&aacute;lida en este contexto, significa que puede 
      aparecer dentro de ficheros <code>.htaccess</code> de <em>contexto de 
      directorio</em>. Aunque podr&iacute;a no ser procesada, dependiendo de la 
      configuraci&oacute;n activa de <a href="#Override">AllowOverride</a> en ese 
      momento.</dd> 
    </dl>

    <p>La directiva <em>solo</em> se permite dentro del contexto designado; si
    intenta usarlo en alg&uacute;n otro, obtendr&aacute; un error de configuraci&oacute;n que 
    impedir&aacute; que el servidor gestione correctamente las solicitudes en ese
    contexto, o impedir&aacute; que el servidor pueda funcionar completamente --
    <em>p.ej.</em>, el servidor no arrancar&aacute;.</p>

    <p>Las ubicaciones v&aacute;lidas para la directiva son actualmente el resultado de 
    un Boolean OR de todos los contextos listados. En otras palabras, una 
    directiva que est&aacute; marcada como v&aacute;lida en 
    "<code>server config, .htaccess</code>" puede usarse en el fichero
    <code>httpd.conf</code> y en ficheros <code>.htaccess</code>, pero no dentro 
    de contenedores <code class="directive"><a href="../mod/core.html#directory">&lt;Directory&gt;</a></code> 
    o <code class="directive"><a href="../mod/core.html#virtualhost">&lt;VirtualHost&gt;</a></code>.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="Override">Override <a title="Enlace permanente" href="#Override" class="permalink">&para;</a></h2>

    <p>Este atributo de directiva indica qu&eacute; Override de configuraci&oacute;n debe 
    estar activo para que la directiva se procese cuando aparece en un fichero 
    <code>.htaccess</code>. Si el <a href="#Context">contexto</a> de la 
    directiva no permite que aparezca en ficheros <code>.htaccess</code>, 
    entonces no se listar&aacute; ning&uacute;n contexto.</p>

    <p>Los Override se activan con la directiva <code class="directive"><a href="../mod/core.html#allowoverride">AllowOverride</a></code>, si se aplican a un &aacute;mbito en 
    particular (como por ejemplo un directorio) y todos sus descendientes, a 
    menos que se modifique m&aacute;s adelante por otras directivas
    <code class="directive"><a href="../mod/core.html#allowoverride">AllowOverride</a></code> en niveles
    inferiores. La documentaci&oacute;n para la directiva tambi&eacute;n muestra una lista de
    los posibles nombres de Override disponibles.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="Status">Estado <a title="Enlace permanente" href="#Status" class="permalink">&para;</a></h2>

    <p>Esto indica cuan vinculada est&aacute; esta directiva al servidor Web de Apache; 
    o en otras palabras, puede que necesite recompilar el servidor con un 
    conjunto mejor de m&oacute;dulos para obtener acceso a esta directiva y su 
    funcionalidad. Valores posibles para estar directiva son:</p>

    <dl>
      <dt>Core</dt>

      <dd>Si una directiva aparece listada con estado "Core", eso significa
      que forma parte de las partes m&aacute;s internas del Servidor Apache Web, y que
      siempre est&aacute; disponible.</dd>

      <dt>MPM</dt>

      <dd>La directivas facilitadas por un
      <a href="../mpm.html">M&oacute;dulo de Multi-Proceso</a> est&aacute;n etiquetadas con
      Estado "MPM". Este tipo de directiva estar&aacute; disponible si y s&oacute;lo si est&aacute; 
      usando uno de los MPM listados en la l&iacute;nea <a href="#Module">M&oacute;dulo</a> 
      de la definici&oacute;n de la directiva.</dd>

      <dt>Base</dt>

      <dd>Una directiva listada con estado "Base" est&aacute; facilitada por uno
      de los m&oacute;dulos est&aacute;ndar de Apache que est&aacute;n compilados con el servidor
      por defecto, y por tanto est&aacute; normalmente disponible a menos que usted 
      haga las acciones necesarias para eliminar este m&oacute;dulo de su 
      configuraci&oacute;n.</dd>

      <dt>Extensi&oacute;n</dt>

      <dd>Una directiva con estado "Extensi&oacute;n" est&aacute; facilitada por uno de los 
      m&oacute;dulos incluidos en el kit del servidor Apache, pero el m&oacute;dulo no 
      est&aacute; compilado generalmente dentro del servidor. Para activar esta y su
      funcionalidad, necesirar&aacute; cambiar la configuraci&oacute;n de compilaci&oacute;n
      del servidor y recompilar Apache.</dd>

      <dt>Experimental</dt>

      <dd>El estado "Experimental" indica que la directiva est&aacute; disponible como
      parte del kit de Apache, pero usted tendr&aacute; que ir por su cuenta si intenta
      usarla. La directiva se documenta para aportar informaci&oacute;n, pero no tiene
      por qu&eacute; estar soportada de manera oficial. El m&oacute;dulo que provee esta 
      directiva puede o puede que no est&eacute; compilado por defecto, compruebe
      la parte superior de la p&aacute;gina que describe la direcitiva y el m&oacute;dulo para
      ver las anotaciones sobre su disponibilidad.</dd>
    </dl>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="Module">M&oacute;dulo <a title="Enlace permanente" href="#Module" class="permalink">&para;</a></h2>

    <p>Esto simplemente hace referencia al nombre del m&oacute;dulo original que provee 
    la directiva.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="Compatibility">Compatibilidad <a title="Enlace permanente" href="#Compatibility" class="permalink">&para;</a></h2>

    <p>Si la directiva no era parte de la distribuci&oacute;n original de Apache 
    versi&oacute;n 2, la versi&oacute;n en la que se introdujo deber&iacute;a estar referida aqu&iacute;. 
    Adem&aacute;s, si la direcitva solo est&aacute; disponible en ciertas plataformas, se ver&aacute;
    anotado aqu&iacute;.</p>
</div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="../en/mod/directive-dict.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/mod/directive-dict.html" title="Espa&ntilde;ol">&nbsp;es&nbsp;</a> |
<a href="../fr/mod/directive-dict.html" hreflang="fr" rel="alternate" title="Fran&ccedil;ais">&nbsp;fr&nbsp;</a> |
<a href="../ja/mod/directive-dict.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="../ko/mod/directive-dict.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="../tr/mod/directive-dict.html" hreflang="tr" rel="alternate" title="T&uuml;rk&ccedil;e">&nbsp;tr&nbsp;</a></p>
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