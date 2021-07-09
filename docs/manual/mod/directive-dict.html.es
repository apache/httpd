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
<title>T&#233;rminos usados en las descripciones de las
  Directivas - Servidor HTTP Apache</title>
<link href="../style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet" />
<link href="../style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size" />
<link href="../style/css/manual-print.css" rel="stylesheet" media="print" type="text/css" />
<link href="../images/favicon.ico" rel="shortcut icon" /><link href="http://httpd.apache.org/docs/current/mod/directive-dict.html" rel="canonical" /></head>
<body id="manual-page"><div id="page-header">
<p class="menu"><a href="../mod/">M&#243;dulos</a> | <a href="../mod/directives.html">Directivas</a> | <a href="../faq/">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa de este sitio web</a></p>
<p class="apache">Versi&#243;n 2.0 del Servidor HTTP Apache</p>
<img alt="" src="../images/feather.gif" /></div>
<div class="up"><a href="./"><img title="&lt;-" alt="&lt;-" src="../images/left.gif" /></a></div>
<div id="path">
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs/">Documentaci&#243;n</a> &gt; <a href="../">Versi&#243;n 2.0</a></div><div id="page-content"><div class="retired"><h4>Please note</h4>
            <p>This document refers to the <strong>2.0</strong> version of Apache httpd, which <strong>is no longer maintained</strong>. Upgrade, and refer to the current version of httpd instead, documented at:</p>
        <ul><li><a href="http://httpd.apache.org/docs/current/">Current release version of Apache HTTP Server documentation</a></li></ul><p>You may follow <a href="http://httpd.apache.org/docs/current/mod/directive-dict.html">this link</a> to go to the current version of this document.</p></div><div id="preamble"><h1>T&#233;rminos usados en las descripciones de las
  Directivas</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="../en/mod/directive-dict.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/mod/directive-dict.html" title="Espa&#241;ol">&nbsp;es&nbsp;</a> |
<a href="../ja/mod/directive-dict.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="../ko/mod/directive-dict.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="../tr/mod/directive-dict.html" hreflang="tr" rel="alternate" title="T&#252;rk&#231;e">&nbsp;tr&nbsp;</a></p>
</div>
<div class="outofdate">Esta traducci&#243;n podr&#237;a estar
            obsoleta. Consulte la versi&#243;n en ingl&#233;s de la
            documentaci&#243;n para comprobar si se han producido cambios
            recientemente.</div>

    <p>Este documento define los t&#233;rminos que se usan para describir
    las <a href="directives.html">directivas de configuraci&#243;n</a> de
    Apache.</p>
</div>
<div id="quickview"><ul id="toc"><li><img alt="" src="../images/down.gif" /> <a href="#Description">Descripci&#243;n</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#Syntax">Sintaxis</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#Default">Valor por defecto</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#Context">Contexto</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#Override">Override</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#Status">Estado</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#Module">M&#243;dulo</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#Compatibility">Compatibilidad</a></li>
</ul><h3>Consulte tambi&#233;n</h3><ul class="seealso"><li><a href="../configuring.html">Fichero de
Configuraci&#243;n</a></li></ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="Description" id="Description">Descripci&#243;n</a></h2>

<p>Descripci&#243;n resumida de para qu&#233; sirve la directiva.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="Syntax" id="Syntax">Sintaxis</a></h2>

    <p>Explica el formato de la directiva en la manera en que
    aparecer&#237;a en un fichero de configuraci&#243;n. La sintaxis es
    espec&#237;fica para cada directiva, y se decribe en detalle en la
    definici&#243;n de cada una de ellas. Generalmente, es el nombre de la
    directiva seguido del argumento o argumentos que correspondan
    separados por espacios. Si un argumento contiene un espacio,
    entonces debe escribirse entre comillas. Los argumentos opcionales
    van entre corchetes ([]). Si cada argumento puede tomar m&#225;s de un
    valor, los valores posibles van separados por barras verticales
    "|".  Los textos literales (los que no hay que sustituir) est&#225;n en
    el tipo de letra por defecto del resto del texto, mientras que los
    que hay que sustituir est&#225;n <em>resaltados</em>. Las directivas
    que pueden tomar un n&#250;mero variable de argumentos terminan con
    puntos suspensivos ("...").</p>

    <p>Las directivas usan una gran variedad de tipos de
    argumentos. Algunos de los m&#225;s comunes son:</p>

    <dl>
      <dt><em>URL</em></dt>

      <dd>Un Localizador de Recursos Uniforme (Uniform Resource
      Locator) que consiste en un esquema (www), un nombre de host
      (example.com), y opcionalmente, una ruta; por ejemplo
      <code>http://www.example.com/path/to/file.html</code></dd>

      <dt><em>URL-path</em></dt>

      <dd>La parte de una <em>url</em> que va a continuaci&#243;n del
      esquema y del nombre de host, por ejemplo
      <code>/path/to/file.html</code>. El <em>url-path</em> representa
      al fichero visto desde el servidor web, en contraposici&#243;n a
      verlo tomando el sistema de ficheros como punto de
      referencia.</dd>

      <dt><em>file-path</em></dt>

      <dd>La ubicaci&#243;n de un fichero en el sistema de archivos local
      que empieza con el directorio raiz, por ejemplo,
      <code>/usr/local/apache/htdocs/path/to/file.html</code>.  A
      menos que se especifique otra cosa, un <em>file-path</em> que no
      empieza con una barra ser&#225; tratado como relativo a <a href="core.html#serverroot">ServerRoot</a>.</dd>

      <dt><em>directory-path</em></dt>

      <dd>La ubicaci&#243;n de un directorio en el sistema de archivos
      local que empieza en el directorio raiz, por ejemplo
      <code>/usr/local/apache/htdocs/path/to/</code>.</dd>

      <dt><em>filename</em></dt>

      <dd>El nombre de un fichero sin informaci&#243;n adicional sobre su
      ubicaci&#243;n, por ejemplo <code>file.html</code>.</dd>

      <dt><em>regex</em></dt>

      <dd>Una expresi&#243;n regular, que es una forma de describir un
      patr&#243;n para encontrar sus equivalencias en un texto. La
      definici&#243;n de la directiva especificar&#225; con qu&#233; se comparar&#225;
      <em>regex</em> para encontrar equivalencias.</dd>

      <dt><em>extension</em></dt>

      <dd>En general, es la parte del <em>filename</em> que va despu&#233;s
      del &#250;ltimo punto. Apache reconoce muchas de estas extensiones,
      de manera que si un <em>filename</em> contiene mas de un punto,
      cada parte separada por uno de esos puntos despu&#233;s del primero
      se trata como una <em>extensi&#243;n</em>.  Por ejemplo, el
      <em>filename</em> <code>file.html.en</code> contiene dos
      extensiones: <code>.html</code> y <code>.en</code>. Para las
      directivas de Apache, puede especificar <em>extensiones</em> con
      o sin punto delante. Las <em>extensiones</em> no distinguen
      may&#250;sculas de min&#250;sculas.</dd>

      <dt><em>MIME Type</em></dt>

      <dd>Es una forma de describir el formato de un fichero, que
      consiste en un tipo de formato principal y un tipo de formato
      secundario, separados por una barra, por ejemplo
      <code>text/html</code>.</dd>

      <dt><em>env-variable</em></dt>

      <dd>El nombre de una <a href="../env.html">variable de
      entorno</a> definida en el proceso de configuraci&#243;n de Apache.
      Tenga en cuenta que esto no es necesariamente exactamente lo
      mismo que una variable de entorno del sistema
      operativo. Consulte la <a href="../env.html">documentaci&#243;n sobre
      variables de entorno</a> si quiere obtener m&#225;s informaci&#243;n.</dd>
    </dl>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="Default" id="Default">Valor por defecto</a></h2>

    <p>Si una directiva tiene un valor por defecto (esto significa
    que, si no especifica un valor explicitamente en la
    configuraci&#243;n, el servidor Apache se comportar&#225; como si hubiera
    especificado ese valor por defecto). Si no existe un valor por
    defecto, en este apartado aparecer&#225; "<em>None</em>". Tenga en
    cuenta que el valor por defecto que se especifica aqu&#237; puede no
    ser el mismo que el que viene especificado para la directiva en el
    fichero de configuraci&#243;n httpd.conf que viene por defecto.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="Context" id="Context">Contexto</a></h2>

    <p>Indica en qu&#233; parte de los ficheros de configuraci&#243;n del
    servidor se puede usar la directiva. Es una lista de elementos
    separados por comas. Los valores permitidos son los
    siguientes:</p>

    <dl>
      <dt>server config</dt>

      <dd>Significa que la directiva puede ser usada en los ficheros
      de configuraci&#243;n del servidor (<em>por ejemplo</em>,
      <code>httpd.conf</code>), pero <strong>no</strong> dentro de las
      secciones <code class="directive"><a href="../mod/core.html#virtualhost">&lt;VirtualHost&gt;</a></code> ni <code class="directive"><a href="../mod/core.html#directory">&lt;Directory&gt;</a></code>. Tambi&#233;n
      significa que la directiva no puede usarse en los ficheros
      <code>.htaccess</code>.</dd>

      <dt>virtual host</dt>

      <dd>Este contexto significa que la directiva puede aparecer
      dentro de las secciones <code class="directive"><a href="../mod/core.html#virtualhost">&lt;VirtualHost&gt;</a></code> de los ficheros de
      configuraci&#243;n del servidor.</dd>

      <dt>directory</dt>

      <dd>Una directiva marcada como v&#225;lida en este contexto puede
      usarse en las secciones <code class="directive"><a href="../mod/core.html#directory">&lt;Directory&gt;</a></code>, <code class="directive"><a href="../mod/core.html#location">&lt;Location&gt;</a></code>, y <code class="directive"><a href="../mod/core.html#files">&lt;Files&gt;</a></code> en los ficheros de
      configuraci&#243;n del servidor, ateni&#233;ndose en todo caso a las
      restricciones especificadas en el documento <a href="../sections.html">Modo de funcionamiento de las secciones
      Directory, Location y Files</a>.</dd>

      <dt>.htaccess</dt>

      <dd>Si una directiva es v&#225;lida en este contexto, eso significa
      que puede aparecer en los ficheros <code>.htaccess</code>. El
      valor de la directiva puede no ser procesada si hay sobre ella
      una orden de <a href="#Override">sobreescritura</a> activa en
      ese momento.</dd>
    </dl>

    <p>Una directiva puede usarse <em>solo</em> en el contexto
    especificado, si la usa en otro sitio, se producir&#225; en error de
    configuraci&#243;n que har&#225; que el servidor no pueda servir peticiones
    en el contexto correctamente, o que el servidor no pueda
    funcionar en absoluto -- <em>por ejemplo</em>, puede que el
    servidor no se inicie.</p>

    <p>Las ubicaciones v&#225;lidas para una directiva son el resultado de
    la operaci&#243;n booleana OR de todos los contextos listados m&#225;s
    arriba en que est&#233; perimitido su uso. En otras palabras, una
    directiva que est&#233; marcada como v&#225;lida en "<code>server config,
    .htaccess</code>" puede usarse tanto en el fichero
    <code>httpd.conf</code> como en los ficheros
    <code>.htaccess</code>, pero no dentro de las secciones
    <code class="directive"><a href="../mod/core.html#directory">&lt;Directory&gt;</a></code> o
    <code class="directive"><a href="../mod/core.html#virtualhost">&lt;VirtualHost&gt;</a></code>.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="Override" id="Override">Override</a></h2>

    <p>Este atributo indica qu&#233; configuraci&#243;n de las especificadas
    para una directiva es la que prevalece cuando la directiva aparece
    en un fichero <code>.htaccess</code>. Si el <a href="#Context">contexto</a> de una directiva no permite que aparezca en ficheros
    <code>.htaccess</code>, entonces no aparecer&#225; ning&#250;n contexto en
    este campo.</p>

    <p>Para que se aplique el valor especificado en este campo se usa
    la directiva <code class="directive"><a href="../mod/core.html#allowoverride">AllowOverride</a></code>, y
    se aplica a un entorno en particular (por ejemplo un directorio)
    y todo lo que haya por debajo de &#233;l, a menos que haya alguna
    modificaci&#243;n posterior por directivas <code class="directive"><a href="../mod/core.html#allowoverride">AllowOverride</a></code> a niveles m&#225;s bajos. La
    documentaci&#243;n de esta directiva tambi&#233;n especifica los valores que
    puede tomar override.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="Status" id="Status">Estado</a></h2>

    <p>Indica el grado de integraci&#243;n con el el servidor web Apache
    que presenta la directiva; en otras palabras, puede que tenga que
    recompilar el servidor con un conjunto mejorado de m&#243;dulos para
    tener acceso a algunas directivas y a sus funcionalidades. Los
    valores posibles de este campo son:</p>

    <dl>
      <dt>Core</dt>

      <dd>Si una directiva tiene estado "Core", esto significa que su
      grado de integraci&#243;n con el servidor Apache es muy alto, y que
      est&#225; disponible siempre.</dd>

      <dt>MPM</dt>

      <dd>Una directiva etiquetada con el estado "MPM" pertenece a un
      <a href="../mpm.html">M&#243;dulo de MultiProcesamiento</a>. Este
      tipo de directiva estar&#225; disponible solamente si est&#225; usando uno
      de los MPMs listados en la l&#237;nea <a href="#Module">M&#243;dulo</a> de
      la deficinici&#243;n de la directiva.</dd>

      <dt>Base</dt>

      <dd>Una directiva etiquetada con el estado "Base" est&#225; soportada
      por uno de los m&#243;dulos est&#225;ndar de Apache, que est&#225; compilado en
      el servidor por defecto, y est&#225; siempre disponible a no ser que
      haya eliminado ese m&#243;dulo espec&#237;ficamente.</dd>

      <dt>Extension</dt>

      <dd>Una directiva con el estado "Extension" pertenece a un
      m&#243;dulo incluido en el kit del servidor Apache, pero que no est&#225;
      normalmente compilado en el servidor. Para activar la directiva
      y sus funcionalidades, tendr&#225; que recompilar Apache.</dd>

      <dt>Experimental</dt>

      <dd>El estado "Experimental" indica que la directiva est&#225;
      disponible como parte de la distribuci&#243;n Apache, pero que su correcto
      funcionamiento no est&#225; todav&#237;a probado. Puede que la directiva
      est&#233; siendo documentada para completarla, o puede que no se
      ofrezca soporte. El m&#243;dulo que ofrece la directiva puede o no
      estar compilado por defecto; compruebe la parte superior de la
      p&#225;gina que describe la directiva y sus m&#243;dulos para ver si hay
      alguna indicaci&#243;n sobre su disponibilidad.</dd>
    </dl>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="Module" id="Module">M&#243;dulo</a></h2>

    <p>Indica el m&#243;dulo en el cual se define la directiva.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="Compatibility" id="Compatibility">Compatibilidad</a></h2>

    <p>Si una directiva no era originalmente parte de la versi&#243;n 2.0
    de la distribuci&#243;n de Apache, la versi&#243;n en la que fue introducida
    debe aparecer aqu&#237;. Adem&#225;s, si la directiva est&#225; disponible solo
    en algunas plataformas, tambi&#233;n debe figurar aqu&#237;.</p>
</div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="../en/mod/directive-dict.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/mod/directive-dict.html" title="Espa&#241;ol">&nbsp;es&nbsp;</a> |
<a href="../ja/mod/directive-dict.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="../ko/mod/directive-dict.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="../tr/mod/directive-dict.html" hreflang="tr" rel="alternate" title="T&#252;rk&#231;e">&nbsp;tr&nbsp;</a></p>
</div><div id="footer">
<p class="apache">Copyright 2013 The Apache Software Foundation.<br />Licencia bajo los t&#233;rminos de la <a href="http://www.apache.org/licenses/LICENSE-2.0">Apache License, Version 2.0</a>.</p>
<p class="menu"><a href="../mod/">M&#243;dulos</a> | <a href="../mod/directives.html">Directivas</a> | <a href="../faq/">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa de este sitio web</a></p></div>
</body></html>