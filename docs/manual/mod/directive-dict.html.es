<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es" xml:lang="es"><head><!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Términos usados en las descripciones de las
  Directivas - Servidor HTTP Apache</title>
<link href="../style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet" />
<link href="../style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size" />
<link href="../style/css/manual-print.css" rel="stylesheet" media="print" type="text/css" />
<link href="../images/favicon.ico" rel="shortcut icon" /></head>
<body id="manual-page"><div id="page-header">
<p class="menu"><a href="../mod/">Módulos</a> | <a href="../mod/directives.html">Directivas</a> | <a href="../faq/">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa de este sitio web</a></p>
<p class="apache">Versión 2.0 del Servidor HTTP Apache</p>
<img alt="" src="../images/feather.gif" /></div>
<div class="up"><a href="./"><img title="&lt;-" alt="&lt;-" src="../images/left.gif" /></a></div>
<div id="path">
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs-project/">Documentación</a> &gt; <a href="../">Versión 2.0</a></div><div id="page-content"><div id="preamble"><h1>Términos usados en las descripciones de las
  Directivas</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="../en/mod/directive-dict.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/mod/directive-dict.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="../ja/mod/directive-dict.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="../ko/mod/directive-dict.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a></p>
</div>
<div class="outofdate">Esta traducción podría estar
            obsoleta. Consulte la versión en inglés de la
            documentación para comprobar si se han producido cambios
            recientemente.</div>

    <p>Este documento define los términos que se usan para describir
    las <a href="directives.html">directivas de configuración</a> de
    Apache.</p>
</div>
<div id="quickview"><ul id="toc"><li><img alt="" src="../images/down.gif" /> <a href="#Description">Descripción</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#Syntax">Sintaxis</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#Default">Valor por defecto</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#Context">Contexto</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#Override">Override</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#Status">Estado</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#Module">Módulo</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#Compatibility">Compatibilidad</a></li>
</ul><h3>Consulte también</h3><ul class="seealso"><li><a href="../configuring.html">Fichero de
Configuración</a></li></ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="Description" id="Description">Descripción</a></h2>

<p>Descripción resumida de para qué sirve la directiva.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="Syntax" id="Syntax">Sintaxis</a></h2>

    <p>Explica el formato de la directiva en la manera en que
    aparecería en un fichero de configuración. La sintaxis es
    específica para cada directiva, y se decribe en detalle en la
    definición de cada una de ellas. Generalmente, es el nombre de la
    directiva seguido del argumento o argumentos que correspondan
    separados por espacios. Si un argumento contiene un espacio,
    entonces debe escribirse entre comillas. Los argumentos opcionales
    van entre corchetes ([]). Si cada argumento puede tomar más de un
    valor, los valores posibles van separados por barras verticales
    "|".  Los textos literales (los que no hay que sustituir) están en
    el tipo de letra por defecto del resto del texto, mientras que los
    que hay que sustituir están <em>resaltados</em>. Las directivas
    que pueden tomar un número variable de argumentos terminan con
    puntos suspensivos ("...").</p>

    <p>Las directivas usan una gran variedad de tipos de
    argumentos. Algunos de los más comunes son:</p>

    <dl>
      <dt><em>URL</em></dt>

      <dd>Un Localizador de Recursos Uniforme (Uniform Resource
      Locator) que consiste en un esquema (www), un nombre de host
      (example.com), y opcionalmente, una ruta; por ejemplo
      <code>http://www.example.com/path/to/file.html</code></dd>

      <dt><em>URL-path</em></dt>

      <dd>La parte de una <em>url</em> que va a continuación del
      esquema y del nombre de host, por ejemplo
      <code>/path/to/file.html</code>. El <em>url-path</em> representa
      al fichero visto desde el servidor web, en contraposición a
      verlo tomando el sistema de ficheros como punto de
      referencia.</dd>

      <dt><em>file-path</em></dt>

      <dd>La ubicación de un fichero en el sistema de archivos local
      que empieza con el directorio raiz, por ejemplo,
      <code>/usr/local/apache/htdocs/path/to/file.html</code>.  A
      menos que se especifique otra cosa, un <em>file-path</em> que no
      empieza con una barra será tratado como relativo a <a href="core.html#serverroot">ServerRoot</a>.</dd>

      <dt><em>directory-path</em></dt>

      <dd>La ubicación de un directorio en el sistema de archivos
      local que empieza en el directorio raiz, por ejemplo
      <code>/usr/local/apache/htdocs/path/to/</code>.</dd>

      <dt><em>filename</em></dt>

      <dd>El nombre de un fichero sin información adicional sobre su
      ubicación, por ejemplo <code>file.html</code>.</dd>

      <dt><em>regex</em></dt>

      <dd>Una expresión regular, que es una forma de describir un
      patrón para encontrar sus equivalencias en un texto. La
      definición de la directiva especificará con qué se comparará
      <em>regex</em> para encontrar equivalencias.</dd>

      <dt><em>extension</em></dt>

      <dd>En general, es la parte del <em>filename</em> que va después
      del último punto. Apache reconoce muchas de estas extensiones,
      de manera que si un <em>filename</em> contiene mas de un punto,
      cada parte separada por uno de esos puntos después del primero
      se trata como una <em>extensión</em>.  Por ejemplo, el
      <em>filename</em> <code>file.html.en</code> contiene dos
      extensiones: <code>.html</code> y <code>.en</code>. Para las
      directivas de Apache, puede especificar <em>extensiones</em> con
      o sin punto delante. Las <em>extensiones</em> no distinguen
      mayúsculas de minúsculas.</dd>

      <dt><em>MIME Type</em></dt>

      <dd>Es una forma de describir el formato de un fichero, que
      consiste en un tipo de formato principal y un tipo de formato
      secundario, separados por una barra, por ejemplo
      <code>text/html</code>.</dd>

      <dt><em>env-variable</em></dt>

      <dd>El nombre de una <a href="../env.html">variable de
      entorno</a> definida en el proceso de configuración de Apache.
      Tenga en cuenta que esto no es necesariamente exactamente lo
      mismo que una variable de entorno del sistema
      operativo. Consulte la <a href="../env.html">documentación sobre
      variables de entorno</a> si quiere obtener más información.</dd>
    </dl>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="Default" id="Default">Valor por defecto</a></h2>

    <p>Si una directiva tiene un valor por defecto (esto significa
    que, si no especifica un valor explicitamente en la
    configuración, el servidor Apache se comportará como si hubiera
    especificado ese valor por defecto). Si no existe un valor por
    defecto, en este apartado aparecerá "<em>None</em>". Tenga en
    cuenta que el valor por defecto que se especifica aquí puede no
    ser el mismo que el que viene especificado para la directiva en el
    fichero de configuración httpd.conf que viene por defecto.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="Context" id="Context">Contexto</a></h2>

    <p>Indica en qué parte de los ficheros de configuración del
    servidor se puede usar la directiva. Es una lista de elementos
    separados por comas. Los valores permitidos son los
    siguientes:</p>

    <dl>
      <dt>server config</dt>

      <dd>Significa que la directiva puede ser usada en los ficheros
      de configuración del servidor (<em>por ejemplo</em>,
      <code>httpd.conf</code>), pero <strong>no</strong> dentro de las
      secciones <code class="directive"><a href="../mod/core.html#virtualhost">&lt;VirtualHost&gt;</a></code> ni <code class="directive"><a href="../mod/core.html#directory">&lt;Directory&gt;</a></code>. También
      significa que la directiva no puede usarse en los ficheros
      <code>.htaccess</code>.</dd>

      <dt>virtual host</dt>

      <dd>Este contexto significa que la directiva puede aparecer
      dentro de las secciones <code class="directive"><a href="../mod/core.html#virtualhost">&lt;VirtualHost&gt;</a></code> de los ficheros de
      configuración del servidor.</dd>

      <dt>directory</dt>

      <dd>Una directiva marcada como válida en este contexto puede
      usarse en las secciones <code class="directive"><a href="../mod/core.html#directory">&lt;Directory&gt;</a></code>, <code class="directive"><a href="../mod/core.html#location">&lt;Location&gt;</a></code>, y <code class="directive"><a href="../mod/core.html#files">&lt;Files&gt;</a></code> en los ficheros de
      configuración del servidor, ateniéndose en todo caso a las
      restricciones especificadas en el documento <a href="../sections.html">Modo de funcionamiento de las secciones
      Directory, Location y Files</a>.</dd>

      <dt>.htaccess</dt>

      <dd>Si una directiva es válida en este contexto, eso significa
      que puede aparecer en los ficheros <code>.htaccess</code>. El
      valor de la directiva puede no ser procesada si hay sobre ella
      una orden de <a href="#Override">sobreescritura</a> activa en
      ese momento.</dd>
    </dl>

    <p>Una directiva puede usarse <em>solo</em> en el contexto
    especificado, si la usa en otro sitio, se producirá en error de
    configuración que hará que el servidor no pueda servir peticiones
    en el contexto correctamente, o que el servidor no pueda
    funcionar en absoluto -- <em>por ejemplo</em>, puede que el
    servidor no se inicie.</p>

    <p>Las ubicaciones válidas para una directiva son el resultado de
    la operación booleana OR de todos los contextos listados más
    arriba en que esté perimitido su uso. En otras palabras, una
    directiva que esté marcada como válida en "<code>server config,
    .htaccess</code>" puede usarse tanto en el fichero
    <code>httpd.conf</code> como en los ficheros
    <code>.htaccess</code>, pero no dentro de las secciones
    <code class="directive"><a href="../mod/core.html#directory">&lt;Directory&gt;</a></code> o
    <code class="directive"><a href="../mod/core.html#virtualhost">&lt;VirtualHost&gt;</a></code>.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="Override" id="Override">Override</a></h2>

    <p>Este atributo indica qué configuración de las especificadas
    para una directiva es la que prevalece cuando la directiva aparece
    en un fichero <code>.htaccess</code>. Si el <a href="#Context">contexto</a> de una directiva no permite que aparezca en ficheros
    <code>.htaccess</code>, entonces no aparecerá ningún contexto en
    este campo.</p>

    <p>Para que se aplique el valor especificado en este campo se usa
    la directiva <code class="directive"><a href="../mod/core.html#allowoverride">AllowOverride</a></code>, y
    se aplica a un entorno en particular (por ejemplo un directorio)
    y todo lo que haya por debajo de él, a menos que haya alguna
    modificación posterior por directivas <code class="directive"><a href="../mod/core.html#allowoverride">AllowOverride</a></code> a niveles más bajos. La
    documentación de esta directiva también especifica los valores que
    puede tomar override.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="Status" id="Status">Estado</a></h2>

    <p>Indica el grado de integración con el el servidor web Apache
    que presenta la directiva; en otras palabras, puede que tenga que
    recompilar el servidor con un conjunto mejorado de módulos para
    tener acceso a algunas directivas y a sus funcionalidades. Los
    valores posibles de este campo son:</p>

    <dl>
      <dt>Core</dt>

      <dd>Si una directiva tiene estado "Core", esto significa que su
      grado de integración con el servidor Apache es muy alto, y que
      está disponible siempre.</dd>

      <dt>MPM</dt>

      <dd>Una directiva etiquetada con el estado "MPM" pertenece a un
      <a href="../mpm.html">Módulo de MultiProcesamiento</a>. Este
      tipo de directiva estará disponible solamente si está usando uno
      de los MPMs listados en la línea <a href="#Module">Módulo</a> de
      la deficinición de la directiva.</dd>

      <dt>Base</dt>

      <dd>Una directiva etiquetada con el estado "Base" está soportada
      por uno de los módulos estándar de Apache, que está compilado en
      el servidor por defecto, y está siempre disponible a no ser que
      haya eliminado ese módulo específicamente.</dd>

      <dt>Extension</dt>

      <dd>Una directiva con el estado "Extension" pertenece a un
      módulo incluido en el kit del servidor Apache, pero que no está
      normalmente compilado en el servidor. Para activar la directiva
      y sus funcionalidades, tendrá que recompilar Apache.</dd>

      <dt>Experimental</dt>

      <dd>El estado "Experimental" indica que la directiva está
      disponible como parte de la distribución Apache, pero que su correcto
      funcionamiento no está todavía probado. Puede que la directiva
      esté siendo documentada para completarla, o puede que no se
      ofrezca soporte. El módulo que ofrece la directiva puede o no
      estar compilado por defecto; compruebe la parte superior de la
      página que describe la directiva y sus módulos para ver si hay
      alguna indicación sobre su disponibilidad.</dd>
    </dl>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="Module" id="Module">Módulo</a></h2>

    <p>Indica el módulo en el cual se define la directiva.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="Compatibility" id="Compatibility">Compatibilidad</a></h2>

    <p>Si una directiva no era originalmente parte de la versión 2.0
    de la distribución de Apache, la versión en la que fue introducida
    debe aparecer aquí. Además, si la directiva está disponible solo
    en algunas plataformas, también debe figurar aquí.</p>
</div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="../en/mod/directive-dict.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/mod/directive-dict.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="../ja/mod/directive-dict.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="../ko/mod/directive-dict.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a></p>
</div><div id="footer">
<p class="apache">Copyright 1995-2005 The Apache Software Foundation or its licensors, as applicable.<br />Licencia bajo los términos de la <a href="http://www.apache.org/licenses/LICENSE-2.0">Apache License, Version 2.0</a>.</p>
<p class="menu"><a href="../mod/">Módulos</a> | <a href="../mod/directives.html">Directivas</a> | <a href="../faq/">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa de este sitio web</a></p></div>
</body></html>