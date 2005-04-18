<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es" xml:lang="es"><head><!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>core - Servidor HTTP Apache</title>
<link href="../style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet" />
<link href="../style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size" />
<link href="../style/css/manual-print.css" rel="stylesheet" media="print" type="text/css" />
<link href="../images/favicon.ico" rel="shortcut icon" /></head>
<body>
<div id="page-header">
<p class="menu"><a href="../mod/">Módulos</a> | <a href="../mod/directives.html">Directivas</a> | <a href="../faq/">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa de este sitio web</a></p>
<p class="apache">Versión 2.0 del Servidor HTTP Apache</p>
<img alt="" src="../images/feather.gif" /></div>
<div class="up"><a href="./"><img title="&lt;-" alt="&lt;-" src="../images/left.gif" /></a></div>
<div id="path">
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs-project/">Documentación</a> &gt; <a href="../">Versión 2.0</a> &gt; <a href="./">Módulos</a></div>
<div id="page-content">
<div id="preamble"><h1>Funcionalidad Básica de Apache</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="../de/mod/core.html" hreflang="de" rel="alternate" title="Deutsch">&nbsp;de&nbsp;</a> |
<a href="../en/mod/core.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/mod/core.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="../ja/mod/core.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a></p>
</div>
<table class="module"><tr><th><a href="module-dict.html#Description">Descripción:</a></th><td>Funcionalidades básicas del servidor HTTP Apache que
están siempre presentes</td></tr>
<tr><th><a href="module-dict.html#Status">Estado:</a></th><td>Core</td></tr></table>
</div>
<div id="quickview"><h3 class="directives">Directivas</h3>
<ul id="toc">
<li><img alt="" src="../images/down.gif" /> <a href="#acceptpathinfo">AcceptPathInfo</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#accessfilename">AccessFileName</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#adddefaultcharset">AddDefaultCharset</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#addoutputfilterbytype">AddOutputFilterByType</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#allowencodedslashes">AllowEncodedSlashes</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#allowoverride">AllowOverride</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#authname">AuthName</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#authtype">AuthType</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#cgimapextension">CGIMapExtension</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#contentdigest">ContentDigest</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#defaulttype">DefaultType</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#directory">&lt;Directory&gt;</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#directorymatch">&lt;DirectoryMatch&gt;</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#documentroot">DocumentRoot</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#enablemmap">EnableMMAP</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#enablesendfile">EnableSendfile</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#errordocument">ErrorDocument</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#errorlog">ErrorLog</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#fileetag">FileETag</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#files">&lt;Files&gt;</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#filesmatch">&lt;FilesMatch&gt;</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#forcetype">ForceType</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#hostnamelookups">HostnameLookups</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#identitycheck">IdentityCheck</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#ifdefine">&lt;IfDefine&gt;</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#ifmodule">&lt;IfModule&gt;</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#include">Include</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#keepalive">KeepAlive</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#keepalivetimeout">KeepAliveTimeout</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#limit">&lt;Limit&gt;</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#limitexcept">&lt;LimitExcept&gt;</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#limitinternalrecursion">LimitInternalRecursion</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#limitrequestbody">LimitRequestBody</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#limitrequestfields">LimitRequestFields</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#limitrequestfieldsize">LimitRequestFieldSize</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#limitrequestline">LimitRequestLine</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#limitxmlrequestbody">LimitXMLRequestBody</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#location">&lt;Location&gt;</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#locationmatch">&lt;LocationMatch&gt;</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#loglevel">LogLevel</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#maxkeepaliverequests">MaxKeepAliveRequests</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#namevirtualhost">NameVirtualHost</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#options">Options</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#require">Require</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#rlimitcpu">RLimitCPU</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#rlimitmem">RLimitMEM</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#rlimitnproc">RLimitNPROC</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#satisfy">Satisfy</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#scriptinterpretersource">ScriptInterpreterSource</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#serveradmin">ServerAdmin</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#serveralias">ServerAlias</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#servername">ServerName</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#serverpath">ServerPath</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#serverroot">ServerRoot</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#serversignature">ServerSignature</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#servertokens">ServerTokens</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#sethandler">SetHandler</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#setinputfilter">SetInputFilter</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#setoutputfilter">SetOutputFilter</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#timeout">TimeOut</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#usecanonicalname">UseCanonicalName</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#virtualhost">&lt;VirtualHost&gt;</a></li>
</ul>
</div>

<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="AcceptPathInfo" id="AcceptPathInfo">AcceptPathInfo</a> <a name="acceptpathinfo" id="acceptpathinfo">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Especifica si los recursos aceptan información de
path añadida (trailing pathname information)</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>AcceptPathInfo On|Off|Default</code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>AcceptPathInfo Default</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host, directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Prevalece sobre:</a></th><td>FileInfo</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
<tr><th><a href="directive-dict.html#Compatibility">Compatibilidad:</a></th><td>Disponible en la versiones de Apache 2.0.30 y posteriores</td></tr>
</table>

    <p>Esta directiva controla si las peticiones que contienen
    información de path añadida (trailing pathname
    information) a continuación de un nombre de fichero existente
    (o no existente en un directorio que sí existe) serán
    aceptadas o rechazadas. La información de path añadida
    (trailing pathname information) puede pasarse a los scripts en la
    variable de entorno <code>PATH_INFO</code>.</p>

    <p>Por ejemplo, suponga que la ubicación <code>/test/</code>
    se refiere a un directorio que contiene un único fichero:
    <code>here.html</code>.  Entonces, tanto las peticiones a
    <code>/test/here.html/more</code> como las peticiones a
    <code>/test/nothere.html/more</code> toman <code>/more</code> como
    <code>PATH_INFO</code>.</p>

    <p>Los tres argumentos que puede tomar la directiva
    <code class="directive">AcceptPathInfo</code> son:</p>
    <dl>
    <dt><code>Off</code></dt><dd>Una petición será aceptada
    solamente si se refiere literalmente a una ruta que existe.  Por
    tanto, una petición con información de path añadida
    (trailing pathname information) después de un nombre de
    fichero que existe, del tipo <code>/test/here.html/more</code>
    como en el ejemplo de arriba, devolverá el mensaje de error
    404 NOT FOUND.</dd>

    <dt><code>On</code></dt><dd>Una petición será aceptada
    si la componente anterior a la información de path
    añadida (trailing pathname information) se refiere a un
    fichero que existe.  El ejemplo de arriba
    <code>/test/here.html/more</code> será aceptado si
    <code>/test/here.html</code> se refiere a un fichero
    válido.</dd>

    <dt><code>Default</code></dt><dd>El tratamiento de las peticiones
    con información de path añadida (trailing pathname
    information) está determinado por el <a href="../handler.html">handler</a> responsable de la
    petición.  El handler básico para ficheros normales
    rechaza por defecto las peticiones de <code>PATH_INFO</code>. Los
    handlers que sirven scripts, como <a href="mod_cgi.html">cgi-script</a> e <a href="mod_isapi.html">isapi-isa</a>, generalmente aceptan
    <code>PATH_INFO</code> por defecto.</dd>
    </dl>

    <p>El propósito principal de la directiva
    <code>AcceptPathInfo</code> es permitirle hacer prevalecer su
    propio criterio sobre el del handler acerca de si se debe aceptar
    o rechazar <code>PATH_INFO</code>. Esto es necesario por ejemplo,
    cuando use un <a href="../filter.html">filtro</a>, como <a href="mod_include.html">INCLUDES</a>, para generar contenido
    basado en <code>PATH_INFO</code>.  El handler básico
    rechazaría normalmente la petición. Puede usar la
    siguiente configuración para activar dicho script:</p>

    <div class="example"><p><code>
      &lt;Files "mypaths.shtml"&gt;<br />
      <span class="indent">
        Options +Includes<br />
        SetOutputFilter INCLUDES<br />
        AcceptPathInfo On<br />
      </span>
      &lt;/Files&gt;
    </code></p></div>


</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="AccessFileName" id="AccessFileName">AccessFileName</a> <a name="accessfilename" id="accessfilename">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Nombre del fichero de configuración distribuida</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>AccessFileName <var>filename</var> [<var>filename</var>] ...</code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>AccessFileName .htaccess</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>Durante el procesamiento de una petición el servidor busca
    el primer fichero de configuración de esta lista de nombres
    en cada directorio de la ruta del documento, siempre y cuando los
    ficheros de configuración distribuida estén <a href="#allowoverride">activados para ese directorio</a>. Por
    ejemplo:</p>

    <div class="example"><p><code>
      AccessFileName .acl
    </code></p></div>

    <p>Antes de devolver el documento
    <code>/usr/local/web/index.html</code>, el servidor leerá
    <code>/.acl</code>, <code>/usr/.acl</code>,
    <code>/usr/local/.acl</code> y <code>/usr/local/web/.acl</code>
    buscando directivas, a menos que hayan sido desactivados con</p>

    <div class="example"><p><code>
      &lt;Directory /&gt;<br />
      <span class="indent">
        AllowOverride None<br />
      </span>
      &lt;/Directory&gt;
    </code></p></div>

<h3>Consulte también</h3>
<ul>
<li><code class="directive"><a href="#allowoverride">AllowOverride</a></code></li>
<li><a href="../configuring.html">Ficheros de Configuración</a></li>
<li><a href="../howto/htaccess.html">Ficheros .htaccess</a></li>
</ul>
</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="AddDefaultCharset" id="AddDefaultCharset">AddDefaultCharset</a> <a name="adddefaultcharset" id="adddefaultcharset">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Parámetro del conjunto de caracteres que se
añade cuando el tipo de contenido de una respuesta es
<code>text/plain</code> o <code>text/html</code></td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>AddDefaultCharset On|Off|<var>charset</var></code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>AddDefaultCharset Off</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host, directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Prevalece sobre:</a></th><td>FileInfo</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>Esta directiva especifica un valor por defecto para el
    parámetro del conjunto de caracteres que se añade
    añade si solo si el tipo de contenido de una respuesta es
    <code>text/plain</code> o <code>text/html</code>. EL valor
    pecificado en esta directiva no prevalecerá si cualquier otro
    conjunto de caracteres es especificado en el cuerpo del documento
    por medio de una etiqueta <code>META</code>, aunque a menudo, el
    comportamiento exacto está determinado por la
    configuración del cliente. Si se especifica
    <code>AddDefaultCharset Off</code>, se desactiva esta
    funcionalidad. <code>AddDefaultCharset On</code> activa el uso del
    conjunto de caracteres por defecto interno de Apache,
    <code>iso-8859-1</code>. Cualquier otro valor se asume que es el
    <var>charset</var> a usar, que será uno los <a href="http://www.iana.org/assignments/character-sets">registrados
    por la IANA</a> como tipos MIME. Por ejemplo:</p>

    <div class="example"><p><code>
      AddDefaultCharset utf-8
    </code></p></div>

    <p><code class="directive">AddDefaultCharset</code> debe ser usada solo
    cuando todos los recursos de texto a los que se aplican se saben
    que usan un determiando conjunto de caracteres (character
    encoding) y no es conveniente etiquetar los documentos
    individualmente. Un ejemplo es su uso en recursos que contienen
    contenido generado, como CGIs antiguos, que puede ser vulnerables
    a ataques debidos a que se incluye en el resultado datos
    suministrados por el usuario. Tenga en cuenta, sin embargo, que
    una mejor solución es simplemente modificar (o borrar) esos
    scripts, porque especificar un conjunto de caracteres por defecto
    no protege a los usuarios que tengan activada en su navegador la
    opción "auto-detect character encoding".</p>

<h3>Consulte también</h3>
<ul>
<li><code class="directive"><a href="../mod/mod_mime.html#addcharset">AddCharset</a></code></li>
</ul>
</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="AddOutputFilterByType" id="AddOutputFilterByType">AddOutputFilterByType</a> <a name="addoutputfilterbytype" id="addoutputfilterbytype">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Asigna un filtro de
salida a un tipo MIME en particular</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>AddOutputFilterByType <var>filter</var>[;<var>filter</var>...]
<var>MIME-type</var> [<var>MIME-type</var>] ...</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host, directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Prevalece sobre:</a></th><td>FileInfo</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
<tr><th><a href="directive-dict.html#Compatibility">Compatibilidad:</a></th><td>Disponible en las
versiones de Apache 2.0.33 y posteriores</td></tr>
</table>
    <p>Esta directiva activa un <a href="../filter.html">filtro</a> de
    salida en particular para las peticiones en función del tipo
    MIME de la respuesta.</p>

    <p>El siguiente ejemplo usa el filtro <code>DEFLATE</code>, del
    módulo <code class="module"><a href="../mod/mod_deflate.html">mod_deflate</a></code>. Este filtro comprime la
    parte de la respuesta de la petición (ya sea estática o
    dinámica) que esté etiquetada como
    <code>text/html</code> o <code>text/plain</code> antes de ser
    enviada al cliente.</p>

    <div class="example"><p><code>
      AddOutputFilterByType DEFLATE text/html text/plain
    </code></p></div>

    <p>Si quiere que los contenidos sean procesados por más de un
    filtro, debe separar sus nombres con puntos y comas
    (;). Tambén es posible usar la directiva
    <code class="directive">AddOutputFilterByType</code> para cada uno de los
    filtros.</p>

    <p>La configuración que se muestra más abajo hace que
    todos los scripts etiquetados como <code>text/html</code> sean
    procesados primero por el filtro <code>INCLUDES</code> y
    posteriormente por el filtro <code>DEFLATE</code>.</p>

    <div class="example"><p><code>
    &lt;Location /cgi-bin/&gt;<br />
    <span class="indent">
      Options Includes<br />
      AddOutputFilterByType INCLUDES;DEFLATE text/html<br />
    </span>
    &lt;/Location&gt;
    </code></p></div>

    <div class="warning"><h3>Nota</h3> <p>Activar filtros con la
      directiva <code class="directive">AddOutputFilterByType</code> puede no
      funcionar parcial o totalmente. Por ejemplo, no se aplica
      ningún filtro si es posible determinar el tipo MIME y se
      aplica en su lugar <code class="directive"><a href="#defaulttype">DefaultType</a></code>, incluso si el <code class="directive"><a href="#defaulttype">DefaultType</a></code> es el mismo.</p>

      <p>Si quiere estar seguro de que se apliquen los filtros, asigne
      el tipo de contenido a un recurso explícitamente, por ejemplo
      con la directiva <code class="directive"><a href="../mod/mod_mime.html#addtype">AddType</a></code> o con <code class="directive"><a href="#forcetype">ForceType</a></code>. Determinar el tipo de
      contenido dentro de un script CGI (que no sea del tipo nph)
      también es seguro.</p>

      <p>Los filtros de salida por tipo no se aplican nunca en
      peticiones proxy.</p>
    </div>

<h3>Consulte también</h3>
<ul>
<li><code class="directive"><a href="../mod/mod_mime.html#addoutputfilter">AddOutputFilter</a></code></li>
<li><code class="directive"><a href="#setoutputfilter">SetOutputFilter</a></code></li>
<li><a href="../filter.html">Filtros</a></li>
</ul>
</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="AllowEncodedSlashes" id="AllowEncodedSlashes">AllowEncodedSlashes</a> <a name="allowencodedslashes" id="allowencodedslashes">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Determina si se acepta el uso de separadores de
ubicación codificados en las URLs</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>AllowEncodedSlashes On|Off</code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>AllowEncodedSlashes Off</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
<tr><th><a href="directive-dict.html#Compatibility">Compatibilidad:</a></th><td>Disponible en las versines de Apache 2.0.46 y posteriores</td></tr>
</table>
    <p>La directiva <code class="directive">AllowEncodedSlashes</code>
    perimite usar URLs que contienen separadores de ubicación
    codificados (<code>%2F</code> para <code>/</code> y 
    <code>%5C</code> para <code>\</code> en función del
    sistema). Normalmente, tales URLs se rechazan y se devuelve un
    mensaje de error 404 (Not found).</p>

    <p>Especificar el valor <code>On</code> en la directiva
    <code class="directive">AllowEncodedSlashes</code> es útil sobre todo
    cuando se usa junto con <code>PATH_INFO</code>.</p>

    <div class="note"><h3>Nota</h3> <p>Permitir barras codificadas
      <em>no</em> implica su <em>decodificado</em>.  La aparición
      de <code>%2F</code> o <code>%5C</code> (según el sistemas
      de que se trate) se dejará como tal en la cadena de
      caracteres que conforma la de otra manera URL decodificada.</p>
    </div>

<h3>Consulte también</h3>
<ul>
<li><code class="directive"><a href="#acceptpathinfo">AcceptPathInfo</a></code></li>
</ul>
</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="AllowOverride" id="AllowOverride">AllowOverride</a> <a name="allowoverride" id="allowoverride">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Tipos de directivas que cuyo uso está permitido en los ficheros <code>.htaccess</code></td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>AllowOverride All|None|<var>directive-type</var>
[<var>directive-type</var>] ...</code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>AllowOverride All</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>directory</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>Cuando el servidor encuentra un fichero <code>.htaccess</code>
    (como se explica en la directiva <code class="directive"><a href="#accessfilename">AccessFileName</a></code>) es necesario saber que
    directivas presentes en ese fichero pueden prevalecer sobre
    las directivas de configuración previas.</p>

    <div class="note"><h3>Solamente disponible en las secciones
    &lt;Directory&gt;</h3>
    
    <code class="directive">AllowOverride</code> puede usarse solo en las
    secciones <code class="directive"><a href="#directory">&lt;Directory&gt;</a></code> especificadas sin expresiones
    regulares, nunca en las secciones <code class="directive"><a href="#location">&lt;Location&gt;</a></code>, <code class="directive"><a href="#directorymatch">&lt;DirectoryMatch&gt;</a></code> o <code class="directive"><a href="#files">&lt;Files&gt;</a></code>.
    </div>

    <p>Cuando el valor de esta directiva es <code>None</code>,
    entonces los ficheros <a href="#accessfilename">.htaccess</a> son
    ignorados completamente. En ese caso, el servidor ni siquiera
    intentará leer los archivos <code>.htaccess</code>
    existentes.</p>

    <p>Cuando el valor especificado en esta directiva es
    <code>All</code>, entonces cualquier directiva que tenga <a href="directive-dict.html#Context">Context</a> .htaccess puede ser
    usada en los ficheros <code>.htaccess</code>.</p>

    <p>El <var>tipo de directiva</var> puede ser uno de los siguientes
    grupos de directivas.</p>

    <dl>
      <dt>AuthConfig</dt>

      <dd>

      Permite usar directivas de autentificación (<code class="directive"><a href="../mod/mod_auth_dbm.html#authdbmgroupfile">AuthDBMGroupFile</a></code>, <code class="directive"><a href="../mod/mod_auth_dbm.html#authdbmuserfile">AuthDBMUserFile</a></code>, <code class="directive"><a href="../mod/mod_auth.html#authgroupfile">AuthGroupFile</a></code>, <code class="directive"><a href="#authname">AuthName</a></code>, <code class="directive"><a href="#authtype">AuthType</a></code>, <code class="directive"><a href="../mod/mod_auth.html#authuserfile">AuthUserFile</a></code>, <code class="directive"><a href="#require">Require</a></code>, <em>etc.</em>).</dd>

      <dt>FileInfo</dt>

      <dd>
      Permite usar directivas que controlan los tipos de documento
      (<code class="directive"><a href="#defaulttype">DefaultType</a></code>, <code class="directive"><a href="#errordocument">ErrorDocument</a></code>, <code class="directive"><a href="#forcetype">ForceType</a></code>, <code class="directive"><a href="../mod/mod_negotiation.html#languagepriority">LanguagePriority</a></code>,
      <code class="directive"><a href="#sethandler">SetHandler</a></code>, <code class="directive"><a href="#setinputfilter">SetInputFilter</a></code>, <code class="directive"><a href="#setoutputfilter">SetOutputFilter</a></code>, y
      <code class="module"><a href="../mod/mod_mime.html">mod_mime</a></code> las directivas Add* y Remove*,
      <em>etc.</em>).</dd>

      <dt>Indexes</dt>

      <dd>
      Permite el uso de directivas que controlan el indexado de
      directorios (<code class="directive"><a href="../mod/mod_autoindex.html#adddescription">AddDescription</a></code>, <code class="directive"><a href="../mod/mod_autoindex.html#addicon">AddIcon</a></code>, <code class="directive"><a href="../mod/mod_autoindex.html#addiconbyencoding">AddIconByEncoding</a></code>, <code class="directive"><a href="../mod/mod_autoindex.html#addiconbytype">AddIconByType</a></code>, <code class="directive"><a href="../mod/mod_autoindex.html#defaulticon">DefaultIcon</a></code>, <code class="directive"><a href="../mod/mod_dir.html#directoryindex">DirectoryIndex</a></code>, <code class="directive"><a href="../mod/mod_autoindex.html#fancyindexing">FancyIndexing</a></code>, <code class="directive"><a href="../mod/mod_autoindex.html#headername">HeaderName</a></code>, <code class="directive"><a href="../mod/mod_autoindex.html#indexignore">IndexIgnore</a></code>, <code class="directive"><a href="../mod/mod_autoindex.html#indexoptions">IndexOptions</a></code>, <code class="directive"><a href="../mod/mod_autoindex.html#readmename">ReadmeName</a></code>,
      <em>etc.</em>).</dd>

      <dt>Limit</dt>

      <dd>
      Permite el uso de directivas que controlan el acceso al host
      (<code class="directive"><a href="../mod/mod_access.html#allow">Allow</a></code>, <code class="directive"><a href="../mod/mod_access.html#deny">Deny</a></code> y <code class="directive"><a href="../mod/mod_access.html#order">Order</a></code>).</dd>

      <dt>Options</dt>

      <dd>
      Permite usar directivas que controlan funcionalidades
      específicas de directorios (<code class="directive"><a href="#options">Options</a></code> y <code class="directive"><a href="../mod/mod_include.html#xbithack">XBitHack</a></code>).</dd>
    </dl>

    <p>Ejemplo:</p>

    <div class="example"><p><code>
      AllowOverride AuthConfig Indexes
    </code></p></div>

    <p>En el ejemplo de arriba todas las directivas que no están
    en el grupo <code>AuthConfig</code> ni en el grupo
    <code>Indexes</code> provocan un error interno del servidor.</p>

<h3>Consulte también</h3>
<ul>
<li><code class="directive"><a href="#accessfilename">AccessFileName</a></code></li>
<li><a href="../configuring.html">Ficheros de
Configuración</a></li>
<li><a href="../howto/htaccess.html">Ficheros .htaccess</a></li>
</ul>
</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="AuthName" id="AuthName">AuthName</a> <a name="authname" id="authname">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Ambito de autorización para su uso en
autentificación HTTP</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>AuthName <var>auth-domain</var></code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Prevalece sobre:</a></th><td>AuthConfig</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>Esta directiva especifica el nombre de dominio que se muestra
     al solicitar autorización para acceder a un directorio. Este
     nombre de dominio se muestra al cliente para que el usuario sepa
     qué nombre de usuario y contraseña ha de introducir.
     <code class="directive">AuthName</code> toma solamente un argumento; si
     el nombre de dominio contiene algún espacio, debe escribirse
     entre comillas. Para que funcione correctamente, esta directiva
     debe usarse junto con las directivas <code class="directive"><a href="#authtype">AuthType</a></code> y <code class="directive"><a href="#require">Require</a></code>, y con directivas como
     <code class="directive"><a href="../mod/mod_auth.html#authuserfile">AuthUserFile</a></code> y
     <code class="directive"><a href="../mod/mod_auth.html#authgroupfile">AuthGroupFile</a></code>.</p>

   <p>Por ejemplo:</p>

   <div class="example"><p><code>
     AuthName "Top Secret"
   </code></p></div>

    <p>La cadena de caracteres que se especifique como valor de
    <code>AuthName</code> será lo que aparecerá en el cuadro
    de diálogo de acceso de la mayoría de los
    navegadores.</p>

<h3>Consulte también</h3>
<ul>
<li>
    <a href="../howto/auth.html">Autentificación, Autorización y
    Control de Acceso</a></li>
</ul>
</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="AuthType" id="AuthType">AuthType</a> <a name="authtype" id="authtype">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Tipo de autentificación de usuarios</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>AuthType Basic|Digest</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Prevalece sobre:</a></th><td>AuthConfig</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>Esta directiva selecciona el tipo de autentificación de
    usuarios que usará para un directorio. Actualmente solamente
    están implementadas las opciones <code>Basic</code> y
    <code>Digest</code>.

     Para que funcione correctamente, esta directiva tiene que ir
     acompañada por las directivas <code class="directive"><a href="#authname">AuthName</a></code> y <code class="directive"><a href="#require">Require</a></code>, y de directivas como
     <code class="directive"><a href="../mod/mod_auth.html#authuserfile">AuthUserFile</a></code> y
     <code class="directive"><a href="../mod/mod_auth.html#authgroupfile">AuthGroupFile</a></code>.</p>

<h3>Consulte también</h3>
<ul>
<li><a href="../howto/auth.html">&gt;Autentificación, Autorización y
Control de Acceso</a></li>
</ul>
</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="CGIMapExtension" id="CGIMapExtension">CGIMapExtension</a> <a name="cgimapextension" id="cgimapextension">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Técnica para localizar
un intérprete de scripts CGI</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>CGIMapExtension <var>cgi-path</var>
<var>.extension</var></code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Prevalece sobre:</a></th><td>FileInfo</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
<tr><th><a href="directive-dict.html#Compatibility">Compatibilidad:</a></th><td>Solamente NetWare</td></tr>
</table>
    <p>Esta directiva se usa para controlar la forma en que Apache
    encuentra el intérprete para ejecutar scripts CGI. Por
    ejemplo, si usa <code>CGIMapExtension sys:\foo.nlm .foo</code>,
    todos los scripts CGI con extensión <code>.foo</code> se
    pasarán al intérprete FOO.</p>

</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="ContentDigest" id="ContentDigest">ContentDigest</a> <a name="contentdigest" id="contentdigest">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Activa la generación de cabeceras de respuesta HTTP
<code>Content-MD5</code></td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>ContentDigest On|Off</code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>ContentDigest Off</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host, directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Prevalece sobre:</a></th><td>Options</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>Esta directiva permite la generación de cabeceras
    <code>Content-MD5</code> según se definen en RFC1864 y
    RFC2068.</p>

    <p>MD5 es un algoritmo que genera una cadena de caracteres
    ("message digest", a veces llamado "huella dactilar") a partir de
    unos datos de longitud arbitraria. La forma en que funciona este
    algoritmo hace que con casi toda seguridad, si se producen
    alteraciones en los datos originales, el "message digest" generado
    también será diferente.</p>

    <p>La cabecera <code>Content-MD5</code> es una forma de comprobar
    la integridad de un mensaje de principio a fin (MIC) para los
    mensajes HTTP (entity-body). Un proxy o un cliente pueden
    comprobar esta cabecera para detectar modificaciones accidentales
    en el mensaje HTTP (entity-body) en tránsito. Cabecera de
    ejemplo:</p>

    <div class="example"><p><code>
      Content-MD5: AuLb7Dp1rqtRtxz2m9kRpA==
    </code></p></div>

    <p>Tenga en cuenta que el uso de esta directiva puede provocar un
    menor rendimiento de su servidor porque el "message digest" se
    genera en cada petición (los valores no se guardan).</p>

    <p>La cebecera <code>Content-MD5</code> se envía solamente
    cuando un documento es servido por <code class="module"><a href="../mod/core.html">core</a></code>. Si el
    documento es servido con cuaquier otro módulo, no se
    envía. Por ejemplo, los documentos SSI, las salidas de
    scripts CGI, y las respuesta parciales (byte range responses) no
    tienen esta cabecera.</p>

</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="DefaultType" id="DefaultType">DefaultType</a> <a name="defaulttype" id="defaulttype">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Tipo de contenido MIME por defecto que usará el servidor si no
puede determinar el tipo MIME en concreto del documento a servir</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>DefaultType <var>MIME-type</var></code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>DefaultType text/plain</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host, directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Prevalece sobre:</a></th><td>FileInfo</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>Hay veces en las que se pide al servidor que devuelva un
    documento cuyo tipo MIME no puede determinar.</p>

    <p>El servidor tiene que informar al cliente del tipo de contenido
    del documento. En el caso de que se trate de un tipo desconocido,
    se usa el tipo <code>DefaultType</code>. Por ejemplo:</p>

    <div class="example"><p><code>
      DefaultType image/gif
    </code></p></div>

    <p>sería apropiado para un directorio que contenga muchas
    imagenes tipo GIF cuyos nombres de fichero no tengan la
    extensión <code>.gif</code>.</p>

    <p>Tenga en cuenta que a diferencia de <code class="directive"><a href="#forcetype">ForceType</a></code>, esta directiva solamente
    indica el tipo MIME por defecto. El resto de definiciones de tipos
    MIME, incluidas las extensiones de fichero, que pueden identificar
    el tipo MIME de que se trata prevalecen sobre esta opción por
    defecto.</p>

</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="Directory" id="Directory">&lt;Directory&gt;</a> <a name="directory" id="directory">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Engloba a un grupo de directivas
que se aplicarán solamente al directorio del sistema de ficheros
especificado y a sus subdirectorios</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>&lt;Directory <var>directory-path</var>&gt;
... &lt;/Directory&gt;</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>Las directivas <code class="directive">&lt;Directory&gt;</code>
    y <code>&lt;/Directory&gt;</code> se usan para englobar un grupo
    de directivas que se aplicarán solamente al directorio
    especificado y a sus subdirectorios. Puede incluir a cualquier
    directiva cuyo uso esté permitido en un contexto
    &lt;directory&gt;. <var>Directory-path</var> puede ser tanto la
    ruta completa a un directorio, como una cadena de caracteres
    comodín que use las reglas de equivalencia de los shells de
    Unix. En una cadena de caracteres comodín, el carácter
    <code>?</code> equivale a cualquier carácter individual, y
    <code>*</code> equivale a cualquier secuencia de
    caracteres. También puede usar <code>[]</code> para expresar
    rangos de caracteres. Ninguno de los caracteres comodín
    equivale al carácter `/', de modo que <code>&lt;Directory
    /*/public_html&gt;</code> no equivale a
    <code>/home/user/public_html</code>, pero sí a
    <code>&lt;Directory /home/*/public_html&gt;</code>. Ejemplo:</p>

    <div class="example"><p><code>
      &lt;Directory /usr/local/httpd/htdocs&gt;<br />
      <span class="indent">
        Options Indexes FollowSymLinks<br />
      </span>
      &lt;/Directory&gt;
    </code></p></div>

    <div class="note">
      <p>Tenga especial cuidado con los argumentos de
      <var>directory-path</var>: tienen que equivaler literalmente a
      la ruta del sistema de ficheros que Apache usa para acceder a
      los ficheros. Las directivas aplicadas a un
      <code>&lt;Directory&gt;</code> en particular no se
      aplicarán a los ficheros de ese mismo directorio pero que
      sean accedidos mediante una ruta diferente, como por ejemplo
      mediante enlaces simbólicos diferentes.</p>
    </div>

    <p>También pueden usar expresiones regulares extendidas,
    añadiendo el carácter <code>~</code>. Por ejemplo:</p>

    <div class="example"><p><code>
      &lt;Directory ~ "^/www/.*/[0-9]{3}"&gt;
    </code></p></div>

    <p>equivaldría a los directorios en <code>/www/</code> cuyo
    nombres consistan en tres números.</p>

    <p>Si varias (expresiones no regulares) secciones <code class="directive">&lt;Directory&gt;</code> equivalen al directorio (o a
    uno de los directorios de los que es subdirectorio) que contiene
    un documento, entonces las directivas se aplican según el
    criterio de la ruta equivalente más corta, junto con las
    directivas de los archivos <a href="#accessfilename">.htaccess</a>. Por ejemplo, con</p>

    <div class="example"><p><code>
      &lt;Directory /&gt;<br />
      <span class="indent">
        AllowOverride None<br />
      </span>
      &lt;/Directory&gt;<br />
      <br />
      &lt;Directory /home/&gt;<br />
      <span class="indent">
        AllowOverride FileInfo<br />
      </span>
      &lt;/Directory&gt;
    </code></p></div>

    <p>para acceder al documento <code>/home/web/dir/doc.html</code>
    los pasos son:</p>

    <ul>
      <li>Se aplica la directiva <code>AllowOverride None</code>
      (desactivando los ficheros <code>.htaccess</code>).</li>

      <li>Se aplica la directiva <code>AllowOverride FileInfo</code>
      (para el directorio <code>/home</code>).</li>

      <li>Se aplica cualquier directiva <code>FileInfo</code> en
      <code>/home/.htaccess</code>, <code>/home/web/.htaccess</code> y
      <code>/home/web/dir/.htaccess</code> por ese orden.</li>
    </ul>

    <p>Las expresiones regulares no se tienen en cuenta hasta que
    todas las secciones normales hayan sido aplicadas. En ese momento
    todas se evalúan las expresiones regulares en el orden en que
    aparecen en el fichero de configuración. Por ejemplo, con</p>

    <div class="example"><p><code>
      &lt;Directory ~ abc$&gt;<br />
      <span class="indent">
        # ... directivas aquí ...<br />
      </span>
      &lt;/Directory&gt;
    </code></p></div>

    <p>la sección de expresiones regulares no será
    considerada hasta después de que todas las directivas
    <code class="directive">&lt;Directory&gt;</code> y los ficheros
    <code>.htaccess</code> hayan sido aplicados. Solamente entonces
    las expresiones regulares que tengan una equivalencia con
    <code>/home/abc/public_html/abc</code> y la correspondiente
    directiva <code class="directive">&lt;Directory&gt;</code>
    serán aplicadas.</p>

   <p><strong>Tenga en cuenta que por defecto el acceso de Apache a
    <code>&lt;Directory /&gt;</code> es <code>Allow from All</code>.
    Esto significa que Apache servirá cualquier fichero que se
    corresponda con una URL. Se recomienda que modifique este
    comportamiento con un bloque del siguiente tipo</strong></p>

    <div class="example"><p><code>
      &lt;Directory /&gt;<br />
      <span class="indent">
        Order Deny,Allow<br />
        Deny from All<br />
      </span>
      &lt;/Directory&gt;
    </code></p></div>

    <p><strong>y haga prevalecer una configuración diferente para
    los solamente para los directorios que usted <em>quiera</em> que
    sean accesibles. Consulte la sección <a href="../misc/security_tips.html">Consejos de seguridad</a> para
    obtener más información.</strong></p>

    <p>Las secciones "directory" se usan en el archivo
    <code>httpd.conf</code>.  Las directivas <code class="directive">&lt;Directory&gt;</code> no pueden anidarse, y no
    pueden aparecer en una sección de tipo <code class="directive"><a href="#limit">&lt;Limit&gt;</a></code> o <code class="directive"><a href="#limitexcept">&lt;LimitExcept&gt;</a></code>.</p>

<h3>Consulte también</h3>
<ul>
<li><a href="../sections.html">Documentación de
    cómo funcionan las secciones &lt;Directory&gt;,
    &lt;Location&gt; y &lt;Files&gt;</a> para obtener más
    información sobre la forma en que se combinan estas secciones
    cuando se recibe una petición</li>
</ul>
</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="DirectoryMatch" id="DirectoryMatch">&lt;DirectoryMatch&gt;</a> <a name="directorymatch" id="directorymatch">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Incluye las directivas que se
aplican a los directorios y subdirectorios del sistema de ficheros que
equivalen a una expresión regular</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>&lt;DirectoryMatch <var>regex</var>&gt;
... &lt;/DirectoryMatch&gt;</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p><code class="directive">&lt;DirectoryMatch&gt;</code> y
    <code>&lt;/DirectoryMatch&gt;</code> se usan para englobar a un
    grupo de directivas que se aplicarán solamente al directorio
    (y los subdirectorios de éste) especificado, al igual que
    <code class="directive"><a href="#directory">&lt;Directory&gt;</a></code>. Sin
    embargo, en ese caso la directiva toma como argumento una
    expresión regular. Por ejemplo:</p>

    <div class="example"><p><code>
      &lt;DirectoryMatch "^/www/.(.+)?[0-9]{3}"&gt;
    </code></p></div>

    <p>equivaldrá a los directorios en <code>/www/</code> cuyo nombre
    consista en tres números.</p>

<h3>Consulte también</h3>
<ul>
<li><code class="directive"><a href="#directory">&lt;Directory&gt;</a></code>
si quiere una descripción completa de cómo se usan
conjuntamente las expresiones regulares con la directiva <code class="directive">&lt;Directory&gt;</code></li>
<li><a href="../sections.html">Modo de funcionamiento de las secciones
&lt;Directory&gt;, &lt;Location&gt; y &lt;Files&gt;</a> para obtener
más información sobre como se combinan estas secciones
cuando se recibe una petición</li>
</ul>
</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="DocumentRoot" id="DocumentRoot">DocumentRoot</a> <a name="documentroot" id="documentroot">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Directorio principal que contiene la estructura de
directorios visible desde la web</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>DocumentRoot <var>directory-path</var></code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>DocumentRoot /usr/local/apache/htdocs</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>Esta directiva especifica el directorio desde el cuál
    <code class="program"><a href="../programs/httpd.html">httpd</a></code> servirá los ficheros. A menos que
    especifique alguna otra equivalencia mediante una directiva
    <code class="directive"><a href="../mod/mod_alias.html#alias">Alias</a></code>, el servidor
    añade la ruta de la URL solicitada a este directorio para
    construir la ruta del documento a servir. Ejemplo:</p>

    <div class="example"><p><code>
      DocumentRoot /usr/web
    </code></p></div>

    <p>esto quiere decir que una petición de acceso a
    <code>http://www.my.host.com/index.html</code> se refiere a
    <code>/usr/web/index.html</code> en el sistema de ficheros.</p>

    <p>El directorio que especifique en
    <code class="directive">DocumentRoot</code> debe escribirlo sin barra al
    final.</p>

<h3>Consulte también</h3>
<ul>
<li><a href="../urlmapping.html">Cómo traducir URLs a
ubicaciones del sistema de ficheros</a></li>
</ul>
</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="EnableMMAP" id="EnableMMAP">EnableMMAP</a> <a name="enablemmap" id="enablemmap">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Permite el uso de mapeo de memoria para leer archivos mientras se
sirven</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>EnableMMAP On|Off</code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>EnableMMAP On</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host, directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Prevalece sobre:</a></th><td>FileInfo</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>Esta directiva controla si <code class="program"><a href="../programs/httpd.html">httpd</a></code> puede usar
    mapeo de memoria en caso de ser necesario para leer los contenidos
    de un archivo al servirlo.  Por defecto, cuando el tratamiento de
    una petición requiere acceder a los datos dentro de un
    fichero -- por ejemplo, cuando se sirve un fichero analizado
    sintácticamente por el servidor con el módulo
    <code class="module"><a href="../mod/mod_include.html">mod_include</a></code> -- Apache mapea en memoria el archivo
    si el sistema operativo soporta esa operación.</p>

    <p>El mapeo de memoria supone a veces una mejora en el
    rendimiento. Sin embargo, en ciertos entornos, es mejor desactivar
    el mapeo de memoria para evitar problemas operacionales:</p>

    <ul>
    <li>En algunos sistemas con más de un procesador, el mapeo de
    memoria puede reducir el rendimiento de
    <code class="program"><a href="../programs/httpd.html">httpd</a></code>.</li> <li>Con un <code class="directive"><a href="#documentroot">DocumentRoot</a></code> montado en NFS,
    <code class="program"><a href="../programs/httpd.html">httpd</a></code> podría abortar su ejecución
    debido a un fallo de segmentación si el fichero se borra o se
    trunca mientras que <code class="program"><a href="../programs/httpd.html">httpd</a></code> lo tiene mapeado en
    memoria.</li>
    </ul>

    <p>Para configuraciones del servidor que son sensibles a estos
    problemas, debe desactivar el uso del mapeo en memoria
    especificando:</p>

    <div class="example"><p><code>
      EnableMMAP Off
    </code></p></div>

    <p>Para ficheros montados en NFS, puede desactivar esta
    funcionalidad explícitamente para los archivos implicados
    especificando:</p>

    <div class="example"><p><code>
      &lt;Directory "/path-to-nfs-files"&gt;
      <span class="indent">
        EnableMMAP Off
      </span>
      &lt;/Directory&gt;
    </code></p></div>

</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="EnableSendfile" id="EnableSendfile">EnableSendfile</a> <a name="enablesendfile" id="enablesendfile">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Permite el uso del soporte de sendfile del kernel para servir ficheros @@@@@ Use the kernel sendfile support to deliver files to the client @@@@@ </td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>EnableSendfile On|Off</code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>EnableSendfile On</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host, directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Prevalece sobre:</a></th><td>FileInfo</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
<tr><th><a href="directive-dict.html#Compatibility">Compatibilidad:</a></th><td>Disponible en las versiones de Apache 2.0.44 y
posteriores</td></tr>
</table>
    <p>Esta directiva controla si <code class="program"><a href="../programs/httpd.html">httpd</a></code> puede usar
    el soporte de sendfile del kernel para transmitir contenidos de
    ficheros al cliente.  Por defecto, cuando se está procesando
    una petición que no requiere acceso a los datos de un fichero
    -- por ejemplo, cuando se sirve un fichero estático -- Apache
    usa sendfile para servir los contenidos del fichero directamente a
    la red, sin leer el fichero si el sistema operativo lo
    permite.</p>

    <p>El mecanismo sendfile evita operaciones separadas de lectura y
    envío, y reservas de buffer. Sin embargo, en algunas
    plataformas o en algunos sistemas de ficheros, es mejor desactivar
    esa funcionalidad para evitar problemas operacionales:</p>

    <ul>
    <li>En algunas plataformas puede que el soporte de sendfile no
    funcione porque al compilar Apache no se detectó
    correctamente, especialmente si los binarios fueron construidos en
    una máquina y después se han trasladado a otra cuando el
    soporte para sendfile ya no funcionaba.</li>

    <li>En Linux, el uso de send file provoca fallos de
    comprobación de TCP_checksum en ciertas tarjetas de red que
    usan IPv6</li> 

    <li>Si <code class="directive"><a href="#documentroot">DocumentRoot</a></code> está
    montado en red (por ejemplo, NFS o SMB), el kernel puede que no
    sea capaz de servir el fichero de red a través de su
    cache.</li>
    </ul>

    <p>Para configuraciones del servidor que son sensibles a estos
    problemas, debe desactivar esta funcionalidad especificando:</p>

    <div class="example"><p><code>
      EnableSendfile Off
    </code></p></div>

    <p>Para archivos montados en NFS o SMB, esta funcionalidad puede
    ser desactivada explícitamente para los ficheros que puedan
    ocasionar problemas mediante:</p>

    <div class="example"><p><code>
      &lt;Directory "/path-to-nfs-files"&gt;
      <span class="indent">
        EnableSendfile Off
      </span>
      &lt;/Directory&gt;
    </code></p></div>

</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="ErrorDocument" id="ErrorDocument">ErrorDocument</a> <a name="errordocument" id="errordocument">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Es lo que el servidor devuelve al cliente si se produce
algún error</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>ErrorDocument <var>error-code</var>
<var>document</var></code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host, directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Prevalece sobre:</a></th><td>FileInfo</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
<tr><th><a href="directive-dict.html#Compatibility">Compatibilidad:</a></th><td>El uso de las comillas
(") en los mensajes de texto es diferente en Apache
2.0</td></tr>
</table>
    <p>En el caso de que aparezca un problema o error, puede
    configurar Apache para hacer una de las siguientes cuatro
    cosas,</p>

    <ol>
      <li>devolver un mensaje de error estándar</li>

      <li>devolver un mensaje de error personalizado</li>

      <li>redireccionar la petición a una <var>ruta-URL</var>
      local</li>

      <li>redireccionar la petición a una <var>URL</var> externa</li>
    </ol>

    <p>La primera opción es la que se usa por defecto, mientras
    que el resto se pueden configurar usando la directiva
    <code class="directive">ErrorDocument</code>, la cual ha de seguirse del
    código de respuesta HTTP y una URL o un mensaje. Apache
    ofrece a veces otra información adicional sobre el problema o
    error.</p>

    <p>Las URLs pueden empezar por una barra (/) para URLs locales, o
    pueden ser una URL completa que el cliente pueda
    resolver. También se puede hacer que el nevagador despliegue
    un mensaje. Ejemplos:</p>

    <div class="example"><p><code>
      ErrorDocument 500 http://foo.example.com/cgi-bin/tester<br />
      ErrorDocument 404 /cgi-bin/bad_urls.pl<br /> 
      ErrorDocument 401 /subscription_info.html<br /> 
      ErrorDocument 403 "Lo sentimos no  podemos permitirle el acceso a esta página hoy"
    </code></p></div>

    <p>Adicionalmente, el valor especial <code>default</code> puede
    ser usado para que Apache use los mensajes literales que trae por
    defecto. Aunque bajo circunstancias normales no es necesario,
    <code>default</code> restaura los mensajes literales de Apache en
    configuraciones que de otra manera heredan una directiva
    <code class="directive">ErrorDocument</code> ya existente.</p>

    <div class="example"><p><code>
      ErrorDocument 404 /cgi-bin/bad_urls.pl<br /><br />
      &lt;Directory /web/docs&gt;<br />
      <span class="indent">
        ErrorDocument 404 default<br />
      </span>
      &lt;/Directory&gt;
    </code></p></div>

    <p>Tenga en cuenta que si usted especifica en
    <code class="directive">ErrorDocument</code> un contenido que apunta a una
    URL remota (por ejemplo, cualquier cosa que empiece por
    <code>http</code>), Apache redireccionará al cliente, incluso
    si al final, el documento al que redirecciona está en el
    mismo servidor. Esto tiene varias implicaciones, la más
    importante es que el cliente no recibirá el código de
    error original, sino que en su lugar recibirá el código
    de estado del redireccionamiento. Esto puede confundir a los
    robots web y otros clientes que tratan de determinar si una URL es
    válida usando el código de estado. Además, si usa
    una URL remota en un <code>ErrorDocument 401</code>, el cliente no
    sabrá pedir contraseñas al usuario porque no
    recibirá el código de estado 401. Por tanto, <strong>si
    usa una directiva <code>ErrorDocument 401</code> entonces
    debe referirse a un documento local.</strong></p>

    <p>Microsoft Internet Explorer (MSIE) ignorará por defecto
    los mensajes de error generados por el servidor cuando sean
    "demasiado pequeños" y los sustituirá por mensajes de
    error propios. El tamaño se considera pequeño según
    el tipo de error de que se trate, pero en general, si su mensaje
    de error es de más de 512 bytes, MSIE mostrará en
    mensaje del error generado por el servidor y no el suyo. Puede
    encontrar más información sobre este asunto en el
    artículo de la Base de Datos de Conocimiento de Microsoft <a href="http://support.microsoft.com/default.aspx?scid=kb;en-us;Q294807">Q294807</a>.</p>

    <p>En las versiones de Apache anteriores a la 2.0, los mensajes se
    indicaban añadiendoles dobles comillas (") al principio que
    no se cerraban al final del mensaje.</p>

<h3>Consulte también</h3>
<ul>
<li><a href="../custom-error.html">Documentación sobre
personalización de respuestas</a></li>
</ul>
</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="ErrorLog" id="ErrorLog">ErrorLog</a> <a name="errorlog" id="errorlog">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Ubicación del fichero en
el que se almacenan los mensajes de error</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code> ErrorLog <var>file-path</var>|syslog[:<var>facility</var>]</code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>ErrorLog logs/error_log (Unix) ErrorLog logs/error.log (Windows y OS/2)</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>La directiva <code class="directive">ErrorLog</code> determina el
    nombre del fichero en el cual el servidor almacenará los
    mensajes de error en caso de que ocurra alguno. Si el
    <var>file-path</var> no es absoluto, entonces se asume que es
    relativo al valor especificado en la directiva <code class="directive"><a href="#serverroot">ServerRoot</a></code>.</p>

    <div class="example"><h3>Ejemplo</h3><p><code>
    ErrorLog /var/log/httpd/error_log
    </code></p></div>

    <p>Si el <var>file-path</var> empieza con un barra vertical (|)
    entonces se asume que es un comando para procesar el registro de
    errores (error_log).</p>

    <div class="example"><h3>Ejemplo</h3><p><code>
    ErrorLog "|/usr/local/bin/httpd_errors"
    </code></p></div>

    <p>Usar <code>syslog</code> en lugar de un nombre de fichero
    permite almanecer los mesajes mediante syslogd(8) si el sistema lo
    soporta. Por defecto se usa la utilidad de syslog
    <code>local7</code>, pero puede cambiar esto usando
    <code>syslog:<var>facility</var></code> donde <var>facility</var>
    es cualquiera de los nombres normalmente documentados en
    syslog(1).</p>

    <div class="example"><h3>Ejemplo</h3><p><code>
    ErrorLog syslog:user
    </code></p></div>

    <p>SEGURIDAD: Consulte la sección <a href="../misc/security_tips.html#serverroot">consejos sobre
    seguridad</a> para obtener más información sobre cómo se
    compromete la seguridad de su sistema si sobre el directorio en
    que se almacenan los ficheros log tiene permisos cualquier usuario
    que no sea únicamente el que arranca el servidor.</p> <div class="warning">

    <h3>Nota</h3> <p>Cuando se especifica una ruta a un fichero
    en una plataforma que no es Unix, hay que tener cuidado de usar
    solo barras (/) aunque el sistema permita barras invertidas
    (\). En general, lo mejor es usar siempre barras / en los ficheros
    de configuración.</p>
    </div>

<h3>Consulte también</h3>
<ul>
<li><code class="directive"><a href="#loglevel">LogLevel</a></code></li>
<li><a href="../logs.html">Archivos Log de Apache</a></li>
</ul>
</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="FileETag" id="FileETag">FileETag</a> <a name="fileetag" id="fileetag">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Atributos de fichero usados para crear la ETAG de la
cabecera de respuesta HTTP</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>FileETag <var>component</var> ...</code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>FileETag INode MTime Size</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host, directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Prevalece sobre:</a></th><td>FileInfo</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>
    La directiva <code class="directive">FileETag</code> configura los
    atributos de fichero que se usan para crear la <code>ETag</code>
    (etiqueta de entidad) del campo cabecera de respuesta cuando el
    documento está basado en un fichero. (El valor de
    <code>ETag</code> se usa en la gestión de cache para ahorrar
    ancho de banda.) En Apache 1.3.22 y en versiones anteriores, el
    valor de <code>ETag</code> se formaba <em>siempre</em> a partir
    del inodo del fichero, su tamaño y la hora y la fecha en que
    se modificó por última vez (mtime). La directiva
    <code class="directive">FileETag</code> permite elegir cuál de esos
    elementos quiere usar -- si es que se quiere usar alguno. Las
    palabras clave reconocidas son:
    </p>

    <dl>
     <dt><strong>INode</strong></dt>
     <dd>Para incluir el número de inodo en el cálculo</dd>
     <dt><strong>MTime</strong></dt>
     <dd>Para incluir en el cálculo la hora y la fecha en que el
     fichero fue modificado por última vez</dd>
     <dt><strong>Size</strong></dt>
     <dd>Para incluir en el cálculo el número de bytes que ocupa el fichero</dd>
     <dt><strong>All</strong></dt>
     <dd>Para incluir en el cálculo todos los campos disponibles. Esto es
     equivalente a:
         <div class="example"><p><code>FileETag INode MTime Size</code></p></div></dd>
     <dt><strong>None</strong></dt>
     <dd>Si el documento está basado en un fichero, ningún campo
     <code>ETag</code> será incluido en la respuesta</dd>
    </dl>

    <p>Las palabras clave <code>INode</code>, <code>MTime</code>, y
    <code>Size</code> pueden ir precedidas por <code>+</code> o
    <code>-</code>, lo cual permite hacer cambios en la configuración
    heredada de un ámbito más amplio. Cualquier palabra clave que
    aparezca sin un prefijo cancela inmediatamente la configuración
    heredada.</p>

    <p>Si la configuración para un directorio incluye
    <code>FileETag INode MTime Size</code>, y la de un subdirectorio
    incluye <code>FileETag -INode</code>, la configuración para
    ese subdirectorio (que será heredada por cualquier
    subdirectorio que no tenga un configuración propia) será
    equivalente a <code>FileETag MTime Size</code>.</p>

</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="Files" id="Files">&lt;Files&gt;</a> <a name="files" id="files">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Contiene directivas que se aplican a los ficheros cuyos
nombres coincidan con los que se especifiquen</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>&lt;Files <var>filename</var>&gt; ... &lt;/Files&gt;</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host, directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Prevalece sobre:</a></th><td>All</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>La directiva <code class="directive">&lt;Files&gt;</code> limita el ámbito de aplicación de las directivas que incluye según el nombre de los ficheros. Es
    comparable a <code class="directive"><a href="#directory">&lt;Directory&gt;</a></code> y <code class="directive"><a href="#location">&lt;Location&gt;</a></code>. Debe cerrarse con <code>&lt;/Files&gt;</code>. Las directivas usadas en
    esta sección se aplicarán a cualquier objeto con un nombre base
    (último componente del nombre de fichero) que coincida con el nombre de fichero especificado. Las
    secciones <code class="directive">&lt;Files&gt;</code> se
    procesan en el orden en que aparecen en el fichero de
    configuración, después de las secciones <code class="directive"><a href="#directory">&lt;Directory&gt;</a></code> y de leer los
    ficheros <code>.htaccess</code>, pero antes de las secciones
    <code class="directive"><a href="#location">&lt;Location&gt;</a></code>. Tenga en cuenta que las directivas <code class="directive">&lt;Files&gt;</code>
    pueden anidarse dentro de las secciones <code class="directive"><a href="#directory">&lt;Directory&gt;</a></code> para restringir la parte del
    sistema de ficheros a la que se aplican.</p>

    <p>El argumento <var>filename</var> puede incluir un nombre de
    fichero, o una cadena de carácteres comodín, donde <code>?</code>
    equivale a cualquier carácter individual, y <code>*</code>
    equivale a cualquier secuencia de caracteres. También pueden
    usarse expresiones regulares extendidas, con la ventaja de que
    tambien se puede usar el carácter <code>~</code>. Por
    ejemplo:</p>

    <div class="example"><p><code>
      &lt;Files ~ "\.(gif|jpe?g|png)$"&gt;
    </code></p></div>

    <p>equivaldría a la mayoría de los formatos gráficos de
    Internet. No obstante, es mejor usar <code class="directive"><a href="#filesmatch">&lt;FilesMatch&gt;</a></code>.</p>

    <p>Tenga en cuenta que a diferencia de las secciones <code class="directive"><a href="#directory">&lt;Directory&gt;</a></code> y <code class="directive"><a href="#location">&lt;Location&gt;</a></code>, las secciones
    <code class="directive">&lt;Files&gt;</code> pueden usarse dentro
    de los ficheros <code>.htaccess</code>. Esto permite a los
    usuarios controlar el acceso a sus propios archivos, a un nivel de
    fichero a fichero.</p>


<h3>Consulte también</h3>
<ul>
<li><a href="../sections.html">Cómo funcionan las secciones
    &lt;Directory&gt;, &lt;Location&gt; and &lt;Files&gt; </a> para
    obtener una información más detallada sobre cómo se combinan estas
    diferentes secciones cuando se recibe una petición
</li>
</ul>
</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="FilesMatch" id="FilesMatch">&lt;FilesMatch&gt;</a> <a name="filesmatch" id="filesmatch">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Contiene las directivas que se aplican a los ficheros
cuyos nombres equivalen a las expresiones regulares que se especifiquen</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>&lt;FilesMatch <var>regex</var>&gt; ... &lt;/FilesMatch&gt;</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host, directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Prevalece sobre:</a></th><td>Todas</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>La directiva <code class="directive">&lt;FilesMatch&gt;</code>
    limita el rango de las directivas incluidas según el nombre de los
    ficheros, como hace la directiva <code class="directive"><a href="#files">&lt;Files&gt;</a></code>. Sin embargo, acepta
    expresiones regulares. Por ejemplo:</p>

    <div class="example"><p><code>
      &lt;FilesMatch "\.(gif|jpe?g|png)$"&gt;
    </code></p></div>

    <p>equivaldría a la mayoría de los formatos gráficos de Internet.</p>

<h3>Consulte también</h3>
<ul>
<li><a href="../sections.html">Cómo funcionan las secciones
    &lt;Directory&gt;, &lt;Location&gt; and &lt;Files&gt;</a> para
    obtener información detallada sobre la forma en que estas
    secciones se combinan cuando se recibe una petición
</li>
</ul>
</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="ForceType" id="ForceType">ForceType</a> <a name="forcetype" id="forcetype">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Hace que todos los ficheros cuyos nombres tengan una equivalencia con con lo que se especifique sean
servidos como contenido del tipo MIME que se establezca</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>ForceType <var>MIME-type</var>|None</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Prevalece sobre:</a></th><td>FileInfo</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
<tr><th><a href="directive-dict.html#Compatibility">Compatibilidad:</a></th><td>Perteneciente al núcleo del servidor a partir de la
versión de Apache 2.0</td></tr>
</table>
    <p>Cuando se usa en un fichero <code>.htaccess</code> o en una
    sección <code class="directive"><a href="#directory">&lt;Directory&gt;</a></code>, <code class="directive"><a href="#location">&lt;Location&gt;</a></code> o <code class="directive"><a href="#files">&lt;Files&gt;</a></code>, esta directiva hace que todos los
    ficheros cuyos nombres guarden una equivalencia con lo
    especificado sean servidos como contenido
    <var>MIME-type</var>. Por ejemplo, si tiene un directorio lleno de
    ficheros GIF, pero no quiere etiquetarlos con <code>.gif</code>,
    puede usar:</p>

    <div class="example"><p><code>
      ForceType image/gif
    </code></p></div>

    <p>Tenga en cuenta que a diferencia de <code class="directive"><a href="#defaulttype">DefaultType</a></code>, esta directiva prevalece sobre
    todas las asociaciones de tipo MIME, incluidas las extensiones de
    nombre de fichero que puedan identificar de qué tipo es un fichero.</p>

    <p>Puede hacer que <code class="directive">ForceType</code> no prevalezca sobre el resto de directivas usando el valor <code>None</code>:</p>

    <div class="example"><p><code>
      # forzar a todos los tipos de fichero a ser tratados como imagen/gif:<br />
      &lt;Location /images&gt;<br />
        <span class="indent">
          ForceType image/gif<br />
        </span>
      &lt;/Location&gt;<br />
      <br />
      # pero permitir la asociación de tipos MIME normal aquí:<br />
      &lt;Location /images/mixed&gt;<br />
      <span class="indent">
        ForceType None<br />
      </span>
      &lt;/Location&gt;
    </code></p></div>

</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="HostnameLookups" id="HostnameLookups">HostnameLookups</a> <a name="hostnamelookups" id="hostnamelookups">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Activa la resolución de
DNS de las direcciones IP de los clientes</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>HostnameLookups On|Off|Double</code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>HostnameLookups Off</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host, directory</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>Esta directiva activa la resolución de DNS de manera que
    los nombres de host puedan ser guardados en los archivos log (y
    pasados a CGIs/SSIs en <code>REMOTE_HOST</code>).  El valor
    <code>Double</code> se refiere a hacer una busqueda de DNSs
    inversa doble. Esto es, después de hacer una busqueda
    inversa, se hace una busqueda normal posteriormente sobre ese
    resultado. Al menos una de las direcciones IP en la búsqueda
    posterior debe equivaler a la dirección IP original. (En
    terminología de "tcpwrappers" se llama
    <code>PARANOID</code>.)</p>

    <p>Independientemente de lo que se especifique, cuando
    <code class="module"><a href="../mod/mod_access.html">mod_access</a></code> se usa para controlar el acceso por
    nombre de host, se hará una consulta inversa doble.  Esto se
    hace por seguridad. Tenga en cuenta que el resultado de una
    busqueda inversa doble no está disponible generalmente a no
    ser que especifique <code>HostnameLookups Double</code>. Por
    ejemplo, si especifica solo <code>HostnameLookups On</code> y se
    hace una petición a un objeto protegido por restricciones de
    nombre de host, independientemente de si la consulta inversa doble
    falla o no, el resultado de la consulta inversa simple se
    pasará a los CGIs en <code>REMOTE_HOST</code>.</p>

    <p>El valor por defecto es <code>Off</code> para ahorrar
    tráfico de red en aquellos sitios web que realmente no
    necesitan hacer búsquedas inversas dobles. También es
    mejor para los usuarios finales porque no tienen que sufrir el
    retardo adicional que introducen las búsquedas.  Los sitios
    web con mucha carga deben usar en esta directiva el valor
    <code>Off</code>, porque las búsquedas de DNSs pueden
    consumir una cantidad de tiempo considerable. La utilidad
    <code class="program"><a href="../programs/logresolve.html">logresolve</a></code>, compilada por defecto en el
    subdirectorio <code>bin</code> de su directorio de
    instalación, puede usarse más tarde para buscar nombres
    de host en direcciones IP que estén en los logs cuando no
    esté en línea.</p>

</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="IdentityCheck" id="IdentityCheck">IdentityCheck</a> <a name="identitycheck" id="identitycheck">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Activa que se registre en los archivos log la entidad RFC1413 del usuario remoto</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>IdentityCheck On|Off</code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>IdentityCheck Off</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host, directory</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>Esta directiva permite el almacenamiento en logs, según se
    especifica en el RFC1413, del nombre de usuario remoto para casda
    conexión cuando la máquina del cliente corra
    "identd" o un programa similar. Esta información se
    registra en el log de acceso.</p>

    <p>La información que se registra con este procedimiento no
    debe ser considerada como fiable excepto para controles
    rudimentarios.</p>

    <p>Tenga en cuenta que esto puede provocar serios problemas de
    retardo en los accesos a su servidor porque para cada
    petición hay que ejecutar una consulta de este tipo. Cuando
    hay firewalls involucrados, cada búsqueda puede probablemente
    fallar y añadir 30 segundos de retardo cada vez que se
    intenta un acceso. De modo que en general, su uso no es muy
    útil en servidores públicos accesibles desde
    Internet.</p>

</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="IfDefine" id="IfDefine">&lt;IfDefine&gt;</a> <a name="ifdefine" id="ifdefine">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Engloba directivas que serán procesadas solo si se
cumple una determinada condición al iniciar el servidor</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>&lt;IfDefine [!]<var>parameter-name</var>&gt; ...
    &lt;/IfDefine&gt;</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host, directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Prevalece sobre:</a></th><td>All</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>La sección <code>&lt;IfDefine
    <var>test</var>&gt;...&lt;/IfDefine&gt; </code> se usa para marcar
    directivas que son condicionales. Las directivas que hay dentro de
    una sección <code class="directive">&lt;IfDefine&gt;</code> se
    procesan solo si <var>test</var> devuelve un resultado
    positivo. Si el <var> test</var> produce un resultado negativo,
    todo lo que haya entre los marcadores de comienzo y final
    será ignorado.</p>

    <p>El <var>test</var> en la sección de directivas <code class="directive">&lt;IfDefine&gt;</code> puede tomar una de las
    siguientes dos formas:</p>

    <ul>
      <li><var>parameter-name</var></li>

      <li><code>!</code><var>parameter-name</var></li>
    </ul>

    <p>En el primer caso, las directivas entre los marcadores de
    comienzo y final se procesan solo si el parámetro llamado
    <var>parameter-name</var> está definido. El segundo formato
    hace lo contrario, y procesa las directivas solo si
    <var>parameter-name</var> <strong>no</strong> está
    definido.</p>

    <p>El argumento <var>parameter-name</var> se define cuando se
    ejecuta <code class="program"><a href="../programs/httpd.html">httpd</a></code> por la línea de comandos con la opción
    <code>-D<var>parameter</var></code>, al iniciar el servidor.</p>

    <p>Las secciones <code class="directive">&lt;IfDefine&gt;</code>
    son anidables, lo cual puede usarse para implementar tests
    simples con varios parámetros. Ejemplo:</p>

    <div class="example"><p><code>
      httpd -DReverseProxy ...<br />
      <br />
      # httpd.conf<br />
      &lt;IfDefine ReverseProxy&gt;<br />
      <span class="indent">
        LoadModule rewrite_module modules/mod_rewrite.so<br />
        LoadModule proxy_module   modules/libproxy.so<br />
      </span>
      &lt;/IfDefine&gt;
    </code></p></div>

</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="IfModule" id="IfModule">&lt;IfModule&gt;</a> <a name="ifmodule" id="ifmodule">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Engloba directivas que se procesan de forma condicional
según esté presente o ausente un módulo específico</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>&lt;IfModule [!]<var>module-name</var>&gt; ...
    &lt;/IfModule&gt;</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host, directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Prevalece sobre:</a></th><td>Todas</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>La sección <code>&lt;IfModule
    <var>test</var>&gt;...&lt;/IfModule&gt;</code> se usa para marcar
    las directivas que se aplican si está presente un módulo
    específico. Las directivas dentro de una sección <code class="directive">&lt;IfModule&gt;</code> solo se procesan si el
    <var>test</var> produce un resultado positivo. Si el <var>test</var> da falso, todo
    lo que haya entre los marcadores de inicio y final es
    ignorado.</p>

    <p>El <var>test</var> de las secciones <code class="directive">&lt;IfModule&gt;</code> puede tomar una de las siguientes
    formas:</p>

    <ul>
      <li><var>module name</var></li>

      <li>!<var>module name</var></li>
    </ul>

    <p>En el primer caso, las directivas entre los marcadores de
    comienzo y final son procesados solo si el módulo llamado
    <var>module name</var> está incluido en Apache -- ya sea
    porque está compilado en el servidor o porque esté
    cargado dinámicamente usando <code class="directive"><a href="../mod/mod_so.html#loadmodule">LoadModule</a></code>. El segundo formato hace lo contrario, y
    solo se procesan las directivas si el módulo <var>module
    name</var> <strong>no</strong> está incluido.</p>

    <p>El argumento <var>module name</var> es  el nombre del fichero del
    módulo en el momento en que fue compilado. Por ejemplo,
    <code>mod_rewrite.c</code>.  Si un módulo consiste en varios
    archivos fuente, use el nombre del fichero que contenga la cadena
    de caracteres <code>STANDARD20_MODULE_STUFF</code>.</p>

    <p>Las secciones <code class="directive">&lt;IfModule&gt;</code>
    son anidables, lo cual puede usarse para implementar tests simples
    con varios módulos.</p>

    <div class="note">Esta sección debe usarse solo si necesita tener un
    fichero de configuración que funcione tanto si está como
    si no está un determinado módulo disponible. En
    condiciones normales, no es necesario usar directivas en
    secciones <code class="directive">&lt;IfModule&gt;</code>.</div>

</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="Include" id="Include">Include</a> <a name="include" id="include">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Incluye otros ficheros de configuración dentro de
los ficheros de configuración del servidor</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>Include <var>file-path</var>|<var>directory-path</var></code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host, directory</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
<tr><th><a href="directive-dict.html#Compatibility">Compatibilidad:</a></th><td>Se pueden usar caracteres comodín para encontrar
equivalencias en las versiones de Apache 2.0.41 y posteriores</td></tr>
</table>
    <p>Esta directiva permite la inclusión de otros ficheros de
    configuración  dentro de los ficheros de configuración del
    servidor.</p>

    <p>Los caracteres comodín de tipo shell (<code>fnmatch()</code>)
    pueden usarse para incluir varios ficheros de una vez por orden
    alfabético. Además, si <code class="directive">Include</code> apunta a un
    directorio, en lugar de a un fichero, Apache leerá todos los
    ficheros en ese directorio y sus subdirectorios. Sin embargo, no se
    recomienda incluir subdirectorios enteros, porque es fácil dejar
    accidentalmente ficheros temporales en un directorio y esto
    provocará que <code class="program"><a href="../programs/httpd.html">httpd</a></code> aborte.</p>

    <p>La ruta del fichero especificada puede ser absoluta, o relativa
    a un directorio respecto al valor especificado en <code class="directive"><a href="#serverroot">ServerRoot</a></code>.</p>

    <p>Ejemplos:</p>

    <div class="example"><p><code>
      Include /usr/local/apache2/conf/ssl.conf<br />
      Include /usr/local/apache2/conf/vhosts/*.conf
    </code></p></div>

    <p>O especificando rutas relativas al directorio <code class="directive"><a href="#serverroot">ServerRoot</a></code>:</p>

    <div class="example"><p><code>
      Include conf/ssl.conf<br />
      Include conf/vhosts/*.conf
    </code></p></div>

    <p>Si ejecuta <code>apachectl configtest</code> le aparecerá
    una lista con los ficheros que están siendo procesados
    durante la comprobación de la configuración:</p>

    <div class="example"><p><code>
      root@host# apachectl configtest<br />
      Processing config file: /usr/local/apache2/conf/ssl.conf<br />
      Processing config file: /usr/local/apache2/conf/vhosts/vhost1.conf<br />
      Processing config file: /usr/local/apache2/conf/vhosts/vhost2.conf<br />
      Syntax OK
    </code></p></div>

<h3>Consulte también</h3>
<ul>
<li><code class="program"><a href="../programs/apachectl.html">apachectl</a></code></li>
</ul>
</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="KeepAlive" id="KeepAlive">KeepAlive</a> <a name="keepalive" id="keepalive">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Permite que se establezcan conexiones HTTP
persistentes</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>KeepAlive On|Off</code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>KeepAlive On</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>La extensión Keep-Alive de HTTP/1.0 y la funcionalidad de
    conexión persistente de HTTP/1.1 facilitan la posibilidad de
    que se establezcan sesiones HTTP de larga duración que
    permiten que se puedan enviar múltiples peticiones sobre la
    misma conexión TCP. En algunos casos, esto tiene como
    resultado una reducción de casi el 50% en los tiempos de
    retardo en el caso de documentos con muchas imágenes. Para
    activar las conexiones Keep-Alive, especifique <code>KeepAlive
    On</code>.</p>

    <p>Para clientes HTTP/1.0, las conexiones Keep-Alive se
    usarán solo si el cliente lo solicita
    específicamente. Además, una conexión Keep-Alive
    con un cliente HTTP/1.0 puede usarse solo cuando el tamaño
    del contenido es conocido con antelación. Esto implica que el
    contenido dinámico, como puede ser el resultado de un CGI,
    páginas SSI y listados de directorios generados por el
    servidor, no usarán por lo general conexiones Keep-Alive para
    clientes HTTP/1.0.  Para clientes HTTP/1.1, las conexiones
    persistentes son las que se usan por defecto a no ser que se
    especifique lo contrario. Si el cliente lo solicita, se usará
    @@@@@ chunked encoding @@@@@ para enviar contenido de tamaño
    desconocido sobre conexiones persistentes.</p>

<h3>Consulte también</h3>
<ul>
<li><code class="directive"><a href="#maxkeepaliverequests">MaxKeepAliveRequests</a></code></li>
</ul>
</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="KeepAliveTimeout" id="KeepAliveTimeout">KeepAliveTimeout</a> <a name="keepalivetimeout" id="keepalivetimeout">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Tiempo que el servidor esperará peticiones subsiguientes
en conexiones persistentes</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>KeepAliveTimeout <var>seconds</var></code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>KeepAliveTimeout 15</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>Es el tiempo en segundos que Apache esperará peticiones
    subsiguientes antes de cerrar una conexión persistente. Una
    vez que una petición ha sido recibida, se aplica el valor
    especificado en la directiva <code class="directive"><a href="#timeout">Timeout</a></code> para cerrar la
    conexión.</p>

    <p>Espeficificar un valor alto para
    <code class="directive">KeepAliveTimeout</code> puede provocar un menor
    rendimiento en servidores con mucha carga. Cuanto mayor sea el
    valor de timeout, mayor será el número de procesos del
    servidor se mantendrán ocupados esperando en conexiones con
    clientes no activos.</p>

</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="Limit" id="Limit">&lt;Limit&gt;</a> <a name="limit" id="limit">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Restringe la aplicación de los controles de acceso incluidos a solo ciertos métodos HTTP</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>&lt;Limit <var>method</var> [<var>method</var>] ... &gt; ...
    &lt;/Limit&gt;</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host, directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Prevalece sobre:</a></th><td>Todas</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>Los controles de acceso se aplican normalmente a
    <strong>todos</strong> los métodos de acceso, y este es el
    comportamiento que se busca casi siempre. <strong>En general, las
    directivas de control de acceso no deben estar dentro de una
    sección <code class="directive">&lt;Limit&gt;</code>.</strong></p>

    <p>El propósito <code class="directive">&lt;Limit&gt;</code>
    es restringir el efecto de los controles de acceso a los
    métodos HTTP que se especifiquen. Para los demás
    métodos, las restricciones de acceso que estén incluidas
    en <code class="directive">&lt;Limit&gt;</code> <strong>no
    tendrán efecto</strong>. Los siguientes ejemplos aplican el
    control de acceso solo a los métodos <code>POST</code>,
    <code>PUT</code>, y <code>DELETE</code>, no afectando al resto de
    métodos:</p>

    <div class="example"><p><code>
      &lt;Limit POST PUT DELETE&gt;<br />
      <span class="indent">
        Require valid-user<br />
      </span>
      &lt;/Limit&gt;
    </code></p></div>

    <p>Los métodos incluidos en la lista pueden ser uno o
    más de los siguientes: <code>GET</code>,
    <code>POST</code>, <code>PUT</code>, <code>DELETE</code>,
    <code>CONNECT</code>, <code>OPTIONS</code>, <code>PATCH</code>,
    <code>PROPFIND</code>, <code>PROPPATCH</code>, <code>MKCOL</code>,
    <code>COPY</code>, <code>MOVE</code>, <code>LOCK</code>, y
    <code>UNLOCK</code>. <strong>Los nombres de los métodos
    distinguen mayúsculas de minúsculas.</strong> Si usa
    <code>GET</code> también se restringirán las peticiones
    <code>HEAD</code>. El método <code>TRACE</code> no puede
    limitarse.</p>

    <div class="warning">Es mejor usar una sección <code class="directive"><a href="#limitexcept">&lt;LimitExcept&gt;</a></code> en lugar de
    una sección <code class="directive"><a href="#limit">&lt;Limit&gt;</a></code> cuando se quiere restringir el
    acceso, porque una sección <code class="directive"><a href="#limitexcept">&lt;LimitExcept&gt;</a></code> protege contra métodos
    arbitrarios.</div>


</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="LimitExcept" id="LimitExcept">&lt;LimitExcept&gt;</a> <a name="limitexcept" id="limitexcept">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Restringe los controles de acceso a todos los métodos
HTTP excepto a los que se especifiquen</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>&lt;LimitExcept <var>method</var> [<var>method</var>] ... &gt;
    ...  &lt;/LimitExcept&gt;</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host, directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Prevalece sobre:</a></th><td>Todas</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p><code class="directive">&lt;LimitExcept&gt;</code> y
    <code>&lt;/LimitExcept&gt;</code> se usan para englobar un grupo
    de directivas de control de acceso que se aplicarán a
    cualquier método de acceso HTTP <strong>no</strong>
    especificado en los argumentos; es lo contrario a lo
    que hace una sección <code class="directive"><a href="#limit">&lt;Limit&gt;</a></code> y puede usarse para controlar
    tanto métodos estándar como no estándar o
    métodos no reconocidos. Consulte la documentación de
    <code class="directive"><a href="#limit">&lt;Limit&gt;</a></code> para
    más detalles.</p>

    <p>Por ejemplo:</p>

    <div class="example"><p><code>
      &lt;LimitExcept POST GET&gt;<br />
      <span class="indent">
        Require valid-user<br />
      </span>
      &lt;/LimitExcept&gt;
    </code></p></div>


</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="LimitInternalRecursion" id="LimitInternalRecursion">LimitInternalRecursion</a> <a name="limitinternalrecursion" id="limitinternalrecursion">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Determina el número máximo de redirecciones internas y
subpeticiones anidadas</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>LimitInternalRecursion <var>number</var> [<var>number</var>]</code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>LimitInternalRecursion 10</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
<tr><th><a href="directive-dict.html#Compatibility">Compatibilidad:</a></th><td>Disponible en las versiones Apache 2.0.47 y posteriores</td></tr>
</table>
    <p>Una redirección interna ocurre, por ejemplo, cuando se usa
    la directiva <code class="directive"><a href="../mod/mod_actions.html#action">Action</a></code>,
    la cual internamente redirige la petición original a un
    script CGI. Una subpetición es un mecanismo de Apache para
    saber qué ocurriría si se produjera una petición a
    una URI.  Por ejemplo, <code class="module"><a href="../mod/mod_dir.html">mod_dir</a></code> usa subpeticiones
    para buscar archivos especificados en la directiva <code class="directive"><a href="../mod/mod_dir.html#directoryindex">DirectoryIndex</a></code>.</p>

    <p><code class="directive">LimitInternalRecursion</code> hace que el
    servidor no sufra un error irrecuperable cuando entra en un ciclo
    infinito de redirecciones internas o subpeticiones. Tales ciclos
    se producen normalmente por errores de configuración.</p>

    <p>La directiva guarda dos límites diferentes, los cuales se
    evalúan en para cada petición. El primer
    <var>número</var> es el número máximo de
    redirecciones internas, que pueden producirse una detrás de
    otra. El segundo <var>número</var> determina, la profundidad
    a la que subpeticiones pueden anidarse. Si especifica solo un
    <var>número</var>, se asignará a ambos límites.</p>

    <div class="example"><h3>Ejemplo</h3><p><code>
      LimitInternalRecursion 5
    </code></p></div>

</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="LimitRequestBody" id="LimitRequestBody">LimitRequestBody</a> <a name="limitrequestbody" id="limitrequestbody">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Restringe el tamaño total del cuerpo de las peticiones
HTTP enviadas desde el cliente</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>LimitRequestBody <var>bytes</var></code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>LimitRequestBody 0</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host, directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Prevalece sobre:</a></th><td>Todas</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>Esta directiva especifica el número de <var>bytes</var>
    desde 0 (que significa sin límite) hasta 2147483647 (2GB) que
    se permite que tenga el cuerpo de una petición.</p>

    <p>La directiva <code class="directive">LimitRequestBody</code> permite al
    usuario especificar un límite al tamaño del cuerpo del
    mensaje de las peticiones dentro del contexto en el que la
    directiva aparece (server, per-directory, per-file o
    per-location). Si la petición del cliente excede ese
    límite, el servidor devolverá una respuesta de error en
    lugar de servir la petición. El tamaño del cuerpo del
    mensaje de una petición normal varía mucho en
    función de la naturaleza del recurso y los métodos
    permitidos para ese recurso. Los scripts CGI usan normamente el
    cuerpo del mensaje para acceder la información de formularios
    HTML.  Las implementaciones del método <code>PUT</code>
    requerirán un valor al menos del mismo tamaño que
    cualquier representación que el servidor desee aceptar para
    ese recurso.</p>

    <p>Esta directiva le da al administrador del servidor un mayor
    control sobre el comportamiento anormal de peticiones de clientes,
    lo cual puede ser útil para evitar algunos tipos de ataques de
    denegación de servicio.</p>

    <p>Si, por ejemplo, permite que se suban archivos a una ubicación
    en concreto, y quiere limitar el tamaño de los ficheros que se
    suban a 100K, puede usar la siguiente directiva:</p>

    <div class="example"><p><code>
      LimitRequestBody 102400
    </code></p></div>


</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="LimitRequestFields" id="LimitRequestFields">LimitRequestFields</a> <a name="limitrequestfields" id="limitrequestfields">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Limita el número de campos de la cabecera de las
peticiones HTTP del cliente que serán aceptadas</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>LimitRequestFields <var>number</var></code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>LimitRequestFields 100</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p><var>Number</var> es un entero entre 0 (sin límite) hasta
    32767. El valor por defecto se define por la constante
    <code>DEFAULT_LIMIT_REQUEST_FIELDS</code> al compilar (y es de 100
    campos para la cabecera).</p>

    <p>La directiva <code class="directive">LimitRequestFields</code> permite
    al administrador del servidor modificar el límite del
    número de campos de la cabecera permitidos en una
    petición HTTP. Este valor tiene que ser mayor que el
    número de campos que tiene la cabecera de una petición
    normal de un cliente. El número de campos de la cabecera de
    una petición usados por un cliente raramente pasa de 20, pero
    esto puede variar según las diferentes implementaciones, a
    menudo dependiendo incluso de la configuración que un usuario
    haya hecho de su navegador para soportar negociación de
    contenidos detallada. Las extensiones opcionales de HTTP se
    expresan muchas veces usando campos de cabecera de
    petición.</p>

    <p>Esta directiva le da al administrador del servidor un mayor
    control sobre el comportamiento anormal de peticiones de clientes,
    lo cual puede ser útil para evitar algunos tipos de ataques
    de denegación de servicio. Debe incrementar el valor que se
    especifica en esta directiva si a los clientes normales les llegan
    mensajes de error que indican que se han enviado demasiados campos
    de cabecera en la petición.</p>

    <p>Por ejemplo:</p>

    <div class="example"><p><code>
      LimitRequestFields 50
    </code></p></div>


</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="LimitRequestFieldSize" id="LimitRequestFieldSize">LimitRequestFieldSize</a> <a name="limitrequestfieldsize" id="limitrequestfieldsize">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Limita el tamaño permitido de las cabeceras de las peticiones HTTP de los clientes</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>LimitRequestFieldsize <var>bytes</var></code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>LimitRequestFieldsize 8190</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>Esta directiva especifica el número de <var>bytes</var>
    desde 0 hasta el valor de la constante definida al compilar
    <code>DEFAULT_LIMIT_REQUEST_FIELDSIZE</code> (8190 por defecto)
    que será permitido para una cabecera de las peticiones
    HTTP.</p>

    <p>La directiva <code class="directive">LimitRequestFieldSize</code>
    permite al administrador del servidor reducir el límite del
    tamaño permitido de una cabecera de las peticiones HTTP por
    debajo del tamaño del buffer de entrada compilado en el
    servidor. Este valor tiene que ser lo suficientemente grande para
    que no quede por debajo del tamaño normal de una cabecera de
    petición de un cliente. El tamaño de una cabecera de una
    petición varía mucho en función de la
    implementación del cliente, a menudo depende incluso de la
    configuración del navegador que haya hecho el usuario para
    soportar negociación de contenido detallada.</p>

    <p>Esta directiva le da al administrador del servidor un mayor
    control sobre el comportamiento anormal de peticiones de clientes,
    lo cual puede ser útil para evitar algunos tipos de ataques de
    denegación de servicio.</p>

    <p>Por ejemplo:</p>

    <div class="example"><p><code>
      LimitRequestFieldSize 4094
    </code></p></div>

    <div class="note">En condiciones normales, no debe modificarse el valor que
    viene por defecto.</div>


</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="LimitRequestLine" id="LimitRequestLine">LimitRequestLine</a> <a name="limitrequestline" id="limitrequestline">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Limita el tamaño la línea de petición HTTP que será
aceptada</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>LimitRequestLine <var>bytes</var></code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>LimitRequestLine 8190</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>Esta directiva especifica el número de <var>bytes</var> de
    0 hasta el valor de la constante definida al compilar
    <code>DEFAULT_LIMIT_REQUEST_LINE</code> ( @@@@ 8190 as distributed @@@@ ) que
    se permitirá para la línea de petición HTTP.</p>

    <p>La directiva <code class="directive">LimitRequestLine</code> permite al
    administrador del servidor reducir el límite de tamaño
    permitido de la línea de petición de las peticiones HTTP
    de los clientes por debajo del tamaño del buffer de entrada
    compilado con el servidor. Como la línea de petición
    consiste en el método HTTP, la URI y la versión del
    protocolo, la directiva <code class="directive">LimitRequestLine</code>
    impone una restricción en la longitud de la URI de la
    petición permitida por el servidor. Este valor tiene que ser
    lo suficientemente grande como para que admita el tamaño de
    sus nombres de recurso, incluida la información que puede
    ser pasada como parte de consulta de una petición
    <code>GET</code>.</p>

    <p>Esta directiva le da al administrador del servidor un mayor
    control sobre el comportamiento anormal de peticiones de clientes,
    lo cual puede ser útil para evitar algunos tipos de ataques de
    denegación de servicio.</p>

    <p>Por ejemplo:</p>

    <div class="example"><p><code>
      LimitRequestLine 4094
    </code></p></div>

    <div class="note">En condiciones normales, no debe modificarse el valor que
    viene por defecto.</div>

</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="LimitXMLRequestBody" id="LimitXMLRequestBody">LimitXMLRequestBody</a> <a name="limitxmlrequestbody" id="limitxmlrequestbody">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Limita el tamaño del cuerpo de una petición XML</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>LimitXMLRequestBody <var>bytes</var></code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>LimitXMLRequestBody 1000000</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host, directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Prevalece sobre:</a></th><td>All</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>Límite (en bytes) o tamaño máximo del cuerpo de una petición
    basada en XML. Si se especifica el valor <code>0</code> se
    desactiva este control.</p>

    <p>Ejemplo:</p>

    <div class="example"><p><code>
      LimitXMLRequestBody 0
    </code></p></div>


</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="Location" id="Location">&lt;Location&gt;</a> <a name="location" id="location">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Aplica las directivas que contiene solo a las URLs que tengan una equivalencia con los valores que se especifiquen</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>&lt;Location
    <var>URL-path</var>|<var>URL</var>&gt; ... &lt;/Location&gt;</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>Una sección <code class="directive">&lt;Location&gt;</code>
    aplica las directivas que contiene según la URL de que se
    trate. Es parecida a la directiva <code class="directive"><a href="#directory">&lt;Directory&gt;</a></code>, y tiene que terminar con una
    directiva <code>&lt;/Location&gt;</code>. Las secciones <code class="directive">&lt;Location&gt;</code> se procesan en el orden en que
    aparecen en el fichero de configuración, después de leer
    las secciones <code class="directive"><a href="#directory">&lt;Directory&gt;</a></code> y los ficheros
    <code>.htaccess</code>, y después de las secciones <code class="directive"><a href="#files">&lt;Files&gt;</a></code>.</p>

    <p>Las secciones <code class="directive">&lt;Location&gt;</code>
    operan completamente fuera del sistema de ficheros.  Esto tiene
    varias consecuencias. La más importante, es que las
    directivas <code class="directive">&lt;Location&gt;</code> no deben
    usarse para controlar el acceso a ubicaciones del sistema de
    ficheros. Como diferentes URLs pueden corresponderse con una misma
    ubicación de un sistema de ficheros, tales controles de
    acceso pueden ser burlados.</p>

    <div class="note"><h3>Cuándo usar <code class="directive">&lt;Location&gt;</code></h3>

    <p>Use <code class="directive">&lt;Location&gt;</code> para aplicar
    las directivas que va a incluir a contenido que está fuera
    del sistema de ficheros.  Para el contenido que esté en el
    sistema de ficheros, use <code class="directive"><a href="#directory">&lt;Directory&gt;</a></code> y <code class="directive"><a href="#files">&lt;Files&gt;</a></code>.  Una excepción a esto es el
    uso de <code>&lt;Location /&gt;</code>, que es un modo fácil
    de aplicar una configuración a un servidor entero.</p>
    </div>

    <p>Para todas las peticiones que no provengan de servidores proxy,
    la URL de la que se buscan equivalencias es una ruta URL de la
    forma <code>/path/</code>.  Ningún esquema, nombre de host,
    puerto o cadena de consulta puede incluirse.  Para peticiones
    provenientes de servidores proxy, la URL de la que se buscan
    euivalencias es de la forma <code>scheme://servername/path</code>,
    y debe incluir el prefijo.</p>

    <p>La URL puede usar caracteres comodín. En una cadena de
    caracteres comodín, <code>?</code> equivale a cualquier
    carácter, y <code>*</code> equivale a cualquier secuencia de
    caracteres.</p>

    <p>También pueden usarse expresiones regulares extendidas,
    con el carácter adicional <code>~</code>. Por ejemplo:</p>

    <div class="example"><p><code>
      &lt;Location ~ "/(extra|special)/data"&gt;
    </code></p></div>

    <p>equivaldrá a las URLs que contengan la subcadena
    <code>/extra/data</code> o <code>/special/data</code>. La
    directiva <code class="directive"><a href="#locationmatch">&lt;LocationMatch&gt;</a></code> se comporta de igual modo
    que la versión de regex de <code class="directive">&lt;Location&gt;</code>.</p>

    <p>El uso de <code class="directive">&lt;Location&gt;</code> es
    especialmente útil cuando se combina con la directiva
    <code class="directive"><a href="#sethandler">SetHandler</a></code>. Por ejemplo, para
    permitir peticiones de status, pero solo de navegadores que
    intenten acceder a <code>foo.com</code>, puede usar:</p>

    <div class="example"><p><code>
      &lt;Location /status&gt;<br />
      <span class="indent">
        SetHandler server-status<br />
        Order Deny,Allow<br />
        Deny from all<br />
        Allow from .foo.com<br />
      </span>
      &lt;/Location&gt;
    </code></p></div>

    <div class="note"><h3>Comentarios sobre la barra : /</h3> <p>El
      carácter de la barra tiene un significado especial
      dependiendo del lugar donde aparece en una URL. Los usuarios
      puede estar no estar acostumbrada a que la barra tenga distintos
      significados, por ejemplo, en los sistemas de ficheros, varias
      barras consecutivas tienen el mismo significado que una sola
      barra (por ejemplo, <code>/home///foo</code> es lo mismo que
      <code>/home/foo</code>). Para las URL's esto no se cumple.  La
      directiva <code class="directive"><a href="#locationmatch">&lt;LocationMatch&gt;</a></code> y la versión de
      regex de <code class="directive">&lt;Location&gt;</code>
      requieren que se especifiquen explícitamente múltiples
      barras solo si esa es su intención.</p>

      <p>Por ejemplo, <code>&lt;LocationMatch ^/abc&gt;</code>
      podría equivaler a la petición de la URL
      <code>/abc</code> pero no a la petición de la URL <code>
      //abc</code>. La directiva (no regex) <code class="directive">&lt;Location&gt;</code> se comporta de manera similar cuando se
      usa para peticiones provenientes de servidores proxy. Sin
      embargo, cuando la directiva (no regex) <code class="directive">&lt;Location&gt;</code> se usa para peticiones no
      provenientes de servidores proxy, a efectos de encontrar
      equivalencias, múltiples barras equivaldrán a una
      sola. Por ejemplo, si especifica <code>&lt;Location
      /abc/def&gt;</code> y la petición es a
      <code>/abc//def</code> se producirá equivalencia.</p>
    </div>

<h3>Consulte también</h3>
<ul>
<li><a href="../sections.html">Cómo funcionan las secciones
    &lt;Directory&gt;, &lt;Location&gt; y &lt;Files&gt; </a> si quiere
    obtener una información detallada sobre cómo se combinan
    esas secciones cuando se recibe una petición</li>
</ul>
</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="LocationMatch" id="LocationMatch">&lt;LocationMatch&gt;</a> <a name="locationmatch" id="locationmatch">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Aplica las directiva que incluye solo a las URLs que tengan equivalencia con alguna de las expresiones regulares que se especifiquen</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>&lt;LocationMatch
    <var>regex</var>&gt; ... &lt;/LocationMatch&gt;</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>La directiva <code class="directive">&lt;LocationMatch&gt;</code> limita la aplicación
    de las directivas que incluye a URLs que tengan equivalencia con
    alguna de las expresiones regulares que se especifican, de manera
    idéntica a como lo hace <code class="directive"><a href="#location">&lt;Location&gt;</a></code>. Sin embargo, toma las
    expresiones regulares como argumentos en lugar de como una cadena
    de caracteres. Por ejemplo:</p>

    <div class="example"><p><code>
      &lt;LocationMatch "/(extra|special)/data"&gt;
    </code></p></div>

    <p>equivaldría a las URLs que contengan la subcadena
    <code>/extra/data</code> ó <code>/special/data</code>.</p>

<h3>Consulte también</h3>
<ul>
<li><a href="../sections.html">Cómo funcionan las secciones
    &lt;Directory&gt;, &lt;Location&gt; y &lt;Files&gt; </a> si quiere
    obtener una explicación detallada de cómo se combinan
    esas secciones cuando se recibe una petición</li>
</ul>
</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="LogLevel" id="LogLevel">LogLevel</a> <a name="loglevel" id="loglevel">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Controla la extensión de los mensajes que se almacenan
en el ErrorLog</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>LogLevel <var>level</var></code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>LogLevel warn</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p><code class="directive">LogLevel</code> especifica el nivel al que se
    detallan los errores que se almacenan en los logs de errores
    (consulte la directiva <code class="directive"><a href="#errorlog">ErrorLog</a></code>). Los <var>niveles</var>
    (levels) disponibles son, por orden decreciente:</p>

    <table class="bordered">
    
      <tr>
        <th><strong>Level</strong> </th>

        <th><strong>Description</strong> </th>

        <th><strong>Example</strong> </th>
      </tr>

      <tr>
        <td><code>emerg</code> </td>

        <td>Emergencias - sistema inutilizable.</td>

        <td>"Un proceso hijo no puede abrir el fichero de lock (lock
        file). El programa va a terminar"</td>
      </tr>

      <tr>
        <td><code>alert</code> </td>

        <td>Debe hacer algo inmediatamente.</td>

        <td>"getpwuid: no pudo determinar el nombre de usuario a partir del uid"</td>
      </tr>

      <tr>
        <td><code>crit</code> </td>

        <td>Condiciones críticas.</td>

        <td>"socket: No se encontró un socket adecuado, el proceso hijo va a terminar"</td>
      </tr>

      <tr>
        <td><code>error</code> </td>

        <td>Condiciones de error.</td>

        <td>"Final prematuro de la cabecera del script""</td>
      </tr>

      <tr>
        <td><code>warn</code> </td>

        <td>Condiciones de advertencia.</td>

        <td>"el proceso hijo 1234 no ha terminado, enviando otra vez
        SIGHUP"</td>
      </tr>

      <tr>
        <td><code>notice</code> </td>

        <td>Condición normal, pero significativa.</td>

        <td>"httpd: interceptada señal SIGBUS, intentando hacer
        un volcado de memoria en ..."</td>
      </tr>

      <tr>
        <td><code>info</code> </td>

        <td>Información.</td>

        <td>"El servidor parece estar ocupado, (puede que necesite incrementar
        StartServers, o Min/MaxSpareServers)..."</td>
      </tr>

      <tr>
        <td><code>debug</code> </td>

        <td>Mensajes de nivel debug</td>

        <td>"Abriendo el fichero de configuración ..."</td>
      </tr>
    </table>

    <p>Cuando se especifica un determinado nivel, se escriben en el
    log también los mensajes de todos los demás niveles por
    encima.  Por ejemplo, cuando se especifica <code>LogLevel
    info</code>, también se escribirán en el log los
    mensajes de los niveles <code>notice</code> y
    <code>warn</code>.</p>

    <p>Se recomienda usar, al menos, el nivel <code>crit</code>.</p>

    <p>Por ejemplo:</p>

    <div class="example"><p><code>
      LogLevel notice
    </code></p></div>

    <div class="note"><h3>Nota</h3> <p>Cuando el fichero log es un fichero
      normal y se escriben en el mensajes de nivel
      <code>notice</code>, estos mensajes no podrán ser
      borrados. Sin embargo, esto no se aplica cuando se usa
      <code>syslog</code>.</p>
    </div>

</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="MaxKeepAliveRequests" id="MaxKeepAliveRequests">MaxKeepAliveRequests</a> <a name="maxkeepaliverequests" id="maxkeepaliverequests">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Número de peticiones permitidas en una conexión
persistente</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>MaxKeepAliveRequests <var>number</var></code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>MaxKeepAliveRequests 100</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>La directiva <code class="directive">MaxKeepAliveRequests</code> limita
    el número de peticiones permitidas por conexión cuando
    <code class="directive"><a href="#keepalive">KeepAlive</a></code> está
    activado. Si se especifica el valor <code>0</code>, el número
    de peticiones permitidas es ilimitado. Se recomienda que en esta
    directiva se especifique un valor alto para obtener el máximo
    rendimiento del servidor.</p>

    <p>Por ejemplo:</p>

    <div class="example"><p><code>
      MaxKeepAliveRequests 500
    </code></p></div>

</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="NameVirtualHost" id="NameVirtualHost">NameVirtualHost</a> <a name="namevirtualhost" id="namevirtualhost">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Designa una dirección IP para usar hosting virtual basado en nombres</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>NameVirtualHost <var>addr</var>[:<var>port</var>]</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>Es necesario usar la directiva
    <code class="directive">NameVirtualHost</code> es necesario usarla si
    quiere configurar <a href="../vhosts/">hosts virtuales basados en
    nombres</a>.</p>

    <p>Aunque <var>addr</var> puede ser un nombre de host, se
    recomienda que use siempre una dirección IP, por ejemplo:</p>

    <div class="example"><p><code>
      NameVirtualHost 111.22.33.44
    </code></p></div>

    <p>Con la directiva <code class="directive">NameVirtualHost</code> se
    especifica la dirección IP en la cual el servidor
    recibirá las peticiones para los hosts virtuales basados en
    nombres. Bsta será normalmente la dirección a la cual su
    host virtual basado en nombres se resuelve. En los casos en que en
    las peticiones las recibe un firewall (cortafuegos) o un proxy y
    las redirige a una dirección IP diferente del servidor, debe
    especificar la dirección IP del adaptador de red físico
    de la máquina que servirá las peticiones. Si tiene
    múltiples hosts basados en nombres o múltiples
    direcciones, repita la directiva para cada dirección.</p>

    <div class="note"><h3>Nota</h3>
       <p>Tenga en cuenta, que el "servidor principal" y cualquier
      servidor <code>_default_</code> <strong>nunca</strong>
      servirán una petición a un dirección IP
      <code class="directive">NameVirtualHost</code> (a menos que por alguna
      razón use <code class="directive">NameVirtualHost</code> pero no
      especifique ningún <code class="directive">VirtualHost</code> para
      esa dirección).</p>
    </div>

    <p>De manera opcional puede especificar un número de puerto en
    el que debe usarse el host virtual basado en el nombre, por
    ejemplo</p>

    <div class="example"><p><code>
      NameVirtualHost 111.22.33.44:8080
    </code></p></div>

    <p>Las direcciones IPv6 deben escribirse entre corchetes, como se
    muestra en el siguiente ejemplo:</p>

    <div class="example"><p><code>
      NameVirtualHost [fe80::a00:20ff:fea7:ccea]:8080
    </code></p></div>

    <p>Para recibir peticiones en todas las interfaces de red, puede
    usar <code>*</code> como argumento</p>

    <div class="example"><p><code>
      NameVirtualHost *
    </code></p></div>

    <div class="note"><h3>Argumento de la directiva <code class="directive">&lt;VirtualHost&gt;</code></h3>
      <p>Tenga en cuenta que el argumento de la directiva <code class="directive">&lt;VirtualHost&gt;</code> debe coincidir
       exactamente con el de la directiva <code class="directive">NameVirtualHost</code>.</p>

      <div class="example"><p><code>
        NameVirtualHost 1.2.3.4<br />
        &lt;VirtualHost 1.2.3.4&gt;<br />
        # ...<br />
        &lt;/VirtualHost&gt;<br />
      </code></p></div>
    </div>

<h3>Consulte también</h3>
<ul>
<li><a href="../vhosts/">Documentación sobre hosting
virtual</a></li>
</ul>
</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="Options" id="Options">Options</a> <a name="options" id="options">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Configura las funcionalidades disponibles en un directorio en particular</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>Options
    [+|-]<var>option</var> [[+|-]<var>option</var>] ...</code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>Options All</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host, directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Prevalece sobre:</a></th><td>Options</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>La directiva <code class="directive">Options</code> controla qué
    funcionalidades del servidor están disponibles en un
    directorio en particular.</p>

    <p>En <var>option</var> puede especificar <code>None</code>, en
    cuyo caso ninguna funcionalidad adicional estará activada, o
    puede especificar una o más de las siguientes opciones:</p>

    <dl>
      <dt><code>All</code></dt>

      <dd>Todas las opciones excepto <code>MultiViews</code>. Este es
      el valor por defecto.</dd>

      <dt><code>ExecCGI</code></dt>

      <dd>Se permite la ejecución de scripts CGI usando
      <code class="module"><a href="../mod/mod_cgi.html">mod_cgi</a></code>.</dd>

      <dt><code>FollowSymLinks</code></dt>

      <dd>

      El servidor seguirá los enlaces simbólicos en este
      directorio
      <div class="note">
      <p>Aunque el servidor siga los enlaces simbólicos, eso
      <em>no</em> cambia la ruta usada para encontrar equivalencias en
      las secciones <code class="directive"><a href="#directory">&lt;Directory&gt;</a></code>.</p> <p>Tenga en cuenta
      también que esta opción <strong>es ignorada</strong> si está
      dentro de una sección <code class="directive"><a href="#location">&lt;Location&gt;</a></code>.</p> </div></dd>

      <dt><code>Includes</code></dt>

      <dd>
      Permite el uso de Server-side includes, del módulo <code class="module"><a href="../mod/mod_include.html">mod_include</a></code>.</dd>

      <dt><code>IncludesNOEXEC</code></dt>

      <dd>

      Permite el uso de Server-side includes, pero <code>#exec cmd</code>
      y <code>#exec cgi</code> son desactivados. Aunque es posible
      <code>#include virtual</code> (incluir de forma virtual) scripts
      CGI desde directorios especificados con <code class="directive"><a href="../mod/mod_alias.html#scriptalias">ScriptAlias</a></code>.</dd>

      <dt><code>Indexes</code></dt>

      <dd>
      Si se produce una petición a una URL que se corresponde con un directorio,
      y no hay <code class="directive"><a href="../mod/mod_dir.html#directoryindex">DirectoryIndex</a></code>
      (por ejemplo, <code>index.html</code>) en ese directorio,
      entonces <code class="module"><a href="../mod/mod_autoindex.html">mod_autoindex</a></code> devolverá una lista con
      los contenidos del directorio.</dd>

      <dt><code>MultiViews</code></dt>

      <dd>
      Se permiten "MultiViews" de <a href="../content-negotiation.html">contenido negociado</a>
      "MultiViews" usando <code class="module"><a href="../mod/mod_negotiation.html">mod_negotiation</a></code>.</dd>

      <dt><code>SymLinksIfOwnerMatch</code></dt>

      <dd>El servidor seguirá los enlaces simbólicos en los que el
      fichero o directorio final pertenezca al mismo usuario que el
      enlace.

      <div class="note"><h3>Nota</h3> Esta opción es ignorada si se pone
      dentro de una sección <code class="directive"><a href="#location">&lt;Location&gt;</a></code>.</div>
      </dd>
    </dl>

    <p>Normalmente, si se pueden aplicar múltiples
    <code class="directive">Options</code> a un directorio, entonces la
    más específica se aplica y las demás se ignoran;
    las opciones no se fusionan. (Consulte <a href="../sections.html#mergin">cómo se fusionan las
    secciones</a>.)  Sin embargo, si <em>todas</em> las opciones en la
    directiva <code class="directive">Options</code> van precedidas de un
    símbolo <code>+</code> o <code>-</code>, las opciones se
    fusionan. Cualquier opción precedida de un <code>+</code> se
    añade a las opciones en ese momento activas, y las opciones
    precedidas de un <code>-</code> se quitan de las activas en ese
    momento. </p>

    <p>Por ejemplo, sin ningún símbolo <code>+</code> o
    <code>-</code>:</p>

    <div class="example"><p><code>
      &lt;Directory /web/docs&gt;<br />
      <span class="indent">
        Options Indexes FollowSymLinks<br />
      </span>
      &lt;/Directory&gt;<br />
      <br />
      &lt;Directory /web/docs/spec&gt;<br />
      <span class="indent">
        Options Includes<br />
      </span>
      &lt;/Directory&gt;
    </code></p></div>

    <p>entoces solo <code>Includes</code> tendrá efecto para el
    directorio <code>/web/docs/spec</code>. Sin embargo, si la segunda
    directiva <code class="directive">Options</code> usara un símbolo
    <code>+</code> y otro <code>-</code>:</p>

    <div class="example"><p><code>
      &lt;Directory /web/docs&gt;<br />
      <span class="indent">
        Options Indexes FollowSymLinks<br />
      </span>
      &lt;/Directory&gt;<br />
      <br />
      &lt;Directory /web/docs/spec&gt;<br />
      <span class="indent">
        Options +Includes -Indexes<br />
      </span>
      &lt;/Directory&gt;
    </code></p></div>

    <p>entonces las opciones <code>FollowSymLinks</code> e
    <code>Includes</code> estarán activas para el directorio
    <code>/web/docs/spec</code>.</p>


    <div class="note"><h3>Nota</h3>
      <p>El uso de <code>-IncludesNOEXEC</code> o <code>-Includes</code>
      desactiva server-side includes completamente independientemente
      de la configuración anterior.</p>
    </div>

    <p>El comportamiento por defecto en ausencia de ninguna
    configuración es <code>All</code>.</p>

</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="Require" id="Require">Require</a> <a name="require" id="require">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Selecciona qué usuarios autentificados pueden acceder a
un recurso</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>Require <var>entity-name</var> [<var>entity-name</var>] ...</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Prevalece sobre:</a></th><td>AuthConfig</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>Esta directiva selecciona qué usuarios autentificados pueden
    acceder a un recurso. La sintaxis a usar es:</p>

    <dl>
      <dt><code>Require user <var>userid</var> [<var>userid</var>]
      ...</code></dt>
      <dd>Solo los usuarios mencionados pueden acceder al
      recurso.</dd>

      <dt><code>Require group <var>group-name</var> [<var>group-name</var>]
      ...</code></dt>
      <dd>Solo los usuarios pertenecientes a los grupos mencionados
      pueden acceder al recurso.</dd>

      <dt><code>Require valid-user</code></dt>
      <dd>Todos los usarios pueden acceder al recurso.</dd>
    </dl>

    <p><code class="directive">Require</code> debe ser usada de forma conjunta
    con las directivas <code class="directive"><a href="#authname">AuthName</a></code>,
    <code class="directive"><a href="#authtype">AuthType</a></code>, y con directivas
    como <code class="directive"><a href="../mod/mod_auth.html#authuserfile">AuthUserFile</a></code> y
    <code class="directive"><a href="../mod/mod_auth.html#authgroupfile">AuthGroupFile</a></code> (para
    definir usuarios y grupos) para funcionar
    correctamente. Ejemplo:</p>

    <div class="example"><p><code>
       AuthType Basic<br />
       AuthName "Restricted Resource"<br />
       AuthUserFile /web/users<br />
       AuthGroupFile /web/groups<br />
       Require group admin
    </code></p></div>

    <p>Los controles de acceso que se aplican de esta manera son
    efectivos para <strong>todos</strong> los
    métodos. <strong>Esto es lo que normalmente se
    quiere.</strong> Si quiere aplicar controles de acceso solo a
    métodos específicos, mientras se dejan otros
    métodos sin protección, use la directiva
    <code class="directive">Require</code> en una sección <code class="directive"><a href="#limit">&lt;Limit&gt;</a></code>.</p>

<h3>Consulte también</h3>
<ul>
<li><code class="directive"><a href="#satisfy">Satisfy</a></code></li>
<li><code class="module"><a href="../mod/mod_access.html">mod_access</a></code></li>
</ul>
</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="RLimitCPU" id="RLimitCPU">RLimitCPU</a> <a name="rlimitcpu" id="rlimitcpu">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Limita el consumo de tiempo de CPU que pueden hacer proceses creados
por procesos hijo de Apache</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>RLimitCPU <var>seconds</var>|max [<var>seconds</var>|max]</code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>Unset; usa el valor por defecto del sistema operativo</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host, directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Prevalece sobre:</a></th><td>Todas</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>Toma 1 ó 2 parámetros. El primer parámetro
    se refiere al límite flexible de recursos para todos los
    procesos y el segundo parámetro especifica el límite
    máximo de recursos. Cada uno de los parámetros puede ser
    un número, ó <code>max</code> para indicarle al servidor que
    el límite debe fijarse al máximo permitido por la
    configuración del sistema operativo. Para elevar el
    límite máximo de recursos es necesario que se esté
    ejecutando el servidor como ususario <code>root</code>, o estar en
    la fase inicial del arranque.</p>

    <p>Esto se aplica a procesos nacidos de procesos hijo de Apache
    que están sirviendo peticiones, no a los procesos hijo de
    Apache propiamente dichos. Esto incluye a los scripts CGI y a los
    comandos de ejecución SSI, pero no a procesos nacidos del
    proceso padre Apache tales como ficheros de registro
    redireccionados (piped logs).</p>

    <p>Los límites de consumo de tiempo de la CPU se expresan en
    segundos por proceso.</p>

<h3>Consulte también</h3>
<ul>
<li><code class="directive"><a href="#rlimitmem">RLimitMEM</a></code></li>
<li><code class="directive"><a href="#rlimitnproc">RLimitNPROC</a></code></li>
</ul>
</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="RLimitMEM" id="RLimitMEM">RLimitMEM</a> <a name="rlimitmem" id="rlimitmem">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Limita el consumo de memoria que pueden hacer procesos creados por procesos hijo de Apache</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>RLimitMEM <var>bytes</var>|max [<var>bytes</var>|max]</code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>Unset; usa el valor por defecto del sistema operativo</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host, directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Prevalece sobre:</a></th><td>Todas</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>Toma 1 ó 2 parámetros. El primer parámetro
    especifica el límite flexible de recursos para todos los
    procesos y el segundo parámetro especifica el límite
    máximo de recursos. Cada uno de los parámetros puede ser
    un número, ó <code>max</code> para indicarle al servidor que
    el límite debe fijarse al máximo permitido por la
    configuración del sistema operativo. Para elevar el
    límite máximo de recursos es necesario que se esté
    ejecutando el servidor como ususario <code>root</code>, o estar en
    la fase inicial del arranque.</p>

    <p>Esto se aplica a procesos nacidos de procesos hijo de Apache
    que están sirviendo peticiones, no a los procesos hijo de
    Apache propiamente dichos. Esto incluye a los scripts CGI y a los
    comandos de ejecución SSI, pero no a procesos nacidos del
    proceso padre Apache tales como ficheros de registro
    redireccionados (piped logs).</p>

    <p>Los límites de consumo de memoria se expresan en bytes por
    proceso.</p>

<h3>Consulte también</h3>
<ul>
<li><code class="directive"><a href="#rlimitcpu">RLimitCPU</a></code></li>
<li><code class="directive"><a href="#rlimitnproc">RLimitNPROC</a></code></li>
</ul>
</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="RLimitNPROC" id="RLimitNPROC">RLimitNPROC</a> <a name="rlimitnproc" id="rlimitnproc">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Limita el número de procesos que pueden crearse por parte de 
procesos creados por procesos hijo de Apache</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>RLimitNPROC <var>number</var>|max [<var>number</var>|max]</code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>Unset; usa el valor por defecto del sistema operativo</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host, directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Prevalece sobre:</a></th><td>Todas</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>Toma 1 ó 2 parámetros. El primer parámetro
    especifica el límite flexible de recursos para todos los
    procesos y el segundo parámetro especifica el límite
    máximo de recursos. Cada uno de los parámetros puede ser
    un número, ó <code>max</code> para indicarle al servidor que
    el límite debe fijarse al máximo permitido por la
    configuración del sistema operativo. Para elevar el
    límite máximo de recursos es necesario que se esté
    ejecutando el servidor como usuario <code>root</code>, o estar en
    la fase inicial del arranque.</p>

    <p>Esto se aplica a procesos nacidos de la división de
    procesos hijo de Apache que están sirviendo peticiones, no a
    los procesos hijo de Apache propiamente dichos. Esto incluye a los
    scripts CGI y a los comandos de ejecución SSI, pero no a procesos
    nacidos de la división del proceso padre Apache tales como
    ficheros de registro
    redireccionados (piped logs).</p>

    <p>Limita el número de procesos por usuario.</p>

    <div class="note"><h3>Nota</h3> <p>Si los procesos CGI
      <strong>no</strong> están siendo ejecutados por
      identificadores de usuario diferentes del identificador de
      usuario que está ejecutando el servidor web, esta directiva
      limitará el número de procesos que el servidor puede
      crear. Como resultado de esta situación, en el
      <code>error_log</code> aparecerán mensajes del tipo
      <strong><code>cannot fork</code></strong>.</p>
    </div>

<h3>Consulte también</h3>
<ul>
<li><code class="directive"><a href="#rlimitmem">RLimitMEM</a></code></li>
<li><code class="directive"><a href="#rlimitcpu">RLimitCPU</a></code></li>
</ul>
</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="Satisfy" id="Satisfy">Satisfy</a> <a name="satisfy" id="satisfy">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Interacción entre el control de acceso basado en host
y la autentificación de usuarios</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>Satisfy Any|All</code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>Satisfy All</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Prevalece sobre:</a></th><td>AuthConfig</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
<tr><th><a href="directive-dict.html#Compatibility">Compatibilidad:</a></th><td>Influenciada por <code class="directive"><a href="#limit">&lt;Limit&gt;</a></code> y <code class="directive"><a href="#limitexcept">&lt;LimitExcept&gt;</a></code> en las versiones de Apache 2.0.51 y
posteriores</td></tr>
</table>
    <p>Especifica la política de acceso a seguir cuando se usan tanto
    <code class="directive"><a href="../mod/mod_access.html#allow">Allow</a></code> como <code class="directive"><a href="#require">Require</a></code>. El parámetro puede ser
    <code>All</code> o <code>Any</code>. Esta directiva es solo útil
    si se va restringir el acceso a un área concreta con un nombre de
    usuario/contraseña <em>y</em> dirección del cliente. En este caso
    el comportamiento por defecto (<code>All</code>) es para requerir
    que el cliente pase la restricción referente a la dirección
    <em>e</em> introduzca un nombre de usuario y contraseña
    válidos. Con la opción <code>Any</code> el cliente podrá acceder
    si cumple la restricción referente a la dirección o si introduce un
    nombre de usuario y contraseñas válidos. Esto puede usarse para
    restringir el acceso a una zona con una contraseña, pero permitir
    a los clientes de algunas direcciones en concreto que accedan sin
    tener que introducir contraseña alguna.</p>

    <p>Por ejemplo, si quiere permitir que todo el mundo tenga acceso
    total a su intranet o a una parte de si sitio web, pero requerir que
    los visitantes de fuera de su intranet introduzcan una
    contraseña, puede usar una configuración similar a la
    siguiente:</p>

    <div class="example"><p><code>
      Require valid-user<br />
      Allow from 192.168.1<br />
      Satisfy Any
    </code></p></div>

    <p>A partir de la versión de Apache 2.0.51, puede limitarse
    la aplicación de las directivas
    <code class="directive">Satisfy</code> a determinados mótodos en
    particular mediante secciones <code class="directive"><a href="#limit">&lt;Limit&gt;</a></code> y <code class="directive"><a href="#limitexcept">&lt;LimitExcept&gt;</a></code>.</p>



<h3>Consulte también</h3>
<ul>
<li><code class="directive"><a href="../mod/mod_access.html#allow">Allow</a></code></li>
<li><code class="directive"><a href="#require">Require</a></code></li>
</ul>
</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="ScriptInterpreterSource" id="ScriptInterpreterSource">ScriptInterpreterSource</a> <a name="scriptinterpretersource" id="scriptinterpretersource">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Técnica para ubicar el intérprete de scripts CGI's</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>ScriptInterpreterSource Registry|Registry-Strict|Script</code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>ScriptInterpreterSource Script</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host, directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Prevalece sobre:</a></th><td>FileInfo</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
<tr><th><a href="directive-dict.html#Compatibility">Compatibilidad:</a></th><td>Solo sistemas Windows; la opció
<code>Registry-Strict</code> está disponible en las versiones de
Apache 2.0 y posteriores</td></tr>
</table>
    <p>Esta directiva se usa para controlar la manera que Apache
    encuentra el intérprete usado para ejecutar scripts CGI. La
    configuración por defecto es <code>Script</code>. Esto hace que
    Apache use el intérprete que aparece en la primera línea, la que
    empieza por <code>#!</code>) en el script. En los sistemas Win32
    esta línea tiene un aspecto similar a:</p>

    <div class="example"><p><code>
      #!C:/Perl/bin/perl.exe
    </code></p></div>

    <p>o, si <code>perl</code> está en el <code>PATH</code>,
    simplemente:</p>

    <div class="example"><p><code>
      #!perl
    </code></p></div>

    <p>Usar <code>ScriptInterpreterSource Registry</code> hará
    que se busque en el Registro de Windows, en
    <code>HKEY_CLASSES_ROOT</code> con la extensión del fichero
    de script (por ejemplo, <code>.pl</code>) como clave de
    búsqueda. El comando definido por la subclave del registro de
    Windows <code>Shell\ExecCGI\Command</code> o, si esta no existe,
    por la subclave <code>Shell\Open\Command</code> se usa para abrir
    el script. Si no se encuentra ningún resutlado, Apache
    recurre al comportamiento de la opción
    <code>Script</code>.</p>

    <div class="warning"><h3>Seguridad</h3> <p>Tenga cuidado
    cuando use <code>ScriptInterpreterSource Registry</code> con
    <code class="directive"><a href="../mod/mod_alias.html#scriptalias">ScriptAlias</a></code> para
    directorios, porque Apache intentará ejecutar
    <strong>cada</strong> fichero dentro de ese directorio. Lo
    especificado en <code>Registry</code> puede causar llamadas
    indeseadas a programas que normalmente no se ejecutan. Por
    ejemplo, el programa por defecto para abrir ficheros
    <code>.htm</code> en la mayoría de los sistemas Windows es
    Microsoft Internet Explorer, entonces cualquier petición HTTP
    de un fichero <code>.htm</code> que exista dentro del script del
    directorio hará que el ejecute de fondo el navegador en el
    servidor. Con esto el servidor se bloqueará en más o
    menos un minuto.</p>
    </div>

    <p>La opción <code>Registry-Strict</code> que es nueva en
    Apache 2.0 hace lo mismo que <code>Registry</code> pero usa solo
    la subclave <code>Shell\ExecCGI\Command</code>. La clave
    <code>ExecCGI</code> no es de uso común. Debe ser configurada
    manualmente en el registro de Windows y por tanto previene la
    ejecución accidental de procesos en su sistema.</p>

</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="ServerAdmin" id="ServerAdmin">ServerAdmin</a> <a name="serveradmin" id="serveradmin">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Dirección de email que el servidor incluye en los
mensajes de error que se envían al cliente</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>ServerAdmin <var>email-address</var></code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p><code class="directive">ServerAdmin</code> especifica la dirección de
    e-mail que el servidor incluye en cualquier mensaje de error que
    envía al cliente.</p>

    <p>Sería conveniente tener una dirección de email solo para esto, por ejemplo</p>

    <div class="example"><p><code>
      ServerAdmin www-admin@foo.example.com
    </code></p></div>
    <p>ya que los usuarios no siempre mencionan que están hablando
    del servidor!</p>

</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="ServerAlias" id="ServerAlias">ServerAlias</a> <a name="serveralias" id="serveralias">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Nombres alternativos usados para un host cuando se
intentan encontrar equivalencias a hosts virtuales basados en el
nombre</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>ServerAlias <var>hostname</var> [<var>hostname</var>] ...</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>virtual host</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p><code class="directive">ServerAlias</code> especifica los nombres
    alternativos para un host, para usarlo con <a href="../vhosts/name-based.html">hosts virtuales basados en el
    nombre</a>.</p>

    <div class="example"><p><code>
      &lt;VirtualHost *&gt;<br />
      ServerName example.com<br />
      ServerAlias example.com server2<br />
      # ...<br />
      &lt;/VirtualHost&gt;
    </code></p></div>

<h3>Consulte también</h3>
<ul>
<li><a href="../vhosts/">Documentación sobre hosting virtual con
Apache</a></li>
</ul>
</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="ServerName" id="ServerName">ServerName</a> <a name="servername" id="servername">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Nombre de host y número de puerto que el servidor usa
para identificarse</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>ServerName <var>fully-qualified-domain-name</var>[:<var>port</var>]</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
<tr><th><a href="directive-dict.html#Compatibility">Compatibilidad:</a></th><td>En la versión 2.0, esta directiva sustituye la
     funcionalidad de la direciva <code class="directive">Port</code> de la
     versión 1.3.</td></tr>
</table>
    <p>La directiva <code class="directive">ServerName</code> especifica el
    nombre de host y el puerto que usa el servidor para
    identificarse. Esto se usa cuando se hace redirección de URLs. Por
    ejemplo, si el nombre de la maquina del servidor web es
    <code>simple.example.com</code>, pero el la maquina también tiene
    el alias DNS <code>www.example.com</code> y quiere que el servidor
    web se identifique así, debe usar la siguiente directiva:</p>

    <div class="example"><p><code>
      ServerName www.example.com:80
    </code></p></div>

    <p>Si no especifa <code class="directive">ServerName</code>, entonces el
    servidor intentará deducir en nombre de host haciendo una
    busqueda reversa en la dirección IP. Si no se especifica
    ningún puerto en <code class="directive">ServerName</code>, entonces
    el servidor usará el puerto para las peticiones
    entrantes. Para disfrutar de la máxima fiabilidad y
    predictibilidad, debe especificar explicitamente un nombre de host
    y un puerto usando la directiva
    <code class="directive">ServerName</code>.</p>

    <p>Si está usando <a href="../vhosts/name-based.html">hosts
    virtuales basados en el nombre</a>, la directiva
    <code class="directive">ServerName</code> dentro de una sección <code class="directive"><a href="#virtualhost">&lt;VirtualHost&gt;</a></code> especifica
    qué nombre de host debe aparecer en la cabecera de petición
    <code>Host:</code> para coincidir con ese host virtual.</p>

    <p>Consulte la descripción de la directiva <code class="directive"><a href="#usecanonicalname">UseCanonicalName</a></code> para configuraciones
    que determinan si URLs autoreferenciadas (por ejemplo, por el
    módulo <code class="module"><a href="../mod/mod_dir.html">mod_dir</a></code> module) se referirán al puerto
    especificado, o al número de puerto dado en la petición del
    cliente.
    </p>

<h3>Consulte también</h3>
<ul>
<li><a href="../dns-caveats.html">Problemas relacionados en DNS y
Apache</a></li>
<li><a href="../vhosts/">Documentación sobre hosting
virtual</a></li>
<li><code class="directive"><a href="#usecanonicalname">UseCanonicalName</a></code></li>
<li><code class="directive"><a href="#namevirtualhost">NameVirtualHost</a></code></li>
<li><code class="directive"><a href="#serveralias">ServerAlias</a></code></li>
</ul>
</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="ServerPath" id="ServerPath">ServerPath</a> <a name="serverpath" id="serverpath">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>URL que se usará para hosts virtuales basados en
nombre que son accedidos con un navegador incompatible</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>ServerPath <var>URL-path</var></code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>virtual host</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>The <code class="directive">ServerPath</code> directive sets the legacy
    URL pathname for a host, for use with <a href="../vhosts/">name-based virtual hosts</a>.</p>

<h3>Consulte también</h3>
<ul>
<li><a href="../vhosts/">Documentación sobre hosting virtual</a></li>
</ul>
</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="ServerRoot" id="ServerRoot">ServerRoot</a> <a name="serverroot" id="serverroot">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Directorio base de la instalación del servidor</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>ServerRoot <var>directory-path</var></code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>ServerRoot /usr/local/apache</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>La directiva <code class="directive">ServerRoot</code> especifica el
    directorio en el que ha sido instalado el servidor. Normalmente
    contendrá los subdirectorios <code>conf/</code> y
    <code>logs/</code>. Las rutas que se especifican en otras
    directivas (por ejemplo en <code class="directive"><a href="#include">Include</a></code> o <code class="directive"><a href="../mod/mod_so.html#loadmodule">LoadModule</a></code>) se toman como relativas a
    este directorio.</p>

    <div class="example"><h3>Example</h3><p><code>
      ServerRoot /home/httpd
    </code></p></div>


<h3>Consulte también</h3>
<ul>
<li><a href="../invoking.html">la opción <code>-d</code> de
    <code>httpd</code></a></li>
<li><a href="../misc/security_tips.html#serverroot">consejos se
    seguridad</a> para más información de como establecer
    adecuadamente los permisos en
    <code class="directive">ServerRoot</code></li>
</ul>
</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="ServerSignature" id="ServerSignature">ServerSignature</a> <a name="serversignature" id="serversignature">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Configura el pie de página en documentos generados
por el servidor</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>ServerSignature On|Off|EMail</code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>ServerSignature Off</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host, directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Prevalece sobre:</a></th><td>All</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>La directiva <code class="directive">ServerSignature</code> permite la
    configuración de un pie de página que se
    añadirá a documentos generados por el sevidor (mensajes
    de error, listado de directorios generados por
    <code class="module"><a href="../mod/mod_proxy.html">mod_proxy</a></code>, salida de
    <code class="module"><a href="../mod/mod_info.html">mod_info</a></code>...). La razón por la que puede no
    querer añadir este pie de página, es que en una cadena
    de proxies, el usuario a menudo no tiene posibilidad de establecer
    cual de los servidores encadenados ha retornado un mensaje de
    error.</p>

    <p>Esta directiva usa por defecto el valor <code>Off</code>, que
    suprime la generación del pie de página (y por tanto, es
    compatible con el comportamiento de Apache 1.2 y las versiones
    anteriores). Si usa el valor <code>On</code> simplemte se
    añade una línea con el número de versión y el
    valor de <code class="directive"><a href="#servername">ServerName</a></code> para el
    host virtual que está respondiendo la petición, y el
    valor <code>EMail</code> crea las referencias adicionales
    "mailto:" a lo especificado en la directiva <code class="directive"><a href="#serveradmin">ServerAdmin</a></code>.</p>

    <p>En las versiones 2.0.44 y posteriores, los detalles del número
    de la versión del servidor son controlados por la directiva
    <code class="directive"><a href="#servertokens">ServerTokens</a></code>.</p>

<h3>Consulte también</h3>
<ul>
<li><code class="directive"><a href="#servertokens">ServerTokens</a></code></li>
</ul>
</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="ServerTokens" id="ServerTokens">ServerTokens</a> <a name="servertokens" id="servertokens">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Configura la cabecera de respuesta HTTP
<code>Server</code></td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>ServerTokens Major|Minor|Min[imal]|Prod[uctOnly]|OS|Full</code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>ServerTokens Full</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>Esta directiva controla si el campo <code>Server</code> de las
    cabeceras de las respuestas que se envían de vuelta a los clientes
    incluye una descripción del sistema operativo genérico del
    servidor así como información sobre los modulos compilados en el
    servidor.</p>

    <dl>
      <dt><code>ServerTokens Prod[uctOnly]</code></dt>

      <dd>El servidor envía (por ejemplo): <code>Server:
      Apache</code></dd>

      <dt><code>ServerTokens Major</code></dt>

      <dd>El servidor envía (por ejemplo): <code>Server:
      Apache/2</code></dd>

      <dt><code>ServerTokens Minor</code></dt>

      <dd>El servidor envía (por ejemplo): <code>Server:
      Apache/2.0</code></dd>

      <dt><code>ServerTokens Min[imal]</code></dt>

      <dd>El servidor envía (por ejemplo): <code>Server:
      Apache/2.0.41</code></dd>

      <dt><code>ServerTokens OS</code></dt>

      <dd>El servidor envía (por ejemplo): <code>Server: Apache/2.0.41
      (Unix)</code></dd>

      <dt><code>ServerTokens Full</code> (or not specified)</dt>

      <dd>El servidor envía (por ejemplo): <code>Server: Apache/2.0.41
      (Unix) PHP/4.2.2 MyMod/1.2</code></dd>
    </dl>

    <p>Esta configuración se aplica al servidor entero, y no puede ser
    activada o desactivada para unos hosts virtuales sí y para otros
    no.</p>

    <p>En las versiones posteriores a la 2.0.44, esta directiva
    también controla la información especificada en la directiva
    <code class="directive"><a href="#serversignature">ServerSignature</a></code>.</p>

<h3>Consulte también</h3>
<ul>
<li><code class="directive"><a href="#serversignature">ServerSignature</a></code></li>
</ul>
</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="SetHandler" id="SetHandler">SetHandler</a> <a name="sethandler" id="sethandler">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Hace que todos los ficheros que correspondan con el valor
especificado sean procesados obligatoriamente por un
handler</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>SetHandler <var>handler-name</var>|None</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host, directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Prevalece sobre:</a></th><td>FileInfo</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
<tr><th><a href="directive-dict.html#Compatibility">Compatibilidad:</a></th><td>Trasladado al núcleo del servidor en Apache
2.0</td></tr>
</table>
    <p>Cuando se usa en un fichero <code>.htaccess</code> o en una
    sección <code class="directive"><a href="#directory">&lt;Directory&gt;</a></code> r <code class="directive"><a href="#location">&lt;Location&gt;</a></code>, esta directiva hace que todos
    los ficheros cuyo nombre tenga equivalencia con el valor que
    especifica sean tratados por el <a href="../handler.html">handler</a> dado en
    <var>handler-name</var>. Por ejemplo, si tiene un directorio cuyo
    contenido quiere que sea tratado como as fichero de reglas de
    mapas de imágenes, independientemente de las extensiones,
    puede poner lo siguiente en un fichero <code>.htaccess</code> en
    ese directorio:</p>

    <div class="example"><p><code>
      SetHandler imap-file
    </code></p></div>

    <p>Otro ejemplo: si quiere que el servidor despliegue un resumen
    de su estado cuando se llame a una URL de
    <code>http://servername/status</code>, puede poner lo siguiente en
    el fichero <code>httpd.conf</code>:</p>

    <div class="example"><p><code>
      &lt;Location /status&gt;<br />
      <span class="indent">
        SetHandler server-status<br />
      </span>
      &lt;/Location&gt;
    </code></p></div>

    <p>Puede evitar que se aplique lo especificado anteriormente en
    una directiva <code class="directive">SetHandler</code> usando el valor
    <code>None</code>.</p>

<h3>Consulte también</h3>
<ul>
<li><code class="directive"><a href="../mod/mod_mime.html#addhandler">AddHandler</a></code></li>
</ul>
</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="SetInputFilter" id="SetInputFilter">SetInputFilter</a> <a name="setinputfilter" id="setinputfilter">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Especifica los filtros que procesarán las peticiones de
los clientes y el contenido de peticiones POST</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>SetInputFilter <var>filter</var>[;<var>filter</var>...]</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host, directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Prevalece sobre:</a></th><td>FileInfo</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>La directiva <code class="directive">SetInputFilter</code> espcifica el
    filtro o filtros que procesarán las peticiones de los
    clientes y el contenido de peticiones POST cuando son recibidas
    por el servidor. El filtro o filtros especificados en esta
    directiva se aplican además de los definidos en otras partes,
    incluyendo los especificados en la directiva <code class="directive"><a href="../mod/mod_mime.html#addinputfilter">AddInputFilter</a></code>.</p>

    <p>Si se especifica más de un filtro, deben separarse con puntos y
    comas en el orden en que deban procesar los contenidos.</p>

<h3>Consulte también</h3>
<ul>
<li>Documentación sobre <a href="../filter.html">Filtros</a></li>
</ul>
</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="SetOutputFilter" id="SetOutputFilter">SetOutputFilter</a> <a name="setoutputfilter" id="setoutputfilter">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Especifica los filtros que procesarán las respuestas del
servidor</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>SetOutputFilter <var>filter</var>[;<var>filter</var>...]</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host, directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Prevalece sobre:</a></th><td>FileInfo</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>La directiva <code class="directive">SetOutputFilter</code> especifica
    los filtros se usarán para procesar las respuestas del servidor
    antes de enviarlas al cliente. Esto es además de los filtros
    definidos en otras partes, incluidos los de la directiva
    <code class="directive"><a href="../mod/mod_mime.html#addoutputfilter">AddOutputFilter</a></code>.</p>

    <p>Por ejemplo, la siguiente configuración procesará todos los
    archivos en el directorio <code>/www/data/</code> con server-side
    includes.</p>

    <div class="example"><p><code>
      &lt;Directory /www/data/&gt;<br />
      <span class="indent">
        SetOutputFilter INCLUDES<br />
      </span>
      &lt;/Directory&gt;
    </code></p></div>

    <p>Si se especifica más de un filtro, deben separarse con puntos y
    comas en el orden en que deban procesar los contenidos.</p>

<h3>Consulte también</h3>
<ul>
<li>Documentación sobre <a href="../filter.html">Filtros</a></li>
</ul>
</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="TimeOut" id="TimeOut">TimeOut</a> <a name="timeout" id="timeout">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Cantidad de tiempo que el servidor esperará para que
ocurran determinados eventos antes de cerrar una
petición</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>TimeOut <var>seconds</var></code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>TimeOut 300</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>La directiva <code class="directive">TimeOut</code> define ahora la
    cantidad de tiempo que Apache esperará para tres cosas:</p>

    <ol>
      <li>La cantidad de tiempo que tarda en recibir una
      petición GET.</li>

      <li>La cantidad de tiempo entre la recepción de paquetes TCP
      packets en una petición POST o PUT.</li>

      <li>La cantidad de tiempo entre ACKs en transmisiones de
      paquetes TCP en las respuestas.</li>
    </ol>

    <p>Lo planeado es hacer configurable por separado cada una de
    estas cosas. La cantidad de tiempo por defecto de 1200 usada antes
    de la versión 1.2, ha sido reducida hasta 300, que es en la mayor
    parte de las situaciones más de lo necesario. El tiempo usado por
    defecto no es menor porque puede que haya alguna parte del código
    en que el contador de tiempo no se pone a cero como debería cuando
    se envía un paquete. </p>

</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="UseCanonicalName" id="UseCanonicalName">UseCanonicalName</a> <a name="usecanonicalname" id="usecanonicalname">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Configura la forma en que el servidor determina su propio
nombre u puerto</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>UseCanonicalName On|Off|DNS</code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>UseCanonicalName On</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host, directory</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p>En muchas ocasiones, Apache tiene que construir una URL
    <em>autoreferenciada</em> -- esto es, una URL que se refiere de
    vuelta al mismo servidor. Con <code>UseCanonicalName On</code>
    Apache usará el nombre de host y puerto que estén especificados en
    la directiva <code class="directive"><a href="#servername">ServerName</a></code> para
    construir el nombre canónico del servidor. Este nombre se usa en
    todas las URLs autoreferenciadas, y para los valores de
    <code>SERVER_NAME</code> y <code>SERVER_PORT</code> en los
    CGIs.</p>

    <p>Con <code>UseCanonicalName Off</code> Apache formará las
    URLs autoreferenciadas usando el nombre de host y puerto
    suministrados por el cliente. Si se ha suministrado esa
    información (si no se ha suministrado, se usará el
    nombre canónico, tal y como se ha definido arriba). Estos
    valores son los mismos que se usan para implementar <a href="../vhosts/name-based.html">hosting virtual basado en
    nombres</a>, y están disponibles con los mismos clientes. Las
    variables de CGI <code>SERVER_NAME</code> y
    <code>SERVER_PORT</code> se construirán con la
    información suministrada por los clientes.</p>

    <p>Un ejemplo de donde esto puede ser útil es en un servidor de
    una intranet, donde los usuarios se conectan a la máquina usando
    nombres cortos como <code>www</code>. Se dará cuenta de que si los
    usuarios teclean un nombre corto, y una URL que es un directorio,
    tal como <code>http://www/splat</code>, <em>sin una barra al
    final</em> entonces Apache los rediccionará a
    <code>http://www.domain.com/splat/</code>. Si tiene la
    autenfificación activada, esto hará que el usuario se tenga que
    autentificar dos veces (una para <code>www</code> y otra para
    <code>www.domain.com</code> -- consulte <a href="http://httpd.apache.org/docs/misc/FAQ.html#prompted-twice">las
    preguntas más frecuentes sobre este asunto para obtener más
    información</a>). Pero si especifica el valor <code>Off</code> en
    la directiva <code class="directive">UseCanonicalName</code>, entonces
    Apache redireccionará a <code>http://www/splat/</code>.</p>

    <p>Hay una tercera opción, <code>UseCanonicalName DNS</code>, para
    el caso en que se usa hosting virtual masivo basado en IP para
    soportar clientes antiguos que no envían la cabecera
    <code>Host:</code>. Con esta opción Apache hace una busqueda de
    DNS reversa en la dirección IP del servidor al que el cliente se
    conectó para hacer funcionar las URLs autoreferenciadas.</p>

    <div class="warning"><h3>Advertencia</h3>

    <p>Si los CGIs asumen los valores de <code>SERVER_NAME</code>,
    puede que no funcionen con esta opción. El cliente es
    esencialmente libre de dar cualquier valor que quiera como nombre
    de host. Pero si el CGI solo usa <code>SERVER_NAME</code> para
    constrir URLs autoreferenciadas, entonces no debe haber ningún
    problema.</p>
    </div>

<h3>Consulte también</h3>
<ul>
<li><code class="directive"><a href="#servername">ServerName</a></code></li>
<li><code class="directive"><a href="../mod/mpm_common.html#listen">Listen</a></code></li>
</ul>
</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="VirtualHost" id="VirtualHost">&lt;VirtualHost&gt;</a> <a name="virtualhost" id="virtualhost">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Contiene las directivas que se aplican solo a un nombre
de host específico o dirección IP</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>&lt;VirtualHost
    <var>addr</var>[:<var>port</var>] [<var>addr</var>[:<var>port</var>]]
    ...&gt; ... &lt;/VirtualHost&gt;</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Core</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>core</td></tr>
</table>
    <p><code class="directive">&lt;VirtualHost&gt;</code> y
    <code>&lt;/VirtualHost&gt;</code> se usan para incluir un grupo de
    directivas que se aplicarán solo a un host virtual en
    particular. Cualquier directiva que esté permitido usar en un
    contexto virtual host puede usarse. Cuando el servidor recibe una
    petición de un documento de un host virtual en concreto, usa las
    directivas de configuración incluidas en la sección <code class="directive">&lt;VirtualHost&gt;</code>. <var>Addr</var> puede
    ser:</p>

    <ul>
      <li>La dirección IP del host virtual;</li>

      <li>Un nombre de dominio completo para la dirección IP del host
      virtual;</li>

      <li>El carácter <code>*</code>, el cual puede usarse en
      combinación con <code>NameVirtualHost *</code> para que
      equivalga a todas las direcciones IP; o</li>

      <li>La cadena de caracteres <code>_default_</code>, que se usa
      solo con hosting virtual IP para detectar direcciones IP sin
      emparejar.</li>
    </ul>

    <div class="example"><h3>Ejemplo</h3><p><code>
      &lt;VirtualHost 10.1.2.3&gt;<br />
      <span class="indent">
        ServerAdmin webmaster@host.foo.com<br />
        DocumentRoot /www/docs/host.foo.com<br />
        ServerName host.foo.com<br />
        ErrorLog logs/host.foo.com-error_log<br />
        TransferLog logs/host.foo.com-access_log<br />
      </span>
      &lt;/VirtualHost&gt;
    </code></p></div>


    <p>Las direcciones IPv6 deben especificarse entre corchetes porque
    el número de puerto opcional no podría determinarse si no se hace
    así. Un ejemplo de dirección IPv6 se mustra aquí abajo:</p>

    <div class="example"><p><code>
      &lt;VirtualHost [fe80::a00:20ff:fea7:ccea]&gt;<br />
      <span class="indent">
        ServerAdmin webmaster@host.example.com<br />
        DocumentRoot /www/docs/host.example.com<br />
        ServerName host.example.com<br />
        ErrorLog logs/host.example.com-error_log<br />
        TransferLog logs/host.example.com-access_log<br />
      </span>
      &lt;/VirtualHost&gt;
    </code></p></div>

    <p>Cada host virtual se corresponde con una dirección IP
    diferente, un número de puerto diferente o un nombre de host
    diferente para el servidor, en el primer caso la máquina del
    servidor debe estar configurada para aceptar paquetes IP para
    múltiples direcciones. (Si la máquina no tiene múltiples infaces
    de red, entonces esto puede conseguirse con el comando
    <code>ifconfig alias</code> -- si su sistema operativo lo
    soporta).</p>

    <div class="note"><h3>Nota</h3> <p>El uso de <code class="directive">&lt;VirtualHost&gt;</code> <strong>no</strong> afecta
    a las direcciones en las que escucha Apache. Puede que necesite
    asegurarse de que Apache está escuchando en la dirección correcta
    usando <code class="directive"><a href="../mod/mpm_common.html#listen">Listen</a></code>.</p>
    </div>

    <p>Cuando se usa hosting virtual basado en IP, puede
    especificarse el nombre especial <code>_default_</code>, en cuyo
    caso, este host virtual equivaldrá a cualquier dirección IP que no
    esté especificamente listada en otro host virtual. En ausencia de
    un host virtual <code>_default_</code> el server config
    "principal", consistente en todas las definiciones fuera de una
    sección VirtualHost, se usa cuando la IP no coincide con ninguna.
    (Pero tenga en cuenta que cualquier dirección IP que equivalga a
    la directiva <code class="directive"><a href="#namevirtualhost">NameVirtualHost</a></code>
    no usará ni el server config "principal" ni el host virtual
    <code>_default_</code> virtual host.  Consulte la documentación de
    <a href="../vhosts/name-based.html">hosting virtual basado en
    nombres</a> para obtener más información.)</p>

    <p>Puede especificar <code>:port</code> para cambiar el puerto
    de equivalencia. Si no especifica ninguno, entonces por defecto se
    usa el mismo puerto de la directiva <code class="directive"><a href="../mod/mpm_common.html#listen">Listen</a></code> mas reciente del servidor
    principal. También puede especificar <code>:*</code> para hacer
    coincidir con todos los puertos en esa dirección. (Esto se
    recomienda cuando se usa con <code>_default_</code>.)</p>

    <div class="warning"><h3>Seguridad</h3>
    <p>Consulte la documentación de <a href="../misc/security_tips.html">consejos de seguridad</a> para
    obtener más información sobre por qué pone en riesgo la seguridad
    si en el directorio donde almacena los archivos log tiene permisos
    de escritura alguien que no sea el usuario que inicia el
    servidor.</p>
    </div>

<h3>Consulte también</h3>
<ul>
<li><a href="../vhosts/">Documentación sobre hosting virtual</a></li>
<li><a href="../dns-caveats.html">Problemas relacionados con DNS y Apache</a></li>
<li><a href="../bind.html">Especificar las direcciones y puertos que usa Apache</a></li>
<li><a href="../sections.html">Cómo funcionan las secciones
    &lt;Directory&gt;, &lt;Location&gt; y &lt;Files&gt;</a> si quiere
    una explicación completa de como se combinan esas secciones cuando
    se recibe una petición</li>
</ul>
</div>
</div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="../de/mod/core.html" hreflang="de" rel="alternate" title="Deutsch">&nbsp;de&nbsp;</a> |
<a href="../en/mod/core.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/mod/core.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="../ja/mod/core.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a></p>
</div><div id="footer">
<p class="apache">Copyright 1995-2005 The Apache Software Foundation or its licensors, as applicable.<br />Licencia bajo los términos de la <a href="http://www.apache.org/licenses/LICENSE-2.0">Apache License, Version 2.0</a>.</p>
<p class="menu"><a href="../mod/">Módulos</a> | <a href="../mod/directives.html">Directivas</a> | <a href="../faq/">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa de este sitio web</a></p></div>
</body></html>