<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es" xml:lang="es"><head>
<meta content="text/html; charset=ISO-8859-1" http-equiv="Content-Type" />
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>mod_alias - Servidor HTTP Apache Versión 2.5</title>
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
<div id="preamble"><h1>Módulo Apache mod_alias</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="../en/mod/mod_alias.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/mod/mod_alias.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="../fr/mod/mod_alias.html" hreflang="fr" rel="alternate" title="Français">&nbsp;fr&nbsp;</a> |
<a href="../ja/mod/mod_alias.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="../ko/mod/mod_alias.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="../tr/mod/mod_alias.html" hreflang="tr" rel="alternate" title="Türkçe">&nbsp;tr&nbsp;</a></p>
</div>
<div class="outofdate">Esta traducción podría estar
            obsoleta. Consulte la versión en inglés de la
            documentación para comprobar si se han producido cambios
            recientemente.</div>
<table class="module"><tr><th><a href="module-dict.html#Description">Descripción:</a></th><td>Facilita el mapeo a diferentes partes del sistema de ficheros del host en el árbol de documentos y la redirección de URLs
</td></tr>
<tr><th><a href="module-dict.html#Status">Estado:</a></th><td>Base</td></tr>
<tr><th><a href="module-dict.html#ModuleIdentifier">Identificador de Módulos:</a></th><td>alias_module</td></tr>
<tr><th><a href="module-dict.html#SourceFile">Fichero de Código Fuente:</a></th><td>mod_alias.c</td></tr></table>
<h3>Resumen de contenidos</h3>

    <p>Las directivas facilitadas por este módulo permiten la manipulación y control de URLs según llegan las peticiones al servidor. Las directivas
    <code class="directive"><a href="#alias">Alias</a></code> y 
    <code class="directive"><a href="#scriptalias">ScriptAlias</a></code> se usan para mapear URLs con rutas del sistema de ficheros. Esto permite que se sirva contenido que no está directamente dentro del 
    <code class="directive"><a href="../mod/core.html#documentroot">DocumentRoot</a></code> como si fuera parte de éste. La directiva <code class="directive"><a href="#scriptalias">ScriptAlias</a></code> tiene además el efecto de hacer que el directorio de destino contenga solo scripts CGI.</p>

    <p>Las directivas <code class="directive"><a href="#redirect">Redirect</a></code> se usan para indicar a los clientes que hagan una nueva petición con una URL distinta. Se usan a menudo cuando el recurso se ha movido a una nueva ubicación.</p>

    <p>Cuando se usan las directivas <code class="directive"><a href="#alias">Alias</a></code>,
    <code class="directive"><a href="#scriptalias">ScriptAlias</a></code> y
    <code class="directive"><a href="#redirect">Redirect</a></code> dentro de una sección 
    <code class="directive"><a href="../mod/core.html#location">&lt;Location&gt;</a></code>
    o <code class="directive"><a href="../mod/core.html#locationmatch">&lt;LocationMatch&gt;</a></code>, se puede usar
    <a href="../expr.html">sintaxis de expresión</a> para manipuilar la ruta de destino o URL.
    </p>

    <p><code class="module"><a href="../mod/mod_alias.html">mod_alias</a></code> se ha diseñado para gestionar tareas sencillas de manipulación de URL. Para tareas más complicadas como la manipulación de "query string", use las herramientas facilitadas por
    <code class="module"><a href="../mod/mod_rewrite.html">mod_rewrite</a></code>.</p>

</div>
<div id="quickview"><h3>Temas</h3>
<ul id="topics">
<li><img alt="" src="../images/down.gif" /> <a href="#order">Orden de Procesamiento</a></li>
</ul><h3 class="directives">Directivas</h3>
<ul id="toc">
<li><img alt="" src="../images/down.gif" /> <a href="#alias">Alias</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#aliasmatch">AliasMatch</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#redirect">Redirect</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#redirectmatch">RedirectMatch</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#redirectpermanent">RedirectPermanent</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#redirecttemp">RedirectTemp</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#scriptalias">ScriptAlias</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#scriptaliasmatch">ScriptAliasMatch</a></li>
</ul>
<h3>Bugfix checklist</h3><ul class="seealso"><li><a href="https://www.apache.org/dist/httpd/CHANGES_2.4">httpd changelog</a></li><li><a href="https://bz.apache.org/bugzilla/buglist.cgi?bug_status=__open__&amp;list_id=144532&amp;product=Apache%20httpd-2&amp;query_format=specific&amp;order=changeddate%20DESC%2Cpriority%2Cbug_severity&amp;component=mod_alias">Known issues</a></li><li><a href="https://bz.apache.org/bugzilla/enter_bug.cgi?product=Apache%20httpd-2&amp;component=mod_alias">Report a bug</a></li></ul><h3>Consulte también</h3>
<ul class="seealso">
<li><code class="module"><a href="../mod/mod_rewrite.html">mod_rewrite</a></code></li>
<li><a href="../urlmapping.html">Mapeo de URLs al sistema de ficheros</a></li>
<li><a href="#comments_section">Comentarios</a></li></ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="order" id="order">Orden de Procesamiento</a></h2>

    <p>Aliases y Redirects que se dan en diferentes contextos se procesan como otras directivas según las <a href="../sections.html#mergin">reglas de fusión</a> estándar.  Pero cuando se dan múltiples 
    Aliases o Redirects en el mismo contexto (por ejemplo, en la misma sección 
    <code class="directive"><a href="../mod/core.html#virtualhost">&lt;VirtualHost&gt;</a></code>)
    entonces se procesan en un orden concreto.</p>

    <p>En primer lugar, todos los Redirect se procesan antes que los Aliases, y por tanto una solicitud que coincida con un 
    <code class="directive"><a href="#redirect">Redirect</a></code> o 
    <code class="directive"><a href="#redirectmatch">RedirectMatch</a></code> nunca aplicará un Alias. En segundo lugar, los Aliases y Redirect se procesan en el orden en el que aparecen en los ficheros de configuración, y la primera coincidencia es la que tiene prioridad.</p>

    <p>Por esta razón, cuando dos o más de estas directivas se aplican a la misma sub-ruta, debe definir la ruta más específica primero para que todas las directivas tengan efecto. Por ejemplo, la siguiente configuración funcionará como se espera:</p>

    <pre class="prettyprint lang-config">Alias "/foo/bar" "/baz"
Alias "/foo" "/gaq"</pre>


    <p>Pero si estas dos directivas estuvieran en orden inverso, el 
    <code class="directive"><a href="#alias">Alias</a></code>
    <code>/foo</code> siempre se aplicaría antes que el 
    <code class="directive"><a href="#alias">Alias</a></code> <code>/foo/bar</code>, así que se obviaría la última directiva.</p>

    <p>Cuando las directivas <code class="directive"><a href="#alias">Alias</a></code>,
    <code class="directive"><a href="#scriptalias">ScriptAlias</a></code> y
    <code class="directive"><a href="#redirect">Redirect</a></code> se usan dentro de una sección
    <code class="directive"><a href="../mod/core.html#location">&lt;Location&gt;</a></code>
    o <code class="directive"><a href="../mod/core.html#locationmatch">&lt;LocationMatch&gt;</a></code>, estas directivas tendrán prioridad sobre cualquier directiva 
    <code class="directive"><a href="#alias">Alias</a></code>, 
    <code class="directive"><a href="#scriptalias">ScriptAlias</a></code> y
    <code class="directive"><a href="#redirect">Redirect</a></code> definidas globalmente.
    </p>

</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="Alias" id="Alias">Alias</a> <a name="alias" id="alias">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Mapea URLs a rutas del sistema de ficheros</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>Alias [<var>URL-path</var>]
<var>file-path</var>|<var>directory-path</var></code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host, directory</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Base</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>mod_alias</td></tr>
</table>

    <p>La directiva <code class="directive">Alias</code> permite que se almacenen documentos en el sistema de ficheros local en rutas distintas de las que están bajo
    <code class="directive"><a href="../mod/core.html#documentroot">DocumentRoot</a></code>. URLs con una ruta 
    (%-decodificada) que comienzan con <var>URL-path</var> serán mapeadas a ficheros locales que comiencen con
    <var>directory-path</var>.  El
    <var>URL-path</var> es sensible a mayúsculas, incluso en sistemas de ficheros que no lo son.</p>

    <pre class="prettyprint lang-config">Alias "/image" "/ftp/pub/image"</pre>


    <p>Una petición para <code>http://example.com/image/foo.gif</code> haría que el servidor respondiera con el fichero 
    <code>/ftp/pub/image/foo.gif</code>. Solo se comparan segmentos de ruta completos, así que el alias de más arriba no valdría para la petición 
    <code>http://example.com/imagefoo.gif</code>. Para ejemplos más complejos de expresiones regulares, vea la directiva 
    <code class="directive"><a href="#aliasmatch">AliasMatch</a></code>.</p>

    <p>Tenga en cuenta que si incluye una / final en el 
    <var>URL-path</var> entonces el servidor requerirá una / final para poder extender el alias. Es decir, si usa</p>

    <pre class="prettyprint lang-config">Alias "/icons/" "/usr/local/apache/icons/"</pre>


    <p>entonces la URL <code>/icons</code> no coincidirá con el alias, porque no tiene la / final. De la misma manera, si omite la barra en el
    <var>URL-path</var> también debe omitirla del
    <var>file-path</var>.</p>

    <p>Considere que seguramente tenga que especificar secciones de  
    <code class="directive"><a href="../mod/core.html#directory">&lt;Directory&gt;</a></code> adicionales que cubran los <em>destinos</em> de los aliases. Las directivas Alias se comprueban antes que las de 
    <code class="directive"><a href="../mod/core.html#directory">&lt;Directory&gt;</a></code>, así que solo los destinos de los alias se ven afectados.
    (Sin embargo tenga en cuenta que las secciones 
    <code class="directive"><a href="../mod/core.html#location">&lt;Location&gt;</a></code>
    se examinan una vez antes de que los alias tengan efecto, así que se aplicarán.)</p>

    <p>En particular, si está creando un <code>Alias</code> a un directorio fuera de su 
    <code class="directive"><a href="../mod/core.html#documentroot">DocumentRoot</a></code>, probablemente tenga que darle permisos de manera explícita al directorio de destino.</p>

    <pre class="prettyprint lang-config">Alias "/image" "/ftp/pub/image"
&lt;Directory "/ftp/pub/image"&gt;
    Require all granted
&lt;/Directory&gt;</pre>


    <p>Cualquier número de barras en el parámetro <var>URL-path</var> coincide con el mismo número de barras en el URL-path solicitado.</p>

    <p>Si la directiva <code class="directive">Alias</code> se usa dentro de una sección
    <code class="directive"><a href="../mod/core.html#location">&lt;Location&gt;</a></code>
    o <code class="directive"><a href="../mod/core.html#locationmatch">&lt;LocationMatch&gt;</a></code> el URL-path se omite, y el file-path se interpreta usando <a href="../expr.html">sintáxis de expresión</a>.<br />
    Esta sintáxis está disponible en Apache 2.4.19 y versiones posteriores.</p>

    <pre class="prettyprint lang-config">&lt;Location "/image"&gt;
    Alias "/ftp/pub/image"
&lt;/Location&gt;
&lt;LocationMatch "/error/(?&lt;NUMBER&gt;[0-9]+)"&gt;
    Alias "/usr/local/apache/errors/%{env:MATCH_NUMBER}.html"
&lt;/LocationMatch&gt;</pre>



</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="AliasMatch" id="AliasMatch">AliasMatch</a> <a name="aliasmatch" id="aliasmatch">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Mapea URLs a ubicaciones del sistema de ficheros usando expresiones regulares</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>AliasMatch <var>regex</var>
<var>file-path</var>|<var>directory-path</var></code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Base</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>mod_alias</td></tr>
</table>
    <p>Esta directiva es equivalente a 
    <code class="directive"><a href="#alias">Alias</a></code>, pero hace uso de 
    <a class="glossarylink" href="../glossary.html#regex" title="ver glosario">expresiones regulares</a>,
    en lugar de comparaciones simples de prefijo. La expresión 
    regular facilitada se compara con el URL-path, y si coincide, 
    el servidor sustituye cualquier coincidencia entre paréntesis con 
    la cadena de caracteres facilitada y la usa como el nombre de fichero. Por ejemplo, para activar el directorio <code>/icons</code>, uno podría usar:
    </p>

    <pre class="prettyprint lang-config">AliasMatch "^/icons(/|$)(.*)" "/usr/local/apache/icons$1$2"</pre>


    <p>Puede usar toda la capacidad que le permiten las
    <a class="glossarylink" href="../glossary.html#regex" title="ver glosario">expresiones regulares</a>. Por ejemplo, es posible construir un alias con comprobación insensible a mayúsculas del URL-path:</p>

    <pre class="prettyprint lang-config">AliasMatch "(?i)^/image(.*)" "/ftp/pub/image$1"</pre>


    <p>Una sutil diferencia entre 
    <code class="directive"><a href="#alias">Alias</a></code>
    y <code class="directive"><a href="#aliasmatch">AliasMatch</a></code> es que
    <code class="directive"><a href="#alias">Alias</a></code> copiará automáticamente cualquier parte adicional de la URI, pasada la parte que coincide, al final de la ruta del fichero en el parámetro de la derecha, mientras que
    <code class="directive"><a href="#aliasmatch">AliasMatch</a></code> no lo hará. Esto significa en casi todos los casos, querrá que las expresiones regulares concuerden con la URI solicitada al completo desde el comienzo al final, y usar la sustitución del parámetro a la derecha.</p>

    <p>En otras palabras, cambiar
    <code class="directive"><a href="#alias">Alias</a></code> a
    <code class="directive"><a href="#aliasmatch">AliasMatch</a></code> no tendrá el mismo resultado. Como mínimo, tendrá que añadir un <code>^</code> al comienzo de la expresión regular, añadir un <code>(.*)$</code> al final y añadir 
    <code>$1</code> al final del reemplazo.</p>

    <p>Por ejemplo, supongamos que quiere reemplazar esto con AliasMatch:</p>

    <pre class="prettyprint lang-config">Alias "/image/" "/ftp/pub/image/"</pre>


    <p>Esto no es equivalente - ¡no haga esto! Esto enviará todas las peticiones que tengan /image/ en cualquier parte de la petición y la pondrá en /ftp/pub/image/:</p>

    <pre class="prettyprint lang-config">AliasMatch "/image/" "/ftp/pub/image/"</pre>


    <p>Esto es lo que necesita para que tenga el mismo efecto:</p>

    <pre class="prettyprint lang-config">AliasMatch "^/image/(.*)$" "/ftp/pub/image/$1"</pre>


    <p>Por supuesto, no hay ningún motivo para usar
    <code class="directive"><a href="#aliasmatch">AliasMatch</a></code>
    donde <code class="directive"><a href="#alias">Alias</a></code> funcionaría.  
    <code class="directive"><a href="#aliasmatch">AliasMatch</a></code> le permite hacer cosas más complicadas. Por ejemplo, puede servir diferentes tipos de ficheros desde diferentes directorios:</p>

    <pre class="prettyprint lang-config">AliasMatch "^/image/(.*)\.jpg$" "/files/jpg.images/$1.jpg"
AliasMatch "^/image/(.*)\.gif$" "/files/gif.images/$1.gif"</pre>


    <p>Si se usan multiples barras iniciales en la URL solicitada, el servidor las descarta antes de que las directivas de este módulo las compare con el URL-path solicitado.
    </p>


</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="Redirect" id="Redirect">Redirect</a> <a name="redirect" id="redirect">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Envía una redirección externa indicando al cliente que solicite una URL distinta</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>Redirect [<var>status</var>] [<var>URL-path</var>]
<var>URL</var></code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host, directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Anula:</a></th><td>FileInfo</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Base</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>mod_alias</td></tr>
</table>
    <p>La directiva <code class="directive">Redirect</code> mapea una URL antigua a una nueva indicando al cliente que solicite el recurso en otra ubicación.</p>

    <p>El antiguo <em>URL-path</em> es una ruta (%-decodificada) que comienza con una barra. No se permite una ruta relativa.</p>

    <p>La nueva <em>URL</em> puede ser una URL absoluta que comienza con esquema y nombre de host, or un URL-path que comienza con una barra (/). En este último caso se añadirán el esquema y nombre de host del servidor actual si tiene <code class="directive"><a href="../mod/core.html#usecanonicalname">UseCanonicalName</a></code> configurado a on, si no el nombre de host se reemplazará por la cabecera Host solicitada.</p>

    <p>Entonces cualquier petición que comience con <em>URL-path</em> devolverá una solicitud de redirección al cliente hacia la ubicación de la <em>URL</em> de destino. Información adicional de la ruta pasado el <em>URL-path</em> que coincide se añadirá al final de la URL de destino.</p>

    <pre class="prettyprint lang-config"># Redirect hacia una URL en un host diferente
Redirect "/service" "http://foo2.example.com/service"

# Redirect hacia una URL en el mismo host
Redirect "/one" "/two"</pre>


    <p>Si el cliente solicita <code>http://example.com/service/foo.txt</code>, se le indicará que acceda a 
    <code>http://foo2.example.com/service/foo.txt</code> en su lugar. Esto incluye solicitudes con parámetros 
    <code>GET</code>, tales como
    <code>http://example.com/service/foo.pl?q=23&amp;a=42</code>,que será
    redirigido a
    <code>http://foo2.example.com/service/foo.pl?q=23&amp;a=42</code>.
    Tenga en cuenta que los <code>POST</code> serán descartados.<br />
    Solo se comparan segmentos completos de ruta, así que el ejemplo de más arriba no coincidiría con una petición a
    <code>http://example.com/servicefoo.txt</code>. Para comparaciones más complejas usando la 
    <a href="../expr.html">sintáxis de expresión</a>, omita el argumento de URL-path tal y como se indica más abajo. Alternativamente, para coincidencias usando expresiones regulares, vea la directiva 
    <code class="directive"><a href="#redirectmatch">RedirectMatch</a></code>.</p>


    <div class="note"><h3>Nota</h3>
    <p>Las directivas <code class="directive">Redirect</code> tienen priodidad sobre directivas 
    <code class="directive"><a href="#alias">Alias</a></code> y 
    <code class="directive"><a href="#scriptalias">ScriptAlias</a></code>, independientemente de su orden en el fichero de configuración. Directivas 
    <code class="directive">Redirect</code> 
    dentro de Location tiene prioridad sobre directivas 
    <code class="directive">Redirect</code> y 
    <code class="directive"><a href="#alias">Alias</a></code> con un <var>URL-path</var>.</p>
    </div>

    <p>Si no se indica un parámetro <var>status</var>, la redirección será
    "temporal" (estado HTTP 302). Esto le indica al cliente que el recurso se ha movido temporalmente. El parámetro <var>status</var> se puede usar para devolver otros códigos de estado HTTP:</p>

    <dl>
      <dt>permanent</dt>

      <dd>Devuelve una estado de redirección permanente (301) indicando que el recurso se ha movido de forma permanente.</dd>

      <dt>temp</dt>

      <dd>Devuelve un estado de redirección temporal (302). Este es el valor por defecto.</dd>

      <dt>seeother</dt>

      <dd>Devuelve un estado "See Other" (303) indicando que el recurso ha sido sustituido.</dd>

      <dt>gone</dt>

      <dd>Devuelve un estado "Gone" (410) indicando que el recurso ha sido eliminado de forma permanente. Cuando se usa este estado, el parámetro 
      <var>URL</var> debería omitirse.</dd>
    </dl>

    <p>Se pueden devolver otros códigos de estado indicando el código numérico del estado en el valor de <var>status</var>. Si el estado está entre 300 y 399, el parámetro <var>URL</var> debe estar presente. Si el estado 
    <em>no</em> está entre 300 and 399, el parámetro <var>URL</var> debe ser omitido. El estado debe ser un código de estado válido HTTP, conocido por el Servidor Apache HTTP (vea la función <code>send_error_response</code> en http_protocol.c).</p>

    <pre class="prettyprint lang-config">Redirect permanent "/one" "http://example.com/two"
Redirect 303 "/three" "http://example.com/other"</pre>


    <p>Si se usa la directiva <code class="directive">Redirect</code> dentro de una sección
    <code class="directive"><a href="../mod/core.html#location">&lt;Location&gt;</a></code>
    o <code class="directive"><a href="../mod/core.html#locationmatch">&lt;LocationMatch&gt;</a></code>
    sin el <var>URL-path</var>, entonces el parámetro <var>URL</var> será interpretado
    usando <a href="../expr.html">sintáxis de expresión</a>.<br />
    Esta sintáxis está disponible en Apache 2.4.19 y versiones posteriores.</p>

    <pre class="prettyprint lang-config">&lt;Location "/one"&gt;
    Redirect permanent "http://example.com/two"
&lt;/Location&gt;
&lt;Location "/three"&gt;
    Redirect 303 "http://example.com/other"
&lt;/Location&gt;
&lt;LocationMatch "/error/(?&lt;NUMBER&gt;[0-9]+)"&gt;
    Redirect permanent "http://example.com/errors/%{env:MATCH_NUMBER}.html"
&lt;/LocationMatch&gt;</pre>


</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="RedirectMatch" id="RedirectMatch">RedirectMatch</a> <a name="redirectmatch" id="redirectmatch">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Envía una redirección externa basada en una coincidencia de expresión regular con la URL actual
</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>RedirectMatch [<var>status</var>] <var>regex</var>
<var>URL</var></code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host, directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Anula:</a></th><td>FileInfo</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Base</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>mod_alias</td></tr>
</table>
    <p>Esta directiva es equivalente a 
    <code class="directive"><a href="#redirect">Redirect</a></code>, pero hace uso de 
    <a class="glossarylink" href="../glossary.html#regex" title="ver glosario">expresiones regulares</a>,
    en lugar de comparaciones simple de prefijo. La expresión 
    regular facilitada se compara con el URL-path, y si coincide, 
    el servidor sustituye cualquier coincidencia entre paréntesis con 
    la cadena de caracteres facilitada y la usa como el nombre de fichero. Por ejemplo, para redirigir todos los ficheros GIF al mismo nombre pero del tipo JPEG en otro servidor, uno podría usar:</p>

    <pre class="prettyprint lang-config">RedirectMatch "(.*)\.gif$" "http://other.example.com$1.jpg"</pre>


    <p>Las consideraciones relacionadas con las diferencias entre
    <code class="directive"><a href="#alias">Alias</a></code> y
    <code class="directive"><a href="#aliasmatch">AliasMatch</a></code>
    también aplican a las diferencias entre
    <code class="directive"><a href="#redirect">Redirect</a></code> y
    <code class="directive"><a href="#redirectmatch">RedirectMatch</a></code>.
    Vea <code class="directive"><a href="#aliasmatch">AliasMatch</a></code> para más
    detalles.</p>


</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="RedirectPermanent" id="RedirectPermanent">RedirectPermanent</a> <a name="redirectpermanent" id="redirectpermanent">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Envía una redirección externa permanente indicando al cliente que solicite una URL diferente</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>RedirectPermanent <var>URL-path</var> <var>URL</var></code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host, directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Anula:</a></th><td>FileInfo</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Base</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>mod_alias</td></tr>
</table>
    <p>Esta directiva hace saber al cliente que el Redirect es permanente
    (estado 301). Exactamente equivalente a 
    <code>Redirect permanent</code>.</p>

</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="RedirectTemp" id="RedirectTemp">RedirectTemp</a> <a name="redirecttemp" id="redirecttemp">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Envía una redirección externa temporal indicando al cliente que solicite una URL diferente</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>RedirectTemp <var>URL-path</var> <var>URL</var></code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host, directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Anula:</a></th><td>FileInfo</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Base</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>mod_alias</td></tr>
</table>
    <p>Esta directiva le hace saber al cliente que el Redirect es solo temporal (estado 302). Exactamente equivalente a 
    <code>Redirect temp</code>.</p>

</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="ScriptAlias" id="ScriptAlias">ScriptAlias</a> <a name="scriptalias" id="scriptalias">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Mapea una URL a una ubicación del sistema de ficheros y designa el destino como un script CGI</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>ScriptAlias [<var>URL-path</var>]
<var>file-path</var>|<var>directory-path</var></code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host, directory</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Base</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>mod_alias</td></tr>
</table>
    <p>La directiva <code class="directive">ScriptAlias</code> tiene el mismo comportamiento que la directiva <code class="directive"><a href="#alias">Alias</a></code>, excepto que además indica el directorio de destino conteniendo scripts CGI que serán procesados por el handler cgi-script de 
    <code class="module"><a href="../mod/mod_cgi.html">mod_cgi</a></code>. URLs con una ruta sensible a mayúsculas y (%-decodificadas) que comienzan con <var>URL-path</var> serán
    mapeadas a scripts que comiencen con el segundo parámetro, que es un nombre de ruta completo en el sistema de ficheros local.</p>

    <pre class="prettyprint lang-config">ScriptAlias "/cgi-bin/" "/web/cgi-bin/"</pre>


    <p>Una petición para <code>http://example.com/cgi-bin/foo</code> haría que el servidor ejecute el script <code>/web/cgi-bin/foo</code>. Esta configuración es esencialmente equivalente a:</p>
    <pre class="prettyprint lang-config">Alias "/cgi-bin/" "/web/cgi-bin/"
&lt;Location "/cgi-bin"&gt;
    SetHandler cgi-script
    Options +ExecCGI
&lt;/Location&gt;</pre>


    <p>También puede usarse <code class="directive">ScriptAlias</code>junto con un script o handler que usted tenga. Por ejemplo:</p>

    <pre class="prettyprint lang-config">ScriptAlias "/cgi-bin/" "/web/cgi-handler.pl"</pre>


    <p>En este escenario todos los ficheros solicitados en 
    <code>/cgi-bin/</code> serán gestionados por el fichero que usted ha configurado, esto permite que use su propio handler personalizado. Puede que quiera usar esto como un wrapper de CGI y así pueda añadir contenido, o alguna otra acción a medida.</p>

    <div class="warning">Es más seguro evitar que se coloquen scripts CGI bajo el <code class="directive"><a href="../mod/core.html#documentroot">DocumentRoot</a></code> para que no se revele de manera accidental el código fuente si la configuración se vuelve a cambiar alguna vez. El <code class="directive">ScriptAlias</code> hace esto fácil mapeando una URL y designando CGI scripts al mismo tiempo. Si decide colocar sus scripts CGI en un directorio que ya es accesible desde la web, no use
    <code class="directive">ScriptAlias</code>. En su lugar, use <code class="directive"><a href="../mod/core.html#directory">&lt;Directory&gt;</a></code>, <code class="directive"><a href="../mod/core.html#sethandler">SetHandler</a></code>, y <code class="directive"><a href="../mod/core.html#options">Options</a></code> como en:

    <pre class="prettyprint lang-config">&lt;Directory "/usr/local/apache2/htdocs/cgi-bin"&gt;
    SetHandler cgi-script
    Options ExecCGI
&lt;/Directory&gt;</pre>


    Esto es necesario puesto que multiples <var>URL-paths</var> pueden mapear a la misma ubicación del sistema de ficheros, potencialmente saltándose el
    <code class="directive">ScriptAlias</code> y revelando el código fuente de los scripts CGI si no están restringidos por una sección 
    <code class="directive"><a href="../mod/core.html#directory">Directory</a></code>.
    </div>

    <p>Si se usa la directiva 
    <code class="directive">ScriptAlias</code> dentro de una sección
    <code class="directive"><a href="../mod/core.html#location">&lt;Location&gt;</a></code>
    o <code class="directive"><a href="../mod/core.html#locationmatch">&lt;LocationMatch&gt;</a></code>
    con el URL-path omitido, entonces el parámetro URL será interpretando usando
    <a href="../expr.html">sintaxis de expresión</a>.<br />
    Esta sintaxis está disponible en Apache 2.4.19 y versiones posteriores.</p>

    <pre class="prettyprint lang-config">&lt;Location "/cgi-bin"&gt;
    ScriptAlias "/web/cgi-bin/"
&lt;/Location&gt;
&lt;LocationMatch "/cgi-bin/errors/(?&lt;NUMBER&gt;[0-9]+)"&gt;
    ScriptAlias "/web/cgi-bin/errors/%{env:MATCH_NUMBER}.cgi"
&lt;/LocationMatch&gt;</pre>



<h3>Consulte también</h3>
<ul>
<li><a href="../howto/cgi.html">Tutorial CGI</a></li>
</ul>
</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="ScriptAliasMatch" id="ScriptAliasMatch">ScriptAliasMatch</a> <a name="scriptaliasmatch" id="scriptaliasmatch">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Mapea una URL a una ubicación del sistema de ficheros usando 
una expresión regular y designa el destino como un script CGI</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>ScriptAliasMatch <var>regex</var>
<var>file-path</var>|<var>directory-path</var></code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>server config, virtual host</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Base</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>mod_alias</td></tr>
</table>
    <p>Esta directiva es equivalente a 
    <code class="directive"><a href="#scriptalias">ScriptAlias</a></code>, pero hace uso de
    <a class="glossarylink" href="../glossary.html#regex" title="ver glosario">expresiones regulares</a>,
    en lugar de comparaciones simples de prefijo. La expresión regular facilitada se compara con el URL-path, y si coincide, el servidor sustituye cualquier coincidencia entre paréntesis con la cadena de caracteres facilitada y la usa como el nombre de fichero. Por ejemplo, para activar el estándar 
    <code>/cgi-bin</code>, uno podría usar:</p>

    <pre class="prettyprint lang-config">ScriptAliasMatch "^/cgi-bin(.*)" "/usr/local/apache/cgi-bin$1"</pre>


    <p>En cuanto a AliasMatch, puede usar toda la capacidad que le permiten las
    <a class="glossarylink" href="../glossary.html#rexex" title="ver glosario">expresiones regulares</a>. 
    Por ejemplo, es posible construir un alias con comparación insensible
    a mayúsculas del URL-path:</p>

    <pre class="prettyprint lang-config">ScriptAliasMatch "(?i)^/cgi-bin(.*)" "/usr/local/apache/cgi-bin$1"</pre>


    <p>Las consideraciones relacionadas con las diferencias entre
    <code class="directive"><a href="#alias">Alias</a></code> y
    <code class="directive"><a href="#aliasmatch">AliasMatch</a></code>
    también aplican a las diferencias entre
    <code class="directive"><a href="#scriptalias">ScriptAlias</a></code> y
    <code class="directive"><a href="#scriptaliasmatch">ScriptAliasMatch</a></code>.
    Vea <code class="directive"><a href="#aliasmatch">AliasMatch</a></code> para más
    detalles.</p>


</div>
</div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="../en/mod/mod_alias.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/mod/mod_alias.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="../fr/mod/mod_alias.html" hreflang="fr" rel="alternate" title="Français">&nbsp;fr&nbsp;</a> |
<a href="../ja/mod/mod_alias.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="../ko/mod/mod_alias.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="../tr/mod/mod_alias.html" hreflang="tr" rel="alternate" title="Türkçe">&nbsp;tr&nbsp;</a></p>
</div><div class="top"><a href="#page-header"><img src="../images/up.gif" alt="top" /></a></div><div class="section"><h2><a id="comments_section" name="comments_section">Comentarios</a></h2><div class="warning"><strong>Notice:</strong><br />This is not a Q&amp;A section. Comments placed here should be pointed towards suggestions on improving the documentation or server, and may be removed again by our moderators if they are either implemented or considered invalid/off-topic. Questions on how to manage the Apache HTTP Server should be directed at either our IRC channel, #httpd, on Freenode, or sent to our <a href="http://httpd.apache.org/lists.html">mailing lists</a>.</div>
<script type="text/javascript"><!--//--><![CDATA[//><!--
var comments_shortname = 'httpd';
var comments_identifier = 'http://httpd.apache.org/docs/trunk/mod/mod_alias.html';
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