<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es" xml:lang="es"><head>
<meta content="text/html; charset=ISO-8859-1" http-equiv="Content-Type" />
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Respuestas de Error Personalizadas - Servidor HTTP Apache Versión 2.5</title>
<link href="./style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet" />
<link href="./style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size" />
<link href="./style/css/manual-print.css" rel="stylesheet" media="print" type="text/css" /><link rel="stylesheet" type="text/css" href="./style/css/prettify.css" />
<script src="./style/scripts/prettify.min.js" type="text/javascript">
</script>

<link href="./images/favicon.ico" rel="shortcut icon" /></head>
<body id="manual-page"><div id="page-header">
<p class="menu"><a href="./mod/">Módulos</a> | <a href="./mod/quickreference.html">Directivas</a> | <a href="http://wiki.apache.org/httpd/FAQ">Preguntas Frecuentes</a> | <a href="./glossary.html">Glosario</a> | <a href="./sitemap.html">Mapa del sitio web</a></p>
<p class="apache">Versión 2.5 del Servidor HTTP Apache</p>
<img alt="" src="./images/feather.png" /></div>
<div class="up"><a href="./"><img title="&lt;-" alt="&lt;-" src="./images/left.gif" /></a></div>
<div id="path">
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs/">Documentación</a> &gt; <a href="./">Versión 2.5</a></div><div id="page-content"><div id="preamble"><h1>Respuestas de Error Personalizadas</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="./en/custom-error.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/custom-error.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="./fr/custom-error.html" hreflang="fr" rel="alternate" title="Français">&nbsp;fr&nbsp;</a> |
<a href="./ja/custom-error.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/custom-error.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./tr/custom-error.html" hreflang="tr" rel="alternate" title="Türkçe">&nbsp;tr&nbsp;</a></p>
</div>


    <p>Aunque el Servidor Apache HTTP ofrece respuestas de error genéricos en
    el caso de los códigos de estado 4xx o 5xx  HTTP, éstas respuestas son 
    bastante austeras, no informativas, y puede ser intimidante para los 
    usuarios del sitio. Si lo desea, para proporcionar respuestas de error 
    personalizados que son o bien más amables, o en algún idioma que no sea 
    Inglés, o tal vez que son de un estilo más acorde con su diseño del sitio.</p>

    <p>Respuestas de error personalizadas se pueden definir para cualquier código HTTP
    designado como condición de error - Esto es, cualquier estado 4xx ó 5xx.</p>

    <p>Además, se proporcionan un conjunto de valores, de manera que el 
      documento de error puede ser personalizado más adelante, basado en 
      los valores de estas variables, usando <a href="howto/ssi.html">Inclusiones del 
      Lado del Servidor (SSI)</a>. O bien, puede tener condiciones de error que maneje 
      un cgi, u otro controlador dinámico (PHP, mod_perl, etc), que
     hace uso de estas variables.</p>

  </div>
<div id="quickview"><ul id="toc"><li><img alt="" src="./images/down.gif" /> <a href="#configuration">Configuración</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#variables">Variables Disponibles</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#custom">Personalizando Respuestas de Errores</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#multi-lang">Documentos de error  personalizados 
    Multilengua</a></li>
</ul><h3>Consulte también</h3><ul class="seealso"><li><a href="#comments_section">Comentarios</a></li></ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="configuration" id="configuration">Configuración</a></h2>

    <p>Los documentos de error personalizados se configuran
    mediante la directiva <code class="directive"><a href="./mod/core.html#errordocument">ErrorDocument</a></code>,
    que puede ser usado en el conjunto general, de los hosts virtuales o en directorios.
    También pueden ser usados en los ficheros .htaccess si
    <code class="directive"><a href="./mod/core.html#allowoverride">AllowOverride</a></code>esta configurado a 
    FileInfo.</p>

    <pre class="prettyprint lang-config">ErrorDocument 500 "Perdón, Nuestro escript ha fallado. ¡Ay Madre!"<br />
ErrorDocument 500 /cgi-bin/crash-recover<br />
ErrorDocument 500 http://error.example.com/server_error.html<br />
ErrorDocument 404 /errors/not_found.html <br />
ErrorDocument 401 /subscription/como_suscribirse.html</pre>


    <p>La sintaxis de la directiva de <code>ErrorDocument</code> es:</p>

    <pre class="prettyprint lang-config">ErrorDocument &lt;código-de-3-dígitos&gt; &lt;acción&gt;</pre>


    <p>Donde la acción será tratada como:</p>

    <ol>
      <li>Una URL local a la que redireccionar (si la acción empieza con "/").</li>
      <li>Una URL externa a la que redireccionar (si la acción es una URL válida).</li>
      <li>Texto para mostrar (si ninguna de las anteriores). El texto tiene que estar 
        entrecomillado ("ERROR") si  consiste de mas de una palabra.</li>
    </ol>

    <p>Cuando se redirija a una URL local, se establecen variables de 
      entorno adicionales de manera que la respuesta puede ser personalizada. 
      Éstas variables no se envían a URLs externas</p>

  </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="variables" id="variables">Variables Disponibles</a></h2>

      <p>Redireccionando a otra URL puede ser útil, pero sólo si algo de información
       puede ser pasado como parámetro, lo cuál puede ser usado para explicar de 
       forma más clara el error o crear un log del mismo.</p>

      <p>Para conseguir esto, cuando se envía el redireccionamiento de error, 
        se establecerán variables de entorno adicionales, que será generado a 
        partir de las cabeceras prestadas a la solicitud original, anteponiendo 'REDIRECT_' 
        en el nombre de la cabecera original. Esto proporciona el 
        documento de error en el ámbito de la petición original</p>

      <p>Por ejemplo, es posible que se reciba, además de las variables de 
        entorno más habituales, lo siguiente:</p>

      <div class="example"><p><code>
        REDIRECT_HTTP_ACCEPT=*/*, image/gif, image/jpeg, image/png<br />
        REDIRECT_HTTP_USER_AGENT=Mozilla/5.0 Fedora/3.5.8-1.fc12 Firefox/3.5.8<br />
        REDIRECT_PATH=.:/bin:/usr/local/bin:/sbin<br />
        REDIRECT_QUERY_STRING=<br />
        REDIRECT_REMOTE_ADDR=121.345.78.123<br />
        REDIRECT_REMOTE_HOST=client.example.com<br />
        REDIRECT_SERVER_NAME=www.example.edu<br />
        REDIRECT_SERVER_PORT=80<br />
        REDIRECT_SERVER_SOFTWARE=Apache/2.2.15<br />
        REDIRECT_URL=/cgi-bin/buggy.pl
      </code></p></div>

      <p> Las variables de entorno de tipo <code>REDIRECT_</code> se crean a partir
      de las variables de entorno que existían antes de la redirección. Se renombran 
      con prefijo <code>REDIRECT_</code>, <em>por ejemplo:</em>,
      <code>HTTP_USER_AGENT</code> se convierte en
      <code>REDIRECT_HTTP_USER_AGENT</code>.</p>

      <p><code>REDIRECT_URL</code>, <code>REDIRECT_STATUS</code>, y
      <code>REDIRECT_QUERY_STRING</code> están garantizados para ser fijado, y
      se establecerán las otras cabeceras solo si existían antes de 
      la condición de error.</p>

      <p><strong>Ninguna</strong> de estas condiciones se establecerá 
      si elobjetivo de <code class="directive"><a href="./mod/core.html#errordocument">ErrorDocument</a></code> es una 
      redirección <em>external</em> (nada a partir de un nombre de esquema 
      como <code>http:</code>, incluso si se refiere a la misma máquina que el servidor.</p>
  </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="custom" id="custom">Personalizando Respuestas de Errores</a></h2>

      <p>Si apunta su <code> ErrorDocument</code> a alguna variedad de controlador
       dinámico como un documento que se incluye en el lado del servidor como CGI, 
       script u otro tipo de manejador, es posible que desee utilizar las variables 
       de entorno disponibles para personalizar esta respuesta.</p>

      <p>Si el ErrorDocument especifica una redirección local a un script CGI, el 
        script debe incluir un campo de cabecera de tipo "<code>Status:</code>" en 
        su salida con el fin de asegurar la propagación de
      todo el camino de vuelta al cliente de la condición de error que se generó.
      Por ejemplo, un script de Perl ErrorDocument podría incluir lo siguiente:</p>

       <pre class="prettyprint lang-perl">...
print  "Content-type: text/html\n"; <br />
printf "Status: %s Condition Intercepted\n", $ENV{"REDIRECT_STATUS"}; <br />
...</pre>


      <p> Si el script está dedicado al manejo de una condición de error en particular,
       como por ejemplo <code>404&nbsp;Not&nbsp;Found</code>, puede usar el propio
        código y el error de texto en su lugar.</p>

      <p>Tenga en cuenta que si la respuesta contiene <code>Location:</code>
      header (con el fin de emitir una redirección del lado del cliente), el 
      script <em>deberá</em>emitir una cabecera apropiada con el <code>Status:</code> 
      (como <code>302&nbsp;Found</code>). De lo contrario la cabecera 
      <code>Location:</code> no tendrá ningún efecto.</p>

  </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="multi-lang" id="multi-lang">Documentos de error  personalizados 
    Multilengua</a></h2>

    <p>Con la instalación de Apache HTTP Server se proporciona un directorio 
      personal con diferentes mensajes de errores traducidos a 16 idiomas 
      diferentes. También hay un archivo de configuración el el directorio 
    <code>conf/extra</code> que puede ser incluido para añadir esta funcionalidad.</p>

    <p>En el archivo de configuración del servidor, verá una línea como:</p>

    <pre class="prettyprint lang-config">    # Multi-language error messages<br />
    #Include conf/extra/httpd-multilang-errordoc.conf</pre>


    <p>Descomentando éste <code>Include</code> habilitará esta característica,
    y proporcionar mensajes de error de idioma-negociado,
    basado en el idioma de preferencia establecido en el navegador del cliente.</p>

    <p>Además, estos documentos contienen varias variables del tipo 
    <code>REDIRECT_</code>, con lo que se le puede añadir información adicional 
    de lo que ha ocurrido al usuario final, y que pueden hacer ahora.</p>

    <p>Estos documentos pueden ser personalizados de cualquier forma que desee 
      mostrar más información al usuario a cerca del su sitio web, y que podrán encontrar en él.</p>

    <p><code class="module"><a href="./mod/mod_include.html">mod_include</a></code> y <code class="module"><a href="./mod/mod_negotiation.html">mod_negotiation</a></code>
    Tienen que estar habilitados para usar estas características.</p>

 </div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="./en/custom-error.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/custom-error.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="./fr/custom-error.html" hreflang="fr" rel="alternate" title="Français">&nbsp;fr&nbsp;</a> |
<a href="./ja/custom-error.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/custom-error.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./tr/custom-error.html" hreflang="tr" rel="alternate" title="Türkçe">&nbsp;tr&nbsp;</a></p>
</div><div class="top"><a href="#page-header"><img src="./images/up.gif" alt="top" /></a></div><div class="section"><h2><a id="comments_section" name="comments_section">Comentarios</a></h2><div class="warning"><strong>Notice:</strong><br />This is not a Q&amp;A section. Comments placed here should be pointed towards suggestions on improving the documentation or server, and may be removed again by our moderators if they are either implemented or considered invalid/off-topic. Questions on how to manage the Apache HTTP Server should be directed at either our IRC channel, #httpd, on Freenode, or sent to our <a href="http://httpd.apache.org/lists.html">mailing lists</a>.</div>
<script type="text/javascript"><!--//--><![CDATA[//><!--
var comments_shortname = 'httpd';
var comments_identifier = 'http://httpd.apache.org/docs/trunk/custom-error.html';
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
<p class="menu"><a href="./mod/">Módulos</a> | <a href="./mod/quickreference.html">Directivas</a> | <a href="http://wiki.apache.org/httpd/FAQ">Preguntas Frecuentes</a> | <a href="./glossary.html">Glosario</a> | <a href="./sitemap.html">Mapa del sitio web</a></p></div><script type="text/javascript"><!--//--><![CDATA[//><!--
if (typeof(prettyPrint) !== 'undefined') {
    prettyPrint();
}
//--><!]]></script>
</body></html>