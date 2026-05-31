<!DOCTYPE html SYSTEM "about:legacy-compat">
<html lang="es"><head><META http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<meta content="width=device-width, initial-scale=1" name="viewport">
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Filtros - Servidor HTTP Apache Versi&oacute;n 2.4</title>
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
<a href="https://www.apache.org/">Apache</a> &gt; <a href="https://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="https://httpd.apache.org/docs/">Documentaci&oacute;n</a> &gt; <a href="./">Versi&oacute;n 2.4</a></div><div id="page-content"><div id="preamble"><h1>Filtros</h1>
<button aria-label="Toggle language list" class="lang-toggle"><svg xmlns="http://www.w3.org/2000/svg" stroke-width="2" stroke="currentColor" fill="none" viewBox="0 0 24 24" height="16" width="16"><circle r="10" cy="12" cx="12"/><line y2="12" x2="22" y1="12" x1="2"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></button>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="./en/filter.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/filter.html" title="Espa&ntilde;ol">&nbsp;es&nbsp;</a> |
<a href="./fr/filter.html" hreflang="fr" rel="alternate" title="Fran&ccedil;ais">&nbsp;fr&nbsp;</a> |
<a href="./ja/filter.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/filter.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./pt-br/filter.html" hreflang="pt-br" rel="alternate" title="Portugu&ecirc;s (Brasil)">&nbsp;pt-br&nbsp;</a> |
<a href="./tr/filter.html" hreflang="tr" rel="alternate" title="T&uuml;rk&ccedil;e">&nbsp;tr&nbsp;</a></p>
</div>
<div class="outofdate">Esta traducci&oacute;n podr&iacute;a estar
            obsoleta. Consulte la versi&oacute;n en ingl&eacute;s de la
            documentaci&oacute;n para comprobar si se han producido cambios
            recientemente.</div>

      <p>Este documento describe c&oacute;mo usar filtros en Apache.</p>
    </div>
<div id="quickview"><ul id="toc"><li><img alt="" src="./images/down.gif"> <a href="#intro">Filtros en Apache 2</a></li>
<li><img alt="" src="./images/down.gif"> <a href="#smart">Filtrado Inteligente</a></li>
<li><img alt="" src="./images/down.gif"> <a href="#service">Filtros expuestos como un servicio HTTP</a></li>
<li><img alt="" src="./images/down.gif"> <a href="#using">Usando los Filtros</a></li>
</ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section">
<h2 id="intro">Filtros en Apache 2 <a title="Enlace permanente" href="#intro" class="permalink">&para;</a></h2>
      
      <table class="related"><tr><th>M&oacute;dulos Relacionados</th><th>Directivas Relacionadas</th></tr><tr><td><ul><li><code class="module"><a href="./mod/mod_filter.html">mod_filter</a></code></li><li><code class="module"><a href="./mod/mod_deflate.html">mod_deflate</a></code></li><li><code class="module"><a href="./mod/mod_ext_filter.html">mod_ext_filter</a></code></li><li><code class="module"><a href="./mod/mod_include.html">mod_include</a></code></li><li><code class="module"><a href="./mod/mod_charset_lite.html">mod_charset_lite</a></code></li><li><code class="module"><a href="./mod/mod_reflector.html">mod_reflector</a></code></li><li><code class="module"><a href="./mod/mod_buffer.html">mod_buffer</a></code></li><li><code class="module"><a href="./mod/mod_data.html">mod_data</a></code></li><li><code class="module"><a href="./mod/mod_ratelimit.html">mod_ratelimit</a></code></li><li><code class="module"><a href="./mod/mod_reqtimeout.html">mod_reqtimeout</a></code></li><li><code class="module"><a href="./mod/mod_request.html">mod_request</a></code></li><li><code class="module"><a href="./mod/mod_sed.html">mod_sed</a></code></li><li><code class="module"><a href="./mod/mod_substitute.html">mod_substitute</a></code></li><li><code class="module"><a href="./mod/mod_xml2enc.html">mod_xml2enc</a></code></li><li><code class="module"><a href="./mod/mod_proxy_html.html">mod_proxy_html</a></code></li><li><code class="module"><a href="./mod/mod_policy.html">mod_policy</a></code></li></ul></td><td><ul><li><code class="directive"><a href="./mod/mod_filter.html#filterchain">FilterChain</a></code></li><li><code class="directive"><a href="./mod/mod_filter.html#filterdeclare">FilterDeclare</a></code></li><li><code class="directive"><a href="./mod/mod_filter.html#filterprotocol">FilterProtocol</a></code></li><li><code class="directive"><a href="./mod/mod_filter.html#filterprovider">FilterProvider</a></code></li><li><code class="directive"><a href="./mod/mod_mime.html#addinputfilter">AddInputFilter</a></code></li><li><code class="directive"><a href="./mod/mod_mime.html#addoutputfilter">AddOutputFilter</a></code></li><li><code class="directive"><a href="./mod/mod_mime.html#removeinputfilter">RemoveInputFilter</a></code></li><li><code class="directive"><a href="./mod/mod_mime.html#removeoutputfilter">RemoveOutputFilter</a></code></li><li><code class="directive"><a href="./mod/mod_reflector.html#reflectorheader">ReflectorHeader</a></code></li><li><code class="directive"><a href="./mod/mod_ext_filter.html#extfilterdefine">ExtFilterDefine</a></code></li><li><code class="directive"><a href="./mod/mod_ext_filter.html#extfilteroptions">ExtFilterOptions</a></code></li><li><code class="directive"><a href="./mod/core.html#setinputfilter">SetInputFilter</a></code></li><li><code class="directive"><a href="./mod/core.html#setoutputfilter">SetOutputFilter</a></code></li></ul></td></tr></table>

        <p>La cadena de filtrado est&aacute; disponible en Apache 2.0 y superiores.
        Un <em>filtro</em> es un proceso que se aplica a los datos que
        se reciben o se env&iacute;an por el servidor. Los datos enviados
        por los clientes al servidor son procesados por <em>filtros de
        entrada</em> mientras que los datos enviados por el servidor se
        procesan por los <em>filtros de salida</em>. A los datos se les
        pueden aplicar varios filtros, y el orden en que se aplica cada
        filtro puede especificarse expl&iacute;citamente.
        Todo este proceso es independiente de las tradicionales fase de
        peticiones</p>
        <p class="figure">
      <img src="images/filter_arch.png" width="569" height="392" alt="Filters can be chained, in a Data Axis orthogonal to request processing">
      </p>
      <p>Algunos ejemplos de filtrado en la distribuci&oacute;n est&aacute;ndar de Apache son:</p>
      <ul>
      <li><code class="module"><a href="./mod/mod_include.html">mod_include</a></code>, implementa  server-side includes (SSI).</li>
      <li><code class="module"><a href="./mod/mod_ssl.html">mod_ssl</a></code>, implementa cifrado SSL (https).</li>
      <li><code class="module"><a href="./mod/mod_deflate.html">mod_deflate</a></code>, implementa compresi&oacute;n y descompresi&oacute;n en el acto.</li>
      <li><code class="module"><a href="./mod/mod_charset_lite.html">mod_charset_lite</a></code>, transcodificaci&oacute;n entre diferentes juegos de caracteres.</li>
      <li><code class="module"><a href="./mod/mod_ext_filter.html">mod_ext_filter</a></code>, ejecuta un programa externo como filtro.</li>
      </ul>
        <p>Los filtros se usan internamente por Apache para llevar a cabo
        funciones tales como chunking y servir peticiones de
        byte-range. Adem&aacute;s, los m&oacute;dulos contienen filtros que se
        pueden seleccionar usando directivas de configuraci&oacute;n al
        iniciar el servidor.</p>

        <p>Una mayor amplitud de aplicaciones son implementadas con m&oacute;dulos de 
        filtros de terceros que estan disponibles en <a href="http://modules.apache.org/">modules.apache.org</a> y en otros lados.
        algunos de ellos son:</p>

        <ul>
      <li>Procesamiento y reescritura de HTML y XML.</li>
      <li>Transformaciones de XSLT y XIncludes.</li>
      <li>Soporte de espacios de nombres en XML.</li>
      <li>Manipulaci&oacute;n de carga de archivos y decodificaci&oacute;n de los 
        formularios HTML.</li>
      <li>Procesamiento de im&aacute;genes.</li>
      <li>Protecci&oacute;n de aplicaciones vulnerables, tales como scripts PHP</li>
      <li>Edici&oacute;n de texto de b&uacute;squeda y remplazo.</li>
      </ul>
    </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section">
<h2 id="smart">Filtrado Inteligente <a title="Enlace permanente" href="#smart" class="permalink">&para;</a></h2>
      
        <p class="figure">
        <img src="images/mod_filter_new.png" width="423" height="331" alt="Smart filtering applies different filter providers according to the state of request processing">
        </p>
        <p><code class="module"><a href="./mod/mod_filter.html">mod_filter</a></code>, incluido en Apache 2.1 y posterior,
        habilita la cadena de filtrado para ser configurada din&aacute;micamente en
        tiempo de ejecuci&oacute;n. As&iacute;, por ejemplo, usted puede configurar un 
        proxy para que reescriba HTML con un filtro de HTML y im&aacute;genes JPEG
        con filtros completos por separado, a pesar de que el proxy no tiene 
        informaci&oacute;n previa sobre lo que enviar&aacute; al servidor de origen.
        Esto funciona usando un engranaje filtros, que env&iacute;a a diferentes 
        proveedores dependiendo del contenido en tiempo de ejecuci&oacute;n.
        Cualquier filtro puede ser, ya sea insertado directamente en la
        cadena y ejecutado incondicionalmente, o usado como proveedor y
        a&ntilde;adido din&aacute;micamente
        Por ejemplo:</p>
        <ul>
        <li>Un filtro de procesamiento de HTML s&oacute;lo se ejecuta si el 
          contenido es text/html o application/xhtml + xml.</li>
        <li>Un filtro de compresi&oacute;n s&oacute;lo se ejecuta si la entrada es un tipo 
          compresible y no est&aacute; ya comprimida.</li>
        <li>Se insertar&aacute; un filtro de conversi&oacute;n de juego de caracteres,
          si un documento de texto no est&aacute; ya en el juego de caracteres 
          deseado.</li>
      </ul>
    </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section">
<h2 id="service">Filtros expuestos como un servicio HTTP <a title="Enlace permanente" href="#service" class="permalink">&para;</a></h2>

    
    <p>Los filtros pueden ser usados para procesar contenido originado 
    desde el cliente adem&aacute;s de usarse para procesar el contenido originado
    desde el propio servidor usando el m&oacute;dulo <code class="module"><a href="./mod/mod_reflector.html">mod_reflector</a></code>.</p>

    <p><code class="module"><a href="./mod/mod_reflector.html">mod_reflector</a></code> acepta peticiones POST de los clientes, y
    refleja el cuerpo de la petici&oacute;n POST recibida, dentro del contenido de la 
    respuesta de la petici&oacute;n, pasa a trav&eacute;s de la pila del filtro de salida en 
    el camino de vuelta al cliente.</p>

    <p>Esta t&eacute;cnica se puede utilizar como una alternativa a un servicio web
    que se ejecuta en una pila de de aplicaciones dentro del servidor,
    en donde el filtro de salida proporciona la transformaci&oacute;n requerida en el
    cuerpo de la petici&oacute;n. Por ejemplo, el m&oacute;dulo <code class="module"><a href="./mod/mod_deflate.html">mod_deflate</a></code>
    puede ser usado para proporcionar un servicio de compresi&oacute;n general,
    o un filtro de transformaci&oacute;n de imagen, puede ser convertido en un
    servicio de conversi&oacute;n de im&aacute;genes.
    </p>

    </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section">
<h2 id="using">Usando los Filtros <a title="Enlace permanente" href="#using" class="permalink">&para;</a></h2>
    
    <p>Hay dos formas de usar el filtrado: de forma Simple y Din&aacute;mica.
    Generalmente, deber&aacute; usar una forma u otra; ya que mezclarlas puede
    causar consecuencias inesperadas (a pesar de que reglas de Entrada de 
    tipo simple pueden ser combinadas libremente con reglas de filtrado 
    de Salidas de tipo simple o din&aacute;mico).</p>
    <p>La forma m&aacute;s sencilla es la &uacute;nica manera de configurar filtros de 
    Entrada, y es suficiente para filtros de Salida donde se necesita una
    cadena de filtros est&aacute;tica.
    Las directivas m&aacute;s relevantes son:
        <code class="directive"><a href="./mod/core.html#setinputfilter">SetInputFilter</a></code>,
        <code class="directive"><a href="./mod/core.html#setoutputfilter">SetOutputFilter</a></code>,
        <code class="directive"><a href="./mod/mod_mime.html#addinputfilter">AddInputFilter</a></code>,
        <code class="directive"><a href="./mod/mod_mime.html#addoutputfilter">AddOutputFilter</a></code>,
        <code class="directive"><a href="./mod/mod_mime.html#removeinputfilter">RemoveInputFilter</a></code>, and
        <code class="directive"><a href="./mod/mod_mime.html#removeoutputfilter">RemoveOutputFilter</a></code>.</p>

    <p>La forma Din&aacute;mica habilita ambas configuraciones est&aacute;tica, y din&aacute;mica, para los filtros de Salida, como se plantea en la p&aacute;gina <code class="module"><a href="./mod/mod_filter.html">mod_filter</a></code>.
    Las directivas m&aacute;s relevantes son:
        <code class="directive"><a href="./mod/mod_filter.html#filterchain">FilterChain</a></code>,
        <code class="directive"><a href="./mod/mod_filter.html#filterdeclare">FilterDeclare</a></code>, and
        <code class="directive"><a href="./mod/mod_filter.html#filterprovider">FilterProvider</a></code>.</p>

    <p>Una directiva m&aacute;s como es <code class="directive"><a href="./mod/mod_filter.html#addoutputfilterbytype">AddOutputFilterByType</a></code> sigue siendo 
    soportada pero esta obsoleta. Usa en cambio la configuraci&oacute;n din&aacute;mica.</p>

    </div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="./en/filter.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/filter.html" title="Espa&ntilde;ol">&nbsp;es&nbsp;</a> |
<a href="./fr/filter.html" hreflang="fr" rel="alternate" title="Fran&ccedil;ais">&nbsp;fr&nbsp;</a> |
<a href="./ja/filter.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/filter.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./pt-br/filter.html" hreflang="pt-br" rel="alternate" title="Portugu&ecirc;s (Brasil)">&nbsp;pt-br&nbsp;</a> |
<a href="./tr/filter.html" hreflang="tr" rel="alternate" title="T&uuml;rk&ccedil;e">&nbsp;tr&nbsp;</a></p>
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