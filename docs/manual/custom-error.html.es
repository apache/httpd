<!DOCTYPE html SYSTEM "about:legacy-compat">
<html lang="es"><head><META http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<meta content="width=device-width, initial-scale=1" name="viewport">
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Respuestas de error personalizadas - Servidor HTTP Apache Versi&oacute;n 2.4</title>
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
<a href="https://www.apache.org/">Apache</a> &gt; <a href="https://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="https://httpd.apache.org/docs/">Documentaci&oacute;n</a> &gt; <a href="./">Versi&oacute;n 2.4</a></div><div id="page-content"><div id="preamble"><h1>Respuestas de error personalizadas</h1>
<button aria-label="Toggle language list" class="lang-toggle"><svg xmlns="http://www.w3.org/2000/svg" stroke-width="2" stroke="currentColor" fill="none" viewBox="0 0 24 24" height="16" width="16"><circle r="10" cy="12" cx="12"/><line y2="12" x2="22" y1="12" x1="2"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></button>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="./en/custom-error.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/custom-error.html" title="Espa&ntilde;ol">&nbsp;es&nbsp;</a> |
<a href="./fr/custom-error.html" hreflang="fr" rel="alternate" title="Fran&ccedil;ais">&nbsp;fr&nbsp;</a> |
<a href="./ja/custom-error.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/custom-error.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./tr/custom-error.html" hreflang="tr" rel="alternate" title="T&uuml;rk&ccedil;e">&nbsp;tr&nbsp;</a></p>
</div>
<div class="outofdate">Esta traducci&oacute;n podr&iacute;a estar
            obsoleta. Consulte la versi&oacute;n en ingl&eacute;s de la
            documentaci&oacute;n para comprobar si se han producido cambios
            recientemente.</div>

    <p>Apache ofrece la posibilidad de que los webmasters puedan
    configurar las respuestas que muestra el servidor Apache cuando se
    producen algunos errores o problemas.</p>

    <p>Las respuestas personalizadas pueden definirse para activarse
    en caso de que el servidor detecte un error o problema.</p>

    <p>Si un script termina de forma anormal y se produce una respuesta
    "500 Server Error", esta respuesta puede ser sustituida por otro
    texto de su elecci&oacute;n o por una redirecci&oacute;n a otra URL
    (local o externa).</p>
  </div>
<div id="quickview"><ul id="toc"><li><img alt="" src="./images/down.gif"> <a href="#behavior">Comportamiento</a></li>
<li><img alt="" src="./images/down.gif"> <a href="#configuration">Configuraci&oacute;n</a></li>
<li><img alt="" src="./images/down.gif"> <a href="#custom">Mesajes de error personalizados y redirecciones</a></li>
</ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section">
<h2 id="behavior">Comportamiento <a title="Enlace permanente" href="#behavior" class="permalink">&para;</a></h2>
    

    <h3>Comportamiento anterior</h3>
      

      <p>NCSA httpd 1.3 devolv&iacute;a mensajes antiguos del error o
      problema encontrado que con frecuencia no ten&iacute;an
      significado alguno para el usuario, y que no inclu&iacute;an en
      los logs informaci&oacute;n que diera pistas sobre las causas de
      lo sucedido.</p>
    

    <h3>Comportamiento actual</h3>
      

      <p>Se puede hacer que el servidor siga uno de los siguientes
      comportamientos:</p>

      <ol>
        <li>Desplegar un texto diferente, en lugar de los mensajes de
        la NCSA, o</li>

        <li>redireccionar la petici&oacute;n a una URL local, o</li>

        <li>redireccionar la petici&oacute;n a una URL externa.</li>
      </ol>

      <p>Redireccionar a otra URL puede resultar de utilidad, pero
      solo si con ello se puede tambi&eacute;n pasar alguna
      informaci&oacute;n que pueda explicar el error o problema y/o
      registrarlo en el log correspondiente m&aacute;s claramente.</p>

      <p>Para conseguir esto, Apache define ahora variables de entorno
      similares a las de los CGI:</p>

      <div class="example"><p><code>
        REDIRECT_HTTP_ACCEPT=*/*, image/gif, image/x-xbitmap, 
            image/jpeg<br>
        REDIRECT_HTTP_USER_AGENT=Mozilla/1.1b2 (X11; I; HP-UX A.09.05 
            9000/712)<br>
        REDIRECT_PATH=.:/bin:/usr/local/bin:/etc<br>
        REDIRECT_QUERY_STRING=<br>
        REDIRECT_REMOTE_ADDR=121.345.78.123<br>
        REDIRECT_REMOTE_HOST=ooh.ahhh.com<br>
        REDIRECT_SERVER_NAME=crash.bang.edu<br>
        REDIRECT_SERVER_PORT=80<br>
        REDIRECT_SERVER_SOFTWARE=Apache/0.8.15<br>
        REDIRECT_URL=/cgi-bin/buggy.pl
      </code></p></div>

      <p>Tenga en cuenta el prefijo <code>REDIRECT_</code>.</p>

      <p>Al menos <code>REDIRECT_URL</code> y
      <code>REDIRECT_QUERY_STRING</code> se pasar&aacute;n a la nueva
      URL (asumiendo que es un cgi-script o un cgi-include). Las otras
      variables existir&aacute;n solo si exist&iacute;an antes de aparecer
      el error o problema. <strong>Ninguna</strong> de estas variables
      se crear&aacute; si en la directiva <code class="directive"><a href="./mod/core.html#errordocument">ErrorDocument</a></code> ha especificado una
      redirecci&oacute;n <em>externa</em> (cualquier cosa que empiece
      por un nombre de esquema del tipo <code>http:</code>, incluso si
      se refiere al mismo servidor).</p>
    
  </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section">
<h2 id="configuration">Configuraci&oacute;n <a title="Enlace permanente" href="#configuration" class="permalink">&para;</a></h2>
    

    <p>El uso de <code class="directive"><a href="./mod/core.html#errordocument">ErrorDocument</a></code>
    est&aacute; activado para los ficheros .htaccess cuando <code class="directive"><a href="./mod/core.html#allowoverride">AllowOverride</a></code> tiene el valor
    adecuado.</p>

    <p>Aqu&iacute; hay algunos ejemplos m&aacute;s...</p>

    <div class="example"><p><code>
      ErrorDocument 500 /cgi-bin/crash-recover <br>
      ErrorDocument 500 "Sorry, our script crashed. Oh dear" <br>
      ErrorDocument 500 http://xxx/ <br>
      ErrorDocument 404 /Lame_excuses/not_found.html <br>
      ErrorDocument 401 /Subscription/how_to_subscribe.html
    </code></p></div>

    <p>La sintaxis es,</p>

    <div class="example"><p><code>
      ErrorDocument &lt;3-digit-code&gt; &lt;action&gt;
    </code></p></div>

    <p>donde action puede ser,</p>

    <ol>
      <li>Texto a mostrar. Ponga antes del texto que quiere que se
      muestre unas comillas ("). Lo que sea que siga a las comillas se
      mostrar&aacute;. <em>Nota: las comillas (") no se
      muestran.</em></li>

      <li>Una URL local a la que se redireccionar&aacute; la
      petici&oacute;n.</li>

      <li>Una URL externa a la que se redireccionar&aacute; la
      petici&oacute;n.</li>
    </ol>
  </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section">
<h2 id="custom">Mesajes de error personalizados y redirecciones <a title="Enlace permanente" href="#custom" class="permalink">&para;</a></h2>
    

    <p>El comportamiento de Apache en cuanto a las redirecciones ha
    cambiado para que puedan usarse m&aacute;s variables de entorno con
    los script/server-include.</p>

    <h3>Antiguo comportamiento</h3>
      

      <p>Las variables CGI est&aacute;ndar estaban disponibles para el
      script al que se hac&iacute;a la redirecci&oacute;n. No se inclu&iacute;a
      ninguna indicaci&oacute;n sobre la precedencia de la
      redirecci&oacute;n.</p>
    

    <h3>Nuevo comportamiento</h3>
      

      <p>Un nuevo grupo de variables de entorno se inicializa para que
      las use el script al que ha sido redireccionado. Cada
      nueva variable tendr&aacute; el prefijo <code>REDIRECT_</code>.
      Las variables de entorno <code>REDIRECT_</code> se crean a
      partir de de las variables de entorno CGI que existen antes de
      la redirecci&oacute;n, se les cambia el nombre
      a&ntilde;adi&eacute;ndoles el prefijo <code>REDIRECT_</code>, por
      ejemplo, <code>HTTP_USER_AGENT</code> pasa a ser
      <code>REDIRECT_HTTP_USER_AGENT</code>. Adem&aacute;s, para esas
      nuevas variables, Apache definir&aacute; <code>REDIRECT_URL</code>
      y <code>REDIRECT_STATUS</code> para ayudar al script a seguir su
      origen. Tanto la URL original como la URL a la que es redirigida
      la petici&oacute;n pueden almacenarse en los logs de acceso.</p>

      <p>Si ErrorDocument especifica una redirecci&oacute;n local a un
      script CGI, el script debe incluir una campo de cabeceraa
      "<code>Status:</code>" en el resultado final para asegurar que
      es posible hacer llegar al cliente de vuelta la condici&oacute;n
      de error que lo provoc&oacute;. Por ejemplo, un script en Perl
      para usar con ErrorDocument podr&iacute;a incluir lo
      siguiente:</p>

      <div class="example"><p><code>
        ... <br>
        print  "Content-type: text/html\n"; <br>
        printf "Status: %s Condition Intercepted\n", $ENV{"REDIRECT_STATUS"}; <br>
        ...
      </code></p></div>

      <p>Si el script tiene como fin tratar una determinada
      condici&oacute;n de error, por ejemplo
      <code>404 Not Found</code>, se pueden usar los
      c&oacute;digos de error y textos espec&iacute;ficos en su lugar.</p>

      <p>Tenga en cuenta que el script <em>debe</em> incluir un campo
      de cabecera <code>Status:</code> apropiado (como
      <code>302 Found</code>), si la respuesta contiene un campo de
      cabecera <code>Location:</code> (para poder enviar una
      redirecci&oacute;n que se interprete en el cliente). De otra
      manera, la cabecera
      <code>Location:</code> puede que no tenga efecto.</p>
    
  </div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="./en/custom-error.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/custom-error.html" title="Espa&ntilde;ol">&nbsp;es&nbsp;</a> |
<a href="./fr/custom-error.html" hreflang="fr" rel="alternate" title="Fran&ccedil;ais">&nbsp;fr&nbsp;</a> |
<a href="./ja/custom-error.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/custom-error.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./tr/custom-error.html" hreflang="tr" rel="alternate" title="T&uuml;rk&ccedil;e">&nbsp;tr&nbsp;</a></p>
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