<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es" xml:lang="es"><head>
<meta content="text/html; charset=ISO-8859-1" http-equiv="Content-Type" />
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Respuestas de error personalizadas - Servidor HTTP Apache Versi&#243;n 2.4</title>
<link href="./style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet" />
<link href="./style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size" />
<link href="./style/css/manual-print.css" rel="stylesheet" media="print" type="text/css" /><link rel="stylesheet" type="text/css" href="./style/css/prettify.css" />
<script src="./style/scripts/prettify.min.js" type="text/javascript">
</script>

<link href="./images/favicon.ico" rel="shortcut icon" /></head>
<body id="manual-page"><div id="page-header">
<p class="menu"><a href="./mod/">M&#243;dulos</a> | <a href="./mod/directives.html">Directivas</a> | <a href="http://wiki.apache.org/httpd/FAQ">Preguntas Frecuentes</a> | <a href="./glossary.html">Glosario</a> | <a href="./sitemap.html">Mapa del sitio web</a></p>
<p class="apache">Versi&#243;n 2.4 del Servidor HTTP Apache</p>
<img alt="" src="./images/feather.png" /></div>
<div class="up"><a href="./"><img title="&lt;-" alt="&lt;-" src="./images/left.gif" /></a></div>
<div id="path">
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs/">Documentaci&#243;n</a> &gt; <a href="./">Versi&#243;n 2.4</a></div><div id="page-content"><div id="preamble"><h1>Respuestas de error personalizadas</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="./en/custom-error.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/custom-error.html" title="Espa&#241;ol">&nbsp;es&nbsp;</a> |
<a href="./fr/custom-error.html" hreflang="fr" rel="alternate" title="Fran&#231;ais">&nbsp;fr&nbsp;</a> |
<a href="./ja/custom-error.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/custom-error.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./tr/custom-error.html" hreflang="tr" rel="alternate" title="T&#252;rk&#231;e">&nbsp;tr&nbsp;</a></p>
</div>

    <p>Apache ofrece la posibilidad de que los webmasters puedan
    configurar las respuestas que muestra el servidor Apache cuando se
    producen algunos errores o problemas.</p>

    <p>Las respuestas personalizadas pueden definirse para activarse
    en caso de que el servidor detecte un error o problema.</p>

    <p>Si un script termina de forma anormal y se produce una respuesta
    "500 Server Error", esta respuesta puede ser sustituida por otro
    texto de su elecci&#243;n o por una redirecci&#243;n a otra URL
    (local o externa).</p>
  </div>
<div id="quickview"><a href="https://www.apache.org/foundation/contributing.html" class="badge"><img src="https://www.apache.org/images/SupportApache-small.png" alt="Support Apache!" /></a><ul id="toc"><li><img alt="" src="./images/down.gif" /> <a href="#behavior">Comportamiento</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#configuration">Configuraci&#243;n</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#custom">Mesajes de error personalizados y redirecciones</a></li>
</ul><h3>Consulte tambi&#233;n</h3><ul class="seealso"><li><a href="#comments_section">Comentarios</a></li></ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="behavior" id="behavior">Comportamiento</a></h2>
    

    <h3>Comportamiento anterior</h3>
      

      <p>NCSA httpd 1.3 devolv&#237;a mensajes antiguos del error o
      problema encontrado que con frecuencia no ten&#237;an
      significado alguno para el usuario, y que no inclu&#237;an en
      los logs informaci&#243;n que diera pistas sobre las causas de
      lo sucedido.</p>
    

    <h3>Comportamiento actual</h3>
      

      <p>Se puede hacer que el servidor siga uno de los siguientes
      comportamientos:</p>

      <ol>
        <li>Desplegar un texto diferente, en lugar de los mensajes de
        la NCSA, o</li>

        <li>redireccionar la petici&#243;n a una URL local, o</li>

        <li>redireccionar la petici&#243;n a una URL externa.</li>
      </ol>

      <p>Redireccionar a otra URL puede resultar de utilidad, pero
      solo si con ello se puede tambi&#233;n pasar alguna
      informaci&#243;n que pueda explicar el error o problema y/o
      registrarlo en el log correspondiente m&#225;s claramente.</p>

      <p>Para conseguir esto, Apache define ahora variables de entorno
      similares a las de los CGI:</p>

      <div class="example"><p><code>
        REDIRECT_HTTP_ACCEPT=*/*, image/gif, image/x-xbitmap, 
            image/jpeg<br />
        REDIRECT_HTTP_USER_AGENT=Mozilla/1.1b2 (X11; I; HP-UX A.09.05 
            9000/712)<br />
        REDIRECT_PATH=.:/bin:/usr/local/bin:/etc<br />
        REDIRECT_QUERY_STRING=<br />
        REDIRECT_REMOTE_ADDR=121.345.78.123<br />
        REDIRECT_REMOTE_HOST=ooh.ahhh.com<br />
        REDIRECT_SERVER_NAME=crash.bang.edu<br />
        REDIRECT_SERVER_PORT=80<br />
        REDIRECT_SERVER_SOFTWARE=Apache/0.8.15<br />
        REDIRECT_URL=/cgi-bin/buggy.pl
      </code></p></div>

      <p>Tenga en cuenta el prefijo <code>REDIRECT_</code>.</p>

      <p>Al menos <code>REDIRECT_URL</code> y
      <code>REDIRECT_QUERY_STRING</code> se pasar&#225;n a la nueva
      URL (asumiendo que es un cgi-script o un cgi-include). Las otras
      variables existir&#225;n solo si exist&#237;an antes de aparecer
      el error o problema. <strong>Ninguna</strong> de estas variables
      se crear&#225; si en la directiva <code class="directive"><a href="./mod/core.html#errordocument">ErrorDocument</a></code> ha especificado una
      redirecci&#243;n <em>externa</em> (cualquier cosa que empiece
      por un nombre de esquema del tipo <code>http:</code>, incluso si
      se refiere al mismo servidor).</p>
    
  </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="configuration" id="configuration">Configuraci&#243;n</a></h2>
    

    <p>El uso de <code class="directive"><a href="./mod/core.html#errordocument">ErrorDocument</a></code>
    est&#225; activado para los ficheros .htaccess cuando <code class="directive"><a href="./mod/core.html#allowoverride">AllowOverride</a></code> tiene el valor
    adecuado.</p>

    <p>Aqu&#237; hay algunos ejemplos m&#225;s...</p>

    <div class="example"><p><code>
      ErrorDocument 500 /cgi-bin/crash-recover <br />
      ErrorDocument 500 "Sorry, our script crashed. Oh dear" <br />
      ErrorDocument 500 http://xxx/ <br />
      ErrorDocument 404 /Lame_excuses/not_found.html <br />
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
      mostrar&#225;. <em>Nota: las comillas (") no se
      muestran.</em></li>

      <li>Una URL local a la que se redireccionar&#225; la
      petici&#243;n.</li>

      <li>Una URL externa a la que se redireccionar&#225; la
      petici&#243;n.</li>
    </ol>
  </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="custom" id="custom">Mesajes de error personalizados y redirecciones</a></h2>
    

    <p>El comportamiento de Apache en cuanto a las redirecciones ha
    cambiado para que puedan usarse m&#225;s variables de entorno con
    los script/server-include.</p>

    <h3>Antiguo comportamiento</h3>
      

      <p>Las variables CGI est&#225;ndar estaban disponibles para el
      script al que se hac&#237;a la redirecci&#243;n. No se inclu&#237;a
      ninguna indicaci&#243;n sobre la precedencia de la
      redirecci&#243;n.</p>
    

    <h3>Nuevo comportamiento</h3>
      

      <p>Un nuevo grupo de variables de entorno se inicializa para que
      las use el script al que ha sido redireccionado. Cada
      nueva variable tendr&#225; el prefijo <code>REDIRECT_</code>.
      Las variables de entorno <code>REDIRECT_</code> se crean a
      partir de de las variables de entorno CGI que existen antes de
      la redirecci&#243;n, se les cambia el nombre
      a&#241;adi&#233;ndoles el prefijo <code>REDIRECT_</code>, por
      ejemplo, <code>HTTP_USER_AGENT</code> pasa a ser
      <code>REDIRECT_HTTP_USER_AGENT</code>. Adem&#225;s, para esas
      nuevas variables, Apache definir&#225; <code>REDIRECT_URL</code>
      y <code>REDIRECT_STATUS</code> para ayudar al script a seguir su
      origen. Tanto la URL original como la URL a la que es redirigida
      la petici&#243;n pueden almacenarse en los logs de acceso.</p>

      <p>Si ErrorDocument especifica una redirecci&#243;n local a un
      script CGI, el script debe incluir una campo de cabeceraa
      "<code>Status:</code>" en el resultado final para asegurar que
      es posible hacer llegar al cliente de vuelta la condici&#243;n
      de error que lo provoc&#243;. Por ejemplo, un script en Perl
      para usar con ErrorDocument podr&#237;a incluir lo
      siguiente:</p>

      <div class="example"><p><code>
        ... <br />
        print  "Content-type: text/html\n"; <br />
        printf "Status: %s Condition Intercepted\n", $ENV{"REDIRECT_STATUS"}; <br />
        ...
      </code></p></div>

      <p>Si el script tiene como fin tratar una determinada
      condici&#243;n de error, por ejemplo
      <code>404 Not Found</code>, se pueden usar los
      c&#243;digos de error y textos espec&#237;ficos en su lugar.</p>

      <p>Tenga en cuenta que el script <em>debe</em> incluir un campo
      de cabecera <code>Status:</code> apropiado (como
      <code>302 Found</code>), si la respuesta contiene un campo de
      cabecera <code>Location:</code> (para poder enviar una
      redirecci&#243;n que se interprete en el cliente). De otra
      manera, la cabecera
      <code>Location:</code> puede que no tenga efecto.</p>
    
  </div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="./en/custom-error.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/custom-error.html" title="Espa&#241;ol">&nbsp;es&nbsp;</a> |
<a href="./fr/custom-error.html" hreflang="fr" rel="alternate" title="Fran&#231;ais">&nbsp;fr&nbsp;</a> |
<a href="./ja/custom-error.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/custom-error.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./tr/custom-error.html" hreflang="tr" rel="alternate" title="T&#252;rk&#231;e">&nbsp;tr&nbsp;</a></p>
</div><div class="top"><a href="#page-header"><img src="./images/up.gif" alt="top" /></a></div><div class="section"><h2><a id="comments_section" name="comments_section">Comentarios</a></h2><div class="warning"><strong>Notice:</strong><br />This is not a Q&amp;A section. Comments placed here should be pointed towards suggestions on improving the documentation or server, and may be removed by our moderators if they are either implemented or considered invalid/off-topic. Questions on how to manage the Apache HTTP Server should be directed at either our IRC channel, #httpd, on Libera.chat, or sent to our <a href="https://httpd.apache.org/lists.html">mailing lists</a>.</div>
<script type="text/javascript"><!--//--><![CDATA[//><!--
var comments_shortname = 'httpd';
var comments_identifier = 'http://httpd.apache.org/docs/2.4/custom-error.html';
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
<p class="apache">Copyright 2024 The Apache Software Foundation.<br />Licencia bajo los t&#233;rminos de la <a href="http://www.apache.org/licenses/LICENSE-2.0">Apache License, Version 2.0</a>.</p>
<p class="menu"><a href="./mod/">M&#243;dulos</a> | <a href="./mod/directives.html">Directivas</a> | <a href="http://wiki.apache.org/httpd/FAQ">Preguntas Frecuentes</a> | <a href="./glossary.html">Glosario</a> | <a href="./sitemap.html">Mapa del sitio web</a></p></div><script type="text/javascript"><!--//--><![CDATA[//><!--
if (typeof(prettyPrint) !== 'undefined') {
    prettyPrint();
}
//--><!]]></script>
</body></html>