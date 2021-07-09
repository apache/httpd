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
<title>Variables de entorno de Apache - Servidor HTTP Apache</title>
<link href="./style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet" />
<link href="./style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size" />
<link href="./style/css/manual-print.css" rel="stylesheet" media="print" type="text/css" />
<link href="./images/favicon.ico" rel="shortcut icon" /><link href="http://httpd.apache.org/docs/current/env.html" rel="canonical" /></head>
<body id="manual-page"><div id="page-header">
<p class="menu"><a href="./mod/">M&#243;dulos</a> | <a href="./mod/directives.html">Directivas</a> | <a href="./faq/">Preguntas Frecuentes</a> | <a href="./glossary.html">Glosario</a> | <a href="./sitemap.html">Mapa de este sitio web</a></p>
<p class="apache">Versi&#243;n 2.0 del Servidor HTTP Apache</p>
<img alt="" src="./images/feather.gif" /></div>
<div class="up"><a href="./"><img title="&lt;-" alt="&lt;-" src="./images/left.gif" /></a></div>
<div id="path">
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs/">Documentaci&#243;n</a> &gt; <a href="./">Versi&#243;n 2.0</a></div><div id="page-content"><div class="retired"><h4>Please note</h4>
            <p>This document refers to the <strong>2.0</strong> version of Apache httpd, which <strong>is no longer maintained</strong>. Upgrade, and refer to the current version of httpd instead, documented at:</p>
        <ul><li><a href="http://httpd.apache.org/docs/current/">Current release version of Apache HTTP Server documentation</a></li></ul><p>You may follow <a href="http://httpd.apache.org/docs/current/env.html">this link</a> to go to the current version of this document.</p></div><div id="preamble"><h1>Variables de entorno de Apache</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="./en/env.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/env.html" title="Espa&#241;ol">&nbsp;es&nbsp;</a> |
<a href="./fr/env.html" hreflang="fr" rel="alternate" title="Fran&#231;ais">&nbsp;fr&nbsp;</a> |
<a href="./ja/env.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/env.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./tr/env.html" hreflang="tr" rel="alternate" title="T&#252;rk&#231;e">&nbsp;tr&nbsp;</a></p>
</div>
<div class="outofdate">Esta traducci&#243;n podr&#237;a estar
            obsoleta. Consulte la versi&#243;n en ingl&#233;s de la
            documentaci&#243;n para comprobar si se han producido cambios
            recientemente.</div>

    <p>El servidor HTTP Apache HTTP ofrece un mecanismo para almacenar
    informaci&#243;n en variables especiales que se llaman
    <em>variables de entorno</em>. Esta informaci&#243;n puede ser
    usada para controlar diversas operaciones como por ejemplo,
    almacenar datos en ficheros de registro (log files) o controlar el
    acceso al servidor. Las variables de entorno se usan tambi&#233;n
    como un mecanismo de comunicaci&#243;n con programas externos como
    por ejemplo, scripts CGI. Este documento explica las diferentes
    maneras de usar y manipular esas variables.</p>

    <p>Aunque estas variables se llaman <em>variables de entorno</em>,
    no son iguales que las variables de entorno que controla el
    sistema operativo de la m&#225;quina en que se est&#225;
    ejecutando Apache. Las variables de entorno de Apache se almacenan
    y manipulan la en estructura interna de Apache. Solamente se
    convierten en aut&#233;nticas variables de entorno del sistema
    operativo cuando se pasan a scripts CGI o a scripts Server Side
    Include. Si quiere manipular el entorno del sistema operativo
    sobre el que Apache se est&#225; ejecutando, debe usar los
    mecanismos est&#225;ndar de manipulaci&#243;n que tenga su sistema
    operativo.</p>
  </div>
<div id="quickview"><ul id="toc"><li><img alt="" src="./images/down.gif" /> <a href="#setting">Especificaci&#243;n de variables de entorno</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#using">C&#243;mo usar las variables de entorno</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#special">Variables de entorno con funciones especiales</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#examples">Ejemplos</a></li>
</ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="setting" id="setting">Especificaci&#243;n de variables de entorno</a></h2>
    
    <table class="related"><tr><th>M&#243;dulos Relacionados</th><th>Directivas Relacionadas</th></tr><tr><td><ul><li><code class="module"><a href="./mod/mod_env.html">mod_env</a></code></li><li><code class="module"><a href="./mod/mod_rewrite.html">mod_rewrite</a></code></li><li><code class="module"><a href="./mod/mod_setenvif.html">mod_setenvif</a></code></li><li><code class="module"><a href="./mod/mod_unique_id.html">mod_unique_id</a></code></li></ul></td><td><ul><li><code class="directive"><a href="./mod/mod_setenvif.html#browsermatch">BrowserMatch</a></code></li><li><code class="directive"><a href="./mod/mod_setenvif.html#browsermatchnocase">BrowserMatchNoCase</a></code></li><li><code class="directive"><a href="./mod/mod_env.html#passenv">PassEnv</a></code></li><li><code class="directive"><a href="./mod/mod_rewrite.html#rewriterule">RewriteRule</a></code></li><li><code class="directive"><a href="./mod/mod_env.html#setenv">SetEnv</a></code></li><li><code class="directive"><a href="./mod/mod_setenvif.html#setenvif">SetEnvIf</a></code></li><li><code class="directive"><a href="./mod/mod_setenvif.html#setenvifnocase">SetEnvIfNoCase</a></code></li><li><code class="directive"><a href="./mod/mod_env.html#unsetenv">UnsetEnv</a></code></li></ul></td></tr></table>

    <h3><a name="basic-manipulation" id="basic-manipulation">Manipulaci&#243;n b&#225;sica del entorno</a></h3>
        

        <p>El modo m&#225;s b&#225;sico de especificar el valor de una
        variable de entorno en Apache es usando la directiva
        incondicional <code class="directive"><a href="./mod/mod_env.html#setenv">SetEnv</a></code>. Las variables pueden
        tambi&#233;n pasarse desde el shell en el que se inicio Apache
        usando la directiva <code class="directive"><a href="./mod/mod_env.html#passenv">PassEnv</a></code>.</p>

    
    <h3><a name="conditional" id="conditional">Especificaci&#243;n condicional por petici&#243;n</a></h3>
        

        <p>Si necesita m&#225;s flexibilidad, las directivas incluidas
        con mod_setenvif permiten especificar valores para las
        variables de entorno de manera condicional en funci&#243;n de
        las caracteristicas particulares de la petici&#243;n que se
        est&#233; procesando. Por ejemplo, se puede especificar un
        valor para una variable solamente cuando la petici&#243;n se
        haga con un navegador espec&#237;fico, o solamente cuando la
        petici&#243;n contenga una determinada informaci&#243;n en su
        cabecera. Si necesita a&#250;n m&#225;s flexibilidad, puede
        conseguirla con la directiva <code class="directive"><a href="./mod/mod_rewrite.html#rewriterule">RewriteRule</a></code> del m&#243;dulo
        mod_rewrite que tiene la opci&#243;n <code>[E=...]</code> para
        especificar valores en las variables de entorno.</p>

    
    <h3><a name="unique-identifiers" id="unique-identifiers">Identificadores &#250;nicos</a></h3>
        

        <p>Finalmente, mod_unique_id determina el valor de la variable
        de entorno <code>UNIQUE_ID</code> para cada
        petici&#243;n. Este valor est&#225; garantizado que sea
        &#250;nico entre todas las peticiones bajo condiciones muy
        espec&#237;ficas.</p>

    
    <h3><a name="standard-cgi" id="standard-cgi">Variables CGI est&#225;ndar</a></h3>
        

        <p>Adem&#225;s de todas las variables de entorno especificadas
        en la configuraci&#243;n de Apache y las que se pasan desde el
        shell, los scripts CGI y las p&#225;ginas SSI tienen un
        conjunto de variables de entorno que contienen
        meta-informaci&#243;n sobre la petici&#243;n tal y como
        establece la <a href="http://cgi-spec.golux.com/">especificaci&#243;n
        CGI</a>.</p>

    
    <h3><a name="caveats" id="caveats">Algunas limitaciones</a></h3>
        

        <ul>
          <li>No es posible reeemplazar los valores o cambiar las
          variables est&#225;ndar CGI usando las directivas de
          manipulaci&#243;n del entorno.</li>

          <li>Cuando se usa <code class="program"><a href="./programs/suexec.html">suexec</a></code> para
          lanzar scripts CGI, el entorno se limpia y se queda reducido
          a un conjunto de variables <em>seguras</em> antes de que se
          lancen los scripts. La lista de variables <em>seguras</em>
          se define en el momento de compilar en
          <code>suexec.c</code>.</li>

          <li>Por razones de portabilidad, los nombres de las
          variables de entorno solo pueden contener letras,
          n&#250;meros y guiones bajos. Adem&#225;s, el primer
          caracter no puede ser un n&#250;mero. Los caracteres que no
          cumplan con esta restricci&#243;n, se reemplazan
          autom&#225;ticamente por un gui&#243;n bajo cuando se pasan
          a scripts CGI y a p&#225;ginas SSI.</li>
        </ul>
    
  </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="using" id="using">C&#243;mo usar las variables de entorno</a></h2>
    

    <table class="related"><tr><th>M&#243;dulos Relacionados</th><th>Directivas Relacionadas</th></tr><tr><td><ul><li><code class="module"><a href="./mod/mod_access.html">mod_access</a></code></li><li><code class="module"><a href="./mod/mod_cgi.html">mod_cgi</a></code></li><li><code class="module"><a href="./mod/mod_ext_filter.html">mod_ext_filter</a></code></li><li><code class="module"><a href="./mod/mod_headers.html">mod_headers</a></code></li><li><code class="module"><a href="./mod/mod_include.html">mod_include</a></code></li><li><code class="module"><a href="./mod/mod_log_config.html">mod_log_config</a></code></li><li><code class="module"><a href="./mod/mod_rewrite.html">mod_rewrite</a></code></li></ul></td><td><ul><li><code class="directive"><a href="./mod/mod_access.html#allow">Allow</a></code></li><li><code class="directive"><a href="./mod/mod_log_config.html#customlog">CustomLog</a></code></li><li><code class="directive"><a href="./mod/mod_access.html#deny">Deny</a></code></li><li><code class="directive"><a href="./mod/mod_ext_filter.html#extfilterdefine">ExtFilterDefine</a></code></li><li><code class="directive"><a href="./mod/mod_headers.html#header">Header</a></code></li><li><code class="directive"><a href="./mod/mod_log_config.html#logformat">LogFormat</a></code></li><li><code class="directive"><a href="./mod/mod_rewrite.html#rewritecond">RewriteCond</a></code></li><li><code class="directive"><a href="./mod/mod_rewrite.html#rewriterule">RewriteRule</a></code></li></ul></td></tr></table>

    <h3><a name="cgi-scripts" id="cgi-scripts">Scripts CGI</a></h3>
        

        <p>Uno de los principales usos de las variables de entorno es
        pasar informaci&#243;n a scripts CGI. Tal y como se explicaba
        m&#225;s arriba, el entorno que se pasa a los scripts CGI
        incluye meta-informaci&#243;n est&#225;ndar acerca de la
        petici&#243;n adem&#225;s de cualquier variable especificada
        en la configuraci&#243;n de Apache. Para obtener m&#225;s
        informaci&#243;n sobre este tema consulte el <a href="howto/cgi.html">tutorial sobre CGIs</a>.</p>

    
    <h3><a name="ssi-pages" id="ssi-pages">P&#225;ginas SSI</a></h3>
        

        <p>Los documentos procesados por el servidor con el filtro
        <code>INCLUDES</code> perteneciente a mod_include pueden
        imprimir las variables de entorno usando el elemento
        <code>echo</code>, y pueden usar las variables de entorno en
        elementos de control de flujo para dividir en partes una
        p&#225;gina condicional seg&#250;n las caracter&#237;sticas de
        la petici&#243;n. Apache tambi&#233;n sirve p&#225;ginas SSI
        con las variables CGI est&#225;ndar tal y como se explica
        m&#225;s arriba en este documento. Para obetener m&#225;s
        informaci&#243;n, consulte el <a href="howto/ssi.html">tutorial sobre SSI</a>.</p>

    
    <h3><a name="access-control" id="access-control">Control de acceso</a></h3>
        

        <p>El acceso al servidor puede ser controlado en funci&#243;n
        del valor de las variables de entorno usando las directivas
        <code>allow from env=</code> y <code>deny from env=</code>. En
        combinaci&#243;n con la directiva <code class="directive"><a href="./mod/mod_setenvif.html#setenvif">SetEnvIf</a></code>, se puede tener un
        control m&#225;s flexible del acceso al servidor en
        funci&#243;n de las caracter&#237;sticas del cliente. Por
        ejemplo, puede usar estas directivas para denegar el acceso si
        el cliente usa un determinado navegador.</p>

    
    <h3><a name="logging" id="logging">Registro condicional</a></h3>
        

        <p>Los valores de las variables de entorno pueden registrarse
        en el log de acceso usando la directiva <code class="directive"><a href="./mod/mod_log_config.html#logformat">LogFormat</a></code> con la
        opci&#243;n <code>%e</code>. Adem&#225;s, la decisi&#243;n
        sobre qu&#233; peticiones se registran puede ser tomada en
        funci&#243;n del valor de las variables de entorno usando la
        forma condicional de la directiva <code class="directive"><a href="./mod/mod_log_config.html#customlog">CustomLog</a></code>. En
        combinaci&#243;n con <code class="directive"><a href="./mod/mod_setenvif.html#setenvif">SetEnvIf</a></code>, esto permite controlar de forma
        flexible de qu&#233; peticiones se guarda registro. Por
        ejemplo, puede elegir no registrar las peticiones que se hagan
        a ficheros cuyo nombre termine en <code>gif</code>, o puede
        elegir registrar &#250;nicamente las peticiones que provengan
        de clientes que est&#233;n fuera de su propia red.</p>

    
    <h3><a name="response-headers" id="response-headers">Cabeceras de respuesta condicionales</a></h3>
        

        <p>La directiva <code class="directive"><a href="./mod/mod_headers.html#header">Header</a></code> puede utilizar la
        presencia o ausencia de una variable de entorno para
        determinar si una determinada cabecera HTTP se incluye en la
        respuesta al cliente. Esto permite, por ejemplo, que una
        determinada cabecera de respuesta sea enviada &#250;nicamente
        si tambi&#233;n estaba presente en la petici&#243;n del
        cliente.</p>

    

    <h3><a name="external-filter" id="external-filter">Activaci&#243;n de filtros externos</a></h3>
        

        <p>External filters configured by <code class="module"><a href="./mod/mod_ext_filter.html">mod_ext_filter</a></code>
        using the <code class="directive"><a href="./mod/mod_ext_filter.html#extfilterdefine">ExtFilterDefine</a></code> directive can
        by activated conditional on an environment variable using the
        <code>disableenv=</code> and <code>enableenv=</code> options.</p>
    

    <h3><a name="url-rewriting" id="url-rewriting">Reescritura de URLs</a></h3>
        

        <p>La expresion <code>%{ENV:...}</code> de <em>TestString</em>
         en una directiva <code class="directive"><a href="./mod/mod_rewrite.html#rewritecond">RewriteCond</a></code> permite que el
         motor de reescritura de mod_rewrite pueda tomar decisiones en
         funci&#243;n del valor de variables de entorno. Tenga en
         cuenta que las variables accesibles en mod_rewrite sin el
         prefijo <code>ENV:</code> no son realmente variables de
         entorno. En realidad, son variables especiales de mod_rewrite
         que no pueden ser accedidas desde otros m&#243;dulos.</p>
    
  </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="special" id="special">Variables de entorno con funciones especiales</a></h2>
    

        <p>Los problemas de interoperatividad han conducido a la
        introducci&#243;n de mecanismos para modificar el
        comportamiento de Apache cuando se comunica con determinados
        clientes. Para hacer que esos mecanismos sean tan flexibles
        como sea posible, se invocan definiendo variables de entorno,
        normalmente con la directiva <code class="directive"><a href="./mod/mod_setenvif.html#browsermatch">BrowserMatch</a></code>, aunque
        tambi&#233;n se puede usar por ejemplo con las directivas
        <code class="directive"><a href="./mod/mod_env.html#setenv">SetEnv</a></code> y <code class="directive"><a href="./mod/mod_env.html#passenv">PassEnv</a></code>.</p>

    <h3><a name="downgrade" id="downgrade">downgrade-1.0</a></h3>
        

        <p>Fuerza que la petici&#243;n sea tratada como una petici&#243;n
        HTTP/1.0 incluso si viene en una especificaci&#243;n posterior.</p>

    
    <h3><a name="force-no-vary" id="force-no-vary">force-no-vary</a></h3>
        

        <p>Hace que cualquier campo <code>Vary</code> se elimine de la
        cabecera de la respuesta antes de ser enviada al
        cliente. Algunos clientes no interpretan este campo
        correctamente (consulte la secci&#243;n sobre <a href="misc/known_client_problems.html">problemas conocidos con
        clientes</a>); usar esta variable puede evitar esos
        problemas. Usar esta variable implica tambi&#233;n el uso de
        <strong>force-response-1.0</strong>.</p>

    
    <h3><a name="force-response" id="force-response">force-response-1.0</a></h3>
        

      <p>Fuerza que la respuesta a una petici&#243;n HTTP/1.0 se haga
      tambi&#233;n seg&#250;n la especificaci&#243;n HTTP/1.0. Esto se
      implement&#243; originalmente como resultado de un problema con
      los proxies de AOL. Algunos clientes HTTP/1.0 no se comportan
      correctamente cuando se les env&#237;a una respuesta HTTP/1.1, y
      este mecanismo hace que se pueda interactuar con ellos.</p>

    

    <h3><a name="gzip-only-text-html" id="gzip-only-text-html">gzip-only-text/html</a></h3>
        

        <p>Cuando tiene valor "1", esta variable desactiva el filtro
        de salida DEFLATE de <code class="module"><a href="./mod/mod_deflate.html">mod_deflate</a></code> para
        contenidos de tipo diferentes de <code>text/html</code>.</p>
    

    <h3><a name="no-gzip" id="no-gzip">no-gzip</a></h3>

        <p>Cuando se especifica, se desactiva el filtro
        <code>DEFLATE</code> de <code class="module"><a href="./mod/mod_deflate.html">mod_deflate</a></code>.</p>

    

    <h3><a name="nokeepalive" id="nokeepalive">nokeepalive</a></h3>
        

        <p>Desactiva <code class="directive"><a href="./mod/core.html#keepalive">KeepAlive</a></code>.</p>

    

    <h3><a name="prefer-language" id="prefer-language">prefer-language</a></h3>

        <p>Influye en el comportamiento de
        <code class="module"><a href="./mod/mod_negotiation.html">mod_negotiation</a></code>. Si contiene una etiqueta de
        idioma (del tipo <code>en</code>, <code>ja</code> o
        <code>x-klingon</code>), <code class="module"><a href="./mod/mod_negotiation.html">mod_negotiation</a></code>
        intenta que se use ese mismo idioma en la respuesta. Si no
        est&#225; disponible ese idioma, se aplica el proceso de <a href="content-negotiation.html">negociaci&#243;n</a>
        normal.</p>

    

    <h3><a name="redirect-carefully" id="redirect-carefully">redirect-carefully</a></h3>
        

        <p>Fuerza que el servidor sea especialmente cuidadoso al
        enviar una redirecci&#243;n al cliente. Se usa normalmente
        cuando un cliente tiene un problema conocido tratando las
        redirecciones. Fue implementado originalmente por el problema
        que presentaba el software de WebFolders de Microsoft, que
        ten&#237;a problemas interpretando redirecciones originadas
        cuando se acced&#237;a a recursos servidos usando DAV.</p>

    

   <h3><a name="suppress-error-charset" id="suppress-error-charset">suppress-error-charset</a></h3>
       

    <p><em>Disponible en las versiones de Apache 2.0.40 y posteriores</em></p>

    <p>Cuando Apache efect&#250;a una redirecci&#243;n en respuesta a la
    petici&#243;n de un cliente, la respuesta incluye alg&#250;n texto para que
    se muestre en caso de que el cliente no pueda seguir (o no siga)
    autom&#225;ticamente la redirecci&#243;n. Apache normalmente etiqueta este
    texto siguiendo la codificaci&#243;n ISO-8859-1.</p> 

    <p>Sin embargo, si la redirecci&#243;n es a una p&#225;gina que
    usa una codificaci&#243;n diferente, algunas versiones de
    navegadores que no funcionan correctamente intentar&#225;n usar la
    codificaci&#243;n del texto de redirecci&#243;n en lugar de la de
    pagina a la que ha sido redireccionado. La consecuencia de esto
    puede ser, por ejemplo, que una p&#225;gina en griego no se
    muestre correctamente.</p>

    <p>Especificar un valor en esta variable de entorno hace que
    Apache omita la codificaci&#243;n en el texto que incluye con las
    redirecciones, y que esos navegadores que no funcionan
    correctamente muestren correctamente la p&#225;gina de destino.</p>

   

  </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="examples" id="examples">Ejemplos</a></h2>
    

    <h3><a name="misbehaving" id="misbehaving">C&#243;mo cambiar el comportamiento de clientes que se
        comportan de manera inapropiada</a></h3>
        

        <p>Recomendamos que incluya las siguentes l&#237;neas en el
        fichero httpd.conf para evitar problemas conocidos</p>
<div class="example"><pre>

#
# Las siguientes directivas modifican el comportamiento normal de las respuestas HTTP.
# La primera directiva desactiva keepalive para Netscape 2.x y para navegadores 
# que la simulan. Hay problemas conocidos con esos navegadores.
# La segunda directiva es para Microsoft Internet Explorer 4.0b2
# que tiene un fallo en la implemantaci&#243;n de HTTP/1.1 y no soporta
# keepalive adecuadamente cuando se usan respuestas 301 &#243; 302 (redirecciones).
#
BrowserMatch "Mozilla/2" nokeepalive
BrowserMatch "MSIE 4\.0b2;" nokeepalive downgrade-1.0 force-response-1.0

#
# La siguiente directiva desactiva las respuestas HTTP/1.1 para navegadores que
# violan la especificaci&#243;n HTTP/1.0 @@@ by not being able to grok a
# basic 1.1 response @@@.
#
BrowserMatch "RealPlayer 4\.0" force-response-1.0
BrowserMatch "Java/1\.0" force-response-1.0
BrowserMatch "JDK/1\.0" force-response-1.0</pre></div>

    
    <h3><a name="no-img-log" id="no-img-log">No almacenar entradas en registro de acceso para las
        im&#225;genes</a></h3>
        

        <p>Este ejemplo evita que las peticiones de im&#225;genes
        aparezcan en el registro de acceso. Puede ser modificada
        f&#225;cilmente para evitar que se registren entradas de
        peticiones de directorios, o provenientes de determinados
        clientes.</p>

        <div class="example"><pre> 
SetEnvIf Request_URI \.gif image-request
SetEnvIf Request_URI \.jpg image-request 
SetEnvIf Request_URI \.png image-request 
CustomLog logs/access_log common env=!image-request</pre></div>

    
    <h3><a name="image-theft" id="image-theft">Evitar el "robo de imagenes"</a></h3>
        

        <p>Este ejemplo muestra como evitar que otras webs usen las
        im&#225;genes de su servidor para sus p&#225;ginas. Esta
        configuraci&#243;n no se recomienda, pero puede funcionar en
        determinadas circunstancias. Asumimos que que todas sus
        im&#225;genes est&#225;n en un directorio llamado
        /web/images.</p>

        <div class="example"><pre> 
SetEnvIf Referer "^http://www.example.com/" local_referal 
# Allow browsers that do not send Referer info
SetEnvIf Referer "^$" local_referal 
&lt;Directory  /web/images&gt; 
   Order Deny,Allow 
   Deny from all 
   Allow from env=local_referal 
&lt;/Directory&gt;</pre></div>

        <p>Para obtener m&#225;s informaci&#243;n sobre esta
        t&#233;cnica, consulte el tutorial de ApacheToday " <a href="http://apachetoday.com/news_story.php3?ltsn=2000-06-14-002-01-PS">
        Keeping Your Images from Adorning Other Sites</a>".</p>
         </div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="./en/env.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/env.html" title="Espa&#241;ol">&nbsp;es&nbsp;</a> |
<a href="./fr/env.html" hreflang="fr" rel="alternate" title="Fran&#231;ais">&nbsp;fr&nbsp;</a> |
<a href="./ja/env.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/env.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./tr/env.html" hreflang="tr" rel="alternate" title="T&#252;rk&#231;e">&nbsp;tr&nbsp;</a></p>
</div><div id="footer">
<p class="apache">Copyright 2013 The Apache Software Foundation.<br />Licencia bajo los t&#233;rminos de la <a href="http://www.apache.org/licenses/LICENSE-2.0">Apache License, Version 2.0</a>.</p>
<p class="menu"><a href="./mod/">M&#243;dulos</a> | <a href="./mod/directives.html">Directivas</a> | <a href="./faq/">Preguntas Frecuentes</a> | <a href="./glossary.html">Glosario</a> | <a href="./sitemap.html">Mapa de este sitio web</a></p></div>
</body></html>