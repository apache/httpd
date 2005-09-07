<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es" xml:lang="es"><head><!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Variables de entorno de Apache - Servidor HTTP Apache</title>
<link href="./style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet" />
<link href="./style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size" />
<link href="./style/css/manual-print.css" rel="stylesheet" media="print" type="text/css" />
<link href="./images/favicon.ico" rel="shortcut icon" /></head>
<body id="manual-page"><div id="page-header">
<p class="menu"><a href="./mod/">Módulos</a> | <a href="./mod/directives.html">Directivas</a> | <a href="./faq/">Preguntas Frecuentes</a> | <a href="./glossary.html">Glosario</a> | <a href="./sitemap.html">Mapa de este sitio web</a></p>
<p class="apache">Versión 2.0 del Servidor HTTP Apache</p>
<img alt="" src="./images/feather.gif" /></div>
<div class="up"><a href="./"><img title="&lt;-" alt="&lt;-" src="./images/left.gif" /></a></div>
<div id="path">
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs-project/">Documentación</a> &gt; <a href="./">Versión 2.0</a></div><div id="page-content"><div id="preamble"><h1>Variables de entorno de Apache</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="./en/env.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/env.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="./fr/env.html" hreflang="fr" rel="alternate" title="Français">&nbsp;fr&nbsp;</a> |
<a href="./ja/env.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/env.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a></p>
</div>
<div class="outofdate">Esta traducción podría estar
            obsoleta. Consulte la versión en inglés de la
            documentación para comprobar si se han producido cambios
            recientemente.</div>

    <p>El servidor HTTP Apache HTTP ofrece un mecanismo para almacenar
    información en variables especiales que se llaman
    <em>variables de entorno</em>. Esta información puede ser
    usada para controlar diversas operaciones como por ejemplo,
    almacenar datos en ficheros de registro (log files) o controlar el
    acceso al servidor. Las variables de entorno se usan también
    como un mecanismo de comunicación con programas externos como
    por ejemplo, scripts CGI. Este documento explica las diferentes
    maneras de usar y manipular esas variables.</p>

    <p>Aunque estas variables se llaman <em>variables de entorno</em>,
    no son iguales que las variables de entorno que controla el
    sistema operativo de la máquina en que se está
    ejecutando Apache. Las variables de entorno de Apache se almacenan
    y manipulan la en estructura interna de Apache. Solamente se
    convierten en auténticas variables de entorno del sistema
    operativo cuando se pasan a scripts CGI o a scripts Server Side
    Include. Si quiere manipular el entorno del sistema operativo
    sobre el que Apache se está ejecutando, debe usar los
    mecanismos estándar de manipulación que tenga su sistema
    operativo.</p>
  </div>
<div id="quickview"><ul id="toc"><li><img alt="" src="./images/down.gif" /> <a href="#setting">Especificación de variables de entorno</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#using">Cómo usar las variables de entorno</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#special">Variables de entorno con funciones especiales</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#examples">Ejemplos</a></li>
</ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="setting" id="setting">Especificación de variables de entorno</a></h2>
    
    <table class="related"><tr><th>Módulos Relacionados</th><th>Directivas Relacionadas</th></tr><tr><td><ul><li><code class="module"><a href="./mod/mod_env.html">mod_env</a></code></li><li><code class="module"><a href="./mod/mod_rewrite.html">mod_rewrite</a></code></li><li><code class="module"><a href="./mod/mod_setenvif.html">mod_setenvif</a></code></li><li><code class="module"><a href="./mod/mod_unique_id.html">mod_unique_id</a></code></li></ul></td><td><ul><li><code class="directive"><a href="./mod/mod_setenvif.html#browsermatch">BrowserMatch</a></code></li><li><code class="directive"><a href="./mod/mod_setenvif.html#browsermatchnocase">BrowserMatchNoCase</a></code></li><li><code class="directive"><a href="./mod/mod_env.html#passenv">PassEnv</a></code></li><li><code class="directive"><a href="./mod/mod_rewrite.html#rewriterule">RewriteRule</a></code></li><li><code class="directive"><a href="./mod/mod_env.html#setenv">SetEnv</a></code></li><li><code class="directive"><a href="./mod/mod_setenvif.html#setenvif">SetEnvIf</a></code></li><li><code class="directive"><a href="./mod/mod_setenvif.html#setenvifnocase">SetEnvIfNoCase</a></code></li><li><code class="directive"><a href="./mod/mod_env.html#unsetenv">UnsetEnv</a></code></li></ul></td></tr></table>

    <h3><a name="basic-manipulation" id="basic-manipulation">Manipulación básica del entorno</a></h3>
        

        <p>El modo más básico de especificar el valor de una
        variable de entorno en Apache es usando la directiva
        incondicional <code class="directive"><a href="./mod/mod_env.html#setenv">SetEnv</a></code>. Las variables pueden
        también pasarse desde el shell en el que se inicio Apache
        usando la directiva <code class="directive"><a href="./mod/mod_env.html#passenv">PassEnv</a></code>.</p>

    
    <h3><a name="conditional" id="conditional">Especificación condicional por petición</a></h3>
        

        <p>Si necesita más flexibilidad, las directivas incluidas
        con mod_setenvif permiten especificar valores para las
        variables de entorno de manera condicional en función de
        las caracteristicas particulares de la petición que se
        esté procesando. Por ejemplo, se puede especificar un
        valor para una variable solamente cuando la petición se
        haga con un navegador específico, o solamente cuando la
        petición contenga una determinada información en su
        cabecera. Si necesita aún más flexibilidad, puede
        conseguirla con la directiva <code class="directive"><a href="./mod/mod_rewrite.html#rewriterule">RewriteRule</a></code> del módulo
        mod_rewrite que tiene la opción <code>[E=...]</code> para
        especificar valores en las variables de entorno.</p>

    
    <h3><a name="unique-identifiers" id="unique-identifiers">Identificadores únicos</a></h3>
        

        <p>Finalmente, mod_unique_id determina el valor de la variable
        de entorno <code>UNIQUE_ID</code> para cada
        petición. Este valor está garantizado que sea
        único entre todas las peticiones bajo condiciones muy
        específicas.</p>

    
    <h3><a name="standard-cgi" id="standard-cgi">Variables CGI estándar</a></h3>
        

        <p>Además de todas las variables de entorno especificadas
        en la configuración de Apache y las que se pasan desde el
        shell, los scripts CGI y las páginas SSI tienen un
        conjunto de variables de entorno que contienen
        meta-información sobre la petición tal y como
        establece la <a href="http://cgi-spec.golux.com/">especificación
        CGI</a>.</p>

    
    <h3><a name="caveats" id="caveats">Algunas limitaciones</a></h3>
        

        <ul>
          <li>No es posible reeemplazar los valores o cambiar las
          variables estándar CGI usando las directivas de
          manipulación del entorno.</li>

          <li>Cuando se usa <code class="program"><a href="./programs/suexec.html">suexec</a></code> para
          lanzar scripts CGI, el entorno se limpia y se queda reducido
          a un conjunto de variables <em>seguras</em> antes de que se
          lancen los scripts. La lista de variables <em>seguras</em>
          se define en el momento de compilar en
          <code>suexec.c</code>.</li>

          <li>Por razones de portabilidad, los nombres de las
          variables de entorno solo pueden contener letras,
          números y guiones bajos. Además, el primer
          caracter no puede ser un número. Los caracteres que no
          cumplan con esta restricción, se reemplazan
          automáticamente por un guión bajo cuando se pasan
          a scripts CGI y a páginas SSI.</li>
        </ul>
    
  </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="using" id="using">Cómo usar las variables de entorno</a></h2>
    

    <table class="related"><tr><th>Módulos Relacionados</th><th>Directivas Relacionadas</th></tr><tr><td><ul><li><code class="module"><a href="./mod/mod_access.html">mod_access</a></code></li><li><code class="module"><a href="./mod/mod_cgi.html">mod_cgi</a></code></li><li><code class="module"><a href="./mod/mod_ext_filter.html">mod_ext_filter</a></code></li><li><code class="module"><a href="./mod/mod_headers.html">mod_headers</a></code></li><li><code class="module"><a href="./mod/mod_include.html">mod_include</a></code></li><li><code class="module"><a href="./mod/mod_log_config.html">mod_log_config</a></code></li><li><code class="module"><a href="./mod/mod_rewrite.html">mod_rewrite</a></code></li></ul></td><td><ul><li><code class="directive"><a href="./mod/mod_access.html#allow">Allow</a></code></li><li><code class="directive"><a href="./mod/mod_log_config.html#customlog">CustomLog</a></code></li><li><code class="directive"><a href="./mod/mod_access.html#deny">Deny</a></code></li><li><code class="directive"><a href="./mod/mod_ext_filter.html#extfilterdefine">ExtFilterDefine</a></code></li><li><code class="directive"><a href="./mod/mod_headers.html#header">Header</a></code></li><li><code class="directive"><a href="./mod/mod_log_config.html#logformat">LogFormat</a></code></li><li><code class="directive"><a href="./mod/mod_rewrite.html#rewritecond">RewriteCond</a></code></li><li><code class="directive"><a href="./mod/mod_rewrite.html#rewriterule">RewriteRule</a></code></li></ul></td></tr></table>

    <h3><a name="cgi-scripts" id="cgi-scripts">Scripts CGI</a></h3>
        

        <p>Uno de los principales usos de las variables de entorno es
        pasar información a scripts CGI. Tal y como se explicaba
        más arriba, el entorno que se pasa a los scripts CGI
        incluye meta-información estándar acerca de la
        petición además de cualquier variable especificada
        en la configuración de Apache. Para obtener más
        información sobre este tema consulte el <a href="howto/cgi.html">tutorial sobre CGIs</a>.</p>

    
    <h3><a name="ssi-pages" id="ssi-pages">Páginas SSI</a></h3>
        

        <p>Los documentos procesados por el servidor con el filtro
        <code>INCLUDES</code> perteneciente a mod_include pueden
        imprimir las variables de entorno usando el elemento
        <code>echo</code>, y pueden usar las variables de entorno en
        elementos de control de flujo para dividir en partes una
        página condicional según las características de
        la petición. Apache también sirve páginas SSI
        con las variables CGI estándar tal y como se explica
        más arriba en este documento. Para obetener más
        información, consulte el <a href="howto/ssi.html">tutorial sobre SSI</a>.</p>

    
    <h3><a name="access-control" id="access-control">Control de acceso</a></h3>
        

        <p>El acceso al servidor puede ser controlado en función
        del valor de las variables de entorno usando las directivas
        <code>allow from env=</code> y <code>deny from env=</code>. En
        combinación con la directiva <code class="directive"><a href="./mod/mod_setenvif.html#setenvif">SetEnvIf</a></code>, se puede tener un
        control más flexible del acceso al servidor en
        función de las características del cliente. Por
        ejemplo, puede usar estas directivas para denegar el acceso si
        el cliente usa un determinado navegador.</p>

    
    <h3><a name="logging" id="logging">Registro condicional</a></h3>
        

        <p>Los valores de las variables de entorno pueden registrarse
        en el log de acceso usando la directiva <code class="directive"><a href="./mod/mod_log_config.html#logformat">LogFormat</a></code> con la
        opción <code>%e</code>. Además, la decisión
        sobre qué peticiones se registran puede ser tomada en
        función del valor de las variables de entorno usando la
        forma condicional de la directiva <code class="directive"><a href="./mod/mod_log_config.html#customlog">CustomLog</a></code>. En
        combinación con <code class="directive"><a href="./mod/mod_setenvif.html#setenvif">SetEnvIf</a></code>, esto permite controlar de forma
        flexible de qué peticiones se guarda registro. Por
        ejemplo, puede elegir no registrar las peticiones que se hagan
        a ficheros cuyo nombre termine en <code>gif</code>, o puede
        elegir registrar únicamente las peticiones que provengan
        de clientes que estén fuera de su propia red.</p>

    
    <h3><a name="response-headers" id="response-headers">Cabeceras de respuesta condicionales</a></h3>
        

        <p>La directiva <code class="directive"><a href="./mod/mod_headers.html#header">Header</a></code> puede utilizar la
        presencia o ausencia de una variable de entorno para
        determinar si una determinada cabecera HTTP se incluye en la
        respuesta al cliente. Esto permite, por ejemplo, que una
        determinada cabecera de respuesta sea enviada únicamente
        si también estaba presente en la petición del
        cliente.</p>

    

    <h3><a name="external-filter" id="external-filter">Activación de filtros externos</a></h3>
        

        <p>External filters configured by <code class="module"><a href="./mod/mod_ext_filter.html">mod_ext_filter</a></code>
        using the <code class="directive"><a href="./mod/mod_ext_filter.html#extfilterdefine">ExtFilterDefine</a></code> directive can
        by activated conditional on an environment variable using the
        <code>disableenv=</code> and <code>enableenv=</code> options.</p>
    

    <h3><a name="url-rewriting" id="url-rewriting">Reescritura de URLs</a></h3>
        

        <p>La expresion <code>%{ENV:...}</code> de <em>TestString</em>
         en una directiva <code class="directive"><a href="./mod/mod_rewrite.html#rewritecond">RewriteCond</a></code> permite que el
         motor de reescritura de mod_rewrite pueda tomar decisiones en
         función del valor de variables de entorno. Tenga en
         cuenta que las variables accesibles en mod_rewrite sin el
         prefijo <code>ENV:</code> no son realmente variables de
         entorno. En realidad, son variables especiales de mod_rewrite
         que no pueden ser accedidas desde otros módulos.</p>
    
  </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="special" id="special">Variables de entorno con funciones especiales</a></h2>
    

        <p>Los problemas de interoperatividad han conducido a la
        introducción de mecanismos para modificar el
        comportamiento de Apache cuando se comunica con determinados
        clientes. Para hacer que esos mecanismos sean tan flexibles
        como sea posible, se invocan definiendo variables de entorno,
        normalmente con la directiva <code class="directive"><a href="./mod/mod_setenvif.html#browsermatch">BrowserMatch</a></code>, aunque
        también se puede usar por ejemplo con las directivas
        <code class="directive"><a href="./mod/mod_env.html#setenv">SetEnv</a></code> y <code class="directive"><a href="./mod/mod_env.html#passenv">PassEnv</a></code>.</p>

    <h3><a name="downgrade" id="downgrade">downgrade-1.0</a></h3>
        

        <p>Fuerza que la petición sea tratada como una petición
        HTTP/1.0 incluso si viene en una especificación posterior.</p>

    
    <h3><a name="force-no-vary" id="force-no-vary">force-no-vary</a></h3>
        

        <p>Hace que cualquier campo <code>Vary</code> se elimine de la
        cabecera de la respuesta antes de ser enviada al
        cliente. Algunos clientes no interpretan este campo
        correctamente (consulte la sección sobre <a href="misc/known_client_problems.html">problemas conocidos con
        clientes</a>); usar esta variable puede evitar esos
        problemas. Usar esta variable implica también el uso de
        <strong>force-response-1.0</strong>.</p>

    
    <h3><a name="force-response" id="force-response">force-response-1.0</a></h3>
        

      <p>Fuerza que la respuesta a una petición HTTP/1.0 se haga
      también según la especificación HTTP/1.0. Esto se
      implementó originalmente como resultado de un problema con
      los proxies de AOL. Algunos clientes HTTP/1.0 no se comportan
      correctamente cuando se les envía una respuesta HTTP/1.1, y
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
        está disponible ese idioma, se aplica el proceso de <a href="content-negotiation.html">negociación</a>
        normal.</p>

    

    <h3><a name="redirect-carefully" id="redirect-carefully">redirect-carefully</a></h3>
        

        <p>Fuerza que el servidor sea especialmente cuidadoso al
        enviar una redirección al cliente. Se usa normalmente
        cuando un cliente tiene un problema conocido tratando las
        redirecciones. Fue implementado originalmente por el problema
        que presentaba el software de WebFolders de Microsoft, que
        tenía problemas interpretando redirecciones originadas
        cuando se accedía a recursos servidos usando DAV.</p>

    

   <h3><a name="suppress-error-charset" id="suppress-error-charset">suppress-error-charset</a></h3>
       

    <p><em>Disponible en las versiones de Apache 2.0.40 y posteriores</em></p>

    <p>Cuando Apache efectúa una redirección en respuesta a la
    petición de un cliente, la respuesta incluye algún texto para que
    se muestre en caso de que el cliente no pueda seguir (o no siga)
    automáticamente la redirección. Apache normalmente etiqueta este
    texto siguiendo la codificación ISO-8859-1.</p> 

    <p>Sin embargo, si la redirección es a una página que
    usa una codificación diferente, algunas versiones de
    navegadores que no funcionan correctamente intentarán usar la
    codificación del texto de redirección en lugar de la de
    pagina a la que ha sido redireccionado. La consecuencia de esto
    puede ser, por ejemplo, que una página en griego no se
    muestre correctamente.</p>

    <p>Especificar un valor en esta variable de entorno hace que
    Apache omita la codificación en el texto que incluye con las
    redirecciones, y que esos navegadores que no funcionan
    correctamente muestren correctamente la página de destino.</p>

   

  </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="examples" id="examples">Ejemplos</a></h2>
    

    <h3><a name="misbehaving" id="misbehaving">Cómo cambiar el comportamiento de clientes que se
        comportan de manera inapropiada</a></h3>
        

        <p>Recomendamos que incluya las siguentes líneas en el
        fichero httpd.conf para evitar problemas conocidos</p>
<div class="example"><pre>

#
# Las siguientes directivas modifican el comportamiento normal de las respuestas HTTP.
# La primera directiva desactiva keepalive para Netscape 2.x y para navegadores 
# que la simulan. Hay problemas conocidos con esos navegadores.
# La segunda directiva es para Microsoft Internet Explorer 4.0b2
# que tiene un fallo en la implemantación de HTTP/1.1 y no soporta
# keepalive adecuadamente cuando se usan respuestas 301 ó 302 (redirecciones).
#
BrowserMatch "Mozilla/2" nokeepalive
BrowserMatch "MSIE 4\.0b2;" nokeepalive downgrade-1.0 force-response-1.0

#
# La siguiente directiva desactiva las respuestas HTTP/1.1 para navegadores que
# violan la especificación HTTP/1.0 @@@ by not being able to grok a
# basic 1.1 response @@@.
#
BrowserMatch "RealPlayer 4\.0" force-response-1.0
BrowserMatch "Java/1\.0" force-response-1.0
BrowserMatch "JDK/1\.0" force-response-1.0</pre></div>

    
    <h3><a name="no-img-log" id="no-img-log">No almacenar entradas en registro de acceso para las
        imágenes</a></h3>
        

        <p>Este ejemplo evita que las peticiones de imágenes
        aparezcan en el registro de acceso. Puede ser modificada
        fácilmente para evitar que se registren entradas de
        peticiones de directorios, o provenientes de determinados
        clientes.</p>

        <div class="example"><pre> 
SetEnvIf Request_URI \.gif image-request
SetEnvIf Request_URI \.jpg image-request 
SetEnvIf Request_URI \.png image-request 
CustomLog logs/access_log common env=!image-request</pre></div>

    
    <h3><a name="image-theft" id="image-theft">Evitar el "robo de imagenes"</a></h3>
        

        <p>Este ejemplo muestra como evitar que otras webs usen las
        imágenes de su servidor para sus páginas. Esta
        configuración no se recomienda, pero puede funcionar en
        determinadas circunstancias. Asumimos que que todas sus
        imágenes están en un directorio llamado
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

        <p>Para obtener más información sobre esta
        técnica, consulte el tutorial de ApacheToday " <a href="http://apachetoday.com/news_story.php3?ltsn=2000-06-14-002-01-PS">
        Keeping Your Images from Adorning Other Sites</a>".</p>
         </div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="./en/env.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/env.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="./fr/env.html" hreflang="fr" rel="alternate" title="Français">&nbsp;fr&nbsp;</a> |
<a href="./ja/env.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/env.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a></p>
</div><div id="footer">
<p class="apache">Copyright 1995-2005 The Apache Software Foundation or its licensors, as applicable.<br />Licencia bajo los términos de la <a href="http://www.apache.org/licenses/LICENSE-2.0">Apache License, Version 2.0</a>.</p>
<p class="menu"><a href="./mod/">Módulos</a> | <a href="./mod/directives.html">Directivas</a> | <a href="./faq/">Preguntas Frecuentes</a> | <a href="./glossary.html">Glosario</a> | <a href="./sitemap.html">Mapa de este sitio web</a></p></div>
</body></html>