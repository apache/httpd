<!DOCTYPE html SYSTEM "about:legacy-compat">
<html lang="es"><head><META http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<meta content="width=device-width, initial-scale=1" name="viewport">
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Tutorial de Apache: Contenido Din&aacute;mico con CGI - Servidor HTTP Apache Versi&oacute;n 2.4</title>
<link href="../style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet">
<link href="../style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size">
<link href="../style/css/manual-print.css" rel="stylesheet" media="print" type="text/css"><link rel="stylesheet" type="text/css" href="../style/css/prettify.css">
<script src="../style/scripts/prettify.min.js">
</script>

<link href="../images/favicon.png" rel="shortcut icon"></head>
<body id="manual-page"><div id="page-header">
<p class="menu"><a href="../mod/">M&oacute;dulos</a> | <a href="../mod/quickreference.html">Directivas</a> | <a href="https://cwiki.apache.org/confluence/display/httpd/FAQ">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa del sitio web</a> | <a href="https://bz.apache.org/bugzilla/enter_bug.cgi?product=Apache%20httpd-2">Reportar un error</a></p>
<p class="apache">Versi&oacute;n 2.4 del Servidor HTTP Apache</p>
<img alt="" src="../images/feather.png"></div>
<div class="up"><a href="./"><img title="<-" alt="<-" src="../images/left.gif"></a></div>
<div id="path">
<a href="https://www.apache.org/">Apache</a> &gt; <a href="https://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="https://httpd.apache.org/docs/">Documentaci&oacute;n</a> &gt; <a href="../">Versi&oacute;n 2.4</a> &gt; <a href="./">How-To / Tutoriales</a></div><div id="page-content"><div id="preamble"><h1>Tutorial de Apache: Contenido Din&aacute;mico con CGI</h1>
<button aria-label="Toggle language list" class="lang-toggle"><svg xmlns="http://www.w3.org/2000/svg" stroke-width="2" stroke="currentColor" fill="none" viewBox="0 0 24 24" height="16" width="16"><circle r="10" cy="12" cx="12"/><line y2="12" x2="22" y1="12" x1="2"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></button>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="../en/howto/cgi.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/howto/cgi.html" title="Espa&ntilde;ol">&nbsp;es&nbsp;</a> |
<a href="../fr/howto/cgi.html" hreflang="fr" rel="alternate" title="Fran&ccedil;ais">&nbsp;fr&nbsp;</a> |
<a href="../ja/howto/cgi.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="../ko/howto/cgi.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a></p>
</div>
<div class="outofdate">Esta traducci&oacute;n podr&iacute;a estar
            obsoleta. Consulte la versi&oacute;n en ingl&eacute;s de la
            documentaci&oacute;n para comprobar si se han producido cambios
            recientemente.</div>
</div>
<div id="quickview"><ul id="toc"><li><img alt="" src="../images/down.gif"> <a href="#intro">Introducci&oacute;n</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#configuring">Configurando Apache para permitir CGI</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#writing">Escribiendo un programa CGI</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#troubleshoot">&iexcl;Pero todav&iacute;a no funciona!</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#behindscenes">&iquest;Qu&eacute; ocurre entre bastidores?</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#libraries">M&oacute;dulos/librer&iacute;as CGI</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#moreinfo">Para m&aacute;s informaci&oacute;n</a></li>
</ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="intro">Introducci&oacute;n <a title="Enlace permanente" href="#intro" class="permalink">&para;</a></h2>
	    
		<table class="related"><tr><th>M&oacute;dulos Relacionados</th><th>Directivas Relacionadas</th></tr><tr><td><ul><li><code class="module"><a href="../mod/mod_alias.html">mod_alias</a></code></li><li><code class="module"><a href="../mod/mod_cgi.html">mod_cgi</a></code></li><li><code class="module"><a href="../mod/mod_cgid.html">mod_cgid</a></code></li></ul></td><td><ul><li><code class="directive"><a href="../mod/mod_mime.html#addhandler">AddHandler</a></code></li><li><code class="directive"><a href="../mod/core.html#options">Options</a></code></li><li><code class="directive"><a href="../mod/mod_alias.html#scriptalias">ScriptAlias</a></code></li></ul></td></tr></table>

    	<p>CGI (Common Gateway Interface) es un m&eacute;todo por el cual
		un servidor web puede interactuar con programas externos de 
		generaci&oacute;n de contenido, a ellos nos referimos com&uacute;nmente como 
		programas CGI o scripts CGI. Es el m&eacute;todo m&aacute;s com&uacute;n y sencillo de
        mostrar contenido din&aacute;mico en su sitio web. Este documento es una 
		introducci&oacute;n para configurar CGI en su servidor web Apache, y de
		iniciaci&oacute;n para escribir programas CGI.</p>
	</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="configuring">Configurando Apache para permitir CGI <a title="Enlace permanente" href="#configuring" class="permalink">&para;</a></h2>
		

        <p>Para conseguir que sus programas CGI funcionen correctamente,
	    deber&aacute; configurar Apache para que permita la ejecuci&oacute;n de CGI. Hay
	    distintas formas de hacerlo.</p>

        <div class="warning">Nota: Si Apache ha sido compilado con soporte
        de m&oacute;dulos compartidos, necesitar&aacute; que el m&oacute;dulo de CGI est&eacute; cargado;
        en su <code>httpd.conf</code> tiene que asegurarse de que la directiva
        <code class="directive"><a href="../mod/mod_so.html#loadmodule">LoadModule</a></code>
        no ha sido comentada. Una directiva configurada correctamente ser&iacute;a as&iacute;:
            
            <pre class="prettyprint lang-config">LoadModule cgid_module modules/mod_cgid.so</pre>


        En Windows, o si usa un mpm que no es multihilo, como prefork, una 
        directiva configurada correctamente podr&iacute;a definirse as&iacute;: 

        <pre class="prettyprint lang-config">LoadModule cgi_module modules/mod_cgi.so</pre>
</div>

        <h3 id="scriptalias">ScriptAlias</h3>
            

            <p>La directiva
            <code class="directive"><a href="../mod/mod_alias.html#scriptalias">ScriptAlias</a></code>
            indica a Apache que un directorio se ha configurado espec&iacute;ficamente
            para programas CGI. Apache asumir&aacute; que cada fichero en este 
            directorio es un programa CGI, e intentar&aacute; ejecutarlos cuando un
            cliente solicita este recurso.</p>
        
            <p>La directiva 
            <code class="directive"><a href="../mod/mod_alias.html#scriptalias">ScriptAlias</a></code> se puede 
            definir as&iacute;:</p>

            <pre class="prettyprint lang-config">ScriptAlias "/cgi-bin/" "/usr/local/apache2/cgi-bin/"</pre>

        
            <p>El ejemplo que se muestra es de un archivo de configuraci&oacute;n
            <code>httpd.conf</code> por defecto si usted instal&oacute; Apache
            en la ubicaci&oacute;n por defecto. La directiva
            <code class="directive"><a href="../mod/mod_alias.html#scriptalias">ScriptAlias</a></code> es muy 
            parecida a la directiva <code class="directive"><a href="../mod/mod_alias.html#alias">Alias</a></code>,
            &eacute;sta define un prefijo de URL que se enlaza a un directorio 
            en particular. <code class="directive">Alias</code> y
            <code class="directive">ScriptAlias</code> se usan generalmente para 
            directorios que se encuentran fuera del directorio 
            <code class="directive"><a href="../mod/core.html#documentroot">DocumentRoot</a></code>. La diferencia
            entre <code class="directive">Alias</code> y <code class="directive">ScriptAlias</code>
            es que en <code class="directive">ScriptAlias</code> cualquier elemento
            debajo de ese prefijo de URL ser&aacute; considerado un programa CGI. As&iacute;, 
            el ejemplo de m&aacute;s arriba le indica a Apache que
            cualquier solicitud para un recurso que comience con 
            <code>/cgi-bin/</code> deber&iacute;a servirse desde el directorio
            <code>/usr/local/apache2/cgi-bin/</code>, y deber&iacute;a tratarse como un
            programa CGI.</p>

            <p>Por ejemplo, si se solicita la URL
            <code>http://www.example.com/cgi-bin/test.pl</code>,
            Apache intentar&aacute; ejecutar el archivo
            <code>/usr/local/apache2/cgi-bin/test.pl</code> y dar
            el resultado. Por supuesto el archivo debe existir y ser ejecutable, 
            y dar el resultado de una manera espec&iacute;fica o Apache devolver&aacute;
            un mensaje de error.</p>
        

        <h3 id="nonscriptalias">CGI fuera de directorios ScriptAlias</h3>
            

            <p>Los programas CGI habitualmente se restringen a los directorios de
            <code class="directive"><a href="../mod/mod_alias.html#scriptalias">ScriptAlias</a></code> por razones de
            seguridad. De esta manera, los administradores pueden controlar de una
            manera m&aacute;s segura quien puede ejecutar programas CGI. Aun as&iacute;, si no
            se toman suficientes precauciones, no hay ninguna raz&oacute;n por la que
            programas CGI no se puedan ejecutar desde directorios seleccionados de 
            manera arbitraria. Por ejemplo, quiz&aacute;s quiera permitir que usuarios del
            sistema tengan contenido web en sus directorios home con la directiva
            <code class="directive"><a href="../mod/mod_userdir.html#userdir">UserDir</a></code>. Si quieren 
            tener sus propios programas CGI, pero no tienen acceso al directorio 
            principal <code>cgi-bin</code>, necesitar&aacute;n ser capaces de 
            ejecutar sus scripts CGI en alg&uacute;n otro sitio.</p>
      
            <p>Hay dos pasos a seguir para permitir la ejecuci&oacute;n CGI en directorios
            seleccionados de manera arbitraria. Primero, el handler 
            <code>cgi-script</code> debe estar activado usando la directiva 
            <code class="directive"><a href="../mod/mod_mime.html#addhandler">AddHandler</a></code> o la directiva 
            <code class="directive"><a href="../mod/core.html#sethandler">SetHandler</a></code>. Segundo, el par&aacute;metro
            <code>ExecCGI</code> debe estar definido en la directiva
            <code class="directive"><a href="../mod/core.html#options">Options</a></code>.</p>
        

        <h3 id="options">Usando Options de manera expl&iacute;cita para permitir ejecuci&oacute;n de 
            CGI</h3>
            

            <p>Puede usar la directiva 
            <code class="directive"><a href="../mod/core.html#options">Options</a></code>, en el archivo de 
            configuraci&oacute;n principal para especificar que se permite la ejecuci&oacute;n 
            de CGI en un directorio en particular:</p>

            <pre class="prettyprint lang-config">&lt;Directory "/usr/local/apache2/htdocs/somedir"&gt;
    Options +ExecCGI
&lt;/Directory&gt;</pre>

            
            <p>Esta directiva de aqu&iacute; arriba le indica a Apache que debe 
            permitir la ejecuci&oacute;n de archivos CGI. Tambi&eacute;n necesitar&aacute; indicarle 
            al servidor que los archivos son archivos CGI. La directiva 
            <code class="directive"><a href="../mod/mod_mime.html#addhandler">AddHandler</a></code> le indica al 
            servidor que debe tratar a todos los archivos con la extensi&oacute;n 
            <code>cgi</code> o <code>pl</code> como programas CGI:</p>

            <pre class="prettyprint lang-config">AddHandler cgi-script .cgi .pl</pre>

        

        <h3 id="htaccess">Ficheros .htaccess</h3>
            

            <p>El <a href="htaccess.html">tutorial <code>.htaccess</code></a>
            ense&ntilde;a como activar programas CGI si no tienes acceso a 
            <code>httpd.conf</code>.</p>
        

        <h3 id="userdir">Directorios de Usuario</h3>
            

            <p>Para permitir la ejecuci&oacute;n de programas CGI para cualquier 
            archivo que acabe en <code>.cgi</code> en directorios de usuario, 
            puedes usar la siguiente configuraci&oacute;n:</p>

            <pre class="prettyprint lang-config">&lt;Directory "/home/*/public_html"&gt;
    Options +ExecCGI
    AddHandler cgi-script .cgi
&lt;/Directory&gt;</pre>


            <p>Si quiere designar un subdirectorio <code>cgi-bin</code> dentro 
            de un directorio de usuario en el que todos los ficheros ser&aacute;n 
            tratados como un programa CGI, puede usar lo siguiente:</p>

            <pre class="prettyprint lang-config">&lt;Directory "/home/*/public_html/cgi-bin"&gt;
    Options ExecCGI
    SetHandler cgi-script
&lt;/Directory&gt;</pre>

        
    </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="writing">Escribiendo un programa CGI <a title="Enlace permanente" href="#writing" class="permalink">&para;</a></h2>
        

        <p>Hay dos diferencias principales entre programaci&oacute;n ``regular'' y 
        programaci&oacute;n en CGI.</p>

        <p>Primera, el resultado al completo de tu programa CGI debe estar 
        precedido de una cabecera <a class="glossarylink" href="../glossary.html#mime-type" title="ver glosario">MIME-type</a>. Esta
        cabecera HTTP le indica al cliente que tipo de contenido est&aacute;
        recibiendo. La mayor parte de las veces, &eacute;sto ser&aacute; algo como:</p>

        <div class="example"><p><code>
            Content-type: text/html
        </code></p></div>

        <p>Segunda, el resultado debe estar en formato HTML, o cualquier 
        otro formato que su navegador sea capaz de mostrar. La mayor
        parte de las veces, ser&aacute; HTML, pero otras escribir&aacute; un programa
        CGI que devuelve una imagen gif, u otro contenido no-HTML.</p>

        <p>Aparte de estas dos cosas, escribir un programa en CGI se 
        parecer&aacute; bastante a cualquier otro programa que vaya a escribir.
        </p>


        <h3 id="firstcgi">Su primer programa CGI</h3>
            

            <p>A continuaci&oacute;n podr&aacute; ver un ejemplo de programa CGI que muestra
            una l&iacute;nea de texto en su navegador. Escriba lo siguiente, 
            gu&aacute;rdelo en un archivo con el nombre <code>first.pl</code>, y 
            p&oacute;ngalo en su directorio <code>cgi-bin</code>.</p>

            <pre class="prettyprint lang-perl">#!/usr/bin/perl
print "Content-type: text/html\n\n";
print "Hola, Mundo.";</pre>


            <p>Incluso si Perl no le resulta familiar, podr&aacute; ver lo que est&aacute;
            ocurriendo aqu&iacute;. La primera l&iacute;nea le dice a Apache (o a
            cualquier shell en la que se est&eacute; ejecutando) que este programa
            puede ejecutarse con el int&eacute;rprete en la ubicaci&oacute;n
            <code>/usr/bin/perl</code>. La segunda l&iacute;nea imprime la
            declaraci&oacute;n de Content-Type que mencionamos antes, seguida de 
            dos pares de retornos de carro. Esto pone una l&iacute;nea en blanco 
            despu&eacute;s de la cabecera para indicar el final de las cabeceras
            HTTP, y el comienzo del cuerpo del contenido. La tercera 
            imprime la cadena de caracteres "Hola, Mundo.". Y ese es el 
            final del programa.</p>

            <p>Si lo abre con su navegador favorito y le dice que solicite la 
            direcci&oacute;n</p>

            <div class="example"><p><code>
                http://www.example.com/cgi-bin/first.pl
            </code></p></div>

            <p>o donde quiera que pusiera el archivo, ver&aacute; una l&iacute;nea
            <code>Hola, Mundo.</code> aparecer&aacute;n la ventana del navegador. No es 
            muy emocionante, pero una vez que consiga que funcione podr&aacute; hacer 
            lo mismo con casi cualquier programa.</p>
        
    </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="troubleshoot">&iexcl;Pero todav&iacute;a no funciona! <a title="Enlace permanente" href="#troubleshoot" class="permalink">&para;</a></h2>
        

        <p>Hay 4 cosas b&aacute;sicas que puede llegar a ver en su navegador cuando
        intenta acceder a un programa CGI desde la web:</p>

        <dl>
            <dt>El resultado del programa CGI</dt>
            <dd>&iexcl;Genial! Esto indica que todo funcion&oacute; correctamente. Si el
            resultado es correcto, pero el navegador no lo procesa
            correctamente, aseg&uacute;rese de que tiene especificado 
            correctamente el <code>Content-Type</code> en su programa 
            CGI.</dd>

            <dt>El c&oacute;digo fuente de su programa CGI o un mensaje del tipo 
            "POST Method Not Allowed".</dt>

            <dd>Eso significa que no ha configurado Apache de manera
            apropiada para interpretar su programa CGI. Relea la secci&oacute;n
            de <a href="#configuring">Configurando Apache</a> e intente
            encontrar qu&eacute; le falta.</dd>

            <dt>Un mensaje que empieza con "Forbidden"</dt>
            <dd>Eso significa que hay un problema de permisos. Compruebe el
            <a href="#errorlogs">Log de Errores de Apache</a> y la
            secci&oacute;n de m&aacute;s abajo de <a href="#permissions">Permisos de
            Fichero</a>.</dd>

            <dt>Un mensaje indicando "Internal Server Error"</dt>
            <dd>Si comprueba el <a href="#errorlogs">Log de errores de
            Apache</a>, probablemente encontrar&aacute; que indica "Premature 
            end of script headers", posiblemente acompa&ntilde;ado de otro 
            mensaje de error generado por su programa CGI. En este caso, 
            querr&aacute; comprobar cada una de las secciones de m&aacute;s adelante 
            para ver qu&eacute; impide que su programa CGI genere las cabeceras 
            HTTP adecuadas.</dd>
            </dl>

        <h3 id="permissions">Permisos de Fichero</h3>
            

            <p>Recuerde que el servidor no se ejecuta con su usuario. Es decir,
            cuando el servidor arranca, est&aacute; funcionando con un usuario sin
            privilegios, generalmente el usuario <code>nobody</code>, o
            <code>www-data</code>, as&iacute; que necesitar&aacute; permisos extra para
            ejecutar los archivos de los que usted es due&ntilde;o. Generalmente, 
            el m&eacute;todo para dar permisos suficientes para que se pueda 
            ejecutar con <code>nobody</code> es dar permisos de ejecuci&oacute;n a 
            todo el mundo en el fichero:</p>

            <div class="example"><p><code>
                chmod a+x first.pl
            </code></p></div>

            <p>Adem&aacute;s, si su programa lee desde o escribe a cualquier otro/s
            archivo/s, esos archivos necesitar&aacute;n tener los permisos correctos
            para permitir esas acciones.</p>

        

        <h3 id="pathinformation">Informaci&oacute;n de Ruta y Entorno</h3>
            

            <p>Cuando ejecuta un programa desde la l&iacute;nea de comandos, usted tiene
            cierta informaci&oacute;n que se le pasa a la shell sin que usted se
            percate de ello. Por ejemplo, usted tiene un <code>PATH</code>,
            que le indica a la shell d&oacute;nde debe buscar archivos a los que usted
            hace referencia.</p>

            <p>Cuando un programa se ejecuta a trav&eacute;s del servidor web como un
            programa CGI, puede que no tenga el mismo <code>PATH</code>. 
            Cualquier programa que invoque desde su programa CGI (como por
            ejemplo <code>sendmail</code>) necesitar&aacute; que se le indique la
            ruta absoluta, as&iacute; la shell puede encontrarlos cuando intenta 
            ejecutar su programa CGI.</p>

            <p>Una manifestaci&oacute;n com&uacute;n de esto es la ruta del int&eacute;rprete del 
            script (a menudo <code>perl</code>) indicado en la primera l&iacute;nea
            de su programa CGI, que parecer&aacute; algo como:</p>

            <pre class="prettyprint lang-perl">#!/usr/bin/perl</pre>


            <p>Aseg&uacute;rese de que &eacute;ste es de hecho el path de su int&eacute;rprete.</p>
            <div class="warning">
            Cuando edita scripts CGI en Windows, los caracteres de retorno de
            carro podr&iacute;an a&ntilde;adirse a la l&iacute;nea donde se especifica el int&eacute;rprete. 
            Aseg&uacute;rese de que los archivos se transfieren al servidor en modo 
            ASCII. Fallar en esto puede acabar con avisos del tipo "Command not 
            found" del Sistema Operativo, debido a que &eacute;ste no reconoce los 
            caracteres de final de l&iacute;nea interpretados como parte del nombre
            de fichero del int&eacute;rprete.
            </div>
        

        <h3 id="missingenv">Faltan Variables de Entorno</h3>
            

            <p>Si su programa CGI depende de <a href="#env">variables de entorno</a> no est&aacute;ndar, necesitar&aacute;
            asegurarse de que Apache pasa esas variables.</p>

            <p>Cuando no encuentra ciertas cabeceras HTTP del entorno, aseg&uacute;rese 
            de que est&aacute;n formateadas seg&uacute;n el 
            <a href="http://tools.ietf.org/html/rfc2616">RFC 2616</a>, 
            secci&oacute;n 4.2: Nombres de Cabeceras deben empezar con una letra, 
            seguida solo de letras, n&uacute;meros o gui&oacute;n. Cualquier cabecera 
            que no cumpla esta regla ser&aacute; ignorada de manera silenciosa.</p>

        

        <h3 id="syntaxerrors">Errores de Programa</h3>
            

            <p>La mayor parte de las veces cuando un programa CGI falla, es por un 
            problema en el programa mismo. Esto ocurre generalmente cuando se 
            maneja bien con "esto del CGI", y ya no comete los dos errores
            mencionados m&aacute;s arriba. Lo primero que hay que hacer es asegurarse
            de que su programa se ejecuta correctamente en l&iacute;nea de comandos 
            antes de probarlo a trav&eacute;s del servidor web.  Por ejemplo, 
            intente:</p>

            <div class="example"><p><code>
                cd /usr/local/apache2/cgi-bin<br>
                ./first.pl
            </code></p></div>

            <p>(No llame al int&eacute;rprete de <code>perl</code>. La consola y Apache 
            tienen que poder encontrar el int&eacute;rprete usando l&iacute;nea 
            <a href="#pathinformation">l&iacute;nea de informaci&oacute;n</a> en la primera 
            l&iacute;nea del script.)</p>

            <p>Lo primero que debe ver escrito por su programa es un conjunto de 
            cabeceras HTTP, incluyendo el <code>Content-Type</code>,
            seguido de una l&iacute;nea en blanco.  Si ve alguna otra cosa, Apache
            devolver&aacute; el error <code>Premature end of script headers</code> si
            intenta lanzar el script en el servidor web. Vea 
            <a href="#writing">Escribiendo un programa CGI</a> m&aacute;s arriba para
            m&aacute;s detalle.</p>
        

        <h3 id="errorlogs">Log de Errores</h3>
            

            <p>El log de errores es su amigo. Cualquier cosa que vaya mal generar&aacute; 
            un mensaje en el log de errores. Deber&iacute;a mirar siempre ah&iacute; primero. 
            Si el lugar donde est&aacute; alojando su sitio web no permite que acceda
            al log de errores, probablemente deber&iacute;a alojarlo en otro sitio.
            Aprenda a leer el log de errores y se dar&aacute; cuenta de que enseguida
            averiguar&aacute; el motivo del error y lo solucionar&aacute; r&aacute;pidamente.</p>
        

        <h3 id="suexec">Suexec</h3>
            

            <p>El programa de soporte <a href="../suexec.html">suexec</a> permite
            que programas CGI se ejecuten con permisos de usuario distintos,
            dependiendo del virtualhost o el directorio home donde se 
            encuentren. Suexec tiene una comprobaci&oacute;n de permisos muy estricta, 
            y cualquier fallo en esa comprobaci&oacute;n dar&aacute; como resultado un error
            con el mensaje <code>Premature end of script headers</code>.</p>

            <p>Para comprobar si est&aacute; usando Suexec, ejecute 
            <code>apachectl -V</code> y compruebe la ubicaci&oacute;n de 
            <code>SUEXEC_BIN</code>. Si Apache encuentra un binario 
            <code class="program"><a href="../programs/suexec.html">suexec</a></code> al arrancar, suexec se activar&aacute;.</p>

            <p>A menos que comprenda suxec perfectamente, no deber&iacute;a usarlo.
            Para desactivar suexec, basta con eliminar el binario 
            <code class="program"><a href="../programs/suexec.html">suexec</a></code> al que apunta <code>SUEXEC_BIN</code> y 
            reiniciar el servidor. Si despu&eacute;s de leer sobre 
            <a href="../suexec.html">suexec</a> todav&iacute;a quiere usarlo, entonces
            ejecute <code>suexec -V</code> para encontrar la ubicaci&oacute;n del 
            fichero log de suexec, y use ese log para encontrar que pol&iacute;tica no
            est&aacute; cumpliendo.</p>
        
    </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="behindscenes">&iquest;Qu&eacute; ocurre entre bastidores? <a title="Enlace permanente" href="#behindscenes" class="permalink">&para;</a></h2>
        

        <p>En cuanto tenga conocimiento avanzado de programaci&oacute;n CGI, le ser&aacute; 
        &uacute;til comprender m&aacute;s de lo que ocurre entre bastidores. 
        Espec&iacute;ficamente, c&oacute;mo el navegador y el servidor se comunican el uno
        con el otro. Porque aunque est&eacute; muy bien escribir un programa que 
        diga "Hola, Mundo.", no tiene una gran utilidad.</p>

        <h3 id="env">Variables de Entorno</h3>
            

            <p>Las variables de entorno son valores que est&aacute;n ah&iacute; cuando 
            usa el ordenador. Son cosas &uacute;tiles como el path (donde su ordenador
            busca el archivo espec&iacute;fico que se lanza cuando usted escribe un 
            comando), su nombre de usuario, el tipo de terminal que usa, etc. 
            Para una lista completa de la variables de entorno normales que se 
            se usan en su d&iacute;a a d&iacute;a escriba <code>env</code> en la l&iacute;nea de 
            comandos.</p>

            <p>Durante la transacci&oacute;n CGI, el servidor y el navegador tambi&eacute;n 
            configuran variables de entorno, y as&iacute; pueden comunicarse entre 
            ellos. Cosas como el tipo de navegador (Netscape, IE, Lynx), el tipo
            de servidor (Apache, IIS, WebSite), el nombre del programa CGI que
            se est&aacute; ejecutando, etc.</p>

            <p>Estas variables est&aacute;n disponibles para el programador de CGI, y son 
            la mitad de la historia de la comunicaci&oacute;n cliente-servidor. La 
            lista completa de las variables necesarias se encuentra en 
            <a href="http://www.ietf.org/rfc/rfc3875">el RFC de Common Gateway
            Interface</a>.</p>

            <p>Este sencillo programa CGI en Perl mostrar&aacute; todas las variables 
            de entorno que se est&aacute;n pasando entre el cliente y el navegador. Dos
            programas similares est&aacute;n incluidos en el directorio 
            <code>cgi-bin</code> de la distribuci&oacute;n de Apache. Tenga en cuenta
            que algunas variables son necesarias mientras que otras son 
            opcionales, as&iacute; que es posible que vea algunas variables que no 
            est&aacute;n en la lista oficial. Adicionalmente, Apache aporta distintas
            maneras diferentes para que pueda
            <a href="../env.html">a&ntilde;adir sus variables de entorno</a> a las 
            b&aacute;sicas que se proveen por defecto.</p>

            <pre class="prettyprint lang-perl">#!/usr/bin/perl
use strict;
use warnings;

print "Content-type: text/html\n\n";
          
foreach my $key (keys %ENV) {
    print "$key --&gt; $ENV{$key}&lt;br&gt;";
}</pre>

        

        <h3 id="stdin">STDIN y STDOUT</h3>
            

            <p>Otra comunicaci&oacute;n entre el servidor y el cliente ocurre en la 
            entrada est&aacute;ndar (<code>STDIN</code>) y la salida est&aacute;ndar 
            (<code>STDOUT</code>). En el contexto normal de cada d&iacute;a, 
            <code>STDIN</code> es la entrada con el teclado, o un fichero que se 
            le da a un programa para que act&uacute;e sobre &eacute;l, y <code>STDOUT</code>
            generalmente es la consola o la pantalla.</p>

            <p>Cuando hace <code>POST</code> con un formulario de web a un programa 
            CGI, los datos en ese formulario se empaquetan en un formato especial
            que se entrega a su programa CGI en el <code>STDIN</code>.
            Entonces el programa puede procesar la informaci&oacute;n como si le llegara
            desde el teclado, o desde un fichero.</p>

            <p>El "formato especial" es muy sencillo. Un nombre de campo y su 
            valor se asocian juntos con el signo igual (=), y pares de valores 
            se asocian juntos con el ampersand &oacute; et en espa&ntilde;ol (&amp;). 
            Caracteres inconvenientes como los espacios, ampersands y signos de 
            igual, se convierten en su equivalente hexadecimal para no impidan 
            el funcionamiento correcto del programa. La cadena de datos al 
            completo ser&aacute; algo como:</p>

  <div class="example"><p><code>
        name=Rich%20Bowen&amp;city=Lexington&amp;state=KY&amp;sidekick=Squirrel%20Monkey
  </code></p></div>

            <p>A veces tendr&aacute; este tipo de cadena de caracteres al final de una 
            URL. Cuando esto ocurre, el servidor pone esa cadena en una variable 
            de entorno que se llama <code>QUERY_STRING</code>. Esto se llama 
            solicitud <code>GET</code>. Su formulario HTML especifica si se usa 
            un <code>GET</code> o un <code>POST</code> para entregar la 
            informaci&oacute;n, configurando el atributo <code>METHOD</code> en la 
            etiqueta <code>FORM</code>.</p>

            <p>Su programa es el responsable de convertir esa cadena de 
            caracteres en informaci&oacute;n &uacute;til. Afortunadamente, hay librer&iacute;as y 
            m&oacute;dulos disponibles que ayudan a procesar la informaci&oacute;n, as&iacute; como a 
            gestionar los distintos aspectos de su programa CGI.</p>
        
    </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="libraries">M&oacute;dulos/librer&iacute;as CGI <a title="Enlace permanente" href="#libraries" class="permalink">&para;</a></h2>
        

        <p>Cuando escribe programas CGI, deber&iacute;a considerar usar una librer&iacute;a de
        c&oacute;digo, o m&oacute;dulo, para hacer todo el trabajo m&aacute;s arduo por usted.
        Esto lleva a tener menos errores y un desarrollo de c&oacute;digo m&aacute;s 
        r&aacute;pido.</p>

        <p>Si est&aacute; escribiendo un programa CGI en Perl, existen m&oacute;dulos 
        disponibles en <a href="http://www.cpan.org/">CPAN</a>. El m&oacute;dulo m&aacute;s
        conocido para este prop&oacute;sito es <code>CGI.pm</code>. Quiz&aacute;s quiera
        considerar <code>CGI::Lite</code>, que implementa una funcionalidad 
        m&iacute;nima, que es todo lo que se necesita en la mayor&iacute;a de los programas.</p>

        <p>Si est&aacute; escribiendo programas CGI en C, hay varidad de opciones. Una
        de estas es la librer&iacute;a <code>CGIC</code>, de
        <a href="http://www.boutell.com/cgic/">http://www.boutell.com/cgic/</a>.
        </p>
    </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="moreinfo">Para m&aacute;s informaci&oacute;n <a title="Enlace permanente" href="#moreinfo" class="permalink">&para;</a></h2>
        

        <p>La especificaci&oacute;n actual de CGI est&aacute; disponible en el
        <a href="http://www.ietf.org/rfc/rfc3875">RFC de Common Gateway
        Interface</a>.</p>

        <p>Cuando env&iacute;e una pregunta sobre un problema de CGI, o bien a una 
        lista de correo, o a un grupo de noticias, aseg&uacute;rese de que facilita suficiente
        informaci&oacute;n de lo que ha ocurrido, de lo que espera que ocurra, y de 
        lo que est&aacute; ocurriendo en su lugar que es diferente, el servidor que 
        est&aacute; ejecutando, en qu&eacute; lenguaje CGI est&aacute; hecho su programa, y si es
        posible, el c&oacute;digo que falla. Esto har&aacute; encontrar el problema mucho m&aacute;s 
        f&aacute;cil.</p>

        <p>Tenga en cuenta que las preguntas sobre problemas CGI 
        <strong>nunca</strong> deber&iacute;an enviarse a la base de datos de bugs de
        bugs de Apache a menos que est&eacute; seguro de haber encontrado un 
        problema en el c&oacute;digo fuente de Apache.</p>
    </div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="../en/howto/cgi.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/howto/cgi.html" title="Espa&ntilde;ol">&nbsp;es&nbsp;</a> |
<a href="../fr/howto/cgi.html" hreflang="fr" rel="alternate" title="Fran&ccedil;ais">&nbsp;fr&nbsp;</a> |
<a href="../ja/howto/cgi.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="../ko/howto/cgi.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a></p>
</div><div id="footer">
<p class="apache">Copyright 2026 The Apache Software Foundation.<br>Licencia bajo los t&eacute;rminos de la <a href="https://www.apache.org/licenses/LICENSE-2.0">Apache License, Version 2.0</a>.</p>
<p class="menu"><a href="../mod/">M&oacute;dulos</a> | <a href="../mod/quickreference.html">Directivas</a> | <a href="https://cwiki.apache.org/confluence/display/httpd/FAQ">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa del sitio web</a> | <a href="https://bz.apache.org/bugzilla/enter_bug.cgi?product=Apache%20httpd-2">Reportar un error</a></p></div><script><!--//--><![CDATA[//><!--
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