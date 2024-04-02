<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es" xml:lang="es"><head>
<meta content="text/html; charset=ISO-8859-1" http-equiv="Content-Type" />
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Tutorial de Apache: Contenido Din&#225;mico con CGI - Servidor HTTP Apache Versi&#243;n 2.4</title>
<link href="../style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet" />
<link href="../style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size" />
<link href="../style/css/manual-print.css" rel="stylesheet" media="print" type="text/css" /><link rel="stylesheet" type="text/css" href="../style/css/prettify.css" />
<script src="../style/scripts/prettify.min.js" type="text/javascript">
</script>

<link href="../images/favicon.ico" rel="shortcut icon" /></head>
<body id="manual-page"><div id="page-header">
<p class="menu"><a href="../mod/">M&#243;dulos</a> | <a href="../mod/directives.html">Directivas</a> | <a href="http://wiki.apache.org/httpd/FAQ">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa del sitio web</a></p>
<p class="apache">Versi&#243;n 2.4 del Servidor HTTP Apache</p>
<img alt="" src="../images/feather.png" /></div>
<div class="up"><a href="./"><img title="&lt;-" alt="&lt;-" src="../images/left.gif" /></a></div>
<div id="path">
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs/">Documentaci&#243;n</a> &gt; <a href="../">Versi&#243;n 2.4</a> &gt; <a href="./">How-To / Tutoriales</a></div><div id="page-content"><div id="preamble"><h1>Tutorial de Apache: Contenido Din&#225;mico con CGI</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="../en/howto/cgi.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/howto/cgi.html" title="Espa&#241;ol">&nbsp;es&nbsp;</a> |
<a href="../fr/howto/cgi.html" hreflang="fr" rel="alternate" title="Fran&#231;ais">&nbsp;fr&nbsp;</a> |
<a href="../ja/howto/cgi.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="../ko/howto/cgi.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a></p>
</div>
<div class="outofdate">Esta traducci&#243;n podr&#237;a estar
            obsoleta. Consulte la versi&#243;n en ingl&#233;s de la
            documentaci&#243;n para comprobar si se han producido cambios
            recientemente.</div>
</div>
<div id="quickview"><a href="https://www.apache.org/foundation/contributing.html" class="badge"><img src="https://www.apache.org/images/SupportApache-small.png" alt="Support Apache!" /></a><ul id="toc"><li><img alt="" src="../images/down.gif" /> <a href="#intro">Introducci&#243;n</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#configuring">Configurando Apache para permitir CGI</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#writing">Escribiendo un programa CGI</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#troubleshoot">&#161;Pero todav&#237;a no funciona!</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#behindscenes">&#191;Qu&#233; ocurre entre bastidores?</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#libraries">M&#243;dulos/librer&#237;as CGI</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#moreinfo">Para m&#225;s informaci&#243;n</a></li>
</ul><h3>Consulte tambi&#233;n</h3><ul class="seealso"><li><a href="#comments_section">Comentarios</a></li></ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="intro" id="intro">Introducci&#243;n</a></h2>
	    
		<table class="related"><tr><th>M&#243;dulos Relacionados</th><th>Directivas Relacionadas</th></tr><tr><td><ul><li><code class="module"><a href="../mod/mod_alias.html">mod_alias</a></code></li><li><code class="module"><a href="../mod/mod_cgi.html">mod_cgi</a></code></li><li><code class="module"><a href="../mod/mod_cgid.html">mod_cgid</a></code></li></ul></td><td><ul><li><code class="directive"><a href="../mod/mod_mime.html#addhandler">AddHandler</a></code></li><li><code class="directive"><a href="../mod/core.html#options">Options</a></code></li><li><code class="directive"><a href="../mod/mod_alias.html#scriptalias">ScriptAlias</a></code></li></ul></td></tr></table>

    	<p>CGI (Common Gateway Interface) es un m&#233;todo por el cual
		un servidor web puede interactuar con programas externos de 
		generaci&#243;n de contenido, a ellos nos referimos com&#250;nmente como 
		programas CGI o scripts CGI. Es el m&#233;todo m&#225;s com&#250;n y sencillo de
        mostrar contenido din&#225;mico en su sitio web. Este documento es una 
		introducci&#243;n para configurar CGI en su servidor web Apache, y de
		iniciaci&#243;n para escribir programas CGI.</p>
	</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="configuring" id="configuring">Configurando Apache para permitir CGI</a></h2>
		

        <p>Para conseguir que sus programas CGI funcionen correctamente,
	    deber&#225; configurar Apache para que permita la ejecuci&#243;n de CGI. Hay
	    distintas formas de hacerlo.</p>

        <div class="warning">Nota: Si Apache ha sido compilado con soporte
        de m&#243;dulos compartidos, necesitar&#225; que el m&#243;dulo de CGI est&#233; cargado;
        en su <code>httpd.conf</code> tiene que asegurarse de que la directiva
        <code class="directive"><a href="../mod/mod_so.html#loadmodule">LoadModule</a></code>
        no ha sido comentada. Una directiva configurada correctamente ser&#237;a as&#237;:
            
            <pre class="prettyprint lang-config">LoadModule cgid_module modules/mod_cgid.so</pre>


        En Windows, o si usa un mpm que no es multihilo, como prefork, una 
        directiva configurada correctamente podr&#237;a definirse as&#237;: 

        <pre class="prettyprint lang-config">LoadModule cgi_module modules/mod_cgi.so</pre>
</div>

        <h3><a name="scriptalias" id="scriptalias">ScriptAlias</a></h3>
            

            <p>La directiva
            <code class="directive"><a href="../mod/mod_alias.html#scriptalias">ScriptAlias</a></code>
            indica a Apache que un directorio se ha configurado espec&#237;ficamente
            para programas CGI. Apache asumir&#225; que cada fichero en este 
            directorio es un programa CGI, e intentar&#225; ejecutarlos cuando un
            cliente solicita este recurso.</p>
        
            <p>La directiva 
            <code class="directive"><a href="../mod/mod_alias.html#scriptalias">ScriptAlias</a></code> se puede 
            definir as&#237;:</p>

            <pre class="prettyprint lang-config">ScriptAlias "/cgi-bin/" "/usr/local/apache2/cgi-bin/"</pre>

        
            <p>El ejemplo que se muestra es de un archivo de configuraci&#243;n
            <code>httpd.conf</code> por defecto si usted instal&#243; Apache
            en la ubicaci&#243;n por defecto. La directiva
            <code class="directive"><a href="../mod/mod_alias.html#scriptalias">ScriptAlias</a></code> es muy 
            parecida a la directiva <code class="directive"><a href="../mod/mod_alias.html#alias">Alias</a></code>,
            &#233;sta define un prefijo de URL que se enlaza a un directorio 
            en particular. <code class="directive">Alias</code> y
            <code class="directive">ScriptAlias</code> se usan generalmente para 
            directorios que se encuentran fuera del directorio 
            <code class="directive"><a href="../mod/core.html#documentroot">DocumentRoot</a></code>. La diferencia
            entre <code class="directive">Alias</code> y <code class="directive">ScriptAlias</code>
            es que en <code class="directive">ScriptAlias</code> cualquier elemento
            debajo de ese prefijo de URL ser&#225; considerado un programa CGI. As&#237;, 
            el ejemplo de m&#225;s arriba le indica a Apache que
            cualquier solicitud para un recurso que comience con 
            <code>/cgi-bin/</code> deber&#237;a servirse desde el directorio
            <code>/usr/local/apache2/cgi-bin/</code>, y deber&#237;a tratarse como un
            programa CGI.</p>

            <p>Por ejemplo, si se solicita la URL
            <code>http://www.example.com/cgi-bin/test.pl</code>,
            Apache intentar&#225; ejecutar el archivo
            <code>/usr/local/apache2/cgi-bin/test.pl</code> y dar
            el resultado. Por supuesto el archivo debe existir y ser ejecutable, 
            y dar el resultado de una manera espec&#237;fica o Apache devolver&#225;
            un mensaje de error.</p>
        

        <h3><a name="nonscriptalias" id="nonscriptalias">CGI fuera de directorios ScriptAlias</a></h3>
            

            <p>Los programas CGI habitualmente se restringen a los directorios de
            <code class="directive"><a href="../mod/mod_alias.html#scriptalias">ScriptAlias</a></code> por razones de
            seguridad. De esta manera, los administradores pueden controlar de una
            manera m&#225;s segura quien puede ejecutar programas CGI. Aun as&#237;, si no
            se toman suficientes precauciones, no hay ninguna raz&#243;n por la que
            programas CGI no se puedan ejecutar desde directorios seleccionados de 
            manera arbitraria. Por ejemplo, quiz&#225;s quiera permitir que usuarios del
            sistema tengan contenido web en sus directorios home con la directiva
            <code class="directive"><a href="../mod/mod_userdir.html#userdir">UserDir</a></code>. Si quieren 
            tener sus propios programas CGI, pero no tienen acceso al directorio 
            principal <code>cgi-bin</code>, necesitar&#225;n ser capaces de 
            ejecutar sus scripts CGI en alg&#250;n otro sitio.</p>
      
            <p>Hay dos pasos a seguir para permitir la ejecuci&#243;n CGI en directorios
            seleccionados de manera arbitraria. Primero, el handler 
            <code>cgi-script</code> debe estar activado usando la directiva 
            <code class="directive"><a href="../mod/mod_mime.html#addhandler">AddHandler</a></code> o la directiva 
            <code class="directive"><a href="../mod/core.html#sethandler">SetHandler</a></code>. Segundo, el par&#225;metro
            <code>ExecCGI</code> debe estar definido en la directiva
            <code class="directive"><a href="../mod/core.html#options">Options</a></code>.</p>
        

        <h3><a name="options" id="options">Usando Options de manera expl&#237;cita para permitir ejecuci&#243;n de 
            CGI</a></h3>
            

            <p>Puede usar la directiva 
            <code class="directive"><a href="../mod/core.html#options">Options</a></code>, en el archivo de 
            configuraci&#243;n principal para especificar que se permite la ejecuci&#243;n 
            de CGI en un directorio en particular:</p>

            <pre class="prettyprint lang-config">&lt;Directory "/usr/local/apache2/htdocs/somedir"&gt;
    Options +ExecCGI
&lt;/Directory&gt;</pre>

            
            <p>Esta directiva de aqu&#237; arriba le indica a Apache que debe 
            permitir la ejecuci&#243;n de archivos CGI. Tambi&#233;n necesitar&#225; indicarle 
            al servidor que los archivos son archivos CGI. La directiva 
            <code class="directive"><a href="../mod/mod_mime.html#addhandler">AddHandler</a></code> le indica al 
            servidor que debe tratar a todos los archivos con la extensi&#243;n 
            <code>cgi</code> o <code>pl</code> como programas CGI:</p>

            <pre class="prettyprint lang-config">AddHandler cgi-script .cgi .pl</pre>

        

        <h3><a name="htaccess" id="htaccess">Ficheros .htaccess</a></h3>
            

            <p>El <a href="htaccess.html">tutorial <code>.htaccess</code></a>
            ense&#241;a como activar programas CGI si no tienes acceso a 
            <code>httpd.conf</code>.</p>
        

        <h3><a name="userdir" id="userdir">Directorios de Usuario</a></h3>
            

            <p>Para permitir la ejecuci&#243;n de programas CGI para cualquier 
            archivo que acabe en <code>.cgi</code> en directorios de usuario, 
            puedes usar la siguiente configuraci&#243;n:</p>

            <pre class="prettyprint lang-config">&lt;Directory "/home/*/public_html"&gt;
    Options +ExecCGI
    AddHandler cgi-script .cgi
&lt;/Directory&gt;</pre>


            <p>Si quiere designar un subdirectorio <code>cgi-bin</code> dentro 
            de un directorio de usuario en el que todos los ficheros ser&#225;n 
            tratados como un programa CGI, puede usar lo siguiente:</p>

            <pre class="prettyprint lang-config">&lt;Directory "/home/*/public_html/cgi-bin"&gt;
    Options ExecCGI
    SetHandler cgi-script
&lt;/Directory&gt;</pre>

        
    </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="writing" id="writing">Escribiendo un programa CGI</a></h2>
        

        <p>Hay dos diferencias principales entre programaci&#243;n ``regular'' y 
        programaci&#243;n en CGI.</p>

        <p>Primera, el resultado al completo de tu programa CGI debe estar 
        precedido de una cabecera <a class="glossarylink" href="../glossary.html#mime-type" title="ver glosario">MIME-type</a>. Esta
        cabecera HTTP le indica al cliente que tipo de contenido est&#225;
        recibiendo. La mayor parte de las veces, &#233;sto ser&#225; algo como:</p>

        <div class="example"><p><code>
            Content-type: text/html
        </code></p></div>

        <p>Segunda, el resultado debe estar en formato HTML, o cualquier 
        otro formato que su navegador sea capaz de mostrar. La mayor
        parte de las veces, ser&#225; HTML, pero otras escribir&#225; un programa
        CGI que devuelve una imagen gif, u otro contenido no-HTML.</p>

        <p>Aparte de estas dos cosas, escribir un programa en CGI se 
        parecer&#225; bastante a cualquier otro programa que vaya a escribir.
        </p>


        <h3><a name="firstcgi" id="firstcgi">Su primer programa CGI</a></h3>
            

            <p>A continuaci&#243;n podr&#225; ver un ejemplo de programa CGI que muestra
            una l&#237;nea de texto en su navegador. Escriba lo siguiente, 
            gu&#225;rdelo en un archivo con el nombre <code>first.pl</code>, y 
            p&#243;ngalo en su directorio <code>cgi-bin</code>.</p>

            <pre class="prettyprint lang-perl">#!/usr/bin/perl
print "Content-type: text/html\n\n";
print "Hola, Mundo.";</pre>


            <p>Incluso si Perl no le resulta familiar, podr&#225; ver lo que est&#225;
            ocurriendo aqu&#237;. La primera l&#237;nea le dice a Apache (o a
            cualquier shell en la que se est&#233; ejecutando) que este programa
            puede ejecutarse con el int&#233;rprete en la ubicaci&#243;n
            <code>/usr/bin/perl</code>. La segunda l&#237;nea imprime la
            declaraci&#243;n de Content-Type que mencionamos antes, seguida de 
            dos pares de retornos de carro. Esto pone una l&#237;nea en blanco 
            despu&#233;s de la cabecera para indicar el final de las cabeceras
            HTTP, y el comienzo del cuerpo del contenido. La tercera 
            imprime la cadena de caracteres "Hola, Mundo.". Y ese es el 
            final del programa.</p>

            <p>Si lo abre con su navegador favorito y le dice que solicite la 
            direcci&#243;n</p>

            <div class="example"><p><code>
                http://www.example.com/cgi-bin/first.pl
            </code></p></div>

            <p>o donde quiera que pusiera el archivo, ver&#225; una l&#237;nea
            <code>Hola, Mundo.</code> aparecer&#225;n la ventana del navegador. No es 
            muy emocionante, pero una vez que consiga que funcione podr&#225; hacer 
            lo mismo con casi cualquier programa.</p>
        
    </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="troubleshoot" id="troubleshoot">&#161;Pero todav&#237;a no funciona!</a></h2>
        

        <p>Hay 4 cosas b&#225;sicas que puede llegar a ver en su navegador cuando
        intenta acceder a un programa CGI desde la web:</p>

        <dl>
            <dt>El resultado del programa CGI</dt>
            <dd>&#161;Genial! Esto indica que todo funcion&#243; correctamente. Si el
            resultado es correcto, pero el navegador no lo procesa
            correctamente, aseg&#250;rese de que tiene especificado 
            correctamente el <code>Content-Type</code> en su programa 
            CGI.</dd>

            <dt>El c&#243;digo fuente de su programa CGI o un mensaje del tipo 
            "POST Method Not Allowed".</dt>

            <dd>Eso significa que no ha configurado Apache de manera
            apropiada para interpretar su programa CGI. Relea la secci&#243;n
            de <a href="#configuring">Configurando Apache</a> e intente
            encontrar qu&#233; le falta.</dd>

            <dt>Un mensaje que empieza con "Forbidden"</dt>
            <dd>Eso significa que hay un problema de permisos. Compruebe el
            <a href="#errorlogs">Log de Errores de Apache</a> y la
            secci&#243;n de m&#225;s abajo de <a href="#permissions">Permisos de
            Fichero</a>.</dd>

            <dt>Un mensaje indicando "Internal Server Error"</dt>
            <dd>Si comprueba el <a href="#errorlogs">Log de errores de
            Apache</a>, probablemente encontrar&#225; que indica "Premature 
            end of script headers", posiblemente acompa&#241;ado de otro 
            mensaje de error generado por su programa CGI. En este caso, 
            querr&#225; comprobar cada una de las secciones de m&#225;s adelante 
            para ver qu&#233; impide que su programa CGI genere las cabeceras 
            HTTP adecuadas.</dd>
            </dl>

        <h3><a name="permissions" id="permissions">Permisos de Fichero</a></h3>
            

            <p>Recuerde que el servidor no se ejecuta con su usuario. Es decir,
            cuando el servidor arranca, est&#225; funcionando con un usuario sin
            privilegios, generalmente el usuario <code>nobody</code>, o
            <code>www-data</code>, as&#237; que necesitar&#225; permisos extra para
            ejecutar los archivos de los que usted es due&#241;o. Generalmente, 
            el m&#233;todo para dar permisos suficientes para que se pueda 
            ejecutar con <code>nobody</code> es dar permisos de ejecuci&#243;n a 
            todo el mundo en el fichero:</p>

            <div class="example"><p><code>
                chmod a+x first.pl
            </code></p></div>

            <p>Adem&#225;s, si su programa lee desde o escribe a cualquier otro/s
            archivo/s, esos archivos necesitar&#225;n tener los permisos correctos
            para permitir esas acciones.</p>

        

        <h3><a name="pathinformation" id="pathinformation">Informaci&#243;n de Ruta y Entorno</a></h3>
            

            <p>Cuando ejecuta un programa desde la l&#237;nea de comandos, usted tiene
            cierta informaci&#243;n que se le pasa a la shell sin que usted se
            percate de ello. Por ejemplo, usted tiene un <code>PATH</code>,
            que le indica a la shell d&#243;nde debe buscar archivos a los que usted
            hace referencia.</p>

            <p>Cuando un programa se ejecuta a trav&#233;s del servidor web como un
            programa CGI, puede que no tenga el mismo <code>PATH</code>. 
            Cualquier programa que invoque desde su programa CGI (como por
            ejemplo <code>sendmail</code>) necesitar&#225; que se le indique la
            ruta absoluta, as&#237; la shell puede encontrarlos cuando intenta 
            ejecutar su programa CGI.</p>

            <p>Una manifestaci&#243;n com&#250;n de esto es la ruta del int&#233;rprete del 
            script (a menudo <code>perl</code>) indicado en la primera l&#237;nea
            de su programa CGI, que parecer&#225; algo como:</p>

            <pre class="prettyprint lang-perl">#!/usr/bin/perl</pre>


            <p>Aseg&#250;rese de que &#233;ste es de hecho el path de su int&#233;rprete.</p>
            <div class="warning">
            Cuando edita scripts CGI en Windows, los caracteres de retorno de
            carro podr&#237;an a&#241;adirse a la l&#237;nea donde se especifica el int&#233;rprete. 
            Aseg&#250;rese de que los archivos se transfieren al servidor en modo 
            ASCII. Fallar en esto puede acabar con avisos del tipo "Command not 
            found" del Sistema Operativo, debido a que &#233;ste no reconoce los 
            caracteres de final de l&#237;nea interpretados como parte del nombre
            de fichero del int&#233;rprete.
            </div>
        

        <h3><a name="missingenv" id="missingenv">Faltan Variables de Entorno</a></h3>
            

            <p>Si su programa CGI depende de <a href="#env">variables de entorno</a> no est&#225;ndar, necesitar&#225;
            asegurarse de que Apache pasa esas variables.</p>

            <p>Cuando no encuentra ciertas cabeceras HTTP del entorno, aseg&#250;rese 
            de que est&#225;n formateadas seg&#250;n el 
            <a href="http://tools.ietf.org/html/rfc2616">RFC 2616</a>, 
            secci&#243;n 4.2: Nombres de Cabeceras deben empezar con una letra, 
            seguida solo de letras, n&#250;meros o gui&#243;n. Cualquier cabecera 
            que no cumpla esta regla ser&#225; ignorada de manera silenciosa.</p>

        

        <h3><a name="syntaxerrors" id="syntaxerrors">Errores de Programa</a></h3>
            

            <p>La mayor parte de las veces cuando un programa CGI falla, es por un 
            problema en el programa mismo. Esto ocurre generalmente cuando se 
            maneja bien con "esto del CGI", y ya no comete los dos errores
            mencionados m&#225;s arriba. Lo primero que hay que hacer es asegurarse
            de que su programa se ejecuta correctamente en l&#237;nea de comandos 
            antes de probarlo a trav&#233;s del servidor web.  Por ejemplo, 
            intente:</p>

            <div class="example"><p><code>
                cd /usr/local/apache2/cgi-bin<br />
                ./first.pl
            </code></p></div>

            <p>(No llame al int&#233;rprete de <code>perl</code>. La consola y Apache 
            tienen que poder encontrar el int&#233;rprete usando l&#237;nea 
            <a href="#pathinformation">l&#237;nea de informaci&#243;n</a> en la primera 
            l&#237;nea del script.)</p>

            <p>Lo primero que debe ver escrito por su programa es un conjunto de 
            cabeceras HTTP, incluyendo el <code>Content-Type</code>,
            seguido de una l&#237;nea en blanco.  Si ve alguna otra cosa, Apache
            devolver&#225; el error <code>Premature end of script headers</code> si
            intenta lanzar el script en el servidor web. Vea 
            <a href="#writing">Escribiendo un programa CGI</a> m&#225;s arriba para
            m&#225;s detalle.</p>
        

        <h3><a name="errorlogs" id="errorlogs">Log de Errores</a></h3>
            

            <p>El log de errores es su amigo. Cualquier cosa que vaya mal generar&#225; 
            un mensaje en el log de errores. Deber&#237;a mirar siempre ah&#237; primero. 
            Si el lugar donde est&#225; alojando su sitio web no permite que acceda
            al log de errores, probablemente deber&#237;a alojarlo en otro sitio.
            Aprenda a leer el log de errores y se dar&#225; cuenta de que enseguida
            averiguar&#225; el motivo del error y lo solucionar&#225; r&#225;pidamente.</p>
        

        <h3><a name="suexec" id="suexec">Suexec</a></h3>
            

            <p>El programa de soporte <a href="../suexec.html">suexec</a> permite
            que programas CGI se ejecuten con permisos de usuario distintos,
            dependiendo del virtualhost o el directorio home donde se 
            encuentren. Suexec tiene una comprobaci&#243;n de permisos muy estricta, 
            y cualquier fallo en esa comprobaci&#243;n dar&#225; como resultado un error
            con el mensaje <code>Premature end of script headers</code>.</p>

            <p>Para comprobar si est&#225; usando Suexec, ejecute 
            <code>apachectl -V</code> y compruebe la ubicaci&#243;n de 
            <code>SUEXEC_BIN</code>. Si Apache encuentra un binario 
            <code class="program"><a href="../programs/suexec.html">suexec</a></code> al arrancar, suexec se activar&#225;.</p>

            <p>A menos que comprenda suxec perfectamente, no deber&#237;a usarlo.
            Para desactivar suexec, basta con eliminar el binario 
            <code class="program"><a href="../programs/suexec.html">suexec</a></code> al que apunta <code>SUEXEC_BIN</code> y 
            reiniciar el servidor. Si despu&#233;s de leer sobre 
            <a href="../suexec.html">suexec</a> todav&#237;a quiere usarlo, entonces
            ejecute <code>suexec -V</code> para encontrar la ubicaci&#243;n del 
            fichero log de suexec, y use ese log para encontrar que pol&#237;tica no
            est&#225; cumpliendo.</p>
        
    </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="behindscenes" id="behindscenes">&#191;Qu&#233; ocurre entre bastidores?</a></h2>
        

        <p>En cuanto tenga conocimiento avanzado de programaci&#243;n CGI, le ser&#225; 
        &#250;til comprender m&#225;s de lo que ocurre entre bastidores. 
        Espec&#237;ficamente, c&#243;mo el navegador y el servidor se comunican el uno
        con el otro. Porque aunque est&#233; muy bien escribir un programa que 
        diga "Hola, Mundo.", no tiene una gran utilidad.</p>

        <h3><a name="env" id="env">Variables de Entorno</a></h3>
            

            <p>Las variables de entorno son valores que est&#225;n ah&#237; cuando 
            usa el ordenador. Son cosas &#250;tiles como el path (donde su ordenador
            busca el archivo espec&#237;fico que se lanza cuando usted escribe un 
            comando), su nombre de usuario, el tipo de terminal que usa, etc. 
            Para una lista completa de la variables de entorno normales que se 
            se usan en su d&#237;a a d&#237;a escriba <code>env</code> en la l&#237;nea de 
            comandos.</p>

            <p>Durante la transacci&#243;n CGI, el servidor y el navegador tambi&#233;n 
            configuran variables de entorno, y as&#237; pueden comunicarse entre 
            ellos. Cosas como el tipo de navegador (Netscape, IE, Lynx), el tipo
            de servidor (Apache, IIS, WebSite), el nombre del programa CGI que
            se est&#225; ejecutando, etc.</p>

            <p>Estas variables est&#225;n disponibles para el programador de CGI, y son 
            la mitad de la historia de la comunicaci&#243;n cliente-servidor. La 
            lista completa de las variables necesarias se encuentra en 
            <a href="http://www.ietf.org/rfc/rfc3875">el RFC de Common Gateway
            Interface</a>.</p>

            <p>Este sencillo programa CGI en Perl mostrar&#225; todas las variables 
            de entorno que se est&#225;n pasando entre el cliente y el navegador. Dos
            programas similares est&#225;n incluidos en el directorio 
            <code>cgi-bin</code> de la distribuci&#243;n de Apache. Tenga en cuenta
            que algunas variables son necesarias mientras que otras son 
            opcionales, as&#237; que es posible que vea algunas variables que no 
            est&#225;n en la lista oficial. Adicionalmente, Apache aporta distintas
            maneras diferentes para que pueda
            <a href="../env.html">a&#241;adir sus variables de entorno</a> a las 
            b&#225;sicas que se proveen por defecto.</p>

            <pre class="prettyprint lang-perl">#!/usr/bin/perl
use strict;
use warnings;

print "Content-type: text/html\n\n";
          
foreach my $key (keys %ENV) {
    print "$key --&gt; $ENV{$key}&lt;br&gt;";
}</pre>

        

        <h3><a name="stdin" id="stdin">STDIN y STDOUT</a></h3>
            

            <p>Otra comunicaci&#243;n entre el servidor y el cliente ocurre en la 
            entrada est&#225;ndar (<code>STDIN</code>) y la salida est&#225;ndar 
            (<code>STDOUT</code>). En el contexto normal de cada d&#237;a, 
            <code>STDIN</code> es la entrada con el teclado, o un fichero que se 
            le da a un programa para que act&#250;e sobre &#233;l, y <code>STDOUT</code>
            generalmente es la consola o la pantalla.</p>

            <p>Cuando hace <code>POST</code> con un formulario de web a un programa 
            CGI, los datos en ese formulario se empaquetan en un formato especial
            que se entrega a su programa CGI en el <code>STDIN</code>.
            Entonces el programa puede procesar la informaci&#243;n como si le llegara
            desde el teclado, o desde un fichero.</p>

            <p>El "formato especial" es muy sencillo. Un nombre de campo y su 
            valor se asocian juntos con el signo igual (=), y pares de valores 
            se asocian juntos con el ampersand &#243; et en espa&#241;ol (&amp;). 
            Caracteres inconvenientes como los espacios, ampersands y signos de 
            igual, se convierten en su equivalente hexadecimal para no impidan 
            el funcionamiento correcto del programa. La cadena de datos al 
            completo ser&#225; algo como:</p>

  <div class="example"><p><code>
        name=Rich%20Bowen&amp;city=Lexington&amp;state=KY&amp;sidekick=Squirrel%20Monkey
  </code></p></div>

            <p>A veces tendr&#225; este tipo de cadena de caracteres al final de una 
            URL. Cuando esto ocurre, el servidor pone esa cadena en una variable 
            de entorno que se llama <code>QUERY_STRING</code>. Esto se llama 
            solicitud <code>GET</code>. Su formulario HTML especifica si se usa 
            un <code>GET</code> o un <code>POST</code> para entregar la 
            informaci&#243;n, configurando el atributo <code>METHOD</code> en la 
            etiqueta <code>FORM</code>.</p>

            <p>Su programa es el responsable de convertir esa cadena de 
            caracteres en informaci&#243;n &#250;til. Afortunadamente, hay librer&#237;as y 
            m&#243;dulos disponibles que ayudan a procesar la informaci&#243;n, as&#237; como a 
            gestionar los distintos aspectos de su programa CGI.</p>
        
    </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="libraries" id="libraries">M&#243;dulos/librer&#237;as CGI</a></h2>
        

        <p>Cuando escribe programas CGI, deber&#237;a considerar usar una librer&#237;a de
        c&#243;digo, o m&#243;dulo, para hacer todo el trabajo m&#225;s arduo por usted.
        Esto lleva a tener menos errores y un desarrollo de c&#243;digo m&#225;s 
        r&#225;pido.</p>

        <p>Si est&#225; escribiendo un programa CGI en Perl, existen m&#243;dulos 
        disponibles en <a href="http://www.cpan.org/">CPAN</a>. El m&#243;dulo m&#225;s
        conocido para este prop&#243;sito es <code>CGI.pm</code>. Quiz&#225;s quiera
        considerar <code>CGI::Lite</code>, que implementa una funcionalidad 
        m&#237;nima, que es todo lo que se necesita en la mayor&#237;a de los programas.</p>

        <p>Si est&#225; escribiendo programas CGI en C, hay varidad de opciones. Una
        de estas es la librer&#237;a <code>CGIC</code>, de
        <a href="http://www.boutell.com/cgic/">http://www.boutell.com/cgic/</a>.
        </p>
    </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="moreinfo" id="moreinfo">Para m&#225;s informaci&#243;n</a></h2>
        

        <p>La especificaci&#243;n actual de CGI est&#225; disponible en el
        <a href="http://www.ietf.org/rfc/rfc3875">RFC de Common Gateway
        Interface</a>.</p>

        <p>Cuando env&#237;e una pregunta sobre un problema de CGI, o bien a una 
        lista de correo, o a un grupo de noticias, aseg&#250;rese de que facilita suficiente
        informaci&#243;n de lo que ha ocurrido, de lo que espera que ocurra, y de 
        lo que est&#225; ocurriendo en su lugar que es diferente, el servidor que 
        est&#225; ejecutando, en qu&#233; lenguaje CGI est&#225; hecho su programa, y si es
        posible, el c&#243;digo que falla. Esto har&#225; encontrar el problema mucho m&#225;s 
        f&#225;cil.</p>

        <p>Tenga en cuenta que las preguntas sobre problemas CGI 
        <strong>nunca</strong> deber&#237;an enviarse a la base de datos de bugs de
        bugs de Apache a menos que est&#233; seguro de haber encontrado un 
        problema en el c&#243;digo fuente de Apache.</p>
    </div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="../en/howto/cgi.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/howto/cgi.html" title="Espa&#241;ol">&nbsp;es&nbsp;</a> |
<a href="../fr/howto/cgi.html" hreflang="fr" rel="alternate" title="Fran&#231;ais">&nbsp;fr&nbsp;</a> |
<a href="../ja/howto/cgi.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="../ko/howto/cgi.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a></p>
</div><div class="top"><a href="#page-header"><img src="../images/up.gif" alt="top" /></a></div><div class="section"><h2><a id="comments_section" name="comments_section">Comentarios</a></h2><div class="warning"><strong>Notice:</strong><br />This is not a Q&amp;A section. Comments placed here should be pointed towards suggestions on improving the documentation or server, and may be removed by our moderators if they are either implemented or considered invalid/off-topic. Questions on how to manage the Apache HTTP Server should be directed at either our IRC channel, #httpd, on Libera.chat, or sent to our <a href="https://httpd.apache.org/lists.html">mailing lists</a>.</div>
<script type="text/javascript"><!--//--><![CDATA[//><!--
var comments_shortname = 'httpd';
var comments_identifier = 'http://httpd.apache.org/docs/2.4/howto/cgi.html';
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
<p class="menu"><a href="../mod/">M&#243;dulos</a> | <a href="../mod/directives.html">Directivas</a> | <a href="http://wiki.apache.org/httpd/FAQ">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa del sitio web</a></p></div><script type="text/javascript"><!--//--><![CDATA[//><!--
if (typeof(prettyPrint) !== 'undefined') {
    prettyPrint();
}
//--><!]]></script>
</body></html>