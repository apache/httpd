<!DOCTYPE html SYSTEM "about:legacy-compat">
<html lang="es"><head><META http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<meta content="width=device-width, initial-scale=1" name="viewport">
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Tutorial de Apache httpd: Introducci&oacute;n a los Server Side Includes
 - Servidor HTTP Apache Versi&oacute;n 2.4</title>
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
<a href="https://www.apache.org/">Apache</a> &gt; <a href="https://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="https://httpd.apache.org/docs/">Documentaci&oacute;n</a> &gt; <a href="../">Versi&oacute;n 2.4</a> &gt; <a href="./">How-To / Tutoriales</a></div><div id="page-content"><div id="preamble"><h1>Tutorial de Apache httpd: Introducci&oacute;n a los Server Side Includes
</h1>
<button aria-label="Toggle language list" class="lang-toggle"><svg xmlns="http://www.w3.org/2000/svg" stroke-width="2" stroke="currentColor" fill="none" viewBox="0 0 24 24" height="16" width="16"><circle r="10" cy="12" cx="12"/><line y2="12" x2="22" y1="12" x1="2"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></button>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="../en/howto/ssi.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/howto/ssi.html" title="Espa&ntilde;ol">&nbsp;es&nbsp;</a> |
<a href="../fr/howto/ssi.html" hreflang="fr" rel="alternate" title="Fran&ccedil;ais">&nbsp;fr&nbsp;</a> |
<a href="../ja/howto/ssi.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="../ko/howto/ssi.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a></p>
</div>

<p>Los Server Side Includes (Inclusiones en la parte Servidor) facilitan un m&eacute;todo para a&ntilde;adir contenido din&aacute;mico a documentos HTML existentes.</p>
</div>
<div id="quickview"><ul id="toc"><li><img alt="" src="../images/down.gif"> <a href="#related">Introducci&oacute;n</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#what">&iquest;Qu&eacute; son los SSI?</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#configuring">Configurar su servidor para permitir SSI</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#basic">Directivas SSI b&aacute;sicas</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#additionalexamples">M&aacute;s ejemplos</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#config">&iquest;Qu&eacute; m&aacute;s puedo configurar?</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#exec">Ejecutando comandos</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#advanced">T&eacute;cnicas avanzadas de SSI</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#conclusion">Conclusi&oacute;n</a></li>
</ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="related">Introducci&oacute;n <a title="Enlace permanente" href="#related" class="permalink">&para;</a></h2>
 <table class="related"><tr><th>M&oacute;dulos Relacionados</th><th>Directivas Relacionadas</th></tr><tr><td><ul><li><code class="module"><a href="../mod/mod_include.html">mod_include</a></code></li><li><code class="module"><a href="../mod/mod_cgi.html">mod_cgi</a></code></li><li><code class="module"><a href="../mod/mod_expires.html">mod_expires</a></code></li></ul></td><td><ul><li><code class="directive"><a href="../mod/core.html#options">Options</a></code></li><li><code class="directive"><a href="../mod/mod_include.html#xbithack">XBitHack</a></code></li><li><code class="directive"><a href="../mod/mod_mime.html#addtype">AddType</a></code></li><li><code class="directive"><a href="../mod/core.html#setoutputfilter">SetOutputFilter</a></code></li><li><code class="directive"><a href="../mod/mod_setenvif.html#browsermatchnocase">BrowserMatchNoCase</a></code></li></ul></td></tr></table>

    <p>Este art&iacute;culo trata sobre los Server Side Includes, generalmente llamados SSI.
     En este art&iacute;culo, hablaremos sobre c&oacute;mo configurar su servidor para permitir SSI,
      y de t&eacute;cnicas b&aacute;sicas de SSI para a&ntilde;adir contenido din&aacute;mico a sus p&aacute;ginas 
      HTML existentes.</p>

    <p>M&aacute;s adelante tambi&eacute;n hablaremos de algunas t&eacute;cnicas m&aacute;s avanzadas que 
    pueden usarse con SSI, tales como declaraciones condicionales en sus directivas SSI.</p>

</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="what">&iquest;Qu&eacute; son los SSI? <a title="Enlace permanente" href="#what" class="permalink">&para;</a></h2>

    <p>SSI (Server Side Includes) son directivas que se introducen en p&aacute;ginas HTML y son 
        evaluadas por el servidor mientras &eacute;ste las sirve. Le permiten a&ntilde;adir 
        contenido generado de manera din&aacute;mica a sus p&aacute;ginas HTML existentes sin tener 
        que servir una p&aacute;gina entera a trav&eacute;s de un programa CGI, u otra tecnolog&iacute;a 
        para generar contenido din&aacute;mico.</p>

    <p>Por ejemplo, podr&iacute;a colocar una directiva en una p&aacute;gina existente de HTML 
        de esta manera:</p>

    <div class="example"><p><code>
    &lt;!--#echo var="DATE_LOCAL" --&gt;
    </code></p></div>

    <p>Y, cuando se sirve la p&aacute;gina, este fragmento ser&aacute; evaluado y sustituido con su resultado:</p>

    <div class="example"><p><code>
    Tuesday, 15-Jan-2013 19:28:54 EST
    </code></p></div>

    <p>La decisi&oacute;n sobre cu&aacute;ndo usar SSI, o de cu&aacute;ndo generar una p&aacute;gina al completo con alg&uacute;n programa, suele depender generalmente de la cantidad de contenido est&aacute;tico que contiene, y cu&aacute;nto de esa p&aacute;gina tiene que ser recalculado cada vez que &eacute;sta se sirve. SSI es un buen m&eacute;todo para a&ntilde;adir peque&ntilde;as partes de informaci&oacute;n, tales como la hora actual - como se ha mostrado m&aacute;s arriba. Pero si la mayor&iacute;a de su p&aacute;gina se tiene que generar en el momento en el que se est&aacute; sirviendo, necesita buscar otra opci&oacute;n m&aacute;s adecuada que no sea SSI.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="configuring">Configurar su servidor para permitir SSI <a title="Enlace permanente" href="#configuring" class="permalink">&para;</a></h2>


    <p>Para permitir SSI en su servidor, debe tener la siguiente directiva en su fichero <code>httpd.conf</code> , o en un fichero 
    <code>.htaccess</code>:</p>
<pre class="prettyprint lang-config">Options +Includes</pre>


    <p>Esto le dice a Apache que quiere permitir que se examinen los ficheros buscando directivas SSI. Tenga en cuenta que la mayor&iacute;a de las configuraciones contienen m&uacute;ltiples directivas <code class="directive"><a href="../mod/core.html#options">Options</a></code> que pueden sobreescribirse las unas a las otras. Probablemente necesitar&aacute; aplicar <code>Options</code> al directorio espec&iacute;fico donde quiere SSI activado para asegurarse de que se eval&uacute;a en &uacute;ltimo lugar y por tanto se acabar&aacute; aplicando.</p>

    <p>No todos los ficheros se examinan buscando directivas SSI. Usted Le tiene que indicar a Apache qu&eacute; ficheros se tienen que examinar. Hay dos formas de hacer esto. Puede decirle a Apache que examine cualquier fichero con una extensi&oacute;n determinada, como por ejemplo <code>.shtml</code>, con las siguientes directivas:</p>
<pre class="prettyprint lang-config">AddType text/html .shtml
AddOutputFilter INCLUDES .shtml</pre>


    <p>Una desventaja de este m&eacute;todo es que si quisiera a&ntilde;adir directivas SSI a una p&aacute;gina ya existente, tendr&iacute;a que cambiar el nombre de la p&aacute;gina, y todos los enlaces que apuntasen a esa p&aacute;gina, todo para poder darle la extensi&oacute;n <code>.shtml</code> y que esas directivas sean interpretadas.</p>

    <p>El otro m&eacute;todo es usar la directiva <code class="directive"><a href="../mod/mod_include.html#xbithack">XBitHack</a></code> :</p>
<pre class="prettyprint lang-config">XBitHack on</pre>


    <p><code class="directive"><a href="../mod/mod_include.html#xbithack">XBitHack</a></code> le dice a Apache que examine ficheros buscando directivas SSI si los ficheros tienen el bit de ejecuci&oacute;n configurado. Asi que para a&ntilde;adir directivas SSI a una p&aacute;gina existente, en lugar de tener que cambiarle el nombre, solo tendr&iacute;a que convertirla en ejecutable usando <code>chmod</code>.</p>
<div class="example"><p><code>
        chmod +x pagename.html
</code></p></div>

    <p>Una breve recomendaci&oacute;n de qu&eacute; no hay que hacer. Ocasionalmente vemos gente recomendar que le diga a Apache que examine todos los ficheros 
    <code>.html</code> para activar SSI, para no tener que lidiar renombrando los ficheros a <code>.shtml</code>. Quiz&aacute;s estas personas no hayan oido hablar de <code class="directive"><a href="../mod/mod_include.html#xbithack">XBitHack</a></code>. Lo que hay que tener en cuenta, es que haciendo eso, est&aacute; pidiendo al Apache que lea cada uno de los ficheros que manda al cliente, incluso si no contenien directivas SSI. Esto puede ralentizar bastante el servidor, y no es una buena idea.</p>

    <p>Por supuesto, en Windows, no hay tal cosa como la configuraci&oacute;n del bit de ejecuci&oacute;n, as&iacute; que esto limita las opciones un poco.</p>

    <p>En su configuraci&oacute;n por defecto, Apache no env&iacute;a la fecha de &uacute;ltima modificaci&oacute;n o la longitud de contenido de p&aacute;ginas SSI porque es dificil calcular estos valores para contenido din&aacute;mico. Esto puede impedir que se cachee un documento, y dar como resultado en apareciencia un rendimiento m&aacute;s lento del cliente. Hay dos maneras de solucionar esto:</p>

    <ol>
      <li>Usando la configuraci&oacute;n <code>XBitHack Full</code>. Esto le indica a apache que determine la fecha de &uacute;ltima modificaci&oacute;n mirando s&oacute;lo la fecha del fichero que se ha solicitado originalmente, obviando la modificaci&oacute;n de cualquier otro fichero al que se hace referencia mediante SSI.</li>

      <li>Use las directivas facilitadas por <code class="module"><a href="../mod/mod_expires.html">mod_expires</a></code> para configurar una expiraci&oacute;n espec&iacute;fica de tiempo en sus ficheros, y as&iacute; hacer saber a proxies o navegadores web que es aceptable cachearlos.</li>
    </ol>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="basic">Directivas SSI b&aacute;sicas <a title="Enlace permanente" href="#basic" class="permalink">&para;</a></h2>

    <p>Las directivas SSI tienen la sintaxis siguiente:</p>
<div class="example"><p><code>
        &lt;!--#function attribute=value attribute=value ... --&gt;
</code></p></div>

    <p>Se formatean como comentarios HTML, as&iacute; si no tiene SSI habilitado correctamente, el navegador las obviar&aacute;, pero todav&iacute;a ser&aacute;n visibles en el fichero HTML. Si tiene SSI configurado correctamente, la directiva ser&aacute; reemplazada con su propio resultado.</p>

    <p>Esta funci&oacute;n es una de tantas, y hablaremos de algunas de ellas m&aacute;s adelante. Por ahora, aqu&iacute; mostramos unos ejemplos de lo que puede hacer con SSI.</p>

<h3 id="todaysdate">La fecha de hoy</h3>

<div class="example"><p><code>
        &lt;!--#echo var="DATE_LOCAL" --&gt;
</code></p></div>

    <p>La funci&oacute;n <code>echo</code> sencillamente muestra el valor de una variable. Hay muchas variables est&aacute;ndar que incluyen un conjunto de variables de entorno disponibles para programas CGI. Tambi&eacute;n puede definir sus propias variables con la funci&oacute;n <code>set</code>.</p>

    <p>Si no le gusta el formato en el que se imprime la fecha, puede usar la funci&oacute;n <code>config</code>, con un atributo
    <code>timefmt</code> para modificar ese formato.</p>

<div class="example"><p><code>
        &lt;!--#config timefmt="%A %B %d, %Y" --&gt;<br>
        Today is &lt;!--#echo var="DATE_LOCAL" --&gt;
</code></p></div>


<h3 id="lastmodified">Fecha de modificaci&oacute;n del fichero</h3>

<div class="example"><p><code>
        La &uacute;ltima modificaci&oacute;n de este documento &lt;!--#flastmod file="index.html" --&gt;
</code></p></div>

    <p>Esta funci&oacute;n tambi&eacute;n est&aacute; sujeta a configuraciones de formato de 
        <code>timefmt</code>.</p>


<h3 id="cgi">Incluyendo los resultados de un programa CGI</h3>

    <p>Este es uno de los usos m&aacute;s comunes de SSI - para sacar el resultado de un programa CGI, tal y como ocurre con el que fuera el programa favorito de todos, un ``contador de visitas.''</p>

<div class="example"><p><code>
        &lt;!--#include virtual="/cgi-bin/counter.pl" --&gt;
</code></p></div>


</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="additionalexamples">M&aacute;s ejemplos <a title="Enlace permanente" href="#additionalexamples" class="permalink">&para;</a></h2>


    <p>A continuaci&oacute;n hay algunos ejemplos espec&iacute;ficos de cosas que puede hacer con SSI en sus documentos HTML.</p>

<h3 id="docmodified">&iquest;Cu&aacute;ndo fue modificado este documento?</h3>

    <p>Antes mencionamos que puede usar SSI para informar al usuario cuando el documento ha sido modificado por &uacute;ltima vez. Aun as&iacute;, el m&eacute;todo actual para hacerlo se dej&oacute; en cuesti&oacute;n. El c&oacute;digo que se muestra a continuaci&oacute;n, puesto en un documento HTML, pondr&aacute; ese sello de tiempo en su p&aacute;gina. Por descontado, tendr&aacute; que tener SSI habilitado correctamente, como se indic&oacute; m&aacute;s arriba.</p>
<div class="example"><p><code>
        &lt;!--#config timefmt="%A %B %d, %Y" --&gt;<br>
        Ultima modificaci&oacute;n de este fichero &lt;!--#flastmod file="ssi.shtml" --&gt;
</code></p></div>

    <p>Obviamente, necesitar&aacute; sustituir el nombre de fichero
    <code>ssi.shtml</code> con el nombre real del fichero al que usted hace referencia. Esto puede ser inconveniente si solo est&aacute; buscando un trozo gen&eacute;rico de c&oacute;digo que pueda copiar y pegar en cualquier fichero, asi que probablemente necesite usar la variable <code>LAST_MODIFIED</code> en su lugar:</p>
<div class="example"><p><code>
        &lt;!--#config timefmt="%D" --&gt;<br>
        &Uacute;ltima modificaci&oacute;n de este fichero &lt;!--#echo var="LAST_MODIFIED" --&gt;
</code></p></div>

    <p>Para m&aacute;s detalles sobre el formato <code>timefmt</code>, vaya a su buscador favorito y busque <code>strftime</code>. La sintaxis es la misma.</p>


<h3 id="standard-footer">Incluyendo un pie de p&aacute;gina est&aacute;ndar</h3>


    <p>Si gestiona un sitio que tiene m&aacute;s de unas cuantas p&aacute;ginas, probablemente se de cuenta de que modificar todas esa p&aacute;ginas es un aut&eacute;ntico engorro, especialmente si trata de mantener una apareciencia homog&eacute;nea en todas ellas.</p>

    <p>Si usa un Include de fichero para la cabecera y/o pie de p&aacute;gina puede reducir la carga de trabajo de estas actualizaciones. Solo tiene que hacer un s&oacute;lo pie de p&aacute;gina, y despu&eacute;s incluirlo en cada p&aacute;gina con el comando SSI <code>include</code>. La funci&oacute;n <code>include</code>
    puede determinar qu&eacute; fichero incluir cuando usa el atributo
    <code>file</code>, o el atributo <code>virtual</code>. El atributo <code>file</code> es una ruta de fichero, <em>relativa al directorio actual</em>. Eso significa que no puede ser una ruta de fichero absoluta (que comienza con /), ni tampoco puede contener ../ como parte de la ruta. El atributo <code>virtual</code> es probablemente m&aacute;s &uacute;til, y deber&iacute;a especificar una URL relativa al documento que se est&aacute; sirviendo. Puede empezar con una /, pero debe estar en el mismo servidor que el fichero que se est&aacute; sirviendo.</p>
<div class="example"><p><code>
        &lt;!--#include virtual="/footer.html" --&gt;
</code></p></div>

    <p>Frecuentemente combinaremos las dos &uacute;ltimas, poniendo una directiva
    <code>LAST_MODIFIED</code> dentro de un fichero de pie de p&aacute;gina que va a ser incluido. Se pueden encontrar directivas SSI en el fichero que se incluye, las inclusiones pueden anidarse - lo que quiere decir, que el fichero incluido puede incluir otro fichero, y as&iacute; sucesivamente.</p>


</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="config">&iquest;Qu&eacute; m&aacute;s puedo configurar? <a title="Enlace permanente" href="#config" class="permalink">&para;</a></h2>


    <p>Adem&aacute;s de poder configurar el formato de la hora, tambi&eacute;n puede configurar dos cosas m&aacute;s.</p> 

    <p>Generalmente, cuando algo sale mal con sus directivas SSI, obtiene el mensaje (ha ocurrido un error procesando esta directiva)</p>
<div class="example"><p><code>
        [an error occurred while processing this directive]
</code></p></div>

    <p>Si quiere cambiar ese mensaje por otra cosa, puede hacerlo con el atributo <code>errmsg</code> para la funci&oacute;n
    <code>config</code>:</p>
<div class="example"><p><code>
        &lt;!--#config errmsg="[Parece que no sabe c&oacute;mo usar SSI]" --&gt;
</code></p></div>

    <p>Afortunadamente, los usuarios finales nunca ver&aacute;n este mensaje, porque habr&aacute; resuelto todos los problemas con sus directivas SSI antes de publicar su p&aacute;gina web. (&iquest;Verdad?)</p>

    <p>Y puede configurar el formato en el que los tama&ntilde;os de fichero se muestran con el formato <code>sizefmt</code>. Puede especificar
    <code>bytes</code> para un recuento total en bytes, o
    <code>abbrev</code> para un n&uacute;mero abreviado en Kb o Mb, seg&uacute;n sea necesario.</p>
    </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="exec">Ejecutando comandos <a title="Enlace permanente" href="#exec" class="permalink">&para;</a></h2>
    

    <p> Puede usar la funci&oacute;n <code>exec</code> para ejecutar comandos. Y SSI puede ejecutar un comando usando la shell (<code>/bin/sh</code>, para ser m&aacute;s precisos - o la shell de DOS , si est&aacute; en Win32). Lo siguiente, por ejemplo, le dar&aacute; un listado de ficheros en un directorio.</p>
<div class="example"><p><code>
        &lt;pre&gt;<br>
        &lt;!--#exec cmd="ls" --&gt;<br>
        &lt;/pre&gt;
</code></p></div>

    <p>o, en Windows</p>
<div class="example"><p><code>
        &lt;pre&gt;<br>
        &lt;!--#exec cmd="dir" --&gt;<br>
        &lt;/pre&gt;
</code></p></div>

    <p>Notar&aacute; un formato estra&ntilde;o con esta directiva en Windows, porque el resultado de <code>dir</code> contiene la cadena de caracterers ``&lt;<code>dir</code>&gt;'' ,que confunde a los navegadores.</p>

    <p>Tenga en cuenta de que esta caracter&iacute;stica es muy peligrosa, puesto que ejecutar&aacute; cualquier c&oacute;digo que est&eacute; especificado con la etiqueta 
    <code>exec</code>. Si tiene una situaci&oacute;n en la que los usuarios pueden editar contenido en sus p&aacute;ginas web, tales como por ejemplo un ``registro de visitas'', aseg&uacute;rese de tener esta caracter&iacute;stica deshabilitada. Puede permitir SSI, pero no la caracter&iacute;stica <code>exec</code>, con el argumento <code>IncludesNOEXEC</code> en la directiva <code>Options</code>.</p>
    </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="advanced">T&eacute;cnicas avanzadas de SSI <a title="Enlace permanente" href="#advanced" class="permalink">&para;</a></h2>


    <p>Adem&aacute;s de mostrar contenido, SSI en Apache da la opci&oacute;n de configurar variables y usar esas variables en comparaciones y condicionales.</p>

<h3 id="variables">Configurando Variables</h3>

    <p>Usando la directiva <code>set</code>, puede configurar variables para su uso posterior. La sintaxis es como sigue:</p>
<div class="example"><p><code>
        &lt;!--#set var="name" value="Rich" --&gt;
</code></p></div>

    <p>Adem&aacute;s de configurar valores literales como esto, puede usar cualquier otra variable, incluyendo <a href="../env.html">variables de entorno</a> o las variables que se han mencionado antes (como por ejemplo <code>LAST_MODIFIED</code>) para dar valores a sus variables. Podr&aacute; especificar que algo es una vaiable, en lugar de una cadena de caracters literal, usando el s&iacute;mbolo del dolar ($) antes del nombre de la variable.</p>

    <div class="example"><p><code> &lt;!--#set var="modified" value="$LAST_MODIFIED" --&gt;
    </code></p></div>

    <p>Para poner el s&iacute;mbolo del dolar de manera literal en un valor de su variable tendr&aacute; que escapar el s&iacute;mbolo del dolar con una barra "\".</p>
<div class="example"><p><code>
        &lt;!--#set var="cost" value="\$100" --&gt;
</code></p></div>

    <p>Por &uacute;ltimo, si quiere poner una variable entre medias de una cadena de caracteres m&aacute;s larga, y se da la coincidencia de que el nombre de la variable se encontrar&aacute; con otros caracteres, y de esta manera se confundir&aacute; con otros caracteres, puedes poner el nombre de la variable entre llaves, y as&iacute; eliminar la confusi&oacute;n. (Es dificil encontrar un buen ejemplo para esto, pero con &eacute;ste a lo mejor entiende lo que tratamos de transmitir.)</p>
<div class="example"><p><code>
        &lt;!--#set var="date" value="${DATE_LOCAL}_${DATE_GMT}" --&gt;
</code></p></div>


<h3 id="conditional">Expresiones condicionales</h3>


    <p>Ahora que tenemos variables, y somos capaces de comparar sus valores, podemos usarlas para expresar condicionales. Esto permite a SSI ser un cierto tipo de lenguaje de programaci&oacute;n diminuto.
    <code class="module"><a href="../mod/mod_include.html">mod_include</a></code> provee una estrucura <code>if</code>,
    <code>elif</code>, <code>else</code>, <code>endif</code>
    para construir declaraciones condicionales. Esto le permite generar de manera efectiva multitud de p&aacute;ginas l&oacute;gicas desde tan solo una p&aacute;gina.</p>

    <p>La estructura de este sistema condicional es:</p>
<div class="example"><p><code>
    &lt;!--#if expr="test_condition" --&gt;<br>
    &lt;!--#elif expr="test_condition" --&gt;<br>
    &lt;!--#else --&gt;<br>
    &lt;!--#endif --&gt;
</code></p></div>

    <p>Una <em>test_condition</em> puede ser cualquier tipo de comparaci&oacute;n l&oacute;gica - o bien comparando valores entre ellos, o probando la ``verdad'' (o falsedad) de un valor en particular. (Una cadena de caracteres cualquiera es verdadera si no est&aacute; vac&iacute;a.) Para una lista completa de operadores de comparaci&oacute;n, vea la documentaci&oacute;n de <code class="module"><a href="../mod/mod_include.html">mod_include</a></code>.</p>

    <p>Por ejemplo, si quiere personalizar el texto en su p&aacute;gina web basado en la hora actual, puede usar la siguiente receta, colocada en su p&aacute;gina HTML:</p>

    <div class="example"><p><code>
    Good
    &lt;!--#if expr="%{TIME_HOUR} &lt;12" --&gt;<br>
    morning!<br>
    &lt;!--#else --&gt;<br>
    afternoon!<br>
    &lt;!--#endif --&gt;<br>
    </code></p></div>

    <p>Cualquier otra variable (o bien las que defina usted, o variables de entorno normales) puede usarse en declaraciones condicionales.
    Vea <a href="../expr.html">Expresiones en el Servidor Apache HTTP</a> para m&aacute;s informaci&oacute;n sobre el motor de evaluaci&oacute;n de expresiones.</p>

    <p>Con la habilidad de Apache de configurar variables de entorno con directivas <code>SetEnvIf</code>, y otras directivas relacionadas,
    esta funcionalidad puede llevarle a hacer una gran variedad de contenido din&aacute;mico en la parte de servidor sin tener que depender de una aplicaci&oacute;n web al completo.</p>

</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="conclusion">Conclusi&oacute;n <a title="Enlace permanente" href="#conclusion" class="permalink">&para;</a></h2>

    <p>Desde luego SSI no es un reemplazo para CGI u otras tecnolog&iacute;as que se usen para generar p&aacute;ginas web din&aacute;micas. Pero es un gran m&eacute;todo para a&ntilde;adir peque&ntilde;as cantidaddes de contenido din&aacute;mico a p&aacute;ginas web, sin hacer mucho m&aacute;s trabajo extra.</p>
</div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="../en/howto/ssi.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/howto/ssi.html" title="Espa&ntilde;ol">&nbsp;es&nbsp;</a> |
<a href="../fr/howto/ssi.html" hreflang="fr" rel="alternate" title="Fran&ccedil;ais">&nbsp;fr&nbsp;</a> |
<a href="../ja/howto/ssi.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="../ko/howto/ssi.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a></p>
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