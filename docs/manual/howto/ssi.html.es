<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es" xml:lang="es"><head>
<meta content="text/html; charset=ISO-8859-1" http-equiv="Content-Type" />
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Tutorial de Apache httpd: Introducci&#243;n a los Server Side Includes
 - Servidor HTTP Apache Versi&#243;n 2.4</title>
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
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs/">Documentaci&#243;n</a> &gt; <a href="../">Versi&#243;n 2.4</a> &gt; <a href="./">How-To / Tutoriales</a></div><div id="page-content"><div id="preamble"><h1>Tutorial de Apache httpd: Introducci&#243;n a los Server Side Includes
</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="../en/howto/ssi.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/howto/ssi.html" title="Espa&#241;ol">&nbsp;es&nbsp;</a> |
<a href="../fr/howto/ssi.html" hreflang="fr" rel="alternate" title="Fran&#231;ais">&nbsp;fr&nbsp;</a> |
<a href="../ja/howto/ssi.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="../ko/howto/ssi.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a></p>
</div>

<p>Los Server Side Includes (Inclusiones en la parte Servidor) facilitan un m&#233;todo para a&#241;adir contenido din&#225;mico a documentos HTML existentes.</p>
</div>
<div id="quickview"><a href="https://www.apache.org/foundation/contributing.html" class="badge"><img src="https://www.apache.org/images/SupportApache-small.png" alt="Support Apache!" /></a><ul id="toc"><li><img alt="" src="../images/down.gif" /> <a href="#related">Introducci&#243;n</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#what">&#191;Qu&#233; son los SSI?</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#configuring">Configurar su servidor para permitir SSI</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#basic">Directivas SSI b&#225;sicas</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#additionalexamples">M&#225;s ejemplos</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#config">&#191;Qu&#233; m&#225;s puedo configurar?</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#exec">Ejecutando comandos</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#advanced">T&#233;cnicas avanzadas de SSI</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#conclusion">Conclusi&#243;n</a></li>
</ul><h3>Consulte tambi&#233;n</h3><ul class="seealso"><li><a href="#comments_section">Comentarios</a></li></ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="related" id="related">Introducci&#243;n</a></h2>
 <table class="related"><tr><th>M&#243;dulos Relacionados</th><th>Directivas Relacionadas</th></tr><tr><td><ul><li><code class="module"><a href="../mod/mod_include.html">mod_include</a></code></li><li><code class="module"><a href="../mod/mod_cgi.html">mod_cgi</a></code></li><li><code class="module"><a href="../mod/mod_expires.html">mod_expires</a></code></li></ul></td><td><ul><li><code class="directive"><a href="../mod/core.html#options">Options</a></code></li><li><code class="directive"><a href="../mod/mod_include.html#xbithack">XBitHack</a></code></li><li><code class="directive"><a href="../mod/mod_mime.html#addtype">AddType</a></code></li><li><code class="directive"><a href="../mod/core.html#setoutputfilter">SetOutputFilter</a></code></li><li><code class="directive"><a href="../mod/mod_setenvif.html#browsermatchnocase">BrowserMatchNoCase</a></code></li></ul></td></tr></table>

    <p>Este art&#237;culo trata sobre los Server Side Includes, generalmente llamados SSI.
     En este art&#237;culo, hablaremos sobre c&#243;mo configurar su servidor para permitir SSI,
      y de t&#233;cnicas b&#225;sicas de SSI para a&#241;adir contenido din&#225;mico a sus p&#225;ginas 
      HTML existentes.</p>

    <p>M&#225;s adelante tambi&#233;n hablaremos de algunas t&#233;cnicas m&#225;s avanzadas que 
    pueden usarse con SSI, tales como declaraciones condicionales en sus directivas SSI.</p>

</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="what" id="what">&#191;Qu&#233; son los SSI?</a></h2>

    <p>SSI (Server Side Includes) son directivas que se introducen en p&#225;ginas HTML y son 
        evaluadas por el servidor mientras &#233;ste las sirve. Le permiten a&#241;adir 
        contenido generado de manera din&#225;mica a sus p&#225;ginas HTML existentes sin tener 
        que servir una p&#225;gina entera a trav&#233;s de un programa CGI, u otra tecnolog&#237;a 
        para generar contenido din&#225;mico.</p>

    <p>Por ejemplo, podr&#237;a colocar una directiva en una p&#225;gina existente de HTML 
        de esta manera:</p>

    <div class="example"><p><code>
    &lt;!--#echo var="DATE_LOCAL" --&gt;
    </code></p></div>

    <p>Y, cuando se sirve la p&#225;gina, este fragmento ser&#225; evaluado y sustituido con su resultado:</p>

    <div class="example"><p><code>
    Tuesday, 15-Jan-2013 19:28:54 EST
    </code></p></div>

    <p>La decisi&#243;n sobre cu&#225;ndo usar SSI, o de cu&#225;ndo generar una p&#225;gina al completo con alg&#250;n programa, suele depender generalmente de la cantidad de contenido est&#225;tico que contiene, y cu&#225;nto de esa p&#225;gina tiene que ser recalculado cada vez que &#233;sta se sirve. SSI es un buen m&#233;todo para a&#241;adir peque&#241;as partes de informaci&#243;n, tales como la hora actual - como se ha mostrado m&#225;s arriba. Pero si la mayor&#237;a de su p&#225;gina se tiene que generar en el momento en el que se est&#225; sirviendo, necesita buscar otra opci&#243;n m&#225;s adecuada que no sea SSI.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="configuring" id="configuring">Configurar su servidor para permitir SSI</a></h2>


    <p>Para permitir SSI en su servidor, debe tener la siguiente directiva en su fichero <code>httpd.conf</code> , o en un fichero 
    <code>.htaccess</code>:</p>
<pre class="prettyprint lang-config">Options +Includes</pre>


    <p>Esto le dice a Apache que quiere permitir que se examinen los ficheros buscando directivas SSI. Tenga en cuenta que la mayor&#237;a de las configuraciones contienen m&#250;ltiples directivas <code class="directive"><a href="../mod/core.html#options">Options</a></code> que pueden sobreescribirse las unas a las otras. Probablemente necesitar&#225; aplicar <code>Options</code> al directorio espec&#237;fico donde quiere SSI activado para asegurarse de que se eval&#250;a en &#250;ltimo lugar y por tanto se acabar&#225; aplicando.</p>

    <p>No todos los ficheros se examinan buscando directivas SSI. Usted Le tiene que indicar a Apache qu&#233; ficheros se tienen que examinar. Hay dos formas de hacer esto. Puede decirle a Apache que examine cualquier fichero con una extensi&#243;n determinada, como por ejemplo <code>.shtml</code>, con las siguientes directivas:</p>
<pre class="prettyprint lang-config">AddType text/html .shtml
AddOutputFilter INCLUDES .shtml</pre>


    <p>Una desventaja de este m&#233;todo es que si quisiera a&#241;adir directivas SSI a una p&#225;gina ya existente, tendr&#237;a que cambiar el nombre de la p&#225;gina, y todos los enlaces que apuntasen a esa p&#225;gina, todo para poder darle la extensi&#243;n <code>.shtml</code> y que esas directivas sean interpretadas.</p>

    <p>El otro m&#233;todo es usar la directiva <code class="directive"><a href="../mod/mod_include.html#xbithack">XBitHack</a></code> :</p>
<pre class="prettyprint lang-config">XBitHack on</pre>


    <p><code class="directive"><a href="../mod/mod_include.html#xbithack">XBitHack</a></code> le dice a Apache que examine ficheros buscando directivas SSI si los ficheros tienen el bit de ejecuci&#243;n configurado. Asi que para a&#241;adir directivas SSI a una p&#225;gina existente, en lugar de tener que cambiarle el nombre, solo tendr&#237;a que convertirla en ejecutable usando <code>chmod</code>.</p>
<div class="example"><p><code>
        chmod +x pagename.html
</code></p></div>

    <p>Una breve recomendaci&#243;n de qu&#233; no hay que hacer. Ocasionalmente vemos gente recomendar que le diga a Apache que examine todos los ficheros 
    <code>.html</code> para activar SSI, para no tener que lidiar renombrando los ficheros a <code>.shtml</code>. Quiz&#225;s estas personas no hayan oido hablar de <code class="directive"><a href="../mod/mod_include.html#xbithack">XBitHack</a></code>. Lo que hay que tener en cuenta, es que haciendo eso, est&#225; pidiendo al Apache que lea cada uno de los ficheros que manda al cliente, incluso si no contenien directivas SSI. Esto puede ralentizar bastante el servidor, y no es una buena idea.</p>

    <p>Por supuesto, en Windows, no hay tal cosa como la configuraci&#243;n del bit de ejecuci&#243;n, as&#237; que esto limita las opciones un poco.</p>

    <p>En su configuraci&#243;n por defecto, Apache no env&#237;a la fecha de &#250;ltima modificaci&#243;n o la longitud de contenido de p&#225;ginas SSI porque es dificil calcular estos valores para contenido din&#225;mico. Esto puede impedir que se cachee un documento, y dar como resultado en apareciencia un rendimiento m&#225;s lento del cliente. Hay dos maneras de solucionar esto:</p>

    <ol>
      <li>Usando la configuraci&#243;n <code>XBitHack Full</code>. Esto le indica a apache que determine la fecha de &#250;ltima modificaci&#243;n mirando s&#243;lo la fecha del fichero que se ha solicitado originalmente, obviando la modificaci&#243;n de cualquier otro fichero al que se hace referencia mediante SSI.</li>

      <li>Use las directivas facilitadas por <code class="module"><a href="../mod/mod_expires.html">mod_expires</a></code> para configurar una expiraci&#243;n espec&#237;fica de tiempo en sus ficheros, y as&#237; hacer saber a proxies o navegadores web que es aceptable cachearlos.</li>
    </ol>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="basic" id="basic">Directivas SSI b&#225;sicas</a></h2>

    <p>Las directivas SSI tienen la sintaxis siguiente:</p>
<div class="example"><p><code>
        &lt;!--#function attribute=value attribute=value ... --&gt;
</code></p></div>

    <p>Se formatean como comentarios HTML, as&#237; si no tiene SSI habilitado correctamente, el navegador las obviar&#225;, pero todav&#237;a ser&#225;n visibles en el fichero HTML. Si tiene SSI configurado correctamente, la directiva ser&#225; reemplazada con su propio resultado.</p>

    <p>Esta funci&#243;n es una de tantas, y hablaremos de algunas de ellas m&#225;s adelante. Por ahora, aqu&#237; mostramos unos ejemplos de lo que puede hacer con SSI.</p>

<h3><a name="todaysdate" id="todaysdate">La fecha de hoy</a></h3>

<div class="example"><p><code>
        &lt;!--#echo var="DATE_LOCAL" --&gt;
</code></p></div>

    <p>La funci&#243;n <code>echo</code> sencillamente muestra el valor de una variable. Hay muchas variables est&#225;ndar que incluyen un conjunto de variables de entorno disponibles para programas CGI. Tambi&#233;n puede definir sus propias variables con la funci&#243;n <code>set</code>.</p>

    <p>Si no le gusta el formato en el que se imprime la fecha, puede usar la funci&#243;n <code>config</code>, con un atributo
    <code>timefmt</code> para modificar ese formato.</p>

<div class="example"><p><code>
        &lt;!--#config timefmt="%A %B %d, %Y" --&gt;<br />
        Today is &lt;!--#echo var="DATE_LOCAL" --&gt;
</code></p></div>


<h3><a name="lastmodified" id="lastmodified">Fecha de modificaci&#243;n del fichero</a></h3>

<div class="example"><p><code>
        La &#250;ltima modificaci&#243;n de este documento &lt;!--#flastmod file="index.html" --&gt;
</code></p></div>

    <p>Esta funci&#243;n tambi&#233;n est&#225; sujeta a configuraciones de formato de 
        <code>timefmt</code>.</p>


<h3><a name="cgi" id="cgi">Incluyendo los resultados de un programa CGI</a></h3>

    <p>Este es uno de los usos m&#225;s comunes de SSI - para sacar el resultado de un programa CGI, tal y como ocurre con el que fuera el programa favorito de todos, un ``contador de visitas.''</p>

<div class="example"><p><code>
        &lt;!--#include virtual="/cgi-bin/counter.pl" --&gt;
</code></p></div>


</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="additionalexamples" id="additionalexamples">M&#225;s ejemplos</a></h2>


    <p>A continuaci&#243;n hay algunos ejemplos espec&#237;ficos de cosas que puede hacer con SSI en sus documentos HTML.</p>

<h3><a name="docmodified" id="docmodified">&#191;Cu&#225;ndo fue modificado este documento?</a></h3>

    <p>Antes mencionamos que puede usar SSI para informar al usuario cuando el documento ha sido modificado por &#250;ltima vez. Aun as&#237;, el m&#233;todo actual para hacerlo se dej&#243; en cuesti&#243;n. El c&#243;digo que se muestra a continuaci&#243;n, puesto en un documento HTML, pondr&#225; ese sello de tiempo en su p&#225;gina. Por descontado, tendr&#225; que tener SSI habilitado correctamente, como se indic&#243; m&#225;s arriba.</p>
<div class="example"><p><code>
        &lt;!--#config timefmt="%A %B %d, %Y" --&gt;<br />
        Ultima modificaci&#243;n de este fichero &lt;!--#flastmod file="ssi.shtml" --&gt;
</code></p></div>

    <p>Obviamente, necesitar&#225; sustituir el nombre de fichero
    <code>ssi.shtml</code> con el nombre real del fichero al que usted hace referencia. Esto puede ser inconveniente si solo est&#225; buscando un trozo gen&#233;rico de c&#243;digo que pueda copiar y pegar en cualquier fichero, asi que probablemente necesite usar la variable <code>LAST_MODIFIED</code> en su lugar:</p>
<div class="example"><p><code>
        &lt;!--#config timefmt="%D" --&gt;<br />
        &#218;ltima modificaci&#243;n de este fichero &lt;!--#echo var="LAST_MODIFIED" --&gt;
</code></p></div>

    <p>Para m&#225;s detalles sobre el formato <code>timefmt</code>, vaya a su buscador favorito y busque <code>strftime</code>. La sintaxis es la misma.</p>


<h3><a name="standard-footer" id="standard-footer">Incluyendo un pie de p&#225;gina est&#225;ndar</a></h3>


    <p>Si gestiona un sitio que tiene m&#225;s de unas cuantas p&#225;ginas, probablemente se de cuenta de que modificar todas esa p&#225;ginas es un aut&#233;ntico engorro, especialmente si trata de mantener una apareciencia homog&#233;nea en todas ellas.</p>

    <p>Si usa un Include de fichero para la cabecera y/o pie de p&#225;gina puede reducir la carga de trabajo de estas actualizaciones. Solo tiene que hacer un s&#243;lo pie de p&#225;gina, y despu&#233;s incluirlo en cada p&#225;gina con el comando SSI <code>include</code>. La funci&#243;n <code>include</code>
    puede determinar qu&#233; fichero incluir cuando usa el atributo
    <code>file</code>, o el atributo <code>virtual</code>. El atributo <code>file</code> es una ruta de fichero, <em>relativa al directorio actual</em>. Eso significa que no puede ser una ruta de fichero absoluta (que comienza con /), ni tampoco puede contener ../ como parte de la ruta. El atributo <code>virtual</code> es probablemente m&#225;s &#250;til, y deber&#237;a especificar una URL relativa al documento que se est&#225; sirviendo. Puede empezar con una /, pero debe estar en el mismo servidor que el fichero que se est&#225; sirviendo.</p>
<div class="example"><p><code>
        &lt;!--#include virtual="/footer.html" --&gt;
</code></p></div>

    <p>Frecuentemente combinaremos las dos &#250;ltimas, poniendo una directiva
    <code>LAST_MODIFIED</code> dentro de un fichero de pie de p&#225;gina que va a ser incluido. Se pueden encontrar directivas SSI en el fichero que se incluye, las inclusiones pueden anidarse - lo que quiere decir, que el fichero incluido puede incluir otro fichero, y as&#237; sucesivamente.</p>


</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="config" id="config">&#191;Qu&#233; m&#225;s puedo configurar?</a></h2>


    <p>Adem&#225;s de poder configurar el formato de la hora, tambi&#233;n puede configurar dos cosas m&#225;s.</p> 

    <p>Generalmente, cuando algo sale mal con sus directivas SSI, obtiene el mensaje (ha ocurrido un error procesando esta directiva)</p>
<div class="example"><p><code>
        [an error occurred while processing this directive]
</code></p></div>

    <p>Si quiere cambiar ese mensaje por otra cosa, puede hacerlo con el atributo <code>errmsg</code> para la funci&#243;n
    <code>config</code>:</p>
<div class="example"><p><code>
        &lt;!--#config errmsg="[Parece que no sabe c&#243;mo usar SSI]" --&gt;
</code></p></div>

    <p>Afortunadamente, los usuarios finales nunca ver&#225;n este mensaje, porque habr&#225; resuelto todos los problemas con sus directivas SSI antes de publicar su p&#225;gina web. (&#191;Verdad?)</p>

    <p>Y puede configurar el formato en el que los tama&#241;os de fichero se muestran con el formato <code>sizefmt</code>. Puede especificar
    <code>bytes</code> para un recuento total en bytes, o
    <code>abbrev</code> para un n&#250;mero abreviado en Kb o Mb, seg&#250;n sea necesario.</p>
    </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="exec" id="exec">Ejecutando comandos</a></h2>
    

    <p> Puede usar la funci&#243;n <code>exec</code> para ejecutar comandos. Y SSI puede ejecutar un comando usando la shell (<code>/bin/sh</code>, para ser m&#225;s precisos - o la shell de DOS , si est&#225; en Win32). Lo siguiente, por ejemplo, le dar&#225; un listado de ficheros en un directorio.</p>
<div class="example"><p><code>
        &lt;pre&gt;<br />
        &lt;!--#exec cmd="ls" --&gt;<br />
        &lt;/pre&gt;
</code></p></div>

    <p>o, en Windows</p>
<div class="example"><p><code>
        &lt;pre&gt;<br />
        &lt;!--#exec cmd="dir" --&gt;<br />
        &lt;/pre&gt;
</code></p></div>

    <p>Notar&#225; un formato estra&#241;o con esta directiva en Windows, porque el resultado de <code>dir</code> contiene la cadena de caracterers ``&lt;<code>dir</code>&gt;'' ,que confunde a los navegadores.</p>

    <p>Tenga en cuenta de que esta caracter&#237;stica es muy peligrosa, puesto que ejecutar&#225; cualquier c&#243;digo que est&#233; especificado con la etiqueta 
    <code>exec</code>. Si tiene una situaci&#243;n en la que los usuarios pueden editar contenido en sus p&#225;ginas web, tales como por ejemplo un ``registro de visitas'', aseg&#250;rese de tener esta caracter&#237;stica deshabilitada. Puede permitir SSI, pero no la caracter&#237;stica <code>exec</code>, con el argumento <code>IncludesNOEXEC</code> en la directiva <code>Options</code>.</p>
    </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="advanced" id="advanced">T&#233;cnicas avanzadas de SSI</a></h2>


    <p>Adem&#225;s de mostrar contenido, SSI en Apache da la opci&#243;n de configurar variables y usar esas variables en comparaciones y condicionales.</p>

<h3><a name="variables" id="variables">Configurando Variables</a></h3>

    <p>Usando la directiva <code>set</code>, puede configurar variables para su uso posterior. La sintaxis es como sigue:</p>
<div class="example"><p><code>
        &lt;!--#set var="name" value="Rich" --&gt;
</code></p></div>

    <p>Adem&#225;s de configurar valores literales como esto, puede usar cualquier otra variable, incluyendo <a href="../env.html">variables de entorno</a> o las variables que se han mencionado antes (como por ejemplo <code>LAST_MODIFIED</code>) para dar valores a sus variables. Podr&#225; especificar que algo es una vaiable, en lugar de una cadena de caracters literal, usando el s&#237;mbolo del dolar ($) antes del nombre de la variable.</p>

    <div class="example"><p><code> &lt;!--#set var="modified" value="$LAST_MODIFIED" --&gt;
    </code></p></div>

    <p>Para poner el s&#237;mbolo del dolar de manera literal en un valor de su variable tendr&#225; que escapar el s&#237;mbolo del dolar con una barra "\".</p>
<div class="example"><p><code>
        &lt;!--#set var="cost" value="\$100" --&gt;
</code></p></div>

    <p>Por &#250;ltimo, si quiere poner una variable entre medias de una cadena de caracteres m&#225;s larga, y se da la coincidencia de que el nombre de la variable se encontrar&#225; con otros caracteres, y de esta manera se confundir&#225; con otros caracteres, puedes poner el nombre de la variable entre llaves, y as&#237; eliminar la confusi&#243;n. (Es dificil encontrar un buen ejemplo para esto, pero con &#233;ste a lo mejor entiende lo que tratamos de transmitir.)</p>
<div class="example"><p><code>
        &lt;!--#set var="date" value="${DATE_LOCAL}_${DATE_GMT}" --&gt;
</code></p></div>


<h3><a name="conditional" id="conditional">Expresiones condicionales</a></h3>


    <p>Ahora que tenemos variables, y somos capaces de comparar sus valores, podemos usarlas para expresar condicionales. Esto permite a SSI ser un cierto tipo de lenguaje de programaci&#243;n diminuto.
    <code class="module"><a href="../mod/mod_include.html">mod_include</a></code> provee una estrucura <code>if</code>,
    <code>elif</code>, <code>else</code>, <code>endif</code>
    para construir declaraciones condicionales. Esto le permite generar de manera efectiva multitud de p&#225;ginas l&#243;gicas desde tan solo una p&#225;gina.</p>

    <p>La estructura de este sistema condicional es:</p>
<div class="example"><p><code>
    &lt;!--#if expr="test_condition" --&gt;<br />
    &lt;!--#elif expr="test_condition" --&gt;<br />
    &lt;!--#else --&gt;<br />
    &lt;!--#endif --&gt;
</code></p></div>

    <p>Una <em>test_condition</em> puede ser cualquier tipo de comparaci&#243;n l&#243;gica - o bien comparando valores entre ellos, o probando la ``verdad'' (o falsedad) de un valor en particular. (Una cadena de caracteres cualquiera es verdadera si no est&#225; vac&#237;a.) Para una lista completa de operadores de comparaci&#243;n, vea la documentaci&#243;n de <code class="module"><a href="../mod/mod_include.html">mod_include</a></code>.</p>

    <p>Por ejemplo, si quiere personalizar el texto en su p&#225;gina web basado en la hora actual, puede usar la siguiente receta, colocada en su p&#225;gina HTML:</p>

    <div class="example"><p><code>
    Good
    &lt;!--#if expr="%{TIME_HOUR} &lt;12" --&gt;<br />
    morning!<br />
    &lt;!--#else --&gt;<br />
    afternoon!<br />
    &lt;!--#endif --&gt;<br />
    </code></p></div>

    <p>Cualquier otra variable (o bien las que defina usted, o variables de entorno normales) puede usarse en declaraciones condicionales.
    Vea <a href="../expr.html">Expresiones en el Servidor Apache HTTP</a> para m&#225;s informaci&#243;n sobre el motor de evaluaci&#243;n de expresiones.</p>

    <p>Con la habilidad de Apache de configurar variables de entorno con directivas <code>SetEnvIf</code>, y otras directivas relacionadas,
    esta funcionalidad puede llevarle a hacer una gran variedad de contenido din&#225;mico en la parte de servidor sin tener que depender de una aplicaci&#243;n web al completo.</p>

</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="conclusion" id="conclusion">Conclusi&#243;n</a></h2>

    <p>Desde luego SSI no es un reemplazo para CGI u otras tecnolog&#237;as que se usen para generar p&#225;ginas web din&#225;micas. Pero es un gran m&#233;todo para a&#241;adir peque&#241;as cantidaddes de contenido din&#225;mico a p&#225;ginas web, sin hacer mucho m&#225;s trabajo extra.</p>
</div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="../en/howto/ssi.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/howto/ssi.html" title="Espa&#241;ol">&nbsp;es&nbsp;</a> |
<a href="../fr/howto/ssi.html" hreflang="fr" rel="alternate" title="Fran&#231;ais">&nbsp;fr&nbsp;</a> |
<a href="../ja/howto/ssi.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="../ko/howto/ssi.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a></p>
</div><div class="top"><a href="#page-header"><img src="../images/up.gif" alt="top" /></a></div><div class="section"><h2><a id="comments_section" name="comments_section">Comentarios</a></h2><div class="warning"><strong>Notice:</strong><br />This is not a Q&amp;A section. Comments placed here should be pointed towards suggestions on improving the documentation or server, and may be removed by our moderators if they are either implemented or considered invalid/off-topic. Questions on how to manage the Apache HTTP Server should be directed at either our IRC channel, #httpd, on Libera.chat, or sent to our <a href="https://httpd.apache.org/lists.html">mailing lists</a>.</div>
<script type="text/javascript"><!--//--><![CDATA[//><!--
var comments_shortname = 'httpd';
var comments_identifier = 'http://httpd.apache.org/docs/2.4/howto/ssi.html';
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