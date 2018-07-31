<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es" xml:lang="es"><head>
<meta content="text/html; charset=ISO-8859-1" http-equiv="Content-Type" />
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Iniciar Apache - Servidor HTTP Apache Versi&#243;n 2.4</title>
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
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs/">Documentaci&#243;n</a> &gt; <a href="./">Versi&#243;n 2.4</a></div><div id="page-content"><div id="preamble"><h1>Iniciar Apache</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="./de/invoking.html" hreflang="de" rel="alternate" title="Deutsch">&nbsp;de&nbsp;</a> |
<a href="./en/invoking.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/invoking.html" title="Espa&#241;ol">&nbsp;es&nbsp;</a> |
<a href="./fr/invoking.html" hreflang="fr" rel="alternate" title="Fran&#231;ais">&nbsp;fr&nbsp;</a> |
<a href="./ja/invoking.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/invoking.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./tr/invoking.html" hreflang="tr" rel="alternate" title="T&#252;rk&#231;e">&nbsp;tr&nbsp;</a></p>
</div>

    <p>En Windows, Apache se ejecuta normalmente como un servicio. 
        Para obtener m&#225;s informaci&#243;n, consulte
    <a href="platform/windows.html#winsvc">Ejecutar Apache como un
    servicio</a>.</p>

    <p>En Unix, el programa <code class="program"><a href="./programs/httpd.html">httpd</a></code> se
    ejecuta como un demonio (daemon) de forma cont&#237;niua y en segundo plano
    y atiende las peticiones que le lleguen.  Este documento describe c&#243;mo
    invocar el programa <code class="program"><a href="./programs/httpd.html">httpd</a></code>.</p>
</div>
<div id="quickview"><a href="https://www.apache.org/foundation/contributing.html" class="badge"><img src="https://www.apache.org/images/SupportApache-small.png" alt="Support Apache!" /></a><ul id="toc"><li><img alt="" src="./images/down.gif" /> <a href="#startup">C&#243;mo iniciar Apache</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#errors">Errores Durante el Arranque</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#boot">Iniciar Apache al Iniciar el Sistema</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#info">Informaci&#243;n Adicional</a></li>
</ul><h3>Consulte tambi&#233;n</h3><ul class="seealso"><li><a href="stopping.html">Parar y reiniciar Apache</a></li><li><code class="program"><a href="./programs/httpd.html">httpd</a></code></li><li><code class="program"><a href="./programs/apachectl.html">apachectl</a></code></li><li><a href="#comments_section">Comentarios</a></li></ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="startup" id="startup">C&#243;mo iniciar Apache</a></h2>

    <p>Si el puerto especificado en la directiva <code class="directive"><a href="./mod/mpm_common.html#listen">Listen</a></code> del fichero de
    configuraci&#243;n es el que viene por defecto, es decir, el
    puerto 80 (o cualquier otro puerto por debajo del 1024), entonces
    es necesario tener privilegios de usuario root (superusuario) para
    iniciar Apache, de modo que pueda establecerse una conexi&#243;n a
    trav&#233;s de esos puertos privilegiados. Una vez que el servidor
    Apache se ha iniciado y ha completado algunas tareas preliminares,
    tales como abrir sus ficheros log, lanzar&#225; varios procesos,
    procesos <em>hijo</em>, que hacen el trabajo de escuchar y atender
    las peticiones de los clientes.  El proceso principal,
    <code>httpd</code> contin&#250;a ejecut&#225;ndose con el usuario root, pero los
    procesos hijo se ejecutan con menores privilegios de usuario.
    Esto lo controla el <a href="mpm.html">M&#243;dulo de
    MultiProcesamiento (MPM)</a> seleccionado.</p>

    <p>La forma recomendada para invocar el ejecutable
    <code class="program"><a href="./programs/httpd.html">httpd</a></code> es usando el script de control 
    <code class="program"><a href="./programs/apachectl.html">apachectl</a></code>.  Este script fija
    determinadas variables de entorno que son necesarias para que
    <code class="program"><a href="./programs/httpd.html">httpd</a></code> funcione correctamente en el sistema operativo,
    y despu&#233;s invoca el binario <code class="program"><a href="./programs/httpd.html">httpd</a></code>.
    <code class="program"><a href="./programs/apachectl.html">apachectl</a></code> pasa a <code class="program"><a href="./programs/httpd.html">httpd</a></code>
    cualquier argumento que se le pase a trav&#233;s de la l&#237;nea de comandos, 
    de forma que cualquier opci&#243;n de <code>httpd</code> puede ser usada
    tambi&#233;n con <code>apachectl</code>.  Puede editar
    directamente el script <code>apachectl</code> y cambiar la
    variable <code>HTTPD</code> variable que est&#225; al principio y
    que especifica la ubicaci&#243;n exacta en la que est&#225; el
    binario <code class="program"><a href="./programs/httpd.html">httpd</a></code> y cualquier argumento de l&#237;nea de
    comandos que quiera que est&#233; <em>siempre</em> presente.</p>

    <p>La primera cosa que hace <code class="program"><a href="./programs/httpd.html">httpd</a></code> cuando es invocado
    es localizar y leer el <a href="configuring.html">fichero de
    configuraci&#243;n</a> <code>httpd.conf</code>. El lugar en el que
    est&#225; ese fichero se determina al compilar, pero tambi&#233;n
    es posible especificar la ubicaci&#243;n en la que se encuentra al
    iniciar el servidor Apache usando la opci&#243;n de l&#237;nea de
    comandos <code>-f</code></p>

<div class="example"><p><code>/usr/local/apache2/bin/apachectl -f
      /usr/local/apache2/conf/httpd.conf</code></p></div>

    <p>Si todo va bien durante el arranque, la sesi&#243;n de terminal
    se suspender&#225; un momento y volver&#225; a estar activa casi
    inmediatamente. Esto quiere decir que el servidor est&#225; activo
    y funcionando. Puede usar su navegador para conectarse al
    servidor y ver la p&#225;gina de prueba que hay en el directorio de
    la directiva
    <code class="directive"><a href="./mod/core.html#documentroot">DocumentRoot</a></code>.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="errors" id="errors">Errores Durante el Arranque</a></h2>

    <p>Si Apache encuentra una error irrecuperable durante el
    arranque, escribir&#225; un mensaje describiendo el problema en la
    consola o en el archivo <code class="directive"><a href="./mod/core.html#errorlog">ErrorLog</a></code> antes de abortar la
    ejecuci&#243;n. Uno de los mensajes de error m&#225;s comunes es
    "<code>Unable to bind to Port ...</code>". Cuando se recibe este
    mensaje es normalmente por alguna de las siguientes razones:</p>

    <ul>
      <li>Est&#225; intentando iniciar el servidor Apache en un puerto
      privilegiado (del 0 al 1024) sin haber hecho login como usuario
      root; &#243; bien</li>

      <li>Est&#225; intentando iniciar el servidor Apache mientras
      est&#225; ya ejecutando Apache o alg&#250;n otro servidor web en
      el mismo puerto.</li>
    </ul>

    <p>Puede encontrar m&#225;s informaci&#243;n sobre c&#243;mo
    solucionar problemas, en la secci&#243;n de <a href="http://wiki.apache.org/httpd/FAQ">Preguntas Frecuentes</a> de Apache.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="boot" id="boot">Iniciar Apache al Iniciar el Sistema</a></h2>

    <p>Si quiere que el servidor Apache contin&#250;e su ejecuci&#243;n
    despu&#233;s de reiniciar el sistema, debe a&#241;adir una llamada
    a <code class="program"><a href="./programs/apachectl.html">apachectl</a></code> en sus archivos de arranque (normalmente
    <code>rc.local</code> o un fichero en ese directorio del tipo
    <code>rc.N</code>). Esto iniciar&#225; Apache como usuario
    root. Antes de hacer esto, aseg&#250;rese de que la
    configuraci&#243;n de seguridad y las restricciones de acceso de
    su servidor Apache est&#225;n correctamente configuradas.</p>

    <p>El script <code class="program"><a href="./programs/apachectl.html">apachectl</a></code> est&#225; dise&#241;ado para
    actuar como un script est&#225;ndar de tipo <code>SysV init</code>; puede tomar los
    argumentos <code>start</code>, <code>restart</code>, y
    <code>stop</code> y traducirlos en las se&#241;ales apropiadas
    para <code class="program"><a href="./programs/httpd.html">httpd</a></code>.  De esta manera, casi siempre puede
    simplemente enlazar <code class="program"><a href="./programs/apachectl.html">apachectl</a></code>con el directorio init
    adecuado. Pero aseg&#250;rese de comprobar los requisitos exactos
    de su sistema.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="info" id="info">Informaci&#243;n Adicional</a></h2>

    <p>En la secci&#243;n <a href="programs/">El Servidor y Programas
    de Soporte </a> puede encontrar m&#225;s informaci&#243;n sobre
    las opciones de l&#237;nea de comandos que puede pasar a <code class="program"><a href="./programs/httpd.html">httpd</a></code> y <code class="program"><a href="./programs/apachectl.html">apachectl</a></code> as&#237; como sobre otros
    programas de soporte incluidos con el servidor Apache.
    Tambi&#233;n hay documentaci&#243;n sobre todos los <a href="mod/">m&#243;dulos</a> incluidos con la distribuci&#243;n de
    Apache y sus correspondientes <a href="mod/directives.html">directivas</a> asociadas.</p>
</div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="./de/invoking.html" hreflang="de" rel="alternate" title="Deutsch">&nbsp;de&nbsp;</a> |
<a href="./en/invoking.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/invoking.html" title="Espa&#241;ol">&nbsp;es&nbsp;</a> |
<a href="./fr/invoking.html" hreflang="fr" rel="alternate" title="Fran&#231;ais">&nbsp;fr&nbsp;</a> |
<a href="./ja/invoking.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/invoking.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./tr/invoking.html" hreflang="tr" rel="alternate" title="T&#252;rk&#231;e">&nbsp;tr&nbsp;</a></p>
</div><div class="top"><a href="#page-header"><img src="./images/up.gif" alt="top" /></a></div><div class="section"><h2><a id="comments_section" name="comments_section">Comentarios</a></h2><div class="warning"><strong>Notice:</strong><br />This is not a Q&amp;A section. Comments placed here should be pointed towards suggestions on improving the documentation or server, and may be removed again by our moderators if they are either implemented or considered invalid/off-topic. Questions on how to manage the Apache HTTP Server should be directed at either our IRC channel, #httpd, on Freenode, or sent to our <a href="http://httpd.apache.org/lists.html">mailing lists</a>.</div>
<script type="text/javascript"><!--//--><![CDATA[//><!--
var comments_shortname = 'httpd';
var comments_identifier = 'http://httpd.apache.org/docs/2.4/invoking.html';
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
<p class="apache">Copyright 2018 The Apache Software Foundation.<br />Licencia bajo los t&#233;rminos de la <a href="http://www.apache.org/licenses/LICENSE-2.0">Apache License, Version 2.0</a>.</p>
<p class="menu"><a href="./mod/">M&#243;dulos</a> | <a href="./mod/directives.html">Directivas</a> | <a href="http://wiki.apache.org/httpd/FAQ">Preguntas Frecuentes</a> | <a href="./glossary.html">Glosario</a> | <a href="./sitemap.html">Mapa del sitio web</a></p></div><script type="text/javascript"><!--//--><![CDATA[//><!--
if (typeof(prettyPrint) !== 'undefined') {
    prettyPrint();
}
//--><!]]></script>
</body></html>