<!DOCTYPE html SYSTEM "about:legacy-compat">
<html lang="es"><head><META http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<meta content="width=device-width, initial-scale=1" name="viewport">
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Iniciar Apache - Servidor HTTP Apache Versi&oacute;n 2.4</title>
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
<a href="https://www.apache.org/">Apache</a> &gt; <a href="https://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="https://httpd.apache.org/docs/">Documentaci&oacute;n</a> &gt; <a href="./">Versi&oacute;n 2.4</a></div><div id="page-content"><div id="preamble"><h1>Iniciar Apache</h1>
<button aria-label="Toggle language list" class="lang-toggle"><svg xmlns="http://www.w3.org/2000/svg" stroke-width="2" stroke="currentColor" fill="none" viewBox="0 0 24 24" height="16" width="16"><circle r="10" cy="12" cx="12"/><line y2="12" x2="22" y1="12" x1="2"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></button>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="./de/invoking.html" hreflang="de" rel="alternate" title="Deutsch">&nbsp;de&nbsp;</a> |
<a href="./en/invoking.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/invoking.html" title="Espa&ntilde;ol">&nbsp;es&nbsp;</a> |
<a href="./fr/invoking.html" hreflang="fr" rel="alternate" title="Fran&ccedil;ais">&nbsp;fr&nbsp;</a> |
<a href="./ja/invoking.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/invoking.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./pt-br/invoking.html" hreflang="pt-br" rel="alternate" title="Portugu&ecirc;s (Brasil)">&nbsp;pt-br&nbsp;</a> |
<a href="./tr/invoking.html" hreflang="tr" rel="alternate" title="T&uuml;rk&ccedil;e">&nbsp;tr&nbsp;</a></p>
</div>
<div class="outofdate">Esta traducci&oacute;n podr&iacute;a estar
            obsoleta. Consulte la versi&oacute;n en ingl&eacute;s de la
            documentaci&oacute;n para comprobar si se han producido cambios
            recientemente.</div>

    <p>En Windows, Apache se ejecuta normalmente como un servicio. 
        Para obtener m&aacute;s informaci&oacute;n, consulte
    <a href="platform/windows.html#winsvc">Ejecutar Apache como un
    servicio</a>.</p>

    <p>En Unix, el programa <code class="program"><a href="./programs/httpd.html">httpd</a></code> se
    ejecuta como un demonio (daemon) de forma cont&iacute;niua y en segundo plano
    y atiende las peticiones que le lleguen.  Este documento describe c&oacute;mo
    invocar el programa <code class="program"><a href="./programs/httpd.html">httpd</a></code>.</p>
</div>
<div id="quickview"><ul id="toc"><li><img alt="" src="./images/down.gif"> <a href="#startup">C&oacute;mo iniciar Apache</a></li>
<li><img alt="" src="./images/down.gif"> <a href="#errors">Errores Durante el Arranque</a></li>
<li><img alt="" src="./images/down.gif"> <a href="#boot">Iniciar Apache al Iniciar el Sistema</a></li>
<li><img alt="" src="./images/down.gif"> <a href="#info">Informaci&oacute;n Adicional</a></li>
</ul><h3>Consulte tambi&eacute;n</h3><ul class="seealso"><li><a href="stopping.html">Parar y reiniciar Apache</a></li><li><code class="program"><a href="./programs/httpd.html">httpd</a></code></li><li><code class="program"><a href="./programs/apachectl.html">apachectl</a></code></li></ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section">
<h2 id="startup">C&oacute;mo iniciar Apache <a title="Enlace permanente" href="#startup" class="permalink">&para;</a></h2>

    <p>Si el puerto especificado en la directiva <code class="directive"><a href="./mod/mpm_common.html#listen">Listen</a></code> del fichero de
    configuraci&oacute;n es el que viene por defecto, es decir, el
    puerto 80 (o cualquier otro puerto por debajo del 1024), entonces
    es necesario tener privilegios de usuario root (superusuario) para
    iniciar Apache, de modo que pueda establecerse una conexi&oacute;n a
    trav&eacute;s de esos puertos privilegiados. Una vez que el servidor
    Apache se ha iniciado y ha completado algunas tareas preliminares,
    tales como abrir sus ficheros log, lanzar&aacute; varios procesos,
    procesos <em>hijo</em>, que hacen el trabajo de escuchar y atender
    las peticiones de los clientes.  El proceso principal,
    <code>httpd</code> contin&uacute;a ejecut&aacute;ndose con el usuario root, pero los
    procesos hijo se ejecutan con menores privilegios de usuario.
    Esto lo controla el <a href="mpm.html">M&oacute;dulo de
    MultiProcesamiento (MPM)</a> seleccionado.</p>

    <p>La forma recomendada para invocar el ejecutable
    <code class="program"><a href="./programs/httpd.html">httpd</a></code> es usando el script de control 
    <code class="program"><a href="./programs/apachectl.html">apachectl</a></code>.  Este script fija
    determinadas variables de entorno que son necesarias para que
    <code class="program"><a href="./programs/httpd.html">httpd</a></code> funcione correctamente en el sistema operativo,
    y despu&eacute;s invoca el binario <code class="program"><a href="./programs/httpd.html">httpd</a></code>.
    <code class="program"><a href="./programs/apachectl.html">apachectl</a></code> pasa a <code class="program"><a href="./programs/httpd.html">httpd</a></code>
    cualquier argumento que se le pase a trav&eacute;s de la l&iacute;nea de comandos, 
    de forma que cualquier opci&oacute;n de <code>httpd</code> puede ser usada
    tambi&eacute;n con <code>apachectl</code>.  Puede editar
    directamente el script <code>apachectl</code> y cambiar la
    variable <code>HTTPD</code> variable que est&aacute; al principio y
    que especifica la ubicaci&oacute;n exacta en la que est&aacute; el
    binario <code class="program"><a href="./programs/httpd.html">httpd</a></code> y cualquier argumento de l&iacute;nea de
    comandos que quiera que est&eacute; <em>siempre</em> presente.</p>

    <p>La primera cosa que hace <code class="program"><a href="./programs/httpd.html">httpd</a></code> cuando es invocado
    es localizar y leer el <a href="configuring.html">fichero de
    configuraci&oacute;n</a> <code>httpd.conf</code>. El lugar en el que
    est&aacute; ese fichero se determina al compilar, pero tambi&eacute;n
    es posible especificar la ubicaci&oacute;n en la que se encuentra al
    iniciar el servidor Apache usando la opci&oacute;n de l&iacute;nea de
    comandos <code>-f</code></p>

<div class="example"><p><code>/usr/local/apache2/bin/apachectl -f
      /usr/local/apache2/conf/httpd.conf</code></p></div>

    <p>Si todo va bien durante el arranque, la sesi&oacute;n de terminal
    se suspender&aacute; un momento y volver&aacute; a estar activa casi
    inmediatamente. Esto quiere decir que el servidor est&aacute; activo
    y funcionando. Puede usar su navegador para conectarse al
    servidor y ver la p&aacute;gina de prueba que hay en el directorio de
    la directiva
    <code class="directive"><a href="./mod/core.html#documentroot">DocumentRoot</a></code>.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section">
<h2 id="errors">Errores Durante el Arranque <a title="Enlace permanente" href="#errors" class="permalink">&para;</a></h2>

    <p>Si Apache encuentra una error irrecuperable durante el
    arranque, escribir&aacute; un mensaje describiendo el problema en la
    consola o en el archivo <code class="directive"><a href="./mod/core.html#errorlog">ErrorLog</a></code> antes de abortar la
    ejecuci&oacute;n. Uno de los mensajes de error m&aacute;s comunes es
    "<code>Unable to bind to Port ...</code>". Cuando se recibe este
    mensaje es normalmente por alguna de las siguientes razones:</p>

    <ul>
      <li>Est&aacute; intentando iniciar el servidor Apache en un puerto
      privilegiado (del 0 al 1024) sin haber hecho login como usuario
      root; &oacute; bien</li>

      <li>Est&aacute; intentando iniciar el servidor Apache mientras
      est&aacute; ya ejecutando Apache o alg&uacute;n otro servidor web en
      el mismo puerto.</li>
    </ul>

    <p>Puede encontrar m&aacute;s informaci&oacute;n sobre c&oacute;mo
    solucionar problemas, en la secci&oacute;n de <a href="https://cwiki.apache.org/confluence/display/httpd/FAQ">Preguntas Frecuentes</a> de Apache.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section">
<h2 id="boot">Iniciar Apache al Iniciar el Sistema <a title="Enlace permanente" href="#boot" class="permalink">&para;</a></h2>

    <p>Si quiere que el servidor Apache contin&uacute;e su ejecuci&oacute;n
    despu&eacute;s de reiniciar el sistema, debe a&ntilde;adir una llamada
    a <code class="program"><a href="./programs/apachectl.html">apachectl</a></code> en sus archivos de arranque (normalmente
    <code>rc.local</code> o un fichero en ese directorio del tipo
    <code>rc.N</code>). Esto iniciar&aacute; Apache como usuario
    root. Antes de hacer esto, aseg&uacute;rese de que la
    configuraci&oacute;n de seguridad y las restricciones de acceso de
    su servidor Apache est&aacute;n correctamente configuradas.</p>

    <p>El script <code class="program"><a href="./programs/apachectl.html">apachectl</a></code> est&aacute; dise&ntilde;ado para
    actuar como un script est&aacute;ndar de tipo <code>SysV init</code>; puede tomar los
    argumentos <code>start</code>, <code>restart</code>, y
    <code>stop</code> y traducirlos en las se&ntilde;ales apropiadas
    para <code class="program"><a href="./programs/httpd.html">httpd</a></code>.  De esta manera, casi siempre puede
    simplemente enlazar <code class="program"><a href="./programs/apachectl.html">apachectl</a></code>con el directorio init
    adecuado. Pero aseg&uacute;rese de comprobar los requisitos exactos
    de su sistema.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section">
<h2 id="info">Informaci&oacute;n Adicional <a title="Enlace permanente" href="#info" class="permalink">&para;</a></h2>

    <p>En la secci&oacute;n <a href="programs/">El Servidor y Programas
    de Soporte </a> puede encontrar m&aacute;s informaci&oacute;n sobre
    las opciones de l&iacute;nea de comandos que puede pasar a <code class="program"><a href="./programs/httpd.html">httpd</a></code> y <code class="program"><a href="./programs/apachectl.html">apachectl</a></code> as&iacute; como sobre otros
    programas de soporte incluidos con el servidor Apache.
    Tambi&eacute;n hay documentaci&oacute;n sobre todos los <a href="mod/">m&oacute;dulos</a> incluidos con la distribuci&oacute;n de
    Apache y sus correspondientes <a href="mod/directives.html">directivas</a> asociadas.</p>
</div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="./de/invoking.html" hreflang="de" rel="alternate" title="Deutsch">&nbsp;de&nbsp;</a> |
<a href="./en/invoking.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/invoking.html" title="Espa&ntilde;ol">&nbsp;es&nbsp;</a> |
<a href="./fr/invoking.html" hreflang="fr" rel="alternate" title="Fran&ccedil;ais">&nbsp;fr&nbsp;</a> |
<a href="./ja/invoking.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/invoking.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./pt-br/invoking.html" hreflang="pt-br" rel="alternate" title="Portugu&ecirc;s (Brasil)">&nbsp;pt-br&nbsp;</a> |
<a href="./tr/invoking.html" hreflang="tr" rel="alternate" title="T&uuml;rk&ccedil;e">&nbsp;tr&nbsp;</a></p>
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