<!DOCTYPE html SYSTEM "about:legacy-compat">
<html lang="es"><head><META http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<meta content="width=device-width, initial-scale=1" name="viewport">
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Iniciar y Parar el servidor Apache - Servidor HTTP Apache Versi&oacute;n 2.4</title>
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
<a href="https://www.apache.org/">Apache</a> &gt; <a href="https://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="https://httpd.apache.org/docs/">Documentaci&oacute;n</a> &gt; <a href="./">Versi&oacute;n 2.4</a></div><div id="page-content"><div id="preamble"><h1>Iniciar y Parar el servidor Apache</h1>
<button aria-label="Toggle language list" class="lang-toggle"><svg xmlns="http://www.w3.org/2000/svg" stroke-width="2" stroke="currentColor" fill="none" viewBox="0 0 24 24" height="16" width="16"><circle r="10" cy="12" cx="12"/><line y2="12" x2="22" y1="12" x1="2"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></button>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="./de/stopping.html" hreflang="de" rel="alternate" title="Deutsch">&nbsp;de&nbsp;</a> |
<a href="./en/stopping.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/stopping.html" title="Espa&ntilde;ol">&nbsp;es&nbsp;</a> |
<a href="./fr/stopping.html" hreflang="fr" rel="alternate" title="Fran&ccedil;ais">&nbsp;fr&nbsp;</a> |
<a href="./ja/stopping.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/stopping.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./tr/stopping.html" hreflang="tr" rel="alternate" title="T&uuml;rk&ccedil;e">&nbsp;tr&nbsp;</a></p>
</div>
<div class="outofdate">Esta traducci&oacute;n podr&iacute;a estar
            obsoleta. Consulte la versi&oacute;n en ingl&eacute;s de la
            documentaci&oacute;n para comprobar si se han producido cambios
            recientemente.</div>

    <p>Este documento explica como iniciar y parar el servidor Apache
     en sistemas tipo Unix. Los usuarios de Windows NT, 2000 y XP
     deben consultar la secci&oacute;n <a href="platform/windows.html#winsvc">Ejecutar Apache como un
     servicio</a> y los usuario de Windows 9x y ME deben consultar <a href="platform/windows.html#wincons">Ejecutar Apache como una
     Aplicaci&oacute;n de Consola</a> para obtener informaci&oacute;n
     sobre como controlar Apache en esas plataformas.</p>
</div>
<div id="quickview"><ul id="toc"><li><img alt="" src="./images/down.gif"> <a href="#introduction">Introducci&oacute;n</a></li>
<li><img alt="" src="./images/down.gif"> <a href="#term">Parar Apache</a></li>
<li><img alt="" src="./images/down.gif"> <a href="#graceful">Reinicio Graceful</a></li>
<li><img alt="" src="./images/down.gif"> <a href="#hup">Reiniciar Apache</a></li>
<li><img alt="" src="./images/down.gif"> <a href="#race">Ap&eacute;ndice: se&ntilde;ales y race conditions</a></li>
</ul><h3>Consulte tambi&eacute;n</h3><ul class="seealso"><li><a href="programs/httpd.html">httpd</a></li><li><a href="programs/apachectl.html">apachectl</a></li></ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section">
<h2 id="introduction">Introducci&oacute;n <a title="Enlace permanente" href="#introduction" class="permalink">&para;</a></h2>

    <p>Para parar y reiniciar Apache, hay que enviar la se&ntilde;al
    apropiada al proceso padre <code>httpd</code> que se est&eacute;
    ejecutando.  Hay dos maneras de enviar estas se&ntilde;ales.  En
    primer lugar, puede usar el comando de Unix <code>kill</code> que
    env&iacute;a se&ntilde;ales directamente a los procesos. Puede que
    tenga varios procesos <code>httpd</code> ejecutandose en su
    sistema, pero las se&ntilde;ales deben enviarse solamente al proceso
    padre, cuyo pid est&aacute; especificado en la directiva <code class="directive"><a href="./mod/mpm_common.html#pidfile">PidFile</a></code>. Esto quiere decir que no
    debe necesitar enviar se&ntilde;ales a ning&uacute;n proceso excepto
    al proceso padre. Hay tres se&ntilde;ales que puede enviar al
    proceso padre: <code><a href="#term">TERM</a></code>, <code><a href="#hup">HUP</a></code>, y <code><a href="#graceful">USR1</a></code>, que van a ser descritas a
    continuaci&oacute;n.</p>

    <p>Para enviar una se&ntilde;al al proceso padre debe escribir un
    comando como el que se muestra en el ejemplo:</p>

<div class="example"><p><code>kill -TERM `cat /usr/local/apache2/logs/httpd.pid`</code></p></div>

    <p>La segunda manera de enviar se&ntilde;ales a los procesos
    <code>httpd</code> es usando las opciones de l&iacute;nea de
    comandos <code>-k</code>: <code>stop</code>, <code>restart</code>,
    y <code>graceful</code>, como se muestra m&aacute;s abajo.  Estas
    opciones se le pueden pasar al binario <a href="programs/httpd.html">httpd</a>, pero se recomienda que se
    pasen al script de control <a href="programs/apachectl.html">apachectl</a>, que a su vez los
    pasar&aacute; a <code>httpd</code>.</p>

    <p>Despu&eacute;s de haber enviado las se&ntilde;ales que desee a
    <code>httpd</code>, puede ver como progresa el proceso
    escribiendo:</p>

<div class="example"><p><code>tail -f /usr/local/apache2/logs/error_log</code></p></div>

    <p>Modifique estos ejemplos para que coincidan con la
    configuraci&oacute;n que tenga especificada en las directivas
    <code class="directive"><a href="./mod/core.html#serverroot">ServerRoot</a></code> y <code class="directive"><a href="./mod/mpm_common.html#pidfile">PidFile</a></code> en su fichero principal de
    configuraci&oacute;n.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section">
<h2 id="term">Parar Apache <a title="Enlace permanente" href="#term" class="permalink">&para;</a></h2>

<dl><dt>Se&ntilde;al: TERM</dt>
<dd><code>apachectl -k stop</code></dd>
</dl>

    <p>Enviar las se&ntilde;ales <code>TERM</code> o <code>stop</code>
    al proceso padre hace que se intenten eliminar todos los procesos
    hijo inmediatamente. Esto puede tardar algunos minutos. Una vez
    que hayan terminado todos los procesos hijo, terminar&aacute; el
    proceso padre. Cualquier petici&oacute;n en proceso terminar&aacute;
    inmediatanmente, y ninguna petici&oacute;n posterior ser&aacute;
    atendida.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section">
<h2 id="graceful">Reinicio Graceful <a title="Enlace permanente" href="#graceful" class="permalink">&para;</a></h2>

<dl><dt>Se&ntilde;al: USR1</dt>
<dd><code>apachectl -k graceful</code></dd>
</dl>

    <p>Las se&ntilde;ales <code>USR1</code> o <code>graceful</code>
    hacen que el proceso padre <em>indique</em> a sus hijos que
    terminen despu&eacute;s de servir la petici&oacute;n que est&eacute;n
    atendiendo en ese momento (o de inmediato si no est&aacute;n
    sirviendo ninguna petici&oacute;n). El proceso padre lee de nuevo
    sus ficheros de configuraci&oacute;n y vuelve a abrir sus ficheros
    log. Conforme cada hijo va terminando, el proceso padre lo va
    sustituyendo con un hijo de una nueva <em>generaci&oacute;n</em> con
    la nueva configuraci&oacute;n, que empeciezan a servir peticiones
    inmediatamente.</p>

    <div class="note">En algunas plataformas que no permiten usar
    <code>USR1</code> para reinicios graceful, puede usarse una
    se&ntilde;al alternativa (como <code>WINCH</code>). Tambien puede
    usar <code>apachectl graceful</code> y el script de control
    enviar&aacute; la se&ntilde;al adecuada para su plataforma.</div>

    <p>Apache est&aacute; dise&ntilde;ado para respetar en todo momento la
    directiva de control de procesos de los MPM, as&iacute; como para
    que el n&uacute;mero de procesos y hebras disponibles para servir a
    los clientes se mantenga en los valores adecuados durante el
    proceso de reinicio.  A&uacute;n m&aacute;s, est&aacute; dise&ntilde;ado
    para respetar la directiva <code class="directive"><a href="./mod/mpm_common.html#startservers">StartServers</a></code> de la siguiente
    manera: si despu&eacute;s de al menos un segundo el nuevo hijo de la
    directiva <code class="directive"><a href="./mod/mpm_common.html#startservers">StartServers</a></code>
    no ha sido creado, entonces crea los suficientes para se atienda
    el trabajo que queda por hacer. As&iacute;, se intenta mantener
    tanto el n&uacute;mero de hijos adecuado para el trabajo que el
    servidor tenga en ese momento, como respetar la configuraci&oacute;n
    determinada por los par&aacute;metros de la directiva
    <code class="directive">StartServers</code>.</p>

    <p>Los usuarios del m&oacute;dulo <code class="module"><a href="./mod/mod_status.html">mod_status</a></code>
    notar&aacute;n que las estad&iacute;sticas del servidor
    <strong>no</strong> se ponen a cero cuando se usa la se&ntilde;al
    <code>USR1</code>. Apache fue escrito tanto para minimizar el
    tiempo en el que el servidor no puede servir nuevas peticiones
    (que se pondr&aacute;n en cola por el sistema operativo, de modo que
    se no se pierda ning&uacute;n evento), como para respetar sus
    par&aacute;metros de ajuste. Para hacer esto, tiene que guardar el
    <em>scoreboard</em> usado para llevar el registro de los procesos
    hijo a trav&eacute;s de las distintas generaciones.</p>

    <p>El mod_status tambi&eacute;n usa una <code>G</code> para indicar
    que esos hijos est&aacute;n todav&iacute;a sirviendo peticiones
    previas al reinicio graceful.</p>

    <p>Actualmente no existe ninguna manera de que un script con un
    log de rotaci&oacute;n usando <code>USR1</code> sepa con seguridad
    que todos los hijos que se registraron en el log con anterioridad
    al reinicio han terminado. Se aconseja que se use un retardo
    adecuado despu&eacute;s de enviar la se&ntilde;al <code>USR1</code>
    antes de hacer nada con el log antiguo. Por ejemplo, si la mayor
    parte las visitas que recibe de usuarios que tienen conexiones de
    baja velocidad tardan menos de 10 minutos en completarse, entoces
    espere 15 minutos antes de hacer nada con el log antiguo.</p>

    <div class="note">Si su fichero de configuraci&oacute;n tiene errores cuando
    haga el reinicio, entonces el proceso padre no se reinciciar&aacute;
    y terminar&aacute; con un error. En caso de un reinicio graceful,
    tambi&eacute;n dejar&aacute; a los procesos hijo ejecutandose mientras
    existan.  (Estos son los hijos de los que se est&aacute; saliendo de
    forma graceful y que est&aacute;n sirviendo sus &uacute;ltimas
    peticiones.) Esto provocar&aacute; problemas si intenta reiniciar el
    servidor -- no ser&aacute; posible conectarse a la lista de puertos
    de escucha. Antes de reiniciar, puede comprobar que la sintaxis de
    sus ficheros de configuracion es correcta con la opci&oacute;n de
    l&iacute;nea de comandos <code>-t</code> (consulte <a href="programs/httpd.html">httpd</a>). No obstante, esto no
    garantiza que el servidor se reinicie correctamente. Para
    comprobar que no hay errores en los ficheros de
    configuraci&oacute;n, puede intentar iniciar <code>httpd</code> con
    un usuario diferente a root. Si no hay errores, intentar&aacute;
    abrir sus sockets y logs y fallar&aacute; porque el usuario no es
    root (o porque el <code>httpd</code> que se est&aacute; ejecutando
    en ese momento ya est&aacute; conectado a esos puertos). Si falla
    por cualquier otra raz&oacute;n, entonces casi seguro que hay
    alg&uacute;n error en alguno de los ficheros de configuraci&oacute;n y
    debe corregir ese o esos errores antes de hacer un reinicio
    graceful.</div>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section">
<h2 id="hup">Reiniciar Apache <a title="Enlace permanente" href="#hup" class="permalink">&para;</a></h2>

<dl><dt>Se&ntilde;al: HUP</dt>
<dd><code>apachectl -k restart</code></dd>
</dl>

    <p>El env&iacute;o de las se&ntilde;ales <code>HUP</code> o
    <code>restart</code> al proceso padre hace que los procesos hijo
    terminen como si le envi&aacute; ramos la se&ntilde;al
    <code>TERM</code>, para eliminar el proceso padre. La diferencia
    est&aacute; en que estas se&ntilde;ales vuelven a leer los archivos de
    configuraci&oacute;n y vuelven a abrir los ficheros log. Se genera
    un nuevo conjunto de hijos y se contin&uacute;a sirviendo
    peticiones.</p>

    <p>Los usuarios del m&oacute;dulo <code class="module"><a href="./mod/mod_status.html">mod_status</a></code>
    notar&aacute;n que las estad&iacute;sticas del servidor se ponen a
    cero cuando se env&iacute;a la se&ntilde;al <code>HUP</code>.</p>

<div class="note">Si su fichero de configuraci&oacute;n contiene errores, cuando
intente reiniciar, el proceso padre del servidor no se
reiniciar&aacute;, sino que terminar&aacute; con un error. Consulte
m&aacute;s arriba c&oacute;mo puede solucionar este problema.</div>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section">
<h2 id="race">Ap&eacute;ndice: se&ntilde;ales y race conditions <a title="Enlace permanente" href="#race" class="permalink">&para;</a></h2>

    <p>Con anterioridad a la versi&oacute;n de Apache 1.2b9 hab&iacute;a
    varias <em>race conditions</em> implicadas en las se&ntilde;ales
    para parar y reiniciar procesos (una descripci&oacute;n sencilla de
    una race condition es: un problema relacionado con el momento en
    que suceden las cosas, como si algo sucediera en momento en que no
    debe, y entonces el resultado esperado no se corresponde con el
    obtenido). Para aquellas arquitecturas que tienen el conjunto de
    caracter&iacute;sticas "adecuadas", se han eliminado tantas race
    conditions como ha sido posible. Pero hay que tener en cuenta que
    todav&iacute;a existen race conditions en algunas arquitecturas.</p>

    <p>En las arquitecturas que usan un <code class="directive"><a href="./mod/mpm_common.html#scoreboardfile">ScoreBoardFile</a></code> en disco, existe la
    posibilidad de que se corrompan los scoreboards. Esto puede hacer
    que se produzca el error "bind: Address already in use"
    (despu&eacute;s de usar<code>HUP</code>) o el error "long lost child
    came home!"  (despu&eacute;s de usar <code>USR1</code>). En el
    primer caso se trata de un error irrecuperable, mientras que en el
    segundo, solo ocurre que el servidor pierde un slot del
    scoreboard. Por lo tanto, ser&iacute;a aconsejable usar reinicios
    graceful, y solo hacer reinicios normales de forma
    ocasional. Estos problemas son bastante complicados de solucionar,
    pero afortunadamente casi ninguna arquitectura necesita un fichero
    scoreboard. Consulte la documentaci&oacute;n de la directiva
    <code class="directive"><a href="./mod/mpm_common.html#scoreboardfile">ScoreBoardFile</a></code> para ver
    las arquitecturas que la usan.</p>

    <p>Todas las arquitecturas tienen una peque&ntilde;a race condition
    en cada proceso hijo implicada en la segunda y subsiguientes
    peticiones en una conexi&oacute;n HTTP persistente
    (KeepAlive). Puede ser que el servidor termine despu&eacute;s de
    leer la l&iacute;nea de petici&oacute;n pero antes de leer cualquiera
    de las cebeceras de petici&oacute;n. Hay una soluci&oacute;n que fue
    descubierta demasiado tarde para la incluirla en versi&oacute;n
    1.2. En teoria esto no debe suponer ning&uacute;n problema porque el
    cliente KeepAlive ha de esperar que estas cosas pasen debido a los
    retardos de red y a los timeouts que a veces dan los
    servidores. En la practica, parece que no afecta a nada m&aacute;s
    -- en una sesi&oacute;n de pruebas, un servidor se reinici&oacute;
    veinte veces por segundo y los clientes pudieron navegar sin
    problemas por el sitio web sin encontrar problemas ni para
    descargar una sola imagen ni encontrar un solo enlace roto. </p>
</div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="./de/stopping.html" hreflang="de" rel="alternate" title="Deutsch">&nbsp;de&nbsp;</a> |
<a href="./en/stopping.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/stopping.html" title="Espa&ntilde;ol">&nbsp;es&nbsp;</a> |
<a href="./fr/stopping.html" hreflang="fr" rel="alternate" title="Fran&ccedil;ais">&nbsp;fr&nbsp;</a> |
<a href="./ja/stopping.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/stopping.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./tr/stopping.html" hreflang="tr" rel="alternate" title="T&uuml;rk&ccedil;e">&nbsp;tr&nbsp;</a></p>
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