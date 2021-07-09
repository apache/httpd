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
<title>Iniciar Apache - Servidor HTTP Apache</title>
<link href="./style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet" />
<link href="./style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size" />
<link href="./style/css/manual-print.css" rel="stylesheet" media="print" type="text/css" />
<link href="./images/favicon.ico" rel="shortcut icon" /><link href="http://httpd.apache.org/docs/current/invoking.html" rel="canonical" /></head>
<body id="manual-page"><div id="page-header">
<p class="menu"><a href="./mod/">M&#243;dulos</a> | <a href="./mod/directives.html">Directivas</a> | <a href="./faq/">Preguntas Frecuentes</a> | <a href="./glossary.html">Glosario</a> | <a href="./sitemap.html">Mapa de este sitio web</a></p>
<p class="apache">Versi&#243;n 2.0 del Servidor HTTP Apache</p>
<img alt="" src="./images/feather.gif" /></div>
<div class="up"><a href="./"><img title="&lt;-" alt="&lt;-" src="./images/left.gif" /></a></div>
<div id="path">
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs/">Documentaci&#243;n</a> &gt; <a href="./">Versi&#243;n 2.0</a></div><div id="page-content"><div class="retired"><h4>Please note</h4>
            <p>This document refers to the <strong>2.0</strong> version of Apache httpd, which <strong>is no longer maintained</strong>. Upgrade, and refer to the current version of httpd instead, documented at:</p>
        <ul><li><a href="http://httpd.apache.org/docs/current/">Current release version of Apache HTTP Server documentation</a></li></ul><p>You may follow <a href="http://httpd.apache.org/docs/current/invoking.html">this link</a> to go to the current version of this document.</p></div><div id="preamble"><h1>Iniciar Apache</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="./de/invoking.html" hreflang="de" rel="alternate" title="Deutsch">&nbsp;de&nbsp;</a> |
<a href="./en/invoking.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/invoking.html" title="Espa&#241;ol">&nbsp;es&nbsp;</a> |
<a href="./ja/invoking.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/invoking.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./ru/invoking.html" hreflang="ru" rel="alternate" title="Russian">&nbsp;ru&nbsp;</a> |
<a href="./tr/invoking.html" hreflang="tr" rel="alternate" title="T&#252;rk&#231;e">&nbsp;tr&nbsp;</a></p>
</div>

    <p>En Windows, Apache se ejecuta normalmente como un servicio en
    Windows NT, 2000 y XP, y como una aplicaci&#243;n de consola en
    Windows 9x y ME. Para obtener m&#225;s informaci&#243;n, consulte
    <a href="platform/windows.html#winsvc">Ejecutar Apache como un
    servicio</a> y <a href="platform/windows.html#wincons">Ejecutar
    Apache como una aplicaci&#243;n de consola</a>.</p>

    <p>En Unix, el programa <code class="program"><a href="./programs/httpd.html">httpd</a></code> se ejecuta como
    un demonio (daemon) en modo silencioso y atiende las peticiones
    que le lleguen.  Este documento explica c&#243;mo invocar el
    programa <code class="program"><a href="./programs/httpd.html">httpd</a></code>.</p>
</div>
<div id="quickview"><ul id="toc"><li><img alt="" src="./images/down.gif" /> <a href="#startup">C&#243;mo iniciar Apache</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#errors">Errores Durante el Arranque</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#boot">Iniciar Apache al Iniciar el Sistema</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#info">Informaci&#243;n Adicional</a></li>
</ul><h3>Consulte tambi&#233;n</h3><ul class="seealso"><li><a href="stopping.html">Parar y reiniciar Apache</a></li><li><code class="program"><a href="./programs/httpd.html">httpd</a></code></li><li><code class="program"><a href="./programs/apachectl.html">apachectl</a></code></li></ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="startup" id="startup">C&#243;mo iniciar Apache</a></h2>

    <p>Si el puerto especificado en la directiva <code class="directive"><a href="./mod/mpm_common.html#listen">Listen</a></code> del fichero de
    configuraci&#243;n es el que viene por defecto, es decir, el
    puerto 80 (o cualquier otro puerto por debajo del 1024), es
    necesario tener privilegios de usuario root (superusuario) para
    iniciar Apache. Solamente con esos privilegios puede establecerse
    una conexi&#243;n a trav&#233;s de esos puertos. Una vez que el
    servidor Apache se ha iniciado y ha completado algunas tareas
    preliminares, como abrir sus ficheros log, lanzar&#225; varios
    procesos <em>hijo</em>, que hacen el trabajo de escuchar y atender
    las peticiones de los clientes.  El proceso principal,
    <code>httpd</code> contin&#250;a ejecutandose como root, pero los
    procesos hijo se ejecutan con menores privilegios de usuario.
    Esto lo controla el <a href="mpm.html">m&#243;dulo de
    multiprocesamiento (MPM)</a> seleccionado.</p>

    <p>El m&#233;todo recomendado para invocar el ejecutable
    <code class="program"><a href="./programs/httpd.html">httpd</a></code> es usar el script de control
    <code class="program"><a href="./programs/apachectl.html">apachectl</a></code>.  Este script fija los valores de
    determinadas variables de entorno que son necesarias para que
    <code>httpd</code> funcione correctamente en el sistema operativo,
    y despu&#233;s invoca el binario <code class="program"><a href="./programs/httpd.html">httpd</a></code>.
    <code class="program"><a href="./programs/apachectl.html">apachectl</a></code> pasa a httpd cualquier argumento que
    se le pase a trav&#233;s de la l&#237;nea de comandos, de forma
    que cualquier opci&#243;n de <code class="program"><a href="./programs/httpd.html">httpd</a></code> puede ser
    usada tambi&#233;n con <code class="program"><a href="./programs/apachectl.html">apachectl</a></code>.  Puede editar
    directamente el script <code class="program"><a href="./programs/apachectl.html">apachectl</a></code> y cambiar la
    variable <code>HTTPD</code> que est&#225; al principio y que
    especifica la ubicaci&#243;n exacta en la que est&#225; el binario
    <code class="program"><a href="./programs/httpd.html">httpd</a></code> y cualquier argumento de l&#237;nea de
    comandos que quiera que est&#233; <em>siempre</em> presente cuando
    use este script.</p>

    <p>La primera cosa que hace <code>httpd</code> cuando es invocado
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
    y funcionando.  Puede usar su navegador para conectarse al
    servidor y ver la p&#225;gina de prueba que hay en el directorio
    <code class="directive"><a href="./mod/core.html#documentroot">DocumentRoot</a></code> y la copia local
    de esta documentaci&#243;n a la que se puede acceder desde esa
    p&#225;gina.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="errors" id="errors">Errores Durante el Arranque</a></h2>

    <p>Si se produce alg&#250;n error irrecuperable durante el proceso de
    arranque de Apache, aparecer&#225; un mensaje describiendo el
    problema en la consola o en el archivo <code class="directive"><a href="./mod/core.html#errorlog">ErrorLog</a></code> antes de abortar la
    ejecuci&#243;n. Uno de los mensajes de error m&#225;s comunes es
    "<code>Unable to bind to Port ...</code>". Cuando se recibe este
    mensaje es normalmente por alguna de las siguientes razones:</p>

    <ul>
      <li>Est&#225; intentando iniciar el servidor Apache en un puerto
      privilegiado (del 0 al 1024) sin haber hecho login como usuario
      root; &#243;</li>

      <li>Est&#225; intentando iniciar el servidor Apache mientras
      est&#225; ya ejecutando Apache o alg&#250;n otro servidor web en
      el mismo puerto.</li>
    </ul>

    <p>Puede encontrar m&#225;s informaci&#243;n sobre c&#243;mo
    solucionar estos problemas, en la secci&#243;n de <a href="faq/">Preguntas Frecuentes</a> de Apache.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="boot" id="boot">Iniciar Apache al Iniciar el Sistema</a></h2>

    <p>Si quiere que el servidor Apache contin&#250;e su
    ejecuci&#243;n despu&#233;s de reiniciar el sistema, debe
    a&#241;adir una llamada a <code class="program"><a href="./programs/apachectl.html">apachectl</a></code> en sus
    archivos de arranque (normalmente <code>rc.local</code> o
    alg&#250;n fichero un directorio del tipo <code>rc.N</code>). Esto
    iniciar&#225; Apache como usuario root. Antes de hacer esto,
    aseg&#250;rese de que la configuraci&#243;n de seguridad y las
    restricciones de acceso de su servidor Apache est&#225;n
    correctamente configuradas.</p>

    <p>El script <code class="program"><a href="./programs/apachectl.html">apachectl</a></code> est&#225; dise&#241;ado
    para actuar como un script est&#225;ndar de tipo SysV init; puede
    tomar los argumentos <code>start</code>, <code>restart</code>, y
    <code>stop</code> y traducirlos en las se&#241;ales apropiadas
    para <code class="program"><a href="./programs/httpd.html">httpd</a></code>.  De esta manera, casi siempre puede
    simplemente enlazar <code class="program"><a href="./programs/apachectl.html">apachectl</a></code> con el directorio
    init adecuado. Pero aseg&#250;rese de comprobar cuales son los
    requerimientos espec&#237;ficos de su sistema.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="info" id="info">Informaci&#243;n Adicional</a></h2>

    <p>En la secci&#243;n <a href="programs/">El Servidor y Programas
    de Soporte</a> puede encontrar m&#225;s informaci&#243;n sobre las
    opciones de l&#237;nea de comandos que puede pasar a
    <code class="program"><a href="./programs/httpd.html">httpd</a></code> y a <code class="program"><a href="./programs/apachectl.html">apachectl</a></code> as&#237;
    como sobre otros programas de soporte incluidos con el servidor
    Apache. Tambi&#233;n hay documentaci&#243;n sobre todos los <a href="mod/">m&#243;dulos</a> incluidos con la distribuci&#243;n de
    Apache y sus correspondientes <a href="mod/directives.html">directivas</a> asociadas.</p>
</div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="./de/invoking.html" hreflang="de" rel="alternate" title="Deutsch">&nbsp;de&nbsp;</a> |
<a href="./en/invoking.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/invoking.html" title="Espa&#241;ol">&nbsp;es&nbsp;</a> |
<a href="./ja/invoking.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/invoking.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./ru/invoking.html" hreflang="ru" rel="alternate" title="Russian">&nbsp;ru&nbsp;</a> |
<a href="./tr/invoking.html" hreflang="tr" rel="alternate" title="T&#252;rk&#231;e">&nbsp;tr&nbsp;</a></p>
</div><div id="footer">
<p class="apache">Copyright 2013 The Apache Software Foundation.<br />Licencia bajo los t&#233;rminos de la <a href="http://www.apache.org/licenses/LICENSE-2.0">Apache License, Version 2.0</a>.</p>
<p class="menu"><a href="./mod/">M&#243;dulos</a> | <a href="./mod/directives.html">Directivas</a> | <a href="./faq/">Preguntas Frecuentes</a> | <a href="./glossary.html">Glosario</a> | <a href="./sitemap.html">Mapa de este sitio web</a></p></div>
</body></html>