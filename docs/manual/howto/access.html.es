<!DOCTYPE html SYSTEM "about:legacy-compat">
<html lang="es"><head><META http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<meta content="width=device-width, initial-scale=1" name="viewport">
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Control de Acceso - Servidor HTTP Apache Versi&oacute;n 2.4</title>
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
<a href="https://www.apache.org/">Apache</a> &gt; <a href="https://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="https://httpd.apache.org/docs/">Documentaci&oacute;n</a> &gt; <a href="../">Versi&oacute;n 2.4</a> &gt; <a href="./">How-To / Tutoriales</a></div><div id="page-content"><div id="preamble"><h1>Control de Acceso</h1>
<button aria-label="Toggle language list" class="lang-toggle"><svg xmlns="http://www.w3.org/2000/svg" stroke-width="2" stroke="currentColor" fill="none" viewBox="0 0 24 24" height="16" width="16"><circle r="10" cy="12" cx="12"/><line y2="12" x2="22" y1="12" x1="2"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></button>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="../en/howto/access.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/howto/access.html" title="Espa&ntilde;ol">&nbsp;es&nbsp;</a> |
<a href="../fr/howto/access.html" hreflang="fr" rel="alternate" title="Fran&ccedil;ais">&nbsp;fr&nbsp;</a></p>
</div>
<div class="outofdate">Esta traducci&oacute;n podr&iacute;a estar
            obsoleta. Consulte la versi&oacute;n en ingl&eacute;s de la
            documentaci&oacute;n para comprobar si se han producido cambios
            recientemente.</div>

    <p>El control de acceso, hace referencia a todos los medios que proporcionan
        una forma de controlar el acceso a cualquier recurso. Esta parte est&aacute;
        separada de <a href="auth.html">autenticaci&oacute;n y autorizaci&oacute;n</a>.</p>
</div>
<div id="quickview"><ul id="toc"><li><img alt="" src="../images/down.gif"> <a href="#related">M&oacute;dulos y Directivas relacionados</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#host">Control de Acceso por host</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#env">Control de acceso por variables arbitrarias.</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#rewrite">Control de acceso con mod_rewrite</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#moreinformation">M&aacute;s informaci&oacute;n</a></li>
</ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="related">M&oacute;dulos y Directivas relacionados <a title="Enlace permanente" href="#related" class="permalink">&para;</a></h2>

    <p>El control de acceso puede efectuarse mediante diferentes m&oacute;dulos. Los 
    m&aacute;s importantes de &eacute;stos son <code class="module"><a href="../mod/mod_authz_core.html">mod_authz_core</a></code> y
    <code class="module"><a href="../mod/mod_authz_host.html">mod_authz_host</a></code>. Tambi&eacute;n se habla en este documento de
    el control de acceso usando el m&oacute;dulo <code class="module"><a href="../mod/mod_rewrite.html">mod_rewrite</a></code>.</p>

</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="host">Control de Acceso por host <a title="Enlace permanente" href="#host" class="permalink">&para;</a></h2>
    <p>
    Si lo que se quiere es restringir algunas zonas del sitio web, bas&aacute;ndonos
    en la direcci&oacute;n del visitante, esto puede ser realizado de manera 
    f&aacute;cil con el m&oacute;dulo <code class="module"><a href="../mod/mod_authz_host.html">mod_authz_host</a></code>.
    </p>

    <p>La directiva <code class="directive"><a href="../mod/mod_authz_core.html#require">Require</a></code>
    proporciona una variedad de diferentes maneras de permitir o denegar el acceso a los recursos. Adem&aacute;s puede ser usada junto con las directivas:<code class="directive"><a href="../mod/mod_authz_core.html#requireall">RequireAll</a></code>, <code class="directive"><a href="../mod/mod_authz_core.html#requireany">RequireAny</a></code>, y <code class="directive"><a href="../mod/mod_authz_core.html#requirenone">RequireNone</a></code>, estos requerimientos pueden
    ser combinados de forma compleja y arbitraria, para cumplir cualquiera que
    sean tus pol&iacute;ticas de acceso.</p>

    <div class="warning"><p>
    Las directivas <code class="directive"><a href="../mod/mod_access_compat.html#allow">Allow</a></code>,
    <code class="directive"><a href="../mod/mod_access_compat.html#deny">Deny</a></code>, y
    <code class="directive"><a href="../mod/mod_access_compat.html#order">Order</a></code>,
    proporcionadas por <code class="module"><a href="../mod/mod_access_compat.html">mod_access_compat</a></code>, est&aacute;n obsoletas y
    ser&aacute;n quitadas en futuras versiones. Deber&aacute; evitar su uso, y tambi&eacute;n
    los tutoriales desactualizaos que recomienden su uso.
    </p></div>

    <p>El uso de estas directivas es:</p>

 
    <pre class="prettyprint lang-config">Require host <var>address</var> <br>
Require ip <var>ip.address</var>
    </pre>


    <p>En la primera l&iacute;nea, <var>address</var> es el FQDN de un nombre de 
    dominio (o un nombre parcial del dominio); puede proporcionar m&uacute;ltiples
    direcciones o nombres de dominio, si se desea.
    </p>

    <p>En la segunda l&iacute;nea, <var>ip.address</var> es la direcci&oacute;n IP, una
    direcci&oacute;n IP parcial, una red con su m&aacute;scara, o una especificaci&oacute;n red/nnn 
    CIDR. Pueden usarse tanto IPV4 como IPV6.</p>

    <p>Consulte tambi&eacute;n <a href="../mod/mod_authz_host.html#requiredirectives">la 
    documentaci&oacute;n de mod_authz_host </a> para otros ejemplos de esta sintaxis.
    </p>

    <p>Puede ser insertado <code>not</code> para negar un requisito en particular.
    Note que, ya que <code>not</code> es una negaci&oacute;n de un valor, no puede ser 
    usado por si solo para permitir o denegar una petici&oacute;n, como <em>not true</em>
    que no contituye ser <em>false</em>. En consecuencia, para denegar una 
    visita usando una negaci&oacute;n, el bloque debe tener un elemento que se eval&uacute;a como
    verdadero o falso. Por ejemplo, si tienes a alguien espameandote tu tabl&oacute;n de 
    mensajes, y tu quieres evitar que entren o dejarlos fuera, puedes realizar
    lo siguiente:
    </p>

    <pre class="prettyprint lang-config">&lt;RequireAll&gt;
    Require all granted
    Require not ip 10.252.46.165
&lt;/RequireAll&gt;</pre>


    <p>Los visitantes que vengan desde la IP que se configura (<code>10.252.46.165</code>)
    no tendr&aacute;n acceso al contenido que cubre esta directiva. Si en cambio, lo que se 
    tiene es el nombre de la m&aacute;quina, en vez de la IP, podr&aacute;s usar:</p>

    <pre class="prettyprint lang-config">Require not host <var>host.example.com</var>
    </pre>


    <p>Y, Si lo que se quiere es bloquear el acceso desde dominio especifico, 
        podr&aacute;s especificar parte de una direcci&oacute;n o nombre de dominio:</p>

    <pre class="prettyprint lang-config">Require not ip 192.168.205
Require not host phishers.example.com moreidiots.example
Require not host gov</pre>


    <p>Uso de las directivas <code class="directive"><a href="../mod/mod_authz_core.html#requireall">RequireAll</a></code>, <code class="directive"><a href="../mod/mod_authz_core.html#requireany">RequireAny</a></code>, y <code class="directive"><a href="../mod/mod_authz_core.html#requirenone">RequireNone</a></code> pueden ser usadas
    para forzar requisitos m&aacute;s complejos.</p>

</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="env">Control de acceso por variables arbitrarias. <a title="Enlace permanente" href="#env" class="permalink">&para;</a></h2>

    <p>Haciendo el uso de <code class="directive"><a href="../mod/core.html#if">&lt;If&gt;</a></code>,
    puedes permitir o denegar el acceso basado en variables de entrono arbitrarias
    o en los valores de las cabeceras de las peticiones. Por ejemplo para denegar 
    el acceso bas&aacute;ndonos en el "user-agent" (tipo de navegador as&iacute; como Sistema Operativo)
    puede que hagamos lo siguiente:
    </p>

    <pre class="prettyprint lang-config">&lt;If "%{HTTP_USER_AGENT} == 'BadBot'"&gt;
    Require all denied
&lt;/If&gt;</pre>


    <p>Usando la sintaxis de <code class="directive"><a href="../mod/mod_authz_core.html#require">Require</a></code>
    <code>expr</code> , esto tambi&eacute;n puede ser escrito de la siguiente forma:
    </p>


    <pre class="prettyprint lang-config">Require expr %{HTTP_USER_AGENT} != 'BadBot'</pre>


    <div class="note"><h3>Advertencia:</h3>
    <p>El control de acceso por <code>User-Agent</code> es una t&eacute;cnica poco fiable,
    ya que la cabecera de <code>User-Agent</code> puede ser modificada y establecerse 
    al antojo del usuario.</p>
    </div>

    <p>Vea tambi&eacute;n la p&aacute;gina de  <a href="../expr.html">expresiones</a>
    para una mayor aclaraci&oacute;n de que sintaxis tienen las expresiones y que
    variables est&aacute;n disponibles.</p>

</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="rewrite">Control de acceso con mod_rewrite <a title="Enlace permanente" href="#rewrite" class="permalink">&para;</a></h2>

    <p>El flag <code>[F]</code> de <code class="directive"><a href="../mod/mod_rewrite.html#rewriterule">RewriteRule</a></code> causa una respuesta 403 Forbidden
    para ser enviada. USando esto, podr&aacute; denegar el acceso a recursos bas&aacute;ndose
    en criterio arbitrario.</p>

    <p>Por ejemplo, si lo que desea es bloquear un recurso entre las 8pm y las 
        7am, podr&aacute; hacerlo usando <code class="module"><a href="../mod/mod_rewrite.html">mod_rewrite</a></code>:</p>

    <pre class="prettyprint lang-config">RewriteEngine On
RewriteCond "%{TIME_HOUR}" "&gt;=20" [OR]
RewriteCond "%{TIME_HOUR}" "&lt;07"
RewriteRule "^/fridge"     "-"       [F]</pre>


    <p>Esto devolver&aacute; una respuesta de error 403 Forbidden para cualquier  petici&oacute;n 
    despu&eacute;s de las 8pm y antes de las 7am. Esta t&eacute;cnica puede ser usada para cualquier 
    criterio que desee usar. Tambi&eacute;n puede redireccionar, o incluso reescribir estas 
    peticiones, si se prefiere ese enfoque.
    </p>

    <p>La directiva <code class="directive"><a href="../mod/core.html#if">&lt;If&gt;</a></code>,
     a&ntilde;adida en la 2.4, sustituye muchas cosas que <code class="module"><a href="../mod/mod_rewrite.html">mod_rewrite</a></code>
     tradicionalmente sol&iacute;a hacer, y deber&aacute; comprobar estas antes de recurrir a 
    </p>

</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="moreinformation">M&aacute;s informaci&oacute;n <a title="Enlace permanente" href="#moreinformation" class="permalink">&para;</a></h2>

    <p>El <a href="../expr.html">motor de expresiones</a> le da una gran
    capacidad de poder para hacer una gran variedad de cosas basadas en 
    las variables arbitrarias del servidor, y debe consultar este 
    documento para m&aacute;s detalles.</p>

    <p>Tambi&eacute;n, deber&aacute; leer la documentaci&oacute;n de <code class="module"><a href="../mod/mod_authz_core.html">mod_authz_core</a></code>
    para ejemplos de combinaciones de m&uacute;ltiples requisitos de acceso y especificar
    c&oacute;mo interact&uacute;an.
    </p>

    <p>Vea tambi&eacute;n los howtos de <a href="auth.html">Authenticaci&oacute;n y Autorizaci&oacute;n</a>
    </p>
</div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="../en/howto/access.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/howto/access.html" title="Espa&ntilde;ol">&nbsp;es&nbsp;</a> |
<a href="../fr/howto/access.html" hreflang="fr" rel="alternate" title="Fran&ccedil;ais">&nbsp;fr&nbsp;</a></p>
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