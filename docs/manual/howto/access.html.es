<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es" xml:lang="es"><head>
<meta content="text/html; charset=ISO-8859-1" http-equiv="Content-Type" />
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Control de Acceso - Servidor HTTP Apache Versi&#243;n 2.4</title>
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
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs/">Documentaci&#243;n</a> &gt; <a href="../">Versi&#243;n 2.4</a> &gt; <a href="./">How-To / Tutoriales</a></div><div id="page-content"><div id="preamble"><h1>Control de Acceso</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="../en/howto/access.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/howto/access.html" title="Espa&#241;ol">&nbsp;es&nbsp;</a> |
<a href="../fr/howto/access.html" hreflang="fr" rel="alternate" title="Fran&#231;ais">&nbsp;fr&nbsp;</a></p>
</div>

    <p>El control de acceso, hace referencia a todos los medios que proporcionan
        una forma de controlar el acceso a cualquier recurso. Esta parte est&#225;
        separada de <a href="auth.html">autenticaci&#243;n y autorizaci&#243;n</a>.</p>
</div>
<div id="quickview"><a href="https://www.apache.org/foundation/contributing.html" class="badge"><img src="https://www.apache.org/images/SupportApache-small.png" alt="Support Apache!" /></a><ul id="toc"><li><img alt="" src="../images/down.gif" /> <a href="#related">M&#243;dulos y Directivas relacionados</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#host">Control de Acceso por host</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#env">Control de acceso por variables arbitrarias.</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#rewrite">Control de acceso con mod_rewrite</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#moreinformation">M&#225;s informaci&#243;n</a></li>
</ul><h3>Consulte tambi&#233;n</h3><ul class="seealso"><li><a href="#comments_section">Comentarios</a></li></ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="related" id="related">M&#243;dulos y Directivas relacionados</a></h2>

    <p>El control de acceso puede efectuarse mediante diferentes m&#243;dulos. Los 
    m&#225;s importantes de &#233;stos son <code class="module"><a href="../mod/mod_authz_core.html">mod_authz_core</a></code> y
    <code class="module"><a href="../mod/mod_authz_host.html">mod_authz_host</a></code>. Tambi&#233;n se habla en este documento de
    el control de acceso usando el m&#243;dulo <code class="module"><a href="../mod/mod_rewrite.html">mod_rewrite</a></code>.</p>

</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="host" id="host">Control de Acceso por host</a></h2>
    <p>
    Si lo que se quiere es restringir algunas zonas del sitio web, bas&#225;ndonos
    en la direcci&#243;n del visitante, esto puede ser realizado de manera 
    f&#225;cil con el m&#243;dulo <code class="module"><a href="../mod/mod_authz_host.html">mod_authz_host</a></code>.
    </p>

    <p>La directiva <code class="directive"><a href="../mod/mod_authz_core.html#require">Require</a></code>
    proporciona una variedad de diferentes maneras de permitir o denegar el acceso a los recursos. Adem&#225;s puede ser usada junto con las directivas:<code class="directive"><a href="../mod/mod_authz_core.html#requireall">RequireAll</a></code>, <code class="directive"><a href="../mod/mod_authz_core.html#requireany">RequireAny</a></code>, y <code class="directive"><a href="../mod/mod_authz_core.html#requirenone">RequireNone</a></code>, estos requerimientos pueden
    ser combinados de forma compleja y arbitraria, para cumplir cualquiera que
    sean tus pol&#237;ticas de acceso.</p>

    <div class="warning"><p>
    Las directivas <code class="directive"><a href="../mod/mod_access_compat.html#allow">Allow</a></code>,
    <code class="directive"><a href="../mod/mod_access_compat.html#deny">Deny</a></code>, y
    <code class="directive"><a href="../mod/mod_access_compat.html#order">Order</a></code>,
    proporcionadas por <code class="module"><a href="../mod/mod_access_compat.html">mod_access_compat</a></code>, est&#225;n obsoletas y
    ser&#225;n quitadas en futuras versiones. Deber&#225; evitar su uso, y tambi&#233;n
    los tutoriales desactualizaos que recomienden su uso.
    </p></div>

    <p>El uso de estas directivas es:</p>

 
    <pre class="prettyprint lang-config">Require host <var>address</var> <br />
Require ip <var>ip.address</var>
    </pre>


    <p>En la primera l&#237;nea, <var>address</var> es el FQDN de un nombre de 
    dominio (o un nombre parcial del dominio); puede proporcionar m&#250;ltiples
    direcciones o nombres de dominio, si se desea.
    </p>

    <p>En la segunda l&#237;nea, <var>ip.address</var> es la direcci&#243;n IP, una
    direcci&#243;n IP parcial, una red con su m&#225;scara, o una especificaci&#243;n red/nnn 
    CIDR. Pueden usarse tanto IPV4 como IPV6.</p>

    <p>Consulte tambi&#233;n <a href="../mod/mod_authz_host.html#requiredirectives">la 
    documentaci&#243;n de mod_authz_host </a> para otros ejemplos de esta sintaxis.
    </p>

    <p>Puede ser insertado <code>not</code> para negar un requisito en particular.
    Note que, ya que <code>not</code> es una negaci&#243;n de un valor, no puede ser 
    usado por si solo para permitir o denegar una petici&#243;n, como <em>not true</em>
    que no contituye ser <em>false</em>. En consecuencia, para denegar una 
    visita usando una negaci&#243;n, el bloque debe tener un elemento que se eval&#250;a como
    verdadero o falso. Por ejemplo, si tienes a alguien espameandote tu tabl&#243;n de 
    mensajes, y tu quieres evitar que entren o dejarlos fuera, puedes realizar
    lo siguiente:
    </p>

    <pre class="prettyprint lang-config">&lt;RequireAll&gt;
    Require all granted
    Require not ip 10.252.46.165
&lt;/RequireAll&gt;</pre>


    <p>Los visitantes que vengan desde la IP que se configura (<code>10.252.46.165</code>)
    no tendr&#225;n acceso al contenido que cubre esta directiva. Si en cambio, lo que se 
    tiene es el nombre de la m&#225;quina, en vez de la IP, podr&#225;s usar:</p>

    <pre class="prettyprint lang-config">Require not host <var>host.example.com</var>
    </pre>


    <p>Y, Si lo que se quiere es bloquear el acceso desde dominio especifico, 
        podr&#225;s especificar parte de una direcci&#243;n o nombre de dominio:</p>

    <pre class="prettyprint lang-config">Require not ip 192.168.205
Require not host phishers.example.com moreidiots.example
Require not host gov</pre>


    <p>Uso de las directivas <code class="directive"><a href="../mod/mod_authz_core.html#requireall">RequireAll</a></code>, <code class="directive"><a href="../mod/mod_authz_core.html#requireany">RequireAny</a></code>, y <code class="directive"><a href="../mod/mod_authz_core.html#requirenone">RequireNone</a></code> pueden ser usadas
    para forzar requisitos m&#225;s complejos.</p>

</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="env" id="env">Control de acceso por variables arbitrarias.</a></h2>

    <p>Haciendo el uso de <code class="directive"><a href="../mod/core.html#if">&lt;If&gt;</a></code>,
    puedes permitir o denegar el acceso basado en variables de entrono arbitrarias
    o en los valores de las cabeceras de las peticiones. Por ejemplo para denegar 
    el acceso bas&#225;ndonos en el "user-agent" (tipo de navegador as&#237; como Sistema Operativo)
    puede que hagamos lo siguiente:
    </p>

    <pre class="prettyprint lang-config">&lt;If "%{HTTP_USER_AGENT} == 'BadBot'"&gt;
    Require all denied
&lt;/If&gt;</pre>


    <p>Usando la sintaxis de <code class="directive"><a href="../mod/mod_authz_core.html#require">Require</a></code>
    <code>expr</code> , esto tambi&#233;n puede ser escrito de la siguiente forma:
    </p>


    <pre class="prettyprint lang-config">Require expr %{HTTP_USER_AGENT} != 'BadBot'</pre>


    <div class="note"><h3>Advertencia:</h3>
    <p>El control de acceso por <code>User-Agent</code> es una t&#233;cnica poco fiable,
    ya que la cabecera de <code>User-Agent</code> puede ser modificada y establecerse 
    al antojo del usuario.</p>
    </div>

    <p>Vea tambi&#233;n la p&#225;gina de  <a href="../expr.html">expresiones</a>
    para una mayor aclaraci&#243;n de que sintaxis tienen las expresiones y que
    variables est&#225;n disponibles.</p>

</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="rewrite" id="rewrite">Control de acceso con mod_rewrite</a></h2>

    <p>El flag <code>[F]</code> de <code class="directive"><a href="../mod/mod_rewrite.html#rewriterule">RewriteRule</a></code> causa una respuesta 403 Forbidden
    para ser enviada. USando esto, podr&#225; denegar el acceso a recursos bas&#225;ndose
    en criterio arbitrario.</p>

    <p>Por ejemplo, si lo que desea es bloquear un recurso entre las 8pm y las 
        7am, podr&#225; hacerlo usando <code class="module"><a href="../mod/mod_rewrite.html">mod_rewrite</a></code>:</p>

    <pre class="prettyprint lang-config">RewriteEngine On
RewriteCond "%{TIME_HOUR}" "&gt;=20" [OR]
RewriteCond "%{TIME_HOUR}" "&lt;07"
RewriteRule "^/fridge"     "-"       [F]</pre>


    <p>Esto devolver&#225; una respuesta de error 403 Forbidden para cualquier  petici&#243;n 
    despu&#233;s de las 8pm y antes de las 7am. Esta t&#233;cnica puede ser usada para cualquier 
    criterio que desee usar. Tambi&#233;n puede redireccionar, o incluso reescribir estas 
    peticiones, si se prefiere ese enfoque.
    </p>

    <p>La directiva <code class="directive"><a href="../mod/core.html#if">&lt;If&gt;</a></code>,
     a&#241;adida en la 2.4, sustituye muchas cosas que <code class="module"><a href="../mod/mod_rewrite.html">mod_rewrite</a></code>
     tradicionalmente sol&#237;a hacer, y deber&#225; comprobar estas antes de recurrir a 
    </p>

</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="moreinformation" id="moreinformation">M&#225;s informaci&#243;n</a></h2>

    <p>El <a href="../expr.html">motor de expresiones</a> le da una gran
    capacidad de poder para hacer una gran variedad de cosas basadas en 
    las variables arbitrarias del servidor, y debe consultar este 
    documento para m&#225;s detalles.</p>

    <p>Tambi&#233;n, deber&#225; leer la documentaci&#243;n de <code class="module"><a href="../mod/mod_authz_core.html">mod_authz_core</a></code>
    para ejemplos de combinaciones de m&#250;ltiples requisitos de acceso y especificar
    c&#243;mo interact&#250;an.
    </p>

    <p>Vea tambi&#233;n los howtos de <a href="auth.html">Authenticaci&#243;n y Autorizaci&#243;n</a>
    </p>
</div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="../en/howto/access.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/howto/access.html" title="Espa&#241;ol">&nbsp;es&nbsp;</a> |
<a href="../fr/howto/access.html" hreflang="fr" rel="alternate" title="Fran&#231;ais">&nbsp;fr&nbsp;</a></p>
</div><div class="top"><a href="#page-header"><img src="../images/up.gif" alt="top" /></a></div><div class="section"><h2><a id="comments_section" name="comments_section">Comentarios</a></h2><div class="warning"><strong>Notice:</strong><br />This is not a Q&amp;A section. Comments placed here should be pointed towards suggestions on improving the documentation or server, and may be removed by our moderators if they are either implemented or considered invalid/off-topic. Questions on how to manage the Apache HTTP Server should be directed at either our IRC channel, #httpd, on Libera.chat, or sent to our <a href="https://httpd.apache.org/lists.html">mailing lists</a>.</div>
<script type="text/javascript"><!--//--><![CDATA[//><!--
var comments_shortname = 'httpd';
var comments_identifier = 'http://httpd.apache.org/docs/2.4/howto/access.html';
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