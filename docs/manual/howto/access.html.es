<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es" xml:lang="es"><head>
<meta content="text/html; charset=ISO-8859-1" http-equiv="Content-Type" />
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Control de Acceso - Servidor HTTP Apache Versión 2.5</title>
<link href="../style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet" />
<link href="../style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size" />
<link href="../style/css/manual-print.css" rel="stylesheet" media="print" type="text/css" /><link rel="stylesheet" type="text/css" href="../style/css/prettify.css" />
<script src="../style/scripts/prettify.min.js" type="text/javascript">
</script>

<link href="../images/favicon.ico" rel="shortcut icon" /></head>
<body id="manual-page"><div id="page-header">
<p class="menu"><a href="../mod/">Módulos</a> | <a href="../mod/quickreference.html">Directivas</a> | <a href="http://wiki.apache.org/httpd/FAQ">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa del sitio web</a></p>
<p class="apache">Versión 2.5 del Servidor HTTP Apache</p>
<img alt="" src="../images/feather.png" /></div>
<div class="up"><a href="./"><img title="&lt;-" alt="&lt;-" src="../images/left.gif" /></a></div>
<div id="path">
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs/">Documentación</a> &gt; <a href="../">Versión 2.5</a> &gt; <a href="./">How-To / Tutoriales</a></div><div id="page-content"><div id="preamble"><h1>Control de Acceso</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="../en/howto/access.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/howto/access.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="../fr/howto/access.html" hreflang="fr" rel="alternate" title="Français">&nbsp;fr&nbsp;</a></p>
</div>

    <p>El control de acceso, hace referencia a todos los medios que proporcionan
    	una forma de controlar el acceso a cualquier recurso. Esta parte está
    	separada de <a href="auth.html">autenticación y autorización</a>.</p>
</div>
<div id="quickview"><ul id="toc"><li><img alt="" src="../images/down.gif" /> <a href="#related">Módulos y Directivas relacionados</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#host">Control de Acceso por host</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#env">Access control by arbitrary variables</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#rewrite">Access control with mod_rewrite</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#moreinformation">More information</a></li>
</ul><h3>Consulte también</h3><ul class="seealso"><li><a href="#comments_section">Comentarios</a></li></ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="related" id="related">Módulos y Directivas relacionados</a></h2>

    <p>El control de acceso puede efectuarse mediante diferentes módulos. Los 
    más importantes de éstos son <code class="module"><a href="../mod/mod_authz_core.html">mod_authz_core</a></code> y
    <code class="module"><a href="../mod/mod_authz_host.html">mod_authz_host</a></code>. También se habla en este documento de
    el control de acceso usando el módulo <code class="module"><a href="../mod/mod_rewrite.html">mod_rewrite</a></code>.</p>

</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="host" id="host">Control de Acceso por host</a></h2>
    <p>
    Si lo que se quiere es restringir algunas zonas del sitio web, basándonos
    en la dirección del visitante, esto puede ser realizado de manera 
    fácil con el módulo <code class="module"><a href="../mod/mod_authz_host.html">mod_authz_host</a></code>.
    </p>

    <p>La directiva <code class="directive"><a href="../mod/mod_authz_core.html#require">Require</a></code>
    proporciona una variedad de diferentes maneras de permitir o denegar el acceso a los recursos. Además puede ser usada junto con las directivas:<code class="directive"><a href="../mod/mod_authz_core.html#requireall">RequireAll</a></code>, <code class="directive"><a href="../mod/mod_authz_core.html#requireany">RequireAny</a></code>, y <code class="directive"><a href="../mod/mod_authz_core.html#requirenone">RequireNone</a></code>, estos requerimientos pueden
    ser combinados de forma compleja y arbitraria, para cumplir cualquiera que
    sean tus políticas de acceso.</p>

    <div class="warning"><p>
    Las directivas <code class="directive"><a href="../mod/mod_access_compat.html#allow">Allow</a></code>,
    <code class="directive"><a href="../mod/mod_access_compat.html#deny">Deny</a></code>, y
    <code class="directive"><a href="../mod/mod_access_compat.html#order">Order</a></code>,
    proporcionadas por <code class="module"><a href="../mod/mod_access_compat.html">mod_access_compat</a></code>, están obsoletas y
    serán quitadas en futuras versiones. Deberá evitar su uso, y también
    los tutoriales desactualizaos que recomienden su uso.
    </p></div>

    <p>El uso de estas directivas es:</p>

    <pre class="prettyprint lang-config">Require host <var>address</var>
Require ip <var>ip.address</var>
    </pre>


    <p>En la primera formaIn the first form, <var>address</var> is a fully qualified
    domain name (or a partial domain name); you may provide multiple
    addresses or domain names, if desired.</p>

    <p>In the second form, <var>ip.address</var> is an IP address, a
    partial IP address, a network/netmask pair, or a network/nnn CIDR
    specification. Either IPv4 or IPv6 addresses may be used.</p>

    <p>See <a href="../mod/mod_authz_host.html#requiredirectives">the
    mod_authz_host documentation</a> for further examples of this
    syntax.</p>

    <p>You can insert <code>not</code> to negate a particular requirement.
    Note, that since a <code>not</code> is a negation of a value, it cannot
    be used by itself to allow or deny a request, as <em>not true</em>
    does not constitute <em>false</em>. Thus, to deny a visit using a negation,
    the block must have one element that evaluates as true or false.
    For example, if you have someone spamming your message
    board, and you want to keep them out, you could do the
    following:</p>

    <pre class="prettyprint lang-config">&lt;RequireAll&gt;
    Require all granted
    Require not ip 10.252.46.165
&lt;/RequireAll&gt;</pre>


    <p>Visitors coming from that address (<code>10.252.46.165</code>)
    will not be able to see the content covered by this directive. If,
    instead, you have a machine name, rather than an IP address, you
    can use that.</p>

    <pre class="prettyprint lang-config">Require not host <var>host.example.com</var>
    </pre>


    <p>And, if you'd like to block access from an entire domain,
    you can specify just part of an address or domain name:</p>

    <pre class="prettyprint lang-config">Require not ip 192.168.205
Require not host phishers.example.com moreidiots.example
Require not host gov</pre>


    <p>Use of the <code class="directive"><a href="../mod/mod_authz_core.html#requireall">RequireAll</a></code>, <code class="directive"><a href="../mod/mod_authz_core.html#requireany">RequireAny</a></code>, and <code class="directive"><a href="../mod/mod_authz_core.html#requirenone">RequireNone</a></code> directives may be
    used to enforce more complex sets of requirements.</p>

</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="env" id="env">Access control by arbitrary variables</a></h2>

    <p>Using the <code class="directive"><a href="../mod/core.html#if">&lt;If&gt;</a></code>,
    you can allow or deny access based on arbitrary environment
    variables or request header values. For example, to deny access
    based on user-agent (the browser type) you might do the
    following:</p>

    <pre class="prettyprint lang-config">&lt;If "%{HTTP_USER_AGENT} == 'BadBot'"&gt;
    Require all denied
&lt;/If&gt;</pre>


    <p>Using the <code class="directive"><a href="../mod/mod_authz_core.html#require">Require</a></code>
    <code>expr</code> syntax, this could also be written as:</p>


    <pre class="prettyprint lang-config">Require expr %{HTTP_USER_AGENT} != 'BadBot'</pre>


    <div class="note"><h3>Warning:</h3>
    <p>Access control by <code>User-Agent</code> is an unreliable technique,
    since the <code>User-Agent</code> header can be set to anything at all,
    at the whim of the end user.</p>
    </div>

    <p>See <a href="../expr.html">the expressions document</a> for a
    further discussion of what expression syntaxes and variables are
    available to you.</p>

</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="rewrite" id="rewrite">Access control with mod_rewrite</a></h2>

    <p>The <code>[F]</code> <code class="directive"><a href="../mod/mod_rewrite.html#rewriterule">RewriteRule</a></code> flag causes a 403 Forbidden
    response to be sent. Using this, you can deny access to a resource based
    on arbitrary criteria.</p>

    <p>For example, if you wish to block access to a resource between 8pm
    and 6am, you can do this using <code class="module"><a href="../mod/mod_rewrite.html">mod_rewrite</a></code>.</p>

    <pre class="prettyprint lang-config">RewriteEngine On
RewriteCond "%{TIME_HOUR}" "&gt;=20" [OR]
RewriteCond "%{TIME_HOUR}" "&lt;07"
RewriteRule "^/fridge"     "-"       [F]</pre>


    <p>This will return a 403 Forbidden response for any request after 8pm
    or before 7am. This technique can be used for any criteria that you wish
    to check. You can also redirect, or otherwise rewrite these requests, if
    that approach is preferred.</p>

    <p>The <code class="directive"><a href="../mod/core.html#if">&lt;If&gt;</a></code> directive,
    added in 2.4, replaces many things that <code class="module"><a href="../mod/mod_rewrite.html">mod_rewrite</a></code> has
    traditionally been used to do, and you should probably look there first
    before resorting to mod_rewrite.</p>

</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="moreinformation" id="moreinformation">More information</a></h2>

    <p>The <a href="../expr.html">expression engine</a> gives you a
    great deal of power to do a variety of things based on arbitrary
    server variables, and you should consult that document for more
    detail.</p>

    <p>Also, you should read the <code class="module"><a href="../mod/mod_authz_core.html">mod_authz_core</a></code>
    documentation for examples of combining multiple access requirements
    and specifying how they interact.</p>

    <p>See also the <a href="auth.html">Authentication and Authorization</a>
    howto.</p>
</div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="../en/howto/access.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/howto/access.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="../fr/howto/access.html" hreflang="fr" rel="alternate" title="Français">&nbsp;fr&nbsp;</a></p>
</div><div class="top"><a href="#page-header"><img src="../images/up.gif" alt="top" /></a></div><div class="section"><h2><a id="comments_section" name="comments_section">Comentarios</a></h2><div class="warning"><strong>Notice:</strong><br />This is not a Q&amp;A section. Comments placed here should be pointed towards suggestions on improving the documentation or server, and may be removed again by our moderators if they are either implemented or considered invalid/off-topic. Questions on how to manage the Apache HTTP Server should be directed at either our IRC channel, #httpd, on Freenode, or sent to our <a href="http://httpd.apache.org/lists.html">mailing lists</a>.</div>
<script type="text/javascript"><!--//--><![CDATA[//><!--
var comments_shortname = 'httpd';
var comments_identifier = 'http://httpd.apache.org/docs/trunk/howto/access.html';
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
<p class="apache">Copyright 2016 The Apache Software Foundation.<br />Licencia bajo los términos de la <a href="http://www.apache.org/licenses/LICENSE-2.0">Apache License, Version 2.0</a>.</p>
<p class="menu"><a href="../mod/">Módulos</a> | <a href="../mod/quickreference.html">Directivas</a> | <a href="http://wiki.apache.org/httpd/FAQ">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa del sitio web</a></p></div><script type="text/javascript"><!--//--><![CDATA[//><!--
if (typeof(prettyPrint) !== 'undefined') {
    prettyPrint();
}
//--><!]]></script>
</body></html>