<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es" xml:lang="es"><head>
<meta content="text/html; charset=ISO-8859-1" http-equiv="Content-Type" />
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>mod_auth_basic - Servidor HTTP Apache Versión 2.5</title>
<link href="../style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet" />
<link href="../style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size" />
<link href="../style/css/manual-print.css" rel="stylesheet" media="print" type="text/css" /><link rel="stylesheet" type="text/css" href="../style/css/prettify.css" />
<script src="../style/scripts/prettify.min.js" type="text/javascript">
</script>

<link href="../images/favicon.ico" rel="shortcut icon" /></head>
<body>
<div id="page-header">
<p class="menu"><a href="../mod/">Módulos</a> | <a href="../mod/quickreference.html">Directivas</a> | <a href="http://wiki.apache.org/httpd/FAQ">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa del sitio web</a></p>
<p class="apache">Versión 2.5 del Servidor HTTP Apache</p>
<img alt="" src="../images/feather.png" /></div>
<div class="up"><a href="./"><img title="&lt;-" alt="&lt;-" src="../images/left.gif" /></a></div>
<div id="path">
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs/">Documentación</a> &gt; <a href="../">Versión 2.5</a> &gt; <a href="./">Módulos</a></div>
<div id="page-content">
<div id="preamble"><h1>Módulo Apache mod_auth_basic</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="../en/mod/mod_auth_basic.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/mod/mod_auth_basic.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="../fr/mod/mod_auth_basic.html" hreflang="fr" rel="alternate" title="Français">&nbsp;fr&nbsp;</a> |
<a href="../ja/mod/mod_auth_basic.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="../ko/mod/mod_auth_basic.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a></p>
</div>
<table class="module"><tr><th><a href="module-dict.html#Description">Descripción:</a></th><td>Autenticación HTTP Básica</td></tr>
<tr><th><a href="module-dict.html#Status">Estado:</a></th><td>Base</td></tr>
<tr><th><a href="module-dict.html#ModuleIdentifier">Identificador de Módulos:</a></th><td>auth_basic_module</td></tr>
<tr><th><a href="module-dict.html#SourceFile">Fichero de Código Fuente:</a></th><td>mod_auth_basic.c</td></tr></table>
<h3>Resumen de contenidos</h3>

    <p>Este módulo permite el uso de Autenticación HTTP Básica para restringir acceso buscando usuarios en los proveedores configurados.
    La autenticación HTTP Digest la facilita el módulo
    <code class="module"><a href="../mod/mod_auth_digest.html">mod_auth_digest</a></code>.  Este módulo debería combinarse generalmente con al menos un módulo de autenticación como <code class="module"><a href="../mod/mod_authn_file.html">mod_authn_file</a></code> y uno de autorización como <code class="module"><a href="../mod/mod_authz_user.html">mod_authz_user</a></code>.</p>
</div>
<div id="quickview"><h3 class="directives">Directivas</h3>
<ul id="toc">
<li><img alt="" src="../images/down.gif" /> <a href="#authbasicauthoritative">AuthBasicAuthoritative</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#authbasicfake">AuthBasicFake</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#authbasicprovider">AuthBasicProvider</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#authbasicusedigestalgorithm">AuthBasicUseDigestAlgorithm</a></li>
</ul>
<h3>Bugfix checklist</h3><ul class="seealso"><li><a href="https://www.apache.org/dist/httpd/CHANGES_2.4">httpd changelog</a></li><li><a href="https://bz.apache.org/bugzilla/buglist.cgi?bug_status=__open__&amp;list_id=144532&amp;product=Apache%20httpd-2&amp;query_format=specific&amp;order=changeddate%20DESC%2Cpriority%2Cbug_severity&amp;component=mod_auth_basic">Known issues</a></li><li><a href="https://bz.apache.org/bugzilla/enter_bug.cgi?product=Apache%20httpd-2&amp;component=mod_auth_basic">Report a bug</a></li></ul><h3>Consulte también</h3>
<ul class="seealso">
<li><code class="directive"><a href="../mod/mod_authn_core.html#authname">AuthName</a></code></li>
<li><code class="directive"><a href="../mod/mod_authn_core.html#authtype">AuthType</a></code></li>
<li><code class="directive"><a href="../mod/mod_authz_core.html#require">Require</a></code></li>
<li><a href="../howto/auth.html">Authentication howto</a></li>
<li><a href="#comments_section">Comentarios</a></li></ul></div>

<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="AuthBasicAuthoritative" id="AuthBasicAuthoritative">AuthBasicAuthoritative</a> <a name="authbasicauthoritative" id="authbasicauthoritative">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Configura si se pasan autorización o autenticación a los módulos de más bajo nivel</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>AuthBasicAuthoritative On|Off</code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>AuthBasicAuthoritative On</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Anula:</a></th><td>AuthConfig</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Base</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>mod_auth_basic</td></tr>
</table>
    <p>Normalmente, cada módulo de autorización listado en 
    <code class="directive"><a href="#authbasicprovider">AuthBasicProvider</a></code>
    intentará vefificar el usuario y si el usuario no se encuentra en ningún proveedor, el acceso será denegado. Configurando la directiva
    <code class="directive">AuthBasicAuthoritative</code> de forma explícita a
    <code>Off</code> permite que ambos autenticación y autorización sean pasados a otros módulos no-proveedores si <strong>no hay ID de usuario</strong> o 
    <strong>regla</strong> coincidente para el ID de usario facilitado.  Esto solo sería necesario cuando se combina <code class="module"><a href="../mod/mod_auth_basic.html">mod_auth_basic</a></code> con módulos de terceros que no están configurados con la directiva 
    <code class="directive"><a href="#authbasicprovider">AuthBasicProvider</a></code>. Cuando se usan tales módulos, el orden de procesamiento se determina en el código fuente de los módulos y no es configurable.</p>

</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="AuthBasicFake" id="AuthBasicFake">AuthBasicFake</a> <a name="authbasicfake" id="authbasicfake">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Autenticación básica falsa usando las expresiones facilitadas para usario y contraseña</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>AuthBasicFake off|username [password]</code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>none</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Anula:</a></th><td>AuthConfig</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Base</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>mod_auth_basic</td></tr>
<tr><th><a href="directive-dict.html#Compatibility">Compatibilidad:</a></th><td>Apache HTTP Server 2.4.5 y posteriores</td></tr>
</table>
    <p>El usuario y contraseña especificados se combinan en una cabecera de Autorización, que se pasa al servidor o servicio detrás del servidor web. Ambos cambios usuario y contraseña son interpretrados usando el <a href="../expr.html">intérprete de expresión</a>, que permite que tanto el usuario como la contraseña se basen en los parámetros solicitados.</p>

    <p>Si la contraseña no se especifica, se utilizará el valor por defecto  "password".  Para desahabilitar la autenticación básica falsa para una URL, especifique "AuthBasicFake off".</p>

    <p>En este ejemplo, enviamos un usuario y contraseña fijos a un servidor backend.</p>

    <div class="example"><h3>Fixed Example</h3><pre class="prettyprint lang-config">&lt;Location "/demo"&gt;
    AuthBasicFake demo demopass
&lt;/Location&gt;</pre>
</div>

    <p>En este ejemplo, pasamos la dirección de email extraida de un certificado cliente, extendiendo la opción de funcionalidad de FakeBasicAuth dentro de la directiva <code class="directive"><a href="../mod/mod_ssl.html#ssloptions">SSLOptions</a></code>.  Como con la opción FakeBasicAuth, la contraseña se configura a la cadena de caracteres específica "password".</p>

    <div class="example"><h3>Ejemplo de Certificado</h3><pre class="prettyprint lang-config">&lt;Location "/secure"&gt;
    AuthBasicFake "%{SSL_CLIENT_S_DN_Email}"
&lt;/Location&gt;</pre>
</div>

    <p>Extendiendo el ejemplo de arriba, generamos una contraseña encriptando la dirección email con una contraseña fija, y pasando el resultado encriptado al servidor de backend.  Este método se puede usar como puerta de acceso a sistemas antiguos que no dan soporte a certificados cliente.</p>

    <div class="example"><h3>Ejemplo de Contraseña</h3><pre class="prettyprint lang-config">&lt;Location "/secure"&gt;
    AuthBasicFake "%{SSL_CLIENT_S_DN_Email}" "%{sha1:passphrase-%{SSL_CLIENT_S_DN_Email}}"
&lt;/Location&gt;</pre>
</div>

    <div class="example"><h3>Ejemplo de Exclusión</h3><pre class="prettyprint lang-config">&lt;Location "/public"&gt;
    AuthBasicFake off
&lt;/Location&gt;</pre>
</div>


</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="AuthBasicProvider" id="AuthBasicProvider">AuthBasicProvider</a> <a name="authbasicprovider" id="authbasicprovider">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Configura el/los proveedor/es de autenticación para esta 
ubicación</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>AuthBasicProvider <var>provider-name</var>
[<var>provider-name</var>] ...</code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>AuthBasicProvider file</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Anula:</a></th><td>AuthConfig</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Base</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>mod_auth_basic</td></tr>
</table>
    <p>La directiva <code class="directive">AuthBasicProvider</code> configura qué proveedor se usa para autenticar los usuarios en esta ubicación. El 
    <code>fichero</code> proveedor por defecto se implementa con el módulo <code class="module"><a href="../mod/mod_authn_file.html">mod_authn_file</a></code>.  Asegúrese de que el proveedor elegido está presente en el servidor.</p>

    <div class="example"><h3>Ejemplo</h3><pre class="prettyprint lang-config">&lt;Location "/secure"&gt;
    AuthType basic
    AuthName "private area"
    AuthBasicProvider  dbm
    AuthDBMType        SDBM
    AuthDBMUserFile    "/www/etc/dbmpasswd"
    Require            valid-user
&lt;/Location&gt;</pre>
</div>

    <p>Se consulta a los proveedores en orden hasta que un proveedor encuentra una coincidencia para el nombre de usuario solicitado, y en este punto solo este proveedor intentará comprobar la contraseña.  Un fallo al verificar la contraseña no provoca que el control se pase a los proveedores 
    subsiguientes.</p>

    <p>Los proveedores son implementados por <code class="module"><a href="../mod/mod_authn_dbm.html">mod_authn_dbm</a></code>,
    <code class="module"><a href="../mod/mod_authn_file.html">mod_authn_file</a></code>, <code class="module"><a href="../mod/mod_authn_dbd.html">mod_authn_dbd</a></code>,
    <code class="module"><a href="../mod/mod_authnz_ldap.html">mod_authnz_ldap</a></code> y <code class="module"><a href="../mod/mod_authn_socache.html">mod_authn_socache</a></code>.</p>

</div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="directive-section"><h2><a name="AuthBasicUseDigestAlgorithm" id="AuthBasicUseDigestAlgorithm">AuthBasicUseDigestAlgorithm</a> <a name="authbasicusedigestalgorithm" id="authbasicusedigestalgorithm">Directiva</a></h2>
<table class="directive">
<tr><th><a href="directive-dict.html#Description">Descripción:</a></th><td>Comprueba contraseñas en proveedores de autenticación como si la Autenticación Digest estuviera en uso en lugar de la Autenticación Básica.
</td></tr>
<tr><th><a href="directive-dict.html#Syntax">Sintaxis:</a></th><td><code>AuthBasicUseDigestAlgorithm MD5|Off</code></td></tr>
<tr><th><a href="directive-dict.html#Default">Valor por defecto:</a></th><td><code>AuthBasicUseDigestAlgorithm Off</code></td></tr>
<tr><th><a href="directive-dict.html#Context">Contexto:</a></th><td>directory, .htaccess</td></tr>
<tr><th><a href="directive-dict.html#Override">Anula:</a></th><td>AuthConfig</td></tr>
<tr><th><a href="directive-dict.html#Status">Estado:</a></th><td>Base</td></tr>
<tr><th><a href="directive-dict.html#Module">Módulo:</a></th><td>mod_auth_basic</td></tr>
<tr><th><a href="directive-dict.html#Compatibility">Compatibilidad:</a></th><td>Apache HTTP Server 2.4.7 y posteriores</td></tr>
</table>
    <p>Normalmente, cuando se usa Autenticación Básica, los proveedores listados en
    <code class="directive"><a href="#authbasicprovider">AuthBasicProvider</a></code> intentan verificar un usuario comprobando sus almacenes de datos para encontrar una coincidencia de nombre de usuario y contraseña asociados.  Las contraseñas almacenadas generalmente están encriptadas, pero no necesariamente; cada proveedor puede usar su propio esquema de almacenamiento para contraseñas.</p>

    <p>Cuando se usa 
    <code class="directive"><a href="../mod/mod_auth_digest.html#authdigestprovider">AuthDigestProvider</a></code> y Autenticación Digest, los proveedores realizan una comprobación similar para encontrar un nombre de usuario en sus almacenes de datos.  Sin embargo, al contrario que en el caso de la Autenticación Básica, el valor asociado con cada nombre de usuario almacenado debe ser una cadena de caracteres encriptada compuesta del nombre de usuario, nombre real y contraseña.  (Vea el
    <a href="http://tools.ietf.org/html/rfc2617#section-3.2.2.2">
    RFC 2617, Sección 3.2.2.2</a> para más detalles en el formato usado para la cadena de caracteres encriptada.)</p>

    <p>Como consecuencia de la diferencia entre los valores almacenados entre la Autenticación Básica y la Digest, convertir desde Autenticación Digest a Autenticación Básica generalmente requiere que a todos los usuarios se les asigne nuevas contraseñas, puesto que sus contraseñas actuales no pueden ser recuperadas desde el esquema de almacenamiento de contraseñas impuesto en esos proveedores que soportan la Autenticación Digest.</p>

    <p>Configurando la directiva 
    <code class="directive"><a href="#authbasicusedigestalgorithm">AuthBasicUseDigestAlgorithm</a></code> a
    <code>MD5</code> hará que se compruebe la contraseña del usuario de Autenticación Básica usando el mismo formato encriptado que para Autenticación Digest.  Primero una cadena de caracteres que se compone del nombre de usuario, nombre real y contraseña es encriptada con MD5; entonces el usuario y esta cadena de caracteres encriptada se pasan a los proveedores listados en 
    <code class="directive"><a href="#authbasicprovider">AuthBasicProvider</a></code> como si
    <code class="directive"><a href="../mod/mod_authn_core.html#authtype">AuthType</a></code> fuera configurado como
    <code>Digest</code> y como si se estuviera usando la Autenticación Digest.
    </p>

    <p>A través del uso de 
    <code class="directive"><a href="#authbasicusedigestalgorithm">AuthBasicUseDigestAlgorithm</a></code> un sitio puede pasar de Autenticación Digest a Básica sin requerir que a los usuarios se les asignen contraseñas nuevas.</p>

    <div class="note">
      El método inverso de cambiar de Autenticación Básica a Digest sin asignar nuevas contraseñas generalmente no es posible.  Solo si las contraseñas de la Autenticación Básica se han almacenado en texto plano o con un esquema de encriptación reversible sería posible recuperarlas y generar un nuevo almacén de datos siguiendo el esquema de almacenamiento de contraseñas de Autenticación Digest.
    </div>

    <div class="note">
      Solo proveedores que dan soporte a Autenticación Digest podrán autenticar usuarios cuando 
      <code class="directive"><a href="#authbasicusedigestalgorithm">AuthBasicUseDigestAlgorithm</a></code>
      está configurada a <code>MD5</code>.  El uso de otros proveedores dará como resultado una respuesta de error y se denegará el acceso al cliente.
    </div>

</div>
</div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="../en/mod/mod_auth_basic.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/mod/mod_auth_basic.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="../fr/mod/mod_auth_basic.html" hreflang="fr" rel="alternate" title="Français">&nbsp;fr&nbsp;</a> |
<a href="../ja/mod/mod_auth_basic.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="../ko/mod/mod_auth_basic.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a></p>
</div><div class="top"><a href="#page-header"><img src="../images/up.gif" alt="top" /></a></div><div class="section"><h2><a id="comments_section" name="comments_section">Comentarios</a></h2><div class="warning"><strong>Notice:</strong><br />This is not a Q&amp;A section. Comments placed here should be pointed towards suggestions on improving the documentation or server, and may be removed again by our moderators if they are either implemented or considered invalid/off-topic. Questions on how to manage the Apache HTTP Server should be directed at either our IRC channel, #httpd, on Freenode, or sent to our <a href="http://httpd.apache.org/lists.html">mailing lists</a>.</div>
<script type="text/javascript"><!--//--><![CDATA[//><!--
var comments_shortname = 'httpd';
var comments_identifier = 'http://httpd.apache.org/docs/trunk/mod/mod_auth_basic.html';
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
<p class="apache">Copyright 2017 The Apache Software Foundation.<br />Licencia bajo los términos de la <a href="http://www.apache.org/licenses/LICENSE-2.0">Apache License, Version 2.0</a>.</p>
<p class="menu"><a href="../mod/">Módulos</a> | <a href="../mod/quickreference.html">Directivas</a> | <a href="http://wiki.apache.org/httpd/FAQ">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa del sitio web</a></p></div><script type="text/javascript"><!--//--><![CDATA[//><!--
if (typeof(prettyPrint) !== 'undefined') {
    prettyPrint();
}
//--><!]]></script>
</body></html>