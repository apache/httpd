<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es" xml:lang="es"><head>
<meta content="text/html; charset=ISO-8859-1" http-equiv="Content-Type" />
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Autenticación y Autorización - Servidor HTTP Apache Versión 2.5</title>
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
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs/">Documentación</a> &gt; <a href="../">Versión 2.5</a> &gt; <a href="./">How-To / Tutoriales</a></div><div id="page-content"><div id="preamble"><h1>Autenticación y Autorización</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="../en/howto/auth.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/howto/auth.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="../fr/howto/auth.html" hreflang="fr" rel="alternate" title="Français">&nbsp;fr&nbsp;</a> |
<a href="../ja/howto/auth.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="../ko/howto/auth.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="../tr/howto/auth.html" hreflang="tr" rel="alternate" title="Türkçe">&nbsp;tr&nbsp;</a></p>
</div>

    <p>Autenticación es cualquier proceso por el cuál se verifica que uno es 
    quien dice ser. Autorización es cualquier proceso en el cuál cualquiera
    está permitido a estar donde se quiera, o tener información la cuál se
    quiera tener.
    </p>

    <p>Para información de control de acceso de forma genérica visite<a href="access.html">How to de Control de Acceso</a>.</p>
</div>
<div id="quickview"><ul id="toc"><li><img alt="" src="../images/down.gif" /> <a href="#related">Módulos y Directivas Relacionados</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#introduction">Introducción</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#theprerequisites">Los Prerequisitos</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#gettingitworking">Conseguir que funcione</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#lettingmorethanonepersonin">Letting more than one
person in</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#possibleproblems">Possible problems</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#dbmdbd">Alternate password storage</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#multprovider">Using multiple providers</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#beyond">Beyond just authorization</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#socache">Authentication Caching</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#moreinformation">More information</a></li>
</ul><h3>Consulte también</h3><ul class="seealso"><li><a href="#comments_section">Comentarios</a></li></ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="related" id="related">Módulos y Directivas Relacionados</a></h2>

<p>Hay tres tipos de módulos involucrados en los procesos de la autenticación 
	y autorización. Normalmente deberás escoger al menos un módulo de cada grupo.</p>

<ul>
  <li>Modos de Autenticación (consulte la directiva
      <code class="directive"><a href="../mod/mod_authn_core.html#authtype">AuthType</a></code> )
    <ul>
      <li><code class="module"><a href="../mod/mod_auth_basic.html">mod_auth_basic</a></code></li>
      <li><code class="module"><a href="../mod/mod_auth_digest.html">mod_auth_digest</a></code></li>
    </ul>
  </li>
  <li>Proveedor de Autenticación (consulte la directiva
  <code class="directive"><a href="../mod/mod_auth_basic.html#authbasicprovider">AuthBasicProvider</a></code> y
  <code class="directive"><a href="../mod/mod_auth_digest.html#authdigestprovider">AuthDigestProvider</a></code>)

    <ul>
      <li><code class="module"><a href="../mod/mod_authn_anon.html">mod_authn_anon</a></code></li>
      <li><code class="module"><a href="../mod/mod_authn_dbd.html">mod_authn_dbd</a></code></li>
      <li><code class="module"><a href="../mod/mod_authn_dbm.html">mod_authn_dbm</a></code></li>
      <li><code class="module"><a href="../mod/mod_authn_file.html">mod_authn_file</a></code></li>
      <li><code class="module"><a href="../mod/mod_authnz_ldap.html">mod_authnz_ldap</a></code></li>
      <li><code class="module"><a href="../mod/mod_authn_socache.html">mod_authn_socache</a></code></li>
    </ul>
  </li>
  <li>Autorización (consulte la directiva
      <code class="directive"><a href="../mod/mod_authz_core.html#require">Require</a></code>)
    <ul>
      <li><code class="module"><a href="../mod/mod_authnz_ldap.html">mod_authnz_ldap</a></code></li>
      <li><code class="module"><a href="../mod/mod_authz_dbd.html">mod_authz_dbd</a></code></li>
      <li><code class="module"><a href="../mod/mod_authz_dbm.html">mod_authz_dbm</a></code></li>
      <li><code class="module"><a href="../mod/mod_authz_groupfile.html">mod_authz_groupfile</a></code></li>
      <li><code class="module"><a href="../mod/mod_authz_host.html">mod_authz_host</a></code></li>
      <li><code class="module"><a href="../mod/mod_authz_owner.html">mod_authz_owner</a></code></li>
      <li><code class="module"><a href="../mod/mod_authz_user.html">mod_authz_user</a></code></li>
    </ul>
  </li>
</ul>

  <p>A parte de éstos módulos, también están
  <code class="module"><a href="../mod/mod_authn_core.html">mod_authn_core</a></code> y
  <code class="module"><a href="../mod/mod_authz_core.html">mod_authz_core</a></code>. Éstos módulos implementan las directivas 
  esenciales que son el centro de todos los módulos de autenticación.</p>

  <p>El módulo <code class="module"><a href="../mod/mod_authnz_ldap.html">mod_authnz_ldap</a></code> es tanto un proveedor de 
  autenticación como de autorización. El módulo
  <code class="module"><a href="../mod/mod_authz_host.html">mod_authz_host</a></code> proporciona autorización y control de acceso
  basado en el nombre del Host, la dirección IP o características de la propia
  petición, pero no es parte del sistema proveedor de 
  autenticación. Para tener compatibilidad inversa con el mod_access, 
  hay un nuevo modulo llamado <code class="module"><a href="../mod/mod_access_compat.html">mod_access_compat</a></code>.</p>

  <p>También puedes mirar el how-to de <a href="access.html">Control de Acceso </a>, donde se plantean varias formas del control de acceso al servidor.</p>

</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="introduction" id="introduction">Introducción</a></h2>
    <p>Si se tiene información en nuestra página web que sea información 
    	sensible o pensada para un grupo reducido de usuarios/personas,
    	las técnicas que se describen en este manual, le servirán  
    	de ayuda para asegurarse de que las personas que ven esas páginas sean 
    	las personas que uno quiere.</p>

    <p>Este artículo cubre la parte "estándar" de cómo proteger partes de un 
    	sitio web que muchos usarán.</p>

    <div class="note"><h3>Nota:</h3>
    <p>Si de verdad es necesario que tus datos estén en un sitio seguro, 
    	considera usar <code class="module"><a href="../mod/mod_ssl.html">mod_ssl</a></code>  como método de autenticación adicional a cualquier forma de autenticación.</p>
    </div>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="theprerequisites" id="theprerequisites">Los Prerequisitos</a></h2>
    <p>Las directivas que se usan en este artículo necesitaran ponerse ya sea 
    	en el fichero de configuración principal del servidor ( típicamente en 
    	la sección 
    <code class="directive"><a href="../mod/core.html#directory">&lt;Directory&gt;</a></code> de httpd.conf ), o
    en cada uno de los ficheros de configuraciones del propio directorio
    (los archivos <code>.htaccess</code>).</p>

    <p>Si planea usar los ficheros <code>.htaccess</code> , necesitarás
    tener en la configuración global del servidor, una configuración que permita
    poner directivas de autenticación en estos ficheros. Esto se hace con la
    directiva <code class="directive"><a href="../mod/core.html#allowoverride">AllowOverride</a></code>, la cual especifica
    que directivas, en su caso, pueden ser puestas en cada fichero de configuración
    por directorio.</p>

    <p>Ya que estamos hablando aquí de autenticación, necesitarás una directiva 
    	<code class="directive"><a href="../mod/core.html#allowoverride">AllowOverride</a></code> como la siguiente:
    	</p>

    <pre class="prettyprint lang-config">AllowOverride AuthConfig</pre>


    <p>O, si solo se van a poner las directivas directamente en la configuración
    	principal del servidor, deberás tener, claro está, permisos de escritura
    	en el archivo. </p>

    <p>Y necesitarás saber un poco de como está estructurado el árbol de 
    	directorios de tu servidor, para poder saber donde se encuentran algunos 
    	archivos. Esto no debería ser una tarea difícil, aún así intentaremos 
    	dejarlo claro llegado el momento de comentar dicho aspecto.</p>

    <p>También deberás de asegurarte de que los módulos 
    <code class="module"><a href="../mod/mod_authn_core.html">mod_authn_core</a></code> y <code class="module"><a href="../mod/mod_authz_core.html">mod_authz_core</a></code>
    han sido incorporados, o añadidos a la hora de compilar en tu binario httpd o
    cargados mediante el archivo de configuración <code>httpd.conf</code>. Estos 
    dos módulos proporcionan directivas básicas y funcionalidades que son críticas
    para la configuración y uso de autenticación y autorización en el servidor web.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="gettingitworking" id="gettingitworking">Conseguir que funcione</a></h2>
    <p>Aquí está lo básico de cómo proteger con contraseña un directorio en tu
     servidor.</p>

    <p>Primero, necesitarás crear un fichero de contraseña. Dependiendo de que 
    	proveedor de autenticación se haya elegido, se hará de una forma u otra. Para empezar, 
    	usaremos un fichero de contraseña de tipo texto.</p>

    <p>Este fichero deberá estar en un sitio que no se pueda tener acceso desde
     la web. Esto también implica que nadie pueda descargarse el fichero de 
     contraseñas. Por ejemplo, si tus documentos están guardados fuera de
     <code>/usr/local/apache/htdocs</code>, querrás poner tu archivo de contraseñas en 
     <code>/usr/local/apache/passwd</code>.</p>

    <p>Para crear el fichero de contraseñas, usa la utilidad 
    	<code class="program"><a href="../programs/htpasswd.html">htpasswd</a></code> que viene con Apache. Esta herramienta se 
    	encuentra en el directorio <code>/bin</code> en donde sea que se ha 
    	instalado el Apache. Si ha instalado Apache desde un paquete de terceros, 
    	puede ser que se encuentre en su ruta de ejecución.</p>

    <p>Para crear el fichero, escribiremos:</p>

    <div class="example"><p><code>
      htpasswd -c /usr/local/apache/passwd/passwords rbowen
    </code></p></div>

    <p><code class="program"><a href="../programs/htpasswd.html">htpasswd</a></code> te preguntará por una contraseña, y después 
    te pedirá que la vuelvas a escribir para confirmarla:</p>

    <div class="example"><p><code>
      $ htpasswd -c /usr/local/apache/passwd/passwords rbowen<br />
      New password: mypassword<br />
      Re-type new password: mypassword<br />
      Adding password for user rbowen
    </code></p></div>

    <p>Si <code class="program"><a href="../programs/htpasswd.html">htpasswd</a></code> no está en tu variable de entorno "path" del 
    sistema, por supuesto deberás escribir la ruta absoluta del ejecutable para 
    poder hacer que se ejecute. En una instalación por defecto, está en:
    <code>/usr/local/apache2/bin/htpasswd</code></p>

    <p>Lo próximo que necesitas, será configurar el servidor para que pida una 
    	contraseña y así decirle al servidor que usuarios están autorizados a acceder.
    	Puedes hacer esto ya sea editando el fichero <code>httpd.conf</code>
    de configuración  o usando in fichero <code>.htaccess</code>. Por ejemplo, 
    si quieres proteger el directorio
    <code>/usr/local/apache/htdocs/secret</code>, puedes usar las siguientes 
    directivas, ya sea en el fichero <code>.htaccess</code> localizado en
    following directives, either placed in the file
    <code>/usr/local/apache/htdocs/secret/.htaccess</code>, o
    en la configuración global del servidor <code>httpd.conf</code> dentro de la
    sección &lt;Directory  
    "/usr/local/apache/htdocs/secret"&gt; section. como se muesta a continuacion:</p>

    <pre class="prettyprint lang-config">&lt;Directory "/usr/local/apache/htdocs/secret"&gt;
AuthType Basic
AuthName "Restricted Files"
# (Following line optional)
AuthBasicProvider file
AuthUserFile "/usr/local/apache/passwd/passwords"
Require user rbowen
&lt;/Directory&gt;</pre>


    <p>Let's examine each of those directives individually. The <code class="directive"><a href="../mod/mod_authn_core.html#authtype">AuthType</a></code> directive selects
    that method that is used to authenticate the user. The most
    common method is <code>Basic</code>, and this is the method
    implemented by <code class="module"><a href="../mod/mod_auth_basic.html">mod_auth_basic</a></code>. It is important to be aware,
    however, that Basic authentication sends the password from the client to
    the server unencrypted. This method should therefore not be used for
    highly sensitive data, unless accompanied by <code class="module"><a href="../mod/mod_ssl.html">mod_ssl</a></code>.
    Apache supports one other authentication method:
    <code>AuthType Digest</code>. This method is implemented by <code class="module"><a href="../mod/mod_auth_digest.html">mod_auth_digest</a></code> and was intended to be more secure. This is no
    longer the case and the connection should be encrypted with <code class="module"><a href="../mod/mod_ssl.html">mod_ssl</a></code> instead.</p>

    <p>The <code class="directive"><a href="../mod/mod_authn_core.html#authname">AuthName</a></code> directive sets
    the <dfn>Realm</dfn> to be used in the authentication. The realm serves
    two major functions. First, the client often presents this information to
    the user as part of the password dialog box. Second, it is used by the
    client to determine what password to send for a given authenticated
    area.</p>

    <p>So, for example, once a client has authenticated in the
    <code>"Restricted Files"</code> area, it will automatically
    retry the same password for any area on the same server that is
    marked with the <code>"Restricted Files"</code> Realm.
    Therefore, you can prevent a user from being prompted more than
    once for a password by letting multiple restricted areas share
    the same realm. Of course, for security reasons, the client
    will always need to ask again for the password whenever the
    hostname of the server changes.</p>

    <p>The <code class="directive"><a href="../mod/mod_auth_basic.html#authbasicprovider">AuthBasicProvider</a></code> is,
    in this case, optional, since <code>file</code> is the default value
    for this directive. You'll need to use this directive if you are
    choosing a different source for authentication, such as
    <code class="module"><a href="../mod/mod_authn_dbm.html">mod_authn_dbm</a></code> or <code class="module"><a href="../mod/mod_authn_dbd.html">mod_authn_dbd</a></code>.</p>

    <p>The <code class="directive"><a href="../mod/mod_authn_file.html#authuserfile">AuthUserFile</a></code>
    directive sets the path to the password file that we just
    created with <code class="program"><a href="../programs/htpasswd.html">htpasswd</a></code>. If you have a large number
    of users, it can be quite slow to search through a plain text
    file to authenticate the user on each request. Apache also has
    the ability to store user information in fast database files.
    The <code class="module"><a href="../mod/mod_authn_dbm.html">mod_authn_dbm</a></code> module provides the <code class="directive"><a href="../mod/mod_authn_dbm.html#authdbmuserfile">AuthDBMUserFile</a></code> directive. These
    files can be created and manipulated with the <code class="program"><a href="../programs/dbmmanage.html">dbmmanage</a></code> and <code class="program"><a href="../programs/htdbm.html">htdbm</a></code> programs. Many
    other types of authentication options are available from third
    party modules in the <a href="http://modules.apache.org/">Apache Modules
    Database</a>.</p>

    <p>Finally, the <code class="directive"><a href="../mod/mod_authz_core.html#require">Require</a></code>
    directive provides the authorization part of the process by
    setting the user that is allowed to access this region of the
    server. In the next section, we discuss various ways to use the
    <code class="directive"><a href="../mod/mod_authz_core.html#require">Require</a></code> directive.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="lettingmorethanonepersonin" id="lettingmorethanonepersonin">Letting more than one
person in</a></h2>
    <p>The directives above only let one person (specifically
    someone with a username of <code>rbowen</code>) into the
    directory. In most cases, you'll want to let more than one
    person in. This is where the <code class="directive"><a href="../mod/mod_authz_groupfile.html#authgroupfile">AuthGroupFile</a></code> comes in.</p>

    <p>If you want to let more than one person in, you'll need to
    create a group file that associates group names with a list of
    users in that group. The format of this file is pretty simple,
    and you can create it with your favorite editor. The contents
    of the file will look like this:</p>

   <div class="example"><p><code>
     GroupName: rbowen dpitts sungo rshersey
   </code></p></div>

    <p>That's just a list of the members of the group in a long
    line separated by spaces.</p>

    <p>To add a user to your already existing password file,
    type:</p>

    <div class="example"><p><code>
      htpasswd /usr/local/apache/passwd/passwords dpitts
    </code></p></div>

    <p>You'll get the same response as before, but it will be
    appended to the existing file, rather than creating a new file.
    (It's the <code>-c</code> that makes it create a new password
    file).</p>

    <p>Now, you need to modify your <code>.htaccess</code> file to
    look like the following:</p>

    <pre class="prettyprint lang-config">AuthType Basic
AuthName "By Invitation Only"
# Optional line:
AuthBasicProvider file
AuthUserFile "/usr/local/apache/passwd/passwords"
AuthGroupFile "/usr/local/apache/passwd/groups"
Require group GroupName</pre>


    <p>Now, anyone that is listed in the group <code>GroupName</code>,
    and has an entry in the <code>password</code> file, will be let in, if
    they type the correct password.</p>

    <p>There's another way to let multiple users in that is less
    specific. Rather than creating a group file, you can just use
    the following directive:</p>

    <pre class="prettyprint lang-config">Require valid-user</pre>


    <p>Using that rather than the <code>Require user rbowen</code>
    line will allow anyone in that is listed in the password file,
    and who correctly enters their password. You can even emulate
    the group behavior here, by just keeping a separate password
    file for each group. The advantage of this approach is that
    Apache only has to check one file, rather than two. The
    disadvantage is that you have to maintain a bunch of password
    files, and remember to reference the right one in the
    <code class="directive"><a href="../mod/mod_authn_file.html#authuserfile">AuthUserFile</a></code> directive.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="possibleproblems" id="possibleproblems">Possible problems</a></h2>
    <p>Because of the way that Basic authentication is specified,
    your username and password must be verified every time you
    request a document from the server. This is even if you're
    reloading the same page, and for every image on the page (if
    they come from a protected directory). As you can imagine, this
    slows things down a little. The amount that it slows things
    down is proportional to the size of the password file, because
    it has to open up that file, and go down the list of users
    until it gets to your name. And it has to do this every time a
    page is loaded.</p>

    <p>A consequence of this is that there's a practical limit to
    how many users you can put in one password file. This limit
    will vary depending on the performance of your particular
    server machine, but you can expect to see slowdowns once you
    get above a few hundred entries, and may wish to consider a
    different authentication method at that time.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="dbmdbd" id="dbmdbd">Alternate password storage</a></h2>

    <p>Because storing passwords in plain text files has the above
    problems, you may wish to store your passwords somewhere else, such
    as in a database.</p>

    <p><code class="module"><a href="../mod/mod_authn_dbm.html">mod_authn_dbm</a></code> and <code class="module"><a href="../mod/mod_authn_dbd.html">mod_authn_dbd</a></code> are two
    modules which make this possible. Rather than selecting <code><code class="directive"><a href="../mod/mod_auth_basic.html#authbasicprovider">AuthBasicProvider</a></code> file</code>, instead
    you can choose <code>dbm</code> or <code>dbd</code> as your storage
    format.</p>

    <p>To select a dbm file rather than a text file, for example:</p>

    <pre class="prettyprint lang-config">&lt;Directory "/www/docs/private"&gt;
    AuthName "Private"
    AuthType Basic
    AuthBasicProvider dbm
    AuthDBMUserFile "/www/passwords/passwd.dbm"
    Require valid-user
&lt;/Directory&gt;</pre>


    <p>Other options are available. Consult the
    <code class="module"><a href="../mod/mod_authn_dbm.html">mod_authn_dbm</a></code> documentation for more details.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="multprovider" id="multprovider">Using multiple providers</a></h2>

    <p>With the introduction of the new provider based authentication and
    authorization architecture, you are no longer locked into a single
    authentication or authorization method. In fact any number of the
    providers can be mixed and matched to provide you with exactly the
    scheme that meets your needs. In the following example, both the
    file and LDAP based authentication providers are being used.</p>

    <pre class="prettyprint lang-config">&lt;Directory "/www/docs/private"&gt;
    AuthName "Private"
    AuthType Basic
    AuthBasicProvider file ldap
    AuthUserFile "/usr/local/apache/passwd/passwords"
    AuthLDAPURL ldap://ldaphost/o=yourorg
    Require valid-user
&lt;/Directory&gt;</pre>


    <p>In this example the file provider will attempt to authenticate
    the user first. If it is unable to authenticate the user, the LDAP
    provider will be called. This allows the scope of authentication
    to be broadened if your organization implements more than
    one type of authentication store. Other authentication and authorization
    scenarios may include mixing one type of authentication with a
    different type of authorization. For example, authenticating against
    a password file yet authorizing against an LDAP directory.</p>

    <p>Just as multiple authentication providers can be implemented, multiple
    authorization methods can also be used. In this example both file group
    authorization as well as LDAP group authorization is being used.</p>

    <pre class="prettyprint lang-config">&lt;Directory "/www/docs/private"&gt;
    AuthName "Private"
    AuthType Basic
    AuthBasicProvider file
    AuthUserFile "/usr/local/apache/passwd/passwords"
    AuthLDAPURL ldap://ldaphost/o=yourorg
    AuthGroupFile "/usr/local/apache/passwd/groups"
    Require group GroupName
    Require ldap-group cn=mygroup,o=yourorg
&lt;/Directory&gt;</pre>


    <p>To take authorization a little further, authorization container
    directives such as
    <code class="directive"><a href="../mod/mod_authz_core.html#requireall">&lt;RequireAll&gt;</a></code>
    and
    <code class="directive"><a href="../mod/mod_authz_core.html#requireany">&lt;RequireAny&gt;</a></code>
    allow logic to be applied so that the order in which authorization
    is handled can be completely controlled through the configuration.
    See <a href="../mod/mod_authz_core.html#logic">Authorization
    Containers</a> for an example of how they may be applied.</p>

</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="beyond" id="beyond">Beyond just authorization</a></h2>

    <p>The way that authorization can be applied is now much more flexible
    than just a single check against a single data store. Ordering, logic
    and choosing how authorization will be done is now possible.</p>

    <h3><a name="authandororder" id="authandororder">Applying logic and ordering</a></h3>
        <p>Controlling how and in what order authorization will be applied
        has been a bit of a mystery in the past. In Apache 2.2 a provider-based
        authentication mechanism was introduced to decouple the actual
        authentication process from authorization and supporting functionality.
        One of the side benefits was that authentication providers could be
        configured and called in a specific order which didn't depend on the
        load order of the auth module itself. This same provider based mechanism
        has been brought forward into authorization as well. What this means is
        that the <code class="directive"><a href="../mod/mod_authz_core.html#require">Require</a></code> directive
        not only specifies which authorization methods should be used, it also
        specifies the order in which they are called. Multiple authorization
        methods are called in the same order in which the
        <code class="directive"><a href="../mod/mod_authz_core.html#require">Require</a></code> directives
        appear in the configuration.</p>

        <p>With the introduction of authorization container directives
        such as
        <code class="directive"><a href="../mod/mod_authz_core.html#requireall">&lt;RequireAll&gt;</a></code>
        and
        <code class="directive"><a href="../mod/mod_authz_core.html#requireany">&lt;RequireAny&gt;</a></code>,
        the configuration also has control over when the
        authorization methods are called and what criteria determines when
        access is granted.  See
        <a href="../mod/mod_authz_core.html#logic">Authorization Containers</a>
        for an example of how they may be used to express complex
        authorization logic.</p>

        <p>By default all
        <code class="directive"><a href="../mod/mod_authz_core.html#require">Require</a></code>
        directives are handled as though contained within a
        <code class="directive"><a href="../mod/mod_authz_core.html#requireany">&lt;RequireAny&gt;</a></code>
        container directive.  In other words, if
        any of the specified authorization methods succeed, then authorization
        is granted.</p>

    

    <h3><a name="reqaccessctrl" id="reqaccessctrl">Using authorization providers for access control</a></h3>
        <p>Authentication by username and password is only part of the
        story. Frequently you want to let people in based on something
        other than who they are. Something such as where they are
        coming from.</p>

        <p>The authorization providers <code>all</code>,
        <code>env</code>, <code>host</code> and <code>ip</code> let you
        allow or deny access based on other host based criteria such as
        host name or ip address of the machine requesting a
        document.</p>

        <p>The usage of these providers is specified through the
        <code class="directive"><a href="../mod/mod_authz_core.html#require">Require</a></code> directive.
        This directive registers the authorization providers
        that will be called during the authorization stage of the request
        processing. For example:</p>

        <pre class="prettyprint lang-config">Require ip <var>address</var>
        </pre>


        <p>where <var>address</var> is an IP address (or a partial IP
        address) or:</p>

        <pre class="prettyprint lang-config">Require host <var>domain_name</var>
        </pre>


        <p>where <var>domain_name</var> is a fully qualified domain name
        (or a partial domain name); you may provide multiple addresses or
        domain names, if desired.</p>

        <p>For example, if you have someone spamming your message
        board, and you want to keep them out, you could do the
        following:</p>

        <pre class="prettyprint lang-config">&lt;RequireAll&gt;
    Require all granted
    Require not ip 10.252.46.165
&lt;/RequireAll&gt;</pre>


        <p>Visitors coming from that address will not be able to see
        the content covered by this directive. If, instead, you have a
        machine name, rather than an IP address, you can use that.</p>

        <pre class="prettyprint lang-config">&lt;RequireAll&gt;
    Require all granted
    Require not host host.example.com
&lt;/RequireAll&gt;</pre>


        <p>And, if you'd like to block access from an entire domain,
        you can specify just part of an address or domain name:</p>

        <pre class="prettyprint lang-config">&lt;RequireAll&gt;
    Require all granted
    Require not ip 192.168.205
    Require not host phishers.example.com moreidiots.example
    Require not host ke
&lt;/RequireAll&gt;</pre>


        <p>Using <code class="directive"><a href="../mod/mod_authz_core.html#requireall">&lt;RequireAll&gt;</a></code>
        with multiple <code class="directive"><a href="../mod/mod_authz_core.html#require">&lt;Require&gt;</a></code> directives, each negated with <code>not</code>,
        will only allow access, if all of negated conditions are true. In other words,
        access will be blocked, if any of the negated conditions fails.</p>

    

    <h3><a name="filesystem" id="filesystem">Access Control backwards compatibility</a></h3>
        <p>One of the side effects of adopting a provider based mechanism for
        authentication is that the previous access control directives
        <code class="directive"><a href="../mod/mod_access_compat.html#order">Order</a></code>,
        <code class="directive"><a href="../mod/mod_access_compat.html#allow">Allow</a></code>,
        <code class="directive"><a href="../mod/mod_access_compat.html#deny">Deny</a></code> and
        <code class="directive"><a href="../mod/mod_access_compat.html#satisfy">Satisfy</a></code> are no longer needed.
        However to provide backwards compatibility for older configurations, these
        directives have been moved to the <code class="module"><a href="../mod/mod_access_compat.html">mod_access_compat</a></code> module.</p>

        <div class="warning"><h3>Note</h3>
        <p>The directives provided by <code class="module"><a href="../mod/mod_access_compat.html">mod_access_compat</a></code> have
        been deprecated by <code class="module"><a href="../mod/mod_authz_host.html">mod_authz_host</a></code>.
        Mixing old directives like <code class="directive"><a href="../mod/mod_access_compat.html#order">Order</a></code>, <code class="directive"><a href="../mod/mod_access_compat.html#allow">Allow</a></code> or <code class="directive"><a href="../mod/mod_access_compat.html#deny">Deny</a></code> with new ones like
        <code class="directive"><a href="../mod/mod_authz_core.html#require">Require</a></code> is technically possible
        but discouraged. The <code class="module"><a href="../mod/mod_access_compat.html">mod_access_compat</a></code> module was created to support
        configurations containing only old directives to facilitate the 2.4 upgrade.
        Please check the <a href="../upgrading.html">upgrading</a> guide for more
        information.
        </p>
        </div>
    

</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="socache" id="socache">Authentication Caching</a></h2>
    <p>There may be times when authentication puts an unacceptable load
    on a provider or on your network.  This is most likely to affect users
    of <code class="module"><a href="../mod/mod_authn_dbd.html">mod_authn_dbd</a></code> (or third-party/custom providers).
    To deal with this, HTTPD 2.3/2.4 introduces a new caching provider
    <code class="module"><a href="../mod/mod_authn_socache.html">mod_authn_socache</a></code> to cache credentials and reduce
    the load on the origin provider(s).</p>
    <p>This may offer a substantial performance boost to some users.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="moreinformation" id="moreinformation">More information</a></h2>
    <p>You should also read the documentation for
    <code class="module"><a href="../mod/mod_auth_basic.html">mod_auth_basic</a></code> and <code class="module"><a href="../mod/mod_authz_host.html">mod_authz_host</a></code>
    which contain some more information about how this all works.  The
    directive <code class="directive"><a href="../mod/mod_authn_core.html#authnprovideralias">&lt;AuthnProviderAlias&gt;</a></code> can also help
    in simplifying certain authentication configurations.</p>

    <p>The various ciphers supported by Apache for authentication data are
    explained in <a href="../misc/password_encryptions.html">Password
    Encryptions</a>.</p>

    <p>And you may want to look at the <a href="access.html">Access
    Control</a> howto, which discusses a number of related topics.</p>

</div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="../en/howto/auth.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/howto/auth.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="../fr/howto/auth.html" hreflang="fr" rel="alternate" title="Français">&nbsp;fr&nbsp;</a> |
<a href="../ja/howto/auth.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="../ko/howto/auth.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="../tr/howto/auth.html" hreflang="tr" rel="alternate" title="Türkçe">&nbsp;tr&nbsp;</a></p>
</div><div class="top"><a href="#page-header"><img src="../images/up.gif" alt="top" /></a></div><div class="section"><h2><a id="comments_section" name="comments_section">Comentarios</a></h2><div class="warning"><strong>Notice:</strong><br />This is not a Q&amp;A section. Comments placed here should be pointed towards suggestions on improving the documentation or server, and may be removed again by our moderators if they are either implemented or considered invalid/off-topic. Questions on how to manage the Apache HTTP Server should be directed at either our IRC channel, #httpd, on Freenode, or sent to our <a href="http://httpd.apache.org/lists.html">mailing lists</a>.</div>
<script type="text/javascript"><!--//--><![CDATA[//><!--
var comments_shortname = 'httpd';
var comments_identifier = 'http://httpd.apache.org/docs/trunk/howto/auth.html';
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