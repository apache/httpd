<!DOCTYPE html SYSTEM "about:legacy-compat">
<html lang="es"><head><META http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<meta content="width=device-width, initial-scale=1" name="viewport">
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Autenticaci&oacute;n y Autorizaci&oacute;n - Servidor HTTP Apache Versi&oacute;n 2.4</title>
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
<a href="https://www.apache.org/">Apache</a> &gt; <a href="https://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="https://httpd.apache.org/docs/">Documentaci&oacute;n</a> &gt; <a href="../">Versi&oacute;n 2.4</a> &gt; <a href="./">How-To / Tutoriales</a></div><div id="page-content"><div id="preamble"><h1>Autenticaci&oacute;n y Autorizaci&oacute;n</h1>
<button aria-label="Toggle language list" class="lang-toggle"><svg xmlns="http://www.w3.org/2000/svg" stroke-width="2" stroke="currentColor" fill="none" viewBox="0 0 24 24" height="16" width="16"><circle r="10" cy="12" cx="12"/><line y2="12" x2="22" y1="12" x1="2"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></button>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="../en/howto/auth.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/howto/auth.html" title="Espa&ntilde;ol">&nbsp;es&nbsp;</a> |
<a href="../fr/howto/auth.html" hreflang="fr" rel="alternate" title="Fran&ccedil;ais">&nbsp;fr&nbsp;</a> |
<a href="../ja/howto/auth.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="../ko/howto/auth.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="../tr/howto/auth.html" hreflang="tr" rel="alternate" title="T&uuml;rk&ccedil;e">&nbsp;tr&nbsp;</a></p>
</div>
<div class="outofdate">Esta traducci&oacute;n podr&iacute;a estar
            obsoleta. Consulte la versi&oacute;n en ingl&eacute;s de la
            documentaci&oacute;n para comprobar si se han producido cambios
            recientemente.</div>

    <p>Autenticaci&oacute;n es cualquier proceso por el cu&aacute;l se verifica que uno es 
    quien dice ser. Autorizaci&oacute;n es cualquier proceso en el cu&aacute;l cualquiera
    est&aacute; permitido a estar donde se quiera, o tener informaci&oacute;n la cu&aacute;l se
    quiera tener.
    </p>

    <p>Para informaci&oacute;n de control de acceso de forma gen&eacute;rica visite<a href="access.html">How to de Control de Acceso</a>.</p>
</div>
<div id="quickview"><ul id="toc"><li><img alt="" src="../images/down.gif"> <a href="#related">M&oacute;dulos y Directivas Relacionados</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#introduction">Introducci&oacute;n</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#theprerequisites">Los Prerequisitos</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#gettingitworking">Conseguir que funcione</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#lettingmorethanonepersonin">Dejar que m&aacute;s de una persona 
	entre</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#possibleproblems">Posibles Problemas</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#dbmdbd">M&eacute;todo alternativo de almacenamiento de las 
	contrase&ntilde;as</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#multprovider">Uso de m&uacute;ltiples proveedores</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#beyond">M&aacute;s all&aacute; de la Autorizaci&oacute;n</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#socache">Cache de Autenticaci&oacute;n</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#moreinformation">M&aacute;s informaci&oacute;n</a></li>
</ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="related">M&oacute;dulos y Directivas Relacionados <a title="Enlace permanente" href="#related" class="permalink">&para;</a></h2>

<p>Hay tres tipos de m&oacute;dulos involucrados en los procesos de la autenticaci&oacute;n 
	y autorizaci&oacute;n. Normalmente deber&aacute;s escoger al menos un m&oacute;dulo de cada grupo.</p>

<ul>
  <li>Modos de Autenticaci&oacute;n (consulte la directiva
      <code class="directive"><a href="../mod/mod_authn_core.html#authtype">AuthType</a></code> )
    <ul>
      <li><code class="module"><a href="../mod/mod_auth_basic.html">mod_auth_basic</a></code></li>
      <li><code class="module"><a href="../mod/mod_auth_digest.html">mod_auth_digest</a></code></li>
    </ul>
  </li>
  <li>Proveedor de Autenticaci&oacute;n (consulte la directiva
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
  <li>Autorizaci&oacute;n (consulte la directiva
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

  <p>A parte de &eacute;stos m&oacute;dulos, tambi&eacute;n est&aacute;n
  <code class="module"><a href="../mod/mod_authn_core.html">mod_authn_core</a></code> y
  <code class="module"><a href="../mod/mod_authz_core.html">mod_authz_core</a></code>. &Eacute;stos m&oacute;dulos implementan las directivas 
  esenciales que son el centro de todos los m&oacute;dulos de autenticaci&oacute;n.</p>

  <p>El m&oacute;dulo <code class="module"><a href="../mod/mod_authnz_ldap.html">mod_authnz_ldap</a></code> es tanto un proveedor de 
  autenticaci&oacute;n como de autorizaci&oacute;n. El m&oacute;dulo
  <code class="module"><a href="../mod/mod_authz_host.html">mod_authz_host</a></code> proporciona autorizaci&oacute;n y control de acceso
  basado en el nombre del Host, la direcci&oacute;n IP o caracter&iacute;sticas de la propia
  petici&oacute;n, pero no es parte del sistema proveedor de 
  autenticaci&oacute;n. Para tener compatibilidad inversa con el mod_access, 
  hay un nuevo modulo llamado <code class="module"><a href="../mod/mod_access_compat.html">mod_access_compat</a></code>.</p>

  <p>Tambi&eacute;n puedes mirar el how-to de <a href="access.html">Control de Acceso </a>, donde se plantean varias formas del control de acceso al servidor.</p>

</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="introduction">Introducci&oacute;n <a title="Enlace permanente" href="#introduction" class="permalink">&para;</a></h2>
    <p>Si se tiene informaci&oacute;n en nuestra p&aacute;gina web que sea informaci&oacute;n 
    	sensible o pensada para un grupo reducido de usuarios/personas,
    	las t&eacute;cnicas que se describen en este manual, le servir&aacute;n  
    	de ayuda para asegurarse de que las personas que ven esas p&aacute;ginas sean 
    	las personas que uno quiere.</p>

    <p>Este art&iacute;culo cubre la parte "est&aacute;ndar" de c&oacute;mo proteger partes de un 
    	sitio web que muchos usar&aacute;n.</p>

    <div class="note"><h3>Nota:</h3>
    <p>Si de verdad es necesario que tus datos est&eacute;n en un sitio seguro, 
    	considera usar <code class="module"><a href="../mod/mod_ssl.html">mod_ssl</a></code>  como m&eacute;todo de autenticaci&oacute;n adicional a cualquier forma de autenticaci&oacute;n.</p>
    </div>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="theprerequisites">Los Prerequisitos <a title="Enlace permanente" href="#theprerequisites" class="permalink">&para;</a></h2>
    <p>Las directivas que se usan en este art&iacute;culo necesitaran ponerse ya sea 
    	en el fichero de configuraci&oacute;n principal del servidor ( t&iacute;picamente en 
    	la secci&oacute;n 
    <code class="directive"><a href="../mod/core.html#directory">&lt;Directory&gt;</a></code> de httpd.conf ), o
    en cada uno de los ficheros de configuraciones del propio directorio
    (los archivos <code>.htaccess</code>).</p>

    <p>Si planea usar los ficheros <code>.htaccess</code> , necesitar&aacute;s
    tener en la configuraci&oacute;n global del servidor, una configuraci&oacute;n que permita
    poner directivas de autenticaci&oacute;n en estos ficheros. Esto se hace con la
    directiva <code class="directive"><a href="../mod/core.html#allowoverride">AllowOverride</a></code>, la cual especifica
    que directivas, en su caso, pueden ser puestas en cada fichero de configuraci&oacute;n
    por directorio.</p>

    <p>Ya que estamos hablando aqu&iacute; de autenticaci&oacute;n, necesitar&aacute;s una directiva 
    	<code class="directive"><a href="../mod/core.html#allowoverride">AllowOverride</a></code> como la siguiente:
    	</p>

    <pre class="prettyprint lang-config">AllowOverride AuthConfig</pre>


    <p>O, si solo se van a poner las directivas directamente en la configuraci&oacute;n
    	principal del servidor, deber&aacute;s tener, claro est&aacute;, permisos de escritura
    	en el archivo. </p>

    <p>Y necesitar&aacute;s saber un poco de como est&aacute; estructurado el &aacute;rbol de 
    	directorios de tu servidor, para poder saber donde se encuentran algunos 
    	archivos. Esto no deber&iacute;a ser una tarea dif&iacute;cil, a&uacute;n as&iacute; intentaremos 
    	dejarlo claro llegado el momento de comentar dicho aspecto.</p>

    <p>Tambi&eacute;n deber&aacute;s de asegurarte de que los m&oacute;dulos 
    <code class="module"><a href="../mod/mod_authn_core.html">mod_authn_core</a></code> y <code class="module"><a href="../mod/mod_authz_core.html">mod_authz_core</a></code>
    han sido incorporados, o a&ntilde;adidos a la hora de compilar en tu binario httpd o
    cargados mediante el archivo de configuraci&oacute;n <code>httpd.conf</code>. Estos 
    dos m&oacute;dulos proporcionan directivas b&aacute;sicas y funcionalidades que son cr&iacute;ticas
    para la configuraci&oacute;n y uso de autenticaci&oacute;n y autorizaci&oacute;n en el servidor web.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="gettingitworking">Conseguir que funcione <a title="Enlace permanente" href="#gettingitworking" class="permalink">&para;</a></h2>
    <p>Aqu&iacute; est&aacute; lo b&aacute;sico de c&oacute;mo proteger con contrase&ntilde;a un directorio en tu
     servidor.</p>

    <p>Primero, necesitar&aacute;s crear un fichero de contrase&ntilde;a. Dependiendo de que 
    	proveedor de autenticaci&oacute;n se haya elegido, se har&aacute; de una forma u otra. Para empezar, 
    	usaremos un fichero de contrase&ntilde;a de tipo texto.</p>

    <p>Este fichero deber&aacute; estar en un sitio que no se pueda tener acceso desde
     la web. Esto tambi&eacute;n implica que nadie pueda descargarse el fichero de 
     contrase&ntilde;as. Por ejemplo, si tus documentos est&aacute;n guardados fuera de
     <code>/usr/local/apache/htdocs</code>, querr&aacute;s poner tu archivo de contrase&ntilde;as en 
     <code>/usr/local/apache/passwd</code>.</p>

    <p>Para crear el fichero de contrase&ntilde;as, usa la utilidad 
    	<code class="program"><a href="../programs/htpasswd.html">htpasswd</a></code> que viene con Apache. Esta herramienta se 
    	encuentra en el directorio <code>/bin</code> en donde sea que se ha 
    	instalado el Apache. Si ha instalado Apache desde un paquete de terceros, 
    	puede ser que se encuentre en su ruta de ejecuci&oacute;n.</p>

    <p>Para crear el fichero, escribiremos:</p>

    <div class="example"><p><code>
      htpasswd -c /usr/local/apache/passwd/passwords rbowen
    </code></p></div>

    <p><code class="program"><a href="../programs/htpasswd.html">htpasswd</a></code> te preguntar&aacute; por una contrase&ntilde;a, y despu&eacute;s 
    te pedir&aacute; que la vuelvas a escribir para confirmarla:</p>

    <div class="example"><p><code>
      $ htpasswd -c /usr/local/apache/passwd/passwords rbowen<br>
      New password: mypassword<br>
      Re-type new password: mypassword<br>
      Adding password for user rbowen
    </code></p></div>

    <p>Si <code class="program"><a href="../programs/htpasswd.html">htpasswd</a></code> no est&aacute; en tu variable de entorno "path" del 
    sistema, por supuesto deber&aacute;s escribir la ruta absoluta del ejecutable para 
    poder hacer que se ejecute. En una instalaci&oacute;n por defecto, est&aacute; en:
    <code>/usr/local/apache2/bin/htpasswd</code></p>

    <p>Lo pr&oacute;ximo que necesitas, ser&aacute; configurar el servidor para que pida una 
    	contrase&ntilde;a y as&iacute; decirle al servidor que usuarios est&aacute;n autorizados a acceder.
    	Puedes hacer esto ya sea editando el fichero <code>httpd.conf</code>
    de configuraci&oacute;n  o usando in fichero <code>.htaccess</code>. Por ejemplo, 
    si quieres proteger el directorio
    <code>/usr/local/apache/htdocs/secret</code>, puedes usar las siguientes 
    directivas, ya sea en el fichero <code>.htaccess</code> localizado en
    following directives, either placed in the file
    <code>/usr/local/apache/htdocs/secret/.htaccess</code>, o
    en la configuraci&oacute;n global del servidor <code>httpd.conf</code> dentro de la
    secci&oacute;n &lt;Directory  
    "/usr/local/apache/htdocs/secret"&gt; , como se muestra a continuaci&oacute;n:</p>

    <pre class="prettyprint lang-config">&lt;Directory "/usr/local/apache/htdocs/secret"&gt;
AuthType Basic
AuthName "Restricted Files"
# (Following line optional)
AuthBasicProvider file
AuthUserFile "/usr/local/apache/passwd/passwords"
Require user rbowen
&lt;/Directory&gt;</pre>


    <p>Vamos a explicar cada una de las directivas individualmente.
    	La directiva <code class="directive"><a href="../mod/mod_authn_core.html#authtype">AuthType</a></code> selecciona el m&eacute;todo
    que se usa para autenticar al usuario. El m&eacute;todo m&aacute;s com&uacute;n es 
    <code>Basic</code>, y &eacute;ste es el m&eacute;todo que implementa 
    <code class="module"><a href="../mod/mod_auth_basic.html">mod_auth_basic</a></code>. Es muy importante ser consciente,
    de que la autenticaci&oacute;n b&aacute;sica, env&iacute;a las contrase&ntilde;as desde el cliente 
    al servidor sin cifrar.
    Este m&eacute;todo por tanto, no debe ser utilizado para proteger datos muy sensibles,
    a no ser que, este m&eacute;todo de autenticaci&oacute;n b&aacute;sica, sea acompa&ntilde;ado del m&oacute;dulo
    <code class="module"><a href="../mod/mod_ssl.html">mod_ssl</a></code>.
    Apache soporta otro m&eacute;todo m&aacute;s de autenticaci&oacute;n  que es del tipo 
    <code>AuthType Digest</code>. Este m&eacute;todo, es implementado por el m&oacute;dulo <code class="module"><a href="../mod/mod_auth_digest.html">mod_auth_digest</a></code> y con el se pretend&iacute;a crear una autenticaci&oacute;n m&aacute;s
    segura. Este ya no es el caso, ya que la conexi&oacute;n deber&aacute; realizarse con  <code class="module"><a href="../mod/mod_ssl.html">mod_ssl</a></code> en su lugar.
    </p>

    <p>La directiva <code class="directive"><a href="../mod/mod_authn_core.html#authname">AuthName</a></code> 
    establece el <dfn>Realm</dfn> para ser usado en la autenticaci&oacute;n. El 
    <dfn>Realm</dfn> tiene dos funciones principales.
    La primera, el cliente presenta a menudo esta informaci&oacute;n al usuario como 
    parte del cuadro de di&aacute;logo de contrase&ntilde;a. La segunda, que es utilizado por 
    el cliente para determinar qu&eacute; contrase&ntilde;a enviar a para una determinada zona 
    de autenticaci&oacute;n.</p>

    <p>As&iacute; que, por ejemple, una vez que el cliente se ha autenticado en el &aacute;rea de
    los <code>"Ficheros Restringidos"</code>, entonces re-intentar&aacute; autom&aacute;ticamente
    la misma contrase&ntilde;a para cualquier &aacute;rea en el mismo servidor que es marcado 
    con el Realm de <code>"Ficheros Restringidos"</code>
    Por lo tanto, puedes prevenir que a un usuario se le pida mas de una vez por su
    contrase&ntilde;a, compartiendo as&iacute; varias &aacute;reas restringidas el mismo Realm
    Por supuesto, por razones de seguridad, el cliente pedir&aacute; siempre por una contrase&ntilde;a, 
    siempre y cuando el nombre del servidor cambie.
    </p>

    <p>La directiva <code class="directive"><a href="../mod/mod_auth_basic.html#authbasicprovider">AuthBasicProvider</a></code> es,
    en este caso, opcional, ya que <code>file</code> es el valor por defecto
    para esta directiva. Deber&aacute;s usar esta directiva si estas usando otro medio
    diferente para la autenticaci&oacute;n, como por ejemplo
    <code class="module"><a href="../mod/mod_authn_dbm.html">mod_authn_dbm</a></code> o <code class="module"><a href="../mod/mod_authn_dbd.html">mod_authn_dbd</a></code>.</p>

    <p>La directiva <code class="directive"><a href="../mod/mod_authn_file.html#authuserfile">AuthUserFile</a></code>
    establece el path al fichero de contrase&ntilde;as que acabamos de crear con el 
    comando <code class="program"><a href="../programs/htpasswd.html">htpasswd</a></code>. Si tiene un n&uacute;mero muy grande de usuarios, 
    puede ser realmente lento el buscar el usuario en ese fichero de texto plano 
    para autenticar a los usuarios en cada petici&oacute;n.
    Apache tambi&eacute;n tiene la habilidad de almacenar informaci&oacute;n de usuarios en 
    unos ficheros de r&aacute;pido acceso a modo de base de datos.
    El m&oacute;dulo <code class="module"><a href="../mod/mod_authn_dbm.html">mod_authn_dbm</a></code> proporciona la directiva <code class="directive"><a href="../mod/mod_authn_dbm.html#authdbmuserfile">AuthDBMUserFile</a></code>. Estos ficheros pueden ser creados y
    manipulados con el programa <code class="program"><a href="../programs/dbmmanage.html">dbmmanage</a></code> y <code class="program"><a href="../programs/htdbm.html">htdbm</a></code>. 
    Muchos otros m&eacute;todos de autenticaci&oacute;n as&iacute; como otras opciones, est&aacute;n disponibles en 
    m&oacute;dulos de terceros 
    <a href="http://modules.apache.org/">Base de datos de M&oacute;dulos disponibles</a>.</p>

    <p>Finalmente, la directiva <code class="directive"><a href="../mod/mod_authz_core.html#require">Require</a></code>
    proporciona la parte del proceso de autorizaci&oacute;n estableciendo el o los
    usuarios que se les est&aacute; permitido acceder a una regi&oacute;n del servidor.
    En la pr&oacute;xima secci&oacute;n, discutiremos las diferentes v&iacute;as de utilizar la 
    directiva <code class="directive"><a href="../mod/mod_authz_core.html#require">Require</a></code>.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="lettingmorethanonepersonin">Dejar que m&aacute;s de una persona 
	entre <a title="Enlace permanente" href="#lettingmorethanonepersonin" class="permalink">&para;</a></h2>
    <p>Las directivas mencionadas arriba s&oacute;lo permiten a una persona 
    (especialmente con un usuario que en ej ejemplo es <code>rbowen</code>) 
    en el directorio. En la mayor&iacute;a de los casos, se querr&aacute; permitir el acceso
    a m&aacute;s de una persona. Aqu&iacute; es donde la directiva 
    <code class="directive"><a href="../mod/mod_authz_groupfile.html#authgroupfile">AuthGroupFile</a></code> entra en juego.</p>

    <p>Si lo que se desea es permitir a m&aacute;s de una persona el acceso, necesitar&aacute;s
     crear un archivo de grupo que asocie los nombres de grupos con el de personas
     para permitirles el acceso. El formato de este fichero es bastante sencillo, 
     y puedes crearlo con tu editor de texto favorito. El contenido del fichero 
     se parecer&aacute; a:</p>

   <div class="example"><p><code>
     GroupName: rbowen dpitts sungo rshersey
   </code></p></div>

    <p>B&aacute;sicamente eso es la lista de miembros los cuales est&aacute;n en un mismo fichero
     de grupo en una sola linea separados por espacios.</p>

    <p>Para a&ntilde;adir un usuario a tu fichero de contrase&ntilde;as existente teclee:</p>

    <div class="example"><p><code>
      htpasswd /usr/local/apache/passwd/passwords dpitts
    </code></p></div>

    <p>Te responder&aacute; lo mismo que anteriormente, pero se a&ntilde;adir&aacute; al fichero 
    	existente en vez de crear uno nuevo. (Es decir el flag <code>-c</code> ser&aacute; 
    	el que haga que se genere un nuevo 
    fichero de contrase&ntilde;as).</p>

    <p>Ahora, tendr&aacute; que modificar su fichero <code>.htaccess</code> para que sea 
    parecido a lo siguiente:</p>

    <pre class="prettyprint lang-config">AuthType Basic
AuthName "By Invitation Only"
# Optional line:
AuthBasicProvider file
AuthUserFile "/usr/local/apache/passwd/passwords"
AuthGroupFile "/usr/local/apache/passwd/groups"
Require group GroupName</pre>


    <p>Ahora, cualquiera que est&eacute; listado en el grupo <code>GroupName</code>,
    y tiene una entrada en el fichero de <code>contrase&ntilde;as</code>, se les 
    permitir&aacute; el acceso, si introducen su contrase&ntilde;a correctamente.</p>

    <p>Hay otra manera de dejar entrar a varios usuarios, que es menos espec&iacute;fica.
    En lugar de crear un archivo de grupo, s&oacute;lo puede utilizar la siguiente 
    directiva:</p>

    <pre class="prettyprint lang-config">Require valid-user</pre>


    <p>Usando &eacute;sto en vez de la l&iacute;nea <code>Require user rbowen</code>
     permitir&aacute; a cualquier persona acceder, la cu&aacute;l aparece en el archivo de 
     contrase&ntilde;as, y que introduzca correctamente su contrase&ntilde;a. Incluso puede 
     emular el comportamiento del grupo aqu&iacute;, s&oacute;lo manteniendo un fichero de 
     contrase&ntilde;as independiente para cada grupo. La ventaja de este enfoque es 
     que Apache s&oacute;lo tiene que comprobar un archivo, en lugar de dos. La desventaja 
     es que se tiene que mantener un mont&oacute;n de ficheros de contrase&ntilde;a de grupo, y 
     recuerde hacer referencia al fichero correcto en la directiva
    <code class="directive"><a href="../mod/mod_authn_file.html#authuserfile">AuthUserFile</a></code>.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="possibleproblems">Posibles Problemas <a title="Enlace permanente" href="#possibleproblems" class="permalink">&para;</a></h2>
    <p>Debido a la forma en que se especifica la autenticaci&oacute;n b&aacute;sica,
    su nombre de usuario y la contrase&ntilde;a deben ser verificados cada vez 
    que se solicita un documento desde el servidor. Esto es, incluso si&nbsp;
    se&nbsp; vuelve a cargar la misma p&aacute;gina, y para cada imagen de la p&aacute;gina (si
&nbsp;&nbsp;&nbsp;&nbsp;provienen de un directorio protegido). Como se puede imaginar, esto
&nbsp;&nbsp;&nbsp;&nbsp;ralentiza las cosas un poco. La cantidad que ralentiza las cosas es 
    proporcional al tama&ntilde;o del archivo de contrase&ntilde;as, porque tiene que 
    abrir ese archivo, recorrer&nbsp;lista de usuarios hasta que llega a su nombre.
    Y tiene que hacer esto cada vez que se carga una p&aacute;gina.</p>

    <p>Una consecuencia de esto, es que hay un limite pr&aacute;ctico de cuantos 
    usuarios puedes introducir en el fichero de contrase&ntilde;as. Este l&iacute;mite
    variar&aacute; dependiendo de la m&aacute;quina en la que tengas el servidor,
    pero puedes notar ralentizaciones en cuanto se metan cientos de entradas,
    y por lo tanto consideraremos entonces otro m&eacute;todo de autenticaci&oacute;n
    en ese momento.
	</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="dbmdbd">M&eacute;todo alternativo de almacenamiento de las 
	contrase&ntilde;as <a title="Enlace permanente" href="#dbmdbd" class="permalink">&para;</a></h2>

    <p>Debido a que el almacenamiento de las contrase&ntilde;as en texto plano tiene 
    	el problema mencionado anteriormente, puede que se prefiera guardar 
    	las contrase&ntilde;as en otro lugar como por ejemplo una base de datos.
    	</p>

    <p>Los m&oacute;dulos <code class="module"><a href="../mod/mod_authn_dbm.html">mod_authn_dbm</a></code> y <code class="module"><a href="../mod/mod_authn_dbd.html">mod_authn_dbd</a></code> son
    dos m&oacute;dulos que hacen esto posible. En vez de seleccionar la directiva de fichero
    <code><code class="directive"><a href="../mod/mod_auth_basic.html#authbasicprovider">AuthBasicProvider</a></code> </code>, en su lugar
    se puede elegir <code>dbm</code> o <code>dbd</code> como formato de almacenamiento.</p>

    <p>Para seleccionar los ficheros de tipo dbm en vez de texto plano, podremos hacer algo parecido a lo siguiente:</p>

    <pre class="prettyprint lang-config">&lt;Directory "/www/docs/private"&gt;
    AuthName "Private"
    AuthType Basic
    AuthBasicProvider dbm
    AuthDBMUserFile "/www/passwords/passwd.dbm"
    Require valid-user
&lt;/Directory&gt;</pre>


    <p>Hay otras opciones disponibles. Consulta la documentaci&oacute;n de
    <code class="module"><a href="../mod/mod_authn_dbm.html">mod_authn_dbm</a></code> para m&aacute;s detalles.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="multprovider">Uso de m&uacute;ltiples proveedores <a title="Enlace permanente" href="#multprovider" class="permalink">&para;</a></h2>

    <p>Con la introducci&oacute;n de la nueva autenticaci&oacute;n basada en un proveedor y
     una arquitectura de autorizaci&oacute;n, ya no estaremos restringidos a un &uacute;nico
     m&eacute;todo de autenticaci&oacute;n o autorizaci&oacute;n. De hecho, cualquier n&uacute;mero de 
     los proveedores pueden ser mezclados y emparejados para ofrecerle 
     exactamente el esquema que se adapte a sus necesidades. 
     En el siguiente ejemplo, veremos como ambos proveedores tanto el fichero 
     como el LDAP son usados en la autenticaci&oacute;n:
     </p>

    <pre class="prettyprint lang-config">&lt;Directory "/www/docs/private"&gt;
    AuthName "Private"
    AuthType Basic
    AuthBasicProvider file ldap
    AuthUserFile "/usr/local/apache/passwd/passwords"
    AuthLDAPURL ldap://ldaphost/o=yourorg
    Require valid-user
&lt;/Directory&gt;</pre>


    <p>En este ejemplo el fichero, que act&uacute;a como proveedor, intentar&aacute; autenticar 
    	primero al usuario. Si no puede autenticar al usuario, el proveedor del LDAP
    	ser&aacute; llamado para que realice la autenticaci&oacute;n.
    	Esto permite al &aacute;mbito de autenticaci&oacute;n ser amplio, si su organizaci&oacute;n 
    	implementa m&aacute;s de un tipo de almac&eacute;n de autenticaci&oacute;n. 
    	Otros escenarios de autenticaci&oacute;n y autorizaci&oacute;n pueden incluir la 
    	mezcla de un tipo de autenticaci&oacute;n con un tipo diferente de autorizaci&oacute;n.
    	Por ejemplo, autenticar contra un fichero de contrase&ntilde;as pero autorizando
    	dicho acceso mediante el directorio del LDAP.</p>

    <p>As&iacute; como m&uacute;ltiples m&eacute;todos y proveedores de autenticaci&oacute;n pueden 
    	ser implementados, tambi&eacute;n pueden usarse m&uacute;ltiples formas de 
    	autorizaci&oacute;n.
    	En este ejemplo ambos ficheros de autorizaci&oacute;n de grupo as&iacute; como 
    	autorizaci&oacute;n de grupo mediante LDAP va a ser usado:
    </p>

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


    <p>Para llevar la autorizaci&oacute;n un poco m&aacute;s lejos, las directivas 
    	de autorizaci&oacute;n de contenedores tales como
    <code class="directive"><a href="../mod/mod_authz_core.html#requireall">&lt;RequireAll&gt;</a></code>
    and
    <code class="directive"><a href="../mod/mod_authz_core.html#requireany">&lt;RequireAny&gt;</a></code>
    nos permiten aplicar una l&oacute;gica de en qu&eacute; orden se manejar&aacute; la autorizaci&oacute;n dependiendo
    de la configuraci&oacute;n y controlada a trav&eacute;s de ella.
    Mire tambi&eacute;n <a href="../mod/mod_authz_core.html#logic">Contenedores de
    Autorizaci&oacute;n</a> para ejemplos de c&oacute;mo pueden ser aplicados.</p>

</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="beyond">M&aacute;s all&aacute; de la Autorizaci&oacute;n <a title="Enlace permanente" href="#beyond" class="permalink">&para;</a></h2>

    <p>El modo en que la autorizaci&oacute;n puede ser aplicada es ahora mucho m&aacute;s flexible
    	que us solo chequeo contra un almac&eacute;n de datos (contrase&ntilde;as). Ordenando la 
    	l&oacute;gica y escoger la forma en que la autorizaci&oacute;n es realizada, ahora es posible 
    </p>

    <h3 id="authandororder">Aplicando la l&oacute;gica y ordenaci&oacute;n</h3>
        <p>Controlar el c&oacute;mo y en qu&eacute; orden se va a aplicar la autorizaci&oacute;n ha 
        	sido un misterio en el pasado. En Apache 2.2 un proveedor del 
        	mecanismo de autenticaci&oacute;n fue introducido para disociar el proceso actual
        	de autenticaci&oacute;n y soportar funcionalidad.
        	Uno de los beneficios secundarios fue que los proveedores de autenticaci&oacute;n
        	pod&iacute;an ser configurados y llamados en un orden especifico que no dependieran
        	en el orden de carga del propio modulo. 
        	Este proveedor de dicho mecanismo, ha sido introducido en la autorizaci&oacute;n
        	tambi&eacute;n. Lo que esto significa es que la directiva 
        	<code class="directive"><a href="../mod/mod_authz_core.html#require">Require</a></code> 
        	no s&oacute;lo especifica que m&eacute;todo de autorizaci&oacute;n deber&aacute; ser usado, si no
        	tambi&eacute;n especifica el orden en que van a ser llamados. M&uacute;ltiples
        	m&eacute;todos de autorizaci&oacute;n son llamados en el mismo orden en que la directiva
            <code class="directive"><a href="../mod/mod_authz_core.html#require">Require</a></code> aparece en la
            configuraci&oacute;n.
        </p>

        <p>
        	Con la Introducci&oacute;n del contenedor de directivas de autorizaci&oacute;n tales como
	        <code class="directive"><a href="../mod/mod_authz_core.html#requireall">&lt;RequireAll&gt;</a></code>
	        y
	        <code class="directive"><a href="../mod/mod_authz_core.html#requireany">&lt;RequireAny&gt;</a></code>,
	        La configuraci&oacute;n tambi&eacute;n tiene control sobre cu&aacute;ndo se llaman a los m&eacute;todos
	        de autorizaci&oacute;n y qu&eacute; criterios determinan cu&aacute;ndo se concede el acceso.
	        Vease
	        <a href="../mod/mod_authz_core.html#logic">Contenedores de autorizaci&oacute;n</a>
	        Para un ejemplo de c&oacute;mo pueden ser utilizados para expresar una l&oacute;gica 
	        m&aacute;s compleja de autorizaci&oacute;n.
	    </p>

        <p>
        	Por defecto todas las directivas 
        	<code class="directive"><a href="../mod/mod_authz_core.html#require">Require</a></code>
       		son manejadas como si estuvieran contenidas en una directiva
       		<code class="directive"><a href="../mod/mod_authz_core.html#requireany">&lt;RequireAny&gt;</a></code>.
       		En otras palabras, Si alguno de los m&eacute;todos de autorizaci&oacute;n 
       		especificados tiene &eacute;xito, se concede la autorizaci&oacute;n.
       	</p>

    

    <h3 id="reqaccessctrl">Uso de los proveedores de autorizaci&oacute;n para 
    	el control de acceso</h3>

    	<p>
    		La autenticaci&oacute;n de nombre de usuario y contrase&ntilde;a es s&oacute;lo parte
    		de toda la historia que conlleva el proceso. Frecuentemente quiere
    		dar acceso a la gente en base a algo m&aacute;s que lo que son.
    		Algo como de donde vienen.
    	</p>

        <p>
        	Los proveedores de autorizaci&oacute;n <code>all</code>,
        	<code>env</code>, <code>host</code> y <code>ip</code>
        	te permiten denegar o permitir el acceso bas&aacute;ndose en otros
        	criterios como el nombre de la m&aacute;quina o la IP de la m&aacute;quina que
        	realiza la consulta para un documento.
        </p>

        <p>
        	El uso de estos proveedores se especifica a trav&eacute;s de la directiva
        	<code class="directive"><a href="../mod/mod_authz_core.html#require">Require</a></code>.
        	La directiva registra los proveedores de autorizaci&oacute;n que ser&aacute;n llamados
        	durante la solicitud de la fase del proceso de autorizaci&oacute;n. Por ejemplo:
        </p>

        <pre class="prettyprint lang-config">Require ip <var>address</var>
        </pre>


        <p>
        	Donde <var>address</var> es una direcci&oacute;n IP (o una direcci&oacute;n IP parcial) 
        	o bien:
        </p>

        <pre class="prettyprint lang-config">Require host <var>domain_name</var>
        </pre>


        <p>
        	Donde <var>domain_name</var> es el nombre completamente cualificado de un nombre 
	        de dominio (FQDN) (o un nombre parcial del dominio);
	        puede proporcionar m&uacute;ltiples direcciones o nombres de dominio, si se desea.
        </p>

        <p>
        	Por ejemplo, si alguien env&iacute;a spam a su tabl&oacute;n de mensajes y desea
        	mantenerlos alejados, podr&iacute;a hacer lo siguiente:</p>

        <pre class="prettyprint lang-config">&lt;RequireAll&gt;
    Require all granted
    Require not ip 10.252.46.165
&lt;/RequireAll&gt;</pre>


        <p>
        	Visitantes que vengan desde esa IP no ser&aacute;n capaces de ver el contenido
        	que cubre esta directiva. Si, en cambio, lo que se tiene es el nombre de
        	la m&aacute;quina, en vez de la direcci&oacute;n IP, podr&iacute;a usar:
        </p>

        <pre class="prettyprint lang-config">&lt;RequireAll&gt;
    Require all granted
    Require not host host.example.com
&lt;/RequireAll&gt;</pre>


        <p>
        	Y, si lo que se quiere es bloquear el acceso desde un determinado dominio
        	(bloquear el acceso desde el dominio entero), puede especificar parte 
        	de la direcci&oacute;n o del propio dominio a bloquear:
        </p>

        <pre class="prettyprint lang-config">&lt;RequireAll&gt;
    Require all granted
    Require not ip 192.168.205
    Require not host phishers.example.com moreidiots.example
    Require not host ke
&lt;/RequireAll&gt;</pre>


        <p>
        	Usando <code class="directive"><a href="../mod/mod_authz_core.html#requireall">&lt;RequireAll&gt;</a></code>
	        con m&uacute;ltiples directivas <code class="directive"><a href="../mod/mod_authz_core.html#require">&lt;Require&gt;</a></code>, cada una negada con un <code>not</code>,
	        S&oacute;lo permitir&aacute; el acceso, si todas las condiciones negadas son verdaderas.
	        En otras palabras, el acceso ser&aacute; bloqueado, si cualquiera de las condiciones
	        negadas fallara.
        </p>

    

    <h3 id="filesystem">Compatibilidad de Control de Acceso con versiones 
    	anteriores </h3>

        <p>
        	Uno de los efectos secundarios de adoptar proveedores basados en 
        	mecanismos de autenticaci&oacute;n es que las directivas anteriores
	        <code class="directive"><a href="../mod/mod_access_compat.html#order">Order</a></code>,
	        <code class="directive"><a href="../mod/mod_access_compat.html#allow">Allow</a></code>,
	        <code class="directive"><a href="../mod/mod_access_compat.html#deny">Deny</a></code> y
        	<code class="directive"><a href="../mod/mod_access_compat.html#satisfy">Satisfy</a></code> ya no son necesarias.
        	Sin embargo, para proporcionar compatibilidad con configuraciones antiguas,
        	estas directivas se han movido al m&oacute;dulo <code class="module"><a href="../mod/mod_access_compat.html">mod_access_compat</a></code>.
        </p>

        <div class="warning"><h3>Nota:</h3>
	        <p>
	        	Las directivas proporcionadas por <code class="module"><a href="../mod/mod_access_compat.html">mod_access_compat</a></code> 
	        	han quedado obsoletas por <code class="module"><a href="../mod/mod_authz_host.html">mod_authz_host</a></code>. Mezclar 
	        	directivas antiguas como
	        	<code class="directive"><a href="../mod/mod_access_compat.html#order">Order</a></code>, 
	            <code class="directive"><a href="../mod/mod_access_compat.html#allow">Allow</a></code> &oacute; 
	            <code class="directive"><a href="../mod/mod_access_compat.html#deny">Deny</a></code> con las nuevas 
	            como 
	            <code class="directive"><a href="../mod/mod_authz_core.html#require">Require</a></code> 
	            es t&eacute;cnicamente posible pero desaconsejable. El m&oacute;dulo 
	            <code class="module"><a href="../mod/mod_access_compat.html">mod_access_compat</a></code> se cre&oacute; para soportar configuraciones
	            que contuvieran s&oacute;lo directivas antiguas para facilitar la actualizaci&oacute;n
	            a la versi&oacute;n 2.4.
	            Por favor revise la documentaci&oacute;n de 
	            <a href="../upgrading.html">actualizaci&oacute;n</a> para m&aacute;s informaci&oacute;n al
	            respecto.
	        </p>
	    </div>
	

	</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="socache">Cache de Autenticaci&oacute;n <a title="Enlace permanente" href="#socache" class="permalink">&para;</a></h2>
	<p>
		Puede haber momentos en que la autenticaci&oacute;n ponga una carga 
		inaceptable en el proveedor (de autenticaci&oacute;n) o en tu red.
		Esto suele afectar a los usuarios de <code class="module"><a href="../mod/mod_authn_dbd.html">mod_authn_dbd</a></code> 
		(u otros proveedores de terceros/personalizados).
		Para lidiar con este problema, HTTPD 2.3/2.4 introduce un nuevo proveedor
		de cach&eacute;  <code class="module"><a href="../mod/mod_authn_socache.html">mod_authn_socache</a></code> para cachear las credenciales 
		y reducir la carga en el proveedor(es) original.
	</p>
    <p>
    	Esto puede ofrecer un aumento de rendimiento sustancial para algunos usuarios.
    </p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="moreinformation">M&aacute;s informaci&oacute;n <a title="Enlace permanente" href="#moreinformation" class="permalink">&para;</a></h2>

    <p>
    	Tambi&eacute;n deber&iacute;a leer la documentaci&oacute;n para
    	<code class="module"><a href="../mod/mod_auth_basic.html">mod_auth_basic</a></code> y <code class="module"><a href="../mod/mod_authz_host.html">mod_authz_host</a></code>
    	la cu&aacute;l contiene m&aacute;s informaci&oacute;n de como funciona todo esto.
    	La directiva <code class="directive"><a href="../mod/mod_authn_core.html#authnprovideralias">&lt;AuthnProviderAlias&gt;</a></code> puede tambi&eacute;n ayudar 
	    a la hora de simplificar ciertas configuraciones de autenticaci&oacute;n.
	</p>

    <p>
    	Los diferentes algoritmos de cifrado que est&aacute;n soportados por Apache
    	para la autenticaci&oacute;n se explican en
    	<a href="../misc/password_encryptions.html">Cifrado de Contrase&ntilde;as</a>.
    </p>

    <p>
    	Y tal vez quiera ojear la documentaci&oacute;n de "how to"  
    	<a href="access.html">Control de Acceso</a>  donde se mencionan temas 
    	relacionados.</p>

</div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="../en/howto/auth.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/howto/auth.html" title="Espa&ntilde;ol">&nbsp;es&nbsp;</a> |
<a href="../fr/howto/auth.html" hreflang="fr" rel="alternate" title="Fran&ccedil;ais">&nbsp;fr&nbsp;</a> |
<a href="../ja/howto/auth.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="../ko/howto/auth.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="../tr/howto/auth.html" hreflang="tr" rel="alternate" title="T&uuml;rk&ccedil;e">&nbsp;tr&nbsp;</a></p>
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