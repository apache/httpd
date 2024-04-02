<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es" xml:lang="es"><head>
<meta content="text/html; charset=ISO-8859-1" http-equiv="Content-Type" />
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Autenticaci&#243;n y Autorizaci&#243;n - Servidor HTTP Apache Versi&#243;n 2.4</title>
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
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs/">Documentaci&#243;n</a> &gt; <a href="../">Versi&#243;n 2.4</a> &gt; <a href="./">How-To / Tutoriales</a></div><div id="page-content"><div id="preamble"><h1>Autenticaci&#243;n y Autorizaci&#243;n</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="../en/howto/auth.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/howto/auth.html" title="Espa&#241;ol">&nbsp;es&nbsp;</a> |
<a href="../fr/howto/auth.html" hreflang="fr" rel="alternate" title="Fran&#231;ais">&nbsp;fr&nbsp;</a> |
<a href="../ja/howto/auth.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="../ko/howto/auth.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="../tr/howto/auth.html" hreflang="tr" rel="alternate" title="T&#252;rk&#231;e">&nbsp;tr&nbsp;</a></p>
</div>
<div class="outofdate">Esta traducci&#243;n podr&#237;a estar
            obsoleta. Consulte la versi&#243;n en ingl&#233;s de la
            documentaci&#243;n para comprobar si se han producido cambios
            recientemente.</div>

    <p>Autenticaci&#243;n es cualquier proceso por el cu&#225;l se verifica que uno es 
    quien dice ser. Autorizaci&#243;n es cualquier proceso en el cu&#225;l cualquiera
    est&#225; permitido a estar donde se quiera, o tener informaci&#243;n la cu&#225;l se
    quiera tener.
    </p>

    <p>Para informaci&#243;n de control de acceso de forma gen&#233;rica visite<a href="access.html">How to de Control de Acceso</a>.</p>
</div>
<div id="quickview"><a href="https://www.apache.org/foundation/contributing.html" class="badge"><img src="https://www.apache.org/images/SupportApache-small.png" alt="Support Apache!" /></a><ul id="toc"><li><img alt="" src="../images/down.gif" /> <a href="#related">M&#243;dulos y Directivas Relacionados</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#introduction">Introducci&#243;n</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#theprerequisites">Los Prerequisitos</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#gettingitworking">Conseguir que funcione</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#lettingmorethanonepersonin">Dejar que m&#225;s de una persona 
	entre</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#possibleproblems">Posibles Problemas</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#dbmdbd">M&#233;todo alternativo de almacenamiento de las 
	contrase&#241;as</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#multprovider">Uso de m&#250;ltiples proveedores</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#beyond">M&#225;s all&#225; de la Autorizaci&#243;n</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#socache">Cache de Autenticaci&#243;n</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#moreinformation">M&#225;s informaci&#243;n</a></li>
</ul><h3>Consulte tambi&#233;n</h3><ul class="seealso"><li><a href="#comments_section">Comentarios</a></li></ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="related" id="related">M&#243;dulos y Directivas Relacionados</a></h2>

<p>Hay tres tipos de m&#243;dulos involucrados en los procesos de la autenticaci&#243;n 
	y autorizaci&#243;n. Normalmente deber&#225;s escoger al menos un m&#243;dulo de cada grupo.</p>

<ul>
  <li>Modos de Autenticaci&#243;n (consulte la directiva
      <code class="directive"><a href="../mod/mod_authn_core.html#authtype">AuthType</a></code> )
    <ul>
      <li><code class="module"><a href="../mod/mod_auth_basic.html">mod_auth_basic</a></code></li>
      <li><code class="module"><a href="../mod/mod_auth_digest.html">mod_auth_digest</a></code></li>
    </ul>
  </li>
  <li>Proveedor de Autenticaci&#243;n (consulte la directiva
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
  <li>Autorizaci&#243;n (consulte la directiva
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

  <p>A parte de &#233;stos m&#243;dulos, tambi&#233;n est&#225;n
  <code class="module"><a href="../mod/mod_authn_core.html">mod_authn_core</a></code> y
  <code class="module"><a href="../mod/mod_authz_core.html">mod_authz_core</a></code>. &#201;stos m&#243;dulos implementan las directivas 
  esenciales que son el centro de todos los m&#243;dulos de autenticaci&#243;n.</p>

  <p>El m&#243;dulo <code class="module"><a href="../mod/mod_authnz_ldap.html">mod_authnz_ldap</a></code> es tanto un proveedor de 
  autenticaci&#243;n como de autorizaci&#243;n. El m&#243;dulo
  <code class="module"><a href="../mod/mod_authz_host.html">mod_authz_host</a></code> proporciona autorizaci&#243;n y control de acceso
  basado en el nombre del Host, la direcci&#243;n IP o caracter&#237;sticas de la propia
  petici&#243;n, pero no es parte del sistema proveedor de 
  autenticaci&#243;n. Para tener compatibilidad inversa con el mod_access, 
  hay un nuevo modulo llamado <code class="module"><a href="../mod/mod_access_compat.html">mod_access_compat</a></code>.</p>

  <p>Tambi&#233;n puedes mirar el how-to de <a href="access.html">Control de Acceso </a>, donde se plantean varias formas del control de acceso al servidor.</p>

</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="introduction" id="introduction">Introducci&#243;n</a></h2>
    <p>Si se tiene informaci&#243;n en nuestra p&#225;gina web que sea informaci&#243;n 
    	sensible o pensada para un grupo reducido de usuarios/personas,
    	las t&#233;cnicas que se describen en este manual, le servir&#225;n  
    	de ayuda para asegurarse de que las personas que ven esas p&#225;ginas sean 
    	las personas que uno quiere.</p>

    <p>Este art&#237;culo cubre la parte "est&#225;ndar" de c&#243;mo proteger partes de un 
    	sitio web que muchos usar&#225;n.</p>

    <div class="note"><h3>Nota:</h3>
    <p>Si de verdad es necesario que tus datos est&#233;n en un sitio seguro, 
    	considera usar <code class="module"><a href="../mod/mod_ssl.html">mod_ssl</a></code>  como m&#233;todo de autenticaci&#243;n adicional a cualquier forma de autenticaci&#243;n.</p>
    </div>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="theprerequisites" id="theprerequisites">Los Prerequisitos</a></h2>
    <p>Las directivas que se usan en este art&#237;culo necesitaran ponerse ya sea 
    	en el fichero de configuraci&#243;n principal del servidor ( t&#237;picamente en 
    	la secci&#243;n 
    <code class="directive"><a href="../mod/core.html#directory">&lt;Directory&gt;</a></code> de httpd.conf ), o
    en cada uno de los ficheros de configuraciones del propio directorio
    (los archivos <code>.htaccess</code>).</p>

    <p>Si planea usar los ficheros <code>.htaccess</code> , necesitar&#225;s
    tener en la configuraci&#243;n global del servidor, una configuraci&#243;n que permita
    poner directivas de autenticaci&#243;n en estos ficheros. Esto se hace con la
    directiva <code class="directive"><a href="../mod/core.html#allowoverride">AllowOverride</a></code>, la cual especifica
    que directivas, en su caso, pueden ser puestas en cada fichero de configuraci&#243;n
    por directorio.</p>

    <p>Ya que estamos hablando aqu&#237; de autenticaci&#243;n, necesitar&#225;s una directiva 
    	<code class="directive"><a href="../mod/core.html#allowoverride">AllowOverride</a></code> como la siguiente:
    	</p>

    <pre class="prettyprint lang-config">AllowOverride AuthConfig</pre>


    <p>O, si solo se van a poner las directivas directamente en la configuraci&#243;n
    	principal del servidor, deber&#225;s tener, claro est&#225;, permisos de escritura
    	en el archivo. </p>

    <p>Y necesitar&#225;s saber un poco de como est&#225; estructurado el &#225;rbol de 
    	directorios de tu servidor, para poder saber donde se encuentran algunos 
    	archivos. Esto no deber&#237;a ser una tarea dif&#237;cil, a&#250;n as&#237; intentaremos 
    	dejarlo claro llegado el momento de comentar dicho aspecto.</p>

    <p>Tambi&#233;n deber&#225;s de asegurarte de que los m&#243;dulos 
    <code class="module"><a href="../mod/mod_authn_core.html">mod_authn_core</a></code> y <code class="module"><a href="../mod/mod_authz_core.html">mod_authz_core</a></code>
    han sido incorporados, o a&#241;adidos a la hora de compilar en tu binario httpd o
    cargados mediante el archivo de configuraci&#243;n <code>httpd.conf</code>. Estos 
    dos m&#243;dulos proporcionan directivas b&#225;sicas y funcionalidades que son cr&#237;ticas
    para la configuraci&#243;n y uso de autenticaci&#243;n y autorizaci&#243;n en el servidor web.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="gettingitworking" id="gettingitworking">Conseguir que funcione</a></h2>
    <p>Aqu&#237; est&#225; lo b&#225;sico de c&#243;mo proteger con contrase&#241;a un directorio en tu
     servidor.</p>

    <p>Primero, necesitar&#225;s crear un fichero de contrase&#241;a. Dependiendo de que 
    	proveedor de autenticaci&#243;n se haya elegido, se har&#225; de una forma u otra. Para empezar, 
    	usaremos un fichero de contrase&#241;a de tipo texto.</p>

    <p>Este fichero deber&#225; estar en un sitio que no se pueda tener acceso desde
     la web. Esto tambi&#233;n implica que nadie pueda descargarse el fichero de 
     contrase&#241;as. Por ejemplo, si tus documentos est&#225;n guardados fuera de
     <code>/usr/local/apache/htdocs</code>, querr&#225;s poner tu archivo de contrase&#241;as en 
     <code>/usr/local/apache/passwd</code>.</p>

    <p>Para crear el fichero de contrase&#241;as, usa la utilidad 
    	<code class="program"><a href="../programs/htpasswd.html">htpasswd</a></code> que viene con Apache. Esta herramienta se 
    	encuentra en el directorio <code>/bin</code> en donde sea que se ha 
    	instalado el Apache. Si ha instalado Apache desde un paquete de terceros, 
    	puede ser que se encuentre en su ruta de ejecuci&#243;n.</p>

    <p>Para crear el fichero, escribiremos:</p>

    <div class="example"><p><code>
      htpasswd -c /usr/local/apache/passwd/passwords rbowen
    </code></p></div>

    <p><code class="program"><a href="../programs/htpasswd.html">htpasswd</a></code> te preguntar&#225; por una contrase&#241;a, y despu&#233;s 
    te pedir&#225; que la vuelvas a escribir para confirmarla:</p>

    <div class="example"><p><code>
      $ htpasswd -c /usr/local/apache/passwd/passwords rbowen<br />
      New password: mypassword<br />
      Re-type new password: mypassword<br />
      Adding password for user rbowen
    </code></p></div>

    <p>Si <code class="program"><a href="../programs/htpasswd.html">htpasswd</a></code> no est&#225; en tu variable de entorno "path" del 
    sistema, por supuesto deber&#225;s escribir la ruta absoluta del ejecutable para 
    poder hacer que se ejecute. En una instalaci&#243;n por defecto, est&#225; en:
    <code>/usr/local/apache2/bin/htpasswd</code></p>

    <p>Lo pr&#243;ximo que necesitas, ser&#225; configurar el servidor para que pida una 
    	contrase&#241;a y as&#237; decirle al servidor que usuarios est&#225;n autorizados a acceder.
    	Puedes hacer esto ya sea editando el fichero <code>httpd.conf</code>
    de configuraci&#243;n  o usando in fichero <code>.htaccess</code>. Por ejemplo, 
    si quieres proteger el directorio
    <code>/usr/local/apache/htdocs/secret</code>, puedes usar las siguientes 
    directivas, ya sea en el fichero <code>.htaccess</code> localizado en
    following directives, either placed in the file
    <code>/usr/local/apache/htdocs/secret/.htaccess</code>, o
    en la configuraci&#243;n global del servidor <code>httpd.conf</code> dentro de la
    secci&#243;n &lt;Directory  
    "/usr/local/apache/htdocs/secret"&gt; , como se muestra a continuaci&#243;n:</p>

    <pre class="prettyprint lang-config">&lt;Directory "/usr/local/apache/htdocs/secret"&gt;
AuthType Basic
AuthName "Restricted Files"
# (Following line optional)
AuthBasicProvider file
AuthUserFile "/usr/local/apache/passwd/passwords"
Require user rbowen
&lt;/Directory&gt;</pre>


    <p>Vamos a explicar cada una de las directivas individualmente.
    	La directiva <code class="directive"><a href="../mod/mod_authn_core.html#authtype">AuthType</a></code> selecciona el m&#233;todo
    que se usa para autenticar al usuario. El m&#233;todo m&#225;s com&#250;n es 
    <code>Basic</code>, y &#233;ste es el m&#233;todo que implementa 
    <code class="module"><a href="../mod/mod_auth_basic.html">mod_auth_basic</a></code>. Es muy importante ser consciente,
    de que la autenticaci&#243;n b&#225;sica, env&#237;a las contrase&#241;as desde el cliente 
    al servidor sin cifrar.
    Este m&#233;todo por tanto, no debe ser utilizado para proteger datos muy sensibles,
    a no ser que, este m&#233;todo de autenticaci&#243;n b&#225;sica, sea acompa&#241;ado del m&#243;dulo
    <code class="module"><a href="../mod/mod_ssl.html">mod_ssl</a></code>.
    Apache soporta otro m&#233;todo m&#225;s de autenticaci&#243;n  que es del tipo 
    <code>AuthType Digest</code>. Este m&#233;todo, es implementado por el m&#243;dulo <code class="module"><a href="../mod/mod_auth_digest.html">mod_auth_digest</a></code> y con el se pretend&#237;a crear una autenticaci&#243;n m&#225;s
    segura. Este ya no es el caso, ya que la conexi&#243;n deber&#225; realizarse con  <code class="module"><a href="../mod/mod_ssl.html">mod_ssl</a></code> en su lugar.
    </p>

    <p>La directiva <code class="directive"><a href="../mod/mod_authn_core.html#authname">AuthName</a></code> 
    establece el <dfn>Realm</dfn> para ser usado en la autenticaci&#243;n. El 
    <dfn>Realm</dfn> tiene dos funciones principales.
    La primera, el cliente presenta a menudo esta informaci&#243;n al usuario como 
    parte del cuadro de di&#225;logo de contrase&#241;a. La segunda, que es utilizado por 
    el cliente para determinar qu&#233; contrase&#241;a enviar a para una determinada zona 
    de autenticaci&#243;n.</p>

    <p>As&#237; que, por ejemple, una vez que el cliente se ha autenticado en el &#225;rea de
    los <code>"Ficheros Restringidos"</code>, entonces re-intentar&#225; autom&#225;ticamente
    la misma contrase&#241;a para cualquier &#225;rea en el mismo servidor que es marcado 
    con el Realm de <code>"Ficheros Restringidos"</code>
    Por lo tanto, puedes prevenir que a un usuario se le pida mas de una vez por su
    contrase&#241;a, compartiendo as&#237; varias &#225;reas restringidas el mismo Realm
    Por supuesto, por razones de seguridad, el cliente pedir&#225; siempre por una contrase&#241;a, 
    siempre y cuando el nombre del servidor cambie.
    </p>

    <p>La directiva <code class="directive"><a href="../mod/mod_auth_basic.html#authbasicprovider">AuthBasicProvider</a></code> es,
    en este caso, opcional, ya que <code>file</code> es el valor por defecto
    para esta directiva. Deber&#225;s usar esta directiva si estas usando otro medio
    diferente para la autenticaci&#243;n, como por ejemplo
    <code class="module"><a href="../mod/mod_authn_dbm.html">mod_authn_dbm</a></code> o <code class="module"><a href="../mod/mod_authn_dbd.html">mod_authn_dbd</a></code>.</p>

    <p>La directiva <code class="directive"><a href="../mod/mod_authn_file.html#authuserfile">AuthUserFile</a></code>
    establece el path al fichero de contrase&#241;as que acabamos de crear con el 
    comando <code class="program"><a href="../programs/htpasswd.html">htpasswd</a></code>. Si tiene un n&#250;mero muy grande de usuarios, 
    puede ser realmente lento el buscar el usuario en ese fichero de texto plano 
    para autenticar a los usuarios en cada petici&#243;n.
    Apache tambi&#233;n tiene la habilidad de almacenar informaci&#243;n de usuarios en 
    unos ficheros de r&#225;pido acceso a modo de base de datos.
    El m&#243;dulo <code class="module"><a href="../mod/mod_authn_dbm.html">mod_authn_dbm</a></code> proporciona la directiva <code class="directive"><a href="../mod/mod_authn_dbm.html#authdbmuserfile">AuthDBMUserFile</a></code>. Estos ficheros pueden ser creados y
    manipulados con el programa <code class="program"><a href="../programs/dbmmanage.html">dbmmanage</a></code> y <code class="program"><a href="../programs/htdbm.html">htdbm</a></code>. 
    Muchos otros m&#233;todos de autenticaci&#243;n as&#237; como otras opciones, est&#225;n disponibles en 
    m&#243;dulos de terceros 
    <a href="http://modules.apache.org/">Base de datos de M&#243;dulos disponibles</a>.</p>

    <p>Finalmente, la directiva <code class="directive"><a href="../mod/mod_authz_core.html#require">Require</a></code>
    proporciona la parte del proceso de autorizaci&#243;n estableciendo el o los
    usuarios que se les est&#225; permitido acceder a una regi&#243;n del servidor.
    En la pr&#243;xima secci&#243;n, discutiremos las diferentes v&#237;as de utilizar la 
    directiva <code class="directive"><a href="../mod/mod_authz_core.html#require">Require</a></code>.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="lettingmorethanonepersonin" id="lettingmorethanonepersonin">Dejar que m&#225;s de una persona 
	entre</a></h2>
    <p>Las directivas mencionadas arriba s&#243;lo permiten a una persona 
    (especialmente con un usuario que en ej ejemplo es <code>rbowen</code>) 
    en el directorio. En la mayor&#237;a de los casos, se querr&#225; permitir el acceso
    a m&#225;s de una persona. Aqu&#237; es donde la directiva 
    <code class="directive"><a href="../mod/mod_authz_groupfile.html#authgroupfile">AuthGroupFile</a></code> entra en juego.</p>

    <p>Si lo que se desea es permitir a m&#225;s de una persona el acceso, necesitar&#225;s
     crear un archivo de grupo que asocie los nombres de grupos con el de personas
     para permitirles el acceso. El formato de este fichero es bastante sencillo, 
     y puedes crearlo con tu editor de texto favorito. El contenido del fichero 
     se parecer&#225; a:</p>

   <div class="example"><p><code>
     GroupName: rbowen dpitts sungo rshersey
   </code></p></div>

    <p>B&#225;sicamente eso es la lista de miembros los cuales est&#225;n en un mismo fichero
     de grupo en una sola linea separados por espacios.</p>

    <p>Para a&#241;adir un usuario a tu fichero de contrase&#241;as existente teclee:</p>

    <div class="example"><p><code>
      htpasswd /usr/local/apache/passwd/passwords dpitts
    </code></p></div>

    <p>Te responder&#225; lo mismo que anteriormente, pero se a&#241;adir&#225; al fichero 
    	existente en vez de crear uno nuevo. (Es decir el flag <code>-c</code> ser&#225; 
    	el que haga que se genere un nuevo 
    fichero de contrase&#241;as).</p>

    <p>Ahora, tendr&#225; que modificar su fichero <code>.htaccess</code> para que sea 
    parecido a lo siguiente:</p>

    <pre class="prettyprint lang-config">AuthType Basic
AuthName "By Invitation Only"
# Optional line:
AuthBasicProvider file
AuthUserFile "/usr/local/apache/passwd/passwords"
AuthGroupFile "/usr/local/apache/passwd/groups"
Require group GroupName</pre>


    <p>Ahora, cualquiera que est&#233; listado en el grupo <code>GroupName</code>,
    y tiene una entrada en el fichero de <code>contrase&#241;as</code>, se les 
    permitir&#225; el acceso, si introducen su contrase&#241;a correctamente.</p>

    <p>Hay otra manera de dejar entrar a varios usuarios, que es menos espec&#237;fica.
    En lugar de crear un archivo de grupo, s&#243;lo puede utilizar la siguiente 
    directiva:</p>

    <pre class="prettyprint lang-config">Require valid-user</pre>


    <p>Usando &#233;sto en vez de la l&#237;nea <code>Require user rbowen</code>
     permitir&#225; a cualquier persona acceder, la cu&#225;l aparece en el archivo de 
     contrase&#241;as, y que introduzca correctamente su contrase&#241;a. Incluso puede 
     emular el comportamiento del grupo aqu&#237;, s&#243;lo manteniendo un fichero de 
     contrase&#241;as independiente para cada grupo. La ventaja de este enfoque es 
     que Apache s&#243;lo tiene que comprobar un archivo, en lugar de dos. La desventaja 
     es que se tiene que mantener un mont&#243;n de ficheros de contrase&#241;a de grupo, y 
     recuerde hacer referencia al fichero correcto en la directiva
    <code class="directive"><a href="../mod/mod_authn_file.html#authuserfile">AuthUserFile</a></code>.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="possibleproblems" id="possibleproblems">Posibles Problemas</a></h2>
    <p>Debido a la forma en que se especifica la autenticaci&#243;n b&#225;sica,
    su nombre de usuario y la contrase&#241;a deben ser verificados cada vez 
    que se solicita un documento desde el servidor. Esto es, incluso si&nbsp;
    se&nbsp; vuelve a cargar la misma p&#225;gina, y para cada imagen de la p&#225;gina (si
&nbsp;&nbsp;&nbsp;&nbsp;provienen de un directorio protegido). Como se puede imaginar, esto
&nbsp;&nbsp;&nbsp;&nbsp;ralentiza las cosas un poco. La cantidad que ralentiza las cosas es 
    proporcional al tama&#241;o del archivo de contrase&#241;as, porque tiene que 
    abrir ese archivo, recorrer&nbsp;lista de usuarios hasta que llega a su nombre.
    Y tiene que hacer esto cada vez que se carga una p&#225;gina.</p>

    <p>Una consecuencia de esto, es que hay un limite pr&#225;ctico de cuantos 
    usuarios puedes introducir en el fichero de contrase&#241;as. Este l&#237;mite
    variar&#225; dependiendo de la m&#225;quina en la que tengas el servidor,
    pero puedes notar ralentizaciones en cuanto se metan cientos de entradas,
    y por lo tanto consideraremos entonces otro m&#233;todo de autenticaci&#243;n
    en ese momento.
	</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="dbmdbd" id="dbmdbd">M&#233;todo alternativo de almacenamiento de las 
	contrase&#241;as</a></h2>

    <p>Debido a que el almacenamiento de las contrase&#241;as en texto plano tiene 
    	el problema mencionado anteriormente, puede que se prefiera guardar 
    	las contrase&#241;as en otro lugar como por ejemplo una base de datos.
    	</p>

    <p>Los m&#243;dulos <code class="module"><a href="../mod/mod_authn_dbm.html">mod_authn_dbm</a></code> y <code class="module"><a href="../mod/mod_authn_dbd.html">mod_authn_dbd</a></code> son
    dos m&#243;dulos que hacen esto posible. En vez de seleccionar la directiva de fichero
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


    <p>Hay otras opciones disponibles. Consulta la documentaci&#243;n de
    <code class="module"><a href="../mod/mod_authn_dbm.html">mod_authn_dbm</a></code> para m&#225;s detalles.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="multprovider" id="multprovider">Uso de m&#250;ltiples proveedores</a></h2>

    <p>Con la introducci&#243;n de la nueva autenticaci&#243;n basada en un proveedor y
     una arquitectura de autorizaci&#243;n, ya no estaremos restringidos a un &#250;nico
     m&#233;todo de autenticaci&#243;n o autorizaci&#243;n. De hecho, cualquier n&#250;mero de 
     los proveedores pueden ser mezclados y emparejados para ofrecerle 
     exactamente el esquema que se adapte a sus necesidades. 
     En el siguiente ejemplo, veremos como ambos proveedores tanto el fichero 
     como el LDAP son usados en la autenticaci&#243;n:
     </p>

    <pre class="prettyprint lang-config">&lt;Directory "/www/docs/private"&gt;
    AuthName "Private"
    AuthType Basic
    AuthBasicProvider file ldap
    AuthUserFile "/usr/local/apache/passwd/passwords"
    AuthLDAPURL ldap://ldaphost/o=yourorg
    Require valid-user
&lt;/Directory&gt;</pre>


    <p>En este ejemplo el fichero, que act&#250;a como proveedor, intentar&#225; autenticar 
    	primero al usuario. Si no puede autenticar al usuario, el proveedor del LDAP
    	ser&#225; llamado para que realice la autenticaci&#243;n.
    	Esto permite al &#225;mbito de autenticaci&#243;n ser amplio, si su organizaci&#243;n 
    	implementa m&#225;s de un tipo de almac&#233;n de autenticaci&#243;n. 
    	Otros escenarios de autenticaci&#243;n y autorizaci&#243;n pueden incluir la 
    	mezcla de un tipo de autenticaci&#243;n con un tipo diferente de autorizaci&#243;n.
    	Por ejemplo, autenticar contra un fichero de contrase&#241;as pero autorizando
    	dicho acceso mediante el directorio del LDAP.</p>

    <p>As&#237; como m&#250;ltiples m&#233;todos y proveedores de autenticaci&#243;n pueden 
    	ser implementados, tambi&#233;n pueden usarse m&#250;ltiples formas de 
    	autorizaci&#243;n.
    	En este ejemplo ambos ficheros de autorizaci&#243;n de grupo as&#237; como 
    	autorizaci&#243;n de grupo mediante LDAP va a ser usado:
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


    <p>Para llevar la autorizaci&#243;n un poco m&#225;s lejos, las directivas 
    	de autorizaci&#243;n de contenedores tales como
    <code class="directive"><a href="../mod/mod_authz_core.html#requireall">&lt;RequireAll&gt;</a></code>
    and
    <code class="directive"><a href="../mod/mod_authz_core.html#requireany">&lt;RequireAny&gt;</a></code>
    nos permiten aplicar una l&#243;gica de en qu&#233; orden se manejar&#225; la autorizaci&#243;n dependiendo
    de la configuraci&#243;n y controlada a trav&#233;s de ella.
    Mire tambi&#233;n <a href="../mod/mod_authz_core.html#logic">Contenedores de
    Autorizaci&#243;n</a> para ejemplos de c&#243;mo pueden ser aplicados.</p>

</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="beyond" id="beyond">M&#225;s all&#225; de la Autorizaci&#243;n</a></h2>

    <p>El modo en que la autorizaci&#243;n puede ser aplicada es ahora mucho m&#225;s flexible
    	que us solo chequeo contra un almac&#233;n de datos (contrase&#241;as). Ordenando la 
    	l&#243;gica y escoger la forma en que la autorizaci&#243;n es realizada, ahora es posible 
    </p>

    <h3><a name="authandororder" id="authandororder">Aplicando la l&#243;gica y ordenaci&#243;n</a></h3>
        <p>Controlar el c&#243;mo y en qu&#233; orden se va a aplicar la autorizaci&#243;n ha 
        	sido un misterio en el pasado. En Apache 2.2 un proveedor del 
        	mecanismo de autenticaci&#243;n fue introducido para disociar el proceso actual
        	de autenticaci&#243;n y soportar funcionalidad.
        	Uno de los beneficios secundarios fue que los proveedores de autenticaci&#243;n
        	pod&#237;an ser configurados y llamados en un orden especifico que no dependieran
        	en el orden de carga del propio modulo. 
        	Este proveedor de dicho mecanismo, ha sido introducido en la autorizaci&#243;n
        	tambi&#233;n. Lo que esto significa es que la directiva 
        	<code class="directive"><a href="../mod/mod_authz_core.html#require">Require</a></code> 
        	no s&#243;lo especifica que m&#233;todo de autorizaci&#243;n deber&#225; ser usado, si no
        	tambi&#233;n especifica el orden en que van a ser llamados. M&#250;ltiples
        	m&#233;todos de autorizaci&#243;n son llamados en el mismo orden en que la directiva
            <code class="directive"><a href="../mod/mod_authz_core.html#require">Require</a></code> aparece en la
            configuraci&#243;n.
        </p>

        <p>
        	Con la Introducci&#243;n del contenedor de directivas de autorizaci&#243;n tales como
	        <code class="directive"><a href="../mod/mod_authz_core.html#requireall">&lt;RequireAll&gt;</a></code>
	        y
	        <code class="directive"><a href="../mod/mod_authz_core.html#requireany">&lt;RequireAny&gt;</a></code>,
	        La configuraci&#243;n tambi&#233;n tiene control sobre cu&#225;ndo se llaman a los m&#233;todos
	        de autorizaci&#243;n y qu&#233; criterios determinan cu&#225;ndo se concede el acceso.
	        Vease
	        <a href="../mod/mod_authz_core.html#logic">Contenedores de autorizaci&#243;n</a>
	        Para un ejemplo de c&#243;mo pueden ser utilizados para expresar una l&#243;gica 
	        m&#225;s compleja de autorizaci&#243;n.
	    </p>

        <p>
        	Por defecto todas las directivas 
        	<code class="directive"><a href="../mod/mod_authz_core.html#require">Require</a></code>
       		son manejadas como si estuvieran contenidas en una directiva
       		<code class="directive"><a href="../mod/mod_authz_core.html#requireany">&lt;RequireAny&gt;</a></code>.
       		En otras palabras, Si alguno de los m&#233;todos de autorizaci&#243;n 
       		especificados tiene &#233;xito, se concede la autorizaci&#243;n.
       	</p>

    

    <h3><a name="reqaccessctrl" id="reqaccessctrl">Uso de los proveedores de autorizaci&#243;n para 
    	el control de acceso</a></h3>

    	<p>
    		La autenticaci&#243;n de nombre de usuario y contrase&#241;a es s&#243;lo parte
    		de toda la historia que conlleva el proceso. Frecuentemente quiere
    		dar acceso a la gente en base a algo m&#225;s que lo que son.
    		Algo como de donde vienen.
    	</p>

        <p>
        	Los proveedores de autorizaci&#243;n <code>all</code>,
        	<code>env</code>, <code>host</code> y <code>ip</code>
        	te permiten denegar o permitir el acceso bas&#225;ndose en otros
        	criterios como el nombre de la m&#225;quina o la IP de la m&#225;quina que
        	realiza la consulta para un documento.
        </p>

        <p>
        	El uso de estos proveedores se especifica a trav&#233;s de la directiva
        	<code class="directive"><a href="../mod/mod_authz_core.html#require">Require</a></code>.
        	La directiva registra los proveedores de autorizaci&#243;n que ser&#225;n llamados
        	durante la solicitud de la fase del proceso de autorizaci&#243;n. Por ejemplo:
        </p>

        <pre class="prettyprint lang-config">Require ip <var>address</var>
        </pre>


        <p>
        	Donde <var>address</var> es una direcci&#243;n IP (o una direcci&#243;n IP parcial) 
        	o bien:
        </p>

        <pre class="prettyprint lang-config">Require host <var>domain_name</var>
        </pre>


        <p>
        	Donde <var>domain_name</var> es el nombre completamente cualificado de un nombre 
	        de dominio (FQDN) (o un nombre parcial del dominio);
	        puede proporcionar m&#250;ltiples direcciones o nombres de dominio, si se desea.
        </p>

        <p>
        	Por ejemplo, si alguien env&#237;a spam a su tabl&#243;n de mensajes y desea
        	mantenerlos alejados, podr&#237;a hacer lo siguiente:</p>

        <pre class="prettyprint lang-config">&lt;RequireAll&gt;
    Require all granted
    Require not ip 10.252.46.165
&lt;/RequireAll&gt;</pre>


        <p>
        	Visitantes que vengan desde esa IP no ser&#225;n capaces de ver el contenido
        	que cubre esta directiva. Si, en cambio, lo que se tiene es el nombre de
        	la m&#225;quina, en vez de la direcci&#243;n IP, podr&#237;a usar:
        </p>

        <pre class="prettyprint lang-config">&lt;RequireAll&gt;
    Require all granted
    Require not host host.example.com
&lt;/RequireAll&gt;</pre>


        <p>
        	Y, si lo que se quiere es bloquear el acceso desde un determinado dominio
        	(bloquear el acceso desde el dominio entero), puede especificar parte 
        	de la direcci&#243;n o del propio dominio a bloquear:
        </p>

        <pre class="prettyprint lang-config">&lt;RequireAll&gt;
    Require all granted
    Require not ip 192.168.205
    Require not host phishers.example.com moreidiots.example
    Require not host ke
&lt;/RequireAll&gt;</pre>


        <p>
        	Usando <code class="directive"><a href="../mod/mod_authz_core.html#requireall">&lt;RequireAll&gt;</a></code>
	        con m&#250;ltiples directivas <code class="directive"><a href="../mod/mod_authz_core.html#require">&lt;Require&gt;</a></code>, cada una negada con un <code>not</code>,
	        S&#243;lo permitir&#225; el acceso, si todas las condiciones negadas son verdaderas.
	        En otras palabras, el acceso ser&#225; bloqueado, si cualquiera de las condiciones
	        negadas fallara.
        </p>

    

    <h3><a name="filesystem" id="filesystem">Compatibilidad de Control de Acceso con versiones 
    	anteriores </a></h3>

        <p>
        	Uno de los efectos secundarios de adoptar proveedores basados en 
        	mecanismos de autenticaci&#243;n es que las directivas anteriores
	        <code class="directive"><a href="../mod/mod_access_compat.html#order">Order</a></code>,
	        <code class="directive"><a href="../mod/mod_access_compat.html#allow">Allow</a></code>,
	        <code class="directive"><a href="../mod/mod_access_compat.html#deny">Deny</a></code> y
        	<code class="directive"><a href="../mod/mod_access_compat.html#satisfy">Satisfy</a></code> ya no son necesarias.
        	Sin embargo, para proporcionar compatibilidad con configuraciones antiguas,
        	estas directivas se han movido al m&#243;dulo <code class="module"><a href="../mod/mod_access_compat.html">mod_access_compat</a></code>.
        </p>

        <div class="warning"><h3>Nota:</h3>
	        <p>
	        	Las directivas proporcionadas por <code class="module"><a href="../mod/mod_access_compat.html">mod_access_compat</a></code> 
	        	han quedado obsoletas por <code class="module"><a href="../mod/mod_authz_host.html">mod_authz_host</a></code>. Mezclar 
	        	directivas antiguas como
	        	<code class="directive"><a href="../mod/mod_access_compat.html#order">Order</a></code>, 
	            <code class="directive"><a href="../mod/mod_access_compat.html#allow">Allow</a></code> &#243; 
	            <code class="directive"><a href="../mod/mod_access_compat.html#deny">Deny</a></code> con las nuevas 
	            como 
	            <code class="directive"><a href="../mod/mod_authz_core.html#require">Require</a></code> 
	            es t&#233;cnicamente posible pero desaconsejable. El m&#243;dulo 
	            <code class="module"><a href="../mod/mod_access_compat.html">mod_access_compat</a></code> se cre&#243; para soportar configuraciones
	            que contuvieran s&#243;lo directivas antiguas para facilitar la actualizaci&#243;n
	            a la versi&#243;n 2.4.
	            Por favor revise la documentaci&#243;n de 
	            <a href="../upgrading.html">actualizaci&#243;n</a> para m&#225;s informaci&#243;n al
	            respecto.
	        </p>
	    </div>
	

	</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="socache" id="socache">Cache de Autenticaci&#243;n</a></h2>
	<p>
		Puede haber momentos en que la autenticaci&#243;n ponga una carga 
		inaceptable en el proveedor (de autenticaci&#243;n) o en tu red.
		Esto suele afectar a los usuarios de <code class="module"><a href="../mod/mod_authn_dbd.html">mod_authn_dbd</a></code> 
		(u otros proveedores de terceros/personalizados).
		Para lidiar con este problema, HTTPD 2.3/2.4 introduce un nuevo proveedor
		de cach&#233;  <code class="module"><a href="../mod/mod_authn_socache.html">mod_authn_socache</a></code> para cachear las credenciales 
		y reducir la carga en el proveedor(es) original.
	</p>
    <p>
    	Esto puede ofrecer un aumento de rendimiento sustancial para algunos usuarios.
    </p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="moreinformation" id="moreinformation">M&#225;s informaci&#243;n</a></h2>

    <p>
    	Tambi&#233;n deber&#237;a leer la documentaci&#243;n para
    	<code class="module"><a href="../mod/mod_auth_basic.html">mod_auth_basic</a></code> y <code class="module"><a href="../mod/mod_authz_host.html">mod_authz_host</a></code>
    	la cu&#225;l contiene m&#225;s informaci&#243;n de como funciona todo esto.
    	La directiva <code class="directive"><a href="../mod/mod_authn_core.html#authnprovideralias">&lt;AuthnProviderAlias&gt;</a></code> puede tambi&#233;n ayudar 
	    a la hora de simplificar ciertas configuraciones de autenticaci&#243;n.
	</p>

    <p>
    	Los diferentes algoritmos de cifrado que est&#225;n soportados por Apache
    	para la autenticaci&#243;n se explican en
    	<a href="../misc/password_encryptions.html">Cifrado de Contrase&#241;as</a>.
    </p>

    <p>
    	Y tal vez quiera ojear la documentaci&#243;n de "how to"  
    	<a href="access.html">Control de Acceso</a>  donde se mencionan temas 
    	relacionados.</p>

</div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="../en/howto/auth.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/howto/auth.html" title="Espa&#241;ol">&nbsp;es&nbsp;</a> |
<a href="../fr/howto/auth.html" hreflang="fr" rel="alternate" title="Fran&#231;ais">&nbsp;fr&nbsp;</a> |
<a href="../ja/howto/auth.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="../ko/howto/auth.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="../tr/howto/auth.html" hreflang="tr" rel="alternate" title="T&#252;rk&#231;e">&nbsp;tr&nbsp;</a></p>
</div><div class="top"><a href="#page-header"><img src="../images/up.gif" alt="top" /></a></div><div class="section"><h2><a id="comments_section" name="comments_section">Comentarios</a></h2><div class="warning"><strong>Notice:</strong><br />This is not a Q&amp;A section. Comments placed here should be pointed towards suggestions on improving the documentation or server, and may be removed by our moderators if they are either implemented or considered invalid/off-topic. Questions on how to manage the Apache HTTP Server should be directed at either our IRC channel, #httpd, on Libera.chat, or sent to our <a href="https://httpd.apache.org/lists.html">mailing lists</a>.</div>
<script type="text/javascript"><!--//--><![CDATA[//><!--
var comments_shortname = 'httpd';
var comments_identifier = 'http://httpd.apache.org/docs/2.4/howto/auth.html';
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