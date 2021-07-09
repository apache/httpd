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
<title>Autentificaci&#243;n, Autorizaci&#243;n y Control de Acceso - Servidor HTTP Apache</title>
<link href="../style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet" />
<link href="../style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size" />
<link href="../style/css/manual-print.css" rel="stylesheet" media="print" type="text/css" />
<link href="../images/favicon.ico" rel="shortcut icon" /><link href="http://httpd.apache.org/docs/current/howto/auth.html" rel="canonical" /></head>
<body id="manual-page"><div id="page-header">
<p class="menu"><a href="../mod/">M&#243;dulos</a> | <a href="../mod/directives.html">Directivas</a> | <a href="../faq/">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa de este sitio web</a></p>
<p class="apache">Versi&#243;n 2.0 del Servidor HTTP Apache</p>
<img alt="" src="../images/feather.gif" /></div>
<div class="up"><a href="./"><img title="&lt;-" alt="&lt;-" src="../images/left.gif" /></a></div>
<div id="path">
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs/">Documentaci&#243;n</a> &gt; <a href="../">Versi&#243;n 2.0</a> &gt; <a href="./">How-To / Tutoriales</a></div><div id="page-content"><div class="retired"><h4>Please note</h4>
            <p>This document refers to the <strong>2.0</strong> version of Apache httpd, which <strong>is no longer maintained</strong>. Upgrade, and refer to the current version of httpd instead, documented at:</p>
        <ul><li><a href="http://httpd.apache.org/docs/current/">Current release version of Apache HTTP Server documentation</a></li></ul><p>You may follow <a href="http://httpd.apache.org/docs/current/howto/auth.html">this link</a> to go to the current version of this document.</p></div><div id="preamble"><h1>Autentificaci&#243;n, Autorizaci&#243;n y Control de Acceso</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="../en/howto/auth.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/howto/auth.html" title="Espa&#241;ol">&nbsp;es&nbsp;</a> |
<a href="../ja/howto/auth.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="../ko/howto/auth.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a></p>
</div>
<div class="outofdate">Esta traducci&#243;n podr&#237;a estar
            obsoleta. Consulte la versi&#243;n en ingl&#233;s de la
            documentaci&#243;n para comprobar si se han producido cambios
            recientemente.</div>

    <p>La autentificaci&#243;n es cualquier proceso mediante el cual se
    verifica que alguien es quien dice ser. La autorizaci&#243;n es
    cualquier proceso por el cual a alguien se le permite estar donde
    quiere ir, o tener la informaci&#243;n que quiere tener.</p>
</div>
<div id="quickview"><ul id="toc"><li><img alt="" src="../images/down.gif" /> <a href="#related">M&#243;dulos y Directivas relacionadas</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#introduction">Introducci&#243;n</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#theprerequisites">Los Prerrequisitos</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#gettingitworking">Puesta en funcionamiento</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#lettingmorethanonepersonin">Permitir el acceso a m&#225;s
de una persona</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#possibleproblems">Posibles Problemas</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#whatotherneatstuffcanido">&#191;Qu&#233; otra cosa
sencilla y efectiva puedo hacer?</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#moreinformation">M&#225;s informaci&#243;n</a></li>
</ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="related" id="related">M&#243;dulos y Directivas relacionadas</a></h2>
    <table class="related"><tr><th>M&#243;dulos Relacionados</th><th>Directivas Relacionadas</th></tr><tr><td><ul><li><code class="module"><a href="../mod/mod_auth.html">mod_auth</a></code></li><li><code class="module"><a href="../mod/mod_access.html">mod_access</a></code></li></ul></td><td><ul><li><code class="directive"><a href="../mod/mod_access.html#allow">Allow</a></code></li><li><code class="directive"><a href="../mod/mod_auth.html#authgroupfile">AuthGroupFile</a></code></li><li><code class="directive"><a href="../mod/core.html#authname">AuthName</a></code></li><li><code class="directive"><a href="../mod/core.html#authtype">AuthType</a></code></li><li><code class="directive"><a href="../mod/mod_auth.html#authuserfile">AuthUserFile</a></code></li><li><code class="directive"><a href="../mod/mod_access.html#deny">Deny</a></code></li><li><code class="directive"><a href="../mod/core.html#options">Options</a></code></li><li><code class="directive"><a href="../mod/core.html#require">Require</a></code></li></ul></td></tr></table>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="introduction" id="introduction">Introducci&#243;n</a></h2>
    <p>Si en su sitio web tiene informaci&#243;n sensible o dirigida
    s&#243;lo a un peque&#241;o grupo de personas, las t&#233;cnicas
    explicadas en &#233;ste art&#237;culo le ayudar&#225;n a
    asegurarse de que las personas que ven esas p&#225;ginas son las
    personas que usted quiere que las vean.</p>

    <p>Este art&#237;culo cubre la manera "est&#225;ndar" de proteger
    partes de su sitio web que la mayor&#237;a de ustedes van a usar.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="theprerequisites" id="theprerequisites">Los Prerrequisitos</a></h2>
    <p>Las directivas tratadas en &#233;ste art&#237;culo necesitar&#225;n
    ir en el archivo de configuraci&#243;n principal de su servidor
    (t&#237;picamente en una secci&#243;n del tipo
    <code class="directive"><a href="../mod/core.html#directory">&lt;Directory&gt;</a></code>),
    o en archivos de configuraci&#243;n por directorios (archivos 
    <code>.htaccess</code>).</p>

    <p>Si planea usar archivos <code>.htaccess</code>, necesitar&#225;
    tener una configuraci&#243;n en el servidor que permita poner directivas
    de autentificaci&#243;n en estos archivos. Esto se logra con la
    directiva <code class="directive"><a href="../mod/core.html#allowoverride">AllowOverride</a></code>,
    la cual especifica cu&#225;les directivas, en caso de existir, pueden
    ser colocadas en los archivos de configuraci&#243;n por directorios.</p>

    <p>Ya que se est&#225; hablando de autentificaci&#243;n, necesitar&#225;
    una directiva <code class="directive"><a href="../mod/core.html#allowoverride">AllowOverride</a></code> como
    la siguiente:</p>

    <div class="example"><p><code>
      AllowOverride AuthConfig
    </code></p></div>

    <p>O, si s&#243;lo va a colocar directivas directamente en el principal
    archivo de configuraci&#243;n del servidor, por supuesto necesitar&#225;
    tener permiso de escritura a ese archivo.</p>

    <p>Y necesitar&#225; saber un poco acerca de la estructura de
    directorios de su servidor, con la finalidad de que sepa d&#243;nde
    est&#225;n algunos archivos. Esto no deber&#237;a ser muy
    dif&#237;cil, y tratar&#233; de hacerlo sencillo cuando lleguemos a
    ese punto.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="gettingitworking" id="gettingitworking">Puesta en funcionamiento</a></h2>
    <p>Aqu&#237; est&#225; lo esencial en cuanto a proteger con
    contrase&#241;a un directorio de su servidor.</p>

    <p>Necesitar&#225; crear un archivo de contrase&#241;as. &#201;ste
    archivo deber&#237;a colocarlo en alg&#250;n sitio no accesible
    mediante la Web. Por ejemplo, si sus documentos son servidos desde
    <code>/usr/local/apache/htdocs</code> usted podr&#237;a querer colocar
    el(los) archivo(s) de contrase&#241;as en
    <code>/usr/local/apache/passwd</code>.</p>

    <p>Para crear un archivo de contrase&#241;as, use la utilidad
    <code class="program"><a href="../programs/htpasswd.html">htpasswd</a></code> que viene con Apache.
    &#201;sta utilidad puede encontrarla en el directorio <code>bin</code>
    de cualquier sitio en que haya instalado Apache. Para crear el
    archivo, escriba:</p>

    <div class="example"><p><code>
      htpasswd -c /usr/local/apache/passwd/passwords rbowen
    </code></p></div>

    <p><code class="program"><a href="../programs/htpasswd.html">htpasswd</a></code> le pedir&#225; la contrase&#241;a, y luego se
    la volver&#225; a pedir para confirmarla:</p>

    <div class="example"><p><code>
      # htpasswd -c /usr/local/apache/passwd/passwords rbowen<br />
      New password: mypassword<br />
      Re-type new password: mypassword<br />
      Adding password for user rbowen
    </code></p></div>

    <p>Si <code class="program"><a href="../programs/htpasswd.html">htpasswd</a></code> no est&#225; en su ruta, por supuesto
    tendr&#225; que escribir la ruta completa al archivo para ejecutarlo.
    En mi servidor, &#233;ste archivo est&#225; en
    <code>/usr/local/apache/bin/htpasswd</code></p>

    <p>El siguiente paso es configurar el servidor para que solicite una
    contrase&#241;a y decirle al servidor a qu&#233; usuarios se les
    permite el acceso. Puede hacer esto editando el archivo
    <code>httpd.conf</code> o usando un archivo <code>.htaccess</code>.
    Por ejemplo, si desea proteger el directorio
    <code>/usr/local/apache/htdocs/secret</code>, puede usar las siguientes
    directivas, ya sea coloc&#225;ndolas en el archivo
    <code>/usr/local/apache/htdocs/secret/.htaccess</code>,
    o en <code>httpd.conf</code> dentro de una secci&#243;n &lt;Directory
    /usr/local/apache/apache/htdocs/secret&gt;.</p>

    <div class="example"><p><code>
      AuthType Basic<br />
      AuthName "Restricted Files"<br />
      AuthUserFile /usr/local/apache/passwd/passwords<br />
      Require user rbowen
    </code></p></div>

    <p>Vamos a examinar cada una de estas directivas por separado. La
    directiva <code class="directive"><a href="../mod/core.html#authtype">AuthType</a></code> selecciona
    el m&#233;todo que se va a usar para autentificar al usuario. El
    m&#233;todo m&#225;s com&#250;n es <code>Basic</code>, y &#233;ste
    m&#233;todo est&#225; implementado en <code class="module"><a href="../mod/mod_auth.html">mod_auth</a></code>. Es importante
    ser consciente, sin embargo, de que la autentificaci&#243;n B&#225;sica
    env&#237;a la contrase&#241;a desde el cliente hasta el navegador sin
    encriptar. Por lo tanto, este m&#233;todo no deber&#237;a ser usado
    para informaci&#243;n altamente sensible. Apache soporta otro m&#233;todo
    de autentificaci&#243;n: <code>AuthType Digest</code>. Este m&#233;todo
    est&#225; implementado en <code class="module"><a href="../mod/mod_auth_digest.html">mod_auth_digest</a></code> y es mucho m&#225;s
    seguro. S&#243;lo las versiones m&#225;s recientes de clientes soportan
    la autentificaci&#243;n del tipo Digest.</p>

    <p>La directiva <code class="directive"><a href="../mod/core.html#authname">AuthName</a></code> establece
    el <dfn>Dominio (Realm)</dfn> a usar en la
    autentificaci&#243;n. El dominio (realm) cumple
    dos funciones importantes. Primero, el cliente frecuentemente presenta
    esta informaci&#243;n al usuario como parte del cuatro de di&#225;logo
    para la contrase&#241;a. Segundo, es usado por el cliente para determinar 
    qu&#233; contrase&#241;a enviar para un &#225;rea autentificada dada.</p>

    <p>As&#237;, por ejemplo, una vez que el cliente se haya autentificado en
    el &#225;rea <code>"Restricted Files"</code>,
    autom&#225;ticamente se volver&#225; a tratar de usar la misma
    contrase&#241;a en cualquier &#225;rea del mismo servidor que est&#233;
    marcado con el Dominio (Realm) <code>"Restricted Files"</code>. Por lo tanto,
    puede evitar que se le pida al usuario la contrase&#241;a
    m&#225;s de una vez permitiendo compartir el mismo dominio (realm)
    para m&#250;ltiples &#225;reas restringidas. Por supuesto, por
    razones de seguridad, el cliente siempre necesitar&#225; pedir de
    nuevo la contrase&#241;a cuando cambie el nombre de la
    m&#225;quina del servidor.</p>

    <p>La directiva <code class="directive"><a href="../mod/mod_auth.html#authuserfile">AuthUserFile</a></code>
    establece la ruta al archivo de contrase&#241;a que acabamos de crear
    con <code class="program"><a href="../programs/htpasswd.html">htpasswd</a></code>. Si tiene un gran n&#250;mero de usuarios,
    ser&#237;a bastante lento buscar por medio de un archivo en texto plano
    para autentificar al usuario en cada solicitud. Apache tambi&#233;n tiene
    la capacidad de almacenar la informaci&#243;n del usuario en 
    archivos r&#225;pidos de bases de datos. El m&#243;dulo <code class="module"><a href="../mod/mod_auth_dbm.html">mod_auth_dbm</a></code>
    proporciona la directiva <code class="directive"><a href="../mod/mod_auth_dbm.html#authdbmuserfile">AuthDBMUserFile</a></code>. Estos archivos pueden
    ser creados y manipulados con el programa
    <code class="program"><a href="../programs/dbmmanage.html">dbmmanage</a></code>. Muchos otros tipos
    de opciones de autentificaci&#243;n est&#225;n disponibles en m&#243;dulos
    de terceras partes en la <a href="http://modules.apache.org/">Base de
    datos de M&#243;dulos de Apache</a>.</p>

    <p>Finalmente, la directiva <code class="directive"><a href="../mod/core.html#require">Require</a></code>
    proporciona la parte de la autorizaci&#243;n del proceso estableciendo
    el usuario al que se le permite acceder a ese &#225;rea del servidor.
    En la pr&#243;xima secci&#243;n, discutimos varias formas de usar la
    directiva <code class="directive"><a href="../mod/core.html#require">Require</a></code>.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="lettingmorethanonepersonin" id="lettingmorethanonepersonin">Permitir el acceso a m&#225;s
de una persona</a></h2>
    <p>Las directivas anteriores s&#243;lo permiten que una persona
    (espec&#237;ficamente alguien con un nombre de usuario de
    <code>rbowen</code>) acceda al directorio. En la mayor&#237;a de los
    casos, usted querr&#225; permitir el acceso a m&#225;s de una persona.
    Aqu&#237; es donde entra la directiva <code class="directive"><a href="../mod/mod_auth.html#authgroupfile">AuthGroupFile</a></code>.</p>

    <p>Si desea permitir la entrada a m&#225;s de una persona, necesitar&#225;
    crear un archivo de grupo que asocie nombres de grupo con una lista
    de usuarios perteneciente a ese grupo. El formato de este archivo es muy sencillo,
    y puede crearlo con su editor favorito. El contenido del archivo
    ser&#225; parecido a este:</p>

   <div class="example"><p><code>
     GroupName: rbowen dpitts sungo rshersey
   </code></p></div>

    <p>Esto es solo una lista de miembros del grupo escritos en una 
    l&#237;nea separados por espacios.</p>

    <p>Para agregar un usuario a un archivo de contrase&#241;as ya existente,
    escriba:</p>

    <div class="example"><p><code>
      htpasswd /usr/local/apache/passwd/passwords dpitts
    </code></p></div>

    <p>Obtendr&#225; la misma respuesta que antes, pero el nuevo usuario ser&#225; agregado
    al archivo existente, en lugar de crear un nuevo archivo.
    (Es la opci&#243;n <code>-c</code> la que se cree un nuevo archivo
    de contrase&#241;as).</p>

    <p>Ahora, necesita modificar su archivo <code>.htaccess</code> para que
    sea como el siguiente:</p>

    <div class="example"><p><code>
      AuthType Basic<br />
      AuthName "By Invitation Only"<br />
      AuthUserFile /usr/local/apache/passwd/passwords<br />
      AuthGroupFile /usr/local/apache/passwd/groups<br />
      Require group GroupName
    </code></p></div>

    <p>Ahora, cualquiera que est&#233; listado en el grupo <code>GroupName</code>,
    y figure en el archivo <code>password</code>, se le permitir&#225;
    el acceso, si escribe la contrase&#241;a correcta.</p>

    <p>Existe otra manera de permitir entrar a m&#250;ltiples usuarios que
    es menos espec&#237;fica. En lugar de crear un archivo de grupo, puede
    usar s&#243;lo la siguiente directiva:</p>

    <div class="example"><p><code>
      Require valid-user
    </code></p></div>

    <p>Usando eso en vez de la l&#237;nea <code>Require user rbowen</code>,
    le permitir&#225; el acceso a cualquiera que est&#233; listado en el
    archivo de contrase&#241;as y que haya introducido correctamente su
    contrase&#241;a. Incluso puede emular el comportamiento del grupo
    aqu&#237;, s&#243;lo manteniendo un archivo de contrase&#241;a para
    cada grupo. La ventaja de esta t&#233;cnica es que Apache s&#243;lo
    tiene que verificar un archivo, en vez de dos. La desventaja es que
    usted tiene que mantener un grupo de archivos de contrase&#241;a, y
    recordar referirse al correcto en la directiva <code class="directive"><a href="../mod/mod_auth.html#authuserfile">AuthUserFile</a></code>.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="possibleproblems" id="possibleproblems">Posibles Problemas</a></h2>
    <p>Por la manera en la que la autentificaci&#243;n b&#225;sica est&#225;
    especificada, su nombre de usuario y contrase&#241;a debe ser verificado
    cada vez que se solicita un documento del servidor. Incluso si est&#225;
    recargando la misma p&#225;gina, y por cada imagen de la p&#225;gina
    (si vienen de un directorio protegido). Como se puede imaginar, esto
    retrasa un poco las cosas. El retraso es proporcional al
    tama&#241;o del archivo de contrase&#241;a, porque se tiene que abrir ese
    archivo, y recorrer la lista de usuarios hasta que encuentre su nombre.
    Y eso se tiene que hacer cada vez que se cargue la p&#225;gina.</p>

    <p>Una consecuencia de esto es que hay un l&#237;mite pr&#225;ctico
    de cu&#225;ntos usuarios puede colocar en un archivo de contrase&#241;as.
    Este l&#237;mite variar&#225; dependiendo del rendimiento de su equipo
    servidor en particular, pero puede esperar observar una disminuci&#243;n
    una vez que inserte unos cientos de entradas, y puede que entonces considere
    un m&#233;todo distinto de autentificaci&#234;n.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="whatotherneatstuffcanido" id="whatotherneatstuffcanido">&#191;Qu&#233; otra cosa
sencilla y efectiva puedo hacer?</a></h2>
    <p>La autentificaci&#243;n por nombre de usuario y contrase&#241;a es
    s&#243;lo parte del cuento. Frecuentemente se desea permitir el acceso
    a los usuarios basandose en algo m&#225;s que qui&#233;nes son. Algo como de
    d&#243;nde vienen.</p>

    <p>Las directivas <code class="directive"><a href="../mod/mod_access.html#allow">Allow</a></code> y
    <code class="directive"><a href="../mod/mod_access.html#deny">Deny</a></code> posibilitan permitir
    y rechazar el acceso dependiendo del nombre o la direcci&#243;n de la
    m&#225;quina que solicita un documento. La directiva <code class="directive"><a href="../mod/mod_access.html#order">Order</a></code> va de la mano con estas dos, y le
    dice a Apache en qu&#233; orden aplicar los filtros.</p>

    <p>El uso de estas directivas es:</p>

    <div class="example"><p><code>
      Allow from <var>address</var>
    </code></p></div>

    <p>donde <var>address</var> es una direcci&#243;n IP (o una
    direcci&#243;n IP parcial) o un nombre de dominio completamente
    cualificado (o un nombre de dominio parcial); puede proporcionar
    m&#250;ltiples direcciones o nombres de dominio, si lo desea.</p>

    <p>Por ejemplo, si usted tiene a alguien que manda mensajes no deseados
    a su foro, y quiere que no vuelva a acceder, podr&#237;a hacer lo
    siguiente:</p>

    <div class="example"><p><code>
      Deny from 205.252.46.165
    </code></p></div>

    <p>Los visitantes que vengan de esa direcci&#243;n no podr&#225;n
    ver el contenido afectado por esta directiva. Si, por el
    contrario, usted tiene un nombre de m&#225;quina pero no una
    direcci&#243;n IP, tambi&#233;n puede usarlo.</p>

    <div class="example"><p><code>
      Deny from <var>host.example.com</var>
    </code></p></div>

    <p>Y, si le gustar&#237;a bloquear el acceso de un dominio entero,
    puede especificar s&#243;lo parte de una direcci&#243;n o nombre de
    dominio:</p>

    <div class="example"><p><code>
      Deny from <var>192.101.205</var><br />
      Deny from <var>cyberthugs.com</var> <var>moreidiots.com</var><br />
      Deny from ke
    </code></p></div>

    <p>Usar <code class="directive"><a href="../mod/mod_access.html#order">Order</a></code> le permitir&#225;
    estar seguro de que efectivamente est&#225; restringiendo el acceso
    al grupo al que quiere permitir el acceso, combinando una directiva
    <code class="directive"><a href="../mod/mod_access.html#deny">Deny</a></code> y una <code class="directive"><a href="../mod/mod_access.html#allow">Allow</a></code>:</p>

    <div class="example"><p><code>
      Order deny,allow<br />
      Deny from all<br />
      Allow from <var>dev.example.com</var>
    </code></p></div>

    <p>Usando s&#243;lo la directiva <code class="directive"><a href="../mod/mod_access.html#allow">Allow</a></code> no har&#237;a lo que desea, porque
    le permitir&#237;a entrar a la gente proveniente de esa m&#225;quina, y
    adicionalmente a cualquier persona. Lo que usted quiere es dejar entrar
    <em>s&#243;lo</em> aquellos.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="moreinformation" id="moreinformation">M&#225;s informaci&#243;n</a></h2>
    <p>Tambi&#233;n deber&#237;a leer la documentaci&#243;n de
    <code class="module"><a href="../mod/mod_auth.html">mod_auth</a></code> y <code class="module"><a href="../mod/mod_access.html">mod_access</a></code> que
    contiene m&#225;s informaci&#243;n acerca de c&#243;mo funciona todo esto.</p>
</div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="../en/howto/auth.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/howto/auth.html" title="Espa&#241;ol">&nbsp;es&nbsp;</a> |
<a href="../ja/howto/auth.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="../ko/howto/auth.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a></p>
</div><div id="footer">
<p class="apache">Copyright 2013 The Apache Software Foundation.<br />Licencia bajo los t&#233;rminos de la <a href="http://www.apache.org/licenses/LICENSE-2.0">Apache License, Version 2.0</a>.</p>
<p class="menu"><a href="../mod/">M&#243;dulos</a> | <a href="../mod/directives.html">Directivas</a> | <a href="../faq/">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa de este sitio web</a></p></div>
</body></html>