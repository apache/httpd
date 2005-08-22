<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es" xml:lang="es"><head><!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Autentificación, Autorización y Control de Acceso - Servidor HTTP Apache</title>
<link href="../style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet" />
<link href="../style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size" />
<link href="../style/css/manual-print.css" rel="stylesheet" media="print" type="text/css" />
<link href="../images/favicon.ico" rel="shortcut icon" /></head>
<body id="manual-page"><div id="page-header">
<p class="menu"><a href="../mod/">Módulos</a> | <a href="../mod/directives.html">Directivas</a> | <a href="../faq/">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa de este sitio web</a></p>
<p class="apache">Versión 2.0 del Servidor HTTP Apache</p>
<img alt="" src="../images/feather.gif" /></div>
<div class="up"><a href="./"><img title="&lt;-" alt="&lt;-" src="../images/left.gif" /></a></div>
<div id="path">
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs-project/">Documentación</a> &gt; <a href="../">Versión 2.0</a> &gt; <a href="./">How-To / Tutoriales</a></div><div id="page-content"><div id="preamble"><h1>Autentificación, Autorización y Control de Acceso</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="../en/howto/auth.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/howto/auth.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="../ja/howto/auth.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="../ko/howto/auth.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a></p>
</div>

    <p>La autentificación es cualquier proceso mediante el cual se
    verifica que alguien es quien dice ser. La autorización es
    cualquier proceso por el cual a alguien se le permite estar donde
    quiere ir, o tener la información que quiere tener.</p>
</div>
<div id="quickview"><ul id="toc"><li><img alt="" src="../images/down.gif" /> <a href="#related">Módulos y Directivas relacionadas</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#introduction">Introducción</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#theprerequisites">Los Prerrequisitos</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#gettingitworking">Puesta en funcionamiento</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#lettingmorethanonepersonin">Permitir el acceso a más
de una persona</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#possibleproblems">Posibles Problemas</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#whatotherneatstuffcanido">¿Qué otra cosa
sencilla y efectiva puedo hacer?</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#moreinformation">Más información</a></li>
</ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="related" id="related">Módulos y Directivas relacionadas</a></h2>
    <table class="related"><tr><th>Módulos Relacionados</th><th>Directivas Relacionadas</th></tr><tr><td><ul><li><code class="module"><a href="../mod/mod_auth.html">mod_auth</a></code></li><li><code class="module"><a href="../mod/mod_access.html">mod_access</a></code></li></ul></td><td><ul><li><code class="directive"><a href="../mod/mod_access.html#allow">Allow</a></code></li><li><code class="directive"><a href="../mod/mod_auth.html#authgroupfile">AuthGroupFile</a></code></li><li><code class="directive"><a href="../mod/core.html#authname">AuthName</a></code></li><li><code class="directive"><a href="../mod/core.html#authtype">AuthType</a></code></li><li><code class="directive"><a href="../mod/mod_auth.html#authuserfile">AuthUserFile</a></code></li><li><code class="directive"><a href="../mod/mod_access.html#deny">Deny</a></code></li><li><code class="directive"><a href="../mod/core.html#options">Options</a></code></li><li><code class="directive"><a href="../mod/core.html#require">Require</a></code></li></ul></td></tr></table>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="introduction" id="introduction">Introducción</a></h2>
    <p>Si en su sitio web tiene información sensible o dirigida
    sólo a un pequeño grupo de personas, las técnicas
    explicadas en éste artículo le ayudarán a
    asegurarse de que las personas que ven esas páginas son las
    personas que usted quiere que las vean.</p>

    <p>Este artículo cubre la manera "estándar" de proteger
    partes de su sitio web que la mayoría de ustedes van a usar.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="theprerequisites" id="theprerequisites">Los Prerrequisitos</a></h2>
    <p>Las directivas tratadas en éste artículo necesitarán
    ir en el archivo de configuración principal de su servidor
    (típicamente en una sección del tipo
    <code class="directive"><a href="../mod/core.html#directory">&lt;Directory&gt;</a></code>),
    o en archivos de configuración por directorios (archivos 
    <code>.htaccess</code>).</p>

    <p>Si planea usar archivos <code>.htaccess</code>, necesitará
    tener una configuración en el servidor que permita poner directivas
    de autentificación en estos archivos. Esto se logra con la
    directiva <code class="directive"><a href="../mod/core.html#allowoverride">AllowOverride</a></code>,
    la cual especifica cuáles directivas, en caso de existir, pueden
    ser colocadas en los archivos de configuración por directorios.</p>

    <p>Ya que se está hablando de autentificación, necesitará
    una directiva <code class="directive"><a href="../mod/core.html#allowoverride">AllowOverride</a></code> como
    la siguiente:</p>

    <div class="example"><p><code>
      AllowOverride AuthConfig
    </code></p></div>

    <p>O, si sólo va a colocar directivas directamente en el principal
    archivo de configuración del servidor, por supuesto necesitará
    tener permiso de escritura a ese archivo.</p>

    <p>Y necesitará saber un poco acerca de la estructura de
    directorios de su servidor, con la finalidad de que sepa dónde
    están algunos archivos. Esto no debería ser muy
    difícil, y trataré de hacerlo sencillo cuando lleguemos a
    ese punto.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="gettingitworking" id="gettingitworking">Puesta en funcionamiento</a></h2>
    <p>Aquí está lo esencial en cuanto a proteger con
    contraseña un directorio de su servidor.</p>

    <p>Necesitará crear un archivo de contraseñas. Éste
    archivo debería colocarlo en algún sitio no accesible
    mediante la Web. Por ejemplo, si sus documentos son servidos desde
    <code>/usr/local/apache/htdocs</code> usted podría querer colocar
    el(los) archivo(s) de contraseñas en
    <code>/usr/local/apache/passwd</code>.</p>

    <p>Para crear un archivo de contraseñas, use la utilidad
    <code class="program"><a href="../programs/htpasswd.html">htpasswd</a></code> que viene con Apache.
    Ésta utilidad puede encontrarla en el directorio <code>bin</code>
    de cualquier sitio en que haya instalado Apache. Para crear el
    archivo, escriba:</p>

    <div class="example"><p><code>
      htpasswd -c /usr/local/apache/passwd/passwords rbowen
    </code></p></div>

    <p><code class="program"><a href="../programs/htpasswd.html">htpasswd</a></code> le pedirá la contraseña, y luego se
    la volverá a pedir para confirmarla:</p>

    <div class="example"><p><code>
      # htpasswd -c /usr/local/apache/passwd/passwords rbowen<br />
      New password: mypassword<br />
      Re-type new password: mypassword<br />
      Adding password for user rbowen
    </code></p></div>

    <p>Si <code class="program"><a href="../programs/htpasswd.html">htpasswd</a></code> no está en su ruta, por supuesto
    tendrá que escribir la ruta completa al archivo para ejecutarlo.
    En mi servidor, éste archivo está en
    <code>/usr/local/apache/bin/htpasswd</code></p>

    <p>El siguiente paso es configurar el servidor para que solicite una
    contraseña y decirle al servidor a qué usuarios se les
    permite el acceso. Puede hacer esto editando el archivo
    <code>httpd.conf</code> o usando un archivo <code>.htaccess</code>.
    Por ejemplo, si desea proteger el directorio
    <code>/usr/local/apache/htdocs/secret</code>, puede usar las siguientes
    directivas, ya sea colocándolas en el archivo
    <code>/usr/local/apache/htdocs/secret/.htaccess</code>,
    o en <code>httpd.conf</code> dentro de una sección &lt;Directory
    /usr/local/apache/apache/htdocs/secret&gt;.</p>

    <div class="example"><p><code>
      AuthType Basic<br />
      AuthName "Restricted Files"<br />
      AuthUserFile /usr/local/apache/passwd/passwords<br />
      Require user rbowen
    </code></p></div>

    <p>Vamos a examinar cada una de estas directivas por separado. La
    directiva <code class="directive"><a href="../mod/core.html#authtype">AuthType</a></code> selecciona
    el método que se va a usar para autentificar al usuario. El
    método más común es <code>Basic</code>, y éste
    método está implementado en <code class="module"><a href="../mod/mod_auth.html">mod_auth</a></code>. Es importante
    ser consciente, sin embargo, de que la autentificación Básica
    envía la contraseña desde el cliente hasta el navegador sin
    encriptar. Por lo tanto, este método no debería ser usado
    para información altamente sensible. Apache soporta otro método
    de autentificación: <code>AuthType Digest</code>. Este método
    está implementado en <code class="module"><a href="../mod/mod_auth_digest.html">mod_auth_digest</a></code> y es mucho más
    seguro. Sólo las versiones más recientes de clientes soportan
    la autentificación del tipo Digest.</p>

    <p>La directiva <code class="directive"><a href="../mod/core.html#authname">AuthName</a></code> establece
    el <dfn>Dominio (Realm)</dfn> a usar en la
    autentificación. El dominio (realm) cumple
    dos funciones importantes. Primero, el cliente frecuentemente presenta
    esta información al usuario como parte del cuatro de diálogo
    para la contraseña. Segundo, es usado por el cliente para determinar 
    qué contraseña enviar para un área autentificada dada.</p>

    <p>Así, por ejemplo, una vez que el cliente se haya autentificado en
    el área <code>"Restricted Files"</code>,
    automáticamente se volverá a tratar de usar la misma
    contraseña en cualquier área del mismo servidor que esté
    marcado con el Dominio (Realm) <code>"Restricted Files"</code>. Por lo tanto,
    puede evitar que se le pida al usuario la contraseña
    más de una vez permitiendo compartir el mismo dominio (realm)
    para múltiples áreas restringidas. Por supuesto, por
    razones de seguridad, el cliente siempre necesitará pedir de
    nuevo la contraseña cuando cambie el nombre de la
    máquina del servidor.</p>

    <p>La directiva <code class="directive"><a href="../mod/mod_auth.html#authuserfile">AuthUserFile</a></code>
    establece la ruta al archivo de contraseña que acabamos de crear
    con <code class="program"><a href="../programs/htpasswd.html">htpasswd</a></code>. Si tiene un gran número de usuarios,
    sería bastante lento buscar por medio de un archivo en texto plano
    para autentificar al usuario en cada solicitud. Apache también tiene
    la capacidad de almacenar la información del usuario en 
    archivos rápidos de bases de datos. El módulo <code class="module"><a href="../mod/mod_auth_dbm.html">mod_auth_dbm</a></code>
    proporciona la directiva <code class="directive"><a href="../mod/mod_auth_dbm.html#authdbmuserfile">AuthDBMUserFile</a></code>. Estos archivos pueden
    ser creados y manipulados con el programa
    <code class="program"><a href="../programs/dbmmanage.html">dbmmanage</a></code>. Muchos otros tipos
    de opciones de autentificación están disponibles en módulos
    de terceras partes en la <a href="http://modules.apache.org/">Base de
    datos de Módulos de Apache</a>.</p>

    <p>Finalmente, la directiva <code class="directive"><a href="../mod/core.html#require">Require</a></code>
    proporciona la parte de la autorización del proceso estableciendo
    el usuario al que se le permite acceder a ese área del servidor.
    En la próxima sección, discutimos varias formas de usar la
    directiva <code class="directive"><a href="../mod/core.html#require">Require</a></code>.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="lettingmorethanonepersonin" id="lettingmorethanonepersonin">Permitir el acceso a más
de una persona</a></h2>
    <p>Las directivas anteriores sólo permiten que una persona
    (específicamente alguien con un nombre de usuario de
    <code>rbowen</code>) acceda al directorio. En la mayoría de los
    casos, usted querrá permitir el acceso a más de una persona.
    Aquí es donde entra la directiva <code class="directive"><a href="../mod/mod_auth.html#authgroupfile">AuthGroupFile</a></code>.</p>

    <p>Si desea permitir la entrada a más de una persona, necesitará
    crear un archivo de grupo que asocie nombres de grupo con una lista
    de usuarios perteneciente a ese grupo. El formato de este archivo es muy sencillo,
    y puede crearlo con su editor favorito. El contenido del archivo
    será parecido a este:</p>

   <div class="example"><p><code>
     GroupName: rbowen dpitts sungo rshersey
   </code></p></div>

    <p>Esto es solo una lista de miembros del grupo escritos en una 
    línea separados por espacios.</p>

    <p>Para agregar un usuario a un archivo de contraseñas ya existente,
    escriba:</p>

    <div class="example"><p><code>
      htpasswd /usr/local/apache/passwd/passwords dpitts
    </code></p></div>

    <p>Obtendrá la misma respuesta que antes, pero el nuevo usuario será agregado
    al archivo existente, en lugar de crear un nuevo archivo.
    (Es la opción <code>-c</code> la que se cree un nuevo archivo
    de contraseñas).</p>

    <p>Ahora, necesita modificar su archivo <code>.htaccess</code> para que
    sea como el siguiente:</p>

    <div class="example"><p><code>
      AuthType Basic<br />
      AuthName "By Invitation Only"<br />
      AuthUserFile /usr/local/apache/passwd/passwords<br />
      AuthGroupFile /usr/local/apache/passwd/groups<br />
      Require group GroupName
    </code></p></div>

    <p>Ahora, cualquiera que esté listado en el grupo <code>GroupName</code>,
    y figure en el archivo <code>password</code>, se le permitirá
    el acceso, si escribe la contraseña correcta.</p>

    <p>Existe otra manera de permitir entrar a múltiples usuarios que
    es menos específica. En lugar de crear un archivo de grupo, puede
    usar sólo la siguiente directiva:</p>

    <div class="example"><p><code>
      Require valid-user
    </code></p></div>

    <p>Usando eso en vez de la línea <code>Require user rbowen</code>,
    le permitirá el acceso a cualquiera que esté listado en el
    archivo de contraseñas y que haya introducido correctamente su
    contraseña. Incluso puede emular el comportamiento del grupo
    aquí, sólo manteniendo un archivo de contraseña para
    cada grupo. La ventaja de esta técnica es que Apache sólo
    tiene que verificar un archivo, en vez de dos. La desventaja es que
    usted tiene que mantener un grupo de archivos de contraseña, y
    recordar referirse al correcto en la directiva <code class="directive"><a href="../mod/mod_auth.html#authuserfile">AuthUserFile</a></code>.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="possibleproblems" id="possibleproblems">Posibles Problemas</a></h2>
    <p>Por la manera en la que la autentificación básica está
    especificada, su nombre de usuario y contraseña debe ser verificado
    cada vez que se solicita un documento del servidor. Incluso si está
    recargando la misma página, y por cada imagen de la página
    (si vienen de un directorio protegido). Como se puede imaginar, esto
    retrasa un poco las cosas. El retraso es proporcional al
    tamaño del archivo de contraseña, porque se tiene que abrir ese
    archivo, y recorrer la lista de usuarios hasta que encuentre su nombre.
    Y eso se tiene que hacer cada vez que se cargue la página.</p>

    <p>Una consecuencia de esto es que hay un límite práctico
    de cuántos usuarios puede colocar en un archivo de contraseñas.
    Este límite variará dependiendo del rendimiento de su equipo
    servidor en particular, pero puede esperar observar una disminución
    una vez que inserte unos cientos de entradas, y puede que entonces considere
    un método distinto de autentificaciên.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="whatotherneatstuffcanido" id="whatotherneatstuffcanido">¿Qué otra cosa
sencilla y efectiva puedo hacer?</a></h2>
    <p>La autentificación por nombre de usuario y contraseña es
    sólo parte del cuento. Frecuentemente se desea permitir el acceso
    a los usuarios basandose en algo más que quiénes son. Algo como de
    dónde vienen.</p>

    <p>Las directivas <code class="directive"><a href="../mod/mod_access.html#allow">Allow</a></code> y
    <code class="directive"><a href="../mod/mod_access.html#deny">Deny</a></code> posibilitan permitir
    y rechazar el acceso dependiendo del nombre o la dirección de la
    máquina que solicita un documento. La directiva <code class="directive"><a href="../mod/mod_access.html#order">Order</a></code> va de la mano con estas dos, y le
    dice a Apache en qué orden aplicar los filtros.</p>

    <p>El uso de estas directivas es:</p>

    <div class="example"><p><code>
      Allow from <var>address</var>
    </code></p></div>

    <p>donde <var>address</var> es una dirección IP (o una
    dirección IP parcial) o un nombre de dominio completamente
    cualificado (o un nombre de dominio parcial); puede proporcionar
    múltiples direcciones o nombres de dominio, si lo desea.</p>

    <p>Por ejemplo, si usted tiene a alguien que manda mensajes no deseados
    a su foro, y quiere que no vuelva a acceder, podría hacer lo
    siguiente:</p>

    <div class="example"><p><code>
      Deny from 205.252.46.165
    </code></p></div>

    <p>Los visitantes que vengan de esa dirección no podrán
    ver el contenido afectado por esta directiva. Si, por el
    contrario, usted tiene un nombre de máquina pero no una
    dirección IP, también puede usarlo.</p>

    <div class="example"><p><code>
      Deny from <var>host.example.com</var>
    </code></p></div>

    <p>Y, si le gustaría bloquear el acceso de un dominio entero,
    puede especificar sólo parte de una dirección o nombre de
    dominio:</p>

    <div class="example"><p><code>
      Deny from <var>192.101.205</var><br />
      Deny from <var>cyberthugs.com</var> <var>moreidiots.com</var><br />
      Deny from ke
    </code></p></div>

    <p>Usar <code class="directive"><a href="../mod/mod_access.html#order">Order</a></code> le permitirá
    estar seguro de que efectivamente está restringiendo el acceso
    al grupo al que quiere permitir el acceso, combinando una directiva
    <code class="directive"><a href="../mod/mod_access.html#deny">Deny</a></code> y una <code class="directive"><a href="../mod/mod_access.html#allow">Allow</a></code>:</p>

    <div class="example"><p><code>
      Order deny,allow<br />
      Deny from all<br />
      Allow from <var>dev.example.com</var>
    </code></p></div>

    <p>Usando sólo la directiva <code class="directive"><a href="../mod/mod_access.html#allow">Allow</a></code> no haría lo que desea, porque
    le permitiría entrar a la gente proveniente de esa máquina, y
    adicionalmente a cualquier persona. Lo que usted quiere es dejar entrar
    <em>sólo</em> aquellos.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="moreinformation" id="moreinformation">Más información</a></h2>
    <p>También debería leer la documentación de
    <code class="module"><a href="../mod/mod_auth.html">mod_auth</a></code> y <code class="module"><a href="../mod/mod_access.html">mod_access</a></code> que
    contiene más información acerca de cómo funciona todo esto.</p>
</div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="../en/howto/auth.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/howto/auth.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="../ja/howto/auth.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="../ko/howto/auth.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a></p>
</div><div id="footer">
<p class="apache">Copyright 1995-2005 The Apache Software Foundation or its licensors, as applicable.<br />Licencia bajo los términos de la <a href="http://www.apache.org/licenses/LICENSE-2.0">Apache License, Version 2.0</a>.</p>
<p class="menu"><a href="../mod/">Módulos</a> | <a href="../mod/directives.html">Directivas</a> | <a href="../faq/">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa de este sitio web</a></p></div>
</body></html>