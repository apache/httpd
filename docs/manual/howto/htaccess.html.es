<!DOCTYPE html SYSTEM "about:legacy-compat">
<html lang="es"><head><META http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<meta content="width=device-width, initial-scale=1" name="viewport">
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Tutorial del Servidor Apache HTTP: Ficheros .htaccess - Servidor HTTP Apache Versi&oacute;n 2.4</title>
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
<a href="https://www.apache.org/">Apache</a> &gt; <a href="https://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="https://httpd.apache.org/docs/">Documentaci&oacute;n</a> &gt; <a href="../">Versi&oacute;n 2.4</a> &gt; <a href="./">How-To / Tutoriales</a></div><div id="page-content"><div id="preamble"><h1>Tutorial del Servidor Apache HTTP: Ficheros .htaccess</h1>
<button aria-label="Toggle language list" class="lang-toggle"><svg xmlns="http://www.w3.org/2000/svg" stroke-width="2" stroke="currentColor" fill="none" viewBox="0 0 24 24" height="16" width="16"><circle r="10" cy="12" cx="12"/><line y2="12" x2="22" y1="12" x1="2"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></button>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="../en/howto/htaccess.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/howto/htaccess.html" title="Espa&ntilde;ol">&nbsp;es&nbsp;</a> |
<a href="../fr/howto/htaccess.html" hreflang="fr" rel="alternate" title="Fran&ccedil;ais">&nbsp;fr&nbsp;</a> |
<a href="../ja/howto/htaccess.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="../ko/howto/htaccess.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="../pt-br/howto/htaccess.html" hreflang="pt-br" rel="alternate" title="Portugu&ecirc;s (Brasil)">&nbsp;pt-br&nbsp;</a></p>
</div>
<div class="outofdate">Esta traducci&oacute;n podr&iacute;a estar
            obsoleta. Consulte la versi&oacute;n en ingl&eacute;s de la
            documentaci&oacute;n para comprobar si se han producido cambios
            recientemente.</div>

    <p>Los ficheros <code>.htaccess</code> facilitan una forma de realizar 
    cambios en la configuraci&oacute;n en contexto directorio.</p>
</div>
<div id="quickview"><ul id="toc"><li><img alt="" src="../images/down.gif"> <a href="#related">Ficheros .htaccess</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#what">Qu&eacute; son/C&oacute;mo usarlos</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#when">Cuando (no) usar ficheros .htaccess</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#how">How directives are applied</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#auth">Ejemplo de Autenticaci&oacute;n</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#ssi">Ejemplo de Server Side Includes</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#rewrite">Reglas de Rewrite en ficheros .htaccess</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#cgi">Ejemplo de CGI</a></li>
<li><img alt="" src="../images/down.gif"> <a href="#troubleshoot">Resoluci&oacute;n de problemas</a></li>
</ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="related">Ficheros .htaccess <a title="Enlace permanente" href="#related" class="permalink">&para;</a></h2>
    <table class="related"><tr><th>M&oacute;dulos Relacionados</th><th>Directivas Relacionadas</th></tr><tr><td><ul><li><code class="module"><a href="../mod/core.html">core</a></code></li><li><code class="module"><a href="../mod/mod_authn_file.html">mod_authn_file</a></code></li><li><code class="module"><a href="../mod/mod_authz_groupfile.html">mod_authz_groupfile</a></code></li><li><code class="module"><a href="../mod/mod_cgi.html">mod_cgi</a></code></li><li><code class="module"><a href="../mod/mod_include.html">mod_include</a></code></li><li><code class="module"><a href="../mod/mod_mime.html">mod_mime</a></code></li></ul></td><td><ul><li><code class="directive"><a href="../mod/core.html#accessfilename">AccessFileName</a></code></li><li><code class="directive"><a href="../mod/core.html#allowoverride">AllowOverride</a></code></li><li><code class="directive"><a href="../mod/core.html#options">Options</a></code></li><li><code class="directive"><a href="../mod/mod_mime.html#addhandler">AddHandler</a></code></li><li><code class="directive"><a href="../mod/core.html#sethandler">SetHandler</a></code></li><li><code class="directive"><a href="../mod/mod_authn_core.html#authtype">AuthType</a></code></li><li><code class="directive"><a href="../mod/mod_authn_core.html#authname">AuthName</a></code></li><li><code class="directive"><a href="../mod/mod_authn_file.html#authuserfile">AuthUserFile</a></code></li><li><code class="directive"><a href="../mod/mod_authz_groupfile.html#authgroupfile">AuthGroupFile</a></code></li><li><code class="directive"><a href="../mod/mod_authz_core.html#require">Require</a></code></li></ul></td></tr></table>

    <div class="note">Deber&iacute;a evitar usar ficheros <code>.htaccess</code> completamente si
    tiene acceso al fichero de configuraci&oacute;n principal de httpd. Usar ficheros 
    <code>.htaccess</code> ralentiza su servidor Apache http. Cualquier 
    directiva que pueda incluir en un fichero <code>.htaccess</code> 
    estar&aacute; mejor configurada dentro de una secci&oacute;n 
    <code class="directive"><a href="../mod/core.html#directory">Directory</a></code>, tendr&aacute; el mismo efecto y
    mejor rendimiento.</div>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="what">Qu&eacute; son/C&oacute;mo usarlos <a title="Enlace permanente" href="#what" class="permalink">&para;</a></h2>


    <p>Los ficheros <code>.htaccess</code> (o "ficheros de configuraci&oacute;n
    distribuida") facilitan una forma de realizar cambios en la configuraci&oacute;n
    en contexto directorio. Un fichero, que contiene una o m&aacute;s directivas, se 
    coloca en un documento espec&iacute;fico de un directorio, y estas directivas 
    aplican a ese directorio y todos sus subdirectorios.</p>

    <div class="note"><h3>Nota:</h3>
      <p>Si quiere llamar a su fichero <code>.htaccess</code> de otra manera, 
      puede cambiar el nombre del fichero usando la directiva <code class="directive"><a href="../mod/core.html#accessfilename">AccessFileName</a></code>. Por ejemplo, si usted prefiere
      llamar al fichero <code>.config</code>, entonces puede poner lo siguiente
      en el fichero de configuraci&oacute;n de su servidor:</p>

      <pre class="prettyprint lang-config">AccessFileName ".config"</pre>

    </div>

    <p>Generalmente, los ficheros <code>.htaccess</code> usan la misma sint&aacute;xis 
    que los <a href="../configuring.html#syntax">ficheros de la configuraci&oacute;n
    principal</a>. Lo que puede utilizar en estos ficheros lo determina la 
    directiva <code class="directive"><a href="../mod/core.html#allowoverride">AllowOverride</a></code>. Esta directiva
    especifica, en categor&iacute;as, qu&eacute; directivas tendr&aacute;n efecto si se encuentran en 
    un fichero <code>.htaccess</code>. Si se permite una directiva en un fichero 
    <code>.htaccess</code>, la documentaci&oacute;n para esa directiva contendr&aacute; una 
    secci&oacute;n Override, especificando qu&eacute; valor debe ir en 
    <code class="directive"><a href="../mod/core.html#allowoverride">AllowOverride</a></code> para que se permita esa
    directiva.</p>

    <p>Por ejemplo, si busca en la documentaci&oacute;n la directiva <code class="directive"><a href="../mod/core.html#adddefaultcharset">AddDefaultCharset</a></code>, encontrar&aacute; que se permite en
    ficheros <code>.htaccess</code>. (Vea la l&iacute;nea de Contexto en el sumario de
    la directiva.) La l&iacute;nea <a href="../mod/directive-dict.html#Context">Override</a> muestra
    <code>FileInfo</code>. De este modo, debe tener al menos
    <code>AllowOverride FileInfo</code> para que esta directiva se aplique en
    ficheros <code>.htaccess</code>.</p>

    <div class="example"><h3>Ejemplo:</h3><table>
        <tr>
          <td><a href="../mod/directive-dict.html#Context">Context:</a></td>
          <td>server config, virtual host, directory, .htaccess</td>
        </tr>

        <tr>
          <td><a href="../mod/directive-dict.html#Override">Override:</a></td>
          <td>FileInfo</td>
        </tr>
      </table></div>

    <p>Si no est&aacute; seguro de cu&aacute;ndo, una directiva en concreto, se puede usar en un 
    fichero <code>.htaccess</code>, consulte la documentaci&oacute;n para esa directiva, 
    y compruebe la l&iacute;nea Context buscando ".htaccess".</p>
    </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="when">Cuando (no) usar ficheros .htaccess <a title="Enlace permanente" href="#when" class="permalink">&para;</a></h2>

    <p>Generalmente, solo deber&iacute;a usar ficheros <code>.htaccess</code> cuando no
    tiene acceso al fichero principal de configuraci&oacute;n del servidor. Hay, por
    ejemplo, una creencia err&oacute;nea de que la autenticaci&oacute;n de usuario deber&iacute;a 
    hacerse siempre dentro de ficheros <code>.htaccess</code>, y, m&aacute;s recientemente, otra creencia err&oacute;nea de que las directivas de 
    <code class="module"><a href="../mod/mod_rewrite.html">mod_rewrite</a></code> deben ir en ficheros <code>.htaccess</code>. 
    Esto sencillamente no es el caso. Puede poner las configuraciones de 
    autenticaci&oacute;n de usuario en la configuraci&oacute;n principal del servidor, y esto 
    es de hecho, el m&eacute;todo preferido de configurar Apache. Del mismo modo, las 
    directivas <code>mod_rewrite</code> funcionan mejor, en muchos sentidos, en 
    el fichero de configuraci&oacute;n principal del servidor.</p>

    <p>Los ficheros <code>.htaccess</code> deber&iacute;an usarse cuando su proveedor 
    de contenidos le permite hacer modificaciones de configuraci&oacute;n 
    en contexto directorio, pero usted no tiene acceso de root en el servidor.
    En el caso de que el administrador no est&eacute; dispuesto a hacer cambios 
    frecuentes en la configuraci&oacute;n, puede que sea necesario permitir a usuarios
    individuales realizar estos cambios de configuraci&oacute;n en ficheros 
    <code>.htaccess</code> por ellos mismos. Lo cual ocurre a menudo, por 
    ejemplo, en casos donde los ISP est&aacute;n albergando m&uacute;ltiples sitios web de 
    usuario en una sola m&aacute;quina, y quieren que sus usuarios tengan la 
    posibilidad de modificar sus configuraciones.</p>

    <p>Aun as&iacute;, generalmente, el uso de ficheros <code>.htaccess</code> deber&iacute;a
    evitarse cuando sea posible. Cualquier configuraci&oacute;n que considerar&iacute;a poner
    en un fichero <code>.htaccess</code>, puede usarse con la misma efectividad
    en una secci&oacute;n <code class="directive"><a href="../mod/core.html#directory">&lt;Directory&gt;</a></code> en el fichero de configuraci&oacute;n 
    del servidor.</p>

    <p>Hay dos razones para evitar el uso de ficheros <code>.htaccess</code>.</p>

    <p>La primera es el rendimiento. Cuando <code class="directive"><a href="../mod/core.html#allowoverride">AllowOverride</a></code>
    est&aacute; configurado para permitir el uso de ficheros <code>.htaccess</code>, 
    httpd buscar&aacute; ficheros <code>.htaccess</code> en cada directorio. As&iacute;,
    permitiendo ficheros <code>.htaccess</code> provoca una p&eacute;rdida de 
    rendimiento, &iexcl;incluso aunque no los use! Adem&aacute;s, los ficheros 
    <code>.htaccess</code> se cargan cada vez que se solicita un documento.</p>

    <p>Adem&aacute;s tenga en cuenta que httpd debe buscar ficheros 
    <code>.htaccess</code> en todos los directorios de mayor jerarqu&iacute;a, 
    para poder terner la lista completa de directivas que debe aplicar. (Vea
    la secci&oacute;n sobre <a href="#how">C&oacute;mo se aplican las directivas</a>.) As&iacute;, si
    se solicita un fichero de un directorio <code>/www/htdocs/example</code>, 
    httpd debe buscar los siguientes ficheros:</p>

    <div class="example"><p><code>
      /.htaccess<br>
      /www/.htaccess<br>
      /www/htdocs/.htaccess<br>
      /www/htdocs/example/.htaccess
    </code></p></div>

    <p>De esta manera, por cada acceso a un fichero de ese directorio, hay 4 
    accesos adicionales al sistema de ficheros, incluso si ninguno de esos 
    ficheros est&aacute; presente. (Tenga en cuenta que este caso solo se dar&iacute;a si los 
    ficheros <code>.htaccess</code> est&aacute;n activados en <code>/</code>, que 
    generalmente no es el caso.).</p>

    <p>En el caso de las directivas <code class="directive"><a href="../mod/mod_rewrite.html#rewriterule">RewriteRule</a></code>, en el contexto de
    <code>.htaccess</code> estas expresiones regulares deben recompilarse con 
    cada solicitud a ese directorio, cuando en el contexto de configuraci&oacute;n del
    servidor solo se compilan una vez y se cachean. Adicionalmente, las reglas
    en s&iacute; mismas son m&aacute;s complicadas, puesto que uno debe sortear las 
    restricciones que vienen acompa&ntilde;adas del contexto directorio y 
    <code>mod_rewrite</code>. Consulte la  <a href="../rewrite/intro.html#htaccess">Gu&iacute;a de Rewrite</a> para un mayor 
    detalle sobre este tema.</p>

    <p>La segunda consideraci&oacute;n es de seguridad. Estar&aacute; permitiendo que usuarios
    modifiquen la configuraci&oacute;n del servidor, lo cual puede dar lugar a cambios sobre los que usted no tendr&aacute; ning&uacute;n control. Medite profundamente si debe 
    dar a sus usuarios ese privilegio. Adem&aacute;s tenga en cuenta que dar a los usuarios menos privilegios de los que necesitan dar&aacute; lugar a m&aacute;s peticiones 
    de soporte. Aseg&uacute;rese de que le indica a sus usuarios claramente el nivel de privilegios que les est&aacute; dando. Especificando exactamente c&oacute;mo ha 
    configurado <code class="directive"><a href="../mod/core.html#allowoverride">AllowOverride</a></code>, e inv&iacute;teles 
    a revisar la documentaci&oacute;n relacionada, lo cual le ahorrar&aacute; 
    bastantes confusiones m&aacute;s adelante.</p>

    <p>Tenga en cuenta que esto es equivalente por completo a poner un fichero
    <code>.htaccess</code> en un directorio <code>/www/htdocs/example</code> 
    con una directiva, y poner la misma directiva en una secci&oacute;n 
    Directory <code>&lt;Directory "/www/htdocs/example"&gt;</code> en su 
    configuraci&oacute;n principal del servidor:</p>

    <p>Fichero <code>.htaccess</code> en <code>/www/htdocs/example</code>:</p>

    <div class="example"><h3>Contenido de fichero .htaccess en
    <code>/www/htdocs/example</code></h3><pre class="prettyprint lang-config">AddType text/example ".exm"</pre>
</div>

    <div class="example"><h3>Secci&oacute;n de su fichero <code>httpd.conf</code></h3><pre class="prettyprint lang-config">&lt;Directory "/www/htdocs/example"&gt;
    AddType text/example ".exm"
&lt;/Directory&gt;</pre>
</div>

    <p>Aun as&iacute;, poniendo &eacute;sta en el fichero de configuraci&oacute;n dar&aacute; como resultado
    una menor p&eacute;rdida de rendimiento, y como la configuraci&oacute;n se carga una vez
    cuando el httpd arranca, en lugar de cada vez que se solicita un fichero.</p>

    <p>El uso de ficheros <code>.htaccess</code> puede desactivarse por completo
    configurando la directiva <code class="directive"><a href="../mod/core.html#allowoverride">AllowOverride</a></code>
    a <code>none</code>:</p>

    <pre class="prettyprint lang-config">AllowOverride None</pre>

</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="how">How directives are applied <a title="Enlace permanente" href="#how" class="permalink">&para;</a></h2>

    <p>Las directivas de configuraci&oacute;n que se encuentran en el fichero
    <code>.htaccess</code> se aplican al directorio en el que el fichero
    <code>.htaccess</code> se encuentra, y a todos sus subdirectorios. Sin 
    embargo, es importante recordar que puede haber otros ficheros 
    <code>.htaccess</code> en directorios previos. Las directivas se aplican en
    el orden en el que se encuentran. Por lo tanto, un fichero 
    <code>.htaccess</code> puede sobrescribir directivas que se encuentran
    en ficheros <code>.htaccess</code> que se encuentran en directorios previos 
    del &aacute;rbol de directorios. Y estos, en cambio, pueden haber sobrescrito 
    directivas que se encontraban m&aacute;s arriba, o en el fichero principal de 
    configuraci&oacute;n del servidor mismo.</p>

    <p>Ejemplo:</p>

    <p>En el directorio <code>/www/htdocs/example1</code> tenemos un fichero
    <code>.htaccess</code> que contiene lo siguiente:</p>

    <pre class="prettyprint lang-config">Options +ExecCGI</pre>


    <p>(Nota: debe terner "<code>AllowOverride Options</code>" configurado para
    permitir el uso de la directiva "<code class="directive"><a href="../mod/core.html#options">Options</a></code>" en ficheros 
    <code>.htaccess</code> files.)</p>

    <p>En el directorio <code>/www/htdocs/example1/example2</code> tenemos un
    fichero <code>.htaccess</code> que contiene:</p>

    <pre class="prettyprint lang-config">Options Includes</pre>


    <p>Por este segundo fichero <code>.htaccess</code>, en el directorio
    <code>/www/htdocs/example1/example2</code>, la ejecuci&oacute;n de CGI execution no
    est&aacute; permitida, porque solo se ha definido <code>Options Includes</code>, 
    que sobrescribe completamente una configuraci&oacute;n previa que se pudiera haber
    definido.</p>

    <h3 id="merge">Incorporando el .htaccess en los ficheros de 
    configuraci&oacute;n principal</h3>

    <p>Como se ha comentado en la documentaci&oacute;n en las <a href="../sections.html">Secciones de Configuraci&oacute;n</a>, los ficheros
    <code>.htaccess</code> pueden sobrescribir las secciones <code class="directive"><a href="../mod/core.html#directory">&lt;Directory&gt;</a></code> por el directorio
    correspondiente, pero se sobrescribir&aacute;n por otros tipos de secciones de 
    configuraci&oacute;n de los ficheros de configuraci&oacute;n principal. Este hecho se
    puede usar para forzar ciertas configuraciones, incluso en presencia
    de una configuraci&oacute;n laxa de 
    <code class="directive"><a href="../mod/core.html#allowoverride">AllowOverride</a></code>. Por ejemplo, para 
    prevenir la ejecuci&oacute;n de un script mientras se permite cualquier otra cosa 
    en <code>.htaccess</code> puede usar:</p>

    <pre class="prettyprint lang-config">&lt;Directory "/www/htdocs"&gt;
    AllowOverride All
&lt;/Directory&gt;

&lt;Location "/"&gt;
    Options +IncludesNoExec -ExecCGI
&lt;/Location&gt;</pre>


    <div class="note">Este ejemplo asume que su <code class="directive"><a href="../mod/core.html#documentroot">DocumentRoot</a></code> es <code>/www/htdocs</code>.</div>


</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="auth">Ejemplo de Autenticaci&oacute;n <a title="Enlace permanente" href="#auth" class="permalink">&para;</a></h2>

    <p>Si salt&oacute; directamente a esta parte del documento para averiguar como 
    hacer la autenticaci&oacute;n, es important que tenga en cuenta una cosa. Hay una 
    creencia err&oacute;nea de que necesita usar ficheros <code>.htaccess</code> para
    configurar autenticaci&oacute;n con contrase&ntilde;a. Este no es el caso. Colocar las
    directivas de autenticaci&oacute;n en una secci&oacute;n 
    <code class="directive"><a href="../mod/core.html#directory">&lt;Directory&gt;</a></code>, en su fichero
    de configuraci&oacute;n principal, es el m&eacute;todo recomendado para configurar esto, 
    y los ficheros <code>.htaccess</code> deber&iacute;an usarse solamente si no tiene 
    acceso al fichero de configuraci&oacute;n principal del servidor. Vea <a href="#when">m&aacute;s arriba</a> una explicaci&oacute;n de cuando deber&iacute;a y cuando no
    deber&iacute;a usar ficheros <code>.htaccess</code>.</p>

    <p>Dicho esto, si todav&iacute;a cree que debe usar el fichero
    <code>.htaccess</code>, podr&aacute; ver que una configuraci&oacute;n como la que sigue 
    podr&iacute;a servirle.</p>

    <p>Contenido del fichero <code>.htaccess</code>:</p>

    <pre class="prettyprint lang-config">AuthType Basic
AuthName "Password Required"
AuthUserFile "/www/passwords/password.file"
AuthGroupFile "/www/passwords/group.file"
Require group admins</pre>


    <p>Tenga en cuenta que <code>AllowOverride AuthConfig</code> debe estar
    habilitado para que estas directivas tengan alg&uacute;n efecto.</p>

    <p>Por favor vea el <a href="auth.html">tutorial de autenticaci&oacute;n</a> para
    una explicaci&oacute;n m&aacute;s completa de la autenticaci&oacute;n y la autorizaci&oacute;n.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="ssi">Ejemplo de Server Side Includes <a title="Enlace permanente" href="#ssi" class="permalink">&para;</a></h2>

    <p>Otro uso com&uacute;n de ficheros <code>.htaccess</code> es activar Server Side 
    Includes para un directorio en particular. Esto puede hacerse 
    con las siguientes directivas de configuraci&oacute;n, colocadas en un fichero
    <code>.htaccess</code> y el directorio deseado:</p>

    <pre class="prettyprint lang-config">Options +Includes
AddType text/html "shtml"
AddHandler server-parsed shtml</pre>


    <p>Tenga en cuenta que <code>AllowOverride Options</code> y 
    <code>AllowOverride FileInfo</code> deben estar activadas para que estas 
    directivas tengan efecto.</p>

    <p>Por favor vea el <a href="ssi.html">tutorial de SSI</a> para una
    explicaci&oacute;n m&aacute;s completa de server-side includes.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="rewrite">Reglas de Rewrite en ficheros .htaccess <a title="Enlace permanente" href="#rewrite" class="permalink">&para;</a></h2>
    <p>Cuando use <code class="directive"><a href="../mod/mod_rewrite.html#rewriterule">RewriteRule</a></code> en
    ficheros <code>.htaccess</code>, tenga en cuenta que el contexto 
    directorio cambia las cosas un poco. En concreto, las reglas son 
    relativas al directorio actual, en lugar de serlo de la petici&oacute;n de URI 
    solicitada originalmente.
    Considere los siguientes ejemplos:</p>

<pre class="prettyprint lang-config"># En httpd.conf
RewriteRule "^/images/(.+)\.jpg" "/images/$1.png"

# En .htaccess en el directorio ra&iacute;z
RewriteRule "^images/(.+)\.jpg" "images/$1.png"

# En .htaccess en images/
RewriteRule "^(.+)\.jpg" "$1.png"</pre>


    <p>En un <code>.htaccess</code> en cualquier directorio del DocumentRoot, la 
    barra ("/") inicial se elimina del valor facilitado a <code class="directive"><a href="../mod/mod_rewrite.html#rewriterule">RewriteRule</a></code>, y en el subdirectorio 
    <code>images</code>, se elimina <code>/images/</code> tambi&eacute;n de este valor. 
    As&iacute;, su expresi&oacute;n regular necesita omitir tambi&eacute;n esa parte.</p>

    <p>Consulte la <a href="../rewrite/">documentaci&oacute;n de mod_rewrite</a> para 
    m&aacute;s detalles al usar <code>mod_rewrite</code>.</p>

</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="cgi">Ejemplo de CGI <a title="Enlace permanente" href="#cgi" class="permalink">&para;</a></h2>

    <p>Finalmente, puede que quiera usar un fichero <code>.htaccess</code> para
    permitir la ejecuci&oacute;n de programas CGI en un directorio en particular. Esto
    se puede implementar con la siguiente configuraci&oacute;n:</p>

    <pre class="prettyprint lang-config">Options +ExecCGI
AddHandler cgi-script "cgi" "pl"</pre>


    <p>Alternativamente, si quiere considerar como programas CGI todos los 
    ficheros de un directorio concreto, esto se puede conseguir con la siguiente 
    configuraci&oacute;n:</p>

    <pre class="prettyprint lang-config">Options +ExecCGI
SetHandler cgi-script</pre>


    <p>Tenga en cuenta que <code>AllowOverride Options</code> y 
    <code>AllowOverride FileInfo</code> deben estar ambas activadas para que 
    estas directivas tengan efecto.</p>

    <p>Por favor vea el <a href="cgi.html">tutorial CGI</a> para mayor detalle
    sobre programaci&oacute;n y configuraci&oacute;n de CGI.</p>

</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif"></a></div>
<div class="section">
<h2 id="troubleshoot">Resoluci&oacute;n de problemas <a title="Enlace permanente" href="#troubleshoot" class="permalink">&para;</a></h2>

    <p>Cuando pone directivas en un fichero <code>.htaccess</code> y no obtiene 
    el efecto deseado hay una serie de cosas que pueden haber ido mal.</p>

    <p>El problema m&aacute;s com&uacute;n es que <code class="directive"><a href="../mod/core.html#allowoverride">AllowOverride
    </a></code> no est&aacute; configurada para que sus directivas puedan surtir
    efecto. Aseg&uacute;rese de que no tiene <code>AllowOverride None</code> 
    configurado para el directorio en cuesti&oacute;n. Una buena forma de probar esto
    es poner "basura" en su fichero <code>.htaccess</code> y recargar la p&aacute;gina. 
    Si no se genera un error en el servidor, casi seguro que tiene configurado 
    <code>AllowOverride None</code>.</p>

    <p>Si, por otro lado, obtiene errores de servidor al intentar acceder a 
    documentos, compruebe el log de errores de httpd. Seguramente le indiquen 
    que la directiva en uso en su fichero <code>.htaccess</code> no est&aacute; 
    permitida.</p>

    <div class="example"><p><code>
    [Fri Sep 17 18:43:16 2010] [alert] [client 192.168.200.51] /var/www/html/.htaccess: DirectoryIndex not allowed here
    </code></p></div>

    <p>Esto indicar&aacute; que o bien ha usado una directiva que no se permite nunca 
    en ficheros <code>.htaccess</code>, o que simplementa no tiene
    <code class="directive"><a href="../mod/core.html#allowoverride">AllowOverride</a></code> configurado
    a un nivel suficiente para la directiva que ha usado. Consulte la
    documentaci&oacute;n para esa directiva en particular para determinar cual es el 
    caso.</p>

    <p>Alternativamente, puede que le indique que hay un error de sintaxis en 
    el uso de la propia directiva.</p>

    <div class="example"><p><code>
    [Sat Aug 09 16:22:34 2008] [alert] [client 192.168.200.51] /var/www/html/.htaccess: RewriteCond: bad flag delimiters
    </code></p></div>

    <p>En este caso, el mensaje de error deber&iacute;a ser espec&iacute;fico para el error de
    sintaxis concreto que ha cometido.</p>

</div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="../en/howto/htaccess.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/howto/htaccess.html" title="Espa&ntilde;ol">&nbsp;es&nbsp;</a> |
<a href="../fr/howto/htaccess.html" hreflang="fr" rel="alternate" title="Fran&ccedil;ais">&nbsp;fr&nbsp;</a> |
<a href="../ja/howto/htaccess.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="../ko/howto/htaccess.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="../pt-br/howto/htaccess.html" hreflang="pt-br" rel="alternate" title="Portugu&ecirc;s (Brasil)">&nbsp;pt-br&nbsp;</a></p>
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