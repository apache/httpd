<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es" xml:lang="es"><head>
<meta content="text/html; charset=ISO-8859-1" http-equiv="Content-Type" />
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Tutorial del Servidor Apache HTTP: Ficheros .htaccess - Servidor HTTP Apache Versi&#243;n 2.4</title>
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
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs/">Documentaci&#243;n</a> &gt; <a href="../">Versi&#243;n 2.4</a> &gt; <a href="./">How-To / Tutoriales</a></div><div id="page-content"><div id="preamble"><h1>Tutorial del Servidor Apache HTTP: Ficheros .htaccess</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="../en/howto/htaccess.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/howto/htaccess.html" title="Espa&#241;ol">&nbsp;es&nbsp;</a> |
<a href="../fr/howto/htaccess.html" hreflang="fr" rel="alternate" title="Fran&#231;ais">&nbsp;fr&nbsp;</a> |
<a href="../ja/howto/htaccess.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="../ko/howto/htaccess.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="../pt-br/howto/htaccess.html" hreflang="pt-br" rel="alternate" title="Portugu&#234;s (Brasil)">&nbsp;pt-br&nbsp;</a></p>
</div>

    <p>Los ficheros <code>.htaccess</code> facilitan una forma de realizar 
    cambios en la configuraci&#243;n en contexto directorio.</p>
</div>
<div id="quickview"><a href="https://www.apache.org/foundation/contributing.html" class="badge"><img src="https://www.apache.org/images/SupportApache-small.png" alt="Support Apache!" /></a><ul id="toc"><li><img alt="" src="../images/down.gif" /> <a href="#related">Ficheros .htaccess</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#what">Qu&#233; son/C&#243;mo usarlos</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#when">Cuando (no) usar ficheros .htaccess</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#how">How directives are applied</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#auth">Ejemplo de Autenticaci&#243;n</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#ssi">Ejemplo de Server Side Includes</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#rewrite">Reglas de Rewrite en ficheros .htaccess</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#cgi">Ejemplo de CGI</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#troubleshoot">Resoluci&#243;n de problemas</a></li>
</ul><h3>Consulte tambi&#233;n</h3><ul class="seealso"><li><a href="#comments_section">Comentarios</a></li></ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="related" id="related">Ficheros .htaccess</a></h2>
    <table class="related"><tr><th>M&#243;dulos Relacionados</th><th>Directivas Relacionadas</th></tr><tr><td><ul><li><code class="module"><a href="../mod/core.html">core</a></code></li><li><code class="module"><a href="../mod/mod_authn_file.html">mod_authn_file</a></code></li><li><code class="module"><a href="../mod/mod_authz_groupfile.html">mod_authz_groupfile</a></code></li><li><code class="module"><a href="../mod/mod_cgi.html">mod_cgi</a></code></li><li><code class="module"><a href="../mod/mod_include.html">mod_include</a></code></li><li><code class="module"><a href="../mod/mod_mime.html">mod_mime</a></code></li></ul></td><td><ul><li><code class="directive"><a href="../mod/core.html#accessfilename">AccessFileName</a></code></li><li><code class="directive"><a href="../mod/core.html#allowoverride">AllowOverride</a></code></li><li><code class="directive"><a href="../mod/core.html#options">Options</a></code></li><li><code class="directive"><a href="../mod/mod_mime.html#addhandler">AddHandler</a></code></li><li><code class="directive"><a href="../mod/core.html#sethandler">SetHandler</a></code></li><li><code class="directive"><a href="../mod/mod_authn_core.html#authtype">AuthType</a></code></li><li><code class="directive"><a href="../mod/mod_authn_core.html#authname">AuthName</a></code></li><li><code class="directive"><a href="../mod/mod_authn_file.html#authuserfile">AuthUserFile</a></code></li><li><code class="directive"><a href="../mod/mod_authz_groupfile.html#authgroupfile">AuthGroupFile</a></code></li><li><code class="directive"><a href="../mod/mod_authz_core.html#require">Require</a></code></li></ul></td></tr></table>

    <div class="note">Deber&#237;a evitar usar ficheros <code>.htaccess</code> completamente si
    tiene acceso al fichero de configuraci&#243;n principal de httpd. Usar ficheros 
    <code>.htaccess</code> ralentiza su servidor Apache http. Cualquier 
    directiva que pueda incluir en un fichero <code>.htaccess</code> 
    estar&#225; mejor configurada dentro de una secci&#243;n 
    <code class="directive"><a href="../mod/core.html#directory">Directory</a></code>, tendr&#225; el mismo efecto y
    mejor rendimiento.</div>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="what" id="what">Qu&#233; son/C&#243;mo usarlos</a></h2>


    <p>Los ficheros <code>.htaccess</code> (o "ficheros de configuraci&#243;n
    distribuida") facilitan una forma de realizar cambios en la configuraci&#243;n
    en contexto directorio. Un fichero, que contiene una o m&#225;s directivas, se 
    coloca en un documento espec&#237;fico de un directorio, y estas directivas 
    aplican a ese directorio y todos sus subdirectorios.</p>

    <div class="note"><h3>Nota:</h3>
      <p>Si quiere llamar a su fichero <code>.htaccess</code> de otra manera, 
      puede cambiar el nombre del fichero usando la directiva <code class="directive"><a href="../mod/core.html#accessfilename">AccessFileName</a></code>. Por ejemplo, si usted prefiere
      llamar al fichero <code>.config</code>, entonces puede poner lo siguiente
      en el fichero de configuraci&#243;n de su servidor:</p>

      <pre class="prettyprint lang-config">AccessFileName ".config"</pre>

    </div>

    <p>Generalmente, los ficheros <code>.htaccess</code> usan la misma sint&#225;xis 
    que los <a href="../configuring.html#syntax">ficheros de la configuraci&#243;n
    principal</a>. Lo que puede utilizar en estos ficheros lo determina la 
    directiva <code class="directive"><a href="../mod/core.html#allowoverride">AllowOverride</a></code>. Esta directiva
    especifica, en categor&#237;as, qu&#233; directivas tendr&#225;n efecto si se encuentran en 
    un fichero <code>.htaccess</code>. Si se permite una directiva en un fichero 
    <code>.htaccess</code>, la documentaci&#243;n para esa directiva contendr&#225; una 
    secci&#243;n Override, especificando qu&#233; valor debe ir en 
    <code class="directive"><a href="../mod/core.html#allowoverride">AllowOverride</a></code> para que se permita esa
    directiva.</p>

    <p>Por ejemplo, si busca en la documentaci&#243;n la directiva <code class="directive"><a href="../mod/core.html#adddefaultcharset">AddDefaultCharset</a></code>, encontrar&#225; que se permite en
    ficheros <code>.htaccess</code>. (Vea la l&#237;nea de Contexto en el sumario de
    la directiva.) La l&#237;nea <a href="../mod/directive-dict.html#Context">Override</a> muestra
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

    <p>Si no est&#225; seguro de cu&#225;ndo, una directiva en concreto, se puede usar en un 
    fichero <code>.htaccess</code>, consulte la documentaci&#243;n para esa directiva, 
    y compruebe la l&#237;nea Context buscando ".htaccess".</p>
    </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="when" id="when">Cuando (no) usar ficheros .htaccess</a></h2>

    <p>Generalmente, solo deber&#237;a usar ficheros <code>.htaccess</code> cuando no
    tiene acceso al fichero principal de configuraci&#243;n del servidor. Hay, por
    ejemplo, una creencia err&#243;nea de que la autenticaci&#243;n de usuario deber&#237;a 
    hacerse siempre dentro de ficheros <code>.htaccess</code>, y, m&#225;s recientemente, otra creencia err&#243;nea de que las directivas de 
    <code class="module"><a href="../mod/mod_rewrite.html">mod_rewrite</a></code> deben ir en ficheros <code>.htaccess</code>. 
    Esto sencillamente no es el caso. Puede poner las configuraciones de 
    autenticaci&#243;n de usuario en la configuraci&#243;n principal del servidor, y esto 
    es de hecho, el m&#233;todo preferido de configurar Apache. Del mismo modo, las 
    directivas <code>mod_rewrite</code> funcionan mejor, en muchos sentidos, en 
    el fichero de configuraci&#243;n principal del servidor.</p>

    <p>Los ficheros <code>.htaccess</code> deber&#237;an usarse cuando su proveedor 
    de contenidos le permite hacer modificaciones de configuraci&#243;n 
    en contexto directorio, pero usted no tiene acceso de root en el servidor.
    En el caso de que el administrador no est&#233; dispuesto a hacer cambios 
    frecuentes en la configuraci&#243;n, puede que sea necesario permitir a usuarios
    individuales realizar estos cambios de configuraci&#243;n en ficheros 
    <code>.htaccess</code> por ellos mismos. Lo cual ocurre a menudo, por 
    ejemplo, en casos donde los ISP est&#225;n albergando m&#250;ltiples sitios web de 
    usuario en una sola m&#225;quina, y quieren que sus usuarios tengan la 
    posibilidad de modificar sus configuraciones.</p>

    <p>Aun as&#237;, generalmente, el uso de ficheros <code>.htaccess</code> deber&#237;a
    evitarse cuando sea posible. Cualquier configuraci&#243;n que considerar&#237;a poner
    en un fichero <code>.htaccess</code>, puede usarse con la misma efectividad
    en una secci&#243;n <code class="directive"><a href="../mod/core.html#directory">&lt;Directory&gt;</a></code> en el fichero de configuraci&#243;n 
    del servidor.</p>

    <p>Hay dos razones para evitar el uso de ficheros <code>.htaccess</code>.</p>

    <p>La primera es el rendimiento. Cuando <code class="directive"><a href="../mod/core.html#allowoverride">AllowOverride</a></code>
    est&#225; configurado para permitir el uso de ficheros <code>.htaccess</code>, 
    httpd buscar&#225; ficheros <code>.htaccess</code> en cada directorio. As&#237;,
    permitiendo ficheros <code>.htaccess</code> provoca una p&#233;rdida de 
    rendimiento, &#161;incluso aunque no los use! Adem&#225;s, los ficheros 
    <code>.htaccess</code> se cargan cada vez que se solicita un documento.</p>

    <p>Adem&#225;s tenga en cuenta que httpd debe buscar ficheros 
    <code>.htaccess</code> en todos los directorios de mayor jerarqu&#237;a, 
    para poder terner la lista completa de directivas que debe aplicar. (Vea
    la secci&#243;n sobre <a href="#how">C&#243;mo se aplican las directivas</a>.) As&#237;, si
    se solicita un fichero de un directorio <code>/www/htdocs/example</code>, 
    httpd debe buscar los siguientes ficheros:</p>

    <div class="example"><p><code>
      /.htaccess<br />
      /www/.htaccess<br />
      /www/htdocs/.htaccess<br />
      /www/htdocs/example/.htaccess
    </code></p></div>

    <p>De esta manera, por cada acceso a un fichero de ese directorio, hay 4 
    accesos adicionales al sistema de ficheros, incluso si ninguno de esos 
    ficheros est&#225; presente. (Tenga en cuenta que este caso solo se dar&#237;a si los 
    ficheros <code>.htaccess</code> est&#225;n activados en <code>/</code>, que 
    generalmente no es el caso.).</p>

    <p>En el caso de las directivas <code class="directive"><a href="../mod/mod_rewrite.html#rewriterule">RewriteRule</a></code>, en el contexto de
    <code>.htaccess</code> estas expresiones regulares deben recompilarse con 
    cada solicitud a ese directorio, cuando en el contexto de configuraci&#243;n del
    servidor solo se compilan una vez y se cachean. Adicionalmente, las reglas
    en s&#237; mismas son m&#225;s complicadas, puesto que uno debe sortear las 
    restricciones que vienen acompa&#241;adas del contexto directorio y 
    <code>mod_rewrite</code>. Consulte la  <a href="../rewrite/intro.html#htaccess">Gu&#237;a de Rewrite</a> para un mayor 
    detalle sobre este tema.</p>

    <p>La segunda consideraci&#243;n es de seguridad. Estar&#225; permitiendo que usuarios
    modifiquen la configuraci&#243;n del servidor, lo cual puede dar lugar a cambios sobre los que usted no tendr&#225; ning&#250;n control. Medite profundamente si debe 
    dar a sus usuarios ese privilegio. Adem&#225;s tenga en cuenta que dar a los usuarios menos privilegios de los que necesitan dar&#225; lugar a m&#225;s peticiones 
    de soporte. Aseg&#250;rese de que le indica a sus usuarios claramente el nivel de privilegios que les est&#225; dando. Especificando exactamente c&#243;mo ha 
    configurado <code class="directive"><a href="../mod/core.html#allowoverride">AllowOverride</a></code>, e inv&#237;teles 
    a revisar la documentaci&#243;n relacionada, lo cual le ahorrar&#225; 
    bastantes confusiones m&#225;s adelante.</p>

    <p>Tenga en cuenta que esto es equivalente por completo a poner un fichero
    <code>.htaccess</code> en un directorio <code>/www/htdocs/example</code> 
    con una directiva, y poner la misma directiva en una secci&#243;n 
    Directory <code>&lt;Directory "/www/htdocs/example"&gt;</code> en su 
    configuraci&#243;n principal del servidor:</p>

    <p>Fichero <code>.htaccess</code> en <code>/www/htdocs/example</code>:</p>

    <div class="example"><h3>Contenido de fichero .htaccess en
    <code>/www/htdocs/example</code></h3><pre class="prettyprint lang-config">AddType text/example ".exm"</pre>
</div>

    <div class="example"><h3>Secci&#243;n de su fichero <code>httpd.conf</code></h3><pre class="prettyprint lang-config">&lt;Directory "/www/htdocs/example"&gt;
    AddType text/example ".exm"
&lt;/Directory&gt;</pre>
</div>

    <p>Aun as&#237;, poniendo &#233;sta en el fichero de configuraci&#243;n dar&#225; como resultado
    una menor p&#233;rdida de rendimiento, y como la configuraci&#243;n se carga una vez
    cuando el httpd arranca, en lugar de cada vez que se solicita un fichero.</p>

    <p>El uso de ficheros <code>.htaccess</code> puede desactivarse por completo
    configurando la directiva <code class="directive"><a href="../mod/core.html#allowoverride">AllowOverride</a></code>
    a <code>none</code>:</p>

    <pre class="prettyprint lang-config">AllowOverride None</pre>

</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="how" id="how">How directives are applied</a></h2>

    <p>Las directivas de configuraci&#243;n que se encuentran en el fichero
    <code>.htaccess</code> se aplican al directorio en el que el fichero
    <code>.htaccess</code> se encuentra, y a todos sus subdirectorios. Sin 
    embargo, es importante recordar que puede haber otros ficheros 
    <code>.htaccess</code> en directorios previos. Las directivas se aplican en
    el orden en el que se encuentran. Por lo tanto, un fichero 
    <code>.htaccess</code> puede sobrescribir directivas que se encuentran
    en ficheros <code>.htaccess</code> que se encuentran en directorios previos 
    del &#225;rbol de directorios. Y estos, en cambio, pueden haber sobrescrito 
    directivas que se encontraban m&#225;s arriba, o en el fichero principal de 
    configuraci&#243;n del servidor mismo.</p>

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
    <code>/www/htdocs/example1/example2</code>, la ejecuci&#243;n de CGI execution no
    est&#225; permitida, porque solo se ha definido <code>Options Includes</code>, 
    que sobrescribe completamente una configuraci&#243;n previa que se pudiera haber
    definido.</p>

    <h3><a name="merge" id="merge">Incorporando el .htaccess en los ficheros de 
    configuraci&#243;n principal</a></h3>

    <p>Como se ha comentado en la documentaci&#243;n en las <a href="../sections.html">Secciones de Configuraci&#243;n</a>, los ficheros
    <code>.htaccess</code> pueden sobrescribir las secciones <code class="directive"><a href="../mod/core.html#directory">&lt;Directory&gt;</a></code> por el directorio
    correspondiente, pero se sobrescribir&#225;n por otros tipos de secciones de 
    configuraci&#243;n de los ficheros de configuraci&#243;n principal. Este hecho se
    puede usar para forzar ciertas configuraciones, incluso en presencia
    de una configuraci&#243;n laxa de 
    <code class="directive"><a href="../mod/core.html#allowoverride">AllowOverride</a></code>. Por ejemplo, para 
    prevenir la ejecuci&#243;n de un script mientras se permite cualquier otra cosa 
    en <code>.htaccess</code> puede usar:</p>

    <pre class="prettyprint lang-config">&lt;Directory "/www/htdocs"&gt;
    AllowOverride All
&lt;/Directory&gt;

&lt;Location "/"&gt;
    Options +IncludesNoExec -ExecCGI
&lt;/Location&gt;</pre>


    <div class="note">Este ejemplo asume que su <code class="directive"><a href="../mod/core.html#documentroot">DocumentRoot</a></code> es <code>/www/htdocs</code>.</div>


</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="auth" id="auth">Ejemplo de Autenticaci&#243;n</a></h2>

    <p>Si salt&#243; directamente a esta parte del documento para averiguar como 
    hacer la autenticaci&#243;n, es important que tenga en cuenta una cosa. Hay una 
    creencia err&#243;nea de que necesita usar ficheros <code>.htaccess</code> para
    configurar autenticaci&#243;n con contrase&#241;a. Este no es el caso. Colocar las
    directivas de autenticaci&#243;n en una secci&#243;n 
    <code class="directive"><a href="../mod/core.html#directory">&lt;Directory&gt;</a></code>, en su fichero
    de configuraci&#243;n principal, es el m&#233;todo recomendado para configurar esto, 
    y los ficheros <code>.htaccess</code> deber&#237;an usarse solamente si no tiene 
    acceso al fichero de configuraci&#243;n principal del servidor. Vea <a href="#when">m&#225;s arriba</a> una explicaci&#243;n de cuando deber&#237;a y cuando no
    deber&#237;a usar ficheros <code>.htaccess</code>.</p>

    <p>Dicho esto, si todav&#237;a cree que debe usar el fichero
    <code>.htaccess</code>, podr&#225; ver que una configuraci&#243;n como la que sigue 
    podr&#237;a servirle.</p>

    <p>Contenido del fichero <code>.htaccess</code>:</p>

    <pre class="prettyprint lang-config">AuthType Basic
AuthName "Password Required"
AuthUserFile "/www/passwords/password.file"
AuthGroupFile "/www/passwords/group.file"
Require group admins</pre>


    <p>Tenga en cuenta que <code>AllowOverride AuthConfig</code> debe estar
    habilitado para que estas directivas tengan alg&#250;n efecto.</p>

    <p>Por favor vea el <a href="auth.html">tutorial de autenticaci&#243;n</a> para
    una explicaci&#243;n m&#225;s completa de la autenticaci&#243;n y la autorizaci&#243;n.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="ssi" id="ssi">Ejemplo de Server Side Includes</a></h2>

    <p>Otro uso com&#250;n de ficheros <code>.htaccess</code> es activar Server Side 
    Includes para un directorio en particular. Esto puede hacerse 
    con las siguientes directivas de configuraci&#243;n, colocadas en un fichero
    <code>.htaccess</code> y el directorio deseado:</p>

    <pre class="prettyprint lang-config">Options +Includes
AddType text/html "shtml"
AddHandler server-parsed shtml</pre>


    <p>Tenga en cuenta que <code>AllowOverride Options</code> y 
    <code>AllowOverride FileInfo</code> deben estar activadas para que estas 
    directivas tengan efecto.</p>

    <p>Por favor vea el <a href="ssi.html">tutorial de SSI</a> para una
    explicaci&#243;n m&#225;s completa de server-side includes.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="rewrite" id="rewrite">Reglas de Rewrite en ficheros .htaccess</a></h2>
    <p>Cuando use <code class="directive"><a href="../mod/mod_rewrite.html#rewriterule">RewriteRule</a></code> en
    ficheros <code>.htaccess</code>, tenga en cuenta que el contexto 
    directorio cambia las cosas un poco. En concreto, las reglas son 
    relativas al directorio actual, en lugar de serlo de la petici&#243;n de URI 
    solicitada originalmente.
    Considere los siguientes ejemplos:</p>

<pre class="prettyprint lang-config"># En httpd.conf
RewriteRule "^/images/(.+)\.jpg" "/images/$1.png"

# En .htaccess en el directorio ra&#237;z
RewriteRule "^images/(.+)\.jpg" "images/$1.png"

# En .htaccess en images/
RewriteRule "^(.+)\.jpg" "$1.png"</pre>


    <p>En un <code>.htaccess</code> en cualquier directorio del DocumentRoot, la 
    barra ("/") inicial se elimina del valor facilitado a <code class="directive"><a href="../mod/mod_rewrite.html#rewriterule">RewriteRule</a></code>, y en el subdirectorio 
    <code>images</code>, se elimina <code>/images/</code> tambi&#233;n de este valor. 
    As&#237;, su expresi&#243;n regular necesita omitir tambi&#233;n esa parte.</p>

    <p>Consulte la <a href="../rewrite/">documentaci&#243;n de mod_rewrite</a> para 
    m&#225;s detalles al usar <code>mod_rewrite</code>.</p>

</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="cgi" id="cgi">Ejemplo de CGI</a></h2>

    <p>Finalmente, puede que quiera usar un fichero <code>.htaccess</code> para
    permitir la ejecuci&#243;n de programas CGI en un directorio en particular. Esto
    se puede implementar con la siguiente configuraci&#243;n:</p>

    <pre class="prettyprint lang-config">Options +ExecCGI
AddHandler cgi-script "cgi" "pl"</pre>


    <p>Alternativamente, si quiere considerar como programas CGI todos los 
    ficheros de un directorio concreto, esto se puede conseguir con la siguiente 
    configuraci&#243;n:</p>

    <pre class="prettyprint lang-config">Options +ExecCGI
SetHandler cgi-script</pre>


    <p>Tenga en cuenta que <code>AllowOverride Options</code> y 
    <code>AllowOverride FileInfo</code> deben estar ambas activadas para que 
    estas directivas tengan efecto.</p>

    <p>Por favor vea el <a href="cgi.html">tutorial CGI</a> para mayor detalle
    sobre programaci&#243;n y configuraci&#243;n de CGI.</p>

</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="troubleshoot" id="troubleshoot">Resoluci&#243;n de problemas</a></h2>

    <p>Cuando pone directivas en un fichero <code>.htaccess</code> y no obtiene 
    el efecto deseado hay una serie de cosas que pueden haber ido mal.</p>

    <p>El problema m&#225;s com&#250;n es que <code class="directive"><a href="../mod/core.html#allowoverride">AllowOverride
    </a></code> no est&#225; configurada para que sus directivas puedan surtir
    efecto. Aseg&#250;rese de que no tiene <code>AllowOverride None</code> 
    configurado para el directorio en cuesti&#243;n. Una buena forma de probar esto
    es poner "basura" en su fichero <code>.htaccess</code> y recargar la p&#225;gina. 
    Si no se genera un error en el servidor, casi seguro que tiene configurado 
    <code>AllowOverride None</code>.</p>

    <p>Si, por otro lado, obtiene errores de servidor al intentar acceder a 
    documentos, compruebe el log de errores de httpd. Seguramente le indiquen 
    que la directiva en uso en su fichero <code>.htaccess</code> no est&#225; 
    permitida.</p>

    <div class="example"><p><code>
    [Fri Sep 17 18:43:16 2010] [alert] [client 192.168.200.51] /var/www/html/.htaccess: DirectoryIndex not allowed here
    </code></p></div>

    <p>Esto indicar&#225; que o bien ha usado una directiva que no se permite nunca 
    en ficheros <code>.htaccess</code>, o que simplementa no tiene
    <code class="directive"><a href="../mod/core.html#allowoverride">AllowOverride</a></code> configurado
    a un nivel suficiente para la directiva que ha usado. Consulte la
    documentaci&#243;n para esa directiva en particular para determinar cual es el 
    caso.</p>

    <p>Alternativamente, puede que le indique que hay un error de sintaxis en 
    el uso de la propia directiva.</p>

    <div class="example"><p><code>
    [Sat Aug 09 16:22:34 2008] [alert] [client 192.168.200.51] /var/www/html/.htaccess: RewriteCond: bad flag delimiters
    </code></p></div>

    <p>En este caso, el mensaje de error deber&#237;a ser espec&#237;fico para el error de
    sintaxis concreto que ha cometido.</p>

</div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="../en/howto/htaccess.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/howto/htaccess.html" title="Espa&#241;ol">&nbsp;es&nbsp;</a> |
<a href="../fr/howto/htaccess.html" hreflang="fr" rel="alternate" title="Fran&#231;ais">&nbsp;fr&nbsp;</a> |
<a href="../ja/howto/htaccess.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="../ko/howto/htaccess.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="../pt-br/howto/htaccess.html" hreflang="pt-br" rel="alternate" title="Portugu&#234;s (Brasil)">&nbsp;pt-br&nbsp;</a></p>
</div><div class="top"><a href="#page-header"><img src="../images/up.gif" alt="top" /></a></div><div class="section"><h2><a id="comments_section" name="comments_section">Comentarios</a></h2><div class="warning"><strong>Notice:</strong><br />This is not a Q&amp;A section. Comments placed here should be pointed towards suggestions on improving the documentation or server, and may be removed by our moderators if they are either implemented or considered invalid/off-topic. Questions on how to manage the Apache HTTP Server should be directed at either our IRC channel, #httpd, on Libera.chat, or sent to our <a href="https://httpd.apache.org/lists.html">mailing lists</a>.</div>
<script type="text/javascript"><!--//--><![CDATA[//><!--
var comments_shortname = 'httpd';
var comments_identifier = 'http://httpd.apache.org/docs/2.4/howto/htaccess.html';
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