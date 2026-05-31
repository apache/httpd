<!DOCTYPE html SYSTEM "about:legacy-compat">
<html lang="es"><head><META http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<meta content="width=device-width, initial-scale=1" name="viewport">
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Compilar e Instalar - Servidor HTTP Apache Versi&oacute;n 2.4</title>
<link href="./style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet">
<link href="./style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size">
<link href="./style/css/manual-print.css" rel="stylesheet" media="print" type="text/css"><link rel="stylesheet" type="text/css" href="./style/css/prettify.css">
<script src="./style/scripts/prettify.min.js">
</script>

<link href="./images/favicon.png" rel="shortcut icon"></head>
<body id="manual-page"><div id="page-header">
<p class="menu"><a href="./mod/">M&oacute;dulos</a> | <a href="./mod/quickreference.html">Directivas</a> | <a href="https://cwiki.apache.org/confluence/display/httpd/FAQ">Preguntas Frecuentes</a> | <a href="./glossary.html">Glosario</a> | <a href="./sitemap.html">Mapa del sitio web</a> | <a href="https://bz.apache.org/bugzilla/enter_bug.cgi?product=Apache%20httpd-2">Reportar un error</a></p>
<p class="apache">Versi&oacute;n 2.4 del Servidor HTTP Apache</p>
<img alt="" src="./images/feather.png"></div>
<div class="up"><a href="./"><img title="<-" alt="<-" src="./images/left.gif"></a></div>
<div id="path">
<a href="https://www.apache.org/">Apache</a> &gt; <a href="https://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="https://httpd.apache.org/docs/">Documentaci&oacute;n</a> &gt; <a href="./">Versi&oacute;n 2.4</a></div><div id="page-content"><div id="preamble"><h1>Compilar e Instalar</h1>
<button aria-label="Toggle language list" class="lang-toggle"><svg xmlns="http://www.w3.org/2000/svg" stroke-width="2" stroke="currentColor" fill="none" viewBox="0 0 24 24" height="16" width="16"><circle r="10" cy="12" cx="12"/><line y2="12" x2="22" y1="12" x1="2"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></button>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="./de/install.html" hreflang="de" rel="alternate" title="Deutsch">&nbsp;de&nbsp;</a> |
<a href="./en/install.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/install.html" title="Espa&ntilde;ol">&nbsp;es&nbsp;</a> |
<a href="./fr/install.html" hreflang="fr" rel="alternate" title="Fran&ccedil;ais">&nbsp;fr&nbsp;</a> |
<a href="./ja/install.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/install.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./pt-br/install.html" hreflang="pt-br" rel="alternate" title="Portugu&ecirc;s (Brasil)">&nbsp;pt-br&nbsp;</a> |
<a href="./tr/install.html" hreflang="tr" rel="alternate" title="T&uuml;rk&ccedil;e">&nbsp;tr&nbsp;</a></p>
</div>
<div class="outofdate">Esta traducci&oacute;n podr&iacute;a estar
            obsoleta. Consulte la versi&oacute;n en ingl&eacute;s de la
            documentaci&oacute;n para comprobar si se han producido cambios
            recientemente.</div>


    <p>&Eacute;ste documento hace referencia a la compilaci&oacute;n y la instalaci&oacute;n del Apache 
    HTTP Server s&oacute;lo para los sistemas Unix y  tipo Unix. Para la compilaci&oacute;n e instalaci&oacute;n en Windows  ir a  <a href="platform/windows.html">Usando Apache HTTP Server con Microsoft
    Windows</a> y <a href="platform/win_compiling.html">Compilando Apache para Microsoft Windows</a>.
    Para otras plataformas visite la documentaci&oacute;n sobre <a href="platform/">plataformas</a>.</p>

    <p>Apache httpd usa <code>libtool</code> y <code>autoconf</code>
    para crear un entorno de compilaci&oacute;n que se parece a muchos otros proyectos de c&oacute;digo abierto</p>

    <p>Si est&aacute; actualizando desde una versi&oacute;n menor a la siguiente (por
    ejemplo, 2.4.8 a 2.4.9), pasa a la secci&oacute;n de  <a href="#upgrading">actualizaci&oacute;n</a>.</p>

</div>
<div id="quickview"><ul id="toc"><li><img alt="" src="./images/down.gif"> <a href="#overview">Descripci&oacute;n general para los impacientes</a></li>
<li><img alt="" src="./images/down.gif"> <a href="#requirements">Requisitos</a></li>
<li><img alt="" src="./images/down.gif"> <a href="#download">Descargar</a></li>
<li><img alt="" src="./images/down.gif"> <a href="#extract">Descomprimir</a></li>
<li><img alt="" src="./images/down.gif"> <a href="#configure">Configuraci&oacute;n de la estructura de
directorios</a></li>
<li><img alt="" src="./images/down.gif"> <a href="#compile">Build</a></li>
<li><img alt="" src="./images/down.gif"> <a href="#install">Instalar</a></li>
<li><img alt="" src="./images/down.gif"> <a href="#customize">Personalizar APACHE</a></li>
<li><img alt="" src="./images/down.gif"> <a href="#test">Comprobar que la instalaci&oacute;n
funciona</a></li>
<li><img alt="" src="./images/down.gif"> <a href="#upgrading">Actualizar una instalaci&oacute;n previa</a></li>
<li><img alt="" src="./images/down.gif"> <a href="#thirdp">Paquetes de terceros</a></li>
</ul><h3>Consulte tambi&eacute;n</h3><ul class="seealso"><li><a href="programs/configure.html">Configuraci&oacute;n del &aacute;rbol de las fuentes de c&oacute;digo</a></li><li><a href="invoking.html">Arrancando Apache httpd</a></li><li><a href="stopping.html">Parada y Reinicio</a></li></ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section">
<h2 id="overview">Descripci&oacute;n general para los impacientes <a title="Enlace permanente" href="#overview" class="permalink">&para;</a></h2>

    <table>
      
      <tr>
        <td><a href="#download">Descarga</a></td>

        <td>Descarga la &uacute;ltima versi&oacute;n 
          desde <a href="http://httpd.apache.org/download.cgi#apache24">
          http://httpd.apache.org/download.cgi</a>
        </td>
      </tr>

      <tr>
        <td><a href="#extract">Extraer</a></td>

        <td><code>$ gzip -d httpd-<em>NN</em>.tar.gz<br>
         $ tar xvf httpd-<em>NN</em>.tar<br>
         $ cd httpd-<em>NN</em></code></td>
      </tr>

      <tr>
        <td><a href="#configure">Configura</a></td>

        <td><code>$ ./configure --prefix=<em>PREFIX</em></code>
        </td>
      </tr>

      <tr>
        <td><a href="#compile">Compila</a></td>

        <td><code>$ make</code> </td>
      </tr>

      <tr>
        <td><a href="#install">Instala</a></td>

        <td><code>$ make install</code> </td>
      </tr>

      <tr>
        <td><a href="#customize">Personalizalo</a></td>

        <td><code>$ vi <em>PREFIX</em>/conf/httpd.conf</code> </td>
      </tr>

      <tr>
        <td><a href="#test">Prueba</a></td>

        <td><code>$ <em>PREFIX</em>/bin/apachectl -k start</code>
        </td>
      </tr>
    </table>

    <p><em>NN</em> hay que reemplazarlo por el n&uacute;mero de la versi&oacute;n menor, y <em>PREFIX</em> hay que reemplazarlo por la ruta en la que se va a instalar Apache. Si no especifica ning&uacute;n valor en <em>PREFIX</em>, el valor por defecto que se toma es /usr/local/apache2.</p>

    <p>Cada parte del proceso de configuraci&oacute;n e instalaci&oacute;n se describe detalladamente m&aacute;s abajo, empezando por los requisitos para compilar e instalar Apache.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section">
<h2 id="requirements">Requisitos <a title="Enlace permanente" href="#requirements" class="permalink">&para;</a></h2>

    <p>Estos son los requisitos necesarios para compilar Apache:</p>

    <dl>
      <dt>APR y APR-Util</dt>
      <dd>Aseg&uacute;rate de que tiene instalado ya en su sistema APR y APR-Util. Si no es as&iacute;, o no quiere utilizar la versi&oacute;n que le proporciona el sistema, puede descargar la &uacute;ltima versi&oacute;n de ambos APR y APR-Util de
      <a href="http://apr.apache.org/">Apache APR</a>, descomprimelo en
       <code>/httpd_source_tree_root/srclib/apr</code> y /httpd_source_tree_root<code>/srclib/apr-util</code>
      (cerci&oacute;rate de que no existen directorios con n&uacute;meros de versiones; por ejemplo,
      la distribuci&oacute;n de APR debe estar en /httpd_source_tree_root/srclib/apr/) y usa el comando
      <code>./configure</code> <code>--con-las-opciones-incluidas-en-apr</code>.
      En algunas plataformas deber&aacute;s instalar la parte correspondiente a los paquetes 
      <code>-dev</code> para permitir que httpd se genere contra la instalaci&oacute;n de la copia de APR y APR-Util.</dd>

      <dt>Librer&iacute;a Compatible de expresiones regulares de Perl (PCRE)</dt>
      <dd>Esta librer&iacute;a es requerida, pero ya no incluido con httpd.
      Descarga el c&oacute;digo fuente de <a href="http://www.pcre.org/">http://www.pcre.org</a>,
      o instala un Port o un  Paquete. Si la distrubuci&oacute;n de su sistema no puede encontrar el escript pcre-config instalado por PCRE, seleccione utilizando el par&aacute;metro<code>--with-pcre</code>.En algunas plataformas,
      deber&aacute;s instalar la correspondiente versi&oacute;n <code>-dev</code>
      del paquete para permitir a httpd que se genere contra la instalaci&oacute;n de la copia del PCRE que se ha instalado.</dd>

      <dt>Espacio en disco</dt> 
      <dd>Compruebe que tiene disponibles al
      menos 50 MB de espacio libre en disco. Despu&eacute;s de la
      instalaci&oacute;n, Apache ocupa aproximadamente 10 MB. No
      obstante, la necesidad real de espacio en disco var&iacute;a
      considerablemente en funci&oacute;n de las opciones de
      configuraci&oacute;n que elija y de los m&oacute;dulos externos que
      use, y como no del tama&ntilde;o de la p&aacute;gina web</dd>

      <dt>Systema de compilaci&oacute;n ANSI-C</dt>
      <dd>Compruebe que tiene instalado un compilador de ANSI-C. Se recomienda el <a href="http://gcc.gnu.org/">Compilador GNU C
      (GCC)</a> de la <a href="http://www.gnu.org/">Free Software
      Foundation (FSF)</a> es el recomendado. Si no tiene instalado el GCC, entonces compruebe que
      el compilador que va a utilizar cumple con los est&aacute;ndares
      ANSI. Adem&aacute;s, su <code>PATH</code> debe contener la
      ubicaci&oacute;n donde de encuentran las herramientas b&aacute;sicas
      para compilar tales como <code>make</code>.</dd>

      <dt>Ajuste exacto del reloj del sistema</dt> 
      <dd>Los elementos
      del protocolo HTTP est&aacute;n expresados seg&uacute;n la hora del
      d&iacute;a. Por eso, si quiere puede investigar como instalar alguna
      utilidad para sincronizar la hora de su sistema. Para esto,
      normalmente, se usan los programas <code>ntpdate</code> o
      <code>xntpd</code>, que est&aacute;n basados en el protocolo
      "Network Time Protocol" (NTP). Consulte el<a href="http://www.ntp.org">sitio web de NTP
      </a> para obtener m&aacute;s informaci&oacute;n sobre NTP y los
      servidores p&uacute;blicos de tiempo.</dd>

      <dt><a href="http://www.perl.org/">Perl 5</a>[OPCIONAL]</dt>
      <dd>Para algunos de los scripts de soporte como<code class="program"><a href="./programs/apxs.html">apxs</a></code> o <code class="program"><a href="./programs/dbmmanage.html">dbmmanage</a></code> (que est&aacute;n
      escritos en Perl) es necesario el int&eacute;rprete de Perl 5 (las
      versiones 5.003 o posteriores son suficientes). Si el escript
      <code class="program"><a href="./programs/configure.html">configure</a></code> no se encuentra, no podr&aacute; usar los
	  escripts correspondientes que lo necesiten. Pero por supuesto
	  podr&aacute;s compilar y usar Apache httpd.</dd>
    </dl>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section">
<h2 id="download">Descargar <a title="Enlace permanente" href="#download" class="permalink">&para;</a></h2>

    <p>Puede descargar Apache desde <a href="http://httpd.apache.org/download.cgi">la secci&oacute;n de
    descargas del sitio web de Apache</a> el cual tiene varios
    mirrors. Para la mayor&iacute;a de los usuarios de Apache que tienen
    sistemas tipo Unix, se recomienda que se descarguen y compilen el
    c&oacute;digo fuente. El proceso de compilaci&oacute;n (descrito
    m&aacute;s abajo) es f&aacute;cil, y permite adaptar el servidor
    Apache a sus necesidades. Adem&aacute;s, las versiones de
    disponibles en archivos binarios no est&aacute;n siempre actualizadas
    con las &uacute;ltimas modificaciones en el c&oacute;digo fuente. Si se
    descarga un binario, siga las instrucciones contenidas en el
    archivo <code>INSTALL.bindist</code> incluido en la
    distribuci&oacute;n</p>

    <p>Despu&eacute;s de la descarga, es importante que verifique que el
    archivo descargado del servidor HTTP Apache est&aacute; completo y
    sin modificaciones.  Esto puede hacerlo comparando el archivo
    descargado (.tgz) con su firma PGP. Instrucciones detalladas de
    c&oacute;mo hacer esto est&aacute;n disponibles en <a href="http://httpd.apache.org/download.cgi#verify"> la
    secci&oacute;n de descargas</a> junto con un ejemplo de c&oacute;mo <a href="http://httpd.apache.org/dev/verification.html">usar
    PGP</a>.</p>

</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section">
<h2 id="extract">Descomprimir <a title="Enlace permanente" href="#extract" class="permalink">&para;</a></h2>

    <p>Extraer el c&oacute;digo fuente del archivo .tgz del Servidor Apache HTTP que acabada 
      de descargar es muy f&aacute;cil. Ejecute los siguientes comandos:</p>

<div class="example"><p><code>
$ gzip -d httpd-<em>NN</em>.tar.gz<br>
$ tar xvf httpd-<em>NN</em>.tar
</code></p></div>

    <p>Estos comandos crear&aacute;n un nuevo directorio dentro del
    directorio en el que se encuentra y que contendr&aacute; el
    c&oacute;digo fuente de distribuci&oacute;n. Debe cambiarse a ese
    directorio con <code>cd</code> para proceder a compilar el
    servidor Apache.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section">
<h2 id="configure">Configuraci&oacute;n de la estructura de
directorios <a title="Enlace permanente" href="#configure" class="permalink">&para;</a></h2>

    <p>El siguiente paso es configurar la estructura de directorios
    para su plataforma y sus necesidades personales. Esto se hace
    usando el script <code class="program"><a href="./programs/configure.html">configure</a></code> incluido en el directorio
    ra&iacute;z de la distribuci&oacute;n que acaba de descargar. (Los
    desarrolladores que se descarguen la versi&oacute;n del CVS de la
    estructura de directorios necesitar&aacute;n tener instalados
    <code>autoconf</code> y <code>libtool</code>, y necesitar&aacute;n
    ejecutar <code>buildconf</code> antes de continuar con los
    siguientes pasos. Esto no es preciso para las versiones
    oficiales.)</p>

    <p>Para configurar la estructura de directorios a partir del
    c&oacute;digo fuente usando las opciones por defecto, solo tiene que
    ejecutar <code>./configure</code>.Para cambiar las opciones por
    defecto, <code class="program"><a href="./programs/configure.html">configure</a></code> acepta una serie de variables y
    opciones por la l&iacute;nea de comandos.</p>

    <p>La opci&oacute;n m&aacute;s importante es <code>--prefix</code>
    que es el directorio en el que Apache va a ser instalado despu&eacute;s,
    porque Apache tiene que ser configurado para el directorio que se
    especifique para que funcione correctamente.  Es posible lograr un
    mayor control del lugar donde se van a instalar los ficheros de
    Apache con otras <a href="programs/configure.html#installationdirectories">opciones de
    configuraci&oacute;n</a>.</p>

    <p>Llegados a este punto, puede especificar que <a href="programs/configure.html#optionalfeatures">caracter&iacute;sticas
    o funcionalidades</a> quiere incluir en Apache activando o
    desactivando <a href="mod/">modules</a>.Apache vine con una amplia
    selecci&oacute;n de m&oacute;dulos incluidos por defecto. Que ser&aacute;n compilados como .
    <a href="dso.html">Objetos Compartidos (DSOs)</a> Que pueden ser activados
    o desactivados en tiempo de ejecuci&oacute;n.
    Tambi&eacute;n puede elegir por compilar m&oacute;dulos de forma est&aacute;tica usando las opciones
    <code>--enable-<var>module</var>=static</code>.</p>



    <p>Se pueden activar otros m&oacute;dulos usando la opci&oacute;n 
    <code>--enable-<var>module</var></code>, where
    <var>module</var> es el nombre del m&oacute;dulo sin el
    <code>mod_</code> y convirtiendo los guiones bajos que tenga en
    guiones normales.  Del mismo modo, puede desactivar los m&oacute;dulos con la
    opci&oacute;n <code>--disable-<var>module</var></code>. Tenga cuidado al utilizar esta opci&oacute;n, ya que
    <code class="program"><a href="./programs/configure.html">configure</a></code> no le avisar&aacute; si el m&oacute;dulo que especifica no existe;
    simplemente ignorar&aacute; esa opci&oacute;n.</p>

    <p>Adem&aacute;s, a veces es necesario pasarle al script
    <code class="program"><a href="./programs/configure.html">configure</a></code> informaci&oacute;n adicional sobre donde esta
    su compilador, librer&iacute;as o ficheros de cabecera.  Esto se puede
    hacer, tanto pasando variables de entorno, como pasandole opciones
    a <code class="program"><a href="./programs/configure.html">configure</a></code>.  Para m&aacute;s informaci&oacute;n, consulte el manual de
    <code class="program"><a href="./programs/configure.html">configure</a></code>. O use <code class="program"><a href="./programs/configure.html">configure</a></code> con la 
    opci&oacute;n <code>--help</code>.</p>

     <p>Para que se haga una idea sobre las posibilidades que tiene,
    aqu&iacute; tiene un ejemplo t&iacute;pico que configura Apache para
    la ruta <code>/sw/pkg/apache</code> con un compilador y unos flags
    determinados, y adem&aacute;s, con dos m&oacute;dulos adicionales
    <code class="module"><a href="./mod/mod_ldap.html">mod_ldap</a></code> y <code class="module"><a href="./mod/mod_ldap.html">mod_ldap</a></code> para
    cargarlos despu&eacute;s a trav&eacute;s del mecanismo DSO:</p>

<div class="example"><p><code>
      $ CC="pgcc" CFLAGS="-O2" \<br>
       ./configure --prefix=/sw/pkg/apache \<br>
       --enable-ldap=shared \<br>
       --enable-lua=shared
</code></p></div>

    <p>Cuando se ejecuta <code class="program"><a href="./programs/configure.html">configure</a></code> se comprueban que
    caracter&iacute;sticas o funcionalidades est&aacute;n disponibles en
    su sistema y se crean los Makefiles que ser&aacute;n usados a continuaci&oacute;n
    para compilar el servidor. Esto tardar&aacute; algunos minutos.</p>

    <p>Los detalles de todas las opciones de <code class="program"><a href="./programs/configure.html">configure</a></code> est&aacute;n disponibles
    en el manual de <code class="program"><a href="./programs/configure.html">configure</a></code> .</p>
  </div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section">
<h2 id="compile">Build <a title="Enlace permanente" href="#compile" class="permalink">&para;</a></h2>

    <p>Ahora puede compilar las diferentes partes que forman Apache
    simplemente ejecutando el siguiente comando:</p>

<div class="example"><p><code>$ make</code></p></div>

    <p>Por favor sea paciente llegado a este punto, ya que una configuraci&oacute;n b&aacute;sica lleva unos minutos
      para su compilaci&oacute;n, y el tiempo puede variar mucho dependiendo de su hardware 
      y del n&uacute;mero de m&oacute;dulos que haya habilitado para la compilaci&oacute;n.(Se recomienda a&ntilde;adir al make el
      par&aacute;metro -j3 como m&iacute;nimo para que vaya m&aacute;s r&aacute;pido)</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section">
<h2 id="install">Instalar <a title="Enlace permanente" href="#install" class="permalink">&para;</a></h2>

    <p>Ahora es el momento de instalar el paquete en el diretorio
    elegido en <em>PREFIX</em> (consulte m&aacute;s arriba la opci&oacute;n
    <code>--prefix</code>) ejecutando:</p>

<div class="example"><p><code>$ make install</code></p></div>

    <p>Este paso requiere de forma t&iacute;pica privilegios de root, ya que 
      el directorio de <em>PREFIX</em> es normalmente un directorio con 
      restricciones de permisos escritura.</p>

    <p>Si lo que esta es s&oacute;lo actualizando, la instalaci&oacute;n no sobreescribir&aacute; los
      archivos de configuraci&oacute;n.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section">
<h2 id="customize">Personalizar APACHE <a title="Enlace permanente" href="#customize" class="permalink">&para;</a></h2>

    <p>Tras la instalaci&oacute;n puede personalizarla, editando los 
    <a href="configuring.html">archivos de configuracion </a> en el directorio de
    <code><em>PREFIX</em>/conf/</code>.</p>

<div class="example"><p><code>$ vi <em>PREFIX</em>/conf/httpd.conf</code></p></div>

    <p>&Eacute;chele un vistazo al Manual de Apache que est&aacute; en
    <code><em>PREFIX</em>/docs/manual/</code> o consulta <a href="http://httpd.apache.org/docs/2.4/">http://httpd.apache.org/docs/2.4/</a> para la versi&oacute;n m&aacute;s
    reciente de este manual y su completa
    referencia de las <a href="mod/directives.html">directivas de configuracion</a> disponibles.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section">
<h2 id="test">Comprobar que la instalaci&oacute;n
funciona <a title="Enlace permanente" href="#test" class="permalink">&para;</a></h2>

    <p>Ahora puedes  <a href="invoking.html">ejecutar</a> tu Apache
    HTTP server ejecutando directamente:</p>

<div class="example"><p><code>$ <em>PREFIX</em>/bin/apachectl -k start</code></p></div>

    <p>Ahora debe poder acceder a su primer documento
    bajo la URL <code>http://localhost/</code>. La p&aacute;gina o documento que ve se encuentra en
    <code class="directive"><a href="./mod/core.html#documentroot">DocumentRoot</a></code>,
    que por norma general casi siempre ser&aacute; <code><em>PREFIX</em>/htdocs/</code>.
    Si quiere  <a href="stopping.html">parar</a> el servidor, puede hacerlo ejecutando:</p>

<div class="example"><p><code>$ <em>PREFIX</em>/bin/apachectl -k stop</code></p></div>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section">
<h2 id="upgrading">Actualizar una instalaci&oacute;n previa <a title="Enlace permanente" href="#upgrading" class="permalink">&para;</a></h2>

    <p>El primer paso para actualizar una instalaci&oacute;n anterior es
    leer las especificaciones de la versi&oacute;n y el fichero
    <code>CHANGES</code> en la distribuci&oacute;n de c&oacute;digo fuente
    que ha descargado para encontrar los cambios que puedan afectar a
    su instalaci&oacute;n actual. Cuando el cambio sea entre versiones
    mayores(por ejemplo, de la 2.0 a 2.2 o de la 2.2 a la 2.4),
    entonces es m&aacute;s probable que haya diferencias importantes en
    la compilaci&oacute;n y en la ejecuci&oacute;n que necesitar&aacute;n
    ajustes manuales. Todos los m&oacute;dulos necesitar&aacute;n
    tambi&eacute;n ser actualizados para adaptarse a los cambios en el
    interfaz de programaci&oacute;n (API) de m&oacute;dulos.</p>

    <p>Actualizando de una versi&oacute;n menor a la siguiente
      (por ejemplo, de la 2.2.55 a la  2.2.57) es mas f&aacute;cil. El prodeso de realizar el <code>make install</code>
    no sobreescribir&aacute; ninguno de tus documentos existentes,archivos
    log, o archivos de configuraci&oacute;n. De hecho, los desarrolladores est&aacute;n haciendo los esfuerzos
    necerarios para evitar cambios que generen incompatibilidades en las opciones de
    <code class="program"><a href="./programs/configure.html">configure</a></code>, la configuraci&oacute;n al ser ejecutado, o el m&oacute;dulo de la API
    entre versiones menores. En la mayor parte de los casos debe poder usar un
    comando <code class="program"><a href="./programs/configure.html">configure</a></code> id&eacute;ntico, un fichero de
    configuraci&oacute;n id&eacute;ntico, y todos sus m&oacute;dulos deben
    seguir funcionando.</p>

    <p>Para actualizar entre versiones menores, empecemos encontrando el archivo de configuraci&oacute;n
    <code>config.nice</code> el directorio <code>de instalaci&oacute;n</code> del servidor
    o en el directorio raiz del c&oacute;digo fuente de tu antigua instalaci&oacute;n. Este archivo contendr&aacute;
    los par&aacute;metros exactos para pasarle al 
    <code class="program"><a href="./programs/configure.html">configure</a></code> que usaste anteriormente para configurar tus directorios.
    Entonces, para actualizar su instalaci&oacute;n de una versi&oacute;n a la
    siguinete, solo tiene que copiar el archivo
    <code>config.nice</code> a la estructura de directorios del
    c&oacute;digo fuente de la nueva versi&oacute;n, editarlo, hacer
    cualquier cambio que desee, y ejecutarlo :</p>

    <div class="example"><p><code>
    $ ./config.nice<br>
    $ make<br>
    $ make install<br>
    $ <em>PREFIX</em>/bin/apachectl -k graceful-stop<br>
    $ <em>PREFIX</em>/bin/apachectl -k start<br>
    </code></p></div>

    <div class="warning">Tenga en cuenta que antes de poner una nueva
    versi&oacute;n de Apache en producci&oacute;n, debe siempre probarla
    antes en un entorno de pruebas. Por ejemplo, puede instalar y ejecutar la
    nueva versi&oacute;n junto con la antigua usando un
    <code>--prefix</code> diferente y un puerto diferente (modificando
    la directiva <code class="directive"><a href="./mod/mpm_common.html#listen">Listen</a></code>)
    para comprobar que no existe ninguna incompatibilidad antes de
    hacer la actualizaci&oacute;n definitiva.</div>

    <p>Puede pasarle argumentos adicionales a <code>config.nice</code>,
    que se agregar&aacute;n a susopciones originales de <code class="program"><a href="./programs/configure.html">configure</a></code>:</p>

    <div class="example"><p><code>
    $ ./config.nice --prefix=/home/test/apache --with-port=90
    </code></p></div>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section">
<h2 id="thirdp">Paquetes de terceros <a title="Enlace permanente" href="#thirdp" class="permalink">&para;</a></h2>

    <p>Un gran n&uacute;mero de terceros proporcionan sus propias 
    distribuciones empaquetadas del Apache HTTP Server para su
    instalaci&oacute;n en plataformas espec&iacute;ficas. Esto incluye las distintas
    distribuciones de Linux, varios paquetes de Windows de terceros,
    Mac OS X, Solaris, y muchos m&aacute;s.</p>

    <p>Nuestra licencia de software no s&oacute;lo permite, sino que anima, 
    este tipo de redistribuci&oacute;n. Sin embargo, se da lugar a una situaci&oacute;n
    en la que el dise&ntilde;o y la configuraci&oacute;n de los valores predeterminados
    de la instalaci&oacute;n del servidor pueden diferir de lo que se indica
    en la documentaci&oacute;n. Mientras lamentablemente, esta situaci&oacute;n no es probable que cambie a corto plazo.</p>

    <p>Una <a href="https://cwiki.apache.org/confluence/display/httpd/DistrosDefaultLayout">descripci&oacute;n
    de estas distribuciones de terceros </a> est&aacute; siendo actualizada en el servidor de la WIKI de HTTP
    Server, y deber&iacute;a reflejar el actual estado de &eacute;stas distribuciones de terceros. 
    Sin embargo, tendr&aacute; que familiarizarse con los procedimientos de gesti&oacute;n
    e instalaci&oacute;n de paquetes de su plataforma (SO) en particular.</p>

</div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="./de/install.html" hreflang="de" rel="alternate" title="Deutsch">&nbsp;de&nbsp;</a> |
<a href="./en/install.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/install.html" title="Espa&ntilde;ol">&nbsp;es&nbsp;</a> |
<a href="./fr/install.html" hreflang="fr" rel="alternate" title="Fran&ccedil;ais">&nbsp;fr&nbsp;</a> |
<a href="./ja/install.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/install.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./pt-br/install.html" hreflang="pt-br" rel="alternate" title="Portugu&ecirc;s (Brasil)">&nbsp;pt-br&nbsp;</a> |
<a href="./tr/install.html" hreflang="tr" rel="alternate" title="T&uuml;rk&ccedil;e">&nbsp;tr&nbsp;</a></p>
</div><div id="footer">
<p class="apache">Copyright 2026 The Apache Software Foundation.<br>Licencia bajo los t&eacute;rminos de la <a href="https://www.apache.org/licenses/LICENSE-2.0">Apache License, Version 2.0</a>.</p>
<p class="menu"><a href="./mod/">M&oacute;dulos</a> | <a href="./mod/quickreference.html">Directivas</a> | <a href="https://cwiki.apache.org/confluence/display/httpd/FAQ">Preguntas Frecuentes</a> | <a href="./glossary.html">Glosario</a> | <a href="./sitemap.html">Mapa del sitio web</a> | <a href="https://bz.apache.org/bugzilla/enter_bug.cgi?product=Apache%20httpd-2">Reportar un error</a></p></div><script><!--//--><![CDATA[//><!--
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