<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es" xml:lang="es"><head><!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Compilación e Instalación - Servidor HTTP Apache</title>
<link href="./style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet" />
<link href="./style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size" />
<link href="./style/css/manual-print.css" rel="stylesheet" media="print" type="text/css" />
<link href="./images/favicon.ico" rel="shortcut icon" /></head>
<body id="manual-page"><div id="page-header">
<p class="menu"><a href="./mod/">Módulos</a> | <a href="./mod/directives.html">Directivas</a> | <a href="./faq/">Preguntas Frecuentes</a> | <a href="./glossary.html">Glosario</a> | <a href="./sitemap.html">Mapa de este sitio web</a></p>
<p class="apache">Versión 2.2 del Servidor HTTP Apache</p>
<img alt="" src="./images/feather.gif" /></div>
<div class="up"><a href="./"><img title="&lt;-" alt="&lt;-" src="./images/left.gif" /></a></div>
<div id="path">
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs/">Documentación</a> &gt; <a href="./">Versión 2.2</a></div><div id="page-content"><div id="preamble"><h1>Compilación e Instalación</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="./de/install.html" hreflang="de" rel="alternate" title="Deutsch">&nbsp;de&nbsp;</a> |
<a href="./en/install.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/install.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="./fr/install.html" hreflang="fr" rel="alternate" title="Français">&nbsp;fr&nbsp;</a> |
<a href="./ja/install.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/install.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./tr/install.html" hreflang="tr" rel="alternate" title="Türkçe">&nbsp;tr&nbsp;</a></p>
</div>
<div class="outofdate">Esta traducción podría estar
            obsoleta. Consulte la versión en inglés de la
            documentación para comprobar si se han producido cambios
            recientemente.</div>


    <p>Este documento explica cómo compilar e instalar Apache en
    sistemas Unix y tipo Unix. Para obtener información sobre
    cómo compilar e instalar en Windows, consulte la sección
    <a href="platform/windows.html">Usar Apache en Microsoft
    Windows</a>. Para otras plataformas, consulte la
    documentación sobre <a href="platform/">plataformas</a>.</p>

    <p>El entorno de configuración e instalación de Apache
    2.0 ha cambiado completamente respecto al de Apache 1.3. Apache
    1.3 usaba un conjunto de scripts a medida para conseguir una
    instalación fácil. Apache 2.0 usa <code>libtool</code> y
    <code>autoconf</code> para crear un entorno más parecido al
    de muchos otros proyectos Open Source.</p>
    
    <p>Si lo que quiere hacer es actualizar su servidor Apache desde
    una versión menor (por ejemplo, desde la 2.0.50 a la 2.0.51),
    pase directamente a la sección de <a href="#upgrading">actualización</a>.</p>

</div>
<div id="quickview"><ul id="toc"><li><img alt="" src="./images/down.gif" /> <a href="#overview">Visión general del proceso para
    impacientes</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#requirements">Requisitos</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#download">Descargar</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#extract">Descomprimir</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#configure">Configuración de la estructura de
directorios</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#compile">Compilar</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#install">Instalar</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#customize">Personalizar</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#test">Comprobar que la instalación
funciona</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#upgrading">Actualizar una instalación
prrevia</a></li>
</ul><h3>Consulte también</h3><ul class="seealso"><li><a href="programs/configure.html">Configuración de la
estructura de directorios</a></li><li><a href="invoking.html">Iniciar Apache</a></li><li><a href="stopping.html">Parar y reiniciar Apache</a></li></ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="overview" id="overview">Visión general del proceso para
    impacientes</a></h2>

    <table>
      
      <tr>
        <td><a href="#download">Descargar</a></td>

        <td><code>$ lynx http://httpd.apache.org/download.cgi</code>
        </td>
      </tr>

      <tr>
        <td><a href="#extract">Descomprimir</a></td>

        <td><code>$ gzip -d httpd-2_1_<em>NN</em>.tar.gz<br />
         $ tar xvf httpd-2_1_<em>NN</em>.tar</code> </td>
      </tr>

      <tr>
        <td><a href="#configure">Ejecutar el script configure</a></td>

        <td><code>$ ./configure --prefix=<em>PREFIX</em></code>
        </td>
      </tr>

      <tr>
        <td><a href="#compile">Compilar</a></td>

        <td><code>$ make</code> </td>
      </tr>

      <tr>
        <td><a href="#install">Instalar</a></td>

        <td><code>$ make install</code> </td>
      </tr>

      <tr>
        <td><a href="#customize">Personalizar</a></td>

        <td><code>$ vi <em>PREFIX</em>/conf/httpd.conf</code> </td>
      </tr>

      <tr>
        <td><a href="#test">Comprobar que la instalación
        funciona</a></td>

        <td><code>$ <em>PREFIX</em>/bin/apachectl start</code>
        </td>
      </tr>
    </table>

    <p><em>NN</em> hay que reemplazarlo por el número de la
    versión menor, y <em>PREFIX</em> hay que reemplazarlo por la
    ruta en la que se va a instalar Apache. Si no especifica
    ningún valor en <em>PREFIX</em>, el valor por defecto que se
    toma es <code>/usr/local/apache2</code>.</p>

    <p>Cada parte del proceso de configuración e instalación
    se describe detalladamente más abajo, empezando por los
    requisitos para compilar e instalar Apache.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="requirements" id="requirements">Requisitos</a></h2>

    <p>Estos son los requisitos necesarios para compilar Apache:</p>
  
    <dl>
      <dt>Espacio en disco</dt> <dd>Compruebe que tiene disponibles al
      menos 50 MB de espacio libre en disco. Después de la
      instalación, Apache ocupa aproximadamente 10 MB. No
      obstante, la necesidad real de espacio en disco varía
      considerablemente en función de las opciones de
      configuración que elija y de los módulos externos que
      use.</dd>

      <dt>Compilador ANSI-C y Build System</dt> <dd>Compruebe que
      tiene instalado un compilador de ANSI-C. Se recomienda el <a href="http://www.gnu.org/software/gcc/gcc.html">Compilador GNU C
      (GCC)</a> de la <a href="http://www.gnu.org/">Free Software
      Foundation (FSF)</a> (con la versión 2.7.2 es
      suficiente). Si no tiene instaldo el GCC, entonces compruebe que
      el compilador que va a utilizar cumple con los estándares
      ANSI. Además, su <code>PATH</code> debe contener la
      ubicación donde de encuentran las herramientas básicas
      para compilar tales como <code>make</code>.</dd>

      <dt>Ajuste exacto del reloj del sistema</dt> <dd>Los elementos
      del protocolo HTTP están expresados según la hora del
      dia. Por eso, si quiere puede investigar como instalar alguna
      utilidad para sincronizar la hora de su sistema. Para esto,
      normalmente, se usan los programas <code>ntpdate</code> o
      <code>xntpd</code>, que están basados en el protocolo
      Network Time Protocol (NTP). Consulte el grupo de noticias <a href="news:comp.protocols.time.ntp">comp.protocols.time.ntp</a>
      y el <a href="http://www.eecis.udel.edu/~ntp/">sitio web de NTP
      </a> para obtener más información sobre NTP y los
      servidores públicos de tiempo.</dd>

      <dt><a href="http://www.perl.org/">Perl 5</a> [OPCIONAL]</dt>
      <dd>Para algunos de los scripts de soporte como <a href="programs/apxs.html">apxs</a> o <a href="programs/dbmmanage.html">dbmmanage</a> (que están
      escritos en Perl) es necesario el intérprete de Perl 5 (las
      versiones 5.003 o posteriores son suficientes). Si el script
      `<code>configure</code>' no encuentra ese intérprete
      tampoco pasa nada. Aún puede compilar e instalar Apache
      2.0. Lo único que ocurrirá es que esos scripts de
      soporte no podrán ser usados. Si usted tiene varios
      interpretes de Perl instalados (quizás Perl 4 porque estaba
      ya incluido en su distribución de Linux y Perl 5 porque lo
      ha instalado usted), entonces se recomienda usar la opción
      <code>--with-perl</code> para asegurarse de que
      <code>./configure</code> usa el intérprete correcto.</dd>
    </dl>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="download" id="download">Descargar</a></h2>

    <p>Puede descargar Apache desde <a href="http://httpd.apache.org/download.cgi">la sección de
    descargas del sitio web de Apache</a> el cual tiene varios
    mirrors. Para la mayoría de los usuarios de Apache que tienen
    sistemas tipo Unix, se recomienda que se descarguen y compilen el
    código fuente. El proceso de compilación (descrito
    más abajo) es fácil, y permite adaptar el servidor
    Apache a sus necesidades. Además, las versiones de
    disponibles en archivos binarios no están siempre actulizadas
    con las últimas modificaciones en el codigo fuente. Si se
    descarga un binario, siga las instrucciones contenidas en el
    archivo <code>INSTALL.bindist</code> incluido en la
    distribución</p>

    <p>Después de la descarga, es importante que verifique que el
    archivo descargado del servidor HTTP Apache está completo y
    sin modificaciones.  Esto puede hacerlo comparando el archivo
    descargado (.tgz) con su firma PGP. Instrucciones detalladas de
    cómo hacer esto están disponibles en <a href="http://httpd.apache.org/download.cgi#verify"> la
    sección de descargas</a> junto con un ejemplo de cómo <a href="http://httpd.apache.org/dev/verification.html">usar
    PGP</a>.</p>
 
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="extract" id="extract">Descomprimir</a></h2>

    <p>Extraer el código fuente del archivo .tgz que acabada de
    descargar es muy fácil. Ejecute los siguientes comandos:</p>

<div class="example"><p><code>
      $ gzip -d httpd-2_1_<em>NN</em>.tar.gz<br />
       $ tar xvf httpd-2_1_<em>NN</em>.tar
</code></p></div>

    <p>Estos comandos crearán un nuevo directorio dentro del
    directorio en el que se encuentra y que contendrá el
    código fuente de la distribución. Debe cambiarse a ese
    directorio con <code>cd</code> para proceder a compilar el
    servidor Apache.</p>

</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="configure" id="configure">Configuración de la estructura de
directorios</a></h2>

    <p>El siguiente paso es configurar la estructura de directorios
    para su plataforma y sus necesidades personales. Esto se hace
    usando el script <code>configure</code> incluido en el directorio
    raiz de la distribución que acaba de descargar. (Los
    desarrolladores que se descarguen la versión del CVS de la
    estructura de directorios necesitarán tener instalados
    <code>autoconf</code> y <code>libtool</code>, y necesitarán
    ejecutar <code>buildconf</code> antes de continuar con los
    siguientes pasos. Esto no es preciso para las versiones
    oficiales.)</p>

    <p>Para configurar la estructura de directorios a partir del
    código fuente usando las opciones por defecto, solo tiene que
    ejecutar <code>./configure</code>. Para cambiar las opciones por
    defecto, <code>configure</code> acepta una serie de variables y
    opciones por la línea de comandos.</p>

    <p>La opción más importante es <code>--prefix</code> que
    es el directorio en el que Apache va a ser instalado después,
    porque Apache tiene que ser configurado para el directorio que se
    especifique para que funcione correctamente.  Es posible lograr un
    mayor control del lugar donde se van a instalar los ficheros de
    Apache con otras <a href="programs/configure.html#installationdirectories">opciones de
    configuración</a>.</p>

    <p>En este momento, puede especificar que <a href="programs/configure.html#optionalfeatures">características
    o funcionalidades</a> quiere incluir en Apache activando o
    desactivando <a href="mod/">módulos</a>.  Apache viene con
    una <a href="mod/module-dict.html#Status">selección
    básica</a> de módulos incluidos por defecto.  Se pueden
    activar otros módulos usando la opción
    <code>--enable-<var>module</var></code>, donde <var>module</var>
    es el nombre del módulo sin el <code>mod_</code> y
    convirtiendo los guiones bajos que tenga en guiones normales.
    También puede optar por compilar módulos como <a href="dso.html">objetos dinámicos compartidos (DSOs)</a> --
    que pueden ser activados o desactivados al ejecutar -- usando la
    opción <code>--enable-<var>module</var>=shared</code>.  De
    igual manera, puede desactivar alguno de los módulos que
    vienen por defecto en la selección basica con la opción
    <code>--disable-<var>module</var></code>.  Tenga cuidado cuando
    use estas opciones, porque <code>configure</code> no le
    avisará si el módulo que especifica no existe;
    simplemente ignorará esa opción.</p>

    <p>Además, a veces es necesario pasarle al script
    <code>configure</code> información adicional sobre donde esta
    su compilador, librerias o ficheros de cabecera.  Esto se puede
    hacer, tanto pasando variables de entorno, como pasandole opciones
    a <code>configure</code> a través de la línea de
    comandos.  Para más información, consulte el <a href="programs/configure.html">Manual del script
    configure</a>.</p>

    <p>Para que se haga una idea sobre las posibilidades que tiene,
    aquí tiene un ejemplo típico que configura Apache para
    la ruta <code>/sw/pkg/apache</code> con un compilador y unos flags
    determinados, y además, con dos módulos adicionales
    <code class="module"><a href="./mod/mod_rewrite.html">mod_rewrite</a></code> y <code class="module"><a href="./mod/mod_speling.html">mod_speling</a></code> para
    cargarlos después a través del mecanismo DSO:</p>

<div class="example"><p><code>
      $ CC="pgcc" CFLAGS="-O2" \<br />
       ./configure --prefix=/sw/pkg/apache \<br />
       --enable-rewrite=shared \<br />
       --enable-speling=shared
</code></p></div>

    <p>Cuando se ejecuta <code>configure</code> se comprueban que
    características o funcionalidades están disponibles en
    su sistema y se crean los Makefiles que serán usados luego
    para compilar el servidor. Esto tardará algunos minutos.</p>

    <p>La información sobre todas las opciones de
    <code>configure</code> está disponible en el <a href="programs/configure.html">Manual del script
    configure</a>.</p>

</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="compile" id="compile">Compilar</a></h2>

    <p>Ahora puede compilar las diferentes partes que forman Apache
    simplemente ejecutando el siguiente comando:</p>

<div class="example"><p><code>$ make</code></p></div>

    <p>Por favor, tanga un poco de paciencia ahora, porque una
    configuración básica tarda aproximadamente 3 minutos en
    compilar en un Pentium III con un sistema Linux 2.2, pero este
    tiempo puede variar considerablemente en función de su
    hardware y del número de módulos que haya
    seleccionado.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="install" id="install">Instalar</a></h2>

    <p>Ahora es el momento de instalar el paquete en el diretorio
    elegido en <em>PREFIX</em> (consulte la opción
    <code>--prefix</code> más arriba) ejecutando:</p>

<div class="example"><p><code>$ make install</code></p></div>

    <p>Si usted está solo actualizando una instalación
    anterior, la nueva instalación no sobreescribirá sus
    ficheros de configuración ni otros documentos.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="customize" id="customize">Personalizar</a></h2>

    <p>El paso siguiente, es personalizar su servidor Apache editando
    los <a href="configuring.html">ficheros de configuración</a>
    que están en <code><em>PREFIX</em>/conf/</code>.</p>

<div class="example"><p><code>$ vi <em>PREFIX</em>/conf/httpd.conf</code></p></div>

    <p>échele un vistazo al Manual de Apache que está en <a href="./">docs/manual/</a> o consulte en <a href="http://httpd.apache.org/docs/2.2/">http://httpd.apache.org/docs/2.2/</a> la versión más
    reciente de este manual y la Guia de Referencia de todas las <a href="mod/directives.html">directivas de configuración</a>
    disponibles.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="test" id="test">Comprobar que la instalación
funciona</a></h2>

    <p>Ahora puede <a href="invoking.html">iniciar</a> su servidor
    Apache cuando quiera ejecutando:</p>

<div class="example"><p><code>$ <em>PREFIX</em>/bin/apachectl start</code></p></div>

    <p>y entonces debe poder acceder al documento que tenga
    especificado por defecto usando el siguiente URL:
    <code>http://localhost/</code>. El documento que verá
    estará en <code class="directive"><a href="./mod/core.html#documentroot">DocumentRoot</a></code> y
    casi siempre estará en <code><em>PREFIX</em>/htdocs/</code>.
    Si quiere <a href="stopping.html">parar</a> el servidor, puede
    hacerlo ejecutando:</p>

<div class="example"><p><code>$ <em>PREFIX</em>/bin/apachectl stop</code></p></div>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="upgrading" id="upgrading">Actualizar una instalación
prrevia</a></h2>

    <p>El primer paso para actualizar una instalación anterior es
    leer las especificaciones de la versión y el fichero
    <code>CHANGES</code> en la distribución de código fuente
    que ha descargado para encontrar los cambios que puedan afectar a
    su instalación actual. Cuando el cambio sea entre versiones
    mayores (por ejemplo, de la 1.3 a la 2.0 o de la 2.0 a la 2.2),
    entonces es más probable que haya diferencias importantes en
    la compilación y en la ejecución que necesitarán
    ajustes manuales. Todos los módulos necesitarán
    también ser actualizados para adaptarse a los cambios en el
    interfaz de programación (API) de módulos.</p>

    <p>La actualización cuando el cambio es entre versiones
    menores (por ejemplo, de la 2.0.55 a la 2.0.57) es más
    fácil.  El proceso <code>make install</code> no
    sobreescribirá ninguno de los documentos existentes, archivos
    log, o archivos de configuración.  Además, los
    desarrolladores hacen todos los esfuerzos posibles para evitar
    cambios que generen incompatibilidades en las opciones de
    <code>configure</code>, en la configuración de la
    ejecución o en la interfaz de programación de
    módulos. En la mayor parte de los casos debe poder usar un
    comando <code>configure</code> idéntico, un fichero de
    configuracién idéntico, y todos sus módulos deben
    seguir funcionando.  (Esto es válido solo para versiones
    posteriores a la 2.0.41; las versiones anteriores contienen
    cambios incompatibles.)</p>

    <p>Si va a conservar la estructura de directorios de su anterior
    instalación, la actualización es más fácil
    incluso.  El fichero <code>config.nice</code> que está en el
    directorio raiz de la estructura de directorios antigua contiene
    exactamente el comando <code>configure</code> que usted usó
    para configurar la estructura de directorios de Apache.  Entonces,
    para actualizar su instalación de una versóon a la
    siguinete, solo tiene que copiar el archivo
    <code>config.nice</code> a la estructura de directorios del
    código fuente de la nueva versión, editarlo, hacer
    cualquier cambio que desee, y ejecutarlo :</p>

    <div class="example"><p><code>
    $ ./config.nice<br />
    $ make<br />
    $ make install<br />
    $ <em>PREFIX</em>/bin/apachectl stop<br />
    $ <em>PREFIX</em>/bin/apachectl start<br />
    </code></p></div>

    <div class="warning">Tenga en cuenta que antes de poner una nueva
    versión de Apache en producción, debe siempre probarla
    antes en su entorno. Por ejemplo, puede instalar y ejecutar la
    nueva versión junto con la antigua usando un
    <code>--prefix</code> diferente y un puerto diferente (modificando
    la directiva <code class="directive"><a href="./mod/mpm_common.html#listen">Listen</a></code>)
    para comprobar que no existe ninguna incompatibilidad antes de
    hacer la actualización definitiva.</div>
</div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="./de/install.html" hreflang="de" rel="alternate" title="Deutsch">&nbsp;de&nbsp;</a> |
<a href="./en/install.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/install.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="./fr/install.html" hreflang="fr" rel="alternate" title="Français">&nbsp;fr&nbsp;</a> |
<a href="./ja/install.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/install.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./tr/install.html" hreflang="tr" rel="alternate" title="Türkçe">&nbsp;tr&nbsp;</a></p>
</div><div id="footer">
<p class="apache">Copyright 2011 The Apache Software Foundation.<br />Licencia bajo los términos de la <a href="http://www.apache.org/licenses/LICENSE-2.0">Apache License, Version 2.0</a>.</p>
<p class="menu"><a href="./mod/">Módulos</a> | <a href="./mod/directives.html">Directivas</a> | <a href="./faq/">Preguntas Frecuentes</a> | <a href="./glossary.html">Glosario</a> | <a href="./sitemap.html">Mapa de este sitio web</a></p></div>
</body></html>