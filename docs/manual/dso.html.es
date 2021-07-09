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
<title>Soporte de Objetos Dinamicos Compartidos (DSO) - Servidor HTTP Apache</title>
<link href="./style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet" />
<link href="./style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size" />
<link href="./style/css/manual-print.css" rel="stylesheet" media="print" type="text/css" />
<link href="./images/favicon.ico" rel="shortcut icon" /><link href="http://httpd.apache.org/docs/current/dso.html" rel="canonical" /></head>
<body id="manual-page"><div id="page-header">
<p class="menu"><a href="./mod/">M&#243;dulos</a> | <a href="./mod/directives.html">Directivas</a> | <a href="./faq/">Preguntas Frecuentes</a> | <a href="./glossary.html">Glosario</a> | <a href="./sitemap.html">Mapa de este sitio web</a></p>
<p class="apache">Versi&#243;n 2.0 del Servidor HTTP Apache</p>
<img alt="" src="./images/feather.gif" /></div>
<div class="up"><a href="./"><img title="&lt;-" alt="&lt;-" src="./images/left.gif" /></a></div>
<div id="path">
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs/">Documentaci&#243;n</a> &gt; <a href="./">Versi&#243;n 2.0</a></div><div id="page-content"><div class="retired"><h4>Please note</h4>
            <p>This document refers to the <strong>2.0</strong> version of Apache httpd, which <strong>is no longer maintained</strong>. Upgrade, and refer to the current version of httpd instead, documented at:</p>
        <ul><li><a href="http://httpd.apache.org/docs/current/">Current release version of Apache HTTP Server documentation</a></li></ul><p>You may follow <a href="http://httpd.apache.org/docs/current/dso.html">this link</a> to go to the current version of this document.</p></div><div id="preamble"><h1>Soporte de Objetos Dinamicos Compartidos (DSO)</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="./en/dso.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/dso.html" title="Espa&#241;ol">&nbsp;es&nbsp;</a> |
<a href="./fr/dso.html" hreflang="fr" rel="alternate" title="Fran&#231;ais">&nbsp;fr&nbsp;</a> |
<a href="./ja/dso.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/dso.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./tr/dso.html" hreflang="tr" rel="alternate" title="T&#252;rk&#231;e">&nbsp;tr&nbsp;</a></p>
</div>
<div class="outofdate">Esta traducci&#243;n podr&#237;a estar
            obsoleta. Consulte la versi&#243;n en ingl&#233;s de la
            documentaci&#243;n para comprobar si se han producido cambios
            recientemente.</div>

    <p>El servidor HTTP Apache es un programa modular en el que el
    administrador puede elegir qu&#233; funcionalidades se incluyen
    mediante la selecci&#243;n de un conjunto de m&#243;dulos. En
    primer lugar, los m&#243;dulos pueden compilarse de manera
    est&#225;tica en el binario <code class="program"><a href="./programs/httpd.html">httpd</a></code>. De forma
    alternativa, los m&#243;dulos tambi&#233;n pueden compilarse como
    Objetos Dinamicos Compartidos (DSOs) que existen de forma
    independiente del archivo binario <code class="program"><a href="./programs/httpd.html">httpd</a></code>. Los
    m&#243;dulos que se deseen usar como objetos din&#225;micos
    compartidos pueden compilarse al mismo tiempo que el servidor, o
    pueden compilarse en otro momento y ser a&#241;adidos despu&#233;s
    usando la Herramienta de Extensi&#243;n de Apache
    (<code class="program"><a href="./programs/apxs.html">apxs</a></code>).</p>

    <p>Este documento describe c&#243;mo usar los m&#243;dulos en
    forma de objeto din&#225;mico compartido (DSO) as&#237; como los
    fundamentos te&#243;ricos que hay detr&#225;s para explicar su
    funcionamiento.</p>
  </div>
<div id="quickview"><ul id="toc"><li><img alt="" src="./images/down.gif" /> <a href="#implementation">Implementaci&#243;n</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#usage">Resumen de uso</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#background">Fundamentos teor&#243;ricos
detr&#225;s de los objetos din&#225;micos compartidos</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#advantages">Ventajas e Inconvenientes</a></li>
</ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="implementation" id="implementation">Implementaci&#243;n</a></h2>

<table class="related"><tr><th>M&#243;dulos Relacionados</th><th>Directivas Relacionadas</th></tr><tr><td><ul><li><code class="module"><a href="./mod/mod_so.html">mod_so</a></code></li></ul></td><td><ul><li><code class="directive"><a href="./mod/mod_so.html#loadmodule">LoadModule</a></code></li></ul></td></tr></table>

    <p>Cargar m&#243;dulos de Apache individualmente como objetos
    din&#225;micos compartidos (DSO) es posible gracias a un
    m&#243;dulo llamado <code class="module"><a href="./mod/mod_so.html">mod_so</a></code> que debe compilarse
    est&#225;ticamente en el n&#250;cleo (kernel) de Apache. Es el
    &#250;nico m&#243;dulo junto con el m&#243;dulo
    <code class="module"><a href="./mod/core.html">core</a></code> que no se puede usar como objeto
    din&#225;mico compartido. Pr&#225;cticamente todos los dem&#225;s
    m&#243;dulos distribuidos con Apache se pueden usar como objetos
    din&#225;micos compartidos individualmente siempre y cuando se
    haya activado la posibilidad de usarlos con la opci&#243;n de
    <code class="program"><a href="./programs/configure.html">configure</a></code>
    <code>--enable-<em>module</em>=shared</code> tal y como se
    explic&#243; en la <a href="install.html">documentaci&#243;n de
    instalaci&#243;n</a>. Una vez que haya compilado un m&#243;dulo
    como objeto din&#225;mico compartido y le haya puesto un nombre
    del tipo <code>mod_foo.so</code>, puede cargarlo al iniciar o
    reiniciar el servidor usando el comando <code class="directive"><a href="./mod/mod_so.html#loadmodule">LoadModule</a></code> de <code class="module"><a href="./mod/mod_so.html">mod_so</a></code>
    en el fichero <code>httpd.conf</code>.</p>

    <p>Para simplificar la creaci&#243;n de objetos din&#225;micos
    compartidos para Apache (especialmente m&#243;dulos de terceras
    partes) est&#225; disponible un nuevo programa de soporte llamado
    <code class="program"><a href="./programs/apxs.html">apxs</a></code> (<em>APache eXtenSion</em>). Puede usar
    este programa para crear m&#243;dulos como objetos din&#225;micos
    compartidos <em>sin tener que</em> crearlos al mismo tiempo que
    compila su servidor Apache. La idea es simple: cuando se instala
    Apache el procedimiento <code>make install</code> de
    <code class="program"><a href="./programs/configure.html">configure</a></code> @@@ installs the Apache C header
    files and puts the platform-dependent compiler and linker flags
    for building DSO files into the apxs program / instala los
    ficheros de cabecera de C de Apache y especifica las opciones de
    compilaci&#243;n y enlace dependientes de la plataforma para
    generar objetos din&#225;micos compartidos con
    <code class="program"><a href="./programs/apxs.html">apxs</a></code>. De esta manera el usuario puede usar
    <code class="program"><a href="./programs/apxs.html">apxs</a></code> para compilar el c&#243;digo fuente de
    m&#243;dulos de Apache de manera independiente y sin tener que
    preocuparse por las opciones de compilaci&#243;n y enlace
    dependientes de la plataforma que soportan objetos din&#225;micos
    compartidos.</p>

</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="usage" id="usage">Resumen de uso</a></h2>

    <p>Para que se haga una idea de lo que permite el soporte de
    objetos din&#225;micos compartidos en Apache 2.0, aqu&#237; tiene
    un resumen breve pero conciso:</p>

    <ol>
      <li>
        Construir e instalar un m&#243;dulo <em>incluido en la
        distribuci&#243;n</em> de Apache, digamos
        <code>mod_foo.c</code>, como un objeto din&#225;mico
        compartido de nombre <code>mod_foo.so</code>:

<div class="example"><p><code>
$ ./configure --prefix=/path/to/install --enable-foo=shared<br />
$ make install
</code></p></div>
      </li>

      <li>
        Construir e instalar un m&#243;dulo de Apache de una
        <em>tercera parte</em>, digamos <code>mod_foo.c</code>, como
        un objeto din&#225;mico compartido de nombre
        <code>mod_foo.so</code>:

<div class="example"><p><code>
$ ./configure --add-module=module_type:/path/to/3rdparty/mod_foo.c --enable-foo=shared<br />
$ make install
</code></p></div>
      </li>

      <li>
        Configurar Apache para poder <em>instalar despu&#233;s</em>
        objetos din&#225;micos compartidos:

<div class="example"><p><code>
$ ./configure --enable-so<br />
$ make install
</code></p></div>
      </li>

      <li>
	Construir e instalar un m&#243;dulo de Apache de una
        <em>tercera parte</em>, digamos <code>mod_foo.c</code>, como
        un objeto din&#225;mico compartido de nombre
        <code>mod_foo.so</code> <em>fuera</em> de la estructura de
        directorios de Apache usando <code class="program"><a href="./programs/apxs.html">apxs</a></code>:

<div class="example"><p><code>
$ cd /path/to/3rdparty<br />
$ apxs -c mod_foo.c<br />
$ apxs -i -a -n foo mod_foo.la
</code></p></div>
      </li>
    </ol>

    <p>En todos los casos, una vez que se compila el objeto
        din&#225;mico compartido, debe usar una directiva <code class="directive"><a href="./mod/mod_so.html#loadmodule">LoadModule</a></code> en
        <code>httpd.conf</code> para activar dicho m&#243;dulo.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="background" id="background">Fundamentos teor&#243;ricos
detr&#225;s de los objetos din&#225;micos compartidos</a></h2>

    <p>En las versiones modernas de Unix, existe un mecanismo
    especialmente &#250;til normalmente llamado enlazado/carga de
    <em>Objetos Din&#225;micos Compartidos</em> (DSO). Este mecanismo
    ofrece una forma de construir trozos de c&#243;digo de programa en
    un formato especial para cargarlo en tiempo de ejecuci&#243;n en
    el espacio de direcciones de memoria de un programa
    ejecutable.</p>

    <p>Esta carga puede hacerse de dos maneras: autom&#225;ticamente
    con un programa de sistema llamado <code>ld.so</code> al inicio de
    un programa ejecutable o manualmente desde dentro del programa en
    ejecuci&#243;n con una interfaz program&#225;tica del sistema al
    cargador de Unix mediante llamadas al sistema
    <code>dlopen()/dlsym()</code>.</p>

    <p>Si se usa el primer m&#233;todo, los objetos din&#225;micos
        compartidos se llaman normalmente <em>librer&#237;as
        compartidas</em> &#243; <em>librer&#237;as DSO</em> y se
        nombran como <code>libfoo.so</code> o
        <code>libfoo.so.1.2</code>. Residen en un directorio de
        sistema (normalmente <code>/usr/lib</code>) y el enlace con el
        programa ejecutable se establece al construir la librer&#237;a
        especificando la opci&#243;n<code>-lfoo</code> al comando de
        enlace. Esto incluye las referencias literales a las
        librer&#237;as en el programa ejecutable de manera que cuando
        se inicie, el cargador de Unix ser&#225; capaz de localizar
        <code>libfoo.so</code> en <code>/usr/lib</code>, en rutas
        referenciadas literalmente mediante opciones del linker como
        <code>-R</code> o en rutas configuradas mediante la variable
        de entorno <code>LD_LIBRARY_PATH</code>. Entonces se resuelven
        los s&#237;mbolos (todav&#237;a no resueltos) en el programa
        ejecutable que est&#225;n presentes en el objeto din&#225;mico
        compartido.</p>

    <p>Los s&#237;mbolos en el programa ejecutable no est&#225;n
    referenciados normalmente en el objeto din&#225;mico compartido
    (porque son librer&#237;as reusables de prop&#243;sito general) y
    por tanto, no se producen m&#225;s resoluciones. El programa
    ejecutable no tiene que hacer nada por s&#237; mismo para usar los
    s&#237;mbolos del objeto din&#225;mico compartido porque todo el
    trabajo de resoluci&#243;n lo hace @@@ Unix loader / el cargador
    de Unix @@@. (De hecho, el c&#243;digo para invocar
    <code>ld.so</code> es parte del c&#243;digo que se ejecuta al
    iniciar, y que hay en cualquier programa ejecutable que haya sido
    construido de forma no est&#225;tica). La ventaja de cargar
    din&#225;micamente el c&#243;digo de las librer&#237;as comunes es
    obvia: el c&#243;digo de las librer&#237;as necesita ser almacenado
    solamente una vez, en una librer&#237;a de sistema como
    <code>libc.so</code>, ahorrando as&#237; espacio en disco.</p>

    <p>Por otro lado, los objetos din&#225;micos compartidos
        tambi&#233;n suelen llamarse <em>objetos compatidos</em> o
        <em>ficheros DSO</em> y se les puede nombrar con cualquier
        extensi&#243;n (aunque su nombre can&#243;nico es
        <code>foo.so</code>). Estos archivos normalmente permanecen
        dentro de un directorio espec&#237;fico del programa y no se
        establecen enlaces autom&#225;ticamente con los programas
        ejecutables con los que se usan.  En lugar de esto, el
        programa ejecutable carga manualmente el objeto din&#225;mico
        compartido en tiempo de ejecuci&#243;n en su espacio de
        direcciones de memoria con <code>dlopen()</code>. En ese
        momento no se resuelven los s&#237;mbolos del objeto
        din&#225;mico compartido para el programa ejecutable. En lugar
        de esto, el cargador de Unix resuelve autom&#225;ticamente los
        s&#237;mbolos (a&#250;n no resueltos en el objeto
        din&#225;mico compartido del conjunto de s&#237;mbolos
        exportados por el programa ejecutable y de las librer&#237;as
        DSO que tenga ya cargadas (especialmente todos los
        s&#237;mbolos de la omnipresente <code>libc.so</code>). De
        esta manera el objeto din&#225;mico compartido puede conocer
        el conjunto de s&#237;mbolos del programa ejecutable como si
        hubiera sido enlazado est&#225;ticamente en un primer
        momento.</p>

    <p>Finalmente, para beneficiarse de la API de las DSOs, el
    programa ejecutable tiene que resolver los s&#237;mbolos
    particulares de la DSO con <code>dlsym()</code> para ser usado
    m&#225;s tarde dentro de tablas de direccionamiento (dispatch
    tables) <em>etc.</em> En otras palabras: El programa ejecutable
    tiene que resolver manualmente cada uno de los s&#237;mbolos que
    necesita para poder usarlo despu&#233;s. La ventaja de ese
    mecanismo es que las partes opcionales del programa no necesitan
    ser cargadas (y por tanto no consumen memoria) hasta que se
    necesitan por el programa en cuesti&#243;n. Cuando es necesario,
    estas partes del programa pueden cargarse din&#225;micamente para
    expandir las funcionalidades b&#225;sicas del programa.</p>

    <p>Aunque este mecanismo DSO parece muy claro, hay al menos un
    paso de cierta dificultad: la resoluci&#243;n de los s&#237;mbolos
    que usa el programa ejecutable por la DSO cuando se usa una DSO
    para extender la funcionalidad de una programa (segundo caso). Por
    qu&#233;? Porque la resoluci&#243;n inversa de s&#237;mbolos de
    DSOs del conjunto de s&#237;mbolos del programa ejecutable se hace
    en contra del dise&#241;o de la librer&#237;a (donde la
    librer&#237;a no tiene conocimiento sobre los programas que la
    usan) y tampoco est&#225; disponible en todas las plataformas no
    estandarizadas. En la pr&#225;ctica los s&#237;mbolos globales del
    programa ejecutable est&#225;n disponibles para su uso en una
    DSO. El mayor problema que hay que resolver cuando se usan DSOs
    para extender un programa en tiempo de ejecuci&#243;n es encontrar
    un modo de forzar al enlazador a exportar todos los s&#237;mbolos
    globales.</p>

    <p>El enfoque de las librer&#237;as compartidas es bastante
    t&#237;pico, porque es para lo que se dise&#241;o el mecanismo
    DSO, por tanto se usa para casi todos los tipos de librer&#237;as
    que incluye el sistema operativo. Por otro lado, no muchos
    programas usan objetos compartidos para expandir sus
    funcionalidades.</p>

    <p>En 1998, hab&#237;a solamente unos pocos programas disponibles
    que usaban el mecanismo DSO para extender su funcionalidad en
    tiempo de ejecucion: Perl 5 (por medio de su mecanismo XS y el
    m&#243;dulo DynaLoader), Netscape Server, <em>etc.</em> A partir
    de la version 1.3, Apache se uni&#243; a este grupo, Apache usa
    desde entonces una concepci&#243;n modular para extender su
    funcionalidad e internamente usa un enfoque de tablas de
    direccionamiento (dispatch-list-based) para enlazar m&#243;dulos
    externos con las funcionalidades propias del servidor. De esta
    manera, Apache puede usar el mecanismo DSO para cargar sus
    m&#243;dulos en tiempo de ejecuci&#243;n.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="advantages" id="advantages">Ventajas e Inconvenientes</a></h2>

    <p>Las caracter&#237;sticas de las librer&#237;as din&#225;micas
    compartidas arriba explicadas tienen las siguientes ventajas:</p>

    <ul>
      <li>El servidor es mucho m&#225;s flexible en tiempo de
      ejecuci&#243;n porque pueden a&#241;adirse m&#243;dulos mediante
      comandos de configuraci&#243;n <code class="directive"><a href="./mod/mod_so.html#loadmodule">LoadModule</a></code> en
      <code>httpd.conf</code> en lugar de tener que hacerlo con las
      opciones de <code class="program"><a href="./programs/configure.html">configure</a></code> al compilar. Por
      ejemplo, de esta manera uno puede ejecutar diferentes instancias
      del servidor (est&#225;ndar &amp; SSL, m&#237;nima &amp; super
      potente [mod_perl, PHP3], <em>etc.</em>) con una &#250;nica
      instalaci&#243;n de Apache.</li>

      <li>El servidor puede ser extendido f&#225;cilmente con
      m&#243;dulos de terceras partes despu&#233;s de la
      instalaci&#243;n. Esto es un gran beneficio al menos para los
      mantenedores de paquetes de distribuciones, que pueden crear un
      paquete b&#225;sico de Apache y paquetes adicionales que
      contengan extensiones tales como PHP3, mod_perl, mod_fastcgi,
      <em>etc.</em></li>

      <li>Facilita la labor de hacer prototipos de m&#243;dulos de
      Apache porque con el d&#250;o DSO/<code class="program"><a href="./programs/apxs.html">apxs</a></code> se
      puede trabajar fuera de la estructura de directorios de Apache y
      &#250;nicamente es necesario el comando <code>apxs -i</code>
      seguido del comando <code>apachectl restart</code> para probar
      la nueva versi&#243;n del m&#243;dulo que se est&#225;
      desarrollando.</li>
    </ul>

    <p>DSO presenta los siguientes inconvenientes:</p>

    <ul>
      <li>El mecanismo DSO no puede ser usado en todas las plataformas
      porque no todos los sistemas operativos soportan la carga
      din&#225;mica de c&#243;digo en el espacio de direcciones de
      memoria de un programa.</li>

      <li>El servidor es aproximadamente un 20% m&#225;s lento
      inici&#225;ndose por la sobrecarga que implica la
      resoluci&#243;n de s&#237;mbolos por parte del cargador de Unix.</li>

      <li>El servidor es aproximadamente un 5% m&#225;s lento
      ejecut&#225;ndose en algunas plataformas porque el c&#243;digo
      posicionado independientemente (PIC) necesita algunas veces
      procesos bastante complicados para calcular direcciones
      relativas que no son en principio tan r&#225;pidos como los que
      se usan para calcular direcciones absolutas.</li>

      <li>Como los m&#243;dulos DSO no pueden enlazarse a otras
      librer&#237;as basadas en DSO (<code>ld -lfoo</code>) en todas
      las plataformas (por ejemplo en las plataformas basadas en a.out
      normalmente no puede ser usada esta funcionalidad, mientras que
      s&#237; puede ser usada en las plataformas basadas en ELF) no se
      puede usar el mecanismo DSO para todos los tipos de
      m&#243;dulos. En otras palabras, los m&#243;dulos compilados
      como ficheros DSO solamente pueden usar s&#237;mbolos del
      n&#250;cleo (kernel) de Apache, los de las librer&#237;as de C
      (<code>libc</code>) y de todas las demas librer&#237;as
      din&#225;micas o est&#225;ticas usadas por el n&#250;cleo de
      Apache, o de archivos de librer&#237;as est&#225;ticas
      (<code>libfoo.a</code>) que contengan c&#243;digo independiente
      de su posici&#243;n. Las &#250;nicas posibilidades para usar
      otro c&#243;digo es asegurarse de que el n&#250;cleo de Apache
      contiene una referencia a &#233;l o cargar el c&#243;digo por
      medio de <code>dlopen()</code>.</li>
    </ul>

</div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="./en/dso.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/dso.html" title="Espa&#241;ol">&nbsp;es&nbsp;</a> |
<a href="./fr/dso.html" hreflang="fr" rel="alternate" title="Fran&#231;ais">&nbsp;fr&nbsp;</a> |
<a href="./ja/dso.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/dso.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./tr/dso.html" hreflang="tr" rel="alternate" title="T&#252;rk&#231;e">&nbsp;tr&nbsp;</a></p>
</div><div id="footer">
<p class="apache">Copyright 2013 The Apache Software Foundation.<br />Licencia bajo los t&#233;rminos de la <a href="http://www.apache.org/licenses/LICENSE-2.0">Apache License, Version 2.0</a>.</p>
<p class="menu"><a href="./mod/">M&#243;dulos</a> | <a href="./mod/directives.html">Directivas</a> | <a href="./faq/">Preguntas Frecuentes</a> | <a href="./glossary.html">Glosario</a> | <a href="./sitemap.html">Mapa de este sitio web</a></p></div>
</body></html>