<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es" xml:lang="es"><head><!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Soporte de Objetos Dinamicos Compartidos (DSO) - Servidor HTTP Apache</title>
<link href="./style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet" />
<link href="./style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size" />
<link href="./style/css/manual-print.css" rel="stylesheet" media="print" type="text/css" />
<link href="./images/favicon.ico" rel="shortcut icon" /></head>
<body id="manual-page"><div id="page-header">
<p class="menu"><a href="./mod/">Módulos</a> | <a href="./mod/directives.html">Directivas</a> | <a href="./faq/">Preguntas Frecuentes</a> | <a href="./glossary.html">Glosario</a> | <a href="./sitemap.html">Mapa de este sitio web</a></p>
<p class="apache">Versión 2.0 del Servidor HTTP Apache</p>
<img alt="" src="./images/feather.gif" /></div>
<div class="up"><a href="./"><img title="&lt;-" alt="&lt;-" src="./images/left.gif" /></a></div>
<div id="path">
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs/">Documentación</a> &gt; <a href="./">Versión 2.0</a></div><div id="page-content"><div id="preamble"><h1>Soporte de Objetos Dinamicos Compartidos (DSO)</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="./en/dso.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/dso.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="./fr/dso.html" hreflang="fr" rel="alternate" title="Français">&nbsp;fr&nbsp;</a> |
<a href="./ja/dso.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/dso.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a></p>
</div>

    <p>El servidor HTTP Apache es un programa modular en el que el
    administrador puede elegir qué funcionalidades se incluyen
    mediante la selección de un conjunto de módulos. En
    primer lugar, los módulos pueden compilarse de manera
    estática en el binario <code class="program"><a href="./programs/httpd.html">httpd</a></code>. De forma
    alternativa, los módulos también pueden compilarse como
    Objetos Dinamicos Compartidos (DSOs) que existen de forma
    independiente del archivo binario <code class="program"><a href="./programs/httpd.html">httpd</a></code>. Los
    módulos que se deseen usar como objetos dinámicos
    compartidos pueden compilarse al mismo tiempo que el servidor, o
    pueden compilarse en otro momento y ser añadidos después
    usando la Herramienta de Extensión de Apache
    (<code class="program"><a href="./programs/apxs.html">apxs</a></code>).</p>

    <p>Este documento describe cómo usar los módulos en
    forma de objeto dinámico compartido (DSO) así como los
    fundamentos teóricos que hay detrás para explicar su
    funcionamiento.</p>
  </div>
<div id="quickview"><ul id="toc"><li><img alt="" src="./images/down.gif" /> <a href="#implementation">Implementación</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#usage">Resumen de uso</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#background">Fundamentos teoróricos
detrás de los objetos dinámicos compartidos</a></li>
<li><img alt="" src="./images/down.gif" /> <a href="#advantages">Ventajas e Inconvenientes</a></li>
</ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="implementation" id="implementation">Implementación</a></h2>

<table class="related"><tr><th>Módulos Relacionados</th><th>Directivas Relacionadas</th></tr><tr><td><ul><li><code class="module"><a href="./mod/mod_so.html">mod_so</a></code></li></ul></td><td><ul><li><code class="directive"><a href="./mod/mod_so.html#loadmodule">LoadModule</a></code></li></ul></td></tr></table>

    <p>Cargar módulos de Apache individualmente como objetos
    dinámicos compartidos (DSO) es posible gracias a un
    módulo llamado <code class="module"><a href="./mod/mod_so.html">mod_so</a></code> que debe compilarse
    estáticamente en el núcleo (kernel) de Apache. Es el
    único módulo junto con el módulo
    <code class="module"><a href="./mod/core.html">core</a></code> que no se puede usar como objeto
    dinámico compartido. Prácticamente todos los demás
    módulos distribuidos con Apache se pueden usar como objetos
    dinámicos compartidos individualmente siempre y cuando se
    haya activado la posibilidad de usarlos con la opción de
    <code class="program"><a href="./programs/configure.html">configure</a></code>
    <code>--enable-<em>module</em>=shared</code> tal y como se
    explicó en la <a href="install.html">documentación de
    instalación</a>. Una vez que haya compilado un módulo
    como objeto dinámico compartido y le haya puesto un nombre
    del tipo <code>mod_foo.so</code>, puede cargarlo al iniciar o
    reiniciar el servidor usando el comando <code class="directive"><a href="./mod/mod_so.html#loadmodule">LoadModule</a></code> de <code class="module"><a href="./mod/mod_so.html">mod_so</a></code>
    en el fichero <code>httpd.conf</code>.</p>

    <p>Para simplificar la creación de objetos dinámicos
    compartidos para Apache (especialmente módulos de terceras
    partes) está disponible un nuevo programa de soporte llamado
    <code class="program"><a href="./programs/apxs.html">apxs</a></code> (<em>APache eXtenSion</em>). Puede usar
    este programa para crear módulos como objetos dinámicos
    compartidos <em>sin tener que</em> crearlos al mismo tiempo que
    compila su servidor Apache. La idea es simple: cuando se instala
    Apache el procedimiento <code>make install</code> de
    <code class="program"><a href="./programs/configure.html">configure</a></code> @@@ installs the Apache C header
    files and puts the platform-dependent compiler and linker flags
    for building DSO files into the apxs program / instala los
    ficheros de cabecera de C de Apache y especifica las opciones de
    compilación y enlace dependientes de la plataforma para
    generar objetos dinámicos compartidos con
    <code class="program"><a href="./programs/apxs.html">apxs</a></code>. De esta manera el usuario puede usar
    <code class="program"><a href="./programs/apxs.html">apxs</a></code> para compilar el código fuente de
    módulos de Apache de manera independiente y sin tener que
    preocuparse por las opciones de compilación y enlace
    dependientes de la plataforma que soportan objetos dinámicos
    compartidos.</p>

</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="usage" id="usage">Resumen de uso</a></h2>

    <p>Para que se haga una idea de lo que permite el soporte de
    objetos dinámicos compartidos en Apache 2.0, aquí tiene
    un resumen breve pero conciso:</p>

    <ol>
      <li>
        Construir e instalar un módulo <em>incluido en la
        distribución</em> de Apache, digamos
        <code>mod_foo.c</code>, como un objeto dinámico
        compartido de nombre <code>mod_foo.so</code>:

<div class="example"><p><code>
$ ./configure --prefix=/path/to/install --enable-foo=shared<br />
$ make install
</code></p></div>
      </li>

      <li>
        Construir e instalar un módulo de Apache de una
        <em>tercera parte</em>, digamos <code>mod_foo.c</code>, como
        un objeto dinámico compartido de nombre
        <code>mod_foo.so</code>:

<div class="example"><p><code>
$ ./configure --add-module=module_type:/path/to/3rdparty/mod_foo.c --enable-foo=shared<br />
$ make install
</code></p></div>
      </li>

      <li>
        Configurar Apache para poder <em>instalar después</em>
        objetos dinámicos compartidos:

<div class="example"><p><code>
$ ./configure --enable-so<br />
$ make install
</code></p></div>
      </li>

      <li>
	Construir e instalar un módulo de Apache de una
        <em>tercera parte</em>, digamos <code>mod_foo.c</code>, como
        un objeto dinámico compartido de nombre
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
        dinámico compartido, debe usar una directiva <code class="directive"><a href="./mod/mod_so.html#loadmodule">LoadModule</a></code> en
        <code>httpd.conf</code> para activar dicho módulo.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="background" id="background">Fundamentos teoróricos
detrás de los objetos dinámicos compartidos</a></h2>

    <p>En las versiones modernas de Unix, existe un mecanismo
    especialmente útil normalmente llamado enlazado/carga de
    <em>Objetos Dinámicos Compartidos</em> (DSO). Este mecanismo
    ofrece una forma de construir trozos de código de programa en
    un formato especial para cargarlo en tiempo de ejecución en
    el espacio de direcciones de memoria de un programa
    ejecutable.</p>

    <p>Esta carga puede hacerse de dos maneras: automáticamente
    con un programa de sistema llamado <code>ld.so</code> al inicio de
    un programa ejecutable o manualmente desde dentro del programa en
    ejecución con una interfaz programática del sistema al
    cargador de Unix mediante llamadas al sistema
    <code>dlopen()/dlsym()</code>.</p>

    <p>Si se usa el primer método, los objetos dinámicos
        compartidos se llaman normalmente <em>librerías
        compartidas</em> ó <em>librerías DSO</em> y se
        nombran como <code>libfoo.so</code> o
        <code>libfoo.so.1.2</code>. Residen en un directorio de
        sistema (normalmente <code>/usr/lib</code>) y el enlace con el
        programa ejecutable se establece al construir la librería
        especificando la opción<code>-lfoo</code> al comando de
        enlace. Esto incluye las referencias literales a las
        librerías en el programa ejecutable de manera que cuando
        se inicie, el cargador de Unix será capaz de localizar
        <code>libfoo.so</code> en <code>/usr/lib</code>, en rutas
        referenciadas literalmente mediante opciones del linker como
        <code>-R</code> o en rutas configuradas mediante la variable
        de entorno <code>LD_LIBRARY_PATH</code>. Entonces se resuelven
        los símbolos (todavía no resueltos) en el programa
        ejecutable que están presentes en el objeto dinámico
        compartido.</p>

    <p>Los símbolos en el programa ejecutable no están
    referenciados normalmente en el objeto dinámico compartido
    (porque son librerías reusables de propósito general) y
    por tanto, no se producen más resoluciones. El programa
    ejecutable no tiene que hacer nada por sí mismo para usar los
    símbolos del objeto dinámico compartido porque todo el
    trabajo de resolución lo hace @@@ Unix loader / el cargador
    de Unix @@@. (De hecho, el código para invocar
    <code>ld.so</code> es parte del código que se ejecuta al
    iniciar, y que hay en cualquier programa ejecutable que haya sido
    construido de forma no estática). La ventaja de cargar
    dinámicamente el código de las librerías comunes es
    obvia: el código de las librerías necesita ser almacenado
    solamente una vez, en una librería de sistema como
    <code>libc.so</code>, ahorrando así espacio en disco.</p>

    <p>Por otro lado, los objetos dinámicos compartidos
        también suelen llamarse <em>objetos compatidos</em> o
        <em>ficheros DSO</em> y se les puede nombrar con cualquier
        extensión (aunque su nombre canónico es
        <code>foo.so</code>). Estos archivos normalmente permanecen
        dentro de un directorio específico del programa y no se
        establecen enlaces automáticamente con los programas
        ejecutables con los que se usan.  En lugar de esto, el
        programa ejecutable carga manualmente el objeto dinámico
        compartido en tiempo de ejecución en su espacio de
        direcciones de memoria con <code>dlopen()</code>. En ese
        momento no se resuelven los símbolos del objeto
        dinámico compartido para el programa ejecutable. En lugar
        de esto, el cargador de Unix resuelve automáticamente los
        símbolos (aún no resueltos en el objeto
        dinámico compartido del conjunto de símbolos
        exportados por el programa ejecutable y de las librerías
        DSO que tenga ya cargadas (especialmente todos los
        símbolos de la omnipresente <code>libc.so</code>). De
        esta manera el objeto dinámico compartido puede conocer
        el conjunto de símbolos del programa ejecutable como si
        hubiera sido enlazado estáticamente en un primer
        momento.</p>

    <p>Finalmente, para beneficiarse de la API de las DSOs, el
    programa ejecutable tiene que resolver los símbolos
    particulares de la DSO con <code>dlsym()</code> para ser usado
    más tarde dentro de tablas de direccionamiento (dispatch
    tables) <em>etc.</em> En otras palabras: El programa ejecutable
    tiene que resolver manualmente cada uno de los símbolos que
    necesita para poder usarlo después. La ventaja de ese
    mecanismo es que las partes opcionales del programa no necesitan
    ser cargadas (y por tanto no consumen memoria) hasta que se
    necesitan por el programa en cuestión. Cuando es necesario,
    estas partes del programa pueden cargarse dinámicamente para
    expandir las funcionalidades básicas del programa.</p>

    <p>Aunque este mecanismo DSO parece muy claro, hay al menos un
    paso de cierta dificultad: la resolución de los símbolos
    que usa el programa ejecutable por la DSO cuando se usa una DSO
    para extender la funcionalidad de una programa (segundo caso). Por
    qué? Porque la resolución inversa de símbolos de
    DSOs del conjunto de símbolos del programa ejecutable se hace
    en contra del diseño de la librería (donde la
    librería no tiene conocimiento sobre los programas que la
    usan) y tampoco está disponible en todas las plataformas no
    estandarizadas. En la práctica los símbolos globales del
    programa ejecutable están disponibles para su uso en una
    DSO. El mayor problema que hay que resolver cuando se usan DSOs
    para extender un programa en tiempo de ejecución es encontrar
    un modo de forzar al enlazador a exportar todos los símbolos
    globales.</p>

    <p>El enfoque de las librerías compartidas es bastante
    típico, porque es para lo que se diseño el mecanismo
    DSO, por tanto se usa para casi todos los tipos de librerías
    que incluye el sistema operativo. Por otro lado, no muchos
    programas usan objetos compartidos para expandir sus
    funcionalidades.</p>

    <p>En 1998, había solamente unos pocos programas disponibles
    que usaban el mecanismo DSO para extender su funcionalidad en
    tiempo de ejecucion: Perl 5 (por medio de su mecanismo XS y el
    módulo DynaLoader), Netscape Server, <em>etc.</em> A partir
    de la version 1.3, Apache se unió a este grupo, Apache usa
    desde entonces una concepción modular para extender su
    funcionalidad e internamente usa un enfoque de tablas de
    direccionamiento (dispatch-list-based) para enlazar módulos
    externos con las funcionalidades propias del servidor. De esta
    manera, Apache puede usar el mecanismo DSO para cargar sus
    módulos en tiempo de ejecución.</p>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif" /></a></div>
<div class="section">
<h2><a name="advantages" id="advantages">Ventajas e Inconvenientes</a></h2>

    <p>Las características de las librerías dinámicas
    compartidas arriba explicadas tienen las siguientes ventajas:</p>

    <ul>
      <li>El servidor es mucho más flexible en tiempo de
      ejecución porque pueden añadirse módulos mediante
      comandos de configuración <code class="directive"><a href="./mod/mod_so.html#loadmodule">LoadModule</a></code> en
      <code>httpd.conf</code> en lugar de tener que hacerlo con las
      opciones de <code class="program"><a href="./programs/configure.html">configure</a></code> al compilar. Por
      ejemplo, de esta manera uno puede ejecutar diferentes instancias
      del servidor (estándar &amp; SSL, mínima &amp; super
      potente [mod_perl, PHP3], <em>etc.</em>) con una única
      instalación de Apache.</li>

      <li>El servidor puede ser extendido fácilmente con
      módulos de terceras partes después de la
      instalación. Esto es un gran beneficio al menos para los
      mantenedores de paquetes de distribuciones, que pueden crear un
      paquete básico de Apache y paquetes adicionales que
      contengan extensiones tales como PHP3, mod_perl, mod_fastcgi,
      <em>etc.</em></li>

      <li>Facilita la labor de hacer prototipos de módulos de
      Apache porque con el dúo DSO/<code class="program"><a href="./programs/apxs.html">apxs</a></code> se
      puede trabajar fuera de la estructura de directorios de Apache y
      únicamente es necesario el comando <code>apxs -i</code>
      seguido del comando <code>apachectl restart</code> para probar
      la nueva versión del módulo que se está
      desarrollando.</li>
    </ul>

    <p>DSO presenta los siguientes inconvenientes:</p>

    <ul>
      <li>El mecanismo DSO no puede ser usado en todas las plataformas
      porque no todos los sistemas operativos soportan la carga
      dinámica de código en el espacio de direcciones de
      memoria de un programa.</li>

      <li>El servidor es aproximadamente un 20% más lento
      iniciándose por la sobrecarga que implica la
      resolución de símbolos por parte del cargador de Unix.</li>

      <li>El servidor es aproximadamente un 5% más lento
      ejecutándose en algunas plataformas porque el código
      posicionado independientemente (PIC) necesita algunas veces
      procesos bastante complicados para calcular direcciones
      relativas que no son en principio tan rápidos como los que
      se usan para calcular direcciones absolutas.</li>

      <li>Como los módulos DSO no pueden enlazarse a otras
      librerías basadas en DSO (<code>ld -lfoo</code>) en todas
      las plataformas (por ejemplo en las plataformas basadas en a.out
      normalmente no puede ser usada esta funcionalidad, mientras que
      sí puede ser usada en las plataformas basadas en ELF) no se
      puede usar el mecanismo DSO para todos los tipos de
      módulos. En otras palabras, los módulos compilados
      como ficheros DSO solamente pueden usar símbolos del
      núcleo (kernel) de Apache, los de las librerías de C
      (<code>libc</code>) y de todas las demas librerías
      dinámicas o estáticas usadas por el núcleo de
      Apache, o de archivos de librerías estáticas
      (<code>libfoo.a</code>) que contengan código independiente
      de su posición. Las únicas posibilidades para usar
      otro código es asegurarse de que el núcleo de Apache
      contiene una referencia a él o cargar el código por
      medio de <code>dlopen()</code>.</li>
    </ul>

</div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="./en/dso.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/dso.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="./fr/dso.html" hreflang="fr" rel="alternate" title="Français">&nbsp;fr&nbsp;</a> |
<a href="./ja/dso.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/dso.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a></p>
</div><div id="footer">
<p class="apache">Copyright 1995-2005 The Apache Software Foundation or its licensors, as applicable.<br />Licencia bajo los términos de la <a href="http://www.apache.org/licenses/LICENSE-2.0">Apache License, Version 2.0</a>.</p>
<p class="menu"><a href="./mod/">Módulos</a> | <a href="./mod/directives.html">Directivas</a> | <a href="./faq/">Preguntas Frecuentes</a> | <a href="./glossary.html">Glosario</a> | <a href="./sitemap.html">Mapa de este sitio web</a></p></div>
</body></html>