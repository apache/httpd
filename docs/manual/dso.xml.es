<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE manualpage SYSTEM "./style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="./style/manual.es.xsl"?>
<!-- English Revision: -->
<!-- Spanish translation : Daniel Ferradal -->

<!--
 Licensed to the Apache Software Foundation (ASF) under one or more
 contributor license agreements.  See the NOTICE file distributed with
 this work for additional information regarding copyright ownership.
 The ASF licenses this file to You under the Apache License, Version 2.0
 (the "License"); you may not use this file except in compliance with
 the License.  You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
-->

<manualpage metafile="dso.xml.meta">

  <title>Dynamic Shared Object (DSO) Support</title>

  <summary>
    <p>El Servidor HTTP Apache es un programa modular en el que el
    administrador puede elegir la funcionalidad a incluir en el
    servidor seleccionando un conjunto de módulos. Los módulos serán compilados 
    como Objetos Dinámicos Compartidos (DSOs) que existen por separado del fichero 
    binario de <program>httpd</program>. Los módulos DSO pueden ser generados en el 
    momento en que el servidor se compila, o pueden compilarse y añadirse 
    posteriormente usando la Herramienta de Extensión de Apache 
    (<program>apxs</program>).</p>

    <p>Alternativamente, los módulos se pueden compilar estáticamente en
    el binario <program>httpd</program> cuando se compila el servidor.</p>

    <p>Este documento describe cómo utilizar los módulos DSO, así como
    la teoría en la que se basan.
    </p>
  </summary>


<section id="implementation"><title>Implementación</title>

<related>
<modulelist>
<module>mod_so</module>
</modulelist>
<directivelist>
<directive module="mod_so">LoadModule</directive>
</directivelist>
</related>

    <p>El soporte DSO para cargar módulos httpd individuales de Apache se basa
    en un módulo llamado <module>mod_so</module> que debe estar compilado
    estáticamente en el núcleo de Apache httpd. Es el único módulo además de
    <module>core</module> que no puede ser puesto en DSO. Prácticamente todos 
    los demás módulos httpd distribuidos de Apache se
    colocarán en un DSO llamado <code>mod_foo.so</code> puede usar la <directive
    module="mod_so">LoadModule</directive> directive de <module>mod_so</module> en
    su fichero <code>httpd.conf</code> para cargar este módulo al iniciar el servidor
    o al reiniciar.</p>
    <p>Se pueden desactivar las construcciones DSO para módulos individuales con 
    la opción <program>configure</program> <code>--enable-mods-static</code>
    tal y como se comenta en la <a href="install.html">documentación de instalación</a>.</p>

    <p>Para simplificar esta creación de archivos DSO para módulos httpd de Apache
    (especialmente para módulos de terceros) un programa de apoyo
    llamado <program>apxs</program> (<dfn>APache
    eXtenSion</dfn>) está disponible. Se puede usar para generar
    módulos basados en DSO <em>fuera del </em> árbol de código fuente de Apache httpd. 
    La idea es sencilla: Cuando se instala el Servidor Apache HTTP el procedimiento 
    <code>make install</code> de <program>configure</program> instala los ficheros 
    de cabecera en C de Apache httpd y pone el compilador que depende de la plataforma y 
    los indicadores de enlazador para generar ficheros DSO en el programa 
    <program>apxs</program>. De esta manera el usuario puede usar <program>apxs</program> 
    para compilar sus fientes de módulos de Apache httpd sin el código fuente de la distribución
    de Apache httpd y sin tener que tratar con el compilador dependiente de plataforma y 
    indicadores de enlazador para el soporte de DSO.</p>
</section>

<section id="usage"><title>Usage Summary</title>

    <p>Para dar una visión general de las características DSO de Apache HTTP Server 2.x,
    aquí tenemos un resumen breve y conciso:</p>

    <ol>
      <li>
        <p>Build and install a <em>distributed</em> Apache httpd module, say
        <code>mod_foo.c</code>, into its own DSO
        <code>mod_foo.so</code>:</p>

<example>
$ ./configure --prefix=/path/to/install --enable-foo<br />
$ make install
</example>
      </li>

      <li>
      <p>Configura Apache HTTP Server con todos los módulos habilitados. Solo unos
      pocos de ellos se cargarán en el inicio del servidor. Se puede cambiar el conjunto
      de módulos cargados activando o desactivando la directiva <directive
      module="mod_so">LoadModule</directive> en
      <code>httpd.conf</code>.</p>

<example>
$ ./configure --enable-mods-shared=all<br />
$ make install
</example>
      </li>

      <li>
      <p>Algunos módulos sólo son útiles para desarrolladores y no se generarán.
      cuando se usa la opción de módulos <em>all</em>. Para generar todos los módulos
      disponibles incluyendo los de desarrolladorhay que usar <em>reallyall</em>. Además
      las directivas <directive module="mod_so">LoadModule</directive> para todos los
      módulos generados puede activarse a través de la opción de ¨configure¨
      <code>--enable-load-all-modules</code>.</p>

<example>
$ ./configure --enable-mods-shared=reallyall --enable-load-all-modules<br />
$ make install
</example>
      </li>

      <li>
        Genera e instala un módulo Apache HTTPD <em>de terceros</em>, convirtiendo
        <code>mod_foo.c</code>, en su propio DSO <code>mod_foo.so</code> 
        <em>fuera del</em> árbol de código de Apache httpd usando <program>apxs</program>:

<example>
$ cd /path/to/3rdparty<br />
$ apxs -cia mod_foo.c
</example>
      </li>
    </ol>

    <p>En todos los casos, una vez se ha compilado el módulo compartido, se debe usar
    una directiva <directive module="mod_so">LoadModule</directive>
    en <code>httpd.conf</code> para indicarle a Apache httpd que active el módulo.</p>

    <p>Ver la <a href="programs/apxs.html">documentacióin apxs</a> para más detalles.</p>
</section>

<section id="background"><title>Contexto</title>

    <p>En derivados modernos de Unix existe un mecanismo llamado
    enlace/carga dinámico de <em>Objetos Dinámicos Compartidos</em> 
    (DSO) que facilita una forma de generar una parte de código
    de programa en un formato espacial para cargar en tiempo real
    en el espacio de direcciones de un programa ejecutable.</p>

    <p>Esta carga generalmente se puede hacer de dos maneras: 
    automáticamente desde programa de sistema llamado <code>ld.so</code>
    cuando se arranca un programa ejecutable o manualmente desde dentro
    del programa que se ejecuta a través de un interfaz de sistema
    programático del cargador de Unix a través de las llamadas de sistema
    <code>dlopen()/dlsym()</code>.</p>

    <p>En la primera manera los DSO se llaman generalmente <em>librerías
    compartidas</em> o <em>librerías DSO</em> y llamadas
    <code>libfoo.so</code> o <code>libfoo.so.1.2</code>. Residen
    en un directorio del sistema (generalmente <code>/usr/lib</code>)
    y el enlace con el programa ejecutable se establece en tiempo de
    compilación especificando <code>-lfoo</code> al comando enlazador. 
    Esto codifica de forma rígida referencias de librería en el fichero de 
    programa ejecutable de manera que en el arranque el cargador Unix es 
    capaz de localizar <code>libfoo.so</code> en <code>/usr/lib</code>, en 
    rutas con codificación rígida a través de opciones-de-enlazador como
    <code>-R</code> o en rutas configuradas por variables de entorno 
    <code>LD_LIBRARY_PATH</code>. Entonces resuelve símbolos (todavía sin
    uresolver) en el programa ejecutable que están disponibles en el DSO.</p>

    <p>Los símbolos en el programa ejecutable no se referencian 
    generalmente por el DSO (porque es una biblioteca reutilizable de código 
    general) y, por lo tanto, no es necesario hacer más resolución. El programa 
    ejecutable no tiene necesidad de hacer nada por sí mismo para usar los 
    símbolos del DSO porque la resolución completa la realiza el cargador de 
    Unix. (De hecho, el código para invocar
    <code>ld.so</code> es parte del código de arranque en tiempo real que
    se enlaza dentro de cada programa ejecutable que se ha generado como 
    no-estático). La ventaja de la carga dinámica de librerías de código común
    es obvía: el código de librería necesita guardarse solo una vez,
    en un sistema de librería como <code>libc.so</code>, ahorrando espacio en 
    disco para cada programa.</p>

    <p>En la segunda manera los DSO se llaman generalmente <em>objetos
    compartidos</em> o <em>ficheros DSO</em> y pueden ser nombrados con una
    extensión aribtraria (aunque el nombre canónico es <code>foo.so</code>). 
    Estos ficheros generalmente permanencen dentro de un directorio de 
    programa específico y no hay enlace establecido automáticamente al 
    programaejecutable donde se están usando. En su lugar el programa ejecutable
    carga manualmente el DSO en tiempo-real en su espacio de direcciones a 
    través de <code>dlopen()</code>. En este momento no se realiza 
    resolución de símbolos del DSO para el programa ejecutable. Perp en
    su lugar se resuelve automáticamente cualquier (todavía sin resolver) 
    símbolo en el DSO del conjunto de símbolos exportado por el programa
    ejecutable y sus ya cargadas librerías DSO (especialmente todos los 
    símbolos del ubícuo <code>libc.so</code>). De esta forma el DSO obtiene
    conocimiento del símbolo del programa ejecutable como si hubiera servidor
    enlazado estáticamente dentro de él mismo en primer lugar.</p>

    <p>Por último, para aprovechar la API del DSO, el programa ejecutable
    tiene que resolver determinados símbolos de la DSO a través de
    <code>dlsym()</code> para su uso posterior dentro de las tablas de envío
    <em>etc.</em> En otras palabras: El programa ejecutable tiene que
    resolver manualmente cada símbolo que necesita para poder utilizarlo.
    La ventaja de este mecanismo es que no es necesario cargar las partes 
    opcionales del programa (y por lo tanto no gastan memoria) hasta que sean 
    necesarias para el programa en cuestión. Cuando se necesitan, estas partes 
    del programa se pueden cargar dinámicamente para ampliar la funcionalidad 
    del programa base.</p>

    <p>Aunque este mecanismo DSO parece sencillo, hay al menos un paso difícil: 
    La resolución de símbolos de del programa ejecutable para el DSO cuando se 
    usa un DSO para extender un programa (la segunda manera). ¿Por qué? Porque 
    la "resolución inversa" de símbolos DSO desde el conjunto de símbolos del 
    programa ejecutable va en contra del diseño de la biblioteca (donde la 
    biblioteca no tiene conocimiento de los programas que la utilizan) y no está 
    disponible en todas las plataformas ni está estandarizada. En la práctica, los 
    símbolos programa ejecutable a menudo no se reexportan y, por lo tanto, no están
    disponibles para su uso en un DSO. Encontrar una forma de forzar al enlazador
    a exportar todos los símbolos globales es el principal problema que uno tiene que
    resolver cuando se utiliza DSO para extender un programa en tiempo de ejecución.</p>

    <p>El método de librería compartida es el típico, porque es para lo que se 
    diseñó el mecanismo DSO, de ahí que se utilice para casi todos los tipos de 
    librerías que el sistema operativo proporciona.</p>

</section>

<section id="advantages"><title>Ventajas y Desventajas</title>

    <p>Las características anteriores basadas en DSO tienen las siguientes ventajas:</p>

    <ul>
      <li>El paquete del servidor es más flexible en tiempo-real porque el proceso
      del servidor puede ser cargado en tiempo-real mediante 
      <directive module="mod_so">LoadModule</directive>
      en directivas de configuración en <code>httpd.conf</code> en lugar de
      opciones de <program>configure</program> en tiempo de compilación. Por ejemplo,
      de esta manera pueden ejecutarse distintas instancias del servidor
      (standard &amp; versión SSL, minimalista &amp; versión dinámica
       [mod_perl, mod_php], <em>etc.</em>) son solo una instalación de Apache 
      httpd.</li>

      <li>El paquete del servidor se puede externder fácilmente con módulos de
      terceros incluso después de la instalación. Esto es un gran beneficio para los 
      es una gran ventaja para los mantenedores de paquetes de proveedores, los cuales
      pueden crear un paquete principal de Apache httpd y paquetes adicionales que 
      contengan extensiones como PHP, mod_perl, mod_security, <em>etc.</em></li>

      <li>Creación más sencilla de prototipos de módulos httpd de Apache, porque
      con la pareja DSO/<program>apxs</program> puedes trabajar fuera del 
      árbol de código fuente de Apache httpd y solo necesitar un comando
      <code>apxs -i</code> seguido de un <code>apachectl restart</code> para
      traer una nueva versión de tu módulo recien desarrollado a un servidor
      Apache HTTP que ya está funcionando.</li>
    </ul>

    <p>DSO tiene las siguientes desventajas:</p>

    <ul>
      <li>El servidor es aproximadamente un 20% más lento en el arranque por
      la sobrecarga de resolución de símbolos que el cargador de Unix tiene 
      que realizar.</li>

      <li>El servidor es aproximadamente un 5% más lento en tiempo de ejecución
      en ciertas plataformas porque el código independiente de positición (PIC)
      a veces necesita realizar trucos complicados de para asignar direcciones, 
      que no son necesariamente tan rápidos como el direccionamiento absoluto.</li>

      <li>Porque los módulos DSO no pueden enlazarse a otras librerías basadas en
      DSO (<code>ld -lfoo</code>) en todas las plataformas (por ejemplo las
      plataformas basadas en a.out generalmente no proveen esta funcionalidad 
      mientras que las plataformas basadas en ELF si) no se puede usar el macanismo
      DSO para todos los tipos de módulos. O en otras palabras, los módulos compilados
      como ficheros DSO están restringidos a símbolos del núcleo de Apache httpd, de
      la librería C (<code>libc</code>) y todas las demás librerías estáticas o 
      dinámicas utilizadas por el nucleo de Apache httpd, o por los archivos de 
      librería estática (<code>libfoo.a</code>) que contienen código independiente de
      posición. Las únicas oportunidades de usar otro código es usar otro núcleo del 
      mismo httpd que previamente contenga una referencia a ellas o si carga el código
      usted mismo a través de <code>dlopen()</code>.</li>
    </ul>

</section>

</manualpage>
