<?xml version='1.0' encoding='UTF-8' ?>
<!DOCTYPE manualpage SYSTEM "./style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="./style/manual.es.xsl"?>
<!-- English Revision: 105989:952009 (outdated) -->

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

<manualpage metafile="install.xml.meta">

  <title>Compilaci&#243;n e Instalaci&#243;n</title>

<summary>

    <p>Este documento explica c&#243;mo compilar e instalar Apache en
    sistemas Unix y tipo Unix. Para obtener informaci&#243;n sobre
    c&#243;mo compilar e instalar en Windows, consulte la secci&#243;n
    <a href="platform/windows.html">Usar Apache en Microsoft
    Windows</a>. Para otras plataformas, consulte la
    documentaci&#243;n sobre <a href="platform/">plataformas</a>.</p>

    <p>El entorno de configuraci&#243;n e instalaci&#243;n de Apache
    2.0 ha cambiado completamente respecto al de Apache 1.3. Apache
    1.3 usaba un conjunto de scripts a medida para conseguir una
    instalaci&#243;n f&#225;cil. Apache 2.0 usa <code>libtool</code> y
    <code>autoconf</code> para crear un entorno m&#225;s parecido al
    de muchos otros proyectos Open Source.</p>
    
    <p>Si lo que quiere hacer es actualizar su servidor Apache desde
    una versi&#243;n menor (por ejemplo, desde la 2.0.50 a la 2.0.51),
    pase directamente a la secci&#243;n de <a
    href="#upgrading">actualizaci&#243;n</a>.</p>

</summary>

<seealso><a href="programs/configure.html">Configuraci&#243;n de la
estructura de directorios</a></seealso> <seealso><a
href="invoking.html">Iniciar Apache</a></seealso> <seealso><a
href="stopping.html">Parar y reiniciar Apache</a></seealso>

<section id="overview"><title>Visi&#243;n general del proceso para
    impacientes</title>

    <table>
      <columnspec><column width=".13"/><column
      width=".80"/></columnspec>
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
        <td><a href="#test">Comprobar que la instalaci&#243;n
        funciona</a></td>

        <td><code>$ <em>PREFIX</em>/bin/apachectl start</code>
        </td>
      </tr>
    </table>

    <p><em>NN</em> hay que reemplazarlo por el n&#250;mero de la
    versi&#243;n menor, y <em>PREFIX</em> hay que reemplazarlo por la
    ruta en la que se va a instalar Apache. Si no especifica
    ning&#250;n valor en <em>PREFIX</em>, el valor por defecto que se
    toma es <code>/usr/local/apache2</code>.</p>

    <p>Cada parte del proceso de configuraci&#243;n e instalaci&#243;n
    se describe detalladamente m&#225;s abajo, empezando por los
    requisitos para compilar e instalar Apache.</p>
</section>

<section id="requirements"><title>Requisitos</title>

    <p>Estos son los requisitos necesarios para compilar Apache:</p>
  
    <dl>
      <dt>Espacio en disco</dt> <dd>Compruebe que tiene disponibles al
      menos 50 MB de espacio libre en disco. Despu&#233;s de la
      instalaci&#243;n, Apache ocupa aproximadamente 10 MB. No
      obstante, la necesidad real de espacio en disco var&#237;a
      considerablemente en funci&#243;n de las opciones de
      configuraci&#243;n que elija y de los m&#243;dulos externos que
      use.</dd>

      <dt>Compilador ANSI-C y Build System</dt> <dd>Compruebe que
      tiene instalado un compilador de ANSI-C. Se recomienda el <a
      href="http://www.gnu.org/software/gcc/gcc.html">Compilador GNU C
      (GCC)</a> de la <a href="http://www.gnu.org/">Free Software
      Foundation (FSF)</a> (con la versi&#243;n 2.7.2 es
      suficiente). Si no tiene instaldo el GCC, entonces compruebe que
      el compilador que va a utilizar cumple con los est&#225;ndares
      ANSI. Adem&#225;s, su <code>PATH</code> debe contener la
      ubicaci&#243;n donde de encuentran las herramientas b&#225;sicas
      para compilar tales como <code>make</code>.</dd>

      <dt>Ajuste exacto del reloj del sistema</dt> <dd>Los elementos
      del protocolo HTTP est&#225;n expresados seg&#250;n la hora del
      dia. Por eso, si quiere puede investigar como instalar alguna
      utilidad para sincronizar la hora de su sistema. Para esto,
      normalmente, se usan los programas <code>ntpdate</code> o
      <code>xntpd</code>, que est&#225;n basados en el protocolo
      Network Time Protocol (NTP). Consulte el grupo de noticias <a
      href="news:comp.protocols.time.ntp">comp.protocols.time.ntp</a>
      y el <a href="http://www.eecis.udel.edu/~ntp/">sitio web de NTP
      </a> para obtener m&#225;s informaci&#243;n sobre NTP y los
      servidores p&#250;blicos de tiempo.</dd>

      <dt><a href="http://www.perl.org/">Perl 5</a> [OPCIONAL]</dt>
      <dd>Para algunos de los scripts de soporte como <a
      href="programs/apxs.html">apxs</a> o <a
      href="programs/dbmmanage.html">dbmmanage</a> (que est&#225;n
      escritos en Perl) es necesario el int&#233;rprete de Perl 5 (las
      versiones 5.003 o posteriores son suficientes). Si el script
      `<code>configure</code>' no encuentra ese int&#233;rprete
      tampoco pasa nada. A&#250;n puede compilar e instalar Apache
      2.0. Lo &#250;nico que ocurrir&#225; es que esos scripts de
      soporte no podr&#225;n ser usados. Si usted tiene varios
      interpretes de Perl instalados (quiz&#225;s Perl 4 porque estaba
      ya incluido en su distribuci&#243;n de Linux y Perl 5 porque lo
      ha instalado usted), entonces se recomienda usar la opci&#243;n
      <code>--with-perl</code> para asegurarse de que
      <code>./configure</code> usa el int&#233;rprete correcto.</dd>
    </dl>
</section>

<section id="download"><title>Descargar</title>

    <p>Puede descargar Apache desde <a
    href="http://httpd.apache.org/download.cgi">la secci&#243;n de
    descargas del sitio web de Apache</a> el cual tiene varios
    mirrors. Para la mayor&#237;a de los usuarios de Apache que tienen
    sistemas tipo Unix, se recomienda que se descarguen y compilen el
    c&#243;digo fuente. El proceso de compilaci&#243;n (descrito
    m&#225;s abajo) es f&#225;cil, y permite adaptar el servidor
    Apache a sus necesidades. Adem&#225;s, las versiones de
    disponibles en archivos binarios no est&#225;n siempre actulizadas
    con las &#250;ltimas modificaciones en el codigo fuente. Si se
    descarga un binario, siga las instrucciones contenidas en el
    archivo <code>INSTALL.bindist</code> incluido en la
    distribuci&#243;n</p>

    <p>Despu&#233;s de la descarga, es importante que verifique que el
    archivo descargado del servidor HTTP Apache est&#225; completo y
    sin modificaciones.  Esto puede hacerlo comparando el archivo
    descargado (.tgz) con su firma PGP. Instrucciones detalladas de
    c&#243;mo hacer esto est&#225;n disponibles en <a
    href="http://httpd.apache.org/download.cgi#verify"> la
    secci&#243;n de descargas</a> junto con un ejemplo de c&#243;mo <a
    href="http://httpd.apache.org/dev/verification.html">usar
    PGP</a>.</p>
 
</section>

<section id="extract"><title>Descomprimir</title>

    <p>Extraer el c&#243;digo fuente del archivo .tgz que acabada de
    descargar es muy f&#225;cil. Ejecute los siguientes comandos:</p>

<example>
      $ gzip -d httpd-2_1_<em>NN</em>.tar.gz<br />
       $ tar xvf httpd-2_1_<em>NN</em>.tar
</example>

    <p>Estos comandos crear&#225;n un nuevo directorio dentro del
    directorio en el que se encuentra y que contendr&#225; el
    c&#243;digo fuente de la distribuci&#243;n. Debe cambiarse a ese
    directorio con <code>cd</code> para proceder a compilar el
    servidor Apache.</p>

</section>

<section id="configure"><title>Configuraci&#243;n de la estructura de
directorios</title>

    <p>El siguiente paso es configurar la estructura de directorios
    para su plataforma y sus necesidades personales. Esto se hace
    usando el script <code>configure</code> incluido en el directorio
    raiz de la distribuci&#243;n que acaba de descargar. (Los
    desarrolladores que se descarguen la versi&#243;n del CVS de la
    estructura de directorios necesitar&#225;n tener instalados
    <code>autoconf</code> y <code>libtool</code>, y necesitar&#225;n
    ejecutar <code>buildconf</code> antes de continuar con los
    siguientes pasos. Esto no es preciso para las versiones
    oficiales.)</p>

    <p>Para configurar la estructura de directorios a partir del
    c&#243;digo fuente usando las opciones por defecto, solo tiene que
    ejecutar <code>./configure</code>. Para cambiar las opciones por
    defecto, <code>configure</code> acepta una serie de variables y
    opciones por la l&#237;nea de comandos.</p>

    <p>La opci&#243;n m&#225;s importante es <code>--prefix</code> que
    es el directorio en el que Apache va a ser instalado despu&#233;s,
    porque Apache tiene que ser configurado para el directorio que se
    especifique para que funcione correctamente.  Es posible lograr un
    mayor control del lugar donde se van a instalar los ficheros de
    Apache con otras <a
    href="programs/configure.html#installationdirectories">opciones de
    configuraci&#243;n</a>.</p>

    <p>En este momento, puede especificar que <a
    href="programs/configure.html#optionalfeatures">caracter&#237;sticas
    o funcionalidades</a> quiere incluir en Apache activando o
    desactivando <a href="mod/">m&#243;dulos</a>.  Apache viene con
    una <a href="mod/module-dict.html#Status">selecci&#243;n
    b&#225;sica</a> de m&#243;dulos incluidos por defecto.  Se pueden
    activar otros m&#243;dulos usando la opci&#243;n
    <code>--enable-<var>module</var></code>, donde <var>module</var>
    es el nombre del m&#243;dulo sin el <code>mod_</code> y
    convirtiendo los guiones bajos que tenga en guiones normales.
    Tambi&#233;n puede optar por compilar m&#243;dulos como <a
    href="dso.html">objetos din&#225;micos compartidos (DSOs)</a> --
    que pueden ser activados o desactivados al ejecutar -- usando la
    opci&#243;n <code>--enable-<var>module</var>=shared</code>.  De
    igual manera, puede desactivar alguno de los m&#243;dulos que
    vienen por defecto en la selecci&#243;n basica con la opci&#243;n
    <code>--disable-<var>module</var></code>.  Tenga cuidado cuando
    use estas opciones, porque <code>configure</code> no le
    avisar&#225; si el m&#243;dulo que especifica no existe;
    simplemente ignorar&#225; esa opci&#243;n.</p>

    <p>Adem&#225;s, a veces es necesario pasarle al script
    <code>configure</code> informaci&#243;n adicional sobre donde esta
    su compilador, librerias o ficheros de cabecera.  Esto se puede
    hacer, tanto pasando variables de entorno, como pasandole opciones
    a <code>configure</code> a trav&#233;s de la l&#237;nea de
    comandos.  Para m&#225;s informaci&#243;n, consulte el <a
    href="programs/configure.html">Manual del script
    configure</a>.</p>

    <p>Para que se haga una idea sobre las posibilidades que tiene,
    aqu&#237; tiene un ejemplo t&#237;pico que configura Apache para
    la ruta <code>/sw/pkg/apache</code> con un compilador y unos flags
    determinados, y adem&#225;s, con dos m&#243;dulos adicionales
    <module>mod_rewrite</module> y <module>mod_speling</module> para
    cargarlos despu&#233;s a trav&#233;s del mecanismo DSO:</p>

<example>
      $ CC="pgcc" CFLAGS="-O2" \<br />
       ./configure --prefix=/sw/pkg/apache \<br />
       --enable-rewrite=shared \<br />
       --enable-speling=shared
</example>

    <p>Cuando se ejecuta <code>configure</code> se comprueban que
    caracter&#237;sticas o funcionalidades est&#225;n disponibles en
    su sistema y se crean los Makefiles que ser&#225;n usados luego
    para compilar el servidor. Esto tardar&#225; algunos minutos.</p>

    <p>La informaci&#243;n sobre todas las opciones de
    <code>configure</code> est&#225; disponible en el <a
    href="programs/configure.html">Manual del script
    configure</a>.</p>

</section>

<section id="compile"><title>Compilar</title>

    <p>Ahora puede compilar las diferentes partes que forman Apache
    simplemente ejecutando el siguiente comando:</p>

<example>$ make</example>

    <p>Por favor, tanga un poco de paciencia ahora, porque una
    configuraci&#243;n b&#225;sica tarda aproximadamente 3 minutos en
    compilar en un Pentium III con un sistema Linux 2.2, pero este
    tiempo puede variar considerablemente en funci&#243;n de su
    hardware y del n&#250;mero de m&#243;dulos que haya
    seleccionado.</p>
</section>

<section id="install"><title>Instalar</title>

    <p>Ahora es el momento de instalar el paquete en el diretorio
    elegido en <em>PREFIX</em> (consulte la opci&#243;n
    <code>--prefix</code> m&#225;s arriba) ejecutando:</p>

<example>$ make install</example>

    <p>Si usted est&#225; solo actualizando una instalaci&#243;n
    anterior, la nueva instalaci&#243;n no sobreescribir&#225; sus
    ficheros de configuraci&#243;n ni otros documentos.</p>
</section>

<section id="customize"><title>Personalizar</title>

    <p>El paso siguiente, es personalizar su servidor Apache editando
    los <a href="configuring.html">ficheros de configuraci&#243;n</a>
    que est&#225;n en <code><em>PREFIX</em>/conf/</code>.</p>

<example>$ vi <em>PREFIX</em>/conf/httpd.conf</example>

    <p>&#233;chele un vistazo al Manual de Apache que est&#225; en <a
    href="./">docs/manual/</a> o consulte en <a
    href="http://httpd.apache.org/docs/&httpd.docs;/"
    >http://httpd.apache.org/docs/&httpd.docs;/</a> la versi&#243;n m&#225;s
    reciente de este manual y la Guia de Referencia de todas las <a
    href="mod/directives.html">directivas de configuraci&#243;n</a>
    disponibles.</p>
</section>

<section id="test"><title>Comprobar que la instalaci&#243;n
funciona</title>

    <p>Ahora puede <a href="invoking.html">iniciar</a> su servidor
    Apache cuando quiera ejecutando:</p>

<example>$ <em>PREFIX</em>/bin/apachectl start</example>

    <p>y entonces debe poder acceder al documento que tenga
    especificado por defecto usando el siguiente URL:
    <code>http://localhost/</code>. El documento que ver&#225;
    estar&#225; en <directive module="core">DocumentRoot</directive> y
    casi siempre estar&#225; en <code><em>PREFIX</em>/htdocs/</code>.
    Si quiere <a href="stopping.html">parar</a> el servidor, puede
    hacerlo ejecutando:</p>

<example>$ <em>PREFIX</em>/bin/apachectl stop</example>
</section>
<section id="upgrading"><title>Actualizar una instalaci&#243;n
prrevia</title>

    <p>El primer paso para actualizar una instalaci&#243;n anterior es
    leer las especificaciones de la versi&#243;n y el fichero
    <code>CHANGES</code> en la distribuci&#243;n de c&#243;digo fuente
    que ha descargado para encontrar los cambios que puedan afectar a
    su instalaci&#243;n actual. Cuando el cambio sea entre versiones
    mayores (por ejemplo, de la 1.3 a la 2.0 o de la 2.0 a la 2.2),
    entonces es m&#225;s probable que haya diferencias importantes en
    la compilaci&#243;n y en la ejecuci&#243;n que necesitar&#225;n
    ajustes manuales. Todos los m&#243;dulos necesitar&#225;n
    tambi&#233;n ser actualizados para adaptarse a los cambios en el
    interfaz de programaci&#243;n (API) de m&#243;dulos.</p>

    <p>La actualizaci&#243;n cuando el cambio es entre versiones
    menores (por ejemplo, de la 2.0.55 a la 2.0.57) es m&#225;s
    f&#225;cil.  El proceso <code>make install</code> no
    sobreescribir&#225; ninguno de los documentos existentes, archivos
    log, o archivos de configuraci&#243;n.  Adem&#225;s, los
    desarrolladores hacen todos los esfuerzos posibles para evitar
    cambios que generen incompatibilidades en las opciones de
    <code>configure</code>, en la configuraci&#243;n de la
    ejecuci&#243;n o en la interfaz de programaci&#243;n de
    m&#243;dulos. En la mayor parte de los casos debe poder usar un
    comando <code>configure</code> id&#233;ntico, un fichero de
    configuraci&#233;n id&#233;ntico, y todos sus m&#243;dulos deben
    seguir funcionando.  (Esto es v&#225;lido solo para versiones
    posteriores a la 2.0.41; las versiones anteriores contienen
    cambios incompatibles.)</p>

    <p>Si va a conservar la estructura de directorios de su anterior
    instalaci&#243;n, la actualizaci&#243;n es m&#225;s f&#225;cil
    incluso.  El fichero <code>config.nice</code> que est&#225; en el
    directorio raiz de la estructura de directorios antigua contiene
    exactamente el comando <code>configure</code> que usted us&#243;
    para configurar la estructura de directorios de Apache.  Entonces,
    para actualizar su instalaci&#243;n de una vers&#243;on a la
    siguinete, solo tiene que copiar el archivo
    <code>config.nice</code> a la estructura de directorios del
    c&#243;digo fuente de la nueva versi&#243;n, editarlo, hacer
    cualquier cambio que desee, y ejecutarlo :</p>

    <example>
    $ ./config.nice<br />
    $ make<br />
    $ make install<br />
    $ <em>PREFIX</em>/bin/apachectl stop<br />
    $ <em>PREFIX</em>/bin/apachectl start<br />
    </example>

    <note type="warning">Tenga en cuenta que antes de poner una nueva
    versi&#243;n de Apache en producci&#243;n, debe siempre probarla
    antes en su entorno. Por ejemplo, puede instalar y ejecutar la
    nueva versi&#243;n junto con la antigua usando un
    <code>--prefix</code> diferente y un puerto diferente (modificando
    la directiva <directive module="mpm_common">Listen</directive>)
    para comprobar que no existe ninguna incompatibilidad antes de
    hacer la actualizaci&#243;n definitiva.</note>
</section>
</manualpage>

