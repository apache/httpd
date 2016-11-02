<?xml version='1.0' encoding='UTF-8' ?>
<!DOCTYPE manualpage SYSTEM "../style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1751930 -->
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

<manualpage metafile="cgi.xml.meta">
	<parentdocument href="./">How-To / Tutoriales</parentdocument>
	<title>Tutorial de Apache: Contenido Dinámico con CGI</title>
	
    <section id="intro">
	    <title>Introducción</title>
		<related>
			<modulelist>
		        <module>mod_alias</module>
		        <module>mod_cgi</module>
		        <module>mod_cgid</module>
			</modulelist>

			<directivelist>
				<directive module="mod_mime">AddHandler</directive>
       			<directive module="core">Options</directive>
       			<directive module="mod_alias">ScriptAlias</directive>
    		</directivelist>
    	</related>

    	<p>CGI (Common Gateway Interface) es un método por el cual
		un servidor web puede interactuar con programas externos de 
		generación de contenido, a ellos nos referimos comúnmente como 
		programas CGI o scripts CGI. Es el método más común y sencillo de
        mostrar contenido dinámico en su sitio web. Este documento es una 
		introducción para configurar CGI en su servidor web Apache, y de
		iniciación para escribir programas CGI.</p>
	</section>

	<section id="configuring">
		<title>Configurando Apache para permitir CGI</title>

        <p>Para conseguir que sus programas CGI funcionen correctamente,
	    deberá configurar Apache para que permita la ejecución de CGI. Hay
	    distintas formas de hacerlo.</p>

        <note type="warning">Nota: Si Apache ha sido compilado con soporte
        de módulos compartidos, necesitará que el módulo de CGI esté cargado;
        en su <code>httpd.conf</code> tiene que asegurarse de que la directiva
        <directive module="mod_so">LoadModule</directive>
        no ha sido comentada. Una directiva configurada correctamente sería así:
            
            <highlight language="config">
                LoadModule cgid_module modules/mod_cgid.so
            </highlight>

        En Windows, o si usa un mpm que no es multihilo, como prefork, una 
        directiva configurada correctamente podría definirse así: 

        <highlight language="config">
            LoadModule cgi_module modules/mod_cgi.so
        </highlight></note>

        <section id="scriptalias">
            <title>ScriptAlias</title>

            <p>La directiva
            <directive module="mod_alias">ScriptAlias</directive>
            indica a Apache que un directorio se ha configurado específicamente
            para programas CGI. Apache asumirá que cada fichero en este 
            directorio es un programa CGI, e intentará ejecutarlos cuando un
            cliente solicita este recurso.</p>
        
            <p>La directiva 
            <directive module="mod_alias">ScriptAlias</directive> se puede 
            definir así:</p>

            <highlight language="config">
                ScriptAlias "/cgi-bin/" "/usr/local/apache2/cgi-bin/"
            </highlight>
        
            <p>El ejemplo que se muestra es de un archivo de configuración
            <code>httpd.conf</code> por defecto si usted instaló Apache
            en la ubicación por defecto. La directiva
            <directive module="mod_alias">ScriptAlias</directive> es muy 
            parecida a la directiva <directive module="mod_alias">Alias</directive>,
            ésta define un prefijo de URL que se enlaza a un directorio 
            en particular. <directive>Alias</directive> y
            <directive>ScriptAlias</directive> se usan generalmente para 
            directorios que se encuentran fuera del directorio 
            <directive module="core">DocumentRoot</directive>. La diferencia
            entre <directive>Alias</directive> y <directive>ScriptAlias</directive>
            es que en <directive>ScriptAlias</directive> cualquier elemento
            debajo de ese prefijo de URL será considerado un programa CGI. Así, 
            el ejemplo de más arriba le indica a Apache que
            cualquier solicitud para un recurso que comience con 
            <code>/cgi-bin/</code> debería servirse desde el directorio
            <code>/usr/local/apache2/cgi-bin/</code>, y debería tratarse como un
            programa CGI.</p>

            <p>Por ejemplo, si se solicita la URL
            <code>http://www.example.com/cgi-bin/test.pl</code>,
            Apache intentará ejecutar el archivo
            <code>/usr/local/apache2/cgi-bin/test.pl</code> y dar
            el resultado. Por supuesto el archivo debe existir y ser ejecutable, 
            y dar el resultado de una manera específica o Apache devolverá
            un mensaje de error.</p>
        </section>

        <section id="nonscriptalias">
            <title>CGI fuera de directorios ScriptAlias</title>

            <p>Los programas CGI habitualmente se restringen a los directorios de
            <directive module="mod_alias">ScriptAlias</directive> por razones de
            seguridad. De esta manera, los administradores pueden controlar de una
            manera más segura quien puede ejecutar programas CGI. Aun así, si no
            se toman suficientes precauciones, no hay ninguna razón por la que
            programas CGI no se puedan ejecutar desde directorios seleccionados de 
            manera arbitraria. Por ejemplo, quizás quiera permitir que usuarios del
            sistema tengan contenido web en sus directorios home con la directiva
            <directive module="mod_userdir">UserDir</directive>. Si quieren 
            tener sus propios programas CGI, pero no tienen acceso al directorio 
            principal <code>cgi-bin</code>, necesitarán ser capaces de 
            ejecutar sus scripts CGI en algún otro sitio.</p>
      
            <p>Hay dos pasos a seguir para permitir la ejecución CGI en directorios
            seleccionados de manera arbitraria. Primero, el handler 
            <code>cgi-script</code> debe estar activado usando la directiva 
            <directive module="mod_mime">AddHandler</directive> o la directiva 
            <directive module="core">SetHandler</directive>. Segundo, el parámetro
            <code>ExecCGI</code> debe estar definido en la directiva
            <directive module="core">Options</directive>.</p>
        </section>

        <section id="options">
            <title>Usando Options de manera explícita para permitir ejecución de 
            CGI</title>

            <p>Puede usar la directiva 
            <directive module="core">Options</directive>, en el archivo de 
            configuración principal para especificar que se permite la ejecución 
            de CGI en un directorio en particular:</p>

            <highlight language="config">
&lt;Directory "/usr/local/apache2/htdocs/somedir"&gt;
    Options +ExecCGI
&lt;/Directory&gt;
            </highlight>
            
            <p>Esta directiva de aquí arriba le indica a Apache que debe 
            permitir la ejecución de archivos CGI. También necesitará indicarle 
            al servidor que los archivos son archivos CGI. La directiva 
            <directive module="mod_mime">AddHandler</directive> le indica al 
            servidor que debe tratar a todos los archivos con la extensión 
            <code>cgi</code> o <code>pl</code> como programas CGI:</p>

            <highlight language="config">
                AddHandler cgi-script .cgi .pl
            </highlight>
        </section>

        <section id="htaccess">
            <title>Ficheros .htaccess</title>

            <p>El <a href="htaccess.html">tutorial <code>.htaccess</code></a>
            enseña como activar programas CGI si no tienes acceso a 
            <code>httpd.conf</code>.</p>
        </section>

        <section id="userdir">
            <title>Directorios de Usuario</title>

            <p>Para permitir la ejecución de programas CGI para cualquier 
            archivo que acabe en <code>.cgi</code> en directorios de usuario, 
            puedes usar la siguiente configuración:</p>

            <highlight language="config">
&lt;Directory "/home/*/public_html"&gt;
    Options +ExecCGI
    AddHandler cgi-script .cgi
&lt;/Directory&gt;
            </highlight>

            <p>Si quiere designar un subdirectorio <code>cgi-bin</code> dentro 
            de un directorio de usuario en el que todos los ficheros serán 
            tratados como un programa CGI, puede usar lo siguiente:</p>

            <highlight language="config">
&lt;Directory "/home/*/public_html/cgi-bin"&gt;
    Options ExecCGI
    SetHandler cgi-script
&lt;/Directory&gt;
            </highlight>
        </section>
    </section>

    <section id="writing">
        <title>Escribiendo un programa CGI</title>

        <p>Hay dos diferencias principales entre programación ``regular'' y 
        programación en CGI.</p>

        <p>Primera, el resultado al completo de tu programa CGI debe estar 
        precedido de una cabecera <glossary>MIME-type</glossary>. Esta
        cabecera HTTP le indica al cliente que tipo de contenido está
        recibiendo. La mayor parte de las veces, ésto será algo como:</p>

        <example>
            Content-type: text/html
        </example>

        <p>Segunda, el resultado debe estar en formato HTML, o cualquier 
        otro formato que su navegador sea capaz de mostrar. La mayor
        parte de las veces, será HTML, pero otras escribirá un programa
        CGI que devuelve una imagen gif, u otro contenido no-HTML.</p>

        <p>Aparte de estas dos cosas, escribir un programa en CGI se 
        parecerá bastante a cualquier otro programa que vaya a escribir.
        </p>


        <section id="firstcgi">
            <title>Su primer programa CGI</title>

            <p>A continuación podrá ver un ejemplo de programa CGI que muestra
            una línea de texto en su navegador. Escriba lo siguiente, 
            guárdelo en un archivo con el nombre <code>first.pl</code>, y 
            póngalo en su directorio <code>cgi-bin</code>.</p>

            <highlight language="perl">
#!/usr/bin/perl
print "Content-type: text/html\n\n";
print "Hola, Mundo.";
            </highlight>

            <p>Incluso si Perl no le resulta familiar, podrá ver lo que está
            ocurriendo aquí. La primera línea le dice a Apache (o a
            cualquier shell en la que se esté ejecutando) que este programa
            puede ejecutarse con el intérprete en la ubicación
            <code>/usr/bin/perl</code>. La segunda línea imprime la
            declaración de Content-Type que mencionamos antes, seguida de 
            dos pares de retornos de carro. Esto pone una línea en blanco 
            después de la cabecera para indicar el final de las cabeceras
            HTTP, y el comienzo del cuerpo del contenido. La tercera 
            imprime la cadena de caracteres "Hola, Mundo.". Y ese es el 
            final del programa.</p>

            <p>Si lo abre con su navegador favorito y le dice que solicite la 
            dirección</p>

            <example>
                http://www.example.com/cgi-bin/first.pl
            </example>

            <p>o donde quiera que pusiera el archivo, verá una línea
            <code>Hola, Mundo.</code> aparecerán la ventana del navegador. No es 
            muy emocionante, pero una vez que consiga que funcione podrá hacer 
            lo mismo con casi cualquier programa.</p>
        </section>
    </section>

    <section id="troubleshoot">
        <title>¡Pero todavía no funciona!</title>

        <p>Hay 4 cosas básicas que puede llegar a ver en su navegador cuando
        intenta acceder a un programa CGI desde la web:</p>

        <dl>
            <dt>El resultado del programa CGI</dt>
            <dd>¡Genial! Esto indica que todo funcionó correctamente. Si el
            resultado es correcto, pero el navegador no lo procesa
            correctamente, asegúrese de que tiene especificado 
            correctamente el <code>Content-Type</code> en su programa 
            CGI.</dd>

            <dt>El código fuente de su programa CGI o un mensaje del tipo 
            "POST Method Not Allowed".</dt>

            <dd>Eso significa que no ha configurado Apache de manera
            apropiada para interpretar su programa CGI. Relea la sección
            de <a href="#configuring">Configurando Apache</a> e intente
            encontrar qué le falta.</dd>

            <dt>Un mensaje que empieza con "Forbidden"</dt>
            <dd>Eso significa que hay un problema de permisos. Compruebe el
            <a href="#errorlogs">Log de Errores de Apache</a> y la
            sección de más abajo de <a href="#permissions">Permisos de
            Fichero</a>.</dd>

            <dt>Un mensaje indicando "Internal Server Error"</dt>
            <dd>Si comprueba el <a href="#errorlogs">Log de errores de
            Apache</a>, probablemente encontrará que indica "Premature 
            end of script headers", posiblemente acompañado de otro 
            mensaje de error generado por su programa CGI. En este caso, 
            querrá comprobar cada una de las secciones de más adelante 
            para ver qué impide que su programa CGI genere las cabeceras 
            HTTP adecuadas.</dd>
            </dl>

        <section id="permissions">
            <title>Permisos de Fichero</title>

            <p>Recuerde que el servidor no se ejecuta con su usuario. Es decir,
            cuando el servidor arranca, está funcionando con un usuario sin
            privilegios, generalmente el usuario <code>nobody</code>, o
            <code>www-data</code>, así que necesitará permisos extra para
            ejecutar los archivos de los que usted es dueño. Generalmente, 
            el método para dar permisos suficientes para que se pueda 
            ejecutar con <code>nobody</code> es dar permisos de ejecución a 
            todo el mundo en el fichero:</p>

            <example>
                chmod a+x first.pl
            </example>

            <p>Además, si su programa lee desde o escribe a cualquier otro/s
            archivo/s, esos archivos necesitarán tener los permisos correctos
            para permitir esas acciones.</p>

        </section>

        <section id="pathinformation">
            <title>Información de Ruta y Entorno</title>

            <p>Cuando ejecuta un programa desde la línea de comandos, usted tiene
            cierta información que se le pasa a la shell sin que usted se
            percate de ello. Por ejemplo, usted tiene un <code>PATH</code>,
            que le indica a la shell dónde debe buscar archivos a los que usted
            hace referencia.</p>

            <p>Cuando un programa se ejecuta a través del servidor web como un
            programa CGI, puede que no tenga el mismo <code>PATH</code>. 
            Cualquier programa que invoque desde su programa CGI (como por
            ejemplo <code>sendmail</code>) necesitará que se le indique la
            ruta absoluta, así la shell puede encontrarlos cuando intenta 
            ejecutar su programa CGI.</p>

            <p>Una manifestación común de esto es la ruta del intérprete del 
            script (a menudo <code>perl</code>) indicado en la primera línea
            de su programa CGI, que parecerá algo como:</p>

            <highlight language="perl">
                #!/usr/bin/perl
            </highlight>

            <p>Asegúrese de que éste es de hecho el path de su intérprete.</p>
            <note type="warning">
            Cuando edita scripts CGI en Windows, los caracteres de retorno de
            carro podrían añadirse a la línea donde se especifica el intérprete. 
            Asegúrese de que los archivos se transfieren al servidor en modo 
            ASCII. Fallar en esto puede acabar con avisos del tipo "Command not 
            found" del Sistema Operativo, debido a que éste no reconoce los 
            caracteres de final de línea interpretados como parte del nombre
            de fichero del intérprete.
            </note>
        </section>

        <section id="missingenv">
            <title>Faltan Variables de Entorno</title>

            <p>Si su programa CGI depende de <a
            href="#env">variables de entorno</a> no estándar, necesitará
            asegurarse de que Apache pasa esas variables.</p>

            <p>Cuando no encuentra ciertas cabeceras HTTP del entorno, asegúrese 
            de que están formateadas según el 
            <a href="http://tools.ietf.org/html/rfc2616">RFC 2616</a>, 
            sección 4.2: Nombres de Cabeceras deben empezar con una letra, 
            seguida solo de letras, números o guión. Cualquier cabecera 
            que no cumpla esta regla será ignorada de manera silenciosa.</p>

        </section>

        <section id="syntaxerrors">
            <title>Errores de Programa</title>

            <p>La mayor parte de las veces cuando un programa CGI falla, es por un 
            problema en el programa mismo. Esto ocurre generalmente cuando se 
            maneja bien con "esto del CGI", y ya no comete los dos errores
            mencionados más arriba. Lo primero que hay que hacer es asegurarse
            de que su programa se ejecuta correctamente en línea de comandos 
            antes de probarlo a través del servidor web.  Por ejemplo, 
            intente:</p>

            <example>
                cd /usr/local/apache2/cgi-bin<br/>
                ./first.pl
            </example>

            <p>(No llame al intérprete de <code>perl</code>. La consola y Apache 
            tienen que poder encontrar el intérprete usando línea 
            <a href="#pathinformation">línea de información</a> en la primera 
            línea del script.)</p>

            <p>Lo primero que debe ver escrito por su programa es un conjunto de 
            cabeceras HTTP, incluyendo el <code>Content-Type</code>,
            seguido de una línea en blanco.  Si ve alguna otra cosa, Apache
            devolverá el error <code>Premature end of script headers</code> si
            intenta lanzar el script en el servidor web. Vea 
            <a href="#writing">Escribiendo un programa CGI</a> más arriba para
            más detalle.</p>
        </section>

        <section id="errorlogs">
            <title>Log de Errores</title>

            <p>El log de errores es su amigo. Cualquier cosa que vaya mal generará 
            un mensaje en el log de errores. Debería mirar siempre ahí primero. 
            Si el lugar donde está alojando su sitio web no permite que acceda
            al log de errores, probablemente debería alojarlo en otro sitio.
            Aprenda a leer el log de errores y se dará cuenta de que enseguida
            averiguará el motivo del error y lo solucionará rápidamente.</p>
        </section>

        <section id="suexec">
            <title>Suexec</title>

            <p>El programa de soporte <a href="../suexec.html">suexec</a> permite
            que programas CGI se ejecuten con permisos de usuario distintos,
            dependiendo del virtualhost o el directorio home donde se 
            encuentren. Suexec tiene una comprobación de permisos muy estricta, 
            y cualquier fallo en esa comprobación dará como resultado un error
            con el mensaje <code>Premature end of script headers</code>.</p>

            <p>Para comprobar si está usando Suexec, ejecute 
            <code>apachectl -V</code> y compruebe la ubicación de 
            <code>SUEXEC_BIN</code>. Si Apache encuentra un binario 
            <program>suexec</program> al arrancar, suexec se activará.</p>

            <p>A menos que comprenda suxec perfectamente, no debería usarlo.
            Para desactivar suexec, basta con eliminar el binario 
            <program>suexec</program> al que apunta <code>SUEXEC_BIN</code> y 
            reiniciar el servidor. Si después de leer sobre 
            <a href="../suexec.html">suexec</a> todavía quiere usarlo, entonces
            ejecute <code>suexec -V</code> para encontrar la ubicación del 
            fichero log de suexec, y use ese log para encontrar que política no
            está cumpliendo.</p>
        </section>
    </section>

    <section id="behindscenes">
        <title>¿Qué ocurre entre bastidores?</title>

        <p>En cuanto tenga conocimiento avanzado de programación CGI, le será 
        útil comprender más de lo que ocurre entre bastidores. 
        Específicamente, cómo el navegador y el servidor se comunican el uno
        con el otro. Porque aunque esté muy bien escribir un programa que 
        diga "Hola, Mundo.", no tiene una gran utilidad.</p>

        <section id="env">
            <title>Variables de Entorno</title>

            <p>Las variables de entorno son valores que están ahí cuando 
            usa el ordenador. Son cosas útiles como el path (donde su ordenador
            busca el archivo específico que se lanza cuando usted escribe un 
            comando), su nombre de usuario, el tipo de terminal que usa, etc. 
            Para una lista completa de la variables de entorno normales que se 
            se usan en su día a día escriba <code>env</code> en la línea de 
            comandos.</p>

            <p>Durante la transacción CGI, el servidor y el navegador también 
            configuran variables de entorno, y así pueden comunicarse entre 
            ellos. Cosas como el tipo de navegador (Netscape, IE, Lynx), el tipo
            de servidor (Apache, IIS, WebSite), el nombre del programa CGI que
            se está ejecutando, etc.</p>

            <p>Estas variables están disponibles para el programador de CGI, y son 
            la mitad de la historia de la comunicación cliente-servidor. La 
            lista completa de las variables necesarias se encuentra en 
            <a href="http://www.ietf.org/rfc/rfc3875">el RFC de Common Gateway
            Interface</a>.</p>

            <p>Este sencillo programa CGI en Perl mostrará todas las variables 
            de entorno que se están pasando entre el cliente y el navegador. Dos
            programas similares están incluidos en el directorio 
            <code>cgi-bin</code> de la distribución de Apache. Tenga en cuenta
            que algunas variables son necesarias mientras que otras son 
            opcionales, así que es posible que vea algunas variables que no 
            están en la lista oficial. Adicionalmente, Apache aporta distintas
            maneras diferentes para que pueda
            <a href="../env.html">añadir sus variables de entorno</a> a las 
            básicas que se proveen por defecto.</p>

            <highlight language="perl">
#!/usr/bin/perl
use strict;
use warnings;

print "Content-type: text/html\n\n";
          
foreach my $key (keys %ENV) {
    print "$key --&gt; $ENV{$key}&lt;br&gt;";
}
            </highlight>
        </section>

        <section id="stdin">
            <title>STDIN y STDOUT</title>

            <p>Otra comunicación entre el servidor y el cliente ocurre en la 
            entrada estándar (<code>STDIN</code>) y la salida estándar 
            (<code>STDOUT</code>). En el contexto normal de cada día, 
            <code>STDIN</code> es la entrada con el teclado, o un fichero que se 
            le da a un programa para que actúe sobre él, y <code>STDOUT</code>
            generalmente es la consola o la pantalla.</p>

            <p>Cuando hace <code>POST</code> con un formulario de web a un programa 
            CGI, los datos en ese formulario se empaquetan en un formato especial
            que se entrega a su programa CGI en el <code>STDIN</code>.
            Entonces el programa puede procesar la información como si le llegara
            desde el teclado, o desde un fichero.</p>

            <p>El "formato especial" es muy sencillo. Un nombre de campo y su 
            valor se asocian juntos con el signo igual (=), y pares de valores 
            se asocian juntos con el ampersand ó et en español (&amp;). 
            Caracteres inconvenientes como los espacios, ampersands y signos de 
            igual, se convierten en su equivalente hexadecimal para no impidan 
            el funcionamiento correcto del programa. La cadena de datos al 
            completo será algo como:</p>

  <example>
        name=Rich%20Bowen&amp;city=Lexington&amp;state=KY&amp;sidekick=Squirrel%20Monkey
  </example>

            <p>A veces tendrá este tipo de cadena de caracteres al final de una 
            URL. Cuando esto ocurre, el servidor pone esa cadena en una variable 
            de entorno que se llama <code>QUERY_STRING</code>. Esto se llama 
            solicitud <code>GET</code>. Su formulario HTML especifica si se usa 
            un <code>GET</code> o un <code>POST</code> para entregar la 
            información, configurando el atributo <code>METHOD</code> en la 
            etiqueta <code>FORM</code>.</p>

            <p>Su programa es el responsable de convertir esa cadena de 
            caracteres en información útil. Afortunadamente, hay librerías y 
            módulos disponibles que ayudan a procesar la información, así como a 
            gestionar los distintos aspectos de su programa CGI.</p>
        </section>
    </section>

    <section id="libraries">
        <title>Módulos/librerías CGI</title>

        <p>Cuando escribe programas CGI, debería considerar usar una librería de
        código, o módulo, para hacer todo el trabajo más arduo por usted.
        Esto lleva a tener menos errores y un desarrollo de código más 
        rápido.</p>

        <p>Si está escribiendo un programa CGI en Perl, existen módulos 
        disponibles en <a href="http://www.cpan.org/">CPAN</a>. El módulo más
        conocido para este propósito es <code>CGI.pm</code>. Quizás quiera
        considerar <code>CGI::Lite</code>, que implementa una funcionalidad 
        mínima, que es todo lo que se necesita en la mayoría de los programas.</p>

        <p>Si está escribiendo programas CGI en C, hay varidad de opciones. Una
        de estas es la librería <code>CGIC</code>, de
        <a href="http://www.boutell.com/cgic/">http://www.boutell.com/cgic/</a>.
        </p>
    </section>

    <section id="moreinfo">
        <title>Para más información</title>

        <p>La especificación actual de CGI está disponible en el
        <a href="http://www.ietf.org/rfc/rfc3875">RFC de Common Gateway
        Interface</a>.</p>

        <p>Cuando envíe una pregunta sobre un problema de CGI, o bien a una 
        lista de correo, o a un grupo de noticias, asegúrese de que facilita suficiente
        información de lo que ha ocurrido, de lo que espera que ocurra, y de 
        lo que está ocurriendo en su lugar que es diferente, el servidor que 
        está ejecutando, en qué lenguaje CGI está hecho su programa, y si es
        posible, el código que falla. Esto hará encontrar el problema mucho más 
        fácil.</p>

        <p>Tenga en cuenta que las preguntas sobre problemas CGI 
        <strong>nunca</strong> deberían enviarse a la base de datos de bugs de
        bugs de Apache a menos que esté seguro de haber encontrado un 
        problema en el código fuente de Apache.</p>
    </section>
</manualpage>
