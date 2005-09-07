<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE manualpage SYSTEM "./style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="./style/manual.es.xsl"?>
<!-- English Revision: 151405:240425 (outdated) -->

<!--
 Copyright 2002-2005 The Apache Software Foundation or its licensors,
 as applicable.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
-->

<manualpage metafile="env.xml.meta">

  <title>Variables de entorno de Apache</title>

  <summary>
    <p>El servidor HTTP Apache HTTP ofrece un mecanismo para almacenar
    informaci&#243;n en variables especiales que se llaman
    <em>variables de entorno</em>. Esta informaci&#243;n puede ser
    usada para controlar diversas operaciones como por ejemplo,
    almacenar datos en ficheros de registro (log files) o controlar el
    acceso al servidor. Las variables de entorno se usan tambi&#233;n
    como un mecanismo de comunicaci&#243;n con programas externos como
    por ejemplo, scripts CGI. Este documento explica las diferentes
    maneras de usar y manipular esas variables.</p>

    <p>Aunque estas variables se llaman <em>variables de entorno</em>,
    no son iguales que las variables de entorno que controla el
    sistema operativo de la m&#225;quina en que se est&#225;
    ejecutando Apache. Las variables de entorno de Apache se almacenan
    y manipulan la en estructura interna de Apache. Solamente se
    convierten en aut&#233;nticas variables de entorno del sistema
    operativo cuando se pasan a scripts CGI o a scripts Server Side
    Include. Si quiere manipular el entorno del sistema operativo
    sobre el que Apache se est&#225; ejecutando, debe usar los
    mecanismos est&#225;ndar de manipulaci&#243;n que tenga su sistema
    operativo.</p>
  </summary>

  <section id="setting">
    <title>Especificaci&#243;n de variables de entorno</title>
    <related>
      <modulelist>
        <module>mod_env</module>
        <module>mod_rewrite</module>
        <module>mod_setenvif</module>
        <module>mod_unique_id</module>
      </modulelist>
      <directivelist>
        <directive module="mod_setenvif">BrowserMatch</directive>
        <directive module="mod_setenvif">BrowserMatchNoCase</directive>
        <directive module="mod_env">PassEnv</directive>
        <directive module="mod_rewrite">RewriteRule</directive>
        <directive module="mod_env">SetEnv</directive>
        <directive module="mod_setenvif">SetEnvIf</directive>
        <directive module="mod_setenvif">SetEnvIfNoCase</directive>
        <directive module="mod_env">UnsetEnv</directive>
      </directivelist>
    </related>

    <section id="basic-manipulation">
        <title>Manipulaci&#243;n b&#225;sica del entorno</title>

        <p>El modo m&#225;s b&#225;sico de especificar el valor de una
        variable de entorno en Apache es usando la directiva
        incondicional <directive
        module="mod_env">SetEnv</directive>. Las variables pueden
        tambi&#233;n pasarse desde el shell en el que se inicio Apache
        usando la directiva <directive
        module="mod_env">PassEnv</directive>.</p>

    </section>
    <section id="conditional">
        <title>Especificaci&#243;n condicional por petici&#243;n</title>

        <p>Si necesita m&#225;s flexibilidad, las directivas incluidas
        con mod_setenvif permiten especificar valores para las
        variables de entorno de manera condicional en funci&#243;n de
        las caracteristicas particulares de la petici&#243;n que se
        est&#233; procesando. Por ejemplo, se puede especificar un
        valor para una variable solamente cuando la petici&#243;n se
        haga con un navegador espec&#237;fico, o solamente cuando la
        petici&#243;n contenga una determinada informaci&#243;n en su
        cabecera. Si necesita a&#250;n m&#225;s flexibilidad, puede
        conseguirla con la directiva <directive
        module="mod_rewrite">RewriteRule</directive> del m&#243;dulo
        mod_rewrite que tiene la opci&#243;n <code>[E=...]</code> para
        especificar valores en las variables de entorno.</p>

    </section>
    <section id="unique-identifiers">
        <title>Identificadores &#250;nicos</title>

        <p>Finalmente, mod_unique_id determina el valor de la variable
        de entorno <code>UNIQUE_ID</code> para cada
        petici&#243;n. Este valor est&#225; garantizado que sea
        &#250;nico entre todas las peticiones bajo condiciones muy
        espec&#237;ficas.</p>

    </section>
    <section id="standard-cgi">
        <title>Variables CGI est&#225;ndar</title>

        <p>Adem&#225;s de todas las variables de entorno especificadas
        en la configuraci&#243;n de Apache y las que se pasan desde el
        shell, los scripts CGI y las p&#225;ginas SSI tienen un
        conjunto de variables de entorno que contienen
        meta-informaci&#243;n sobre la petici&#243;n tal y como
        establece la <a
        href="http://cgi-spec.golux.com/">especificaci&#243;n
        CGI</a>.</p>

    </section>
    <section id="caveats">
        <title>Algunas limitaciones</title>

        <ul>
          <li>No es posible reeemplazar los valores o cambiar las
          variables est&#225;ndar CGI usando las directivas de
          manipulaci&#243;n del entorno.</li>

          <li>Cuando se usa <program>suexec</program> para
          lanzar scripts CGI, el entorno se limpia y se queda reducido
          a un conjunto de variables <em>seguras</em> antes de que se
          lancen los scripts. La lista de variables <em>seguras</em>
          se define en el momento de compilar en
          <code>suexec.c</code>.</li>

          <li>Por razones de portabilidad, los nombres de las
          variables de entorno solo pueden contener letras,
          n&#250;meros y guiones bajos. Adem&#225;s, el primer
          caracter no puede ser un n&#250;mero. Los caracteres que no
          cumplan con esta restricci&#243;n, se reemplazan
          autom&#225;ticamente por un gui&#243;n bajo cuando se pasan
          a scripts CGI y a p&#225;ginas SSI.</li>
        </ul>
    </section>
  </section>
  <section id="using">
    <title>C&#243;mo usar las variables de entorno</title>

    <related>
      <modulelist>
        <module>mod_access</module>
        <module>mod_cgi</module>
        <module>mod_ext_filter</module>
        <module>mod_headers</module>
        <module>mod_include</module>
        <module>mod_log_config</module>
        <module>mod_rewrite</module>
      </modulelist>
      <directivelist>
        <directive module="mod_access">Allow</directive>
        <directive module="mod_log_config">CustomLog</directive>
        <directive module="mod_access">Deny</directive>
        <directive module="mod_ext_filter">ExtFilterDefine</directive>
        <directive module="mod_headers">Header</directive>
        <directive module="mod_log_config">LogFormat</directive>
        <directive module="mod_rewrite">RewriteCond</directive>
        <directive module="mod_rewrite">RewriteRule</directive>
      </directivelist>
    </related>

    <section id="cgi-scripts">
        <title>Scripts CGI</title>

        <p>Uno de los principales usos de las variables de entorno es
        pasar informaci&#243;n a scripts CGI. Tal y como se explicaba
        m&#225;s arriba, el entorno que se pasa a los scripts CGI
        incluye meta-informaci&#243;n est&#225;ndar acerca de la
        petici&#243;n adem&#225;s de cualquier variable especificada
        en la configuraci&#243;n de Apache. Para obtener m&#225;s
        informaci&#243;n sobre este tema consulte el <a
        href="howto/cgi.html">tutorial sobre CGIs</a>.</p>

    </section>
    <section id="ssi-pages">
        <title>P&#225;ginas SSI</title>

        <p>Los documentos procesados por el servidor con el filtro
        <code>INCLUDES</code> perteneciente a mod_include pueden
        imprimir las variables de entorno usando el elemento
        <code>echo</code>, y pueden usar las variables de entorno en
        elementos de control de flujo para dividir en partes una
        p&#225;gina condicional seg&#250;n las caracter&#237;sticas de
        la petici&#243;n. Apache tambi&#233;n sirve p&#225;ginas SSI
        con las variables CGI est&#225;ndar tal y como se explica
        m&#225;s arriba en este documento. Para obetener m&#225;s
        informaci&#243;n, consulte el <a
        href="howto/ssi.html">tutorial sobre SSI</a>.</p>

    </section>
    <section id="access-control">
        <title>Control de acceso</title>

        <p>El acceso al servidor puede ser controlado en funci&#243;n
        del valor de las variables de entorno usando las directivas
        <code>allow from env=</code> y <code>deny from env=</code>. En
        combinaci&#243;n con la directiva <directive
        module="mod_setenvif">SetEnvIf</directive>, se puede tener un
        control m&#225;s flexible del acceso al servidor en
        funci&#243;n de las caracter&#237;sticas del cliente. Por
        ejemplo, puede usar estas directivas para denegar el acceso si
        el cliente usa un determinado navegador.</p>

    </section>
    <section id="logging">
        <title>Registro condicional</title>

        <p>Los valores de las variables de entorno pueden registrarse
        en el log de acceso usando la directiva <directive
        module="mod_log_config">LogFormat</directive> con la
        opci&#243;n <code>%e</code>. Adem&#225;s, la decisi&#243;n
        sobre qu&#233; peticiones se registran puede ser tomada en
        funci&#243;n del valor de las variables de entorno usando la
        forma condicional de la directiva <directive
        module="mod_log_config">CustomLog</directive>. En
        combinaci&#243;n con <directive module="mod_setenvif"
        >SetEnvIf</directive>, esto permite controlar de forma
        flexible de qu&#233; peticiones se guarda registro. Por
        ejemplo, puede elegir no registrar las peticiones que se hagan
        a ficheros cuyo nombre termine en <code>gif</code>, o puede
        elegir registrar &#250;nicamente las peticiones que provengan
        de clientes que est&#233;n fuera de su propia red.</p>

    </section>
    <section id="response-headers">
        <title>Cabeceras de respuesta condicionales</title>

        <p>La directiva <directive
        module="mod_headers">Header</directive> puede utilizar la
        presencia o ausencia de una variable de entorno para
        determinar si una determinada cabecera HTTP se incluye en la
        respuesta al cliente. Esto permite, por ejemplo, que una
        determinada cabecera de respuesta sea enviada &#250;nicamente
        si tambi&#233;n estaba presente en la petici&#243;n del
        cliente.</p>

    </section>

    <section id="external-filter">
        <title>Activaci&#243;n de filtros externos</title>

        <p>External filters configured by <module>mod_ext_filter</module>
        using the <directive
        module="mod_ext_filter">ExtFilterDefine</directive> directive can
        by activated conditional on an environment variable using the
        <code>disableenv=</code> and <code>enableenv=</code> options.</p>
    </section>

    <section id="url-rewriting">
        <title>Reescritura de URLs</title>

        <p>La expresion <code>%{ENV:...}</code> de <em>TestString</em>
         en una directiva <directive
         module="mod_rewrite">RewriteCond</directive> permite que el
         motor de reescritura de mod_rewrite pueda tomar decisiones en
         funci&#243;n del valor de variables de entorno. Tenga en
         cuenta que las variables accesibles en mod_rewrite sin el
         prefijo <code>ENV:</code> no son realmente variables de
         entorno. En realidad, son variables especiales de mod_rewrite
         que no pueden ser accedidas desde otros m&#243;dulos.</p>
    </section>
  </section>

  <section id="special">
    <title>Variables de entorno con funciones especiales</title>

        <p>Los problemas de interoperatividad han conducido a la
        introducci&#243;n de mecanismos para modificar el
        comportamiento de Apache cuando se comunica con determinados
        clientes. Para hacer que esos mecanismos sean tan flexibles
        como sea posible, se invocan definiendo variables de entorno,
        normalmente con la directiva <directive
        module="mod_setenvif">BrowserMatch</directive>, aunque
        tambi&#233;n se puede usar por ejemplo con las directivas
        <directive module="mod_env">SetEnv</directive> y <directive
        module="mod_env">PassEnv</directive>.</p>

    <section id="downgrade">
        <title>downgrade-1.0</title>

        <p>Fuerza que la petici&#243;n sea tratada como una petici&#243;n
        HTTP/1.0 incluso si viene en una especificaci&#243;n posterior.</p>

    </section>
    <section id="force-no-vary">
        <title>force-no-vary</title>

        <p>Hace que cualquier campo <code>Vary</code> se elimine de la
        cabecera de la respuesta antes de ser enviada al
        cliente. Algunos clientes no interpretan este campo
        correctamente (consulte la secci&#243;n sobre <a
        href="misc/known_client_problems.html">problemas conocidos con
        clientes</a>); usar esta variable puede evitar esos
        problemas. Usar esta variable implica tambi&#233;n el uso de
        <strong>force-response-1.0</strong>.</p>

    </section>
    <section id="force-response">
        <title>force-response-1.0</title>

      <p>Fuerza que la respuesta a una petici&#243;n HTTP/1.0 se haga
      tambi&#233;n seg&#250;n la especificaci&#243;n HTTP/1.0. Esto se
      implement&#243; originalmente como resultado de un problema con
      los proxies de AOL. Algunos clientes HTTP/1.0 no se comportan
      correctamente cuando se les env&#237;a una respuesta HTTP/1.1, y
      este mecanismo hace que se pueda interactuar con ellos.</p>

    </section>

    <section id="gzip-only-text-html">
        <title>gzip-only-text/html</title>

        <p>Cuando tiene valor "1", esta variable desactiva el filtro
        de salida DEFLATE de <module>mod_deflate</module> para
        contenidos de tipo diferentes de <code>text/html</code>.</p>
    </section>

    <section id="no-gzip"><title>no-gzip</title>

        <p>Cuando se especifica, se desactiva el filtro
        <code>DEFLATE</code> de <module>mod_deflate</module>.</p>

    </section>

    <section id="nokeepalive">
        <title>nokeepalive</title>

        <p>Desactiva <directive module="core">KeepAlive</directive>.</p>

    </section>

    <section id="prefer-language"><title>prefer-language</title>

        <p>Influye en el comportamiento de
        <module>mod_negotiation</module>. Si contiene una etiqueta de
        idioma (del tipo <code>en</code>, <code>ja</code> o
        <code>x-klingon</code>), <module>mod_negotiation</module>
        intenta que se use ese mismo idioma en la respuesta. Si no
        est&#225; disponible ese idioma, se aplica el proceso de <a
        href="content-negotiation.html">negociaci&#243;n</a>
        normal.</p>

    </section>

    <section id="redirect-carefully">
        <title>redirect-carefully</title>

        <p>Fuerza que el servidor sea especialmente cuidadoso al
        enviar una redirecci&#243;n al cliente. Se usa normalmente
        cuando un cliente tiene un problema conocido tratando las
        redirecciones. Fue implementado originalmente por el problema
        que presentaba el software de WebFolders de Microsoft, que
        ten&#237;a problemas interpretando redirecciones originadas
        cuando se acced&#237;a a recursos servidos usando DAV.</p>

    </section>

   <section id="suppress-error-charset">
       <title>suppress-error-charset</title>

    <p><em>Disponible en las versiones de Apache 2.0.40 y posteriores</em></p>

    <p>Cuando Apache efect&#250;a una redirecci&#243;n en respuesta a la
    petici&#243;n de un cliente, la respuesta incluye alg&#250;n texto para que
    se muestre en caso de que el cliente no pueda seguir (o no siga)
    autom&#225;ticamente la redirecci&#243;n. Apache normalmente etiqueta este
    texto siguiendo la codificaci&#243;n ISO-8859-1.</p> 

    <p>Sin embargo, si la redirecci&#243;n es a una p&#225;gina que
    usa una codificaci&#243;n diferente, algunas versiones de
    navegadores que no funcionan correctamente intentar&#225;n usar la
    codificaci&#243;n del texto de redirecci&#243;n en lugar de la de
    pagina a la que ha sido redireccionado. La consecuencia de esto
    puede ser, por ejemplo, que una p&#225;gina en griego no se
    muestre correctamente.</p>

    <p>Especificar un valor en esta variable de entorno hace que
    Apache omita la codificaci&#243;n en el texto que incluye con las
    redirecciones, y que esos navegadores que no funcionan
    correctamente muestren correctamente la p&#225;gina de destino.</p>

   </section>

  </section>

  <section id="examples">
    <title>Ejemplos</title>

    <section id="misbehaving">
        <title>C&#243;mo cambiar el comportamiento de clientes que se
        comportan de manera inapropiada</title>

        <p>Recomendamos que incluya las siguentes l&#237;neas en el
        fichero httpd.conf para evitar problemas conocidos</p>
<example><pre>

#
# Las siguientes directivas modifican el comportamiento normal de las respuestas HTTP.
# La primera directiva desactiva keepalive para Netscape 2.x y para navegadores 
# que la simulan. Hay problemas conocidos con esos navegadores.
# La segunda directiva es para Microsoft Internet Explorer 4.0b2
# que tiene un fallo en la implemantaci&#243;n de HTTP/1.1 y no soporta
# keepalive adecuadamente cuando se usan respuestas 301 &#243; 302 (redirecciones).
#
BrowserMatch "Mozilla/2" nokeepalive
BrowserMatch "MSIE 4\.0b2;" nokeepalive downgrade-1.0 force-response-1.0

#
# La siguiente directiva desactiva las respuestas HTTP/1.1 para navegadores que
# violan la especificaci&#243;n HTTP/1.0 @@@ by not being able to grok a
# basic 1.1 response @@@.
#
BrowserMatch "RealPlayer 4\.0" force-response-1.0
BrowserMatch "Java/1\.0" force-response-1.0
BrowserMatch "JDK/1\.0" force-response-1.0</pre></example>

    </section>
    <section id="no-img-log">
        <title>No almacenar entradas en registro de acceso para las
        im&#225;genes</title>

        <p>Este ejemplo evita que las peticiones de im&#225;genes
        aparezcan en el registro de acceso. Puede ser modificada
        f&#225;cilmente para evitar que se registren entradas de
        peticiones de directorios, o provenientes de determinados
        clientes.</p>

        <example><pre> 
SetEnvIf Request_URI \.gif image-request
SetEnvIf Request_URI \.jpg image-request 
SetEnvIf Request_URI \.png image-request 
CustomLog logs/access_log common env=!image-request</pre></example>

    </section>
    <section id="image-theft">
        <title>Evitar el "robo de imagenes"</title>

        <p>Este ejemplo muestra como evitar que otras webs usen las
        im&#225;genes de su servidor para sus p&#225;ginas. Esta
        configuraci&#243;n no se recomienda, pero puede funcionar en
        determinadas circunstancias. Asumimos que que todas sus
        im&#225;genes est&#225;n en un directorio llamado
        /web/images.</p>

        <example><pre> 
SetEnvIf Referer "^http://www.example.com/" local_referal 
# Allow browsers that do not send Referer info
SetEnvIf Referer "^$" local_referal 
&lt;Directory  /web/images&gt; 
   Order Deny,Allow 
   Deny from all 
   Allow from env=local_referal 
&lt;/Directory&gt;</pre></example>

        <p>Para obtener m&#225;s informaci&#243;n sobre esta
        t&#233;cnica, consulte el tutorial de ApacheToday " <a
        href="http://apachetoday.com/news_story.php3?ltsn=2000-06-14-002-01-PS">
        Keeping Your Images from Adorning Other Sites</a>".</p>
        </section> </section> </manualpage>
