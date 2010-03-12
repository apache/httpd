<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE manualpage SYSTEM "./style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="./style/manual.es.xsl"?>
<!-- English Revision: 420990:922267 (outdated) -->

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
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 implied.  See the License for the specific language governing
 permissions and limitations under the License.  -->

<manualpage metafile="custom-error.xml.meta">

  <title>Respuestas de error personalizadas</title>

  <summary>
    <p>Apache ofrece la posibilidad de que los webmasters puedan
    configurar las respuestas que muestra el servidor Apache cuando se
    producen algunos errores o problemas.</p>

    <p>Las respuestas personalizadas pueden definirse para activarse
    en caso de que el servidor detecte un error o problema.</p>

    <p>Si un script termina de forma anormal y se produce una respuesta
    "500 Server Error", esta respuesta puede ser sustituida por otro
    texto de su elecci&#243;n o por una redirecci&#243;n a otra URL
    (local o externa).</p>
  </summary>

  <section id="behavior">
    <title>Comportamiento</title>

    <section>
      <title>Comportamiento anterior</title>

      <p>NCSA httpd 1.3 devolv&#237;a mensajes antiguos del error o
      problema encontrado que con frecuencia no ten&#237;an
      significado alguno para el usuario, y que no inclu&#237;an en
      los logs informaci&#243;n que diera pistas sobre las causas de
      lo sucedido.</p>
    </section>

    <section>
      <title>Comportamiento actual</title>

      <p>Se puede hacer que el servidor siga uno de los siguientes
      comportamientos:</p>

      <ol>
        <li>Desplegar un texto diferente, en lugar de los mensajes de
        la NCSA, o</li>

        <li>redireccionar la petici&#243;n a una URL local, o</li>

        <li>redireccionar la petici&#243;n a una URL externa.</li>
      </ol>

      <p>Redireccionar a otra URL puede resultar de utilidad, pero
      solo si con ello se puede tambi&#233;n pasar alguna
      informaci&#243;n que pueda explicar el error o problema y/o
      registrarlo en el log correspondiente m&#225;s claramente.</p>

      <p>Para conseguir esto, Apache define ahora variables de entorno
      similares a las de los CGI:</p>

      <example>
        REDIRECT_HTTP_ACCEPT=*/*, image/gif, image/x-xbitmap, 
            image/jpeg<br />
        REDIRECT_HTTP_USER_AGENT=Mozilla/1.1b2 (X11; I; HP-UX A.09.05 
            9000/712)<br />
        REDIRECT_PATH=.:/bin:/usr/local/bin:/etc<br />
        REDIRECT_QUERY_STRING=<br />
        REDIRECT_REMOTE_ADDR=121.345.78.123<br />
        REDIRECT_REMOTE_HOST=ooh.ahhh.com<br />
        REDIRECT_SERVER_NAME=crash.bang.edu<br />
        REDIRECT_SERVER_PORT=80<br />
        REDIRECT_SERVER_SOFTWARE=Apache/0.8.15<br />
        REDIRECT_URL=/cgi-bin/buggy.pl
      </example>

      <p>Tenga en cuenta el prefijo <code>REDIRECT_</code>.</p>

      <p>Al menos <code>REDIRECT_URL</code> y
      <code>REDIRECT_QUERY_STRING</code> se pasar&#225;n a la nueva
      URL (asumiendo que es un cgi-script o un cgi-include). Las otras
      variables existir&#225;n solo si exist&#237;an antes de aparecer
      el error o problema. <strong>Ninguna</strong> de estas variables
      se crear&#225; si en la directiva <directive
      module="core">ErrorDocument</directive> ha especificado una
      redirecci&#243;n <em>externa</em> (cualquier cosa que empiece
      por un nombre de esquema del tipo <code>http:</code>, incluso si
      se refiere al mismo servidor).</p>
    </section>
  </section>

  <section id="configuration">
    <title>Configuraci&#243;n</title>

    <p>El uso de <directive module="core">ErrorDocument</directive>
    est&#225; activado para los ficheros .htaccess cuando <directive
    module="core">AllowOverride</directive> tiene el valor
    adecuado.</p>

    <p>Aqu&#237; hay algunos ejemplos m&#225;s...</p>

    <example>
      ErrorDocument 500 /cgi-bin/crash-recover <br />
      ErrorDocument 500 "Sorry, our script crashed. Oh dear" <br />
      ErrorDocument 500 http://xxx/ <br />
      ErrorDocument 404 /Lame_excuses/not_found.html <br />
      ErrorDocument 401 /Subscription/how_to_subscribe.html
    </example>

    <p>La sintaxis es,</p>

    <example>
      ErrorDocument &lt;3-digit-code&gt; &lt;action&gt;
    </example>

    <p>donde action puede ser,</p>

    <ol>
      <li>Texto a mostrar. Ponga antes del texto que quiere que se
      muestre unas comillas ("). Lo que sea que siga a las comillas se
      mostrar&#225;. <em>Nota: las comillas (") no se
      muestran.</em></li>

      <li>Una URL local a la que se redireccionar&#225; la
      petici&#243;n.</li>

      <li>Una URL externa a la que se redireccionar&#225; la
      petici&#243;n.</li>
    </ol>
  </section>

  <section id="custom">
    <title>Mesajes de error personalizados y redirecciones</title>

    <p>El comportamiento de Apache en cuanto a las redirecciones ha
    cambiado para que puedan usarse m&#225;s variables de entorno con
    los script/server-include.</p>

    <section>
      <title>Antiguo comportamiento</title>

      <p>Las variables CGI est&#225;ndar estaban disponibles para el
      script al que se hac&#237;a la redirecci&#243;n. No se inclu&#237;a
      ninguna indicaci&#243;n sobre la precedencia de la
      redirecci&#243;n.</p>
    </section>

    <section>
      <title>Nuevo comportamiento</title>

      <p>Un nuevo grupo de variables de entorno se inicializa para que
      las use el script al que ha sido redireccionado. Cada
      nueva variable tendr&#225; el prefijo <code>REDIRECT_</code>.
      Las variables de entorno <code>REDIRECT_</code> se crean a
      partir de de las variables de entorno CGI que existen antes de
      la redirecci&#243;n, se les cambia el nombre
      a&#241;adi&#233;ndoles el prefijo <code>REDIRECT_</code>, por
      ejemplo, <code>HTTP_USER_AGENT</code> pasa a ser
      <code>REDIRECT_HTTP_USER_AGENT</code>. Adem&#225;s, para esas
      nuevas variables, Apache definir&#225; <code>REDIRECT_URL</code>
      y <code>REDIRECT_STATUS</code> para ayudar al script a seguir su
      origen. Tanto la URL original como la URL a la que es redirigida
      la petici&#243;n pueden almacenarse en los logs de acceso.</p>

      <p>Si ErrorDocument especifica una redirecci&#243;n local a un
      script CGI, el script debe incluir una campo de cabeceraa
      "<code>Status:</code>" en el resultado final para asegurar que
      es posible hacer llegar al cliente de vuelta la condici&#243;n
      de error que lo provoc&#243;. Por ejemplo, un script en Perl
      para usar con ErrorDocument podr&#237;a incluir lo
      siguiente:</p>

      <example>
        ... <br />
        print  "Content-type: text/html\n"; <br />
        printf "Status: %s Condition Intercepted\n", $ENV{"REDIRECT_STATUS"}; <br />
        ...
      </example>

      <p>Si el script tiene como fin tratar una determinada
      condici&#243;n de error, por ejemplo
      <code>404 Not Found</code>, se pueden usar los
      c&#243;digos de error y textos espec&#237;ficos en su lugar.</p>

      <p>Tenga en cuenta que el script <em>debe</em> incluir un campo
      de cabecera <code>Status:</code> apropiado (como
      <code>302 Found</code>), si la respuesta contiene un campo de
      cabecera <code>Location:</code> (para poder enviar una
      redirecci&#243;n que se interprete en el cliente). De otra
      manera, la cabecera
      <code>Location:</code> puede que no tenga efecto.</p>
    </section>
  </section>
</manualpage>

