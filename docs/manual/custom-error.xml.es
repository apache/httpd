<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE manualpage SYSTEM "./style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="./style/manual.es.xsl"?>
<!-- English Revision: 1741842  -->
<!-- Spanish Translator: Luis Gil de Bernabé -->
<!-- Reviewed by: Sergio Ramos -->

<!--
 Licensed to the Apache Software Foundation (ASF) under one or more
 contributor license agreements.  See the NOTICE file distributed with
 this work for additional information regarding copyright ownership.
 The ASF licenses this file to You under the Apache License, Version 2.0
 (the "License"); you may not use this file except in compliance with
 the License.  You may obtain a copy of the License at

     https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
-->

<manualpage metafile="custom-error.xml.meta">

  <title>Respuestas de Error Personalizadas</title>

  <summary>

    <p>Aunque el Servidor Apache HTTP ofrece respuestas de error genéricos en
    el caso de los códigos de estado 4xx o 5xx  HTTP, éstas respuestas son 
    bastante austeras, no informativas, y puede ser intimidante para los 
    usuarios del sitio. Si lo desea, para proporcionar respuestas de error 
    personalizados que son o bien más amables, o en algún idioma que no sea 
    Inglés, o tal vez que son de un estilo más acorde con su diseño del sitio.</p>

    <p>Respuestas de error personalizadas se pueden definir para cualquier código HTTP
    designado como condición de error - Esto es, cualquier estado 4xx ó 5xx.</p>

    <p>Además, se proporcionan un conjunto de valores, de manera que el 
      documento de error puede ser personalizado más adelante, basado en 
      los valores de estas variables, usando <a href="howto/ssi.html">Inclusiones del 
      Lado del Servidor (SSI)</a>. O bien, puede tener condiciones de error que maneje 
      un cgi, u otro controlador dinámico (PHP, mod_perl, etc), que
     hace uso de estas variables.</p>

  </summary>

  <section id="configuration"><title>Configuración</title>

    <p>Los documentos de error personalizados se configuran
    mediante la directiva <directive module="core">ErrorDocument</directive>,
    que puede ser usado en el conjunto general, de los hosts virtuales o en directorios.
    También pueden ser usados en los ficheros .htaccess si
    <directive module="core">AllowOverride</directive>esta configurado a 
    FileInfo.</p>

    <highlight language="config">
ErrorDocument 500 "Perdón, Nuestro escript ha fallado. ¡Ay Madre!"<br />
ErrorDocument 500 /cgi-bin/crash-recover<br />
ErrorDocument 500 https://error.example.com/server_error.html<br />
ErrorDocument 404 /errors/not_found.html <br />
ErrorDocument 401 /subscription/como_suscribirse.html
    </highlight>

    <p>La sintaxis de la directiva de <code>ErrorDocument</code> es:</p>

    <highlight language="config">
      ErrorDocument &lt;código-de-3-dígitos&gt; &lt;acción&gt;
    </highlight>

    <p>Donde la acción será tratada como:</p>

    <ol>
      <li>Una URL local a la que redireccionar (si la acción empieza con "/").</li>
      <li>Una URL externa a la que redireccionar (si la acción es una URL válida).</li>
      <li>Texto para mostrar (si ninguna de las anteriores). El texto tiene que estar 
        entrecomillado ("ERROR") si  consiste de mas de una palabra.</li>
    </ol>

    <p>Cuando se redirija a una URL local, se establecen variables de 
      entorno adicionales de manera que la respuesta puede ser personalizada. 
      Éstas variables no se envían a URLs externas</p>

  </section>

  <section id="variables"><title>Variables Disponibles</title>

      <p>Redireccionando a otra URL puede ser útil, pero sólo si algo de información
       puede ser pasado como parámetro, lo cuál puede ser usado para explicar de 
       forma más clara el error o crear un log del mismo.</p>

      <p>Para conseguir esto, cuando se envía el redireccionamiento de error, 
        se establecerán variables de entorno adicionales, que será generado a 
        partir de las cabeceras prestadas a la solicitud original, anteponiendo 'REDIRECT_' 
        en el nombre de la cabecera original. Esto proporciona el 
        documento de error en el ámbito de la petición original</p>

      <p>Por ejemplo, es posible que se reciba, además de las variables de 
        entorno más habituales, lo siguiente:</p>

      <example>
        REDIRECT_HTTP_ACCEPT=*/*, image/gif, image/jpeg, image/png<br />
        REDIRECT_HTTP_USER_AGENT=Mozilla/5.0 Fedora/3.5.8-1.fc12 Firefox/3.5.8<br />
        REDIRECT_PATH=.:/bin:/usr/local/bin:/sbin<br />
        REDIRECT_QUERY_STRING=<br />
        REDIRECT_REMOTE_ADDR=121.345.78.123<br />
        REDIRECT_REMOTE_HOST=client.example.com<br />
        REDIRECT_SERVER_NAME=www.example.edu<br />
        REDIRECT_SERVER_PORT=80<br />
        REDIRECT_SERVER_SOFTWARE=Apache/2.2.15<br />
        REDIRECT_URL=/cgi-bin/buggy.pl
      </example>

      <p> Las variables de entorno de tipo <code>REDIRECT_</code> se crean a partir
      de las variables de entorno que existían antes de la redirección. Se renombran 
      con prefijo <code>REDIRECT_</code>, <em>por ejemplo:</em>,
      <code>HTTP_USER_AGENT</code> se convierte en
      <code>REDIRECT_HTTP_USER_AGENT</code>.</p>

      <p><code>REDIRECT_URL</code>, <code>REDIRECT_STATUS</code>, y
      <code>REDIRECT_QUERY_STRING</code> están garantizados para ser fijado, y
      se establecerán las otras cabeceras solo si existían antes de 
      la condición de error.</p>

      <p><strong>Ninguna</strong> de estas condiciones se establecerá 
      si elobjetivo de <directive module="core">ErrorDocument</directive> es una 
      redirección <em>external</em> (nada a partir de un nombre de esquema 
      como <code>http:</code>, incluso si se refiere a la misma máquina que el servidor.</p>
  </section>

  <section id="custom"><title>Personalizando Respuestas de Errores</title>

      <p>Si apunta su <code> ErrorDocument</code> a alguna variedad de controlador
       dinámico como un documento que se incluye en el lado del servidor como CGI, 
       script u otro tipo de manejador, es posible que desee utilizar las variables 
       de entorno disponibles para personalizar esta respuesta.</p>

      <p>Si el ErrorDocument especifica una redirección local a un script CGI, el 
        script debe incluir un campo de cabecera de tipo "<code>Status:</code>" en 
        su salida con el fin de asegurar la propagación de
      todo el camino de vuelta al cliente de la condición de error que se generó.
      Por ejemplo, un script de Perl ErrorDocument podría incluir lo siguiente:</p>

       <highlight language="perl">
...
print  "Content-type: text/html\n"; <br />
printf "Status: %s Condition Intercepted\n", $ENV{"REDIRECT_STATUS"}; <br />
...
      </highlight>

      <p> Si el script está dedicado al manejo de una condición de error en particular,
       como por ejemplo <code>404&nbsp;Not&nbsp;Found</code>, puede usar el propio
        código y el error de texto en su lugar.</p>

      <p>Tenga en cuenta que si la respuesta contiene <code>Location:</code>
      header (con el fin de emitir una redirección del lado del cliente), el 
      script <em>deberá</em>emitir una cabecera apropiada con el <code>Status:</code> 
      (como <code>302&nbsp;Found</code>). De lo contrario la cabecera 
      <code>Location:</code> no tendrá ningún efecto.</p>

  </section>

  <section id="multi-lang"><title>Documentos de error  personalizados 
    Multilengua</title>

    <p>Con la instalación de Apache HTTP Server se proporciona un directorio 
      personal con diferentes mensajes de errores traducidos a 16 idiomas 
      diferentes. También hay un archivo de configuración el el directorio 
    <code>conf/extra</code> que puede ser incluido para añadir esta funcionalidad.</p>

    <p>En el archivo de configuración del servidor, verá una línea como:</p>

    <highlight language="config">
    # Multi-language error messages<br />
    #Include conf/extra/httpd-multilang-errordoc.conf
    </highlight>

    <p>Descomentando éste <code>Include</code> habilitará esta característica,
    y proporcionar mensajes de error de idioma-negociado,
    basado en el idioma de preferencia establecido en el navegador del cliente.</p>

    <p>Además, estos documentos contienen varias variables del tipo 
    <code>REDIRECT_</code>, con lo que se le puede añadir información adicional 
    de lo que ha ocurrido al usuario final, y que pueden hacer ahora.</p>

    <p>Estos documentos pueden ser personalizados de cualquier forma que desee 
      mostrar más información al usuario a cerca del su sitio web, y que podrán encontrar en él.</p>

    <p><module>mod_include</module> y <module>mod_negotiation</module>
    Tienen que estar habilitados para usar estas características.</p>

 </section>

</manualpage>
