<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933502 -->
<!-- Spanish Translation: Arturo Bernal <arturobernalg@gmail.com> -->

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

<modulesynopsis metafile="mod_setenvif.xml.meta">

<name>mod_setenvif</name>
<description>Permite establecer variables de entorno según
las características de la petición</description>
<status>Base</status>
<sourcefile>mod_setenvif.c</sourcefile>
<identifier>setenvif_module</identifier>


<summary>

    <p>El módulo <module>mod_setenvif</module> le permite establecer
    variables de entorno internas según si distintos aspectos de la
    petición coinciden con expresiones regulares que usted especifique.
    Estas variables de entorno pueden ser usadas por otras partes del
    servidor para tomar decisiones sobre las acciones a realizar, además
    de estar disponibles para los scripts CGI y las páginas SSI.</p>

    <p>Las directivas se consideran en el orden en que aparecen en
    los archivos de configuración. Así se pueden usar secuencias más
    complejas, como este ejemplo, que establece <code>netscape</code> si
    el navegador es mozilla pero no MSIE.</p>

<highlight language="config">
BrowserMatch ^Mozilla netscape
BrowserMatch MSIE !netscape
</highlight>

   <p>Cuando el servidor busca una ruta mediante una <glossary
   ref="subrequest">subpetición</glossary> interna, como al buscar un
   <directive module="mod_dir" >DirectoryIndex</directive> o al generar
   un listado de directorio con <module>mod_autoindex</module>, las
   variables de entorno por petición <em>no</em> se heredan en la
   subpetición. Además, las directivas
   <directive module="mod_setenvif">SetEnvIf</directive> no se evalúan
   por separado en la subpetición debido a las fases de la API en las
   que actúa <module>mod_setenvif</module>.</p>

   <p>Una expresión regular solo necesita comillas cuando contiene un
   espacio, en cuyo caso las comillas simples y dobles son equivalentes.
   A diferencia de <module>mod_rewrite</module>, <module>mod_setenvif</module>
   elimina cada segunda barra invertida al analizar la expresión; así,
   <code>\\</code> requiere <code>\\\</code>, y <code>\\\</code> requiere
   <code>\\\\\</code>.</p>

</summary>

<seealso><a href="../env.html">Variables de entorno en Apache HTTP Server</a></seealso>

<directivesynopsis>
<name>BrowserMatch</name>
<description>Establece variables de entorno condicionadas por la
cabecera HTTP User-Agent
</description>
<syntax>BrowserMatch <em>regex [!]env-variable</em>[=<em>value</em>]
[[!]<em>env-variable</em>[=<em>value</em>]] ...</syntax>
<contextlist><context>server config</context>
<context>virtual host</context><context>directory</context>
<context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>
  <p>La directiva <directive>BrowserMatch</directive> es un caso especial de
  la directiva <directive module="mod_setenvif">SetEnvIf</directive> que
  establece variables de entorno condicionadas por la cabecera de
  petición HTTP <code>User-Agent</code>. Las siguientes dos líneas
  tienen el mismo efecto:</p>
<highlight language="config">
BrowserMatch Robot is_a_robot
SetEnvIf User-Agent Robot is_a_robot
</highlight>

    <p>Algunos ejemplos adicionales:</p>
<highlight language="config">
BrowserMatch ^Mozilla forms jpeg=yes browser=netscape
BrowserMatch "^Mozilla/[2-3]" tables agif frames javascript
BrowserMatch MSIE !javascript
</highlight>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>BrowserMatchNoCase</name>
<description>Establece variables de entorno condicionadas por User-Agent sin
distinguir mayúsculas y minúsculas</description>
<syntax>BrowserMatchNoCase  <em>regex [!]env-variable</em>[=<em>value</em>]
    [[!]<em>env-variable</em>[=<em>value</em>]] ...</syntax>
<contextlist><context>server config</context>
<context>virtual host</context><context>directory</context>
<context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>

    <p>La directiva <directive>BrowserMatchNoCase</directive> es
    semánticamente idéntica a la directiva <directive
    module="mod_setenvif">BrowserMatch</directive>.
    Sin embargo, realiza la coincidencia sin distinguir mayúsculas y
    minúsculas. Por ejemplo:</p>
<highlight language="config">
BrowserMatchNoCase mac platform=macintosh
BrowserMatchNoCase win platform=windows
</highlight>

    <p>Las directivas <directive>BrowserMatch</directive> y
    <directive>BrowserMatchNoCase</directive> son casos especiales de
    las directivas <directive module="mod_setenvif">SetEnvIf</directive> y <directive
    module="mod_setenvif">SetEnvIfNoCase</directive>.
    Las siguientes dos líneas tienen el mismo efecto:</p>
<highlight language="config">
BrowserMatchNoCase Robot is_a_robot
SetEnvIfNoCase User-Agent Robot is_a_robot
</highlight>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SetEnvIf</name>
<description>Establece variables de entorno en función de los atributos de
la petición
</description>
<syntax>SetEnvIf <em>attribute
    regex [!]env-variable</em>[=<em>value</em>]
    [[!]<em>env-variable</em>[=<em>value</em>]] ...</syntax>
<contextlist><context>server config</context>
<context>virtual host</context><context>directory</context>
<context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>
    <p>La directiva <directive>SetEnvIf</directive> define
    variables de entorno en función de los atributos de la petición. El
    <em>atributo</em> especificado en el primer argumento puede ser uno
    de los siguientes:</p>

<ol>
<li>Un campo de cabecera de petición HTTP (consulte <rfc>2616</rfc>
    para más información sobre estos); por ejemplo: <code>Host</code>,
    <code>User-Agent</code>, <code>Referer</code> y
    <code>Accept-Language</code>. Puede usarse una expresión regular
    para especificar un conjunto de cabeceras de petición.</li>

<li>Uno de los siguientes aspectos de la petición:
    <ul>
      <li><code>Remote_Host</code> - el nombre de host (si está
      disponible) del cliente que realiza la petición</li>

      <li><code>Remote_Addr</code> - la dirección IP del cliente
      que realiza la petición</li>

      <li><code>Server_Addr</code> - la dirección IP del servidor
      en el que se recibió la petición (solo en versiones
      posteriores a la 2.0.43)</li>

      <li><code>Request_Method</code> - el nombre del método
      usado (<code>GET</code>, <code>POST</code>, <em>etc.</em>)</li>

      <li><code>Request_Protocol</code> - el nombre y versión del
      protocolo con el que se realizó la petición (<em>por
      ejemplo</em>, "HTTP/0.9", "HTTP/1.1", <em>etc.</em>)</li>

      <li><code>Request_URI</code> - el recurso solicitado en la línea
       de petición HTTP, generalmente la parte de la URL
      que sigue al esquema y a la parte del host, sin la cadena de
      consulta. Vea la directiva <directive module="mod_rewrite">RewriteCond</directive>
      de <module>mod_rewrite</module> para más información sobre
      cómo hacer coincidir su cadena de consulta.</li>
    </ul>
</li>

<li>El nombre de una variable de entorno de la lista de las asociadas
con la petición. Esto permite que las directivas
<directive>SetEnvIf</directive> comprueben el resultado de
coincidencias anteriores. Solo están disponibles para esta comprobación
las variables de entorno definidas por directivas
<code>SetEnvIf[NoCase]</code> anteriores. 'Anteriores' significa que se
definieron en un ámbito más amplio (como a nivel de todo el servidor) o
previamente dentro del ámbito de la directiva actual. Las variables de
entorno solo se tendrán en cuenta si no hubo coincidencia entre las
características de la petición y no se usó una expresión regular para
el <em>atributo</em>.</li>

</ol>

<p>El segundo argumento (<em>regex</em>) es una <glossary
ref="regex">expresión regular</glossary>. Si la <em>regex</em>
coincide con el <em>atributo</em>, entonces se evalúa el resto de los
argumentos.</p>

<p>El resto de los argumentos indican los nombres de las variables a
establecer, y opcionalmente los valores a los que deben establecerse.
Tienen la forma de</p>

    <ol>
      <li><code><em>varname</em></code>, o</li>

      <li><code>!<em>varname</em></code>, o</li>

      <li><code><em>varname</em>=<em>value</em></code></li>
    </ol>

    <p>En la primera forma, el valor se establecerá en "1". La segunda
    eliminará la variable dada si ya estaba definida, y la
    tercera establecerá la variable con el valor literal dado por
    <code><em>value</em></code>. Desde la versión 2.0.51, Apache httpd
    reconocerá las apariciones de <code>$1</code>..<code>$9</code> dentro
    de <var>value</var> y las sustituirá por las subexpresiones entre
    paréntesis de <var>regex</var>. <code>$0</code> da acceso a la
    cadena completa coincidente con ese patrón.</p>

    <p>Si se especifica el valor especial <code>--early</code>, y esta
    directiva no está en un contexto de directorio, la directiva se
    evaluará antes durante el procesamiento de la petición. Esto permite
    que las variables de salida establecidas por esta directiva se usen
    como entrada para la opción "early mode" de la
    directiva <directive module="mod_headers">RequestHeader</directive>.
    Disponible en la versión 2.5.1 y posteriores.</p>

<highlight language="config">
SetEnvIf Request_URI "\.gif$" object_is_image=gif
SetEnvIf Request_URI "\.jpg$" object_is_image=jpg
SetEnvIf Request_URI "\.xbm$" object_is_image=xbm

SetEnvIf Referer www\.mydomain\.example\.com intra_site_referral

SetEnvIf object_is_image xbm XBIT_PROCESSING=1

SetEnvIf Request_URI "\.(.*)$" EXTENSION=$1

SetEnvIf ^TS  ^[a-z]  HAVE_TS
</highlight>

    <p>Las primeras tres establecerán la variable de entorno
    <code>object_is_image</code> si la petición era de un archivo de
    imagen, y la cuarta establece <code>intra_site_referral</code> si
    la página de referencia estaba en algún lugar del sitio web
    <code>www.mydomain.example.com</code>.</p>

    <p>El último ejemplo establecerá la variable de entorno
    <code>HAVE_TS</code> si la petición contiene alguna cabecera que
    comience con "TS" cuyo valor comience con cualquier carácter del
    conjunto [a-z].</p>
</usage>

<seealso><a href="../env.html">Variables de entorno en Apache HTTP Server</a>,
para más ejemplos.
</seealso>
</directivesynopsis>


<directivesynopsis>

<name>SetEnvIfExpr</name>
<description>Establece variables de entorno basándose en una expresión ap_expr</description>
<syntax>SetEnvIfExpr <em>expr
    [!]env-variable</em>[=<em>value</em>]
    [[!]<em>env-variable</em>[=<em>value</em>]] ...</syntax>
<contextlist><context>server config</context>
<context>virtual host</context><context>directory</context>
<context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>
    <p>La directiva <directive>SetEnvIfExpr</directive> define
    variables de entorno basándose en una <a href="../expr.html">expresión</a>.
    Estas expresiones se evaluarán en tiempo de ejecución,
    y se aplicarán a <em>env-variable</em> de la misma forma que
    <directive>SetEnvIf</directive>, incluyendo las referencias
    inversas.</p>

<highlight language="config">
    SetEnvIfExpr "tolower(req('X-Sendfile')) == 'd:\images\very_big.iso')" iso_delivered
    SetEnvIfExpr "tolower(req('X-Sendfile')) =~ /(.*\.iso$)/" iso-path=$1
</highlight>

    <p>Esto establecería la variable de entorno <code>iso_delivered</code>
    cada vez que nuestra aplicación intente enviarlo mediante <code>X-Sendfile</code></p>

    <p>Un ejemplo más útil sería establecer la variable rfc1918 si la
    dirección IP remota es una dirección privada según RFC 1918:</p>

<highlight language="config">
    SetEnvIfExpr "-R '10.0.0.0/8' || -R '172.16.0.0/12' || -R '192.168.0.0/16'" rfc1918
</highlight>
</usage>

<seealso><a href="../expr.html">Expresiones en Apache HTTP Server</a>,
para una referencia completa y más ejemplos.</seealso>
<seealso><directive module="core" type="section">If</directive> puede usarse para lograr
resultados similares.</seealso>
<seealso><module>mod_filter</module></seealso>
</directivesynopsis>

<directivesynopsis>
<name>SetEnvIfNoCase</name>
<description>Establece variables de entorno en función de los atributos de
la petición sin distinguir mayúsculas y minúsculas</description>
<syntax>SetEnvIfNoCase <em>attribute regex
        [!]env-variable</em>[=<em>value</em>]
    [[!]<em>env-variable</em>[=<em>value</em>]] ...</syntax>
<contextlist><context>server config</context>
<context>virtual host</context><context>directory</context>
<context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>

    <p>La directiva <directive>SetEnvIfNoCase</directive> es
    semánticamente idéntica a la directiva <directive module="mod_setenvif">SetEnvIf</directive>,
    y solo se diferencia en que la coincidencia de la expresión regular
    se realiza sin distinguir mayúsculas y minúsculas. Por ejemplo:</p>
<highlight language="config">
   SetEnvIfNoCase Host Example\.Org site=example
</highlight>

    <p>Esto hará que la variable de entorno <code>site</code>
    se establezca en "<code>example</code>" si se incluyó el campo de
    cabecera de petición HTTP <code>Host:</code> y contenía
    <code>Example.Org</code>, <code>example.org</code>, o cualquier otra
    combinación.</p>
</usage>
</directivesynopsis>
</modulesynopsis>
