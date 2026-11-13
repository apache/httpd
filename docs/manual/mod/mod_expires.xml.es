<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933750 -->
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

<modulesynopsis metafile="mod_expires.xml.meta">

<name>mod_expires</name>
<description>Generación de las cabeceras HTTP <code>Expires</code> y
<code>Cache-Control</code> según criterios especificados por el
usuario</description>
<status>Extension</status>
<sourcefile>mod_expires.c</sourcefile>
<identifier>expires_module</identifier>

<summary>
    <p>Este módulo controla el establecimiento de la cabecera HTTP
    <code>Expires</code> y de la directiva <code>max-age</code> de la
    cabecera HTTP <code>Cache-Control</code> en las respuestas del servidor. La
    fecha de caducidad puede establecerse en relación con la hora en que
    se modificó por última vez el archivo de origen, o con la hora del
    acceso del cliente.</p>

    <p>Estas cabeceras HTTP son una instrucción para el cliente sobre la
    validez y la persistencia del documento. Si está en caché, el documento puede
    obtenerse de la caché en lugar de la fuente hasta que haya transcurrido ese
    tiempo. Después de eso, la copia en caché se considera
    "caducada" e inválida, y debe obtenerse una copia nueva de la
    fuente.</p>

    <p>Para modificar directivas de <code>Cache-Control</code> distintas de
    <code>max-age</code> (vea <rfc section="14.9">2616</rfc>), puede usar la directiva
    <directive module="mod_headers">Header</directive>.</p>

    <p>Cuando la cabecera <code>Expires</code> ya forma parte de la respuesta
    generada por el servidor, por ejemplo cuando la genera un script CGI o
    proviene de un servidor de origen a través de un proxy, este módulo no cambia ni añade
    una cabecera <code>Expires</code> o <code>Cache-Control</code>.</p>
</summary>

<section id="AltSyn"><title>Sintaxis alternativa de intervalo</title>
    <p>Las directivas <directive module="mod_expires">ExpiresDefault</directive> y
    <directive module="mod_expires">ExpiresByType</directive>
    también pueden definirse con una sintaxis más legible de la forma:</p>

    <highlight language="config">
ExpiresDefault "<var>base</var>  [plus <var>num</var> <var>type</var>] [<var>num</var> <var>type</var>] ..."
ExpiresByType type/encoding "<var>base</var>  [plus <var>num</var> <var>type</var>] [<var>num</var> <var>type</var>] ..."
    </highlight>

    <p>donde <var>base</var> es una de:</p>

    <ul>
      <li><code>access</code></li>

      <li><code>now</code> (equivalente a
      "<code>access</code>")</li>

      <li><code>modification</code></li>
    </ul>

    <p>La palabra clave <code>plus</code> es opcional. <var>num</var>
    debe ser un valor entero [aceptable para <code>atoi()</code>],
    y <var>type</var> es una de:</p>

    <ul>
      <li><code>years</code></li>
      <li><code>months</code></li>
      <li><code>weeks</code></li>
      <li><code>days</code></li>
      <li><code>hours</code></li>
      <li><code>minutes</code></li>
      <li><code>seconds</code></li>
    </ul>

    <p>Por ejemplo, cualquiera de las siguientes directivas puede usarse para
    hacer que los documentos caduquen 1 mes después de haberse accedido a ellos,
    por defecto:</p>

    <highlight language="config">
ExpiresDefault "access plus 1 month"
ExpiresDefault "access plus 4 weeks"
ExpiresDefault "access plus 30 days"
    </highlight>

    <p>El tiempo de caducidad puede ajustarse con precisión añadiendo varias
    cláusulas "<var>num</var> <var>type</var>":</p>

    <highlight language="config">
ExpiresByType text/html "access plus 1 month 15 days 2 hours"
ExpiresByType image/gif "modification plus 5 hours 3 minutes"
    </highlight>

    <p>Tenga en cuenta que si usa un ajuste basado en la fecha de modificación, la
    cabecera Expires <strong>no</strong> se añadirá al contenido
    que no proceda de un archivo en disco. Esto se debe a que
    ese tipo de contenido no tiene fecha de modificación.</p>
</section>

<directivesynopsis>
<name>ExpiresActive</name>
<description>Activa la generación de cabeceras
<code>Expires</code></description>
<syntax>ExpiresActive On|Off</syntax>
<default>ExpiresActive Off</default>
<contextlist><context>server config</context>
<context>virtual host</context><context>directory</context>
<context>.htaccess</context></contextlist>
<override>Indexes</override>

<usage>
    <p>Esta directiva activa o desactiva la generación de las cabeceras
    <code>Expires</code> y <code>Cache-Control</code> para el
    ámbito de documentos en cuestión. (Es decir, si se encuentra en un
    archivo <code>.htaccess</code>, por ejemplo, solo se aplica a los
    documentos generados desde ese directorio.) Si se establece en
    <code>Off</code>, las cabeceras no se generarán para ningún
    documento del ámbito (a menos que se sobrescriba en un nivel inferior, como
    un archivo <code>.htaccess</code> que sobrescriba un archivo de
    configuración del servidor). Si se establece en <code>On</code>, las cabeceras se añadirán a
    los documentos servidos según los criterios definidos por las directivas
    <directive module="mod_expires">ExpiresByType</directive> y
    <directive module="mod_expires">ExpiresDefault</directive>
    (<em>q.v.</em>).</p>

    <p>Tenga en cuenta que esta directiva no garantiza que se vaya a
    generar una cabecera <code>Expires</code> o <code>Cache-Control</code>. Si no se
    cumplen los criterios, no se enviará ninguna cabecera, y
    el efecto será como si esta directiva ni siquiera se hubiera
    especificado.</p>
 </usage>
</directivesynopsis>

<directivesynopsis>
<name>ExpiresByType</name>
<description>Valor de la cabecera <code>Expires</code> configurado
por tipo MIME</description>
<syntax>ExpiresByType <var>MIME-type</var>
<var>&lt;code&gt;seconds</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>Indexes</override>

<usage>
    <p>Esta directiva define el valor de la cabecera <code>Expires</code>
    y de la directiva <code>max-age</code> de la cabecera
    <code>Cache-Control</code> generada para los documentos del
    tipo especificado (<em>p. ej.</em>, <code>text/html</code>). El segundo
    argumento establece el número de segundos que se añadirán a una hora base
    para construir la fecha de caducidad. El <code>Cache-Control:
    max-age</code> se calcula restando la hora de la petición a
    la fecha de caducidad y expresando el resultado en segundos.</p>

    <p>La hora base es o bien la hora de la última modificación del
    archivo, o la hora de acceso del cliente al documento. Cuál
    debe usarse se especifica mediante el campo
    <code><var>&lt;code&gt;</var></code>; <code>M</code>
    significa que debe usarse como hora base la hora de la última
    modificación del archivo, y <code>A</code> significa que debe usarse
    la hora de acceso del cliente.</p>

    <p>La diferencia en el efecto es sutil. Si se usa <code>M</code>,
    todas las copias actuales del documento en todas las cachés caducarán en
    el mismo momento, lo que puede ser bueno para algo como un aviso semanal
    que siempre se encuentra en la misma URL. Si se usa <code>A</code>,
    la fecha de caducidad es distinta para cada cliente; esto
    puede ser bueno para archivos de imagen que no cambian muy a menudo,
    especialmente para un conjunto de documentos relacionados que todos hacen referencia a
    las mismas imágenes (<em>es decir</em>, se accederá a las imágenes
    repetidamente en un periodo de tiempo relativamente corto).</p>

    <example><title>Ejemplo:</title>
    <highlight language="config">
# activar las caducidades
ExpiresActive On
# caducar las imágenes GIF después de un mes en la caché del cliente
ExpiresByType image/gif A2592000
# los documentos HTML son válidos durante una semana desde el
# momento en que se modificaron
ExpiresByType text/html M604800
      </highlight>
    </example>

    <p>Tenga en cuenta que esta directiva solo tiene efecto si
    se ha especificado <code>ExpiresActive On</code>. Sobrescribe,
    únicamente para el tipo MIME especificado, cualquier fecha de caducidad
    establecida por la directiva <directive module="mod_expires">ExpiresDefault</directive>.</p>

    <p>También puede especificar el cálculo del tiempo de caducidad usando
    una <a href="#AltSyn">sintaxis alternativa</a>, descrita anteriormente en
    este documento.</p>

    <p>El tipo MIME puede usar un carácter comodín para el subtipo, por
    ejemplo <code>image/*</code>. Esto coincidirá con cualquier tipo bajo
    ese tipo principal. Cuando el tipo de contenido de una petición no coincide con
    una entrada <directive>ExpiresByType</directive> concreta, se comprueba
    una entrada con comodín para el tipo principal antes de recurrir
    a <directive module="mod_expires">ExpiresDefault</directive>.</p>

    <example><title>Ejemplo con comodín:</title>
    <highlight language="config">
ExpiresActive On
# Todas las imágenes caducan al cabo de 1 mes
ExpiresByType image/* "access plus 1 month"
# Sobrescribir específicamente para GIF
ExpiresByType image/gif "access plus 1 week"
    </highlight>
    </example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ExpiresDefault</name>
<description>Algoritmo por defecto para calcular el tiempo de caducidad</description>
<syntax>ExpiresDefault <var>&lt;code&gt;seconds</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>Indexes</override>

<usage>
    <p>Esta directiva establece el algoritmo por defecto para calcular el
    tiempo de caducidad de todos los documentos del ámbito afectado. Puede
    sobrescribirse por tipo mediante la directiva <directive
    module="mod_expires">ExpiresByType</directive>. Consulte la
    descripción de esa directiva para más detalles sobre la sintaxis del
    argumento, así como la descripción de la <a href="#AltSyn">sintaxis
    alternativa</a>.</p>
</usage>
</directivesynopsis>
</modulesynopsis>
