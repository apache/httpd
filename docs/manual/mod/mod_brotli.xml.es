<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1934416 -->
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

<modulesynopsis metafile="mod_brotli.xml.meta">

<name>mod_brotli</name>
<description>Comprime el contenido mediante Brotli antes de entregarlo al
cliente</description>
<status>Extension</status>
<sourcefile>mod_brotli.c</sourcefile>
<identifier>brotli_module</identifier>
<compatibility>Disponible en la versión 2.4.26 y posteriores.</compatibility>
<summary>
    <p>El módulo <module>mod_brotli</module> proporciona
    el filtro de salida <code>BROTLI_COMPRESS</code> que permite que la
    salida de su servidor se comprima usando el formato de compresión brotli antes de ser enviada
    al cliente a través de la red. Este módulo usa la biblioteca Brotli disponible en
    <a href="https://github.com/google/brotli">https://github.com/google/brotli</a>.</p>
</summary>
<seealso><a href="../filter.html">Filtros</a></seealso>

<section id="recommended"><title>Ejemplos de configuración</title>
    <note type="warning"><title>Compresión y TLS</title>
        <p>Algunas aplicaciones web son vulnerables a un ataque de divulgación
        de información cuando una conexión TLS transporta datos comprimidos. Para más
        información, consulte los detalles de la familia de ataques "BREACH".</p>
    </note>
    <p>Esta es una configuración sencilla que comprime los tipos de contenido de texto más comunes.</p>

    <example><title>Comprimir solo unos pocos tipos</title>
    <highlight language="config">
AddOutputFilterByType BROTLI_COMPRESS text/html text/plain text/xml text/css text/javascript application/javascript
    </highlight>
    </example>

</section>

<section id="enable"><title>Activar la compresión</title>
    <note type="warning"><title>Compresión y TLS</title>
        <p>Algunas aplicaciones web son vulnerables a un ataque de divulgación
        de información cuando una conexión TLS transporta datos comprimidos. Para más
        información, consulte los detalles de la familia de ataques "BREACH".</p>
    </note>

    <section id="output"><title>Compresión de la salida</title>
      <p>La compresión se implementa mediante el <a href="../filter.html">filtro</a>
      <code>BROTLI_COMPRESS</code>. La siguiente directiva
      activará la compresión para los documentos en el contenedor donde
      se coloque:</p>

      <highlight language="config">
SetOutputFilter BROTLI_COMPRESS
SetEnvIfNoCase Request_URI \.(?:gif|jpe?g|png)$ no-brotli
      </highlight>

      <p>Si desea restringir la compresión a tipos MIME concretos
      en general, puede usar la directiva <directive module="mod_filter"
      >AddOutputFilterByType</directive>. Aquí tiene un ejemplo de cómo
      activar la compresión solo para los archivos html de la
      documentación de httpd:</p>

      <highlight language="config">
&lt;Directory "/your-server-root/manual"&gt;
    AddOutputFilterByType BROTLI_COMPRESS text/html
&lt;/Directory&gt;
      </highlight>

      <note><title>Nota</title>
        El filtro <code>BROTLI_COMPRESS</code> se inserta siempre después de los
        filtros RESOURCE, como PHP o SSI. Nunca afecta a las subpeticiones internas.
      </note>
      <note><title>Nota</title>
        Existe una variable de entorno <code>no-brotli</code>,
        establecida mediante <directive module="mod_env">SetEnv</directive>, que
        desactivará la compresión brotli para una petición concreta, aunque
        el cliente la admita.
      </note>

    </section>

</section>

<section id="proxies"><title>Tratamiento de servidores proxy</title>

    <p>El módulo <module>mod_brotli</module> envía una cabecera de respuesta HTTP
    <code>Vary: Accept-Encoding</code> para avisar a los proxies de que
    una respuesta cacheada solo debe enviarse a los clientes que envíen la
    cabecera de petición <code>Accept-Encoding</code> apropiada. Esto
    evita que se envíe contenido comprimido a un cliente que no vaya a
    entenderlo.</p>

    <p>Si usa exclusiones especiales que dependen,
    por ejemplo, de la cabecera <code>User-Agent</code>, debe
    configurar manualmente una adición a la cabecera <code>Vary</code>
    para avisar a los proxies de las restricciones adicionales. Por ejemplo,
    en una configuración típica en la que la adición del filtro <code>BROTLI_COMPRESS</code>
    depende de <code>User-Agent</code>, debería añadir:</p>

    <highlight language="config">
Header append Vary User-Agent
    </highlight>

    <p>Si su decisión sobre la compresión depende de información
    distinta de las cabeceras de la petición (<em>p. ej.</em> la versión de HTTP), debe establecer
    la cabecera <code>Vary</code> con el valor <code>*</code>. Esto evita
    que los proxies que cumplen las especificaciones puedan cachear el contenido por completo.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
Header set Vary *
    </highlight>
    </example>
</section>

<section id="precompressed"><title>Servir contenido
precomprimido</title>

    <p>Dado que <module>mod_brotli</module> vuelve a comprimir el contenido
    en cada petición, se puede obtener algún beneficio de rendimiento
    precomprimiendo el contenido e indicando a mod_brotli que lo sirva
    sin volver a comprimirlo. Esto puede lograrse con una
    configuración como la siguiente:</p>

    <highlight language="config">
&lt;IfModule mod_headers.c&gt;
    # Servir archivos CSS comprimidos con brotli si existen
    # y el cliente admite brotli.
    RewriteEngine On
    RewriteCond "%{HTTP:Accept-encoding}" "br"
    RewriteCond "%{LA-U:REQUEST_FILENAME}.br" "-s"
    RewriteRule "^(.*)\.css"              "$1.css.br" [QSA]

    # Servir archivos JS comprimidos con brotli si existen
    # y el cliente admite brotli.
    RewriteCond "%{HTTP:Accept-encoding}" "br"
    RewriteCond "%{LA-U:REQUEST_FILENAME}.br" "-s"
    RewriteRule "^(.*)\.js"               "$1.js.br" [QSA]

    # Servir los tipos de contenido correctos y evitar la doble compresión.
    RewriteRule "\.css\.br$" "-" [T=text/css,E=no-brotli:1,E=no-gzip:1]
    RewriteRule "\.js\.br$"  "-" [T=text/javascript,E=no-brotli:1,E=no-gzip:1]

    &lt;FilesMatch "(\.js\.br|\.css\.br)$"&gt;
      # Servir el tipo de codificación correcto.
      Header append Content-Encoding br

      # Forzar a los proxies a cachear los archivos css/js brotli
      # y no brotli por separado.
      Header append Vary Accept-Encoding
    &lt;/FilesMatch&gt;
&lt;/IfModule&gt;
    </highlight>

</section>

<directivesynopsis>
<name>BrotliFilterNote</name>
<description>Guarda el ratio de compresión en una nota para el registro</description>
<syntax>BrotliFilterNote [<var>type</var>] <var>notename</var></syntax>
<default>None</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive>BrotliFilterNote</directive>
    especifica que debe adjuntarse a la petición una nota sobre los ratios
    de compresión. El nombre de la nota es el valor especificado para
    la directiva. Puede usar esa nota con fines estadísticos
    añadiendo el valor a su <a href="../logs.html#accesslog"
    >log de acceso</a>.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
BrotliFilterNote ratio

LogFormat '"%r" %b (%{ratio}n) "%{User-agent}i"' brotli
CustomLog "logs/brotli_log" brotli
    </highlight>
    </example>

    <p>Si desea extraer valores más precisos de sus logs, puede
    usar el argumento <var>type</var> para especificar el tipo de dato
    que se deja como nota para el registro. <var>type</var> puede ser uno de:</p>

    <dl>
      <dt><code>Input</code></dt>
      <dd>Guarda en la nota el número de bytes del flujo de entrada del filtro.</dd>

      <dt><code>Output</code></dt>
      <dd>Guarda en la nota el número de bytes del flujo de salida del filtro.</dd>

      <dt><code>Ratio</code></dt>
      <dd>Guarda en la nota el ratio de compresión (<code>output/input * 100</code>).
      Este es el valor por defecto si se omite el argumento
      <var>type</var>.</dd>
    </dl>

    <p>Así, puede registrarlo de esta manera:</p>

    <example><title>Registro preciso</title>
    <highlight language="config">
BrotliFilterNote Input instream
BrotliFilterNote Output outstream
BrotliFilterNote Ratio ratio

LogFormat '"%r" %{outstream}n/%{instream}n (%{ratio}n%%)' brotli
CustomLog "logs/brotli_log" brotli
    </highlight>
    </example>
</usage>
<seealso><module>mod_log_config</module></seealso>
</directivesynopsis>

<directivesynopsis>
<name>BrotliCompressionQuality</name>
<description>Calidad de compresión</description>
<syntax>BrotliCompressionQuality <var>value</var></syntax>
<default>BrotliCompressionQuality 5</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive>BrotliCompressionQuality</directive> especifica
    la calidad de compresión (un valor entre 0 y 11). Los valores más altos
    dan como resultado una compresión mejor pero más lenta. El valor por defecto de 5 es un
    equilibrio razonable para contenido dinámico.</p>

    <example><title>Compresión rápida para contenido dinámico</title>
    <highlight language="config">
# La calidad 4 es aproximadamente equivalente al nivel 6 de gzip
BrotliCompressionQuality 4
    </highlight>
    </example>

    <example><title>Compresión máxima para contenido estático</title>
    <highlight language="config">
# Mejor ratio pero muy lento; solo adecuado si se usa con caché
BrotliCompressionQuality 11
    </highlight>
    </example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>BrotliCompressionWindow</name>
<description>Tamaño de la ventana deslizante de compresión de brotli</description>
<syntax>BrotliCompressionWindow <var>value</var></syntax>
<default>BrotliCompressionWindow 18</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive>BrotliCompressionWindow</directive> especifica el
    tamaño de la ventana deslizante de compresión de brotli (un valor entre 10 y 24,
    que representa una ventana de 2^<var>value</var> bytes). Por
    ejemplo, 18 (el valor por defecto) da una ventana de 256 KB, mientras que 24 da
    16 MB. Los tamaños de ventana mayores pueden mejorar la calidad de la compresión, pero
    requieren más memoria por conexión.</p>

    <example><title>Ventana moderada para un uso de memoria equilibrado</title>
    <highlight language="config">
# Ventana de 1 MB (2^20 bytes)
BrotliCompressionWindow 20
    </highlight>
    </example>

    <example><title>Ventana máxima para la mejor compresión</title>
    <highlight language="config">
# Ventana de 16 MB (2^24 bytes); requiere bastante memoria por conexión
BrotliCompressionWindow 24
    </highlight>
    </example>
</usage>
</directivesynopsis>

<directivesynopsis>

<name>BrotliCompressionMaxInputBlock</name>
<description>Tamaño máximo del bloque de entrada</description>
<syntax>BrotliCompressionMaxInputBlock <var>value</var></syntax>
<default>(automatic)</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive>BrotliCompressionMaxInputBlock</directive> especifica
    el tamaño máximo del bloque de entrada como potencia de dos, entre 16 y 24
    (lo que representa bloques de 2^<var>value</var> bytes, es decir,
    de 64 KB a 16 MB). Los bloques de mayor tamaño pueden mejorar la compresión, pero
    requieren más memoria. Cuando no se establece, el tamaño del bloque se
    selecciona automáticamente en función del valor de calidad.</p>

    <example><title>Bloques de entrada explícitos de 1 MB</title>
    <highlight language="config">
# 2^20 = bloques de 1 MB
BrotliCompressionMaxInputBlock 20
    </highlight>
    </example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>BrotliAlterETag</name>
<description>Cómo debe modificarse la cabecera ETag de salida durante la compresión</description>
<syntax>BrotliAlterETag AddSuffix|NoChange|Remove</syntax>
<default>BrotliAlterETag AddSuffix</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive>BrotliAlterETag</directive> especifica
    cómo debe alterarse la cabecera ETag cuando una respuesta se comprime.</p>
    <dl>
    <dt>AddSuffix</dt>
    <dd><p>Añade el método de compresión al final del ETag, haciendo
        que las representaciones comprimidas y sin comprimir tengan ETags distintos.
        En otro módulo de compresión dinámica, mod_deflate, este ha sido el
        comportamiento por defecto desde la versión 2.4.0. Esta opción evita que se sirvan
        respuestas "HTTP Not Modified" (304) a peticiones condicionales de contenido
        comprimido.</p></dd>
    <dt>NoChange</dt>
    <dd><p>No cambia el ETag de una respuesta comprimida. En otro módulo de
        compresión dinámica, mod_deflate, este ha sido el comportamiento por defecto antes de
        la versión 2.4.0. Esta opción no cumple la propiedad de HTTP/1.1 según la cual todas
        las representaciones del mismo recurso deben tener ETags distintos.</p></dd>
    <dt>Remove</dt>
    <dd><p>Elimina la cabecera ETag de las respuestas comprimidas. Esto impide
        que sean posibles algunas peticiones condicionales, pero evita
        los inconvenientes de las dos opciones anteriores.</p></dd>
    </dl>
</usage>
</directivesynopsis>

</modulesynopsis>
