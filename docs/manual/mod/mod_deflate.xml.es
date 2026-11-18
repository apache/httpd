<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1934517 -->
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

<modulesynopsis metafile="mod_deflate.xml.meta">

<name>mod_deflate</name>
<description>Comprime el contenido antes de entregarlo al
cliente</description>
<status>Extension</status>
<sourcefile>mod_deflate.c</sourcefile>
<identifier>deflate_module</identifier>

<summary>
    <p>El módulo <module>mod_deflate</module> proporciona
    el filtro de salida <code>DEFLATE</code> que permite que la salida
    de su servidor se comprima antes de ser enviada al cliente a través de
    la red.</p>
</summary>
<seealso><a href="../filter.html">Filtros</a></seealso>

<section id="supportedencodings"><title>Codificaciones admitidas</title>
  <p>La codificación <code>gzip</code> es la única admitida para garantizar la compatibilidad completa
  con implementaciones de navegadores antiguos. La codificación <code>deflate</code> no está admitida,
  consulte la <a href="https://zlib.net/zlib_faq.html#faq39">documentación de zlib</a>
  para una explicación completa.
  </p>
</section>

<section id="recommended"><title>Ejemplos de configuración</title>
    <note type="warning"><title>Compresión y TLS</title>
        <p>Algunas aplicaciones web son vulnerables a un ataque de divulgación
        de información cuando una conexión TLS transporta datos comprimidos con deflate. Para más
        información, consulte los detalles de la familia de ataques "BREACH".</p>
    </note>
    <p>Esta es una configuración sencilla que comprime los tipos de contenido de texto más comunes.</p>

    <example><title>Comprimir solo unos pocos tipos</title>
    <highlight language="config">
AddOutputFilterByType DEFLATE text/html text/plain text/xml text/css text/javascript application/javascript
    </highlight>
    </example>

</section>

<section id="enable"><title>Activar la compresión</title>
    <note type="warning"><title>Compresión y TLS</title>
        <p>Algunas aplicaciones web son vulnerables a un ataque de divulgación
        de información cuando una conexión TLS transporta datos comprimidos con deflate. Para más
        información, consulte los detalles de la familia de ataques "BREACH".</p>
    </note>

    <section id="output"><title>Compresión de la salida</title>
      <p>La compresión se implementa mediante el <a href="../filter.html">filtro</a>
      <code>DEFLATE</code>. La siguiente directiva
      activará la compresión para los documentos en el contenedor donde
      se coloque:</p>

      <highlight language="config">
SetOutputFilter DEFLATE
SetEnvIfNoCase Request_URI "\.(?:gif|jpe?g|png)$" no-gzip
      </highlight>

      <p>Si desea restringir la compresión a tipos MIME concretos
      en general, puede usar la directiva <directive module="mod_filter"
      >AddOutputFilterByType</directive>. Aquí tiene un ejemplo de cómo
      activar la compresión solo para los archivos html de la
      documentación de Apache httpd:</p>

      <highlight language="config">
&lt;Directory "/your-server-root/manual"&gt;
    AddOutputFilterByType DEFLATE text/html
&lt;/Directory&gt;
      </highlight>

      <note><title>Nota</title>
        El filtro <code>DEFLATE</code> se inserta siempre después de los
        filtros RESOURCE, como PHP o SSI. Nunca afecta a las subpeticiones internas.
      </note>
      <note><title>Nota</title>
        Existe una variable de entorno <code>force-gzip</code>,
        establecida mediante <directive module="mod_env">SetEnv</directive>, que
        ignorará el ajuste de accept-encoding de su navegador y
        enviará la salida comprimida.
      </note>

    </section>
    <section id="inflate"><title>Descompresión de la salida</title>
      <p>El módulo <module>mod_deflate</module> también proporciona un filtro para
      inflar/descomprimir un cuerpo de respuesta comprimido con gzip. Para activar
      esta funcionalidad, debe insertar el filtro <code>INFLATE</code> en
      la cadena de filtros de salida mediante <directive module="core"
      >SetOutputFilter</directive> o <directive module="mod_mime"
      >AddOutputFilter</directive>, por ejemplo:</p>

      <highlight language="config">
&lt;Location "/dav-area"&gt;
    ProxyPass "http://example.com/"
    SetOutputFilter INFLATE
&lt;/Location&gt;
      </highlight>

      <p>Este ejemplo descomprimirá la salida comprimida con gzip de example.com, de modo que otros
      filtros puedan procesarla posteriormente.
      </p>

    </section>
    <section id="input"><title>Descompresión de la entrada</title>
      <p>El módulo <module>mod_deflate</module> también proporciona un filtro para
      descomprimir un cuerpo de petición comprimido con gzip. Para activar
      esta funcionalidad, debe insertar el filtro <code>DEFLATE</code> en
      la cadena de filtros de entrada mediante <directive module="core"
      >SetInputFilter</directive> o <directive module="mod_mime"
      >AddInputFilter</directive>, por ejemplo:</p>

      <highlight language="config">
&lt;Location "/dav-area"&gt;
    SetInputFilter DEFLATE
&lt;/Location&gt;
      </highlight>

      <p>Ahora, si una petición contiene una cabecera <code>Content-Encoding:
      gzip</code>, el cuerpo se descomprimirá automáticamente.
      Pocos navegadores tienen la capacidad de comprimir con gzip los cuerpos de las peticiones.
      Sin embargo, algunas aplicaciones especiales sí admiten la
      compresión de peticiones, por ejemplo algunos clientes de
      <a href="https://www.webdav.org">WebDAV</a>.</p>

      <note type="warning"><title>Nota sobre Content-Length</title>
        <p>Si usted mismo evalúa el cuerpo de la petición, <em>no confíe
        en la cabecera <code>Content-Length</code></em>.
        La cabecera Content-Length refleja la longitud de los
        datos entrantes del cliente y <em>no</em> el número de bytes del
        flujo de datos descomprimido.</p>
      </note>
    </section>
</section>

<section id="proxies"><title>Tratamiento de servidores proxy</title>

    <p>El módulo <module>mod_deflate</module> envía una cabecera de respuesta HTTP
    <code>Vary: Accept-Encoding</code> para avisar a los proxies de que
    una respuesta cacheada solo debe enviarse a los clientes que envíen la
    cabecera de petición <code>Accept-Encoding</code> apropiada. Esto
    evita que se envíe contenido comprimido a un cliente que no vaya a
    entenderlo.</p>

    <p>Si usa exclusiones especiales que dependen,
    por ejemplo, de la cabecera <code>User-Agent</code>, debe
    configurar manualmente una adición a la cabecera <code>Vary</code>
    para avisar a los proxies de las restricciones adicionales. Por ejemplo,
    en una configuración típica en la que la adición del filtro <code>DEFLATE</code>
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

    <p>Dado que <module>mod_deflate</module> vuelve a comprimir el contenido
    en cada petición, se puede obtener algún beneficio de rendimiento
    precomprimiendo el contenido e indicando a <module>mod_deflate</module> que lo sirva
    sin volver a comprimirlo. Esto puede lograrse con una
    configuración como la siguiente:</p>

    <highlight language="config">
&lt;IfModule mod_headers.c&gt;
    # Servir archivos CSS y JS comprimidos con gzip si existen
    # y el cliente admite gzip.
    RewriteCond "%{HTTP:Accept-encoding}" "gzip"
    RewriteCond "%{REQUEST_FILENAME}\.gz" -s
    RewriteRule "^(.*)\.(css|js)"         "$1\.$2\.gz" [QSA]

    # Servir los tipos de contenido correctos y evitar la doble compresión de mod_deflate.
    RewriteRule "\.css\.gz$" "-" [T=text/css,E=no-gzip:1]
    RewriteRule "\.js\.gz$"  "-" [T=text/javascript,E=no-gzip:1]


    &lt;FilesMatch "(\.js\.gz|\.css\.gz)$"&gt;
      # Servir el tipo de codificación correcto.
      Header append Content-Encoding gzip

      # Forzar a los proxies a cachear los archivos css/js comprimidos
      # y sin comprimir por separado.
      Header append Vary Accept-Encoding
    &lt;/FilesMatch&gt;
&lt;/IfModule&gt;
    </highlight>

</section>

<directivesynopsis>
<name>DeflateFilterNote</name>
<description>Guarda el ratio de compresión en una nota para el registro</description>
<syntax>DeflateFilterNote [<var>type</var>] <var>notename</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive>DeflateFilterNote</directive>
    especifica que debe adjuntarse a la petición una nota sobre los ratios
    de compresión. El nombre de la nota es el valor especificado para
    la directiva. Puede usar esa nota con fines estadísticos
    añadiendo el valor a su <a href="../logs.html#accesslog"
    >log de acceso</a>.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
DeflateFilterNote ratio

LogFormat '"%r" %b (%{ratio}n) "%{User-agent}i"' deflate
CustomLog "logs/deflate_log" deflate
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
DeflateFilterNote Input instream
DeflateFilterNote Output outstream
DeflateFilterNote Ratio ratio

LogFormat '"%r" %{outstream}n/%{instream}n (%{ratio}n%%)' deflate
CustomLog "logs/deflate_log" deflate
</highlight>
    </example>
</usage>
<seealso><module>mod_log_config</module></seealso>
</directivesynopsis>

<directivesynopsis>
<name>DeflateBufferSize</name>
<description>Tamaño del fragmento que zlib comprime a la vez</description>
<syntax>DeflateBufferSize <var>value</var></syntax>
<default>DeflateBufferSize 8096</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive>DeflateBufferSize</directive> especifica
    el tamaño en bytes de los fragmentos que zlib debe comprimir a la
    vez. Si el tamaño de la respuesta comprimida es mayor que el especificado
    por esta directiva, httpd pasará a usar la codificación fragmentada
    (cabecera HTTP <code>Transfer-Encoding</code> establecida a <code>Chunked</code>), con el
    efecto secundario de no establecer ninguna cabecera HTTP <code>Content-Length</code>. Esto es especialmente
    importante cuando httpd trabaja detrás de proxies de caché inverso o cuando httpd está configurado con
    <module>mod_cache</module> y <module>mod_cache_disk</module>, porque
    las respuestas HTTP sin ninguna cabecera <code>Content-Length</code> podrían no cachearse.
  </p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>DeflateWindowSize</name>
<description>Tamaño de la ventana de compresión de zlib</description>
<syntax>DeflateWindowSize <var>value</var></syntax>
<default>DeflateWindowSize 15</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive>DeflateWindowSize</directive> especifica el
    tamaño de la ventana de compresión de zlib (un valor entre 1 y 15). En general,
    cuanto mayor sea el tamaño de la ventana, mayor puede esperarse que sea el ratio de compresión.</p>
</usage>
</directivesynopsis>

<directivesynopsis>

<name>DeflateMemLevel</name>
<description>Cuánta memoria debe usar zlib para la compresión</description>
<syntax>DeflateMemLevel <var>value</var></syntax>
<default>DeflateMemLevel 9</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive>DeflateMemLevel</directive> especifica
    cuánta memoria debe usar zlib para la compresión
    (un valor entre 1 y 9).</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>DeflateCompressionLevel</name>
<description>Cuánta compresión se aplica a la salida</description>
<syntax>DeflateCompressionLevel <var>value</var></syntax>
<default>El valor por defecto de Zlib</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive>DeflateCompressionLevel</directive> especifica
        qué nivel de compresión debe usarse; cuanto mayor sea el valor,
        mejor será la compresión, pero más tiempo de CPU se requerirá
        para lograrlo.</p>
    <p>El valor debe estar entre 1 (menos compresión) y 9 (más compresión).</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>DeflateInflateLimitRequestBody</name>
<description>Tamaño máximo de los cuerpos de petición inflados</description>
<syntax>DeflateInflateLimitRequestBody <var>value</var></syntax>
<default>Ninguno, pero LimitRequestBody se aplica tras la inflado</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>All</override>
<compatibility>2.4.10 y posteriores</compatibility>

<usage>
    <p>La directiva <directive>DeflateInflateLimitRequestBody</directive>
        especifica el tamaño máximo de un cuerpo de petición inflado. Si no se establece,
        <directive module="core">LimitRequestBody</directive> se aplica al
        cuerpo inflado. Un valor de <code>0</code> significa que no se aplica límite
        alguno al tamaño del cuerpo inflado (pero otros límites, como
        <directive module="core">LimitRequestBody</directive>, pueden seguir aplicándose).</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>DeflateInflateRatioLimit</name>
<description>Ratio máximo de inflado para los cuerpos de petición</description>
<syntax>DeflateInflateRatioLimit <var>value</var></syntax>
<default>DeflateInflateRatioLimit 200</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>All</override>
<compatibility>2.4.10 y posteriores</compatibility>

<usage>
    <p>La directiva <directive>DeflateInflateRatioLimit</directive>
        especifica el ratio máximo entre el tamaño deflado e inflado de un
        cuerpo de petición inflado. Este ratio se comprueba mientras el cuerpo
        se va recibiendo, y si se sobrepasa más de
        <directive module="mod_deflate">DeflateInflateRatioBurst</directive>
        veces, la petición se terminará.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>DeflateInflateRatioBurst</name>
<description>Número máximo de veces que puede sobrepasarse el ratio de inflado
             para los cuerpos de petición</description>
<syntax>DeflateInflateRatioBurst <var>value</var></syntax>
<default>DeflateInflateRatioBurst 3</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>All</override>
<compatibility>2.4.10 y posteriores</compatibility>

<usage>
    <p>La directiva <directive>DeflateInflateRatioBurst</directive>
       especifica el número máximo de veces que se puede sobrepasar
       <directive module="mod_deflate">DeflateInflateRatioLimit</directive>
       antes de terminar la petición.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>DeflateAlterETag</name>
<description>Cómo debe modificarse la cabecera ETag de salida durante la compresión</description>
<syntax>DeflateAlterETag AddSuffix|NoChange|Remove</syntax>
<default>DeflateAlterETag AddSuffix</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>
<compatibility>Disponible en Apache 2.4.58 y posteriores</compatibility>

<usage>
    <p>La directiva <directive>DeflateAlterETag</directive> especifica
    cómo debe alterarse la cabecera ETag cuando una respuesta se comprime.</p>
    <dl>
    <dt>AddSuffix</dt>
    <dd><p>Añade el método de compresión al final del ETag, haciendo
        que las representaciones comprimidas y sin comprimir tengan ETags distintos.
        Este ha sido el comportamiento por defecto desde la versión 2.4.0, pero evita que se sirvan
        respuestas "HTTP Not Modified" (304) a peticiones condicionales de contenido
        comprimido.</p></dd>
    <dt>NoChange</dt>
    <dd><p>No cambia el ETag de una respuesta comprimida. Este era el comportamiento por defecto
        antes de la versión 2.4.0, pero no cumple la propiedad de HTTP/1.1 según la cual todas
        las representaciones del mismo recurso deben tener ETags distintos.</p></dd>
    <dt>Remove</dt>
    <dd><p>Elimina la cabecera ETag de las respuestas comprimidas. Esto impide
        que sean posibles algunas peticiones condicionales, pero evita
        los inconvenientes de las dos opciones anteriores.</p></dd>
    </dl>
</usage>
</directivesynopsis>

</modulesynopsis>
