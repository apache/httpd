<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1939369 -->
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

<modulesynopsis metafile="mod_mime.xml.meta">

<name>mod_mime</name>
<description>Asocia las extensiones del nombre de archivo solicitado
    con el comportamiento del archivo (handlers y filtros)
    y su contenido (tipo mime, idioma, conjunto de caracteres y
    codificación)</description>
<status>Base</status>
<sourcefile>mod_mime.c</sourcefile>
<identifier>mime_module</identifier>

<summary>
    <p>Este módulo se usa para asignar metadatos de contenido al contenido
    seleccionado para una respuesta HTTP, relacionando patrones en la
    URI o en los nombres de archivo con los valores de esos metadatos. Por ejemplo, las
    extensiones de nombre de archivo de los archivos de contenido a menudo definen el tipo de medio de Internet,
    el idioma, el conjunto de caracteres y la codificación de contenido. Esta
    información se envía en los mensajes HTTP que contienen ese contenido y se
    usa en la negociación de contenido al elegir entre alternativas, de forma que
    se respeten las preferencias del usuario al escoger uno de varios
    contenidos posibles que servir. Consulte
    <module>mod_negotiation</module> para más información
    sobre la <a href="../content-negotiation.html">negociación de contenido</a>.</p>

    <p>Las directivas <directive
    module="mod_mime">AddCharset</directive>, <directive
    module="mod_mime">AddEncoding</directive>, <directive
    module="mod_mime">AddLanguage</directive> y <directive
    module="mod_mime">AddType</directive> se usan todas para relacionar
    extensiones de archivo con los metadatos de ese archivo. Respectivamente,
    establecen el conjunto de caracteres, la codificación de contenido, el idioma de contenido
    y el <glossary>tipo de medio</glossary> (tipo de contenido) de los documentos. La directiva <directive
    module="mod_mime">TypesConfig</directive> se usa para especificar un
    archivo que también relaciona extensiones con tipos de medio. </p>

    <p>Además, <module>mod_mime</module> puede definir el <a
    href="../handler.html">handler</a> y los <a
    href="../filter.html">filtros</a> que originan y procesan el
    contenido. Las directivas <directive
    module="mod_mime">AddHandler</directive>, <directive
    module="mod_mime">AddOutputFilter</directive> y <directive
    module="mod_mime">AddInputFilter</directive> controlan los módulos
    o scripts que sirven el documento. La directiva <directive
    module="mod_mime">MultiviewsMatch</directive> permite que
    <module>mod_negotiation</module> considere que estas extensiones de archivo
    deben incluirse al comprobar coincidencias de Multiviews.</p>

    <p>Mientras que <module>mod_mime</module> asocia metadatos
    con extensiones de nombre de archivo, el servidor <module>core</module>
    proporciona directivas que se usan para asociar todos los archivos de un
    contenedor dado (<em>p. ej.</em>, <directive type="section"
    module="core">Location</directive>, <directive type="section"
    module="core">Directory</directive>, o <directive type="section"
    module="core">Files</directive>) con unos metadatos
    concretos. Estas directivas incluyen <directive
    module="core">ForceType</directive>, <directive
    module="core">SetHandler</directive>, <directive
    module="core">SetInputFilter</directive> y <directive
    module="core">SetOutputFilter</directive>. Las directivas del core
    prevalecen sobre cualquier relación por extensión de archivo definida en
    <module>mod_mime</module>.</p>

    <p>Tenga en cuenta que cambiar los metadatos de un archivo no
    cambia el valor de la cabecera <code>Last-Modified</code>.
    Por tanto, un cliente o un proxy pueden seguir usando copias cacheadas
    previamente, con las cabeceras anteriores. Si cambia los
    metadatos (idioma, tipo de contenido, conjunto de caracteres o
    codificación), puede que necesite hacer un 'touch' de los archivos afectados
    (actualizando su fecha de última modificación) para garantizar que todos los visitantes
    reciban las cabeceras de contenido corregidas.</p>
</summary>
<seealso><directive
module="mod_mime_magic">MimeMagicFile</directive></seealso>
<seealso><directive module="core">AddDefaultCharset</directive></seealso>
<seealso><directive module="core">ForceType</directive></seealso>
<seealso><directive module="core">SetHandler</directive></seealso>
<seealso><directive module="core">SetInputFilter</directive></seealso>
<seealso><directive module="core">SetOutputFilter</directive></seealso>

<section id="multipleext"><title>Archivos con varias extensiones</title>
    <p>Los archivos pueden tener más de una extensión; el orden de las
    extensiones <em>normalmente</em> no es relevante. Por ejemplo, si el
    archivo <code>welcome.html.fr</code> se relaciona con el tipo de contenido
    <code>text/html</code> y el idioma francés, entonces el archivo
    <code>welcome.fr.html</code> se relacionará exactamente con la misma
    información. Si se indica más de una extensión que se relacione con
    el mismo tipo de metadato, se usará la de más a la derecha,
    excepto para idiomas y codificaciones de contenido. Por ejemplo,
    si <code>.gif</code> se relaciona con el <glossary>tipo de medio</glossary>
    <code>image/gif</code> y <code>.html</code> se relaciona con el
    tipo de medio <code>text/html</code>, entonces el archivo
    <code>welcome.gif.html</code> se asociará con el
    tipo de medio <code>text/html</code>.</p>

    <p>Los <a href="#charset-lang">idiomas</a> y las <a href="#contentencoding"
    >codificaciones de contenido</a> se tratan de forma acumulativa, porque se puede asignar
    más de un idioma o codificación a un recurso concreto. Por ejemplo,
    el archivo <code>welcome.html.en.de</code> se entregará con
    <code>Content-Language: en, de</code> y <code>Content-Type:
    text/html</code>.</p>

    <p>Hay que tener cuidado cuando un archivo con varias extensiones
    se asocia a la vez con un <glossary>tipo de medio</glossary>
    y con un handler. Esto
    normalmente hará que la petición la gestione el módulo asociado
    con el handler. Por ejemplo, si la extensión <code>.imap</code>
    se relaciona con el handler <code>imap-file</code> (de
    <module>mod_imagemap</module>) y la extensión <code>.html</code> se
    relaciona con el tipo de medio <code>text/html</code>, entonces el archivo
    <code>world.imap.html</code> se asociará tanto con el
    handler <code>imap-file</code> como con el tipo de medio <code>text/html</code>.
    Al procesarse, se usará el handler <code>imap-file</code>,
    por lo que se tratará como un archivo de mapa de imagen de
    <module>mod_imagemap</module>.</p>

    <p>Si prefiere que solo la última parte del nombre de archivo separada por puntos
    se relacione con un metadato concreto, no use las
    directivas <code>Add*</code>. Por ejemplo, si quiere
    que el archivo <code>foo.html.asis</code> lo sirva el handler <code>send-as-is</code>
    proporcionado por el script de <module>mod_asis</module>,
    pero no el archivo <code>bar.asis.html</code>, en lugar
    de usar <code>AddHandler send-as-is .asis</code>, use</p>

    <example><title>Configurar el handler basándose solo en la extensión final</title>
    <highlight language="config">
&lt;FilesMatch "[^.]+\.asis$"&gt;
  SetHandler send-as-is
&lt;/FilesMatch&gt;
    </highlight>
    </example>

    <note><title>Archivos sin extensión</title>
    <p>Los archivos sin extensión (como <code>Makefile</code>) no se pueden
    hacer coincidir con las directivas basadas en extensión de <module>mod_mime</module>.
    Para establecer el tipo de contenido o el charset de estos archivos, use en su lugar
    una sección <directive type="section" module="core">Files</directive> o
    <directive type="section" module="core">FilesMatch</directive>:</p>

    <highlight language="config">
# For a specific file:
&lt;Files "Makefile"&gt;
    ForceType text/plain
    AddDefaultCharset UTF-8
&lt;/Files&gt;

# For all files with no extension:
&lt;FilesMatch "^[^.]+$"&gt;
    ForceType text/plain
    AddDefaultCharset UTF-8
&lt;/FilesMatch&gt;
    </highlight>
    </note>

</section>

<section id="contentencoding"><title>Codificación de contenido</title>
    <p>Un archivo de un <glossary>tipo de medio</glossary> concreto puede, además, codificarse de una
    forma determinada para simplificar su transmisión por Internet.
    Aunque normalmente esto se refiere a compresión, como
    <code>gzip</code>, también puede referirse a cifrado, como
    <code>pgp</code>, o a una codificación como UUencoding, que
    está diseñada para transmitir un archivo binario en un formato
    ASCII (texto).</p>

    <p>El RFC de HTTP/1.1 (<rfc>2616</rfc>), en su sección 14.11, lo expresa así:</p>

    <blockquote cite="https://www.rfc-editor.org/rfc/rfc2616">
      <p>The Content-Encoding entity-header field is used as a modifier to
      the media-type. When present, its value indicates what additional
      content codings have been applied to the entity-body, and thus what
      decoding mechanisms must be applied in order to obtain the media-type
      referenced by the Content-Type header field. Content-Encoding is
      primarily used to allow a document to be compressed without losing
      the identity of its underlying media type.</p>
    </blockquote>

    <p>Usando más de una extensión de archivo (vea la <a
    href="#multipleext">sección anterior sobre varias
    extensiones de archivo</a>), puede indicar que un archivo es de un
    <em>tipo</em> concreto, y que además tiene una
    <em>codificación</em> concreta. </p>

    <p>Por ejemplo, puede tener un archivo que sea un documento de
    Microsoft Word, comprimido con pkzip para reducir su tamaño. Si la
    extensión <code>.doc</code> está asociada con el tipo de archivo de Microsoft
    Word, y la extensión <code>.zip</code> está
    asociada con la codificación de archivo pkzip, entonces se sabrá que el archivo
    <code>Resume.doc.zip</code> es un documento de Word comprimido con
    pkzip.</p>

    <p>Apache envía una cabecera <code>Content-encoding</code> con el
    recurso, para indicar al navegador cliente el
    método de codificación.</p>

    <highlight language="config">
Content-encoding: pkzip
    </highlight>
</section>

<section id="charset-lang"><title>Conjuntos de caracteres e idiomas</title>
    <p>Además del tipo de archivo y de su codificación,
    otro dato importante es en qué idioma está un
    documento concreto, y en qué conjunto de caracteres debe
    mostrarse el archivo. Por ejemplo, el documento puede estar escrito
    en el alfabeto vietnamita, o en cirílico, y debería
    mostrarse como tal. Esta información también se transmite en
    las cabeceras HTTP.</p>

    <p>El conjunto de caracteres, el idioma, la codificación y el tipo mime se
    usan todos en el proceso de negociación de contenido (vea
    <module>mod_negotiation</module>) para determinar
    qué documento entregar al cliente, cuando hay documentos
    alternativos en más de un conjunto de caracteres, idioma,
    codificación o tipo mime. Todas las asociaciones de extensiones de archivo
    creadas con las directivas <directive module="mod_mime">AddCharset</directive>,
    <directive module="mod_mime">AddEncoding</directive>, <directive
    module="mod_mime">AddLanguage</directive> y <directive
    module="mod_mime">AddType</directive>
    (y las extensiones listadas en <directive module="mod_mime_magic"
    >MimeMagicFile</directive>) participan en este proceso de selección.
    Las extensiones de archivo asociadas únicamente mediante las directivas <directive
    module="mod_mime">AddHandler</directive>, <directive module="mod_mime"
    >AddInputFilter</directive> o <directive module="mod_mime"
    >AddOutputFilter</directive> pueden incluirse o excluirse
    de la coincidencia usando la directiva <directive module="mod_mime"
    >MultiviewsMatch</directive>.</p>

    <section id="charset"><title>Charset</title>
      <p>Para transmitir esta información adicional, Apache puede enviar opcionalmente
      una cabecera <code>Content-Language</code>, para indicar el idioma
      en el que está el documento, y puede añadir información
      adicional a la cabecera <code>Content-Type</code> para indicar el
      conjunto de caracteres concreto que debe usarse para procesar
      correctamente la información.</p>

      <example>
Content-Language: en, fr
Content-Type: text/plain; charset=ISO-8859-1
      </example>

      <p>El idioma se especifica con la abreviatura de dos letras
      del idioma. El <code>charset</code> es el nombre del
      conjunto de caracteres concreto que debe usarse.</p>
    </section>
</section>

<directivesynopsis>
<name>AddCharset</name>
<description>Relaciona las extensiones de archivo indicadas con el charset de
contenido especificado</description>
<syntax>AddCharset <var>charset</var> <var>extension</var>
[<var>extension</var>] ...</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>
    <p>La directiva <directive>AddCharset</directive> relaciona las
    extensiones de archivo indicadas con el charset de contenido especificado (el nombre
    registrado en Internet para una codificación de caracteres dada). <var>charset</var>
    es el <a href="http://www.iana.org/assignments/character-sets">parámetro charset
    del tipo de medio</a> para los recursos cuyos nombres de archivo contengan
    <var>extension</var>. Esta relación se añade a las ya vigentes,
    sobrescribiendo cualquier relación que ya exista para la misma
    <var>extension</var>.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
AddLanguage ja .ja
AddCharset EUC-JP .euc
AddCharset ISO-2022-JP .jis
AddCharset SHIFT_JIS .sjis
      </highlight>
    </example>

    <p>Entonces, el documento <code>xxxx.ja.jis</code> se tratará
    como un documento en japonés cuyo charset es <code>ISO-2022-JP</code>
    (igual que el documento <code>xxxx.jis.ja</code>). La directiva
    <directive>AddCharset</directive> es útil tanto para
    informar al cliente sobre la codificación de caracteres del documento, de modo que
    pueda interpretarse y mostrarse adecuadamente, como para la <a
    href="../content-negotiation.html">negociación de contenido</a>,
    donde el servidor devuelve uno entre varios documentos según
    la preferencia de charset del cliente.</p>

    <p>El argumento <var>extension</var> no distingue mayúsculas y minúsculas y puede
    especificarse con o sin un punto inicial. Los nombres de archivo pueden tener <a
    href="#multipleext">varias extensiones</a> y el argumento
    <var>extension</var> se comparará con cada una de
    ellas.</p>

</usage>
<seealso><module>mod_negotiation</module></seealso>
<seealso><directive module="core">AddDefaultCharset</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>AddEncoding</name>
<description>Relaciona las extensiones de archivo indicadas con el tipo de
codificación especificado</description>
<syntax>AddEncoding <var>encoding</var> <var>extension</var>
[<var>extension</var>] ...</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>
    <p>La directiva <directive>AddEncoding</directive> relaciona las
    extensiones de archivo indicadas con la codificación de contenido HTTP especificada.
    <var>encoding</var> es la codificación de contenido HTTP que se añade al
    valor del campo de cabecera Content-Encoding para los documentos con
    la <var>extension</var> indicada. Esta relación se añade a las ya vigentes,
    sobrescribiendo cualquier relación que ya exista para la misma
    <var>extension</var>.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
AddEncoding x-gzip .gz
AddEncoding x-compress .Z
      </highlight>
    </example>

    <p>Esto hará que los nombres de archivo que contengan la extensión <code>.gz</code>
    se marquen como codificados usando la codificación <code>x-gzip</code>, y que
    los nombres de archivo que contengan la extensión <code>.Z</code> se marquen como
    codificados con <code>x-compress</code>.</p>

    <p>Los clientes antiguos esperan <code>x-gzip</code> y <code>x-compress</code>,
    sin embargo, el estándar establece que son equivalentes a
    <code>gzip</code> y <code>compress</code> respectivamente. Apache hace
    las comparaciones de codificación de contenido ignorando cualquier <code>x-</code> inicial.
    Al responder con una codificación, Apache usará la forma que el
    cliente haya solicitado (<em>i.e.</em>, <code>x-foo</code> o <code>foo</code>).
    Si el cliente no solicitó específicamente una forma
    concreta, Apache usará la forma indicada por la directiva
    <code>AddEncoding</code>. Para resumir, siempre debería
    usar <code>x-gzip</code> y <code>x-compress</code> para estas dos
    codificaciones concretas. Las codificaciones más
    recientes, como <code>deflate</code>, deberían
    especificarse sin el <code>x-</code>.</p>

    <p>El argumento <var>extension</var> no distingue mayúsculas y minúsculas y puede
    especificarse con o sin un punto inicial. Los nombres de archivo pueden tener <a
    href="#multipleext">varias extensiones</a> y el argumento
    <var>extension</var> se comparará con cada una de
    ellas.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AddHandler</name>
<description>Relaciona las extensiones de archivo con el handler
indicado</description>
<syntax>AddHandler <var>handler-name</var> <var>extension</var>
[<var>extension</var>] ...</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>
    <p>Los archivos con el nombre <var>extension</var> se servirán con el
    <var><a href="../handler.html">handler-name</a></var> indicado. Esta
    relación se añade a las ya vigentes, sobrescribiendo cualquier relación que
    ya exista para la misma <var>extension</var>. Por ejemplo, para asociar
    los archivos <code>.var</code> con el handler <code>type-map</code> proporcionado por
    <module>mod_negotiation</module>, podría usar:</p>

    <highlight language="config">
AddHandler type-map .var
    </highlight>

    <p>El argumento <var>extension</var> no distingue mayúsculas y minúsculas y puede
    especificarse con o sin un punto inicial. Los nombres de archivo pueden tener <a
    href="#multipleext">varias extensiones</a> y el argumento
    <var>extension</var> se comparará con cada una de
    ellas.</p>
</usage>
<seealso><directive module="core">SetHandler</directive></seealso>
<seealso><directive module="mod_dir">FallbackResource</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>AddInputFilter</name>
<description>Relaciona extensiones de archivo con los filtros que procesarán
las peticiones de los clientes</description>
<syntax>AddInputFilter <var>filter</var>[;<var>filter</var>...]
<var>extension</var> [<var>extension</var>] ...</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>
    <p><directive>AddInputFilter</directive> relaciona la extensión de archivo
    <var>extension</var> con los <a href="../filter.html">filtros</a> que
    procesarán las peticiones de los clientes y la entrada POST cuando el servidor
    los recibe. Esto se añade a cualquier filtro definido en otro lugar,
    incluida la directiva <directive module="core">SetInputFilter</directive>.
    Esta relación se combina con cualquiera ya vigente, sobrescribiendo
    cualquier relación que ya exista para la misma <var>extension</var>.</p>

    <p>Si se especifica más de un <var>filter</var>, deben separarse
    con punto y coma en el orden en que deben procesar el
    contenido. El <var>filter</var> no distingue mayúsculas y minúsculas.</p>

    <p>El argumento <var>extension</var> no distingue mayúsculas y minúsculas y puede
    especificarse con o sin un punto inicial. Los nombres de archivo pueden tener <a
    href="#multipleext">varias extensiones</a> y el argumento
    <var>extension</var> se comparará con cada una de
    ellas.</p>

</usage>
<seealso><directive module="mod_mime">RemoveInputFilter</directive></seealso>
<seealso><directive module="core">SetInputFilter</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>AddLanguage</name>
<description>Relaciona la extensión de archivo indicada con el idioma de
contenido especificado</description>
<syntax>AddLanguage <var>language-tag</var> <var>extension</var>
[<var>extension</var>] ...</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>
    <p>La directiva <directive>AddLanguage</directive> relaciona la
    extensión de archivo indicada con el idioma de contenido especificado. A los archivos con la
    <var>extension</var> indicada se les asigna un valor de Content-Language HTTP
    de <var>language-tag</var>, correspondiente a los identificadores de idioma
    definidos por RFC 3066.
    Esta directiva sobrescribe cualquier relación que ya exista para la misma
    <var>extension</var>.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
AddEncoding x-compress .Z
AddLanguage en .en
AddLanguage fr .fr
      </highlight>
    </example>

    <p>Entonces, el documento <code>xxxx.en.Z</code> se tratará como
    un documento en inglés comprimido (igual que el documento
    <code>xxxx.Z.en</code>). Aunque el idioma de contenido se
    informa al cliente, es poco probable que el navegador use esta
    información. La directiva <directive>AddLanguage</directive> es
    más útil para la <a href="../content-negotiation.html">negociación
    de contenido</a>, donde el servidor devuelve uno entre varios documentos
    según la preferencia de idioma del cliente.</p>

    <p>Si se hacen varias asignaciones de idioma para la misma
    extensión, se usa la última que se encuentre.
    Es decir, en el caso de:</p>

    <highlight language="config">
AddLanguage en .en
AddLanguage en-gb .en
AddLanguage en-us .en
    </highlight>

    <p>los documentos con la extensión <code>.en</code> se tratarían como si
    fueran <code>en-us</code>.</p>

    <p>El argumento <var>extension</var> no distingue mayúsculas y minúsculas y puede
    especificarse con o sin un punto inicial. Los nombres de archivo pueden tener <a
    href="#multipleext">varias extensiones</a> y el argumento
    <var>extension</var> se comparará con cada una de
    ellas.</p>
</usage>
<seealso><module>mod_negotiation</module></seealso>
</directivesynopsis>

<directivesynopsis>
<name>AddOutputFilter</name>
<description>Relaciona extensiones de archivo con los filtros que procesarán
las respuestas del servidor</description>
<syntax>AddOutputFilter <var>filter</var>[;<var>filter</var>...]
<var>extension</var> [<var>extension</var>] ...</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>
    <p>La directiva <directive>AddOutputFilter</directive> relaciona la
    extensión de archivo <var>extension</var> con los <a
    href="../filter.html">filtros</a> que procesarán las respuestas
    del servidor antes de enviarse al cliente. Esto se añade
    a cualquier filtro definido en otro lugar, incluidas las directivas <directive
    module="core">SetOutputFilter</directive> y <directive module="mod_filter"
    >AddOutputFilterByType</directive>. Esta relación se combina
    con cualquiera ya vigente, sobrescribiendo cualquier relación que ya exista
    para la misma <var>extension</var>.</p>

    <p>Por ejemplo, la siguiente configuración procesará todos los
    archivos <code>.shtml</code> para server-side includes, y después
    comprimirá la salida usando <module>mod_deflate</module>.</p>

    <highlight language="config">
AddOutputFilter INCLUDES;DEFLATE shtml
    </highlight>

    <p>Si se especifica más de un filtro, deben separarse
    con punto y coma en el orden en que deben procesar el
    contenido. El argumento <var>filter</var> no distingue mayúsculas y minúsculas.</p>

    <p>El argumento <var>extension</var> no distingue mayúsculas y minúsculas y puede
    especificarse con o sin un punto inicial. Los nombres de archivo pueden tener <a
    href="#multipleext">varias extensiones</a> y el argumento
    <var>extension</var> se comparará con cada una de
    ellas.</p>

    <p>Tenga en cuenta que al definir un conjunto de filtros usando la
    directiva <directive module="mod_mime">AddOutputFilter</directive>,
    cualquier definición que haga sustituirá a cualquier definición anterior hecha con
    la directiva <directive module="mod_mime">AddOutputFilter</directive>.</p>

    <highlight language="config">
# Effective filter "DEFLATE"
AddOutputFilter DEFLATE shtml
&lt;Location "/foo"&gt;
  # Effective filter "INCLUDES", replacing "DEFLATE"
  AddOutputFilter INCLUDES shtml
&lt;/Location&gt;
&lt;Location "/bar"&gt;
  # Effective filter "INCLUDES;DEFLATE", replacing "DEFLATE"
  AddOutputFilter INCLUDES;DEFLATE shtml
&lt;/Location&gt;
&lt;Location "/bar/baz"&gt;
  # Effective filter "BUFFER", replacing "INCLUDES;DEFLATE"
  AddOutputFilter BUFFER shtml
&lt;/Location&gt;
&lt;Location "/bar/baz/buz"&gt;
  # No effective filter, replacing "BUFFER"
  RemoveOutputFilter shtml
&lt;/Location&gt;
    </highlight>
</usage>
<seealso><directive module="mod_mime">RemoveOutputFilter</directive></seealso>
<seealso><directive module="core">SetOutputFilter</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>AddType</name>
<description>Relaciona las extensiones de archivo indicadas con el tipo de
contenido especificado</description>
<syntax>AddType <var>media-type</var> <var>extension</var>
[<var>extension</var>] ...</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>
    <p>La directiva <directive>AddType</directive> relaciona las extensiones
    de archivo indicadas con el tipo de
    contenido especificado. <var>media-type</var> es el <glossary ref="media-type">tipo
    de medio</glossary> que se usará para los nombres de archivo que contengan
    <var>extension</var>. Esta relación se añade a las ya
    vigentes, sobrescribiendo cualquier relación que ya exista para la misma
    <var>extension</var>.</p>

    <note>
      Se recomienda añadir los nuevos tipos de medio usando la
      directiva <directive>AddType</directive> en lugar de modificar el
      archivo <directive module="mod_mime">TypesConfig</directive>.
    </note>

    <example><title>Ejemplo</title>
    <highlight language="config">
AddType image/gif .gif
    </highlight>
    </example>

    <p>O, para indicar varias extensiones de archivo en una sola directiva:</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
AddType image/jpeg jpeg jpg jpe
    </highlight>
    </example>

    <p>El argumento <var>extension</var> no distingue mayúsculas y minúsculas y puede
    especificarse con o sin un punto inicial. Los nombres de archivo pueden tener <a
    href="#multipleext">varias extensiones</a> y el argumento
    <var>extension</var> se comparará con cada una de
    ellas.</p>

    <p>Se puede lograr un efecto similar al de
    <directive module="mod_negotiation">LanguagePriority</directive> de
    <module>mod_negotiation</module> calificando un <var>media-type</var> con
    <code>qs</code>:</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
AddType application/rss+xml;qs=0.8 .xml
    </highlight>
    </example>

    <p>Esto es útil en situaciones, <em>p. ej.</em> cuando un cliente
    que solicita <code>Accept: */*</code> en realidad no puede procesar
    el contenido devuelto por el servidor.</p>

    <p>Esta directiva configura principalmente los tipos de contenido generados para
    los archivos estáticos servidos desde el sistema de archivos. Para recursos que no son
    archivos estáticos, donde el generador de la respuesta normalmente indica
    un Content-Type, esta directiva no tiene efecto.</p>


    <note><title>Nota</title>
    <p>Si no se establece explícitamente un handler para una petición, el tipo de contenido
    indicado también se usará como nombre del handler. </p>

    <p>Cuando directivas explícitas como
    <directive module="core" >SetHandler</directive> o
    <directive module="mod_mime">AddHandler</directive> no se aplican
    a la petición actual, el nombre interno de handler que normalmente establecen esas
    directivas se sustituye en su lugar por el tipo de contenido indicado por esta directiva.
    </p>
    <p>
    Este es un comportamiento histórico que pueden usar algunos módulos de terceros
    (como mod_php) para asumir la responsabilidad de la petición correspondiente.
    </p>

    <p>Deberían evitarse las configuraciones que dependen de estos tipos "sintéticos".
    Además, las configuraciones que restringen el acceso a
    <directive module="core" >SetHandler</directive> o
    <directive module="mod_mime">AddHandler</directive> deberían
    restringir también el acceso a esta directiva.</p>
    </note>

</usage>
<seealso><directive module="core">ForceType</directive></seealso>
<seealso><module>mod_negotiation</module></seealso>
</directivesynopsis>

<directivesynopsis>
<name>MultiviewsMatch</name>
<description>Los tipos de archivo que se incluirán al buscar
un archivo coincidente con MultiViews</description>
<syntax>MultiviewsMatch Any|NegotiatedOnly|Filters|Handlers
[Handlers|Filters]</syntax>
<default>MultiviewsMatch NegotiatedOnly</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>
    <p><directive>MultiviewsMatch</directive> permite tres comportamientos
    distintos para la funcionalidad Multiviews de <a href="mod_negotiation.html"
    >mod_negotiation</a>. Multiviews permite que una petición de un archivo,
    <em>p. ej.</em> <code>index.html</code>, coincida con cualquier
    extensión negociada que siga a la petición base, <em>p. ej.</em>
    <code>index.html.en</code>, <code>index.html.fr</code> o
    <code>index.html.gz</code>.</p>

    <p>La opción <code>NegotiatedOnly</code> establece que cada extensión
    que siga al nombre base debe corresponder a una extensión de <module>mod_mime</module>
    reconocida para negociación de contenido, <em>p. ej.</em>
    Charset, Content-Type, Language o Encoding. Esta es la implementación
    más estricta, con menos efectos secundarios inesperados, y es el
    comportamiento por defecto.</p>

    <p>Para incluir extensiones asociadas con Handlers y/o Filtros,
    establezca la directiva <directive>MultiviewsMatch</directive> a
    <code>Handlers</code>, <code>Filters</code>, o ambas palabras clave.
    Si todos los demás factores son iguales, se servirá el archivo más pequeño,
    <em>p. ej.</em> al decidir entre <code>index.html.cgi</code> de 500
    bytes e <code>index.html.pl</code> de 1000 bytes, en este ejemplo ganaría el archivo
    <code>.cgi</code>. Quienes usen archivos <code>.asis</code>
    pueden preferir usar la opción Handler, si los archivos <code>.asis</code> están
    asociados con el handler <code>send-as-is</code>.</p>

    <p>Por último, puede permitir que coincida <code>Any</code> extensión, aunque
    <module>mod_mime</module> no la reconozca. Esto puede provocar
    resultados impredecibles, como servir archivos .old o .bak que el webmaster
    nunca esperó que se sirvieran.</p>

    <p>Por ejemplo, la siguiente configuración permitirá que los handlers
    y los filtros participen en MultiViews, pero excluirá los archivos
    desconocidos:</p>

    <highlight language="config">
MultiviewsMatch Handlers Filters
    </highlight>

    <p><directive>MultiviewsMatch</directive> no se permite en una sección
    <directive type="section" module="core">Location</directive> o <directive
    type="section" module="core">LocationMatch</directive>.</p>

</usage>
<seealso><directive module="core">Options</directive></seealso>
<seealso><module>mod_negotiation</module></seealso>
</directivesynopsis>

<directivesynopsis>
<name>DefaultLanguage</name>
<description>Define un language-tag por defecto que se enviará en el campo de cabecera
Content-Language para todos los recursos en el contexto actual a los que no se
haya asignado un language-tag por otros medios.</description>
<syntax>DefaultLanguage <var>language-tag</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>
    <p>La directiva <directive>DefaultLanguage</directive> indica a Apache
    que a todos los recursos dentro del ámbito de la directiva (<em>p. ej.</em>, todos los recursos
    cubiertos por el contenedor <directive module="core" type="section"
    >Directory</directive> actual) que no tengan una extensión de idioma explícita
    (como <code>.fr</code> o <code>.de</code>, según se configure
    con <directive module="mod_mime">AddLanguage</directive>) se les
    asigne un Content-Language de <var>language-tag</var>. Esto permite
    marcar árboles de directorios completos como contenido en neerlandés, por
    ejemplo, sin tener que renombrar cada archivo. Tenga en cuenta que, a diferencia de usar
    extensiones para indicar idiomas, <directive>DefaultLanguage</directive>
    solo puede indicar un único idioma.</p>

    <p>Si no hay en vigor ninguna directiva <directive>DefaultLanguage</directive>
    y un archivo no tiene ninguna extensión de idioma según lo configurado
    con <directive module="mod_mime">AddLanguage</directive>, no se generará
    ningún campo de cabecera Content-Language.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
DefaultLanguage en
    </highlight>
    </example>
</usage>
<seealso><module>mod_negotiation</module></seealso>
</directivesynopsis>

<directivesynopsis>
<name>ModMimeUsePathInfo</name>
<description>Indica a <module>mod_mime</module> que trate los componentes de
<code>path_info</code> como parte del nombre de archivo</description>
<syntax>ModMimeUsePathInfo On|Off</syntax>
<default>ModMimeUsePathInfo Off</default>
<contextlist><context>directory</context></contextlist>

<usage>
    <p>La directiva <directive>ModMimeUsePathInfo</directive> se usa para
    combinar el nombre de archivo con el componente de URL <code>path_info</code> para
    aplicar las directivas de <module>mod_mime</module> a la petición. El valor
    por defecto es <code>Off</code>; por tanto, se ignora el componente
    <code>path_info</code>.</p>

    <p>Se recomienda esta directiva cuando dispone de un sistema de archivos virtual.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
ModMimeUsePathInfo On
    </highlight>
    </example>

    <p>Si tiene una petición para <code>/index.php/foo.shtml</code>,
    <module>mod_mime</module> tratará ahora la
    petición entrante como <code>/index.php/foo.shtml</code>, y directivas
    como <code>AddOutputFilter INCLUDES .shtml</code> añadirán el
    filtro <code>INCLUDES</code> a la petición. Si <directive
    >ModMimeUsePathInfo</directive> no está establecida, el
    filtro <code>INCLUDES</code> no se añadirá. Esto funcionará de forma
    análoga para rutas virtuales, como las definidas por
    <directive type="section">Location</directive></p>
</usage>
<seealso><directive module="core">AcceptPathInfo</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>RemoveCharset</name>
<description>Elimina cualquier asociación de conjunto de caracteres para un conjunto de
extensiones de archivo</description>
<syntax>RemoveCharset <var>extension</var> [<var>extension</var>]
...</syntax>
<contextlist><context>virtual host</context><context>directory</context>
<context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>
    <p>La directiva <directive>RemoveCharset</directive> elimina cualquier
    asociación de conjunto de caracteres para los archivos con las extensiones indicadas.
    Esto permite que los archivos <code>.htaccess</code> en subdirectorios
    deshagan cualquier asociación heredada de directorios superiores o de los
    archivos de configuración del servidor.</p>

    <p>El argumento <var>extension</var> no distingue mayúsculas y minúsculas y puede
    especificarse con o sin un punto inicial.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
RemoveCharset .html .shtml
    </highlight>
    </example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>RemoveEncoding</name>
<description>Elimina cualquier asociación de codificación de contenido para un conjunto de
extensiones de archivo</description>
<syntax>RemoveEncoding <var>extension</var> [<var>extension</var>]
...</syntax>
<contextlist><context>virtual host</context><context>directory</context>
<context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>
    <p>La directiva <directive>RemoveEncoding</directive> elimina cualquier
    asociación de codificación para los archivos con las extensiones indicadas. Esto
    permite que los archivos <code>.htaccess</code> en subdirectorios deshagan
    cualquier asociación heredada de directorios superiores o de los
    archivos de configuración del servidor. Un ejemplo de uso podría ser:</p>

    <example><title>/foo/.htaccess:</title>
    <highlight language="config">
AddEncoding x-gzip .gz
AddType text/plain .asc
&lt;Files "*.gz.asc"&gt;
    RemoveEncoding .gz
&lt;/Files&gt;
      </highlight>
    </example>

    <p>Esto hará que <code>foo.gz</code> se marque como codificado
    con el método gzip, pero <code>foo.gz.asc</code> como un
    archivo de texto plano sin codificar.</p>

    <note><title>Nota</title>
      <p>Las directivas <directive>RemoveEncoding</directive> se procesan
      <em>después</em> de cualquier directiva <directive module="mod_mime">AddEncoding</directive>,
      por lo que es posible que deshagan los efectos de esta última
      si ambas aparecen en la misma configuración de directorio.</p>
    </note>

    <p>El argumento <var>extension</var> no distingue mayúsculas y minúsculas y puede
    especificarse con o sin un punto inicial.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>RemoveHandler</name>
<description>Elimina cualquier asociación de handler para un conjunto de
extensiones de archivo</description>
<syntax>RemoveHandler <var>extension</var> [<var>extension</var>]
...</syntax>
<contextlist><context>virtual host</context><context>directory</context>
<context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>
    <p>La directiva <directive>RemoveHandler</directive> elimina cualquier
    asociación de handler para los archivos con las extensiones indicadas. Esto permite que
    los archivos <code>.htaccess</code> en subdirectorios deshagan cualquier
    asociación heredada de directorios superiores o de los archivos de
    configuración del servidor. Un ejemplo de uso podría ser:</p>

    <example><title>/foo/.htaccess:</title>
    <highlight language="config">
AddHandler server-parsed .html
    </highlight>
    </example>

    <example><title>/foo/bar/.htaccess:</title>
    <highlight language="config">
RemoveHandler .html
    </highlight>
    </example>

    <p>Esto tiene el efecto de devolver los archivos <code>.html</code> del
    directorio <code>/foo/bar</code> a tratarse como archivos
    normales, en lugar de como candidatos a ser analizados (vea el módulo
    <module>mod_include</module>).</p>

    <p>El argumento <var>extension</var> no distingue mayúsculas y minúsculas y puede
    especificarse con o sin un punto inicial.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>RemoveInputFilter</name>
<description>Elimina cualquier asociación de filtro de entrada para un conjunto de
extensiones de archivo</description>
<syntax>RemoveInputFilter <var>extension</var> [<var>extension</var>]
...</syntax>
<contextlist><context>virtual host</context><context>directory</context>
<context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>
    <p>La directiva <directive>RemoveInputFilter</directive> elimina cualquier
    asociación de <a href="../filter.html">filtro</a> de entrada para los archivos con
    las extensiones indicadas.
    Esto permite que los archivos <code>.htaccess</code> en subdirectorios
    deshagan cualquier asociación heredada de directorios superiores o de los
    archivos de configuración del servidor.</p>

    <p>El argumento <var>extension</var> no distingue mayúsculas y minúsculas y puede
    especificarse con o sin un punto inicial.</p>
</usage>
<seealso><directive module="mod_mime">AddInputFilter</directive></seealso>
<seealso><directive module="core">SetInputFilter</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>RemoveLanguage</name>
<description>Elimina cualquier asociación de idioma para un conjunto de
extensiones de archivo</description>
<syntax>RemoveLanguage <var>extension</var> [<var>extension</var>]
...</syntax>
<contextlist><context>virtual host</context><context>directory</context>
<context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>
    <p>La directiva <directive>RemoveLanguage</directive> elimina cualquier
    asociación de idioma para los archivos con las extensiones indicadas. Esto
    permite que los archivos <code>.htaccess</code> en subdirectorios deshagan
    cualquier asociación heredada de directorios superiores o de los
    archivos de configuración del servidor.</p>

    <p>El argumento <var>extension</var> no distingue mayúsculas y minúsculas y puede
    especificarse con o sin un punto inicial.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>RemoveOutputFilter</name>
<description>Elimina cualquier asociación de filtro de salida para un conjunto de
extensiones de archivo</description>
<syntax>RemoveOutputFilter <var>extension</var> [<var>extension</var>]
...</syntax>
<contextlist><context>virtual host</context><context>directory</context>
<context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>
    <p>La directiva <directive>RemoveOutputFilter</directive> elimina cualquier
    asociación de <a href="../filter.html">filtro</a> de salida para los archivos con
    las extensiones indicadas.
    Esto permite que los archivos <code>.htaccess</code> en subdirectorios
    deshagan cualquier asociación heredada de directorios superiores o de los
    archivos de configuración del servidor.</p>

    <p>El argumento <var>extension</var> no distingue entre mayúsculas y
    minúsculas, y puede especificarse con o sin el punto inicial.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
RemoveOutputFilter shtml
    </highlight>
    </example>
</usage>
<seealso><directive module="mod_mime">AddOutputFilter</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>RemoveType</name>
<description>Elimina cualquier asociación de tipo de contenido para un conjunto de
extensiones de archivo</description>
<syntax>RemoveType <var>extension</var> [<var>extension</var>]
...</syntax>
<contextlist><context>virtual host</context><context>directory</context>
<context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>
    <p>La directiva <directive>RemoveType</directive> elimina cualquier
    asociación de <glossary ref="media-type">tipo de medio</glossary> para los archivos con
    las extensiones indicadas. Esto permite que los archivos <code>.htaccess</code> en
    subdirectorios deshagan cualquier asociación heredada de directorios
    superiores o de los archivos de configuración del servidor. Un ejemplo de uso
    podría ser:</p>

    <example><title>/foo/.htaccess:</title>
    <highlight language="config">
RemoveType .cgi
    </highlight>
    </example>

    <p>Esto eliminará cualquier tratamiento especial de los archivos
    <code>.cgi</code> en el directorio <code>/foo/</code> y por debajo de él,
    haciendo que las respuestas que contengan esos archivos omitan el campo de cabecera
    HTTP Content-Type.</p>

    <note><title>Nota</title>
      <p>Las directivas <directive>RemoveType</directive> se procesan
      <em>después</em> de cualquier directiva <directive module="mod_mime">AddType</directive>,
      por lo que es posible que deshagan los efectos de
      esta última si ambas aparecen en la misma configuración de directorio.</p>
    </note>

    <p>El argumento <var>extension</var> no distingue mayúsculas y minúsculas y puede
    especificarse con o sin un punto inicial.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>TypesConfig</name>
<description>La ubicación del archivo <code>mime.types</code></description>
<syntax>TypesConfig <var>file-path</var></syntax>
<default>TypesConfig conf/mime.types</default>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>La directiva <directive>TypesConfig</directive> establece la
    ubicación del archivo de configuración de <glossary ref="media-type">tipos
    de medio</glossary>. <var>File-path</var> es relativo a
    <directive module="core">ServerRoot</directive>. Este archivo establece
    la lista por defecto de relaciones entre extensiones de archivo y tipos
    de contenido. La mayoría de los administradores usan el archivo <code>mime.types</code>
    proporcionado por su sistema operativo, que asocia extensiones de archivo
    comunes con la lista oficial de tipos de medio registrados en IANA
    y mantenida en <a href=
    "http://www.iana.org/assignments/media-types/index.html"
    >http://www.iana.org/assignments/media-types/index.html</a>,
    así como un gran número de tipos no oficiales. Esto
    simplifica el archivo <code>httpd.conf</code> proporcionando la
    mayoría de las definiciones de tipo de medio, y puede sobrescribirse mediante
    directivas <directive module="mod_mime">AddType</directive> si es
    necesario. No debería editar el archivo <code>mime.types</code>,
    porque puede sustituirse al actualizar su servidor.</p>

    <p>El archivo contiene líneas con el formato de los argumentos de
    una directiva <directive module="mod_mime">AddType</directive>:</p>

    <example>
      <var>media-type</var> [<var>extension</var>] ...
    </example>

    <p>Las mayúsculas y minúsculas de la extensión no importan. Las líneas en blanco, y las líneas
    que empiezan por un carácter almohadilla (<code>#</code>), se ignoran.
    Las líneas vacías están ahí por completitud (del archivo mime.types).
    Apache httpd aún puede determinar estos tipos con <module
    >mod_mime_magic</module>.
    </p>

    <note>
      Por favor, <strong>no</strong> envíe peticiones al Proyecto Apache HTTP
      Server para añadir nuevas entradas en el archivo
      <code>mime.types</code> distribuido, salvo que (1) ya estén
      registradas en IANA, y (2) usen extensiones de archivo ampliamente aceptadas
      y sin conflictos entre plataformas.
      Las peticiones de tipo <code>category/x-subtype</code> se
      rechazarán automáticamente, igual que cualquier nueva extensión de dos letras, ya que
      probablemente entrarán más adelante en conflicto con el ya abarrotado espacio de
      nombres de idiomas y conjuntos de caracteres.
    </note>
</usage>
<seealso><module>mod_mime_magic</module></seealso>
</directivesynopsis>

<directivesynopsis>
<name>MimeOptions</name>
<description>Configura el comportamiento de mod_mime</description>
<syntax>MimeOptions <var>option</var> [<var>option</var>] ...</syntax>
<contextlist><context>server config</context>
<context>virtual host</context><context>directory</context>
<context>.htaccess</context>
</contextlist>
<override>FileInfo</override>
<compatibility>Apache HTTP Server 2.5.1 y posteriores</compatibility>

<usage>
    <p>La directiva <directive>MimeOptions</directive> configura determinados
    comportamientos de <module>mod_mime</module>. <var>Option</var> puede
    ser uno de</p>

    <dl>
      <dt><code>TypesLastExtension</code></dt>
      <dd>Esta opción solo considera la última extensión de nombre de archivo (la de más a la derecha)
      al determinar el Content-Type de un archivo.</dd>
      <dt><code>NoTypesLastExtension</code></dt>
      <dd>Esta opción puede usarse para volver al comportamiento por defecto de comprobar
      todas las extensiones de nombre de archivo al determinar el Content-Type de un archivo.</dd>
      <dt><code>AllLastExtension</code></dt>
      <dd>Esta opción solo considera la última extensión de nombre de archivo (la de más a la derecha)
      al examinar los nombres de archivo.</dd>
      <dt><code>NoAllLastExtension</code></dt>
      <dd>Esta opción puede usarse para volver al comportamiento por defecto de examinar
      todas las extensiones de nombre de archivo. Solo es útil si
      <code>MimeOptions AllLastExtension</code> se ha usado en una sección de
      configuración de menor precedencia</dd>
      <dt><code>Disable</code></dt>
      <dd>Se omite toda asignación de metadatos basada en el nombre de archivo.</dd>
      <dt><code>Enable</code></dt>
      <dd>Vuelve a activar la comprobación de extensión de archivo por parte de este módulo. Solo es útil si una
      sección de configuración de menor precedencia ha especificado
      <code>MimeOptions Disable</code>.</dd>
    </dl>
</usage>
</directivesynopsis>
</modulesynopsis>
