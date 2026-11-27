<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933746 -->
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

<modulesynopsis metafile="mod_negotiation.xml.meta">

<name>mod_negotiation</name>
<description>Proporciona <a
    href="../content-negotiation.html">negociación de contenido</a></description>
<status>Base</status>
<sourcefile>mod_negotiation.c</sourcefile>
<identifier>negotiation_module</identifier>

<summary>
    <p>La negociación de contenido, o más exactamente la selección de
    contenido, es la selección del documento que mejor se ajusta a las
    capacidades del cliente, de entre varios documentos disponibles. Hay
    dos implementaciones de esto.</p>

    <ul>
      <li>Un mapa de tipos (un archivo con el manejador
      <code>type-map</code>) que enumera explícitamente los archivos
      que contienen las variantes.</li>

      <li>Una búsqueda Multiviews (activada mediante la opción
      <code>Multiviews</code> de <directive module="core">Options</directive>),
      en la que el servidor realiza una coincidencia implícita de patrones
      de nombre de archivo y elige entre los resultados.</li>
    </ul>
</summary>
<seealso><directive module="core">Options</directive></seealso>
<seealso><module>mod_mime</module></seealso>
<seealso><a href="../content-negotiation.html">Negociación
de contenido</a></seealso>
<seealso><a href="../env.html">Variables de entorno</a></seealso>

<section id="typemaps"><title>Mapas de tipos</title>
    <p>Un mapa de tipos tiene un formato similar al de las cabeceras de
    correo de RFC822. Contiene descripciones de documentos separadas por
    líneas en blanco, y las líneas que comienzan con un carácter de
    almohadilla ('#') se tratan como comentarios. Una descripción de
    documento consta de varios registros de cabecera; los registros pueden
    continuar en varias líneas si las líneas de continuación comienzan
    con espacios. El espacio inicial se eliminará y las líneas se
    concatenarán. Un registro de cabecera consta de un nombre de palabra
    clave, que siempre termina en dos puntos, seguido de un valor. Se
    permiten espacios en blanco entre el nombre de la cabecera y el
    valor, y entre los tokens del valor. Las cabeceras permitidas
    son: </p>

    <dl>
      <dt><code>Content-Encoding:</code></dt>
      <dd>La codificación del archivo. Apache solo reconoce
      las codificaciones definidas mediante una directiva <directive
      module="mod_mime">AddEncoding</directive>.
      Esto normalmente incluye las codificaciones <code>x-compress</code>
      para archivos comprimidos con compress, y <code>x-gzip</code> para
      archivos comprimidos con gzip. El prefijo <code>x-</code> se ignora
      en las comparaciones de codificación.</dd>

      <dt><code>Content-Language:</code></dt>
      <dd>El idioma (o idiomas) de la variante, como una etiqueta de
      idioma estándar de Internet (<rfc>1766</rfc>). Un ejemplo es
      <code>en</code>, que significa inglés. Si la variante contiene
      más de un idioma, se separan con una coma.</dd>

      <dt><code>Content-Length:</code></dt>
      <dd>La longitud del archivo, en bytes. Si esta cabecera no está
      presente, se usa la longitud real del archivo.</dd>

      <dt><code>Content-Type:</code></dt>

      <dd>
        El <glossary ref="mime-type">tipo de medio MIME</glossary> del
        documento, con parámetros opcionales. Cada variante debe
        incluir una cabecera <code>Content-Type</code>; la negociación
        no funcionará correctamente para las variantes que no la
        tengan. Los parámetros se separan del tipo de medio y entre sí
        mediante un punto y coma, con una sintaxis de
        <code>nombre=valor</code>. Los parámetros habituales incluyen:

        <dl>
          <dt><code>level</code></dt>
          <dd>un entero que especifica la versión del tipo de medio.
          Para <code>text/html</code> el valor por defecto es 2, en
          caso contrario es 0.</dd>

          <dt><code>qs</code></dt>
          <dd>un número de punto flotante con un valor en el rango de 0[.000]
          a 1[.000], que indica la 'calidad' relativa de esta variante
          en comparación con las otras variantes disponibles,
          independientemente de las capacidades del cliente. Por
          ejemplo, un archivo jpeg suele tener mayor calidad de origen
          que un archivo ascii si intenta representar una fotografía.
          Sin embargo, si el recurso representado es arte ascii,
          entonces un archivo ascii tendría mayor calidad de origen
          que un archivo jpeg. Por tanto, todos los valores de
          <code>qs</code> son específicos de un recurso dado.</dd>
        </dl>

        <example><title>Ejemplo</title>
          Content-Type: image/jpeg; qs=0.8
        </example>
      </dd>

      <dt><code>URI:</code></dt>
      <dd>uri del archivo que contiene la variante (del tipo de medio
      dado, codificado con la codificación de contenido dada). Estas se
      interpretan como URLs relativas al archivo de mapa; deben estar
      en el mismo servidor, y deben referirse a archivos a los que el
      cliente tendría acceso concedido si los solicitara directamente.</dd>

      <dt><code>Body:</code></dt>
      <dd>El contenido real del recurso puede incluirse en el archivo
      type-map usando la cabecera Body. Esta cabecera debe contener una
      cadena que designe un delimitador para el contenido del cuerpo.
      Entonces, todas las líneas siguientes en el archivo type-map se
      considerarán parte del cuerpo del recurso hasta que se encuentre
      la cadena delimitadora.

      <example><title>Ejemplo:</title>
        Body:----xyz----<br />
        &lt;html&gt;<br />
        &lt;body&gt;<br />
        &lt;p&gt;Contenido de la página.&lt;/p&gt;<br />
        &lt;/body&gt;<br />
        &lt;/html&gt;<br />
        ----xyz----
      </example>
      </dd>
    </dl>

    <p>Considere, por ejemplo, un recurso llamado
    <code>document.html</code> disponible en inglés, francés
    y alemán. Los archivos de cada uno de ellos se llaman
    <code>document.html.en</code>, <code>document.html.fr</code> y
    <code>document.html.de</code>, respectivamente. El archivo de mapa
    de tipos se llamará <code>document.html.var</code>, y contendrá lo
    siguiente:</p>

    <example>
    URI: document.html<br />
    <br />
    Content-language: en<br />
    Content-type: text/html<br />
    URI: document.html.en<br />
    <br />
    Content-language: fr<br />
    Content-type: text/html<br />
    URI: document.html.fr<br />
    <br />
    Content-language: de<br />
    Content-type: text/html<br />
    URI: document.html.de<br />
    <br />

    </example>

    <p>Los cuatro archivos deben colocarse en el mismo directorio, y el
    archivo <code>.var</code> debe asociarse con el manejador
    <code>type-map</code> mediante una directiva <directive
    module="mod_mime">AddHandler</directive>:</p>

    <highlight language="config">
    AddHandler type-map .var
    </highlight>

    <p>Una petición de <code>document.html.var</code> en este directorio
    dará como resultado la elección de la variante que mejor coincida
    con la preferencia de idioma especificada en la cabecera de
    petición <code>Accept-Language</code> del usuario.</p>

    <p>Si <code>Multiviews</code> está activado, y <directive module="mod_mime"
    >MultiviewsMatch</directive> está establecido en "handlers" o "any", una
    petición a <code>document.html</code> descubrirá
    <code>document.html.var</code> y continuará negociando con el mapa de
    tipos explícito.</p>

    <p>Otras directivas de configuración, como <directive module="mod_alias"
    >Alias</directive>, pueden usarse para asociar <code>document.html</code>
    con <code>document.html.var</code>.</p>

</section>

<section id="multiviews"><title>Multiviews</title>
    <p>Una búsqueda Multiviews se activa mediante la opción
    <code>Multiviews</code> de <directive module="core">Options</directive>.
    Si el servidor recibe una petición de <code>/some/dir/foo</code> y
    <code>/some/dir/foo</code> <em>no</em> existe, entonces el
    servidor lee el directorio buscando todos los archivos llamados
    <code>foo.*</code>, y efectivamente simula un mapa de tipos que
    nombra todos esos archivos, asignándoles los mismos tipos de medio
    y codificaciones de contenido que tendría si el cliente hubiera
    solicitado uno de ellos por su nombre. A continuación, elige la
    mejor coincidencia con los requisitos del cliente, y devuelve ese
    documento.</p>

    <p>La directiva <directive module="mod_mime">MultiviewsMatch</directive>
    configura si Apache tendrá en cuenta los archivos que no tienen
    asignada metainformación de negociación de contenido al elegir los
    archivos.</p>
</section>

<directivesynopsis>
<name>CacheNegotiatedDocs</name>
<description>Permite que los servidores proxy almacenen en caché
los documentos negociados por contenido</description>
<syntax>CacheNegotiatedDocs On|Off</syntax>
<default>CacheNegotiatedDocs Off</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>Si se establece, esta directiva permite que los documentos
    negociados por contenido sean almacenados en caché por servidores
    proxy. Esto podría significar que los clientes situados detrás de
    esos proxies podrían recibir versiones de los documentos que no
    sean la mejor coincidencia para sus capacidades, pero hará que el
    almacenamiento en caché sea más eficiente.</p>

    <p>Esta directiva solo se aplica a las peticiones que proceden de
    navegadores HTTP/1.0. HTTP/1.1 proporciona un control mucho mejor
    sobre el almacenamiento en caché de los documentos negociados, y
    esta directiva no tiene efecto en las respuestas a peticiones
    HTTP/1.1.</p>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>ForceLanguagePriority</name>
<description>Acción a tomar si no se encuentra un único documento
aceptable</description>
<syntax>ForceLanguagePriority None|Prefer|Fallback [Prefer|Fallback]</syntax>
<default>ForceLanguagePriority Prefer</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>
    <p>La directiva <directive>ForceLanguagePriority</directive> usa
    el valor dado de <directive
    module="mod_negotiation">LanguagePriority</directive> para
    satisfacer la negociación cuando el servidor de otro modo no
    podría devolver un único documento coincidente.</p>

    <p><code>ForceLanguagePriority Prefer</code> usa
    <code>LanguagePriority</code> para servir un único resultado
    válido, en lugar de devolver un resultado HTTP 300 (MULTIPLE
    CHOICES) cuando hay varias opciones igualmente válidas. Si se
    dieran las directivas siguientes, y la cabecera
    <code>Accept-Language</code> del usuario asignara a <code>en</code>
    y <code>de</code> la misma calidad <code>.500</code> (igualmente
    aceptables), entonces se serviría la primera variante coincidente,
    <code>en</code>.</p>

    <highlight language="config">
LanguagePriority en fr de
ForceLanguagePriority Prefer
    </highlight>

    <p><code>ForceLanguagePriority Fallback</code> usa
    <directive module="mod_negotiation">LanguagePriority</directive>
    para servir un resultado válido, en lugar de devolver un resultado
    HTTP 406 (NOT ACCEPTABLE). Si se dieran las directivas siguientes, y
    la cabecera <code>Accept-Language</code> del usuario solo permitiera
    una respuesta en idioma <code>es</code>, pero no se encontrara tal
    variante, entonces se serviría la primera variante de la lista
    <directive module="mod_negotiation"
    >LanguagePriority</directive> siguiente.</p>

    <highlight language="config">
LanguagePriority en fr de
ForceLanguagePriority Fallback
    </highlight>

    <p>Pueden especificarse ambas opciones, <code>Prefer</code> y
    <code>Fallback</code>, de modo que se sirva la primera variante
    coincidente de <directive
    module="mod_negotiation">LanguagePriority</directive> si hay más de
    una variante aceptable, o se sirva el primer documento disponible si
    ninguna de las variantes coincide con la lista de idiomas aceptables
    del cliente.</p>

    <p><code>ForceLanguagePriority None</code> desactiva tanto el
    comportamiento de <code>Prefer</code> como el de
    <code>Fallback</code>, de modo que el servidor devolverá 300
    (MULTIPLE CHOICES) o 406 (NOT ACCEPTABLE) según corresponda.
    <code>None</code> no puede combinarse con
    <code>Prefer</code> ni con <code>Fallback</code>.</p>
</usage>
<seealso><directive module="mod_mime">AddLanguage</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>LanguagePriority</name>
<description>La precedencia de las variantes de idioma para los casos
en los que el cliente no expresa una preferencia</description>
<syntax>LanguagePriority <var>MIME-lang</var> [<var>MIME-lang</var>]
...</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>
    <p>La directiva <directive>LanguagePriority</directive> establece
    la precedencia de las variantes de idioma para el caso en que el
    cliente no expresa una preferencia, al gestionar una petición
    Multiviews. La lista de <var>MIME-lang</var> está en orden de
    preferencia decreciente.</p>

    <highlight language="config">
      LanguagePriority en fr de
    </highlight>

    <p>Para una petición de <code>foo.html</code>, donde existieran
    tanto <code>foo.html.fr</code> como <code>foo.html.de</code>, pero
    el navegador no expresara una preferencia de idioma, entonces se
    devolvería <code>foo.html.fr</code>.</p>

    <p>Tenga en cuenta que esta directiva solo tiene efecto si no se
    puede determinar un 'mejor' idioma por ningún otro medio o si la
    directiva <directive
    module="mod_negotiation">ForceLanguagePriority</directive> no es
    <code>None</code>. En general, es el cliente quien determina la
    preferencia de idioma, no el servidor.</p>
</usage>
<seealso><directive module="mod_mime">AddLanguage</directive></seealso>
</directivesynopsis>

</modulesynopsis>
