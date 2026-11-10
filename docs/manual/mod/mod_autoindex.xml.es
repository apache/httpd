<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
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

<modulesynopsis metafile="mod_autoindex.xml.meta">
<name>mod_autoindex</name>

<description>Genera índices de directorio automáticamente,
    similar al comando Unix <code>ls</code> o al comando de shell
    Win32 <code>dir</code></description>
<status>Base</status>
<sourcefile>mod_autoindex.c</sourcefile>
<identifier>autoindex_module</identifier>

<summary>
      <p>El índice de un directorio puede proceder de una de dos
      fuentes:</p>

    <ul>
      <li>Un archivo ubicado en ese directorio, normalmente llamado
      <code>index.html</code>. La directiva <directive
      module="mod_dir">DirectoryIndex</directive> establece el
      nombre del archivo o archivos que se van a usar. Esto lo
      controla <module>mod_dir</module>.</li>

      <li>En caso contrario, un listado generado por el servidor. Las
      demás directivas controlan el formato de este listado. Las
      directivas <directive module="mod_autoindex">AddIcon</directive>,
      <directive module="mod_autoindex">AddIconByEncoding</directive> y
      <directive module="mod_autoindex">AddIconByType</directive> se
      usan para establecer una lista de iconos que se mostrarán para
      los distintos tipos de archivo; para cada archivo listado, se
      muestra el primer icono de la lista que coincida con el
      archivo. Esto lo controla
      <module>mod_autoindex</module>.</li>
    </ul>
    <p>Las dos funciones están separadas para que pueda eliminar (o
    reemplazar) por completo la generación automática de índices si
    así lo desea.</p>

    <p>La generación automática de índices se activa usando
    <code>Options +Indexes</code>. Consulte la directiva
    <directive module="core">Options</directive> para más
    detalles.</p>

    <p>Si se indica la opción <code><a href="#indexoptions.fancyindexing"
    >FancyIndexing</a></code> con la directiva <directive
    module="mod_autoindex">IndexOptions</directive>, los encabezados
    de columna son enlaces que controlan el orden en que se muestra
    el listado. Si selecciona el enlace de un encabezado, el listado
    se regenerará, ordenado por los valores de esa columna.
    Seleccionar el mismo encabezado repetidamente alterna entre
    orden ascendente y descendente. Estos enlaces de encabezado de
    columna se suprimen con la opción
    <code><a href="#indexoptions.suppresscolumnsorting">SuppressColumnSorting</a></code>
    de la directiva <directive module="mod_autoindex">IndexOptions</directive>.</p>

    <p>Tenga en cuenta que cuando el listado se ordena por "Size",
    se usa el tamaño <em>real</em> de los archivos, no el valor
    mostrado, de modo que un archivo de 1010 bytes siempre se
    mostrará antes que uno de 1011 bytes (en orden ascendente)
    aunque ambos se muestren como "1K".</p>
</summary>

<section id="query">
    <title>Argumentos de consulta en las peticiones de Autoindex</title>

    <p>Hay varios argumentos de cadena de consulta disponibles para
    dar al cliente cierto control sobre el orden del listado del
    directorio, así como sobre qué archivos se listan. Si no desea
    dar este control al cliente, la opción <code><a
    href="#indexoptions.ignoreclient">IndexOptions
    IgnoreClient</a></code> desactiva esa funcionalidad.</p>

    <p>Los propios encabezados de ordenación de columnas son
    hiperenlaces autorreferenciales que añaden las opciones de
    consulta de ordenación que se muestran a continuación. Cualquiera
    de las opciones siguientes puede añadirse a cualquier petición
    del recurso de directorio.</p>

    <ul>
      <li><code>C=N</code> ordena el directorio por nombre de archivo</li>

      <li><code>C=M</code> ordena el directorio por fecha de última
      modificación y luego por nombre de archivo</li>

      <li><code>C=S</code> ordena el directorio por tamaño y luego
      por nombre de archivo</li>

      <li class="separate"><code>C=D</code> ordena el directorio por
      descripción y luego por nombre de archivo</li>

      <li><code>O=A</code> ordena el listado en orden
      ascendente</li>

      <li class="separate"><code>O=D</code> ordena el listado en
      orden descendente</li>

      <li><code>F=0</code> da formato al listado como una lista
      simple (sin FancyIndexed)</li>

      <li><code>F=1</code> da formato al listado como una lista
      FancyIndexed</li>

      <li class="separate"><code>F=2</code> da formato al listado
      como una lista FancyIndexed de tipo HTMLTable</li>

      <li><code>V=0</code> desactiva la ordenación por versión</li>

      <li class="separate"><code>V=1</code> activa la ordenación por
      versión</li>

      <li><code>P=<var>pattern</var></code> lista solo los archivos
      que coinciden con el <var>pattern</var> indicado</li>
    </ul>

    <p>Tenga en cuenta que el argumento de consulta 'P'attern se
    evalúa <em>después</em> de que se procesen las directivas
    habituales de <directive module="mod_autoindex"
    >IndexIgnore</directive>, y todos los nombres de archivo siguen
    estando sujetos a los mismos criterios que cualquier otro listado
    de autoindex. El analizador de argumentos de consulta de
    <module>mod_autoindex</module> se detendrá abruptamente al
    encontrar una opción no reconocida. Los argumentos de consulta
    deben estar bien formados, de acuerdo con la tabla anterior.</p>

    <p>El sencillo ejemplo siguiente, que puede recortarse y
    guardarse en un archivo header.html, ilustra estas opciones de
    consulta. Tenga en cuenta que el argumento desconocido "X",
    correspondiente al botón de envío, se coloca al final para
    asegurar que todos los argumentos se analicen antes de que
    <module>mod_autoindex</module> encuentre la entrada X=Go.</p>

    <example><title>Ejemplo</title>
        <highlight language="html">
&lt;form action="" method="get"&gt;
    Show me a &lt;select name="F"&gt;
        &lt;option value="0"&gt; Plain list&lt;/option&gt;
        &lt;option value="1" selected="selected"&gt; Fancy list&lt;/option&gt;
        &lt;option value="2"&gt; Table list&lt;/option&gt;
    &lt;/select&gt;
    Sorted by &lt;select name="C"&gt;
        &lt;option value="N" selected="selected"&gt; Name&lt;/option&gt;
        &lt;option value="M"&gt; Date Modified&lt;/option&gt;
        &lt;option value="S"&gt; Size&lt;/option&gt;
        &lt;option value="D"&gt; Description&lt;/option&gt;
    &lt;/select&gt;
    &lt;select name="O"&gt;
        &lt;option value="A" selected="selected"&gt; Ascending&lt;/option&gt;
        &lt;option value="D"&gt; Descending&lt;/option&gt;
    &lt;/select&gt;
    &lt;select name="V"&gt;
        &lt;option value="0" selected="selected"&gt; in Normal order&lt;/option&gt;
        &lt;option value="1"&gt; in Version order&lt;/option&gt;
    &lt;/select&gt;
    Matching &lt;input type="text" name="P" value="*" /&gt;
    &lt;input type="submit" name="X" value="Go" /&gt;
&lt;/form&gt;
    </highlight></example>

</section>

<directivesynopsis>
<name>AddAlt</name>
<description>Texto alternativo que se muestra para un archivo, en
lugar de un icono seleccionado por nombre de archivo</description>
<syntax>AddAlt <var>string</var> <var>file</var> [<var>file</var>] ...</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>Indexes</override>

<usage>
    <p><directive>AddAlt</directive> proporciona el texto alternativo
    que se muestra para un archivo, en lugar de un icono, para
    <code><a href="#indexoptions.fancyindexing"
    >FancyIndexing</a></code>. <var>File</var> es una extensión de
    archivo, un nombre de archivo parcial, una expresión con
    comodines o un nombre de archivo completo para los archivos que
    se van a describir. Si <var>String</var> contiene algún espacio
    en blanco, debe encerrarlo entre comillas (<code>"</code> o
    <code>'</code>). Este texto alternativo se muestra si el cliente
    no admite imágenes, tiene desactivada la carga de imágenes, o no
    puede recuperar el icono.</p>

    <highlight language="config">
AddAlt "PDF file" *.pdf
AddAlt Compressed *.gz *.zip *.Z
    </highlight>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AddAltByEncoding</name>
<description>Texto alternativo que se muestra para un archivo en
lugar de un icono seleccionado por codificación MIME</description>
<syntax>AddAltByEncoding <var>string</var> <var>MIME-encoding</var>
[<var>MIME-encoding</var>] ...</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>Indexes</override>

<usage>
    <p><directive>AddAltByEncoding</directive> proporciona el texto
    alternativo que se muestra para un archivo, en lugar de un
    icono, para <code><a href="#indexoptions.fancyindexing"
    >FancyIndexing</a></code>. <var>MIME-encoding</var> es una
    codificación de contenido válida, como <code>x-compress</code>.
    Si <var>String</var> contiene algún espacio en blanco, debe
    encerrarlo entre comillas (<code>"</code> o <code>'</code>).
    Este texto alternativo se muestra si el cliente no admite
    imágenes, tiene desactivada la carga de imágenes, o no puede
    recuperar el icono.</p>

    <highlight language="config">
      AddAltByEncoding gzip x-gzip
    </highlight>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AddAltByType</name>
<description>Texto alternativo que se muestra para un archivo, en
lugar de un icono seleccionado por tipo de contenido MIME</description>
<syntax>AddAltByType <var>string</var> <var>MIME-type</var>
[<var>MIME-type</var>] ...</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>Indexes</override>

<usage>
    <p><directive>AddAltByType</directive> establece el texto
    alternativo que se muestra para un archivo, en lugar de un
    icono, para <code><a href="#indexoptions.fancyindexing"
    >FancyIndexing</a></code>. <var>MIME-type</var> es un tipo de
    contenido válido, como <code>text/html</code>. Si
    <var>String</var> contiene algún espacio en blanco, debe
    encerrarlo entre comillas (<code>"</code> o <code>'</code>).
    Este texto alternativo se muestra si el cliente no admite
    imágenes, tiene desactivada la carga de imágenes, o no puede
    recuperar el icono.</p>

    <highlight language="config">
      AddAltByType 'plain text' text/plain
    </highlight>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AddDescription</name>
<description>Descripción que se muestra para un archivo</description>
<syntax>AddDescription <var>string file</var> [<var>file</var>] ...</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>Indexes</override>

<usage>
    <p>Esto establece la descripción que se muestra para un archivo,
    para <code><a href="#indexoptions.fancyindexing"
    >FancyIndexing</a></code>. <var>File</var> es una extensión de
    archivo, un nombre de archivo parcial, una expresión con
    comodines o un nombre de archivo completo para los archivos que
    se van a describir. <var>String</var> se encierra entre comillas
    dobles (<code>"</code>).</p>

    <highlight language="config">
AddDescription "The planet Mars" mars.gif
AddDescription "My friend Marshall" friends/mars.gif
    </highlight>

    <p>El campo de descripción habitual, por defecto, tiene un ancho
    de 23 bytes. La opción <code><a href="#indexoptions.suppressicon"
    >IndexOptions SuppressIcon</a></code> añade 6 bytes más, la
    opción <code><a href="#indexoptions.suppresssize"
    >IndexOptions SuppressSize</a></code> añade 7 bytes, y la
    opción <code><a href="#indexoptions.suppresslastmodified"
    >IndexOptions SuppressLastModified</a></code> añade 19 bytes.
    Por lo tanto, el ancho máximo por defecto que se puede asignar a
    la columna de descripción es de 55 bytes.</p>

    <p>Dado que el argumento <var>File</var> puede ser un nombre de
    archivo parcial, recuerde que un nombre parcial demasiado corto
    puede coincidir con archivos no deseados. Por ejemplo,
    <code>le.html</code> coincidirá con el archivo
    <code>le.html</code>, pero también coincidirá con el archivo
    <code>example.html</code>. En caso de que pueda haber
    ambigüedad, use un nombre de archivo tan completo como sea
    posible, pero tenga en cuenta que se usará la primera coincidencia
    encontrada, así que ordene en consecuencia su lista de
    directivas <code>AddDescription</code>.</p>

    <p>Consulte la palabra clave <a href="#indexoptions.descriptionwidth"
    >DescriptionWidth</a> de la directiva <directive module="mod_autoindex"
    >IndexOptions</directive> para más detalles sobre cómo anular el
    tamaño de esta columna, o permitir descripciones de longitud
    ilimitada.</p>

    <note><title>Precaución</title>
      <p>El texto descriptivo definido con <directive>AddDescription</directive>
      puede contener marcado HTML, como etiquetas y entidades de
      caracteres. Si el ancho de la columna de descripción llegara a
      truncar un elemento etiquetado (como cortar el final de una
      frase en negrita), el resultado puede afectar al resto del
      listado del directorio.</p>
    </note>

    <note><title>Argumentos con información de ruta</title>
      <p>Actualmente no se admiten rutas absolutas y no coinciden con
      nada en tiempo de ejecución. Los argumentos con información de
      ruta relativa, que normalmente solo se usarían en contexto
      htaccess, llevan implícitamente el prefijo '*/' para evitar que
      coincidan con nombres de directorio parciales.</p>
    </note>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>AddIcon</name>
<description>Icono que se muestra para un archivo seleccionado por nombre</description>
<syntax>AddIcon <var>icon</var> <var>name</var> [<var>name</var>]
...</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>Indexes</override>

<usage>
    <p>Esto establece el icono que se muestra junto a un archivo que
    termina en <var>name</var> para <code><a href="#indexoptions.fancyindexing"
    >FancyIndexing</a></code>. <var>Icon</var> es, o bien una URL
    relativa al icono (escapada con %), o bien una URL remota
    completa, o bien tiene el formato <code>
    (<var>alttext</var>,<var>url</var>)</code> donde <var>alttext</var>
    es el texto que se da para un icono en navegadores no
    gráficos.</p>

    <p><var>Name</var> es, o bien <code>^^DIRECTORY^^</code> para
    directorios, <code>^^BLANKICON^^</code> para líneas en blanco
    (para dar formato correcto a la lista), una extensión de
    archivo, una expresión con comodines, un nombre de archivo
    parcial o un nombre de archivo completo.</p>

    <p><code>^^BLANKICON^^</code> solo se usa para dar formato, por
    lo que no es necesario si está usando <code>IndexOptions
    HTMLTable</code>.</p>

    <highlight language="config">
#Examples
AddIcon (IMG,/icons/image.png) .gif .jpg .png
AddIcon /icons/dir.png ^^DIRECTORY^^
AddIcon /icons/backup.png *~
    </highlight>

    <p>Debería usarse <directive module="mod_autoindex">AddIconByType</directive>
    en preferencia a <directive>AddIcon</directive>, siempre que sea
    posible.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AddIconByEncoding</name>
<description>Icono que se muestra junto a los archivos seleccionados
por codificación de contenido MIME</description>
<syntax>AddIconByEncoding <var>icon</var> <var>MIME-encoding</var>
[<var>MIME-encoding</var>] ...</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>Indexes</override>

<usage>
    <p>Esto establece el icono que se muestra junto a los archivos
    con <code><a
    href="#indexoptions.fancyindexing">FancyIndexing</a></code>.
    <var>Icon</var> es, o bien una URL relativa al icono (escapada
    con %), o bien una URL remota completa,
    o bien tiene el formato <code>(<var>alttext</var>,<var>url</var>)</code>
    donde <var>alttext</var> es el texto que se da para un icono en
    navegadores no gráficos.</p>

    <p><var>MIME-encoding</var> es una codificación de contenido
    válida, como <code>x-compress</code>.</p>

    <highlight language="config">
      AddIconByEncoding /icons/compress.png x-compress
    </highlight>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AddIconByType</name>
<description>Icono que se muestra junto a los archivos seleccionados
por tipo de contenido MIME</description>
<syntax>AddIconByType <var>icon</var> <var>MIME-type</var>
[<var>MIME-type</var>] ...</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>Indexes</override>

<usage>
    <p>Esto establece el icono que se muestra junto a los archivos
    de tipo <var>MIME-type</var> para <code><a
    href="#indexoptions.fancyindexing">FancyIndexing</a></code>.
    <var>Icon</var> es, o bien una URL relativa al icono (escapada
    con %), o bien una URL remota completa,
    o bien tiene el formato <code>(<var>alttext</var>,<var>url</var>)</code>
    donde <var>alttext</var> es el texto que se da para un icono en
    navegadores no gráficos.</p>

    <p><var>MIME-type</var> es una expresión con comodines que
    coincide con los tipos MIME requeridos.</p>

    <highlight language="config">
      AddIconByType (IMG,/icons/image.png) image/*
    </highlight>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>DefaultIcon</name>
<description>Icono que se muestra para los archivos cuando no hay
ningún icono específico configurado</description>
<syntax>DefaultIcon <var>url-path</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>Indexes</override>

<usage>
    <p>La directiva <directive>DefaultIcon</directive> establece el
    icono que se muestra para los archivos cuando no se conoce
    ningún icono específico, para <code><a
    href="#indexoptions.fancyindexing">FancyIndexing</a></code>.
    <var>Url-path</var> es una URL relativa al icono (escapada con
    %), o una URL remota completa.</p>

    <highlight language="config">
      DefaultIcon /icon/unknown.png
    </highlight>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>HeaderName</name>
<description>Nombre del archivo que se insertará al principio
del listado del índice</description>
<syntax>HeaderName <var>filename</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>Indexes</override>

<usage>
    <p>La directiva <directive>HeaderName</directive> establece el
    nombre del archivo que se insertará al principio del listado
    del índice. <var>Filename</var> es el nombre del archivo que se
    va a incluir.</p>

    <highlight language="config">
      HeaderName HEADER.html
    </highlight>

    <note>
      <p>Tanto HeaderName como <directive
      module="mod_autoindex">ReadmeName</directive> tratan ahora
      <var>Filename</var> como una ruta URI relativa a la usada para
      acceder al directorio que se está indexando. Si
      <var>Filename</var> empieza por una barra, se tomará como
      relativa al <directive
      module="core">DocumentRoot</directive>.</p>

      <highlight language="config">
        HeaderName /include/HEADER.html
      </highlight>

      <p><var>Filename</var> debe resolverse a un documento cuyo
      tipo de contenido principal sea <code>text/*</code>
      (<em>por ejemplo</em>, <code>text/html</code>,
      <code>text/plain</code>, etc.). Esto significa que
      <var>filename</var> puede hacer referencia a un script CGI si
      el tipo de archivo real del script (a diferencia de su salida)
      está marcado como <code>text/html</code>, como por ejemplo con
      una directiva como:</p>

      <highlight language="config">
        AddType text/html .cgi
      </highlight>

      <p>Se realizará <a href="../content-negotiation.html"
      >negociación de contenido</a> si está en vigor <directive
      module="core">Options</directive> <code>MultiViews</code>. Si
      <var>filename</var> se resuelve a un documento estático
      <code>text/html</code> (no un script CGI) y está activada
      alguna de las <directive module="core">options</directive>
      <code>Includes</code> o <code>IncludesNOEXEC</code>, el archivo
      se procesará para includes del lado del servidor (consulte la
      documentación de <module>mod_include</module>).</p>
    </note>

    <p>Si el archivo especificado por <directive>HeaderName</directive>
    contiene el comienzo de un documento HTML (&lt;html&gt;,
    &lt;head&gt;, etc.), probablemente querrá establecer <a
    href="#indexoptions.suppresshtmlpreamble"><code>IndexOptions
    +SuppressHTMLPreamble</code></a>, para que estas etiquetas no se
    repitan.</p>
</usage>

<seealso><directive module="mod_autoindex">ReadmeName</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>IndexIgnore</name>
<description>Añade a la lista de archivos que se ocultan al listar
un directorio</description>
<syntax>IndexIgnore <var>file</var> [<var>file</var>] ...</syntax>
<default>IndexIgnore "."</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>Indexes</override>

<usage>
    <p>La directiva <directive>IndexIgnore</directive> añade a la
    lista de archivos que se ocultan al listar un directorio.
    <var>File</var> es un nombre de archivo o un patrón que puede
    contener los caracteres comodín <code>?</code> y <code>*</code>.
    <code>?</code> coincide con un único carácter cualquiera, y
    <code>*</code> coincide con cualquier secuencia de caracteres,
    incluida una secuencia vacía. Varias directivas IndexIgnore se
    añaden a la lista, en lugar de sustituir la lista de archivos
    ignorados. Por defecto, la lista contiene <code>.</code> (el
    directorio actual).</p>

    <highlight language="config">
      IndexIgnore .??* *~ *# HEADER* README* RCS CVS *,v *,t
    </highlight>

    <p>Si <var>File</var> contiene un carácter <code>/</code>, solo
    se usa para la comparación con nombres de archivo la parte
    posterior a la última <code>/</code>. Por ejemplo,
    <code>*/.??*</code> es equivalente a <code>.??*</code>.</p>

    <note><title>Diferencias con los patrones de comodines de shell</title>
      <p>La comparación de comodines usada aquí <em>no</em> es la
      misma que la comparación de patrones de nombres de archivo al
      estilo shell (glob). En particular:</p>
      <ul>
        <li>Las expresiones entre corchetes como <code>[abc]</code>
        o <code>[!.]</code> no se admiten; se tratan como caracteres
        literales.</li>
        <li>Un <code>.</code> inicial en un nombre de archivo no se
        trata de forma especial. Por ejemplo, <code>*~</code>
        coincidirá con <code>.example~</code>, mientras que un glob
        de shell no lo haría.</li>
      </ul>
    </note>

    <note><title>Expresiones regulares</title>
      <p>Actualmente esta directiva no funciona en secciones de
      configuración que tengan argumentos de expresión regular,
      como <directive module="core" type="section"
      >DirectoryMatch</directive>
      </p>
    </note>
</usage>

</directivesynopsis>

<directivesynopsis>
<name>IndexIgnoreReset</name>
<description>Vacía la lista de archivos que se ocultan al listar
un directorio</description>
<syntax>IndexIgnoreReset ON|OFF</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>Indexes</override>
<compatibility>2.3.10 y posteriores</compatibility>

<usage>
    <p>La directiva <directive>IndexIgnoreReset</directive> elimina
    cualquier archivo ignorado por <directive
    module="mod_autoindex">IndexIgnore</directive> que de otro modo
    se heredaría de otras secciones de configuración.</p>

    <highlight language="config">
&lt;Directory "/var/www"&gt;
    IndexIgnore *.bak .??* *~ *# HEADER* README* RCS CVS *,v *,t
&lt;/Directory&gt;
&lt;Directory "/var/www/backups"&gt;
    IndexIgnoreReset ON
    IndexIgnore .??* *# HEADER* README* RCS CVS *,v *,t
&lt;/Directory&gt;
    </highlight>

    <note type="warning"><p> Revise la configuración por defecto
    para ver una lista de patrones que quizás quiera ignorar
    explícitamente después de usar esta directiva.</p></note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>IndexOptions</name>
<description>Varios parámetros de configuración para la indexación
de directorios</description>
<syntax>IndexOptions  [+|-]<var>option</var> [[+|-]<var>option</var>]
...</syntax>
<default>Por defecto, no hay ninguna opción activada.</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>Indexes</override>

<usage>
    <p>La directiva <directive>IndexOptions</directive> especifica
    el comportamiento de la indexación de directorios.
    <var>Option</var> puede ser una de las siguientes:</p>

    <dl>
      <dt><a name="indexoptions.addaltclass"
               id="indexoptions.addaltclass">AddAltClass</a></dt>
      <dd>Añade una declaración de clase CSS adicional a cada fila de
      la tabla del listado del directorio cuando está en vigor
      <code>IndexOptions HTMLTable</code> y se ha definido un
      <code>IndexStyleSheet</code>. En lugar de las clases estándar
      <code>even</code> y <code>odd</code> que de otro modo se
      aplicarían a cada fila de la tabla, se usa una clase
      <code>even-<em>ALT</em></code> o
      <code>odd-<em>ALT</em></code> donde <em>ALT</em> es, o bien el
      texto alternativo estándar asociado al estilo de archivo (por
      ejemplo, <em>snd</em>, <em>txt</em>, <em>img</em>, etc.), o bien
      el texto alternativo definido por alguna de las distintas
      directivas <code>AddAlt*</code>.
      </dd>

      <dt><a name="indexoptions.charset"
               id="indexoptions.charset"
      >Charset=<var>character-set</var></a></dt>

      <dd>La palabra clave <code>Charset</code> permite especificar
      el juego de caracteres de la página generada. El valor por
      defecto es <code>UTF-8</code> en Windows y Mac OS X, e
      <code>ISO-8859-1</code> en el resto.
      (Depende de si el sistema de archivos subyacente usa nombres
      de archivo Unicode o no.)

      <highlight language="config">
        IndexOptions Charset=UTF-8
      </highlight>
      </dd>

      <dt><a name="indexoptions.descriptionwidth"
               id="indexoptions.descriptionwidth"
      >DescriptionWidth=[<var>n</var> | *]</a></dt>

      <dd>La palabra clave <code>DescriptionWidth</code> permite
      especificar el ancho de la columna de descripción en
      caracteres.</dd>

      <dt><code>-DescriptionWidth</code> (o sin establecer) permite
      que <module>mod_autoindex</module> calcule el mejor ancho.</dt>

      <dd><code>DescriptionWidth=<var>n</var></code> fija el ancho de
      la columna a <var>n</var> bytes.</dd>

      <dd><code>DescriptionWidth=*</code> amplía la columna hasta el
      ancho necesario para acomodar la cadena de descripción más
      larga.

      <strong>Consulte la sección sobre <directive
      module="mod_autoindex">AddDescription</directive> para conocer
      los peligros inherentes al truncamiento de
      descripciones.</strong></dd>

      <dd>Este ancho se mide en bytes, no en caracteres; consulte la
      nota en <code><a
      href="#indexoptions.namewidth">NameWidth</a></code> sobre cómo
      esto puede afectar a la visualización de descripciones con
      caracteres multibyte o de ancho doble.</dd>

      <dt><a name="indexoptions.fancyindexing"
               id="indexoptions.fancyindexing">FancyIndexing</a></dt>

      <dd>Esto activa el indexado elegante de directorios.</dd>

      <dt><a name="indexoptions.foldersfirst"
               id="indexoptions.foldersfirst">FoldersFirst</a></dt>

      <dd>Si esta opción está activada, los listados de
      subdirectorios aparecerán <em>siempre</em> primero, seguidos
      de los archivos normales del directorio. El listado se divide
      básicamente en dos componentes, los archivos y los
      subdirectorios, y cada uno se ordena por separado y se muestra
      con los subdirectorios primero. Por ejemplo, si el orden de
      clasificación es descendente por nombre, y
      <code>FoldersFirst</code> está activado, el subdirectorio
      <code>Zed</code> se listará antes que el subdirectorio
      <code>Beta</code>, que se listará antes que los archivos
      normales <code>Gamma</code> y <code>Alpha</code>.
      <strong>Esta opción solo tiene efecto si <a
      href="#indexoptions.fancyindexing"><code>FancyIndexing</code></a>
      también está activada.</strong>
      </dd>

      <dt><a name="indexoptions.htmltable"
               id="indexoptions.htmltable">HTMLTable</a></dt>

      <dd>Esta opción, junto con <code>FancyIndexing</code>,
      construye una tabla sencilla para el listado elegante del
      directorio. Es necesaria en plataformas con utf-8 activado, o
      si los nombres de archivo o el texto de descripción van a
      alternar entre orden de lectura de izquierda a derecha y de
      derecha a izquierda.</dd>

      <dt><a name="indexoptions.iconsarelinks"
               id="indexoptions.iconsarelinks">IconsAreLinks</a></dt>

      <dd>Esto hace que los iconos formen parte del enlace del
      nombre de archivo, para el indexado elegante.</dd>

      <dt><a name="indexoptions.iconheight"
               id="indexoptions.iconheight">IconHeight[=<var
               >pixels</var>]</a></dt>

      <dd>La presencia de esta opción, cuando se usa junto con
      <code>IconWidth</code>, hará que el servidor incluya los
      atributos <code>height</code> y <code>width</code> en la
      etiqueta <code>img</code> del icono del archivo. Esto permite
      que el navegador precalcule la disposición de la página sin
      tener que esperar a que se carguen todas las imágenes. Si no se
      da ningún valor para la opción, se usa por defecto la altura
      estándar de los iconos suministrados con el software Apache
      httpd.

      <strong>Esta opción
      solo tiene efecto si <a href="#indexoptions.fancyindexing"
      ><code>FancyIndexing</code></a> también está activada.</strong>

      </dd>

      <dt><a name="indexoptions.iconwidth"
               id="indexoptions.iconwidth">IconWidth[=<var
               >pixels</var>]</a></dt>

      <dd>La presencia de esta opción, cuando se usa junto con
      <code>IconHeight</code>, hará que el servidor incluya los
      atributos <code>height</code> y <code>width</code> en la
      etiqueta <code>img</code> del icono del archivo. Esto permite
      que el navegador precalcule la disposición de la página sin
      tener que esperar a que se carguen todas las imágenes. Si no se
      da ningún valor para la opción, se usa por defecto el ancho
      estándar de los iconos suministrados con el software Apache
      httpd.</dd>

      <dt><a name="indexoptions.ignorecase"
               id="indexoptions.ignorecase">IgnoreCase</a></dt>

      <dd>Si esta opción está activada, los nombres se ordenan sin
      distinguir mayúsculas y minúsculas. Por ejemplo, si el orden de
      clasificación es ascendente por nombre, y <code>IgnoreCase</code>
      está activado, el archivo Zeta se listará después del archivo
      alfa (Nota: el archivo GAMMA siempre se listará antes que el
      archivo gamma).
      </dd>

      <dt><a name="indexoptions.ignoreclient"
               id="indexoptions.ignoreclient">IgnoreClient</a></dt>

      <dd>Esta opción hace que <module>mod_autoindex</module> ignore
      todas las variables de consulta del cliente, incluido el orden
      de clasificación (implica <code><a
      href="#indexoptions.suppresscolumnsorting"
      >SuppressColumnSorting</a></code>.)</dd>

      <dt><a name="indexoptions.namewidth"
               id="indexoptions.namewidth">NameWidth=[<var>n</var>
               | *]</a></dt>

      <dd>La palabra clave <code>NameWidth</code> permite especificar
      el ancho de la columna de nombre de archivo en bytes. El valor
      debe ser mayor que 5, o <code>*</code> para ancho automático.
      Si no se establece, o se prefija con <code>-</code>, se usa el
      valor por defecto de 20 bytes.</dd>

      <dd>Cuando no se establece, permite que <module
      >mod_autoindex</module> calcule el mejor ancho, pero solo
      hasta un máximo de 20 bytes.</dd>

      <dd><code>NameWidth=<var>n</var></code> fija el ancho de la
      columna a <var>n</var> bytes.</dd>

      <dd><code>NameWidth=*</code> amplía la columna hasta el ancho
      necesario.</dd>

      <dd>Dado que este ancho se mide en bytes, un nombre que
      contenga caracteres UTF-8 multibyte, o caracteres de escrituras
      Unicode "anchas" como CJK, ocupa más bytes, o menos columnas
      de terminal, que el mismo número de bytes ASCII. El relleno
      resultante puede, por tanto, desalinear las columnas que siguen
      al nombre. Esto se aplica igualmente a <code><a
      href="#indexoptions.descriptionwidth">DescriptionWidth</a></code>.
      Los directorios con ese tipo de contenido deberían usar en su
      lugar <code><a
      href="#indexoptions.htmltable">HTMLTable</a></code>, que
      presenta el listado como una tabla HTML en lugar de rellenarlo
      con espacios en blanco.</dd>

      <dt><a name="indexoptions.scanhtmltitles"
               id="indexoptions.scanhtmltitles">ScanHTMLTitles</a></dt>

      <dd>Esto activa la extracción del título de los documentos
      HTML para el indexado elegante. Si el archivo no tiene una
      descripción dada por <directive module="mod_autoindex"
      >AddDescription</directive>, httpd leerá el documento para
      obtener el valor del elemento <code>title</code>. Esto consume
      muchos recursos de CPU y disco.</dd>

      <dt><a name="indexoptions.showforbidden"
               id="indexoptions.showforbidden">ShowForbidden</a></dt>

      <dd>Si se especifica, Apache httpd mostrará los archivos
      normalmente ocultos porque la subpetición devolvió
      <code>HTTP_UNAUTHORIZED</code> o
      <code>HTTP_FORBIDDEN</code></dd>

      <dt><a name="indexoptions.suppresscolumnsorting"
               id="indexoptions.suppresscolumnsorting"
               >SuppressColumnSorting</a></dt>

      <dd>Si se especifica, Apache httpd no convertirá los
      encabezados de columna de un listado de directorio FancyIndexed
      en enlaces de ordenación. El comportamiento por defecto es que
      sean enlaces; al seleccionar el encabezado de columna se
      ordenará el listado del directorio por los valores de esa
      columna. No obstante, los argumentos de cadena de consulta que
      se añadan a la URL seguirán siendo respetados. Ese
      comportamiento se controla con <a
      href="#indexoptions.ignoreclient"><code>IndexOptions
      IgnoreClient</code></a>.</dd>

      <dt><a name="indexoptions.suppressdescription"
               id="indexoptions.suppressdescription"
               >SuppressDescription</a></dt>

      <dd>Esto suprimirá la descripción del archivo en los listados
      de indexado elegante. Por defecto, no se define ninguna
      descripción de archivo, así que el uso de esta opción
      recuperará 23 caracteres de espacio en pantalla para usarlos
      para otra cosa. Consulte <directive module="mod_autoindex"
      >AddDescription</directive> para obtener información sobre
      cómo establecer la descripción del archivo. Consulte también
      la opción de índice <code><a
      href="#indexoptions.descriptionwidth">DescriptionWidth</a></code>
      para limitar el tamaño de la columna de descripción.

      <strong>Esta opción
      solo tiene efecto si <a href="#indexoptions.fancyindexing"
      ><code>FancyIndexing</code></a> también está activada.</strong>
      </dd>

      <dt><a name="indexoptions.suppresshtmlpreamble"
               id="indexoptions.suppresshtmlpreamble"
               >SuppressHTMLPreamble</a></dt>

      <dd>Si el directorio contiene realmente un archivo especificado
      por la directiva <directive module="mod_autoindex"
      >HeaderName</directive>, el módulo normalmente incluye el
      contenido del archivo después de un preámbulo HTML estándar
      (<code>&lt;html&gt;</code>, <code>&lt;head&gt;</code>,
      <em>etcétera</em>). La opción <code>SuppressHTMLPreamble</code>
      desactiva este comportamiento, haciendo que el módulo empiece
      a mostrar directamente el contenido del archivo de cabecera. En
      este caso, el archivo de cabecera debe contener las
      instrucciones HTML adecuadas. Si no hay archivo de cabecera, el
      preámbulo se genera como de costumbre. Si además se especifica
      un <directive
      module="mod_autoindex">ReadmeName</directive>, y ese archivo
      existe, también se omiten de la salida las etiquetas de cierre
      &lt;/body&gt;&lt;/html&gt;, suponiendo que probablemente
      incluirá esas etiquetas de cierre en ese archivo.</dd>

      <dt><a name="indexoptions.suppressicon"
               id="indexoptions.suppressicon">SuppressIcon</a></dt>

      <dd>Esto suprimirá el icono en los listados de indexado
      elegante. Combinar <code>SuppressIcon</code> y
      <code>SuppressRules</code> produce una salida HTML 3.2
      correcta, que según la especificación final prohíbe los
      elementos <code>img</code> y <code>hr</code> dentro del bloque
      <code>pre</code> (usado para dar formato a los listados
      FancyIndexed.)</dd>

      <dt><a name="indexoptions.suppresslastmodified"
               id="indexoptions.suppresslastmodified"
               >SuppressLastModified</a></dt>

      <dd>Esto suprimirá la visualización de la fecha de última
      modificación, en los listados de indexado elegante.

      <strong>Esta opción
      solo tiene efecto si <a href="#indexoptions.fancyindexing"
      ><code>FancyIndexing</code></a> también está activada.</strong>
      </dd>

      <dt><a name="indexoptions.suppressrules"
               id="indexoptions.suppressrules">SuppressRules</a>
      </dt>

      <dd>Esto suprimirá las líneas de regla horizontal (elementos
      <code>hr</code>) en los listados de directorio. Combinar
      <code>SuppressIcon</code> y
      <code>SuppressRules</code> produce una salida HTML 3.2
      correcta, que según la especificación final prohíbe los
      elementos <code>img</code> y <code>hr</code> dentro del bloque
      <code>pre</code> (usado para dar formato a los listados
      FancyIndexed.)

      <strong>Esta opción
      solo tiene efecto si <a href="#indexoptions.fancyindexing"
      ><code>FancyIndexing</code></a> también está activada.</strong>

      </dd>

      <dt><a name="indexoptions.suppresssize"
               id="indexoptions.suppresssize">SuppressSize</a></dt>

      <dd>Esto suprimirá el tamaño del archivo en los listados de
      indexado elegante.

      <strong>Esta opción
      solo tiene efecto si <a href="#indexoptions.fancyindexing"
      ><code>FancyIndexing</code></a> también está activada.</strong>
      </dd>

      <dt><a name="indexoptions.trackmodified"
               id="indexoptions.trackmodified">TrackModified</a></dt>

      <dd>Esto devuelve los valores <code>Last-Modified</code> y
      <code>ETag</code> del directorio listado en la cabecera HTTP.
      Solo es válido si el sistema operativo y el sistema de archivos
      devuelven resultados stat() apropiados. Algunos sistemas Unix
      lo hacen, igual que los volúmenes JFS de OS2 y NTFS de Win32.
      Los volúmenes FAT de OS2 y Win32, por ejemplo, no lo hacen. Una
      vez activada esta funcionalidad, el cliente o el proxy pueden
      seguir los cambios en la lista de archivos cuando realizan una
      petición <code>HEAD</code>. Tenga en cuenta que algunos
      sistemas operativos siguen correctamente los archivos nuevos y
      eliminados, pero no siguen los cambios de tamaño o fecha de los
      archivos dentro del directorio. <strong>Los cambios en el
      tamaño o la fecha de un archivo existente no actualizarán la
      cabecera <code>Last-Modified</code> en todas las plataformas
      Unix.</strong> Si esto le preocupa, deje esta opción
      desactivada.</dd>

      <dt><a name="indexoptions.type"
               id="indexoptions.type"
      >Type=<var>MIME content-type</var></a></dt>

      <dd>La palabra clave <code>Type</code> permite especificar el
      tipo de contenido MIME de la página generada. El valor por
      defecto es <var>text/html</var>.

      <highlight language="config">
        IndexOptions Type=text/plain
      </highlight>
      </dd>

      <dt><a name="indexoptions.useolddateformat"
               id="indexoptions.useolddateformat"
      >UseOldDateFormat</a>
      (<em>Apache HTTP Server 2.4.26 y posteriores</em>)</dt>

      <dd>El formato de fecha usado para el campo <code>Last
      Modified</code> se cambió involuntariamente a
      <code>"%Y-%m-%d %H:%M"</code> desde
      <code>"%d-%b-%Y %H:%M"</code> en la versión 2.4.0. Al activar
      esta opción se restaura el formato de fecha de la versión 2.2 y
      anteriores.</dd>

      <dt><a name="indexoptions.versionsort"
               id="indexoptions.versionsort">VersionSort</a></dt>

      <dd>La palabra clave <code>VersionSort</code> hace que los
      archivos que contienen números de versión se ordenen de forma
      natural. Las cadenas se ordenan como de costumbre, salvo que
      las subcadenas de dígitos en el nombre y la descripción se
      comparan según su valor numérico.

      <example><title>Ejemplo:</title>
        foo-1.7<br />
        foo-1.7.2<br />
        foo-1.7.12<br />
        foo-1.8.2<br />
        foo-1.8.2a<br />
        foo-1.12
      </example>

      <p>Si el número empieza por cero, entonces se considera una
      fracción:</p>

      <example>
        foo-1.001<br />
        foo-1.002<br />
        foo-1.030<br />
        foo-1.04
      </example>
      </dd>

      <dt><a name="indexoptions.xhtml"
               id="indexoptions.xhtml">XHTML</a></dt>

      <dd>La palabra clave <code>XHTML</code> fuerza a
      <module>mod_autoindex</module> a emitir código XHTML 1.0 en
      lugar de HTML 3.2.
      <strong>Esta opción
      solo tiene efecto si <a href="#indexoptions.fancyindexing"
      ><code>FancyIndexing</code></a> también está activada.</strong>
      </dd>

      <dt><a name="indexoptions.none"
               id="indexoptions.none">None</a></dt>

      <dd>La palabra clave <code>None</code> desactiva todas las
      opciones de indexado para el directorio. No se activará
      ninguna funcionalidad de indexado elegante.
      <note><code>None</code> no puede prefijarse con <code>+</code>
      ni con <code>-</code>, y no puede combinarse con ninguna otra
      palabra clave de <directive>IndexOptions</directive>. Si se
      especifica <code>None</code>, debe ser la única opción
      dada.</note>
      </dd>

    </dl>


   <!--
     XXX: we should consider to allow sections inside <usage>
     this would require some xslt changes...
   -->
   <dl><dt>IndexOptions incrementales</dt>
   <dd>
     <p>Tenga en cuenta cómo se gestionan varias directivas
     <directive>IndexOptions</directive>.</p>

     <ul>
     <li>Varias directivas <directive>IndexOptions</directive> para
     un único directorio ahora se combinan entre sí. El resultado
     de:

     <highlight language="config">
&lt;Directory "/foo"&gt;
    IndexOptions HTMLTable
    IndexOptions SuppressColumnsorting
&lt;/Directory&gt;
     </highlight>

     <p>será equivalente a</p>

     <highlight language="config">
       IndexOptions HTMLTable SuppressColumnsorting
     </highlight>
     </li>

     <li>La incorporación de la sintaxis incremental (<em>es
     decir</em>, prefijar las palabras clave con <code>+</code> o
     <code>-</code>).</li>
     </ul>

     <p>Cada vez que se encuentra una palabra clave prefijada con
     '+' o '-', se aplica a la configuración actual de
     <directive>IndexOptions</directive> (que puede haberse heredado
     de un directorio de nivel superior). Sin embargo, cada vez que
     se procesa una palabra clave sin prefijo, se borran todas las
     opciones heredadas y cualquier configuración incremental
     encontrada hasta ese momento, excepto las opciones que toman un
     valor
     (<code>Charset</code>, <code>Type</code>,
     <code>DescriptionWidth</code>, <code>NameWidth</code>,
     <code>IconWidth</code>, <code>IconHeight</code>),
     que se heredan de forma independiente.
     Considere el siguiente ejemplo:</p>

     <highlight language="config">
IndexOptions +ScanHTMLTitles -IconsAreLinks FancyIndexing
IndexOptions +SuppressSize
     </highlight>

     <p>El efecto neto es equivalente a <code>IndexOptions
     FancyIndexing +SuppressSize</code>, porque el
     <code>FancyIndexing</code> sin prefijo descartó las palabras
     clave incrementales anteriores a él, pero permitió que volvieran
     a acumularse después.</p>

     <p>Para establecer incondicionalmente las
     <directive>IndexOptions</directive> de un directorio concreto,
     borrando la configuración heredada, especifique las palabras
     clave sin ningún prefijo <code>+</code> o <code>-</code>.</p>

     <p>Tenga en cuenta que los prefijos <code>+</code> y
     <code>-</code> no se pueden usar con opciones que toman un
     valor, como
     <code>IconWidth</code>, <code>IconHeight</code>,
     <code>NameWidth</code>, o <code>DescriptionWidth</code>.</p>
   </dd>
   </dl>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>IndexOrderDefault</name>
<description>Establece el orden por defecto del índice de directorio</description>
<syntax>IndexOrderDefault Ascending|Descending
Name|Date|Size|Description</syntax>
<default>IndexOrderDefault Ascending Name</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>Indexes</override>

<usage>
    <p>La directiva <directive>IndexOrderDefault</directive> se usa
    en combinación con la opción de índice <code><a
    href="#indexoptions.fancyindexing">FancyIndexing</a></code>. Por
    defecto, los listados de directorio con indexado elegante se
    muestran en orden ascendente por nombre de archivo; la directiva
    <directive>IndexOrderDefault</directive> permite cambiar este
    orden de visualización inicial.</p>

    <p><directive>IndexOrderDefault</directive> toma dos
    argumentos. El primero debe ser <code>Ascending</code> o
    <code>Descending</code>, indicando la dirección de la
    ordenación. El segundo argumento debe ser una de las palabras
    clave <code>Name</code>,
    <code>Date</code>, <code>Size</code>, o <code>Description</code>,
    e identifica la clave principal. La clave secundaria es
    <em>siempre</em> el nombre de archivo en orden ascendente.</p>

    <p>Si lo desea, puede evitar que el cliente reordene la lista
    añadiendo también la opción de índice <code><a
    href="#indexoptions.suppresscolumnsorting">SuppressColumnSorting</a></code>
    para eliminar el enlace de ordenación de la parte superior de la
    columna, junto con la opción de índice <code><a
    href="#indexoptions.ignoreclient">IgnoreClient</a></code> para
    evitar que añadan manualmente opciones de ordenación a la cadena
    de consulta con el fin de anular sus preferencias de
    ordenación.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>IndexStyleSheet</name>
<description>Añade una hoja de estilo CSS al índice de directorio</description>
<syntax>IndexStyleSheet <var>url-path</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>Indexes</override>

<usage>
    <p>La directiva <directive>IndexStyleSheet</directive> establece
    el nombre del archivo que se usará como CSS para el listado del
    índice.
    </p>
    <highlight language="config">
      IndexStyleSheet "/css/style.css"
    </highlight>

    <p>Usar esta directiva junto con <code>IndexOptions
    HTMLTable</code> añade una serie de clases CSS al HTML
    resultante. A toda la tabla se le asigna un id CSS de
    <code>indexlist</code>, y las siguientes clases se asocian a las
    distintas partes del listado:</p>

    <table border="1" style="zebra">
    <tr><th>Clase</th><th>Definición</th></tr>
    <tr><td>tr.indexhead</td><td>Fila de encabezado del listado</td></tr>
    <tr><td>th.indexcolicon y td.indexcolicon</td> <td>Columna de icono</td></tr>
    <tr><td>th.indexcolname y td.indexcolname</td> <td>Columna de nombre de archivo</td></tr>
    <tr><td>th.indexcollastmod y td.indexcollastmod</td> <td>Columna de última modificación</td></tr>
    <tr><td>th.indexcolsize y td.indexcolsize</td> <td>Columna de tamaño de archivo</td></tr>
    <tr><td>th.indexcoldesc y td.indexcoldesc</td> <td>Columna de descripción</td></tr>
    <tr><td>tr.breakrow</td> <td>Regla horizontal en la parte inferior de la tabla</td></tr>
    <tr><td>tr.odd y tr.even</td> <td>Filas pares e impares alternas</td></tr>
    </table>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>IndexHeadInsert</name>
<description>Inserta texto en la sección HEAD de una página de índice.</description>
<syntax>IndexHeadInsert <var>"markup ..."</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>Indexes</override>

<usage>
    <p>La directiva <directive>IndexHeadInsert</directive> especifica
    una cadena que se insertará en la sección <var>&lt;head&gt;</var>
    del HTML generado para la página de índice.</p>
    <highlight language="config">
      IndexHeadInsert "&lt;link rel=\"sitemap\" href=\"/sitemap.html\"&gt;"
    </highlight>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ReadmeName</name>
<description>Nombre del archivo que se insertará al final
del listado del índice</description>
<syntax>ReadmeName <var>filename</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>Indexes</override>

<usage>
    <p>La directiva <directive>ReadmeName</directive> establece el
    nombre del archivo que se añadirá al final del listado del
    índice. <var>Filename</var> es el nombre del archivo que se va a
    incluir, y se toma como relativo a la ubicación que se está
    indexando. Si
    <var>Filename</var> empieza por una barra, como en el ejemplo 2,
    se tomará como relativo al <directive module="core">DocumentRoot</directive>.
    </p>

    <highlight language="config">
# Example 1
ReadmeName FOOTER.html
    </highlight>

    <highlight language="config">
# Example 2
ReadmeName /include/FOOTER.html
    </highlight>

    <p>Consulte también <directive module="mod_autoindex"
    >HeaderName</directive>, donde este comportamiento se describe
    con mayor detalle.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>IndexForbiddenReturn404</name>
<description>Devuelve un error HTTP 404 en lugar de Forbidden cuando
las opciones no permiten el listado de directorio</description>
<syntax>IndexForbiddenReturn404 On|Off</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>Indexes</override>
<compatibility>Añadido en la versión 2.5.1</compatibility>

<usage>
    <p>La directiva <directive>IndexForbiddenReturn404</directive>
    controla si este módulo devuelve un código de estado HTTP 404 en
    lugar de un código de estado HTTP 403 cuando
    <directive>Options</directive> no permite que se devuelvan
    índices.</p>
</usage>
</directivesynopsis>

</modulesynopsis>
