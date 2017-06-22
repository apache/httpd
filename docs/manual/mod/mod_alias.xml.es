<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1799478 -->
<!-- Spanish Translation: Daniel Ferradal <dferradal@apache.org> -->

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

<modulesynopsis metafile="mod_alias.xml.meta">

<name>mod_alias</name>
<description>Facilita el mapeo a diferentes partes del sistema de ficheros del host en el árbol de documentos y la redirección de URLs
</description>

<status>Base</status>
<sourcefile>mod_alias.c</sourcefile>
<identifier>alias_module</identifier>

<summary>
    <p>Las directivas facilitadas por este módulo permiten la manipulación y control de URLs según llegan las peticiones al servidor. Las directivas
    <directive module="mod_alias">Alias</directive> y 
    <directive module="mod_alias">ScriptAlias</directive> se usan para mapear URLs con rutas del sistema de ficheros. Esto permite que se sirva contenido que no está directamente dentro del 
    <directive module="core">DocumentRoot</directive> como si fuera parte de éste. La directiva <directive module="mod_alias">ScriptAlias</directive> tiene además el efecto de hacer que el directorio de destino contenga solo scripts CGI.</p>

    <p>Las directivas <directive module="mod_alias">Redirect</directive> se usan para indicar a los clientes que hagan una nueva petición con una URL distinta. Se usan a menudo cuando el recurso se ha movido a una nueva ubicación.</p>

    <p>Cuando se usan las directivas <directive module="mod_alias">Alias</directive>,
    <directive module="mod_alias">ScriptAlias</directive> y
    <directive module="mod_alias">Redirect</directive> dentro de una sección 
    <directive type="section" module="core">Location</directive>
    o <directive type="section" module="core">LocationMatch</directive>, se puede usar
    <a href="../expr.html">sintaxis de expresión</a> para manipuilar la ruta de destino o URL.
    </p>

    <p><module>mod_alias</module> se ha diseñado para gestionar tareas sencillas de manipulación de URL. Para tareas más complicadas como la manipulación de "query string", use las herramientas facilitadas por
    <module>mod_rewrite</module>.</p>

</summary>

<seealso><module>mod_rewrite</module></seealso> 
<seealso><a href="../urlmapping.html">Mapeo de URLs al sistema de ficheros</a></seealso>

<section id="order"><title>Orden de Procesamiento</title>

    <p>Aliases y Redirects que se dan en diferentes contextos se procesan como otras directivas según las <a href="../sections.html#mergin">reglas de fusión</a> estándar.  Pero cuando se dan múltiples 
    Aliases o Redirects en el mismo contexto (por ejemplo, en la misma sección 
    <directive type="section" module="core">VirtualHost</directive>)
    entonces se procesan en un orden concreto.</p>

    <p>En primer lugar, todos los Redirect se procesan antes que los Aliases, y por tanto una solicitud que coincida con un 
    <directive module="mod_alias">Redirect</directive> o 
    <directive module="mod_alias">RedirectMatch</directive> nunca aplicará un Alias. En segundo lugar, los Aliases y Redirect se procesan en el orden en el que aparecen en los ficheros de configuración, y la primera coincidencia es la que tiene prioridad.</p>

    <p>Por esta razón, cuando dos o más de estas directivas se aplican a la misma sub-ruta, debe definir la ruta más específica primero para que todas las directivas tengan efecto. Por ejemplo, la siguiente configuración funcionará como se espera:</p>

    <highlight language="config">
Alias "/foo/bar" "/baz"
Alias "/foo" "/gaq"
    </highlight>

    <p>Pero si estas dos directivas estuvieran en orden inverso, el 
    <directive module="mod_alias">Alias</directive>
    <code>/foo</code> siempre se aplicaría antes que el 
    <directive module="mod_alias">Alias</directive> <code>/foo/bar</code>, así que se obviaría la última directiva.</p>

    <p>Cuando las directivas <directive module="mod_alias">Alias</directive>,
    <directive module="mod_alias">ScriptAlias</directive> y
    <directive module="mod_alias">Redirect</directive> se usan dentro de una sección
    <directive type="section" module="core">Location</directive>
    o <directive type="section" module="core">LocationMatch</directive>, estas directivas tendrán prioridad sobre cualquier directiva 
    <directive module="mod_alias">Alias</directive>, 
    <directive module="mod_alias">ScriptAlias</directive> y
    <directive module="mod_alias">Redirect</directive> definidas globalmente.
    </p>

</section>

<directivesynopsis>
<name>Alias</name>
<description>Mapea URLs a rutas del sistema de ficheros</description>
<syntax>Alias [<var>URL-path</var>]
<var>file-path</var>|<var>directory-path</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context>
</contextlist>

<usage>

    <p>La directiva <directive>Alias</directive> permite que se almacenen documentos en el sistema de ficheros local en rutas distintas de las que están bajo
    <directive module="core">DocumentRoot</directive>. URLs con una ruta 
    (%-decodificada) que comienzan con <var>URL-path</var> serán mapeadas a ficheros locales que comiencen con
    <var>directory-path</var>.  El
    <var>URL-path</var> es sensible a mayúsculas, incluso en sistemas de ficheros que no lo son.</p>

    <highlight language="config">
Alias "/image" "/ftp/pub/image"
    </highlight>

    <p>Una petición para <code>http://example.com/image/foo.gif</code> haría que el servidor respondiera con el fichero 
    <code>/ftp/pub/image/foo.gif</code>. Solo se comparan segmentos de ruta completos, así que el alias de más arriba no valdría para la petición 
    <code>http://example.com/imagefoo.gif</code>. Para ejemplos más complejos de expresiones regulares, vea la directiva 
    <directive module="mod_alias">AliasMatch</directive>.</p>

    <p>Tenga en cuenta que si incluye una / final en el 
    <var>URL-path</var> entonces el servidor requerirá una / final para poder extender el alias. Es decir, si usa</p>

    <highlight language="config">
Alias "/icons/" "/usr/local/apache/icons/"
    </highlight>

    <p>entonces la URL <code>/icons</code> no coincidirá con el alias, porque no tiene la / final. De la misma manera, si omite la barra en el
    <var>URL-path</var> también debe omitirla del
    <var>file-path</var>.</p>

    <p>Considere que seguramente tenga que especificar secciones de  
    <directive type="section" module="core">Directory</directive> adicionales que cubran los <em>destinos</em> de los aliases. Las directivas Alias se comprueban antes que las de 
    <directive type="section" module="core">Directory</directive>, así que solo los destinos de los alias se ven afectados.
    (Sin embargo tenga en cuenta que las secciones 
    <directive type="section" module="core">Location</directive>
    se examinan una vez antes de que los alias tengan efecto, así que se aplicarán.)</p>

    <p>En particular, si está creando un <code>Alias</code> a un directorio fuera de su 
    <directive module="core">DocumentRoot</directive>, probablemente tenga que darle permisos de manera explícita al directorio de destino.</p>

    <highlight language="config">
Alias "/image" "/ftp/pub/image"
&lt;Directory "/ftp/pub/image"&gt;
    Require all granted
&lt;/Directory&gt;
    </highlight>

    <p>Cualquier número de barras en el parámetro <var>URL-path</var> coincide con el mismo número de barras en el URL-path solicitado.</p>

    <p>Si la directiva <directive>Alias</directive> se usa dentro de una sección
    <directive type="section" module="core">Location</directive>
    o <directive type="section" module="core">LocationMatch</directive> el URL-path se omite, y el file-path se interpreta usando <a href="../expr.html">sintáxis de expresión</a>.<br />
    Esta sintáxis está disponible en Apache 2.4.19 y versiones posteriores.</p>

    <highlight language="config">
&lt;Location "/image"&gt;
    Alias "/ftp/pub/image"
&lt;/Location&gt;
&lt;LocationMatch "/error/(?&lt;NUMBER&gt;[0-9]+)"&gt;
    Alias "/usr/local/apache/errors/%{env:MATCH_NUMBER}.html"
&lt;/LocationMatch&gt;
    </highlight>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>AliasMatch</name>
<description>Mapea URLs a ubicaciones del sistema de ficheros usando expresiones regulares</description>
<syntax>AliasMatch <var>regex</var>
<var>file-path</var>|<var>directory-path</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>Esta directiva es equivalente a 
    <directive module="mod_alias">Alias</directive>, pero hace uso de 
    <glossary ref="regex">expresiones regulares</glossary>,
    en lugar de comparaciones simples de prefijo. La expresión 
    regular facilitada se compara con el URL-path, y si coincide, 
    el servidor sustituye cualquier coincidencia entre paréntesis con 
    la cadena de caracteres facilitada y la usa como el nombre de fichero. Por ejemplo, para activar el directorio <code>/icons</code>, uno podría usar:
    </p>

    <highlight language="config">
AliasMatch "^/icons(/|$)(.*)" "/usr/local/apache/icons$1$2"
    </highlight>

    <p>Puede usar toda la capacidad que le permiten las
    <glossary ref="regex">expresiones regulares</glossary>. Por ejemplo, es posible construir un alias con comprobación insensible a mayúsculas del URL-path:</p>

    <highlight language="config">
AliasMatch "(?i)^/image(.*)" "/ftp/pub/image$1"
    </highlight>

    <p>Una sutil diferencia entre 
    <directive module="mod_alias">Alias</directive>
    y <directive module="mod_alias">AliasMatch</directive> es que
    <directive module="mod_alias">Alias</directive> copiará automáticamente cualquier parte adicional de la URI, pasada la parte que coincide, al final de la ruta del fichero en el parámetro de la derecha, mientras que
    <directive module="mod_alias">AliasMatch</directive> no lo hará. Esto significa en casi todos los casos, querrá que las expresiones regulares concuerden con la URI solicitada al completo desde el comienzo al final, y usar la sustitución del parámetro a la derecha.</p>

    <p>En otras palabras, cambiar
    <directive module="mod_alias">Alias</directive> a
    <directive module="mod_alias">AliasMatch</directive> no tendrá el mismo resultado. Como mínimo, tendrá que añadir un <code>^</code> al comienzo de la expresión regular, añadir un <code>(.*)$</code> al final y añadir 
    <code>$1</code> al final del reemplazo.</p>

    <p>Por ejemplo, supongamos que quiere reemplazar esto con AliasMatch:</p>

    <highlight language="config">
Alias "/image/" "/ftp/pub/image/"
    </highlight>

    <p>Esto no es equivalente - ¡no haga esto! Esto enviará todas las peticiones que tengan /image/ en cualquier parte de la petición y la pondrá en /ftp/pub/image/:</p>

    <highlight language="config">
AliasMatch "/image/" "/ftp/pub/image/"
    </highlight>

    <p>Esto es lo que necesita para que tenga el mismo efecto:</p>

    <highlight language="config">
AliasMatch "^/image/(.*)$" "/ftp/pub/image/$1"
    </highlight>

    <p>Por supuesto, no hay ningún motivo para usar
    <directive module="mod_alias">AliasMatch</directive>
    donde <directive module="mod_alias">Alias</directive> funcionaría.  
    <directive module="mod_alias">AliasMatch</directive> le permite hacer cosas más complicadas. Por ejemplo, puede servir diferentes tipos de ficheros desde diferentes directorios:</p>

    <highlight language="config">
AliasMatch "^/image/(.*)\.jpg$" "/files/jpg.images/$1.jpg"
AliasMatch "^/image/(.*)\.gif$" "/files/gif.images/$1.gif"
    </highlight>

    <p>Si se usan multiples barras iniciales en la URL solicitada, el servidor las descarta antes de que las directivas de este módulo las compare con el URL-path solicitado.
    </p>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>Redirect</name>
<description>Envía una redirección externa indicando al cliente que solicite una URL distinta</description>
<syntax>Redirect [<var>status</var>] [<var>URL-path</var>]
<var>URL</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>
    <p>La directiva <directive>Redirect</directive> mapea una URL antigua a una nueva indicando al cliente que solicite el recurso en otra ubicación.</p>

    <p>El antiguo <em>URL-path</em> es una ruta (%-decodificada) que comienza con una barra. No se permite una ruta relativa.</p>

    <p>La nueva <em>URL</em> puede ser una URL absoluta que comienza con esquema y nombre de host, or un URL-path que comienza con una barra (/). En este último caso se añadirán el esquema y nombre de host del servidor actual si tiene <directive module="core">UseCanonicalName</directive> configurado a on, si no el nombre de host se reemplazará por la cabecera Host solicitada.</p>

    <p>Entonces cualquier petición que comience con <em>URL-path</em> devolverá una solicitud de redirección al cliente hacia la ubicación de la <em>URL</em> de destino. Información adicional de la ruta pasado el <em>URL-path</em> que coincide se añadirá al final de la URL de destino.</p>

    <highlight language="config">
# Redirect hacia una URL en un host diferente
Redirect "/service" "http://foo2.example.com/service"

# Redirect hacia una URL en el mismo host
Redirect "/one" "/two"
    </highlight>

    <p>Si el cliente solicita <code>http://example.com/service/foo.txt</code>, se le indicará que acceda a 
    <code>http://foo2.example.com/service/foo.txt</code> en su lugar. Esto incluye solicitudes con parámetros 
    <code>GET</code>, tales como
    <code>http://example.com/service/foo.pl?q=23&amp;a=42</code>,que será
    redirigido a
    <code>http://foo2.example.com/service/foo.pl?q=23&amp;a=42</code>.
    Tenga en cuenta que los <code>POST</code> serán descartados.<br />
    Solo se comparan segmentos completos de ruta, así que el ejemplo de más arriba no coincidiría con una petición a
    <code>http://example.com/servicefoo.txt</code>. Para comparaciones más complejas usando la 
    <a href="../expr.html">sintáxis de expresión</a>, omita el argumento de URL-path tal y como se indica más abajo. Alternativamente, para coincidencias usando expresiones regulares, vea la directiva 
    <directive module="mod_alias">RedirectMatch</directive>.</p>


    <note><title>Nota</title>
    <p>Las directivas <directive>Redirect</directive> tienen priodidad sobre directivas 
    <directive module="mod_alias">Alias</directive> y 
    <directive module="mod_alias">ScriptAlias</directive>, independientemente de su orden en el fichero de configuración. Directivas 
    <directive>Redirect</directive> 
    dentro de Location tiene prioridad sobre directivas 
    <directive>Redirect</directive> y 
    <directive module="mod_alias">Alias</directive> con un <var>URL-path</var>.</p>
    </note>

    <p>Si no se indica un parámetro <var>status</var>, la redirección será
    "temporal" (estado HTTP 302). Esto le indica al cliente que el recurso se ha movido temporalmente. El parámetro <var>status</var> se puede usar para devolver otros códigos de estado HTTP:</p>

    <dl>
      <dt>permanent</dt>

      <dd>Devuelve una estado de redirección permanente (301) indicando que el recurso se ha movido de forma permanente.</dd>

      <dt>temp</dt>

      <dd>Devuelve un estado de redirección temporal (302). Este es el valor por defecto.</dd>

      <dt>seeother</dt>

      <dd>Devuelve un estado "See Other" (303) indicando que el recurso ha sido sustituido.</dd>

      <dt>gone</dt>

      <dd>Devuelve un estado "Gone" (410) indicando que el recurso ha sido eliminado de forma permanente. Cuando se usa este estado, el parámetro 
      <var>URL</var> debería omitirse.</dd>
    </dl>

    <p>Se pueden devolver otros códigos de estado indicando el código numérico del estado en el valor de <var>status</var>. Si el estado está entre 300 y 399, el parámetro <var>URL</var> debe estar presente. Si el estado 
    <em>no</em> está entre 300 and 399, el parámetro <var>URL</var> debe ser omitido. El estado debe ser un código de estado válido HTTP, conocido por el Servidor Apache HTTP (vea la función <code>send_error_response</code> en http_protocol.c).</p>

    <highlight language="config">
Redirect permanent "/one" "http://example.com/two"
Redirect 303 "/three" "http://example.com/other"
    </highlight>

    <p>Si se usa la directiva <directive>Redirect</directive> dentro de una sección
    <directive type="section" module="core">Location</directive>
    o <directive type="section" module="core">LocationMatch</directive>
    sin el <var>URL-path</var>, entonces el parámetro <var>URL</var> será interpretado
    usando <a href="../expr.html">sintáxis de expresión</a>.<br />
    Esta sintáxis está disponible en Apache 2.4.19 y versiones posteriores.</p>

    <highlight language="config">
&lt;Location "/one"&gt;
    Redirect permanent "http://example.com/two"
&lt;/Location&gt;
&lt;Location "/three"&gt;
    Redirect 303 "http://example.com/other"
&lt;/Location&gt;
&lt;LocationMatch "/error/(?&lt;NUMBER&gt;[0-9]+)"&gt;
    Redirect permanent "http://example.com/errors/%{env:MATCH_NUMBER}.html"
&lt;/LocationMatch&gt;
    </highlight>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>RedirectMatch</name>
<description>Envía una redirección externa basada en una coincidencia de expresión regular con la URL actual
</description>
<syntax>RedirectMatch [<var>status</var>] <var>regex</var>
<var>URL</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>
    <p>Esta directiva es equivalente a 
    <directive module="mod_alias">Redirect</directive>, pero hace uso de 
    <glossary ref="regex">expresiones regulares</glossary>,
    en lugar de comparaciones simple de prefijo. La expresión 
    regular facilitada se compara con el URL-path, y si coincide, 
    el servidor sustituye cualquier coincidencia entre paréntesis con 
    la cadena de caracteres facilitada y la usa como el nombre de fichero. Por ejemplo, para redirigir todos los ficheros GIF al mismo nombre pero del tipo JPEG en otro servidor, uno podría usar:</p>

    <highlight language="config">
RedirectMatch "(.*)\.gif$" "http://other.example.com$1.jpg"
    </highlight>

    <p>Las consideraciones relacionadas con las diferencias entre
    <directive module="mod_alias">Alias</directive> y
    <directive module="mod_alias">AliasMatch</directive>
    también aplican a las diferencias entre
    <directive module="mod_alias">Redirect</directive> y
    <directive module="mod_alias">RedirectMatch</directive>.
    Vea <directive module="mod_alias">AliasMatch</directive> para más
    detalles.</p>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>RedirectTemp</name>
<description>Envía una redirección externa temporal indicando al cliente que solicite una URL diferente</description>
<syntax>RedirectTemp <var>URL-path</var> <var>URL</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>
    <p>Esta directiva le hace saber al cliente que el Redirect es solo temporal (estado 302). Exactamente equivalente a 
    <code>Redirect temp</code>.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>RedirectPermanent</name>
<description>Envía una redirección externa permanente indicando al cliente que solicite una URL diferente</description>
<syntax>RedirectPermanent <var>URL-path</var> <var>URL</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>
    <p>Esta directiva hace saber al cliente que el Redirect es permanente
    (estado 301). Exactamente equivalente a 
    <code>Redirect permanent</code>.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ScriptAlias</name>
<description>Mapea una URL a una ubicación del sistema de ficheros y designa el destino como un script CGI</description>
<syntax>ScriptAlias [<var>URL-path</var>]
<var>file-path</var>|<var>directory-path</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context>
</contextlist>

<usage>
    <p>La directiva <directive>ScriptAlias</directive> tiene el mismo comportamiento que la directiva <directive module="mod_alias">Alias</directive>, excepto que además indica el directorio de destino conteniendo scripts CGI que serán procesados por el handler cgi-script de 
    <module>mod_cgi</module>. URLs con una ruta sensible a mayúsculas y (%-decodificadas) que comienzan con <var>URL-path</var> serán
    mapeadas a scripts que comiencen con el segundo parámetro, que es un nombre de ruta completo en el sistema de ficheros local.</p>

    <highlight language="config">
ScriptAlias "/cgi-bin/" "/web/cgi-bin/"
    </highlight>

    <p>Una petición para <code>http://example.com/cgi-bin/foo</code> haría que el servidor ejecute el script <code>/web/cgi-bin/foo</code>. Esta configuración es esencialmente equivalente a:</p>
    <highlight language="config">
Alias "/cgi-bin/" "/web/cgi-bin/"
&lt;Location "/cgi-bin"&gt;
    SetHandler cgi-script
    Options +ExecCGI
&lt;/Location&gt;
    </highlight>

    <p>También puede usarse <directive>ScriptAlias</directive>junto con un script o handler que usted tenga. Por ejemplo:</p>

    <highlight language="config">
ScriptAlias "/cgi-bin/" "/web/cgi-handler.pl"
    </highlight>

    <p>En este escenario todos los ficheros solicitados en 
    <code>/cgi-bin/</code> serán gestionados por el fichero que usted ha configurado, esto permite que use su propio handler personalizado. Puede que quiera usar esto como un wrapper de CGI y así pueda añadir contenido, o alguna otra acción a medida.</p>

    <note type="warning">Es más seguro evitar que se coloquen scripts CGI bajo el <directive module="core">DocumentRoot</directive> para que no se revele de manera accidental el código fuente si la configuración se vuelve a cambiar alguna vez. El <directive>ScriptAlias</directive> hace esto fácil mapeando una URL y designando CGI scripts al mismo tiempo. Si decide colocar sus scripts CGI en un directorio que ya es accesible desde la web, no use
    <directive>ScriptAlias</directive>. En su lugar, use <directive
    module="core" type="section">Directory</directive>, <directive
    module="core">SetHandler</directive>, y <directive
    module="core">Options</directive> como en:

    <highlight language="config">
&lt;Directory "/usr/local/apache2/htdocs/cgi-bin"&gt;
    SetHandler cgi-script
    Options ExecCGI
&lt;/Directory&gt;
    </highlight>

    Esto es necesario puesto que multiples <var>URL-paths</var> pueden mapear a la misma ubicación del sistema de ficheros, potencialmente saltándose el
    <directive>ScriptAlias</directive> y revelando el código fuente de los scripts CGI si no están restringidos por una sección 
    <directive module="core">Directory</directive>.
    </note>

    <p>Si se usa la directiva 
    <directive>ScriptAlias</directive> dentro de una sección
    <directive type="section" module="core">Location</directive>
    o <directive type="section" module="core">LocationMatch</directive>
    con el URL-path omitido, entonces el parámetro URL será interpretando usando
    <a href="../expr.html">sintaxis de expresión</a>.<br />
    Esta sintaxis está disponible en Apache 2.4.19 y versiones posteriores.</p>

    <highlight language="config">
&lt;Location "/cgi-bin"&gt;
    ScriptAlias "/web/cgi-bin/"
&lt;/Location&gt;
&lt;LocationMatch "/cgi-bin/errors/(?&lt;NUMBER&gt;[0-9]+)"&gt;
    ScriptAlias "/web/cgi-bin/errors/%{env:MATCH_NUMBER}.cgi"
&lt;/LocationMatch&gt;
    </highlight>

</usage>
<seealso><a href="../howto/cgi.html">Tutorial CGI</a></seealso>
</directivesynopsis>

<directivesynopsis>
<name>ScriptAliasMatch</name>
<description>Mapea una URL a una ubicación del sistema de ficheros usando 
una expresión regular y designa el destino como un script CGI</description>
<syntax>ScriptAliasMatch <var>regex</var>
<var>file-path</var>|<var>directory-path</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>Esta directiva es equivalente a 
    <directive module="mod_alias">ScriptAlias</directive>, pero hace uso de
    <glossary ref="regex">expresiones regulares</glossary>,
    en lugar de comparaciones simples de prefijo. La expresión regular facilitada se compara con el URL-path, y si coincide, el servidor sustituye cualquier coincidencia entre paréntesis con la cadena de caracteres facilitada y la usa como el nombre de fichero. Por ejemplo, para activar el estándar 
    <code>/cgi-bin</code>, uno podría usar:</p>

    <highlight language="config">
ScriptAliasMatch "^/cgi-bin(.*)" "/usr/local/apache/cgi-bin$1"
    </highlight>

    <p>En cuanto a AliasMatch, puede usar toda la capacidad que le permiten las
    <glossary ref="rexex">expresiones regulares</glossary>. 
    Por ejemplo, es posible construir un alias con comparación insensible
    a mayúsculas del URL-path:</p>

    <highlight language="config">
ScriptAliasMatch "(?i)^/cgi-bin(.*)" "/usr/local/apache/cgi-bin$1"
    </highlight>

    <p>Las consideraciones relacionadas con las diferencias entre
    <directive module="mod_alias">Alias</directive> y
    <directive module="mod_alias">AliasMatch</directive>
    también aplican a las diferencias entre
    <directive module="mod_alias">ScriptAlias</directive> y
    <directive module="mod_alias">ScriptAliasMatch</directive>.
    Vea <directive module="mod_alias">AliasMatch</directive> para más
    detalles.</p>

</usage>
</directivesynopsis>

</modulesynopsis>
