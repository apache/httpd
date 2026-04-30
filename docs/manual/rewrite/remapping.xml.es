<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE manualpage SYSTEM "../style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933068:1933611 (outdated) -->

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

<manualpage metafile="remapping.xml.meta">
  <parentdocument href="./">Rewrite</parentdocument>

<title>Redirección y Remapeo con mod_rewrite</title>

<summary>

<p>Este documento complementa la <module>mod_rewrite</module>
<a href="../mod/mod_rewrite.html">documentación de referencia</a>. Describe
cómo puede usar <module>mod_rewrite</module> para redirigir y remapear
solicitudes. Esto incluye muchos ejemplos de usos comunes de <module>mod_rewrite</module>,
incluyendo descripciones detalladas de cómo funciona cada uno.</p>

<note type="warning">Tenga en cuenta que muchos de estos ejemplos no funcionarán sin cambios en su
configuración particular del servidor, por lo que es importante que los
entienda, en lugar de simplemente copiar y pegar los ejemplos en su
configuración.</note>

</summary>
<seealso><a href="../mod/mod_rewrite.html">Documentación del módulo</a></seealso>
<seealso><a href="intro.html">Introducción a mod_rewrite</a></seealso>
<!--<seealso><a href="remapping.html">Redirección y remapeo</a></seealso>-->
<seealso><a href="access.html">Control de acceso</a></seealso>
<seealso><a href="vhosts.html">Hosts virtuales</a></seealso>
<seealso><a href="proxy.html">Proxy</a></seealso>
<seealso><a href="rewritemap.html">Uso de RewriteMap</a></seealso>
<seealso><a href="advanced.html">Técnicas avanzadas</a></seealso>
<seealso><a href="avoid.html">Cuándo no usar mod_rewrite</a></seealso>

<section id="old-to-new">

  <title>De Antiguo a Nuevo (interno)</title>

  <dl>
    <dt>Descripción:</dt>

    <dd>
      <p>Supongamos que hemos renombrado recientemente la página
      <code>foo.html</code> a <code>bar.html</code> y ahora queremos
      proporcionar la antigua URL por compatibilidad hacia atrás. Sin embargo,
      queremos que los usuarios de la antigua URL ni siquiera se den cuenta de que
      la página fue renombrada - es decir, no queremos que la dirección
      cambie en su navegador.</p>
    </dd>

    <dt>Solución:</dt>

    <dd>
      <p>Reescribimos la antigua URL a la nueva internamente mediante la
      siguiente regla:</p>

<highlight language="config">
RewriteEngine  on
RewriteRule    "^<strong>/foo</strong>\.html$"  "<strong>/bar</strong>.html" [PT]
</highlight>
    </dd>
  </dl>

</section>

<section id="old-to-new-extern">

  <title>Reescritura de Antiguo a Nuevo (externo)</title>

  <dl>
    <dt>Descripción:</dt>

    <dd>
      <p>Supongamos de nuevo que hemos renombrado recientemente la página
      <code>foo.html</code> a <code>bar.html</code> y ahora queremos
      proporcionar la antigua URL por compatibilidad hacia atrás. Pero esta
      vez queremos que los usuarios de la antigua URL reciban una indicación de
      la nueva, es decir, que el campo de Ubicación de su navegador también
      cambie.</p>
    </dd>

    <dt>Solución:</dt>

    <dd>
      <p>Forzamos una redirección HTTP a la nueva URL que lleva a un
      cambio del navegador y por lo tanto de la vista del usuario:</p>

<highlight language="config">
RewriteEngine  on
RewriteRule    "^<strong>/foo</strong>\.html$"  "<strong>bar</strong>.html"  [<strong>R</strong>]
</highlight>
</dd>

<dt>Discusión</dt>

    <dd>
    <p>En este ejemplo, a diferencia del ejemplo <a
    href="#old-to-new-intern">interno</a> anterior, podemos simplemente
    usar la directiva Redirect. <module>mod_rewrite</module> se usó en ese ejemplo
    anterior para ocultar la redirección del cliente:</p>

    <highlight language="config">
Redirect "/foo.html" "/bar.html"
    </highlight>

    </dd>
  </dl>

</section>

<section id="movehomedirs">

  <title>Recurso Movido a Otro Servidor</title>

  <dl>
    <dt>Descripción:</dt>

    <dd>
      <p>Si un recurso se ha movido a otro servidor, puede desear que
      las URLs continúen funcionando por un tiempo en el antiguo servidor mientras
      la gente actualiza sus marcadores.</p>
    </dd>

    <dt>Solución:</dt>

    <dd>
      <p>Puede usar <module>mod_rewrite</module> para redirigir estas URLs
      al nuevo servidor, pero también podría considerar usar la directiva Redirect
      o RedirectMatch.</p>

<highlight language="config">
#With mod_rewrite
RewriteEngine on
RewriteRule   "^/docs/(.+)"  "http://new.example.com/docs/$1"  [R,L]
</highlight>

<highlight language="config">
#With RedirectMatch
RedirectMatch "^/docs/(.*)" "http://new.example.com/docs/$1"
</highlight>

<highlight language="config">
#With Redirect
Redirect "/docs/" "http://new.example.com/docs/"
</highlight>
    </dd>
  </dl>

</section>

<section id="static-to-dynamic">

  <title>De Estático a Dinámico</title>

  <dl>
    <dt>Descripción:</dt>

    <dd>
      <p>¿Cómo podemos transformar una página estática
      <code>foo.html</code> en una variante dinámica
      <code>foo.cgi</code> de manera transparente, es decir, sin que
      el navegador/usuario lo note.</p>
    </dd>

    <dt>Solución:</dt>

    <dd>
      <p>Simplemente reescribimos la URL al script CGI y forzamos el
      manejador a ser <strong>cgi-script</strong> para que se
      ejecute como un programa CGI.
      De esta manera, una solicitud a <code>/~quux/foo.html</code>
      internamente lleva a la invocación de
      <code>/~quux/foo.cgi</code>.</p>

<highlight language="config">
RewriteEngine  on
RewriteBase    "/~quux/"
RewriteRule    "^foo\.html$"  "foo.cgi"  [H=<strong>cgi-script</strong>]
</highlight>
    </dd>
  </dl>

</section>

<section id="backward-compatibility">

  <title>Compatibilidad hacia atrás para cambio de extensión de archivo</title>

  <dl>
    <dt>Descripción:</dt>

    <dd>
      <p>¿Cómo podemos hacer URLs retrocompatibles (aún
      existentes virtualmente) después de migrar <code>document.YYYY</code>
      a <code>document.XXXX</code>, por ejemplo, después de traducir un
      grupo de archivos <code>.html</code> a <code>.php</code>?</p>
    </dd>

    <dt>Solución:</dt>

    <dd>
      <p>La URL se reescribe de la antigua extensión a la nueva
      solo si el archivo destino con la nueva extensión existe
      y el archivo original con la antigua extensión no existe.
      De lo contrario, la URL se deja sin cambios.</p>

<highlight language="config">
#   backward compatibility ruleset for
#   rewriting document.html to document.php
#   when and only when document.php exists
&lt;Directory "/var/www/htdocs"&gt;
    RewriteEngine on
    RewriteBase   "/var/www/htdocs"

    RewriteCond   "$1.php"           -f
    RewriteCond   "$1.html"          !-f
    RewriteRule   "^(.*).html$"      "$1.php"
&lt;/Directory&gt;
</highlight>
    </dd>

    <dt>Discusión</dt>
    <dd>
    <p>Este ejemplo usa una característica a menudo pasada por alto de <module>mod_rewrite</module>,
    aprovechando el orden de ejecución del conjunto de reglas. En
    particular, <module>mod_rewrite</module> evalúa el lado izquierdo de la
    RewriteRule antes de evaluar las directivas RewriteCond.
    En consecuencia, $1 ya está definido para el momento en que las directivas
    RewriteCond se evalúan. Esto nos permite probar la existencia
    del archivo original (<code>document.html</code>) y destino
    (<code>document.php</code>) usando el mismo nombre de archivo base.</p>

    <p>Este conjunto de reglas está diseñado para usarse en un contexto per-directorio (en un
    bloque &lt;Directory&gt; o en un archivo .htaccess), de modo que las
    verificaciones <code>-f</code> busquen en la ruta de directorio correcta.
    Puede necesitar establecer una directiva <directive
    module="mod_rewrite">RewriteBase</directive> para especificar la
    base de directorio en la que está trabajando.</p>
    </dd>
  </dl>

</section>

<section id="canonicalhost">

<title>Nombres de Host Canónicos</title>

      <dl>
        <dt>Descripción:</dt>

        <dd>El objetivo de esta regla es forzar el uso de un nombre de
        host particular, en preferencia a otros nombres de host que pueden usarse para
        alcanzar el mismo sitio. Por ejemplo, si desea forzar el uso
        de <strong>www.example.com</strong> en lugar de
        <strong>example.com</strong>, podría usar una variante de la
        siguiente receta.</dd>

        <dt>Solución:</dt>

        <dd>

<p>La mejor manera de resolver esto no involucra <module>mod_rewrite</module> en absoluto,
sino que usa la directiva <directive module="mod_alias">Redirect</directive>
colocada en un host virtual para el o los nombres de host no canónicos.</p>

<highlight language="config">
&lt;VirtualHost *:80&gt;
  ServerName undesired.example.com
  ServerAlias example.com notthis.example.com

  Redirect "/" "http://www.example.com/"
&lt;/VirtualHost&gt;

&lt;VirtualHost *:80&gt;
  ServerName www.example.com
&lt;/VirtualHost&gt;
</highlight>

<p>Alternativamente puede lograr esto usando la
directiva <directive module="core" type="section">If</directive>:
(<strong>2.4 y posterior</strong>)</p>

<highlight language="config">
&lt;If "%{HTTP_HOST} != 'www.example.com'"&gt;
    Redirect "/" "http://www.example.com/"
&lt;/If&gt;
</highlight>

<p>O, por ejemplo, para redirigir una porción de su sitio a HTTPS, podría
hacer lo siguiente:</p>

<highlight language="config">
&lt;If "%{SERVER_PROTOCOL} != 'HTTPS'"&gt;
    Redirect "/admin/" "https://www.example.com/admin/"
&lt;/If&gt;
</highlight>

<p>Si, por cualquier razón, aún desea usar <module>mod_rewrite</module>
- si, por ejemplo, necesita que esto funcione con un conjunto más grande de RewriteRules -
podría usar una de las recetas siguientes.</p>

<p>Para sitios ejecutándose en un puerto distinto al 80:</p>
<highlight language="config">
RewriteCond "%{HTTP_HOST}"   "!^www\.example\.com" [NC]
RewriteCond "%{HTTP_HOST}"   "!^$"
RewriteCond "%{SERVER_PORT}" "!^80$"
RewriteRule "^/?(.*)"        "http://www.example.com:%{SERVER_PORT}/$1" [L,R,NE]
</highlight>

<p>Y para un sitio ejecutándose en el puerto 80</p>
<highlight language="config">
RewriteCond "%{HTTP_HOST}"   "!^www\.example\.com"       [NC]
RewriteCond "%{HTTP_HOST}"   "!^$"
RewriteRule "^/?(.*)"        "http://www.example.com/$1" [L,R,NE]
</highlight>

        <p>
        Si quisiera hacer esto genéricamente para todos los nombres de dominio - es
        decir, si quiere redirigir <strong>example.com</strong> a
        <strong>www.example.com</strong> para todos los valores posibles de
        <strong>example.com</strong>, podría usar la siguiente
        receta:</p>

<highlight language="config">
RewriteCond "%{HTTP_HOST}" "!^www\."                    [NC]
RewriteCond "%{HTTP_HOST}" "!^$"
RewriteRule "^/?(.*)"      "http://www.%{HTTP_HOST}/$1" [L,R,NE]
</highlight>

    <p>Estos conjuntos de reglas funcionarán tanto en su archivo de configuración principal
    del servidor, como en un archivo <code>.htaccess</code> colocado en el <directive
    module="core">DocumentRoot</directive> del servidor.</p>
        </dd>
      </dl>

</section>

<section id="multipledirs">

  <title>Búsqueda de páginas en más de un directorio</title>

  <dl>
    <dt>Descripción:</dt>

    <dd>
      <p>Un recurso particular podría existir en uno de varios lugares, y
      queremos buscar en esos lugares el recurso cuando se
      solicita. Quizás hemos reorganizado recientemente nuestra estructura de
      directorios, dividiendo el contenido en varias ubicaciones.</p>
    </dd>

    <dt>Solución:</dt>

    <dd>
      <p>El siguiente conjunto de reglas busca en dos directorios para encontrar el
      recurso, y, si no lo encuentra en ninguno de los dos, intentará
      simplemente servirlo desde la ubicación solicitada.</p>

<highlight language="config">
RewriteEngine on

#   first try to find it in dir1/...
#   ...and if found stop and be happy:
RewriteCond         "%{DOCUMENT_ROOT}/<strong>dir1</strong>/%{REQUEST_URI}"  -f
RewriteRule "^(.+)" "%{DOCUMENT_ROOT}/<strong>dir1</strong>/$1"  [L]

#   second try to find it in dir2/...
#   ...and if found stop and be happy:
RewriteCond         "%{DOCUMENT_ROOT}/<strong>dir2</strong>/%{REQUEST_URI}"  -f
RewriteRule "^(.+)" "%{DOCUMENT_ROOT}/<strong>dir2</strong>/$1"  [L]

#   else go on for other Alias or ScriptAlias directives,
#   etc.
RewriteRule "^"     "-"                                          [PT]
</highlight>
    </dd>
  </dl>

</section>

<section id="archive-access-multiplexer">

  <title>Redirección a Servidores Distribuidos Geográficamente</title>

  <dl>
    <dt>Descripción:</dt>

    <dd>
    <p>Tenemos numerosos espejos de nuestro sitio web, y queremos redirigir
    a la gente al que está ubicado en el país donde se
    encuentran.</p>
    </dd>

    <dt>Solución:</dt>

    <dd>
    <p>Mirando el nombre de host del cliente solicitante, determinamos
    de qué país provienen. Si no podemos hacer una búsqueda de su
    dirección IP, recurrimos a un servidor predeterminado.</p>
    <p>Usaremos una directiva <directive module="mod_rewrite">RewriteMap</directive>
    para construir una lista de servidores que deseamos usar.</p>

<highlight language="config">
HostnameLookups on
RewriteEngine on
RewriteMap    multiplex         "txt:/path/to/map.mirrors"
RewriteCond  "%{REMOTE_HOST}"   "([a-z]+)$"                [NC]
RewriteRule  "^/(.*)$"          "${multiplex:<strong>%1</strong>|http://www.example.com/}$1"  [R,L]
</highlight>

<example>
##  map.mirrors -- Mapa de Multiplexación<br />
<br />
de        http://www.example.de/<br />
uk        http://www.example.uk/<br />
com       http://www.example.com/<br />
##EOF##
</example>
    </dd>

    <dt>Discusión</dt>
    <dd>
    <note type="warning">Este conjunto de reglas depende de que
    <directive module="core">HostNameLookups</directive>
    esté configurado como <code>on</code>, lo que puede ser
    un impacto significativo en el rendimiento.</note>

    <p>La directiva <directive module="mod_rewrite">RewriteCond</directive>
    captura la última parte del nombre de host del
    cliente solicitante - el código de país - y la siguiente RewriteRule
    usa ese valor para buscar el host espejo apropiado en el archivo
    de mapa.</p>
    </dd>
  </dl>

</section>

<section id="canonicalurl">

<title>URLs Canónicas</title>

<dl>
 <dt>Descripción:</dt>

   <dd>
     <p>En algunos servidores web hay más de una URL para un
     recurso. Generalmente hay URLs canónicas (que son las que realmente
     se usan y distribuyen) y aquellas que son solo
     atajos, internas, etc. Independientemente de qué URL
     proporcionó el usuario con la solicitud, finalmente debería ver la
     canónica en la barra de direcciones de su navegador.</p>
   </dd>

   <dt>Solución:</dt>

     <dd>
       <p>Hacemos una redirección HTTP externa para todas las
       URLs no canónicas para corregirlas en la vista de ubicación del navegador y
       para todas las solicitudes posteriores. En el conjunto de reglas de ejemplo
       reemplazamos <code>/puppies</code> y <code>/canines</code>
       por el canónico <code>/dogs</code>.</p>

<highlight language="config">
RewriteRule   "^/(puppies|canines)/(.*)"    "/dogs/$2"  [R]
</highlight>
        </dd>

     <dt>Discusión:</dt>
     <dd>
     Esto realmente debería lograrse con directivas Redirect o RedirectMatch:

     <highlight language="config">
RedirectMatch "^/(puppies|canines)/(.*)" "/dogs/$2"
     </highlight>
     </dd>
      </dl>

</section>

<section id="moveddocroot">

  <title><code>DocumentRoot</code> Movido</title>

  <dl>
    <dt>Descripción:</dt>

    <dd>
<p>Generalmente el <directive module="core">DocumentRoot</directive>
del servidor web se relaciona directamente con la URL "<code>/</code>".
Pero a menudo estos datos no son realmente de máxima prioridad. Por ejemplo,
puede desear que los visitantes, al entrar por primera vez a un sitio, vayan a un
subdirectorio particular <code>/about/</code>. Esto puede lograrse
usando el siguiente conjunto de reglas:</p>
</dd>

    <dt>Solución:</dt>

    <dd>
      <p>Redirigimos la URL <code>/</code> a
      <code>/about/</code>:
      </p>

<highlight language="config">
RewriteEngine on
RewriteRule   "^/$"  "/about/"  [<strong>R</strong>]
</highlight>

<p>Tenga en cuenta que esto también puede manejarse usando la directiva <directive
module="mod_alias">RedirectMatch</directive>:</p>

<highlight language="config">
RedirectMatch "^/$" "http://example.com/about/"
</highlight>

<p>Tenga en cuenta también que el ejemplo solo reescribe la URL raíz. Es decir, reescribe
una solicitud para <code>http://example.com/</code>, pero no una
solicitud para <code>http://example.com/page.html</code>. Si de hecho ha
cambiado la raíz de documentos - es decir, si <strong>todo</strong> su
contenido está en ese subdirectorio, es muy preferible
simplemente cambiar su directiva <directive module="core">DocumentRoot</directive>,
o mover todo el contenido un directorio arriba,
en lugar de reescribir URLs.</p>
</dd>
</dl>

</section>

<section id="fallback-resource">
<title>Recurso de Respaldo</title>

<dl>
<dt>Descripción:</dt>
<dd>Desea que un solo recurso (digamos, un cierto archivo, como index.php) maneje
todas las solicitudes que lleguen a un directorio particular, excepto aquellas
que deberían ir a un recurso existente como una imagen, o un archivo css.</dd>

<dt>Solución:</dt>
<dd>
<p>A partir de la versión 2.2.16, debería usar la directiva <directive
module="mod_dir">FallbackResource</directive> para esto:</p>

<highlight language="config">
&lt;Directory "/var/www/my_blog"&gt;
  FallbackResource index.php
&lt;/Directory&gt;
</highlight>

<p>Sin embargo, en versiones anteriores de Apache, o si sus necesidades son más
complicadas que esto, puede usar una variación del siguiente conjunto de
reescritura para lograr lo mismo:</p>

<highlight language="config">
&lt;Directory "/var/www/my_blog"&gt;
  RewriteBase "/my_blog"

  RewriteCond "/var/www/my_blog/%{REQUEST_FILENAME}" !-f
  RewriteCond "/var/www/my_blog/%{REQUEST_FILENAME}" !-d
  RewriteRule "^"                                    "index.php" [PT]
&lt;/Directory&gt;
</highlight>

<p>Si, por otro lado, desea pasar la URI solicitada como un argumento de
cadena de consulta a index.php, puede reemplazar esa RewriteRule con:</p>

<highlight language="config">
RewriteRule "(.*)" "index.php?$1" [PT,QSA]
</highlight>

<p>Tenga en cuenta que estos conjuntos de reglas pueden usarse en un archivo <code>.htaccess</code>,
así como en un bloque &lt;Directory&gt;.</p>

</dd>

</dl>

</section>

<section id="rewrite-query">
<title>Reescribir cadena de consulta</title>

<dl>
<dt>Descripción:</dt>
<dd>Desea capturar un valor particular de una cadena de consulta
y reemplazarlo o incorporarlo en otro componente
de la URL.</dd>

<dt>Soluciones:</dt>
<dd>
<p>Muchas de las soluciones en esta sección usarán la misma condición,
que deja el valor coincidente en la referencia inversa %2. %1 es el inicio
de la cadena de consulta (hasta la clave de interés), y %3 es el resto. Esta
condición es un poco compleja por flexibilidad y para evitar doble '&amp;&amp;' en las
sustituciones.</p>
<ul>
  <li>Esta solución elimina la clave y valor coincidentes:

<highlight language="config">
# Remove mykey=???
RewriteCond "%{QUERY_STRING}" "(.*(?:^|&amp;))mykey=([^&amp;]*)&amp;?(.*)&amp;?$"
RewriteRule "(.*)"            "$1?%1%3"
</highlight>
  </li>

  <li>Esta solución usa el valor capturado en la sustitución de URL,
  descartando el resto de la consulta original añadiendo un '?':

<highlight language="config">
# Copy from query string to PATH_INFO
RewriteCond "%{QUERY_STRING}" "(.*(?:^|&amp;))mykey=([^&amp;]*)&amp;?(.*)&amp;?$"
RewriteRule "(.*)"            "$1/products/%2/?" [PT]
</highlight>
  </li>

  <li>Esta solución verifica el valor capturado en una condición posterior:

<highlight language="config">
# Capture the value of mykey in the query string
RewriteCond "%{QUERY_STRING}" "(.*(?:^|&amp;))mykey=([^&amp;]*)&amp;?(.*)&amp;?$"
RewriteCond "%2"              !=not-so-secret-value
RewriteRule "(.*)"            "-" [F]
</highlight>
  </li>

  <li>Esta solución muestra lo inverso de las anteriores, copiando
      componentes de ruta (quizás PATH_INFO) de la URL a la cadena de consulta.
<highlight language="config">
# The desired URL might be /products/kitchen-sink, and the script expects
# /path?products=kitchen-sink.
RewriteRule "^/?path/([^/]+)/([^/]+)" "/path?$1=$2" [PT]
</highlight>
  </li>
</ul>

</dd>

</dl>
</section>


</manualpage>
