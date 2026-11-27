<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933180 -->
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

<modulesynopsis metafile="mod_proxy_html.xml.meta">

<name>mod_proxy_html</name>
<description>Reescribe los enlaces HTML para asegurar que sean direccionables
desde las redes de los clientes en un contexto de proxy.</description>
<status>Base</status>
<sourcefile>mod_proxy_html.c</sourcefile>
<identifier>proxy_html_module</identifier>
<compatibility>Versión 2.4 y posteriores</compatibility>

<summary>
<p>Este módulo proporciona un filtro de salida para reescribir enlaces HTML en una
situación de proxy, con el fin de asegurar que los enlaces funcionen para los usuarios
que están fuera del proxy. Cumple el mismo propósito que la directiva
<directive module="mod_proxy">ProxyPassReverse</directive> de Apache para las
cabeceras HTTP, y es un componente esencial de un proxy inverso.</p>

<p>Por ejemplo, si una empresa tiene un servidor de aplicaciones en
<code>appserver.example.com</code> que solo es visible desde dentro de
la red interna de la empresa, y un servidor web público
<code>www.example.com</code>, puede que quiera ofrecer una puerta de enlace al
servidor de aplicaciones en <code>http://www.example.com/appserver/</code>.
Cuando el servidor de aplicaciones enlaza consigo mismo, esos enlaces necesitan
reescribirse para que funcionen a través de la puerta de enlace. <module>mod_proxy_html</module> sirve para reescribir
<code>&lt;a href="http://appserver.example.com/foo/bar.html"&gt;foobar&lt;/a&gt;</code> como
<code>&lt;a href="http://www.example.com/appserver/foo/bar.html"&gt;foobar&lt;/a&gt;</code>
haciéndolo accesible desde fuera.</p>

<p>mod_proxy_html se desarrolló originalmente en Web&#222;ing, cuya
extensa <a href="http://apache.webthing.com/mod_proxy_html/"
>documentación</a> puede ser útil para los usuarios.</p>
</summary>

<directivesynopsis>
<name>ProxyHTMLMeta</name>
<description>Activa o desactiva el preanálisis adicional de metadatos en las
secciones <code>&lt;head&gt;</code> del HTML.</description>
<syntax>ProxyHTMLMeta On|Off</syntax>
<default>ProxyHTMLMeta Off</default>
<contextlist><context>server config</context>
<context>virtual host</context><context>directory</context>
</contextlist>
<compatibility>Versión 2.4 y posteriores; disponible como módulo de terceros
para versiones 2.x anteriores.</compatibility>

<usage>
    <p>Esto activa o desactiva el preanálisis de metadatos en las
    secciones <code>&lt;head&gt;</code> del HTML.</p>
    <p>Si no es necesario, desactivar ProxyHTMLMeta dará una pequeña
    mejora de rendimiento al saltarse este paso de análisis. Sin embargo,
    a veces es necesario para que la internacionalización funcione correctamente.</p>
    <p><directive>ProxyHTMLMeta</directive> tiene dos efectos. En primer lugar, y lo más importante,
    activa la detección de codificaciones de caracteres declaradas de la forma</p>
    <pre>&lt;meta http-equiv="Content-Type" content="text/html;charset=<var>foo</var>"&gt;</pre>
    <p>o, en el caso de un documento XHTML, una declaración XML.
    NO es necesario si el charset se declara en una cabecera HTTP real
    (lo cual siempre es preferible) del servidor de backend, ni si el
    documento está en <var>utf-8</var> (unicode) o un subconjunto como ASCII.
    También puede prescindir de esto cuando los documentos usan un valor
    por defecto declarado mediante <directive module="mod_xml2enc"
    >xml2EncDefault</directive>, pero eso implica el riesgo de propagar una
    declaración incorrecta. Un <directive module="mod_proxy_html">ProxyHTMLCharsetOut</directive>
    puede eliminar ese riesgo, pero probablemente suponga una sobrecarga de
    procesamiento mayor que activar ProxyHTMLMeta.</p>
    <p>El otro efecto de activar <directive>ProxyHTMLMeta</directive> es analizar todas
    las declaraciones <code>&lt;meta http-equiv=...&gt;</code> y convertirlas
    en cabeceras HTTP reales, en línea con el propósito original
    de esta forma del elemento HTML &lt;meta&gt;.</p>

    <note type="warning"><title>Advertencia</title>
      Debido a que ProxyHTMLMeta promueve a cabeceras HTTP <strong>todos</strong>
      los elementos <code>http-equiv</code>, es importante activarlo
      únicamente en los casos en los que confíe en el contenido HTML tanto como
      confía en el servidor de origen. Si el HTML está controlado por actores
      maliciosos, estos podrán inyectar cabeceras HTTP arbitrarias, posiblemente
      maliciosas, en las respuestas de su servidor.
    </note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyHTMLEnable</name>
<description>Activa o desactiva el filtro proxy_html.</description>
<syntax>ProxyHTMLEnable On|Off</syntax>
<default>ProxyHTMLEnable Off</default>
<contextlist><context>server config</context>
<context>virtual host</context><context>directory</context>
</contextlist>
<compatibility>Versión 2.4 y posteriores; disponible como módulo de terceros
para versiones 2.x anteriores.</compatibility>

<usage>
    <p>Un simple interruptor para activar o desactivar el filtro proxy_html.
    Si <module>mod_xml2enc</module> está cargado, también configurará
    automáticamente el soporte de internacionalización.</p>
    <p>Tenga en cuenta que el filtro proxy_html solo actuará sobre datos HTML
    (Content-Type text/html o application/xhtml+xml) y cuando los
    datos se envíen a través de un proxy. Puede anular esto (bajo su propio riesgo)
    estableciendo la variable de entorno <var>PROXY_HTML_FORCE</var>.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyHTMLURLMap</name>
<description>Define una regla para reescribir enlaces HTML</description>
<syntax>ProxyHTMLURLMap <var>from-pattern to-pattern [flags] [cond]</var></syntax>
<contextlist><context>server config</context>
<context>virtual host</context><context>directory</context>
</contextlist>
<compatibility>Versión 2.4 y posteriores; disponible como módulo de terceros
para versiones 2.x anteriores.</compatibility>

<usage>
<p>Esta es la directiva clave para reescribir enlaces HTML. Al analizar un documento,
cada vez que el destino de un enlace coincida con <var>from-pattern</var>, la parte
coincidente se reescribirá como <var>to-pattern</var>, modificada según las
marcas (flags) indicadas y según la directiva
<directive module="mod_proxy_html">ProxyHTMLExtended</directive>.
Solo se considerarán enlaces HTML los elementos especificados mediante
la directiva <directive module="mod_proxy_html">ProxyHTMLLinks</directive>.</p>

<p>El tercer argumento, opcional, puede definir cualquiera de las siguientes
<strong>Flags</strong> (marcas). Las marcas distinguen entre mayúsculas y minúsculas.</p>
<dl>
<dt>h</dt>
<dd><p>Ignora los enlaces HTML (los deja pasar sin cambios)</p></dd>
<dt>e</dt>
<dd><p>Ignora los eventos de scripting (los deja pasar sin cambios)</p></dd>
<dt>c</dt>
<dd><p>Deja pasar sin tocar las secciones de script y estilo incrustadas.</p></dd>

<dt>L</dt>
<dd><p>Última coincidencia (last-match). Si esta regla coincide, no se aplican
más reglas (tenga en cuenta que esto sucede automáticamente con los enlaces HTML).</p></dd>
<dt>l</dt>
<dd><p>Opuesto a L. Anula el comportamiento por defecto de un único cambio
con los enlaces HTML.</p></dd>
<dt>R</dt>
<dd><p>Usa coincidencia y sustitución con expresiones regulares. <code>from-pattern</code>
es una expresión regular, y <code>to-pattern</code> una cadena de sustitución que puede
basarse en dicha expresión regular. Se admite la memoria de la expresión regular: puede usar paréntesis ()
en <code>from-pattern</code> y recuperar las coincidencias con $1 a $9
en <code>to-pattern</code>.</p>

<p>Si no se establece R, se usará búsqueda y sustitución de cadena literal.
La lógica es de tipo <em>empieza-por</em> en los enlaces HTML, pero de tipo
<em>contiene</em> en los eventos de scripting y en las secciones de script y estilo incrustadas.
</p>
</dd>
<dt>x</dt>
<dd><p>Usa expresiones regulares extendidas POSIX. Solo se aplica con R.</p></dd>
<dt>i</dt>
<dd><p>Coincidencia sin distinguir mayúsculas y minúsculas. Solo se aplica con R.</p></dd>

<dt>n</dt>
<dd><p>Desactiva la memoria de la expresión regular (por velocidad). Solo se aplica con R.</p></dd>
<dt>s</dt>
<dd><p>Coincidencia de expresión regular por líneas. Solo se aplica con R.</p></dd>
<dt>^</dt>
<dd><p>Coincide solo al principio. Esto solo se aplica a la coincidencia de cadenas
(no a las expresiones regulares) y es irrelevante para los enlaces HTML.</p></dd>
<dt>$</dt>
<dd><p>Coincide solo al final. Esto solo se aplica a la coincidencia de cadenas
(no a las expresiones regulares) y es irrelevante para los enlaces HTML.</p></dd>
<dt>V</dt>
<dd><p>Interpola variables de entorno en <code>to-pattern</code>.
Una cadena de la forma <code>${varname|default}</code> se sustituirá por el
valor de la variable de entorno <code>varname</code>. Si no está establecida, se
sustituye por <code>default</code>. El <code>|default</code> es opcional.</p>
<p>NOTA: la interpolación solo se activará si
<directive module="mod_proxy_html">ProxyHTMLInterp</directive> está en <var>On</var>.</p>
</dd>

<dt>v</dt>
<dd><p>Interpola variables de entorno en <code>from-pattern</code>.
Los patrones admitidos son los mismos que arriba.</p>
<p>NOTA: la interpolación solo se activará si
<directive module="mod_proxy_html">ProxyHTMLInterp</directive> está en <var>On</var>.</p>
</dd>
</dl>

<p>El cuarto argumento, opcional, <strong>cond</strong>, define una condición
que se evaluará por cada petición, siempre que
<directive module="mod_proxy_html">ProxyHTMLInterp</directive> esté en <var>On</var>.
Si la condición se evalúa como FALSE, el mapa no se aplicará en esa petición.
Si se evalúa como TRUE, o si no se define ninguna condición, el mapa se aplica.</p>
<p>Un <strong>cond</strong> se evalúa mediante el <a href="../expr.html"
>analizador de expresiones</a>. Además, también se admite la sintaxis más sencilla
de las condiciones de mod_proxy_html 3.x para HTTPD 2.0 y 2.2.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyHTMLInterp</name>
<description>Activa la interpolación por petición de las reglas de
<directive>ProxyHTMLURLMap</directive>.</description>
<syntax>ProxyHTMLInterp On|Off</syntax>
<default>ProxyHTMLInterp Off</default>
<contextlist><context>server config</context>
<context>virtual host</context><context>directory</context>
</contextlist>
<compatibility>Versión 2.4 y posteriores; disponible como módulo de terceros
para versiones 2.x anteriores</compatibility>

<usage>
    <p>Esto activa la interpolación por petición en los patrones de origen y destino
    de <directive module="mod_proxy_html">ProxyHTMLURLMap</directive>.</p>
    <p>Si la interpolación no está activada, todas las reglas se precompilan al arrancar.
    Con la interpolación, deben recompilarse en cada petición, lo que
    implica una sobrecarga de procesamiento adicional. Por ello, debería
    activarse solo cuando sea necesario.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyHTMLDocType</name>
<description>Establece una declaración de tipo de documento HTML o XHTML.</description>
<syntax>ProxyHTMLDocType HTML|XHTML [Legacy]<br/><strong>O BIEN</strong>
<br/>ProxyHTMLDocType <var>fpi</var> [SGML|XML]</syntax>
<contextlist><context>server config</context>
<context>virtual host</context><context>directory</context>
</contextlist>
<compatibility>Versión 2.4 y posteriores; disponible como de terceros
para versiones 2.x anteriores</compatibility>

<usage>
<p>En la primera forma, los documentos se declararán como HTML 4.01 o XHTML 1.0
según la opción elegida. Esta opción también determina si se usa
sintaxis HTML o XHTML para la salida. Tenga en cuenta que el formato de los
documentos que proceden del servidor de origen es indiferente: el analizador se
encargará de ello automáticamente. Si el segundo argumento opcional se establece en
<code>Legacy</code>, los documentos se declararán "Transitional", una opción que puede
ser necesaria si está haciendo de proxy de contenido anterior a 1998 o trabaja con
herramientas de autoría/publicación defectuosas.</p>
<p>En la segunda forma, insertará su propio FPI. El segundo argumento opcional
determina si se usará sintaxis SGML/HTML o XML/XHTML.</p>
<p>El valor por defecto se cambia para omitir cualquier FPI,
partiendo de la base de que no tener FPI es mejor que tener uno erróneo. Si su
backend genera HTML o XHTML correcto, establézcalo en consecuencia.</p>
<p>Si se usa la primera forma, mod_proxy_html
también limpiará el HTML según el estándar especificado. No puede
corregir todos los errores, pero eliminará elementos y atributos
espurios. También puede, opcionalmente, registrar otros errores con <directive
module="core">LogLevel</directive> Debug.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyHTMLFixups</name>
<description>Correcciones para errores sencillos de HTML.</description>
<syntax>ProxyHTMLFixups [lowercase] [dospath] [reset]</syntax>
<default>ProxyHTMLFixups none</default>
<contextlist><context>server config</context>
<context>virtual host</context><context>directory</context>
</contextlist>
<compatibility>Versión 2.4 y posteriores; disponible como de terceros
para versiones 2.x anteriores</compatibility>
<usage>
<p>Esta directiva admite de uno a tres argumentos, como sigue:</p>
<ul>
<li><code>lowercase</code> Las URLs se reescriben en minúsculas</li>
<li><code>dospath</code> Las barras invertidas en las URLs se reescriben como barras normales.</li>
<li><code>reset</code> Desactiva cualquier opción establecida en un nivel superior de la configuración.</li>
</ul>
<p>Tenga cuidado al usarlas. Las correcciones arreglarán ciertos errores de autoría,
pero también corren el riesgo de corregir erróneamente enlaces que ya eran correctos.
Úselas solo si sabe que tiene un servidor de origen defectuoso.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyHTMLExtended</name>
<description>Determina si se corrigen los enlaces en scripts, hojas de estilo
y eventos de scripting incrustados.</description>
<syntax>ProxyHTMLExtended On|Off</syntax>
<default>ProxyHTMLExtended Off</default>
<contextlist><context>server config</context>
<context>virtual host</context><context>directory</context>
</contextlist>
<compatibility>Versión 2.4 y posteriores; disponible como de terceros
para versiones 2.x anteriores</compatibility>
<usage>
<p>Si se establece en <code>Off</code>, los enlaces HTML se reescriben según las
directivas <directive module="mod_proxy_html">ProxyHTMLURLMap</directive>, pero los enlaces que aparecen
en Javascript y CSS se ignoran.</p>
<p>Si se establece en <code>On</code>, todos los eventos de scripting (según determine
<directive module="mod_proxy_html">ProxyHTMLEvents</directive>) y los scripts u hojas
de estilo incrustados también se procesan mediante las reglas de <directive module="mod_proxy_html">ProxyHTMLURLMap</directive>,
según las marcas establecidas para cada regla. Dado que esto requiere más
análisis, el rendimiento será mejor si solo lo activa cuando sea estrictamente necesario.
</p><p>
También deberá tener cuidado con los patrones usados, ya que el analizador no
sabe qué es una URL dentro de un script o una hoja de estilo incrustados.
En particular, es probable que la coincidencia extendida de <code>/</code> provoque
coincidencias falsas.
</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyHTMLStripComments</name>
<description>Determina si se eliminan los comentarios HTML.</description>
<syntax>ProxyHTMLStripComments On|Off</syntax>
<default>ProxyHTMLStripComments Off</default>
<contextlist><context>server config</context>
<context>virtual host</context><context>directory</context>
</contextlist>
<compatibility>Versión 2.4 y posteriores; disponible como de terceros
para versiones 2.x anteriores</compatibility>
<usage>
<p>Esta directiva hace que mod_proxy_html elimine los comentarios HTML.
Tenga en cuenta que esto también eliminará cualquier script o estilo incrustado en
comentarios (una práctica dudosa introducida en 1995/6 con Netscape 2 en
beneficio de navegadores entonces más antiguos, pero que todavía se usa hoy).
También puede interferir con procesadores basados en comentarios, como SSI o ESI:
¡asegúrese de ejecutar cualquiera de ellos <em>antes</em> de mod_proxy_html en la
cadena de filtros si va a eliminar comentarios!</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyHTMLBufSize</name>
<description>Establece el incremento del tamaño del búfer para almacenar
scripts y hojas de estilo incrustados.</description>
<syntax>ProxyHTMLBufSize <var>bytes</var></syntax>
<default>ProxyHTMLBufSize 8192</default>
<contextlist><context>server config</context>
<context>virtual host</context><context>directory</context>
</contextlist>
<compatibility>Versión 2.4 y posteriores; disponible como de terceros
para versiones 2.x anteriores</compatibility>
<usage>
<p>Para analizar contenido no HTML (hojas de estilo y scripts) incrustado
en documentos HTML, <module>mod_proxy_html</module>
tiene que leer el script o la hoja de estilo completos en un búfer. Este búfer se
ampliará según sea necesario para contener el script o la hoja de estilo más grande de una página,
en incrementos de <var>bytes</var> según establezca esta directiva.</p>
<p>El valor por defecto es 8192, y funcionará bien para casi todas las páginas. Sin embargo,
si sabe que está haciendo de proxy de páginas con hojas de estilo y/o
scripts mayores de 8K (es decir, por cada script o hoja de estilo individual,
no en total), será más eficiente establecer un tamaño de búfer
mayor y evitar la necesidad de redimensionarlo dinámicamente durante una petición.
</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyHTMLEvents</name>
<description>Especifica atributos que se deben tratar como eventos de scripting.</description>
<syntax>ProxyHTMLEvents <var>attribute [attribute ...]</var></syntax>
<contextlist><context>server config</context>
<context>virtual host</context><context>directory</context>
</contextlist>
<compatibility>Versión 2.4 y posteriores; disponible como de terceros
para versiones 2.x anteriores</compatibility>
<usage>
<p>Especifica uno o más atributos que se deben tratar como eventos de scripting y
a los que se aplican las reglas de <directive module="mod_proxy_html">ProxyHTMLURLMap</directive> donde estén activadas.
Puede especificar cualquier número de atributos en una o más
directivas <directive>ProxyHTMLEvents</directive>.</p>
<note><title>Requiere ProxyHTMLExtended</title>
<p>Los eventos de scripting solo se procesan cuando
<directive module="mod_proxy_html">ProxyHTMLExtended</directive> está establecido en
<var>On</var>. Sin ello, los atributos de evento se dejan pasar sin modificar,
incluso si se indican en <directive>ProxyHTMLEvents</directive>.</p>
</note>
<p>Normalmente, esto se establece globalmente. Si establece <directive>ProxyHTMLEvents</directive> en más de
un ámbito de modo que uno anule al otro, deberá especificar un conjunto
completo en cada uno de esos ámbitos.</p>
<p>En <var>proxy-html.conf</var> se proporciona una configuración por defecto
que define los eventos estándar de HTML 4 y XHTML 1.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyHTMLLinks</name>
<description>Especifica elementos HTML que tienen atributos de URL que deben reescribirse.</description>
<syntax>ProxyHTMLLinks <var>element attribute [attribute2 ...]</var></syntax>
<contextlist><context>server config</context>
<context>virtual host</context><context>directory</context>
</contextlist>
<compatibility>Versión 2.4 y posteriores; disponible como de terceros
para versiones 2.x anteriores</compatibility>
<usage>
<p>Especifica elementos que tienen atributos de URL que deben reescribirse
usando las reglas estándar de <directive module="mod_proxy_html">ProxyHTMLURLMap</directive>.
Necesitará una directiva <directive>ProxyHTMLLinks</directive> por cada elemento,
pero puede tener cualquier número de atributos.</p>
<p>Normalmente, esto se establece globalmente. Si establece <directive>ProxyHTMLLinks</directive> en más de
un ámbito de modo que uno anule al otro, deberá especificar un conjunto
completo en cada uno de esos ámbitos.</p>
<p>En <var>proxy-html.conf</var> se proporciona una configuración por defecto
que define los enlaces HTML para HTML 4 y XHTML 1 estándar.</p>
<example>
<title>Ejemplos de proxy-html.conf</title>
<highlight language="config">
ProxyHTMLLinks  a          href
ProxyHTMLLinks  area       href
ProxyHTMLLinks  link       href
ProxyHTMLLinks  img        src longdesc usemap
ProxyHTMLLinks  object     classid codebase data usemap
ProxyHTMLLinks  q          cite
ProxyHTMLLinks  blockquote cite
ProxyHTMLLinks  ins        cite
ProxyHTMLLinks  del        cite
ProxyHTMLLinks  form       action
ProxyHTMLLinks  input      src usemap
ProxyHTMLLinks  head       profile
ProxyHTMLLinks  base       href
ProxyHTMLLinks  script     src for
</highlight>
</example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyHTMLCharsetOut</name>
<description>Especifica un juego de caracteres para la salida de mod_proxy_html.</description>
<syntax>ProxyHTMLCharsetOut <var>Charset | *</var></syntax>
<default>ProxyHTMLCharsetOut UTF-8</default>
<contextlist><context>server config</context>
<context>virtual host</context><context>directory</context>
</contextlist>
<compatibility>Versión 2.4 y posteriores; disponible como de terceros
para versiones 2.x anteriores</compatibility>
<usage>
<p>Esto selecciona una codificación para la salida de mod_proxy_html. Normalmente no
debería usarse, ya que cualquier cambio respecto al valor por defecto <code>UTF-8</code>
(Unicode, el que usa internamente libxml2) impondrá una sobrecarga de
procesamiento adicional. El token especial <code>ProxyHTMLCharsetOut *</code>
generará la salida usando la misma codificación que la de la entrada.</p>
<p>Tenga en cuenta que esto depende de que <module>mod_xml2enc</module> esté cargado.</p>
</usage>
</directivesynopsis>



</modulesynopsis>
