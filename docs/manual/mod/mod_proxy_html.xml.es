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
</summary>

<section id="intro"><title>Introducción</title>
<p>mod_proxy_html fue originalmente un módulo de terceros para Apache HTTPD
2.0.x y versiones posteriores. Se donó a la ASF en 2011 junto con
<module>mod_xml2enc</module> (vea <a href="#i18n">Internacionalización</a>)
y es un módulo estándar en HTTPD 2.4 y en las versiones de desarrollo.</p>
</section>
<section id="custom"><title>Análisis de HTML personalizado</title>
<p>Internamente, mod_proxy_html usa el módulo HTMLParser de la
biblioteca de terceros <a href="http://xmlsoft.org/">libxml2</a>.
A diferencia de otros analizadores de libxml2, HTMLParser trata el HTML sin
exigir que sea XML bien formado. En particular, entiende
las etiquetas implícitas, como un &lt;/p&gt; de cierre, y las inserta
en el flujo de eventos SAX que usa mod_proxy_html. También tiene
conocimiento explícito de los estándares W3C HTML 4 y XHTML 1, y puede
corregir ciertos errores en ellos.</p>
<p>mod_proxy_html ofrece una serie de opciones para controlar el análisis de HTML.
La corrección de errores puede activarse (según el estándar HTML que elija)
o desactivarse mediante <directive>ProxyHTMLDocType</directive>.
Y, atendiendo a una demanda habitual, puede configurarse
para tratar elementos y atributos no estándar como enlaces que puedan
necesitar reescritura, y para reescribir enlaces en contenido no HTML incrustado
(hojas de estilo y scripts). Tenga en cuenta que no es adecuado para
hojas de estilo o scripts externos: para esos casos debería usar otro analizador, como
<module>mod_substitute</module> o <module>mod_sed</module>.
Las principales directivas de personalización son <directive>ProxyHTMLLinks</directive>
y <directive>ProxyHTMLEvents</directive>. Por defecto, estas se establecen en el
archivo de configuración <var>proxy-html.conf</var>, que también contiene
comentarios para ayudarle a personalizar su analizador si lo necesita.</p>
<note>Por razones históricas, configurar mod_proxy_html para reescribir
URLs en eventos de scripting no reescribe por defecto las URLs en hojas de estilo.
Esto puede cambiarse descomentando la línea correspondiente en
<var>proxy-html.conf</var>, tal y como se documenta allí.</note>

</section>
<section id="i18n"><title>Internacionalización</title>
<p>Internamente, mod_proxy_html usa un analizador de HTML inteligente de la
biblioteca de terceros <a href="http://xmlsoft.org/">libxml2</a>.
El analizador usa Unicode (utf-8) internamente. Esto convierte en una
tarea algo compleja el manejo de otras codificaciones necesarias para procesar
muchos sitios web en idiomas distintos del inglés. Si esto no se gestiona correctamente,
los sitios web que muestran caracteres no ASCII en codificaciones distintas de
utf-8 (Unicode) se mostrarán incorrectamente.</p>
<p>Desde la primera versión en 2003 hasta la donación a Apache en 2011,
el soporte de internacionalización (i18n) evolucionó desde casi nada hasta un
marco sofisticado capaz de aplicar reglas de HTTP, HTML y XML
para detectar la codificación de un documento y gestionarla correctamente. Sin embargo,
este procesamiento era común a mod_proxy_html y a otros módulos que usan
libxml2, así que tenía sentido moverlo a un módulo independiente en lugar de
mantenerlo en varios sitios. Ese módulo es <module>mod_xml2enc</module>,
y debe cargarse para que i18n funcione.</p>
<p>La interacción de mod_proxy_html con mod_xml2enc es demasiado compleja para
configurarse usando la configuración de filtros habitual, incluidas las directivas de
<module>mod_filter</module>. Así, aunque mod_proxy_html todavía puede
configurarse usando las directivas de filtro habituales, esto no admitirá
i18n en absoluto. En su lugar, se ha introducido una nueva directiva, <directive>ProxyHTMLEnable</directive>,
para configurar tanto el filtro de mod_proxy_html como mod_xml2enc.
Se recomienda usar siempre ProxyHTMLEnable, incluso cuando no se necesite
el soporte de i18n.</p>
<note>Esto supone un cambio respecto a versiones
anteriores, en las que se usaban directivas de filtro para activar mod_proxy_html.</note>

</section>

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
    <note>
      <p>ProxyHTMLMeta formaba parte del soporte de i18n en versiones anteriores
      de mod_proxy_html, incluidas las de Apache HTTPD 2.0 y 2.2.
      Esa funcionalidad se ha separado ahora en el módulo independiente
      <module>mod_xml2enc</module>. ProxyHTMLMeta ya no
      sirve para nada que probablemente sea útil en un servidor en producción,
      aunque puede servir como ayuda de pruebas/depuración para desarrolladores
      de software como navegadores.</p>
    </note>

    <p>Esto activa o desactiva el preanálisis de metadatos en las
    secciones <code>&lt;head&gt;</code> del HTML.</p>

    <p>Activar <directive>ProxyHTMLMeta</directive> analizará todas
    las declaraciones <code>&lt;meta http-equiv=...&gt;</code> y las convertirá
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
<compatibility>Versión 2.4 y posteriores; disponible como de terceros
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
<br/>ProxyHTMLDocType <var>fpi</var> [SGML|XML]<br/><strong>O BIEN</strong>
<br/>ProxyHTMLDocType html5<br/><strong>O BIEN</strong>
<br/>ProxyHTMLDocType auto</syntax>
<default>ProxyHTMLDocType auto (versiones 2.5/trunk); sin FPI (2.4.x)</default>
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
<p>La tercera forma declara los documentos como HTML 5.</p>
<p>La cuarta forma es nueva en el trunk de HTTPD y todavía no está disponible en
las versiones publicadas, y usa el analizador HTML de libxml2 para detectar el doctype.</p>
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
<compatibility>Versión 2.4 y posteriores; disponible como módulo de terceros
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
que define los eventos estándar de HTML 4 y XHTML 1. Esto puede
ampliarse para aplicarse a URLs incrustadas en atributos de hojas de estilo CSS
añadiendo el atributo <var>style</var> a ProxyHTMLEvents, aunque
esto no está activado en la configuración por defecto suministrada.</p>
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
<note>
<p>Esto no admite la codificación de entidades HTML. Si un documento contiene
caracteres que no pueden representarse en el juego de caracteres de destino, fallará
y es probable que el documento quede dañado. Esto se aplica incluso si
dichos caracteres están representados como entidades en el documento de entrada.</p>
</note>
</usage>
</directivesynopsis>



</modulesynopsis>
