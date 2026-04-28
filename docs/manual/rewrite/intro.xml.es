<?xml version='1.0' encoding='UTF-8' ?>
<!DOCTYPE manualpage SYSTEM "../style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933423 -->

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

<manualpage metafile="intro.xml.meta">
<parentdocument href="./">Rewrite</parentdocument>

  <title>Introducción a Apache mod_rewrite</title>

<summary>
<p>Este documento complementa la <module>mod_rewrite</module>
<a href="../mod/mod_rewrite.html">documentación de referencia</a>. Describe
los conceptos básicos necesarios para el uso de
<module>mod_rewrite</module>. Otros documentos entran en mayor detalle,
pero este documento debería ayudar al principiante a mojarse los pies.
</p>
</summary>

<seealso><a href="../mod/mod_rewrite.html">Documentación del módulo</a></seealso>
<!-- <seealso><a href="intro.html">Introducción a mod_rewrite</a></seealso> -->
<seealso><a href="remapping.html">Redirección y remapeo</a></seealso>
<seealso><a href="access.html">Control de acceso</a></seealso>
<seealso><a href="vhosts.html">Hosts virtuales</a></seealso>
<seealso><a href="proxy.html">Proxy</a></seealso>
<seealso><a href="rewritemap.html">Uso de RewriteMap</a></seealso>
<seealso><a href="advanced.html">Técnicas avanzadas</a></seealso>
<seealso><a href="avoid.html">Cuándo no usar mod_rewrite</a></seealso>

<section id="introduction"><title>Introducción</title>
<p>El módulo de Apache <module>mod_rewrite</module> es un módulo muy potente y
sofisticado que proporciona una forma de hacer manipulaciones de URL. Con
él, puede hacer casi todos los tipos de reescritura de URL que pueda necesitar. Es,
sin embargo, algo complejo, y puede ser intimidante para el principiante.
También hay una tendencia a tratar las reglas de reescritura como encantamientos mágicos,
usándolas sin realmente entender lo que hacen.</p>

<p>Este documento intenta dar suficiente contexto para que lo que
sigue sea entendido, en lugar de simplemente copiado a ciegas.
</p>

<p>Recuerde que muchas tareas comunes de manipulación de URL no requieren la
potencia y complejidad completas de <module>mod_rewrite</module>. Para tareas
simples, consulte <module>mod_alias</module> y la documentación
sobre <a href="../urlmapping.html">mapeo de URLs al
sistema de archivos</a>.</p>

<p>Finalmente, antes de continuar, asegúrese de configurar
el nivel de log de <module>mod_rewrite</module> a uno de los niveles de traza usando
la directiva <directive module="core">LogLevel</directive>. Aunque esto
puede dar una cantidad abrumadora de información, es indispensable para
depurar problemas con la configuración de <module>mod_rewrite</module>, ya que
le dirá exactamente cómo se procesa cada regla.</p>

</section>

<section id="regex"><title>Expresiones Regulares</title>

<p><module>mod_rewrite</module> usa el vocabulario de <a href="http://pcre.org/">Expresiones
Regulares Compatibles con Perl</a>. En este documento, no intentamos
proporcionar una referencia detallada de expresiones regulares. Para eso,
recomendamos las <a href="http://pcre.org/pcre.txt">páginas man de PCRE</a>, la
<a href="http://perldoc.perl.org/perlre.html">página man de expresiones
regulares de Perl</a>, y <a
href="https://www.oreilly.com/library/view/mastering-regular-expressions/0596528124/">Mastering
Regular Expressions, de Jeffrey Friedl</a> (la tercera edición es de
2006, pero la sintaxis de expresiones regulares es esencialmente la misma, y este
sigue siendo la referencia definitiva sobre el tema).</p>

<p>En este documento, intentamos proporcionar suficiente vocabulario de regex
para que pueda comenzar, sin ser abrumador, con la esperanza de que
las <directive module="mod_rewrite">RewriteRule</directive>s sean fórmulas
científicas, en lugar de encantamientos mágicos.</p>

<section id="regexvocab"><title>Vocabulario de Regex</title>

<p>Los siguientes son los bloques de construcción mínimos que necesitará, para
escribir expresiones regulares y <directive
module="mod_rewrite">RewriteRule</directive>s. Ciertamente no
representan un vocabulario completo de expresiones regulares, pero son un buen
punto de partida, y deberían ayudarle a leer expresiones regulares básicas, así
como a escribir las suyas propias.</p>

<table>
<tr>
<th>Carácter</th>
<th>Significado</th>
<th>Ejemplo</th>
</tr>

<tr>
    <td><code>.</code></td>
    <td>Coincide con cualquier carácter individual</td>
    <td><code>c.t</code> coincidirá con <code>cat</code>, <code>cot</code>,
      <code>cut</code>, etc</td>
</tr>
<tr>
    <td><code>+</code></td>
    <td>Repite la coincidencia anterior una o más veces</td>
    <td><code>a+</code> coincide con <code>a</code>, <code>aa</code>,
      <code>aaa</code>, etc</td>
</tr>
<tr>
    <td><code>*</code></td>
    <td>Repite la coincidencia anterior cero o más veces</td>
    <td><code>a*</code> coincide con todo lo mismo que <code>a+</code>,
      pero también coincidirá con una cadena vacía</td>
</tr>
<tr>
    <td><code>?</code></td>
    <td>Hace la coincidencia opcional</td>
    <td><code>colou?r</code> coincidirá con <code>color</code> y
    <code>colour</code></td>
</tr>
<tr>
    <td><code>\</code></td>
    <td>Escapa el siguiente carácter</td>
    <td><code>\.</code> coincidirá con <code>.</code> (punto) y no con <em>cualquier
    carácter individual</em> como se explicó arriba</td>
</tr>
<tr>
    <td><code>^</code></td>
    <td>Llamado ancla, coincide con el inicio de la cadena</td>
    <td><code>^a</code> coincide con una cadena que comienza con <code>a</code></td>
</tr>
<tr>
    <td><code>$</code></td>
    <td>La otra ancla, coincide con el final de la cadena</td>
    <td><code>a$</code> coincide con una cadena que termina con <code>a</code></td>
</tr>
<tr>
    <td><code>( )</code></td>
    <td>Agrupa varios caracteres en una sola unidad, y captura una coincidencia
      para uso en una referencia inversa</td>
    <td><code>(ab)+</code> coincide con <code>ababab</code> - es decir, el
      <code>+</code> se aplica al grupo. Para más sobre referencias inversas vea
      <a href="#InternalBackRefs">más abajo</a></td>
</tr>
<tr>
    <td><code>[ ]</code></td>
    <td>Una clase de caracteres - coincide con uno de los caracteres</td>
    <td><code>c[uoa]t</code> coincide con <code>cut</code>, <code>cot</code> o
      <code>cat</code></td>
</tr>
<tr>
    <td><code>[^ ]</code></td>
    <td>Clase de caracteres negativa - coincide con cualquier carácter no especificado</td>
    <td><code>c[^/]t</code> coincide con <code>cat</code> o <code>c=t</code> pero
      no con <code>c/t</code></td></tr>
</table>

<p>En <module>mod_rewrite</module> el carácter <code>!</code> puede usarse
antes de una expresión regular para negarla. Es decir, una cadena se
considerará que ha coincidido solo si no coincide con el resto de
la expresión.</p>

</section>

<section id="InternalBackRefs"><title>Disponibilidad de Referencias Inversas de Regex</title>

      <p>Una cosa importante que debe recordarse aquí: Siempre que
      use paréntesis en <em>Pattern</em> o en uno de los
      <em>CondPattern</em>, se crean referencias inversas internas
      que pueden usarse con las cadenas <code>$N</code> y
      <code>%N</code> (ver más abajo). Estas están disponibles para crear
      el parámetro <em>Substitution</em> de una
      <directive module="mod_rewrite">RewriteRule</directive> o
      el parámetro <em>TestString</em> de una
      <directive module="mod_rewrite">RewriteCond</directive>.</p>
      <p>  Las capturas en los patrones de <directive module="mod_rewrite"
      >RewriteRule</directive> están (contraintuitivamente) disponibles para
       todas las directivas
      <directive module="mod_rewrite">RewriteCond</directive> precedentes,
      porque la expresión de <directive module="mod_rewrite">RewriteRule</directive>
      se evalúa antes que las condiciones individuales.</p>

      <p>La Figura 1 muestra a qué
      ubicaciones se transfieren las referencias inversas para expansión, así
      como ilustra el flujo de la coincidencia de RewriteRule, RewriteCond.
      En los próximos capítulos, exploraremos cómo usar
      estas referencias inversas, así que no se preocupe si le parece un poco extraño
      al principio.
      </p>

<p class="figure">
      <img src="../images/rewrite_backreferences.png"
      alt="Flujo de coincidencia de RewriteRule y RewriteCond" /><br />
      <dfn>Figura 1:</dfn> El flujo de referencias inversas a través de una regla.<br />
      En este ejemplo, una solicitud para <code>/test/1234</code> sería transformada en <code>/admin.foo?page=test&amp;id=1234&amp;host=admin.example.com</code>.
</p>

</section>
</section>

<section id="rewriterule"><title>Conceptos Básicos de RewriteRule</title>
<p>Una <directive module="mod_rewrite">RewriteRule</directive> consiste
en tres argumentos separados por espacios. Los argumentos son</p>
<ol>
<li><var>Pattern</var>: qué URLs entrantes deben ser afectadas por la regla;</li>
<li><var>Substitution</var>: a dónde deben enviarse las solicitudes coincidentes;</li>
<li><var>[flags]</var>: opciones que afectan a la solicitud reescrita.</li>
</ol>

<p>El <var>Pattern</var> es una <a href="#regex">expresión regular</a>.
Se compara inicialmente (para la primera regla de reescritura o hasta que ocurra una sustitución)
contra la ruta URL de la solicitud entrante (la parte después del
nombre de host pero antes de cualquier signo de interrogación que indique el inicio de una cadena
de consulta) o, en contexto per-directorio, contra la ruta de la solicitud relativa
al directorio para el cual se define la regla. Una vez que ha ocurrido una sustitución,
las reglas siguientes se comparan contra el valor
sustituido.
</p>

<p class="figure">
      <img src="../images/syntax_rewriterule.png"
      alt="Sintaxis de la directiva RewriteRule" /><br />
      <dfn>Figura 2:</dfn> Sintaxis de la directiva RewriteRule.
</p>


<p>La <var>Substitution</var> puede ser una de tres cosas:</p>

<dl>
<dt>1. Una ruta completa del sistema de archivos a un recurso</dt>
<dd>
<highlight language="config">
RewriteRule "^/games" "/usr/local/games/web/puzzles.html"
</highlight>
<p>Esto mapea una solicitud a una ubicación arbitraria en su sistema de archivos, de forma
similar a la directiva <directive module="mod_alias">Alias</directive>.</p>
</dd>

<dt>2. Una ruta web a un recurso</dt>
<dd>
<highlight language="config">
RewriteRule "^/games$" "/puzzles.html"
</highlight>
<p>Si <directive module="core">DocumentRoot</directive> está configurado
como <code>/usr/local/apache2/htdocs</code>, entonces esta directiva
mapearía solicitudes para <code>http://example.com/games</code> a la
ruta <code>/usr/local/apache2/htdocs/puzzles.html</code>.</p>

</dd>

<dt>3. Una URL absoluta</dt>
<dd>
<highlight language="config">
RewriteRule "^/product/view$" "http://site2.example.com/seeproduct.html" [R]
</highlight>
<p>Esto le dice al cliente que haga una nueva solicitud a la URL especificada.</p>
</dd>
</dl>

<note type="warning">Tenga en cuenta que <strong>1</strong> y <strong>2</strong> tienen exactamente la misma sintaxis. La diferencia entre ellos es que en el caso de <strong>1</strong>, el nivel superior de la ruta destino (es decir, <code>/usr/</code>) existe en el sistema de archivos, mientras que en el caso de <strong>2</strong>, no existe. (es decir, no hay <code>/bar/</code> como directorio de nivel raíz en el sistema de archivos.)</note>

<p>La <var>Substitution</var> también puede
contener <em>referencias inversas</em> a partes de la ruta URL entrante
coincidida por el <var>Pattern</var>. Considere lo siguiente:</p>
<highlight language="config">
RewriteRule "^/product/(.*)/view$" "/var/web/productdb/$1"
</highlight>
<p>La variable <code>$1</code> será reemplazada por cualquier texto
que haya coincidido con la expresión dentro de los paréntesis en
el <var>Pattern</var>. Por ejemplo, una solicitud
para <code>http://example.com/product/r14df/view</code> será mapeada
a la ruta <code>/var/web/productdb/r14df</code>.</p>

<p>Si hay más de una expresión entre paréntesis, están
disponibles en orden en las
variables <code>$1</code>, <code>$2</code>, <code>$3</code>, y así
sucesivamente.</p>


</section>

<section id="flags"><title>Banderas de Reescritura</title>
<p>El comportamiento de una <directive
module="mod_rewrite">RewriteRule</directive> puede ser modificado por la
aplicación de una o más banderas al final de la regla. Por ejemplo, el
comportamiento de coincidencia de una regla puede hacerse insensible a mayúsculas/minúsculas mediante la
aplicación de la bandera <code>[NC]</code>:
</p>
<highlight language="config">
RewriteRule "^puppy.html" "smalldog.html" [NC]
</highlight>

<p>Para más detalles sobre las banderas disponibles, sus significados, y
ejemplos, consulte el documento de <a href="flags.html">Banderas de Reescritura</a>.</p>

</section>


<section id="rewritecond"><title>Condiciones de Reescritura</title>
<p>Una o más directivas <directive module="mod_rewrite">RewriteCond</directive>
pueden usarse para restringir los tipos de solicitudes que estarán
sujetas a la
<directive module="mod_rewrite">RewriteRule</directive> siguiente. El
primer argumento es una variable que describe una característica de la
solicitud, el segundo argumento es una <a href="#regex">expresión
regular</a> que debe coincidir con la variable, y un tercer argumento opcional
es una lista de banderas que modifican cómo se evalúa la coincidencia.</p>

<p class="figure">
      <img src="../images/syntax_rewritecond.png"
      alt="Sintaxis de la directiva RewriteCond" /><br />
      <dfn>Figura 3:</dfn> Sintaxis de la directiva RewriteCond
</p>

<p>Por ejemplo, para enviar todas las solicitudes desde un rango de IP particular a un
servidor diferente, podría usar:</p>
<highlight language="config">
RewriteCond "%{REMOTE_ADDR}" "^10\.2\."
RewriteRule "(.*)"           "http://intranet.example.com$1"
</highlight>

<p>Cuando se especifica más de
una <directive module="mod_rewrite">RewriteCond</directive>,
todas deben coincidir para que la
<directive module="mod_rewrite">RewriteRule</directive> se aplique.
Por ejemplo, para denegar solicitudes que contengan la palabra "hack" en
su cadena de consulta, a menos que también contengan una cookie que contenga
la palabra "go", podría usar:</p>
<highlight language="config">
RewriteCond "%{QUERY_STRING}" "hack"
RewriteCond "%{HTTP_COOKIE}"  !go
RewriteRule "."               "-"   [F]
</highlight>
<p>Note que el signo de exclamación especifica una coincidencia negativa, por lo que la regla solo se aplica si la cookie no contiene "go".</p>

<p>Las coincidencias en las expresiones regulares contenidas en
las <directive module="mod_rewrite">RewriteCond</directive>s pueden
usarse como parte de la <var>Substitution</var> en
la <directive module="mod_rewrite">RewriteRule</directive> usando las
variables <code>%1</code>, <code>%2</code>, etc. Por ejemplo, esto
dirigirá la solicitud a un directorio diferente dependiendo del
nombre de host usado para acceder al sitio:</p>
<highlight language="config">
RewriteCond "%{HTTP_HOST}" "(.*)"
RewriteRule "^/(.*)"       "/sites/%1/$1"
</highlight>
<p>Si la solicitud fue para <code>http://example.com/foo/bar</code>,
entonces <code>%1</code> contendrá <code>example.com</code>
y <code>$1</code> contendrá <code>foo/bar</code>.</p>



</section>

<section id="rewritemap"><title>Mapas de reescritura</title>

<p>La directiva <directive module="mod_rewrite">RewriteMap</directive>
proporciona una forma de llamar a una función externa, por así decirlo, para hacer su
reescritura por usted. Esto se discute con mayor detalle en la <a
href="rewritemap.html">documentación complementaria de RewriteMap</a>.</p>
</section>

<section id="htaccess"><title>Archivos .htaccess</title>

<p>La reescritura se configura típicamente en la configuración principal del servidor
(fuera de cualquier sección <directive type="section"
module="core">Directory</directive>) o
dentro de contenedores <directive type="section" module="core">VirtualHost</directive>.
Esta es la forma más fácil de hacer reescritura y es
recomendada. Sin embargo, es posible hacer reescritura
dentro de secciones <directive type="section" module="core">Directory</directive>
o archivos <a href="../howto/htaccess.html"><code>.htaccess</code></a>
a costa de algo de complejidad adicional. Esta técnica
se llama reescrituras per-directorio.</p>

<p>La principal diferencia con las reescrituras per-servidor es que el prefijo de ruta
del directorio que contiene el archivo <code>.htaccess</code> se
elimina antes de la coincidencia en
la <directive module="mod_rewrite">RewriteRule</directive>. Además, se debería usar <directive module="mod_rewrite">RewriteBase</directive> para asegurar que la solicitud se mapee correctamente.</p>

</section>

</manualpage>
