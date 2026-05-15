<?xml version='1.0' encoding='UTF-8' ?>
<!DOCTYPE manualpage SYSTEM "../style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933062:1934234 (outdated) -->

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

<manualpage metafile="flags.xml.meta">
<parentdocument href="./">Rewrite</parentdocument>

  <title>Banderas de RewriteRule</title>

<summary>
<p>Este documento describe las banderas que están disponibles para la
directiva <directive module="mod_rewrite">RewriteRule</directive>,
proporcionando explicaciones detalladas y ejemplos.</p>
</summary>

<seealso><a href="../mod/mod_rewrite.html">Documentación del módulo</a></seealso>
<seealso><a href="intro.html">Introducción a mod_rewrite</a></seealso>
<seealso><a href="remapping.html">Redirección y remapeo</a></seealso>
<seealso><a href="access.html">Control de acceso</a></seealso>
<seealso><a href="vhosts.html">Hosts virtuales</a></seealso>
<seealso><a href="proxy.html">Proxy</a></seealso>
<seealso><a href="rewritemap.html">Uso de RewriteMap</a></seealso>
<seealso><a href="advanced.html">Técnicas avanzadas</a></seealso>
<seealso><a href="avoid.html">Cuándo no usar mod_rewrite</a></seealso>

<section id="introduction"><title>Introducción</title>
<p>Una <directive module="mod_rewrite">RewriteRule</directive> puede tener
su comportamiento modificado por una o más banderas. Las banderas se incluyen entre
corchetes al final de la regla, y múltiples banderas se separan
con comas.</p>
<highlight language="config">
RewriteRule pattern target [Flag1,Flag2,Flag3]
</highlight>

<p>Cada bandera (con algunas excepciones) tiene una forma corta, como
<code>CO</code>, así como una forma más larga, como <code>cookie</code>.
Aunque es más común usar
la forma corta, se recomienda que se familiarice con la
forma larga, para que recuerde qué se supone que hace cada bandera.
Algunas banderas toman uno o más argumentos. Las banderas no distinguen entre mayúsculas y minúsculas.</p>

<p>Las banderas que alteran metadatos asociados con la solicitud (T=, H=, E=)
no tienen efecto en contexto per-directorio y htaccess, cuando una sustitución
(distinta de '-') se realiza durante la misma ronda de procesamiento de reescritura.
</p>

<p>Aquí se presentan cada una de las banderas disponibles, junto con un ejemplo
de cómo podría usarlas.</p>
</section>

<section id="flag_b"><title>B (escapar referencias inversas)</title>
<p>La bandera [B] indica a <directive
module="mod_rewrite">RewriteRule</directive> que escape los caracteres no alfanuméricos
antes de aplicar la transformación.</p>

<p><module>mod_rewrite</module> tiene que desescapar URLs antes de mapearlas,
por lo que las referencias inversas se desescapan en el momento en que se aplican.
Usando la bandera B, los caracteres no alfanuméricos en las referencias inversas
se escaparán. Por ejemplo, considere la regla:</p>

<p>Para un escape similar de variables del servidor, vea
    la <a href="#mapfunc">función de mapeo</a> "escape"</p>


<highlight language="config">
RewriteRule "^search/(.*)$" "/search.php?term=$1"
</highlight>

<p>Dado un término de búsqueda de 'x &amp; y/z', un navegador lo codificará como
'x%20%26%20y%2Fz', haciendo la solicitud 'search/x%20%26%20y%2Fz'. Sin la bandera B,
esta regla de reescritura mapeará a 'search.php?term=x &amp; y/z', que
no es una URL válida, y por lo tanto sería codificada como
<code>search.php?term=x%20&amp;y%2Fz=</code>, que no era lo que se pretendía.</p>

<p>Con la bandera B establecida en esta misma regla, los parámetros se re-codifican
antes de pasarse a la URL de salida, resultando en un mapeo correcto a
<code>/search.php?term=x%20%26%20y%2Fz</code>.</p>

<highlight language="config">
RewriteRule "^search/(.*)$" "/search.php?term=$1" [B,PT]
</highlight>

<p>Tenga en cuenta que también puede necesitar establecer <directive
module="core">AllowEncodedSlashes</directive> a <code>On</code> para que este
ejemplo particular funcione, ya que httpd no permite barras codificadas en URLs, y
devuelve un 404 si ve una.</p>

<p>Este escape es particularmente necesario en una situación de proxy,
cuando el backend puede fallar si se le presenta una URL sin escapar.</p>

<p>Una alternativa a esta bandera es usar una <directive module="mod_rewrite"
>RewriteCond</directive> para capturar contra %{THE_REQUEST} que capturará
cadenas en la forma codificada.</p>

<p>En 2.4.26 y posterior, puede limitar el escape a caracteres específicos
en las referencias inversas listándolos: <code>[B=#?;]</code>. Nota: El carácter
de espacio puede usarse en la lista de caracteres a escapar, pero debe entrecomillar
el tercer argumento completo de <directive module="mod_rewrite">RewriteRule</directive>
y el espacio no debe ser el último carácter en la lista.</p>

<highlight language="config">
# Escapar espacios y signos de interrogación. Las comillas alrededor del argumento final
# son necesarias cuando se incluye un espacio.
RewriteRule "^search/(.*)$" "/search.php?term=$1" "[B= ?]"
</highlight>

<p>Para limitar los caracteres escapados de esta manera, vea <a href="#flag_bne">#flag_bne</a>
        y <a href="#flag_bctls">#flag_bctls</a></p>
</section>

<section id="flag_bnp"><title>BNP|backrefnoplus (no escapar espacio a +)</title>
<p>La bandera [BNP] indica a <directive
module="mod_rewrite">RewriteRule</directive> que escape el carácter de espacio
en una referencia inversa a %20 en lugar de '+'. Útil cuando la referencia inversa
se usará en el componente de ruta en lugar de la cadena de consulta.</p>

<highlight language="config">
# Escapar espacios a %20 en la ruta en lugar de + como se usa en el envío de formularios a través de
# la cadena de consulta
RewriteRule "^search/(.*)$" "/search.php/$1" "[B,BNP]"
</highlight>


<p>Esta bandera está disponible en la versión 2.4.26 y posterior.</p>
</section>

<section id="flag_bctls"><title>BCTLS</title>
<p>La bandera [BCTLS] es similar a la bandera [B], pero solo escapa
caracteres de control y el carácter de espacio. Este es el mismo conjunto de
caracteres rechazados cuando se copian en la cadena de consulta sin codificar.
</p>

<highlight language="config">
# Escapar caracteres de control y espacios
RewriteRule "^search/(.*)$" "/search.php/$1" "[BCTLS]"
</highlight>

<p>Esta bandera está disponible en la versión 2.5.1 y posterior.</p>

</section>

<section id="flag_bne"><title>BNE</title>
<p>La lista de caracteres en [BNE=...] se trata como exclusiones de los
caracteres de las banderas [B] o [BCTLS]. Los caracteres listados no serán
escapados.
</p>

<highlight language="config">
# Escapar los caracteres predeterminados, pero dejar /
RewriteRule "^search/(.*)$" "/search.php?term=$1" "[B,BNE=/]"
</highlight>

<p>Esta bandera está disponible en la versión 2.5.1 y posterior.</p>
</section>

<section id="flag_c"><title>C|chain</title>
<p>La bandera [C] o [chain] indica que la <directive
module="mod_rewrite">RewriteRule</directive> está encadenada a la siguiente
regla. Es decir, si la regla coincide, entonces se procesa como de costumbre y
el control pasa a la siguiente regla. Sin embargo, si no coincide, entonces
la siguiente regla, y cualquier otra regla que esté encadenada, se
omiten.</p>

</section>

<section id="flag_co"><title>CO|cookie</title>
<p>La bandera [CO], o [cookie], le permite establecer una cookie cuando una
<directive module="mod_rewrite">RewriteRule</directive> particular
coincide. El argumento consiste en tres campos obligatorios y cinco
campos opcionales.</p>

<p>La sintaxis completa para la bandera, incluyendo todos los atributos, es la
siguiente:</p>

<example>
[CO=NAME:VALUE:DOMAIN:lifetime:path:secure:httponly:samesite]
</example>

<p>Si se necesita un carácter literal ':' en cualquiera de los campos de la cookie, está disponible una
sintaxis alternativa. Para optar por la sintaxis alternativa, el
"Name" de la cookie debe ir precedido por un carácter ';', y los separadores de campo deben
especificarse como ';'.</p>

<example>
[CO=;NAME;VALUE:MOREVALUE;DOMAIN;lifetime;path;secure;httponly;samesite]
</example>

<p>Debe declarar un nombre, un valor y un dominio para que la cookie se establezca.</p>

<dl>
<dt>Dominio</dt>
<dd>El dominio para el cual desea que la cookie sea válida. Este puede ser un
nombre de host, como <code>www.example.com</code>, o puede ser un dominio,
como <code>.example.com</code>. Debe tener al menos dos partes
separadas por un punto. Es decir, no puede ser simplemente <code>.com</code> o
<code>.net</code>. Las cookies de ese tipo están prohibidas por el modelo de
seguridad de cookies.</dd>
</dl>

<p>Opcionalmente también puede establecer los siguientes valores:</p>

<dl>
<dt>Tiempo de vida</dt>
<dd>El tiempo durante el cual la cookie persistirá, en minutos.</dd>
<dd>Un valor de 0 indica que la cookie persistirá solo durante la
sesión actual del navegador. Este es el valor predeterminado si no se
especifica ninguno.</dd>
<dd>Un valor negativo causa que la cookie sea eliminada en el navegador.</dd>

<dt>Ruta</dt>
<dd>La ruta, en el sitio web actual, para la cual la cookie es válida,
como <code>/customers/</code> o <code>/files/download/</code>.</dd>
<dd>Por defecto, esto se establece a <code>/</code> - es decir, todo el
sitio web.</dd>

<dt>Secure</dt>
<dd>Si se establece a <code>secure</code>, <code>true</code>, o <code>1</code>,
la cookie solo se permitirá ser transmitida a través de conexiones seguras (https).</dd>

<dt>httponly</dt>
<dd>Si se establece a <code>HttpOnly</code>, <code>true</code>, o
<code>1</code>, la cookie tendrá la bandera <code>HttpOnly</code> establecida,
lo que significa que la cookie es inaccesible para código JavaScript en
navegadores que soportan esta característica.</dd>

<dt>samesite</dt>
<dd>Si se establece a algo distinto de <code>false</code> o <code>0</code>, el atributo <code>SameSite</code>
se establece al valor especificado. Valores típicos son <code>None</code>,
<code>Lax</code>, y <code>Strict</code>. Disponible en 2.5.1 y posterior.</dd>
</dl>


<p>Considere este ejemplo:</p>

<highlight language="config">
RewriteEngine On
RewriteRule   "^/index\.html"   "-" [CO=frontdoor:yes:.example.com:1440:/]
</highlight>

<p>En el ejemplo dado, la regla no reescribe la solicitud.
El destino de reescritura "-" le dice a <module>mod_rewrite</module> que pase la solicitud
sin cambios. En su lugar, establece una cookie
llamada 'frontdoor' con un valor de 'yes'. La cookie es válida para cualquier host
en el dominio <code>.example.com</code>. Se establece para expirar en 1440
minutos (24 horas) y se devuelve para todas las URIs.</p>

</section>

<section id="flag_dpi"><title>DPI|discardpath</title>
<p>La bandera DPI causa que la porción PATH_INFO de la URI reescrita sea
descartada.</p>
<p>Esta bandera está disponible en la versión 2.2.12 y posterior.</p>
<p>En contexto per-directorio, la URI contra la que cada <directive>RewriteRule</directive>
compara es la concatenación de los valores actuales de la URI
y PATH_INFO.</p>

<p>La URI actual puede ser la URI inicial solicitada por el cliente, el
resultado de una ronda anterior de procesamiento de <module>mod_rewrite</module>, o el resultado de
una regla previa en la ronda actual de procesamiento de <module>mod_rewrite</module>.</p>

<p>En contraste, el PATH_INFO que se añade a la URI antes de cada
regla refleja solo el valor de PATH_INFO antes de esta ronda de
procesamiento de <module>mod_rewrite</module>. Como consecuencia, si porciones grandes
de la URI se hacen coincidir y copian en una sustitución en múltiples
directivas <directive>RewriteRule</directive>, sin considerar
qué partes de la URI provienen del PATH_INFO actual, la URI
final puede tener múltiples copias de PATH_INFO añadidas.</p>

<p>Use esta bandera en cualquier sustitución donde el PATH_INFO que resultó
del mapeo anterior de esta solicitud al sistema de archivos no es de
interés. Esta bandera olvida permanentemente el PATH_INFO establecido
antes de que comenzara esta ronda de procesamiento de <module>mod_rewrite</module>. PATH_INFO no
se recalculará hasta que se complete la ronda actual de procesamiento de <module>mod_rewrite</module>.
Las reglas subsiguientes durante esta ronda de procesamiento verán
solo el resultado directo de las sustituciones, sin ningún PATH_INFO
añadido.</p>
</section>

<section id="flag_e"><title>E|env</title>
<p>Con la bandera [E], o [env], puede establecer el valor de una variable
de entorno. Tenga en cuenta que algunas variables de entorno pueden establecerse después de que la regla
se ejecute, deshaciendo así lo que ha establecido. Vea <a href="../env.html">el
documento de Variables de Entorno</a> para más detalles sobre cómo funcionan las variables
de entorno.</p>

<p>La sintaxis completa para esta bandera es:</p>

<highlight language="config">
[E=VAR:VAL]
[E=!VAR]
</highlight>

<p><code>VAL</code> puede contener referencias inversas (<code>$N</code> o
<code>%N</code>) que se expanden.</p>

<p>Usando la forma corta</p>

<example>
[E=VAR]
</example>

<p>puede establecer la variable de entorno llamada <code>VAR</code> a un
valor vacío.</p>

<p>La forma</p>

<example>
[E=!VAR]
</example>

<p>permite eliminar una variable de entorno previamente establecida
llamada <code>VAR</code>.</p>

<p>Las variables de entorno pueden usarse en una variedad de
contextos, incluyendo programas CGI, otras directivas RewriteRule, o
directivas CustomLog.</p>

<p>El siguiente ejemplo establece una variable de entorno llamada 'image' con un
valor de '1' si la URI solicitada es un archivo de imagen. Entonces, esa
variable de entorno se usa para excluir esas solicitudes del registro de
acceso.</p>

<highlight language="config">
RewriteRule "\.(png|gif|jpg)$"   "-" [E=image:1]
CustomLog   "logs/access_log"    combined env=!image
</highlight>

<p>Tenga en cuenta que este mismo efecto se puede obtener usando <directive
module="mod_setenvif">SetEnvIf</directive>. Esta técnica se ofrece como
un ejemplo, no como una recomendación.</p>
</section>

<section id="flag_end"><title>END</title>
<p>Usar la bandera [END] termina no solo la ronda actual de procesamiento de
reescritura (como [L]) sino también previene que cualquier procesamiento de
reescritura posterior ocurra en contexto per-directorio (htaccess).</p>

<p>Esto no se aplica a nuevas solicitudes resultantes de
redirecciones externas.</p>
</section>

<section id="flag_f"><title>F|forbidden</title>
<p>Usar la bandera [F] causa que el servidor devuelva un código de estado 403 Forbidden
al cliente. Aunque el mismo comportamiento puede lograrse usando
la directiva <directive module="mod_access_compat">Deny</directive>, esto
permite más flexibilidad en la asignación de un estado Forbidden.</p>

<p>La siguiente regla prohibirá que archivos <code>.exe</code> sean
descargados de su servidor.</p>

<highlight language="config">
RewriteRule "\.exe"   "-" [F]
</highlight>

<p>Este ejemplo usa la sintaxis "-" para el destino de reescritura, que significa
que la URI solicitada no se modifica. No hay razón para reescribir a
otra URI, si va a prohibir la solicitud.</p>

<p>Cuando se usa [F], se implica un [L] - es decir, la respuesta se devuelve
inmediatamente, y no se evalúan más reglas.</p>

</section>

<section id="flag_g"><title>G|gone</title>
<p>La bandera [G] fuerza al servidor a devolver un estado 410 Gone con la
respuesta. Esto indica que un recurso solía estar disponible, pero ya no
lo está.</p>

<p>Como con la bandera [F], normalmente usará la sintaxis "-" para el
destino de reescritura cuando use la bandera [G]:</p>

<highlight language="config">
RewriteRule "oldproduct"   "-" [G,NC]
</highlight>

<p>Cuando se usa [G], se implica un [L] - es decir, la respuesta se devuelve
inmediatamente, y no se evalúan más reglas.</p>

</section>

<section id="flag_h"><title>H|handler</title>
<p>Fuerza que la solicitud resultante sea manejada con el manejador
especificado. Por ejemplo, uno podría usar esto para forzar que todos los archivos sin
extensión de archivo sean procesados por el manejador de php:</p>

<highlight language="config">
RewriteRule "!\."  "-" [H=application/x-httpd-php]
</highlight>

<p>
La expresión regular anterior - <code>!\.</code> - coincidirá con cualquier solicitud
que no contenga el carácter literal <code>.</code>.
</p>

<p>Esto también puede usarse para forzar el manejador basado en algunas condiciones.
Por ejemplo, el siguiente fragmento usado en contexto per-servidor permite que
archivos <code>.php</code> sean <em>mostrados</em> por <code>mod_php</code>
si se solicitan con la extensión <code>.phps</code>:</p>

<highlight language="config">
RewriteRule "^(/source/.+\.php)s$" "$1" [H=application/x-httpd-php-source]
</highlight>

<p>La expresión regular anterior - <code>^(/source/.+\.php)s$</code> - coincidirá
con cualquier solicitud que comience con <code>/source/</code> seguido de 1 o
más caracteres seguidos de <code>.phps</code> literalmente. La referencia inversa
$1 se refiere a la coincidencia capturada dentro de los paréntesis de la expresión
regular.</p>
</section>

<section id="flag_l"><title>L|last</title>
<p>La bandera [L] causa que <module>mod_rewrite</module> deje de procesar
el conjunto de reglas. En la mayoría de los contextos, esto significa que si la regla coincide, no
se procesarán más reglas. Esto corresponde al
comando <code>last</code> en Perl, o al comando <code>break</code> en
C. Use esta bandera para indicar que la regla actual debe aplicarse
inmediatamente sin considerar más reglas.</p>

<p>Si está usando <directive
module="mod_rewrite">RewriteRule</directive> en archivos
<code>.htaccess</code> o en
secciones <directive type="section" module="core">Directory</directive>,
es importante entender cómo se procesan las reglas. La forma simplificada de esto es que una vez que las reglas han sido
procesadas, la solicitud reescrita se devuelve al motor de análisis
de URL para que haga lo que pueda con ella. Es posible que mientras se maneja la solicitud reescrita, el archivo <code>.htaccess</code> o
la sección <directive type="section" module="core">Directory</directive>
pueda encontrarse de nuevo, y así el conjunto de reglas pueda ejecutarse de nuevo desde el
inicio. Lo más común es que esto suceda si una de las reglas causa una
redirección - ya sea interna o externa - causando que el proceso de solicitud
comience de nuevo.</p>

<p>Es por lo tanto importante, si está usando directivas <directive
module="mod_rewrite">RewriteRule</directive> en uno de estos
contextos, que tome pasos explícitos para evitar bucles en las reglas, y no
contar únicamente con la bandera [L] para terminar la ejecución de una serie de
reglas, como se muestra a continuación.</p>

<p>Una bandera alternativa, [END], puede usarse para terminar no solo la
ronda actual de procesamiento de reescritura sino prevenir cualquier
procesamiento de reescritura posterior en contexto per-directorio
(htaccess). Esto no se aplica a nuevas solicitudes resultantes de
redirecciones externas.</p>

<p>El ejemplo dado aquí reescribirá cualquier solicitud a
<code>index.php</code>, dando la solicitud original como un argumento de cadena
de consulta a <code>index.php</code>, sin embargo, la <directive
module="mod_rewrite">RewriteCond</directive> asegura que si la solicitud
ya es para <code>index.php</code>, la <directive
module="mod_rewrite">RewriteRule</directive> se omitirá.</p>

<highlight language="config">
RewriteBase "/"
RewriteCond "%{REQUEST_URI}" !=/index.php
RewriteRule "^(.*)"          "/index.php?req=$1" [L,PT]
</highlight>
</section>

<section id="flag_n"><title>N|next</title>
<p>
La bandera [N] causa que el conjunto de reglas comience de nuevo desde el principio, usando
el resultado del conjunto de reglas hasta el momento como punto de partida. Use
con extrema precaución, ya que puede resultar en un bucle.
</p>
<p>
La bandera [Next] podría usarse, por ejemplo, si deseara reemplazar una
cierta cadena o letra repetidamente en una solicitud. El ejemplo mostrado aquí
reemplazará A con B en todas partes de una solicitud, y continuará haciéndolo
hasta que no haya más As por reemplazar.
</p>
<highlight language="config">
RewriteRule "(.*)A(.*)" "$1B$2" [N]
</highlight>
<p>Puede pensar en esto como un bucle <code>while</code>: Mientras este
patrón siga coincidiendo (es decir, mientras la URI aún contenga una
<code>A</code>), realice esta sustitución (es decir, reemplace la
<code>A</code> con una <code>B</code>).</p>

<p>En 2.5.0 y posterior, este módulo devuelve un error después de 10,000 iteraciones para
proteger contra bucles no intencionados. Se puede especificar un número máximo alternativo de
iteraciones añadiéndolo a la bandera N. </p>
<highlight language="config">
# Estar dispuesto a reemplazar 1 carácter en cada pasada del bucle
RewriteRule "(.+)[&gt;&lt;;]$" "$1" [N=32000]
# ... o, rendirse después de 10 bucles
RewriteRule "(.+)[&gt;&lt;;]$" "$1" [N=10]
</highlight>

</section>

<section id="flag_nc"><title>NC|nocase</title>
<p>El uso de la bandera [NC] causa que la <directive
module="mod_rewrite">RewriteRule</directive> se evalúe de manera
insensible a mayúsculas/minúsculas. Es decir, no importa si las letras aparecen
en mayúsculas o minúsculas en la URI coincidente.</p>

<p>En el ejemplo siguiente, cualquier solicitud de un archivo de imagen será proxied
a su servidor de imágenes dedicado. La coincidencia es insensible a mayúsculas/minúsculas, de modo que
archivos <code>.jpg</code> y <code>.JPG</code> son ambos aceptables, por
ejemplo.</p>

<highlight language="config">
RewriteRule "(.*\.(jpg|gif|png))$" "http://images.example.com$1" [P,NC]
</highlight>
</section>

<section id="flag_ne"><title>NE|noescape</title>
<p>Por defecto, cuando una <directive module="mod_rewrite">RewriteRule</directive>
resulta en una redirección externa, cualquier carácter en la salida que no esté
en el siguiente conjunto seguro será convertido a sus equivalentes en hexadecimal
(codificación porcentual):</p>

<ul>
  <li>Caracteres alfanuméricos: <code>A-Z</code>, <code>a-z</code>,
  <code>0-9</code></li>
  <li>Caracteres especiales: <code>$-_.+!*'(),:;@&amp;=/~</code></li>
</ul>

<p>Por ejemplo, <code>#</code> se convertiría a <code>%23</code>,
y <code>?</code> a <code>%3F</code>. El carácter <code>%</code>
también se escapa (a <code>%25</code>), lo que significa que cualquier
codificación porcentual ya presente en la sustitución será
doblemente codificada.</p>

<p>Usar la bandera [NE] previene este escape, permitiendo que caracteres
como <code>#</code> y <code>?</code> pasen a la
URL de redirección sin modificar.</p>

<highlight language="config">
RewriteRule "^/anchor/(.+)" "/bigpage.html#$1" [NE,R]
</highlight>

<p>
El ejemplo anterior redirigirá <code>/anchor/xyz</code> a
<code>/bigpage.html#xyz</code>. Omitir la [NE] resultará en que el #
sea convertido a su equivalente hexadecimal, <code>%23</code>, lo que
entonces resultará en una condición de error 404 No Encontrado.
</p>

</section>

<section id="flag_ns"><title>NS|nosubreq</title>
<p>El uso de la bandera [NS] previene que la regla se use en
sub-solicitudes. Por ejemplo, una página incluida usando un SSI (Server
Side Include) es una sub-solicitud, y usted puede querer evitar que las reescrituras
ocurran en esas sub-solicitudes. También, cuando <module>mod_dir</module>
intenta encontrar información sobre posibles archivos predeterminados de directorio
(como archivos <code>index.html</code>), esto es una
sub-solicitud interna, y a menudo querrá evitar reescrituras en tales sub-solicitudes.
En sub-solicitudes, no siempre es útil, e incluso puede causar errores, si
el conjunto completo de reglas se aplica. Use esta bandera para excluir
reglas problemáticas.</p>

<p>Para decidir si usar o no esta regla: si prefija URLs con
scripts CGI, para forzar que sean procesadas por el script CGI, es
probable que tenga problemas (o una sobrecarga significativa)
en sub-solicitudes. En estos casos, use esta bandera.</p>

<p>
Imágenes, archivos javascript, o archivos css, cargados como parte de una página HTML,
no son sub-solicitudes - el navegador los solicita como solicitudes HTTP
separadas.
</p>
</section>

<section id="flag_p"><title>P|proxy</title>
<p>El uso de la bandera [P] causa que la solicitud sea manejada por
<module>mod_proxy</module>, y procesada a través de una solicitud proxy. Por
ejemplo, si quisiera que todas las solicitudes de imágenes fueran manejadas por un servidor
de imágenes backend, podría hacer algo como lo siguiente:</p>

<highlight language="config">
RewriteRule "/(.*)\.(jpg|gif|png)$" "http://images.example.com/$1.$2" [P]
</highlight>

<p>El uso de la bandera [P] implica [L] - es decir, la solicitud se envía inmediatamente
a través del proxy, y cualquier regla siguiente no será
considerada.</p>

<p>
Debe asegurarse de que la cadena de sustitución sea una URI válida
(típicamente comenzando con <code>http://</code><em>hostname</em>) que pueda ser
manejada por <module>mod_proxy</module>. Si no, obtendrá un
error del módulo proxy. Use esta bandera para lograr una
implementación más potente de la directiva <directive
module="mod_proxy">ProxyPass</directive>,
para mapear contenido remoto al espacio de nombres del servidor local.</p>

<note type="warning">
<title>Advertencia de Seguridad</title>
<p>Tenga cuidado al construir la URL destino de la regla, considerando
el impacto de seguridad de permitir que el cliente influya en el conjunto de
URLs a las que su servidor actuará como proxy. Asegúrese de que la parte del esquema
y nombre de host de la URL sea fija, o no permita al
cliente una influencia indebida.</p>
</note>

<note type="warning">
<title>Advertencia de Rendimiento</title>
<p>Usar esta bandera provoca el uso de <module>mod_proxy</module>, sin
manejo de conexiones persistentes ya que se usa el worker predeterminado en este caso,
el cual no maneja agrupación/reutilización de conexiones.</p>
<p>Para usar conexiones persistentes necesita configurar un
bloque <directive module="mod_proxy">Proxy</directive> al menos para la parte del esquema
y host de la URL destino conteniendo una
directiva <directive module="mod_proxy">ProxySet</directive> donde por ejemplo establezca
un timeout.</p>
<p>Si lo configura con <directive module="mod_proxy">ProxyPass</directive> o
<directive module="mod_proxy">ProxyPassMatch</directive> se usarán conexiones
persistentes automáticamente.</p>
</note>

<p>Nota: <module>mod_proxy</module> debe estar habilitado para
usar esta bandera.</p>

</section>

<section id="flag_pt"><title>PT|passthrough</title>

<p>
El destino (o cadena de sustitución) en una RewriteRule se asume que es una
ruta de archivo, por defecto. El uso de la bandera [PT] causa que sea tratada
como una URI en su lugar. Es decir, el
uso de la bandera [PT] causa que el resultado de la <directive
module="mod_rewrite">RewriteRule</directive> se pase de vuelta a través del
mapeo de URL, de modo que mapeos basados en ubicación, como <directive
module="mod_alias">Alias</directive>, <directive
module="mod_alias">Redirect</directive>, o <directive
module="mod_alias">ScriptAlias</directive>, por ejemplo, puedan tener la
oportunidad de tomar efecto.
</p>

<p>
Si, por ejemplo, tiene un
<directive module="mod_alias">Alias</directive>
para /icons, y tiene una <directive
module="mod_rewrite">RewriteRule</directive> apuntando allí, debería
usar la bandera [PT] para asegurar que el
<directive module="mod_alias">Alias</directive> sea evaluado.
</p>

<highlight language="config">
Alias "/icons" "/usr/local/apache/icons"
RewriteRule "/pics/(.+)\.jpg$" "/icons/$1.gif" [PT]
</highlight>

<p>
La omisión de la bandera [PT] en este caso causará que el Alias sea
ignorado, resultando en un error 'Archivo no encontrado'.
</p>

<p>La bandera <code>PT</code> implica la bandera <code>L</code>:
la reescritura se detendrá para pasar la solicitud a
la siguiente fase de procesamiento.</p>

<p>Tenga en cuenta que la bandera <code>PT</code> está implícita en contextos per-directorio
como secciones
<directive type="section" module="core">Directory</directive>
o en archivos <code>.htaccess</code>. La única forma de evitar eso
es reescribir a <code>-</code>.</p>

</section>

<section id="flag_qsa"><title>QSA|qsappend</title>
<p>
Cuando la URI de reemplazo contiene una cadena de consulta, el comportamiento predeterminado
de <directive module="mod_rewrite">RewriteRule</directive> es descartar
la cadena de consulta existente, y reemplazarla con la recién generada.
Usar la bandera [QSA] causa que las cadenas de consulta se combinen.
</p>

<p>Considere la siguiente regla:</p>

<highlight language="config">
RewriteRule "/pages/(.+)" "/page.php?page=$1" [QSA]
</highlight>

<p>Con la bandera [QSA], una solicitud para <code>/pages/123?one=two</code> será
mapeada a <code>/page.php?page=123&amp;one=two</code>. Sin la bandera [QSA],
esa misma solicitud será mapeada a
<code>/page.php?page=123</code> - es decir, la cadena de consulta existente
será descartada.
</p>
</section>

<section id="flag_qsd"><title>QSD|qsdiscard</title>
<p>
Cuando la URI solicitada contiene una cadena de consulta, y la URI destino no
la contiene, el comportamiento predeterminado de <directive
module="mod_rewrite">RewriteRule</directive> es copiar esa cadena de consulta
a la URI destino. Usar la bandera [QSD] causa que la cadena de consulta
sea descartada.
</p>

<p>Esta bandera está disponible en la versión 2.4.0 y posterior.</p>

<p>
Usar [QSD] y [QSA] juntos resultará en que [QSD] tenga precedencia.
</p>

<p>
Si la URI destino tiene una cadena de consulta, se observará el comportamiento predeterminado
- es decir, la cadena de consulta original será descartada y
reemplazada con la cadena de consulta en la URI destino de la <code>RewriteRule</code>.
</p>

</section>

<section id="flag_qsl"><title>QSL|qslast</title>
<p>
Por defecto, el primer signo de interrogación (el más a la izquierda) en la sustitución
delimita la ruta de la cadena de consulta. Usar la bandera [QSL] indica a
<directive module="mod_rewrite">RewriteRule</directive> que en su lugar divida
los dos componentes usando el último signo de interrogación (el más a la derecha). </p>

<p>
Esto es útil cuando se mapea a archivos que tienen signos de interrogación literales en
sus nombres de archivo. Si no se usa cadena de consulta en la sustitución,
se puede añadir un signo de interrogación en combinación con esta bandera. </p>

<p>Esta bandera está disponible en la versión 2.4.19 y posterior.</p>

</section>


<section id="flag_r"><title>R|redirect</title>
<p>
El uso de la bandera [R] causa que se emita una redirección HTTP al navegador.
Si se especifica una URL completamente cualificada (es decir, incluyendo
<code>http://servername/</code>) entonces se emitirá una redirección a esa
ubicación. De lo contrario, se usará el protocolo actual, nombre del servidor, y número de puerto
para generar la URL enviada con la redirección.
</p>

<p>
Se puede especificar <em>cualquier</em> código de estado de respuesta HTTP válido,
usando la sintaxis [R=305], con un código de estado 302 siendo usado por
defecto si no se especifica ninguno. El código de estado especificado no necesita
necesariamente ser un código de estado de redirección (3xx). Sin embargo,
si un código de estado está fuera del rango de redirección (300-399) entonces la
cadena de sustitución se descarta por completo, y la reescritura se detiene como si
se usara <code>L</code>.</p>

<p>Además de los códigos de estado de respuesta, también puede especificar estados de
redirección usando sus nombres simbólicos: <code>temp</code> (predeterminado),
<code>permanent</code>, o <code>seeother</code>.</p>

<p>
Casi siempre querrá usar [R] junto con [L] (es decir,
usar [R,L]) porque por sí sola, la bandera [R] antepone
<code>http://thishost[:thisport]</code> a la URI, pero luego pasa esto
a la siguiente regla en el conjunto de reglas, lo que a menudo puede resultar en advertencias de 'URI
inválida en solicitud'.
</p>

<p>Nota: httpd solo soporta códigos de estado que están incluidos en la especificación
HTTP. Usar un código de estado no reconocido resultará en un error 500 y
un mensaje en el log de errores.</p>

</section>

<section id="flag_s"><title>S|skip</title>
<p>La bandera [S] se usa para omitir reglas que no desea ejecutar. La
sintaxis de la bandera skip es [S=<em>N</em>], donde <em>N</em> indica
el número de reglas a omitir (siempre que la <directive module="mod_rewrite">
RewriteRule</directive> y cualquier directiva <directive module="mod_rewrite">
RewriteCond</directive> precedente coincidan). Esto puede pensarse como una
sentencia <code>goto</code> en su conjunto de reglas de reescritura. En el siguiente
ejemplo, solo queremos ejecutar la <directive module="mod_rewrite">
RewriteRule</directive> si la URI solicitada no corresponde a un
archivo real.</p>

<highlight language="config">
# Is the request for a non-existent file?
RewriteCond "%{REQUEST_FILENAME}" !-f
RewriteCond "%{REQUEST_FILENAME}" !-d
# If so, skip these two RewriteRules
RewriteRule ".?"                  "-" [S=2]

RewriteRule "(.*\.gif)"           "images.php?$1"
RewriteRule "(.*\.html)"          "docs.php?$1"
</highlight>

<p>Esta técnica es útil porque una <directive
module="mod_rewrite">RewriteCond</directive> solo se aplica a la
<directive module="mod_rewrite">RewriteRule</directive> inmediatamente
siguiente. Así, si desea hacer que una <code>RewriteCond</code> se aplique
a varias <code>RewriteRule</code>s, una técnica posible es negar
esas condiciones y añadir una <code>RewriteRule</code> con una bandera [Skip]. Puede
usar esto para hacer construcciones pseudo if-then-else: La última regla de
la cláusula then se convierte en <code>skip=N</code>, donde N es el
número de reglas en la cláusula else:</p>
<highlight language="config">
# Does the file exist?
RewriteCond "%{REQUEST_FILENAME}" !-f
RewriteCond "%{REQUEST_FILENAME}" !-d
# Create an if-then-else construct by skipping 3 lines if we meant to go to the &quot;else&quot; stanza.
RewriteRule ".?"                  "-" [S=3]

# IF the file exists, then:
    RewriteRule "(.*\.gif)"  "images.php?$1"
    RewriteRule "(.*\.html)" "docs.php?$1"
    # Skip past the &quot;else&quot; stanza.
    RewriteRule ".?"         "-" [S=1]
# ELSE...
    RewriteRule "(.*)"       "404.php?file=$1"
# END
</highlight>

<p>Probablemente sea más fácil lograr este tipo de configuración usando
las directivas <directive type="section">If</directive>, <directive
type="section">ElseIf</directive>, y <directive
type="section">Else</directive> en su lugar.</p>

</section>

<section id="flag_t"><title>T|type</title>
<p>Establece el tipo MIME con el que se enviará la respuesta
resultante. Esto tiene el mismo efecto que la directiva <directive
module="mod_mime">AddType</directive>.</p>

<p>Por ejemplo, podría usar la siguiente técnica para servir código fuente Perl
como texto plano, si se solicita de una manera particular:</p>

<highlight language="config">
# Servir archivos .pl como texto plano
RewriteRule "\.pl$"  "-" [T=text/plain]
</highlight>

<p>O, quizás, si tiene una cámara que produce imágenes jpeg sin
extensiones de archivo, podría forzar que esas imágenes sean servidas con el
tipo MIME correcto por virtud de sus nombres de archivo:</p>

<highlight language="config">
# Los archivos con 'IMG' en el nombre son imágenes jpg.
RewriteRule "IMG"  "-" [T=image/jpg]
</highlight>

<p>Por favor tenga en cuenta que este es un ejemplo trivial, y podría hacerse mejor
usando <directive type="section" module="core">FilesMatch</directive>
en su lugar. Siempre considere las soluciones
alternativas a un problema antes de recurrir a rewrite, que invariablemente
será una solución menos eficiente que las alternativas.</p>

<p>
Si se usa en contexto per-directorio, use solo <code>-</code> (guión)
como la sustitución <em>para toda la ronda de procesamiento de <module>mod_rewrite</module></em>,
de lo contrario el tipo MIME establecido con esta bandera se pierde debido a un
re-procesamiento interno (incluyendo rondas posteriores de procesamiento de <module>mod_rewrite</module>).
La bandera <code>L</code> puede ser útil en este contexto para terminar la
ronda <em>actual</em> de procesamiento de <module>mod_rewrite</module>.</p>
</section>

<section id="flag_unsafe_allow_3f"><title>UnsafeAllow3F</title>
    <p>Establecer esta bandera es necesario para permitir que una reescritura continúe si la
    solicitud HTTP que se está reescribiendo tiene un signo de interrogación codificado, '%3f', y el
    resultado reescrito tiene un '?' en la sustitución. Esto protege contra una URL
    maliciosa que aproveche una captura y re-sustitución del signo de interrogación
    codificado.</p>
</section>
<section id="flag_unsafe_prefix_stat"><title>UnsafePrefixStat</title>
    <p>Establecer esta bandera es necesario en sustituciones de ámbito de servidor
    que comienzan con una variable o referencia inversa y se resuelven a una ruta del sistema de archivos.
    Estas sustituciones no se prefijan con la raíz del documento.
    Esto protege contra una URL maliciosa que cause que la sustitución expandida se
    mapee a una ubicación inesperada del sistema de archivos.</p>

    <p><since>2.5.1</since></p>
</section>
<section id="flag_unc"><title>UNC</title>
    <p>Establecer esta bandera previene la fusión de múltiples barras iniciales,
    como se usa en las rutas UNC de Windows. La bandera no es necesaria cuando la
    sustitución de las reglas comienza con múltiples barras literales.</p>

    <p><since>2.5.1</since></p>
</section>

</manualpage>
