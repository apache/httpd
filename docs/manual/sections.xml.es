<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE manualpage SYSTEM "./style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="./style/manual.es.xsl"?>
<!-- English Revision: 151405 -->

<!--
 Copyright 2004-2006 The Apache Software Foundation or it licensors,
 as applicable.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
-->

<manualpage metafile="sections.xml.meta">

<title>Secciones de configuraci&#243;n</title>

<summary> <p> Las directivas presentes en los <a
href="configuring.html">ficheros de configuraci&#243;n</a> pueden ser
de aplicaci&#243;n para todo el servidor, o puede que su
aplicaci&#243;n se limite solamente a determinados directorios,
ficheros, hosts, o URLs. Este documento explica c&#243;mo usar las
secciones de configuraci&#243;n y los ficheros <code>.htaccess</code>
para modificar el &#225;mbito de aplicaci&#243;n de las directivas de
configuraci&#243;n.</p> </summary>

<section id="types"><title>Tipos de secciones de
configuraci&#243;n</title>

<related>
<modulelist>
<module>core</module>
<module>mod_proxy</module>
</modulelist>
<directivelist>
<directive type="section" module="core">Directory</directive>
<directive type="section" module="core">DirectoryMatch</directive>
<directive type="section" module="core">Files</directive>
<directive type="section" module="core">FilesMatch</directive>
<directive type="section" module="core">IfDefine</directive>
<directive type="section" module="core">IfModule</directive>
<directive type="section" module="core">Location</directive>
<directive type="section" module="core">LocationMatch</directive>
<directive type="section" module="mod_proxy">Proxy</directive>
<directive type="section" module="mod_proxy">ProxyMatch</directive>
<directive type="section" module="core">VirtualHost</directive>
</directivelist>
</related>

<p>Exiten dos tipos b&#225;sicos de secciones de
configuraci&#243;n. Por un lado, la mayor&#237;a de las secciones de
configuraci&#243;n se eval&#250;an para cada petici&#243;n que se
recibe y se aplican las directivas que se incluyen en las distintas
secciones solamente a las peticiones que se adec&#250;an a
determinadas caracter&#237;sticas. Por otro lado, las secciones de tipo
<directive type="section" module="core">IfDefine</directive> e
<directive type="section" module="core">IfModule</directive>, se
eval&#250;an solamente al inicio o reinicio del servidor. Si al
iniciar el servidor las condiciones son las adecuadas, las directivas
que incluyen estas secciones se aplicar&#225;n a todas las peticiones
que se reciban. Es caso contrario, esas directivas que incluyen se
ignoran completamente.</p>

<p>Las secciones <directive type="section"
module="core">IfDefine</directive> incluyen directivas que se
aplicar&#225;n solamente si se pasa un determinado par&#225;metro por
l&#237;nea de comandos al ejecutar <program>httpd</program>.  Por
ejemplo, con la siguiente configuraci&#243;n, todas las peticiones
ser&#225;n redireccionadas a otro sitio web solamente si el servidor
se inici&#243; usando <code>httpd -DClosedForNow</code>:</p>

<example>
&lt;IfDefine ClosedForNow&gt;<br />
Redirect / http://otherserver.example.com/<br />
&lt;/IfDefine&gt;
</example>

<p>La secci&#243;n <directive type="section"
module="core">IfModule</directive> es muy parecida. La diferencia
respecto a <directive type="section"
module="core">IfDefine</directive> est&#225; en que incluye directivas
que se aplicar&#225;n solamente si un determinado m&#243;dulo en
particular est&#225; disponible en el servidor. El m&#243;dulo debe
estar compilado est&#225;ticamente en el servidor, o si est&#225;
compilado de forma din&#225;mica ha de ponerse antes una l&#237;nea
<directive module="mod_so">LoadModule</directive> en el fichero de
configuraci&#243;n. Esta directiva debe usarla solamente si necesita
que su fichero de configuraci&#243;n funcione est&#233;n o no
instalados determinados m&#243;dulos. No debe usarla para incluir
directivas que quiera que se apliquen siempre, porque puede suprimir
mensajes de error que pueden ser de mucha utilidad para detectar la
falta de alg&#250;n m&#243;dulo.</p>

<p>En el siguiente ejemplo, la directiva <directive
module="mod_mime_magic">MimeMagicFiles</directive> se aplicar&#225;
solamente si el m&#243;dulo <module>mod_mime_magic</module> est&#225;
disponible.</p>

<example>
&lt;IfModule mod_mime_magic.c&gt;<br />
MimeMagicFile conf/magic<br />
&lt;/IfModule&gt;
</example>

<p>Tanto <directive type="section" module="core">IfDefine</directive>
como <directive type="section" module="core">IfModule</directive>
pueder usarse con condiones negativas anteponiendo al test el
car&#225;cter "!".  Estas secciones tambi&#233;n pueden anidarse para
establecer restricciones m&#225;s complejas.</p>

</section>

<section id="file-and-web"><title>Sistemas de ficheros y espacio
web</title>

<p>Las secciones de configuraci&#243;n usadas con m&#225;s frecuencia
son las que cambian la configuraci&#243;n de &#225;reas del sistema de
ficheros o del espacio web. En primer lugar, es importante comprender
la diferencia que existe entre estos dos conceptos. El sistema de
ficheros es la visi&#243;n de sus discos desde el punto de vista del
sistema operativo. Por ejemplo, en una instalaci&#243;n est&#225;ndar,
Apache estar&#225; en <code>/usr/local/apache2</code> en un sistema
Unix o en <code>"c:/Program Files/Apache Group/Apache2"</code> en un
sistema Windows.  (Tenga en cuenta que con Apache debe usar siempre
barras /, incluso en Windows.)  Por el contrario, el espacio web lo
que presenta el servidor web y que visualiza el cliente. De manera que
la ruta <code>/dir/</code> en el espacio web se corresponde con la
ruta <code>/usr/local/apache2/htdocs/dir/</code> en el sistema de
ficheros de una instalaci&#243;n est&#225;ndar en Unix.  El espacio
web no tiene que tener correspondencia directa con el sistema de
ficheros, porque las p&#225;ginas web pueden generarse de forma
din&#225;mica a partir de bases de datos o partiendo de otras
ubicaciones.</p>

<section id="filesystem"><title>Secciones relacionadas con el sistema
de ficheros</title>

<p>Las secciones <directive type="section"
module="core">Directory</directive> y <directive type="section"
module="core">Files</directive>, junto con sus contrapartes que usan
expresiones regulares, aplican sus directivas a &#225;reas del sistema de
ficheros. Las directivas incluidas en una secci&#243;n <directive
type="section" module="core">Directory</directive> se aplican al
directorio del sistema de ficheros especificado y a sus
subdirectorios. El mismo resultado puede obtenerse usando <a
href="howto/htaccess.html">ficheros .htaccess</a>.  Por ejemplo, en la
siguiente configuraci&#243;n, se activar&#225;n los &#237;ndices de
directorio para el directorio <code>/var/web/dir1</code> y sus
subdirectorios.</p>

<example>
&lt;Directory /var/web/dir1&gt;<br />
Options +Indexes<br />
&lt;/Directory&gt;
</example>

<p>Las directivas incluidas en una secci&#243;n <directive
type="section" module="core">Files</directive> se aplicar&#225;n a
cualquier fichero cuyo nombre se especifique, sin tener en cuenta en
que directorio se encuentra. Por ejemplo, las siguientes directivas de
configuraci&#243;n, cuando se colocan en la secci&#243;n principal del
fichero de configuraci&#243;n, deniegan el acceso a cualquier fichero
llamado <code>private.html</code> sin tener en cuenta de donde se
encuentre.</p>

<example>
&lt;Files private.html&gt;<br />
Order allow,deny<br />
Deny from all<br />
&lt;/Files&gt;
</example>

<p>Para referirse a archivos que se encuentren en un determinado lugar
del sistema de ficheros, se pueden combinar las secciones <directive
type="section" module="core">Files</directive> y <directive
type="section" module="core">Directory</directive>. Por ejemplo, la
siguiente configuraci&#243;n denegar&#225; el acceso a
<code>/var/web/dir1/private.html</code>,
<code>/var/web/dir1/subdir2/private.html</code>,
<code>/var/web/dir1/subdir3/private.html</code>, y cualquier otra
aparici&#243;n de <code>private.html</code> que se encuentre en
<code>/var/web/dir1/</code> o cualquiera de sus subdirectorios.</p>

<example>
&lt;Directory /var/web/dir1&gt;<br />
&lt;Files private.html&gt;<br />
Order allow,deny<br />
Deny from all<br />
&lt;/Files&gt;<br />
&lt;/Directory&gt;
</example>
</section>

<section id="webspace"><title>Secciones relacionadas con el espacio
web</title>

<p>La secci&#243;n <directive type="section"
 module="core">Location</directive> y su contraparte que usa
 expresiones regulares, cambian
 la configuraci&#243;n para el contenido del espacio web. Por ejemplo,
 la siguiente configuraci&#243;n evita que se acceda a cualquier URL
 que empiece por /private.  En concreto, se aplicar&#225; a
 peticiones que vayan dirigidas a
 <code>http://yoursite.example.com/private</code>,
 <code>http://yoursite.example.com/private123</code>, y a
 <code>http://yoursite.example.com/private/dir/file.html</code>
 as&#237; como
 tambi&#233;n a cualquier otra petici&#243;n que comience por
 <code>/private</code>.</p>

<example>
&lt;Location /private&gt;<br />
Order Allow,Deny<br />
Deny from all<br />
&lt;/Location&gt;
</example>

<p>La secci&#243;n <directive type="section"
module="core">Location</directive> puede no tener nada que ver con el
sistema de ficheros. Por ejemplo, el siguiente ejemplo muestra como
asociar una determinada URL a un handler interno de Apache del
m&#243;dulo <module>mod_status</module>.  No tiene por qu&#233;
existir ning&#250;n fichero <code>server-status</code> en el sistema
de ficheros.</p>

<example>
&lt;Location /server-status&gt;<br />
SetHandler server-status<br />
&lt;/Location&gt;
</example>
</section>

<section id="wildcards"><title>Caracteres comod&#237;n y expresiones
regulares</title>

<p>Las secciones <directive type="section"
module="core">Directory</directive>, <directive type="section"
module="core">Files</directive>, y <directive type="section"
module="core">Location</directive> pueden usar caracteres comod&#237;n
del tipo <code>fnmatch</code> de la librer&#237;a est&#225;ndar de C.
El car&#225;cter "*" equivale a cualquier secuencia de caracteres, "?"
equivale a cualquier car&#225;cter individual, y "[<em>seq</em>]"
equivale a cualquier car&#225;cter en <em>seq</em>.  Ning&#250;n
car&#225;cter comod&#237;n equivale a"/", que debe siempre
especificarse expl&#237;citamente.</p>

<p>Si necesita un sistema de equivalencias m&#225;s flexible, cada
secci&#243;n tiene una contraparte que acepta <a
href="glossary.html#regex">expresiones regulares</a> compatibles con
Perl: <directive type="section"
module="core">DirectoryMatch</directive>, <directive type="section"
module="core">FilesMatch</directive>, y <directive type="section"
module="core">LocationMatch</directive>. Consulte la secci&#243;n
sobre la fusi&#243;n de secciones de configuraci&#243;n para ver la
forma en que las secciones expresiones regulares cambian el modo en
que se aplican las directivas.</p>

<p>Abajo se muestra un ejemplo en el que una secci&#243;n de
configuraci&#243;n que usa caracteres comod&#237;n en lugar de una
expresi&#243;n regular modifica la configuraci&#243;n de todos los
directorios de usuario:</p>

<example>
&lt;Directory /home/*/public_html&gt;<br />
Options Indexes<br />
&lt;/Directory&gt;
</example>

<p>Usando expresiones regulares, podemos denegar el acceso a muchos
tipos ficheros de im&#225;genes de una sola vez:</p>

<example>
&lt;FilesMatch \.(?i:gif|jpe?g|png)$&gt;<br /> 
Order allow,deny<br />
Deny from all<br /> 
&lt;/FilesMatch&gt; 
</example>

</section>

<section id="whichwhen"><title>Qu&#233; usar en cada momento</title>

<p>Decidir cuando hay que usar secciones que se apliquen sobre el
sistema de ficheros y cuando usar secciones que se apliquen sobre el
espacio web es bastante f&#225;cil. Cuando se trata de directivas que
se aplican a objetos que residen en el sistema de ficheros, siempre se
deben usar <directive type="section"
module="core">Directory</directive> o <directive type="section"
module="core">Files</directive>.  Cuando se trata de directivas que se
aplican a objetos que no residen en el sistema de ficheros (por
ejemplo una p&#225;gina web generada a partir de una base de datos),
se usa <directive type="section"
module="core">Location</directive>.</p>

<p>Es importante no usar nunca <directive type="section"
module="core">Location</directive> cuando se trata de restringir el
acceso a objetos en el sistema de ficheros. Esto se debe a que varias
URLs diferentes pueden corresponderse con una misma ubicaci&#243;n en
el sistema de ficheros, haciendo que la restricci&#243;n pueda ser
evitada. Por ejemplo, considere la siguiente configuraci&#243;n:</p>

<example>
&lt;Location /dir/&gt;<br />
Order allow,deny<br />
Deny from all<br />
&lt;/Location&gt;
</example>

<p>La restricci&#243;n funciona si se produce una petici&#243;n a
<code>http://yoursite.example.com/dir/</code>.  Pero, &#191;qu&#233;
ocurrir&#237;a si se trata de un sistema de ficheros que no distingue
may&#250;sculas de min&#250;sculas? Entonces, la restricci&#243;n que
ha establecido podr&#237;a evitarse f&#225;cilmente haciendo una
peticion a <code>http://yoursite.example.com/DIR/</code>.  Una
secci&#243;n <directive type="section"
module="core">Directory</directive> por el contrario, se aplicar&#225;
a cualquier contenido servido desde esa ubicaci&#243;n,
independientemente de c&#243;mo se llame. (Una excepci&#243;n son los
enlaces del sistema de ficheros. El mismo directorio puede ser
colocado en m&#225;s de una ubicaci&#243;n del sistema de ficheros
usando enlaces simb&#243;licos.  La secci&#243;n <directive
type="section" module="core">Directory</directive> seguir&#225; los
enlaces simb&#243;licos sin resetear la ruta de fichero (resetting the
pathname). Por tanto, para conseguir el mayor nivel de seguridad, los
enlaces simb&#243;licos deben desactivarse con la directiva <directive
module="core">Options</directive> correspondiente.)</p>

<p>En el caso de que piense que nada de esto le afecta porque usa un
sistema de ficheros que distingue may&#250;sculas de min&#250;sculas,
recuerde que hay muchas otras maneras de hacer corresponder
m&#250;ltiples direcciones del espacio web con una misma
ubicaci&#243;n del sistema de ficheros. Por tanto, use las secciones
de configuraci&#243;n que se aplican al sistema de ficheros siempre
que sea posible.  Hay, sin embargo, una excepci&#243;n a esta
regla. Poner restricciones de configuraci&#243;n en una secci&#243;n
<code>&lt;Location /&gt;</code> es completamente seguro porque estas
secciones se aplicar&#225;n a todas las peticiones independientemente
de la URL espec&#237;fica que se solicite.</p> </section>

</section>

<section id="virtualhost"><title>Hosts virtuales</title>

<p>El contenedor <directive type="section"
module="core">VirtualHost</directive> agrupa directivas que se
aplicar&#225;n a hosts espec&#237;ficos. Esto es &#250;til cuando se
sirven varios hosts con una misma m&#225;quina y con una
configuraci&#243;n diferente cada uno. Para m&#225;s informaci&#243;n,
consulte la <a href="vhosts/">documentaci&#243;n sobre hosts
virtuales</a>.</p> </section>

<section id="proxy"><title>Proxy</title>

<p>Las secciones <directive type="section"
module="mod_proxy">Proxy</directive> y <directive type="section"
module="mod_proxy">ProxyMatch</directive> aplican las directivas de
configuraci&#243;n que engloban solo a los sitios accedidos a
trav&#233;s del servidor proxy del m&#243;dulo
<module>mod_proxy</module> que tengan equivalencia con la URL
especificada. Por ejemplo, la siguiente configuraci&#243;n
evitar&#225; que se use el servidor proxy para acceder al sitio web
<code>cnn.com</code>.</p>

<example>
&lt;Proxy http://cnn.com/*&gt;<br />
Order allow,deny<br />
Deny from all<br />
&lt;/Proxy&gt;
</example>
</section>

<section id="whatwhere"><title>&#191;Qu&#233; directivas se pueden
usar?</title>

<p>Para ver que directivas son las que se pueden usar en cada
secci&#243;n de configuraci&#243;n, consulte el <a
href="mod/directive-dict.html#Context">Context</a> de la directiva.
Todas las directivas que est&#225; permitido usar en las secciones
<directive type="section" module="core">Directory</directive> se
pueden usar tambi&#233;n en las secciones <directive type="section"
module="core">DirectoryMatch</directive>, <directive type="section"
module="core">Files</directive>, <directive type="section"
module="core">FilesMatch</directive>, <directive type="section"
module="core">Location</directive>, <directive type="section"
module="core">LocationMatch</directive>, <directive type="section"
module="mod_proxy">Proxy</directive>, y <directive type="section"
module="mod_proxy">ProxyMatch</directive>. Sin embargo, hay algunas
excepciones:</p>

<ul> <li>La directiva <directive
module="core">AllowOverride</directive> funciona en las secciones
<directive type="section" module="core">Directory</directive>.</li>

<li>Las directivas <directive module="core">Options</directive>
<code>FollowSymLinks</code> y <code>SymLinksIfOwnerMatch</code>
<directive module="core">Options</directive> funcionan solo en las
secciones <directive type="section"
module="core">Directory</directive> y en los ficheros
<code>.htaccess</code>.</li>

<li>La direcitva <directive module="core">Options</directive> no puede
ser usada en secciones <directive type="section"
module="core">Files</directive> y <directive type="section"
module="core">FilesMatch</directive>.</li>
</ul>
</section>

<section id="mergin"><title>&#191;C&#243;mo se fusionan las distintas
secciones?</title>

<p>Las secciones de configuraci&#243;n se aplican en un determinado
orden. Como este orden puede tener efectos significativos en como se
interpretan las directivas de configuraci&#243;n, es importante
entender c&#243;mo funciona este proceso.</p>

    <p>El orden de fusi&#243;n es el siguiente:</p>

    <ol>
      <li> <directive type="section"
      module="core">Directory</directive> (excepto expresiones
      regulares) y <code>.htaccess</code> simult&#225;neamente (si el
      uso de <code>.htaccess</code> est&#225; permitido, prevaleciendo
      sobre <directive type="section"
      module="core">Directory</directive>)</li>

      <li><directive type="section" module="core">DirectoryMatch</directive>
      (y <code>&lt;Directory ~&gt;</code>)</li>

      <li><directive type="section" module="core">Files</directive> y
      <directive type="section" module="core">FilesMatch</directive>
      simult&#225;neamente</li>

      <li><directive type="section" module="core">Location</directive>
      y <directive type="section"
      module="core">LocationMatch</directive>
      simult&#225;neamente</li>
    </ol>

    <p>Aparte de <directive type="section"
    module="core">Directory</directive>, cada grupo se procesa en el
    orden en que aparezca en los ficheros de configuraci&#243;n.
    <directive type="section" module="core">Directory</directive>
    (grupo 1 arriba) se procesa empezando por los componentes de la
    ruta al directorio m&#225;s cortos. Por ejemplo,
    <code>&lt;Directory
    /var/web/dir&gt;</code> se procesar&#225; antes de
    <code>&lt;Directory /var/web/dir/subdir&gt;</code>. Si hay que
    aplicar varias secciones <directive type="section"
    module="core">Directory</directive> a un mismo directorio, se
    aplican en el orden en que aparezcan en el fichero de
    configuraci&#243;n. Las configuraciones incluidas mediante la
    directiva <directive module="core">Include</directive> se
    tratar&#225;n como si estuvieran dentro del fichero de
    configuraci&#243;n principal en lugar de la secci&#243;n
    <directive module="core">Include</directive>.</p>

    <p>Las secciones incluidas dentro de secciones <directive
    type="section" module="core">VirtualHost</directive> se aplican
    <em>despu&#233;s de</em> las correspondientes secciones fuera
    de la definici&#243;n del host virtual. Esto permite que la
    configuraci&#243;n especificada para los hosts virtuales pueda
    prevalecer sobre la configuraci&#243;n del servidor principal.</p>

    <p>Las secciones que aparecen despu&#233;s prevalecen sobre las
    que aparecen antes.</p>

<note><title>Nota t&#233;cnica.</title> Previamente a la fase de
      traducci&#243;n de nombres (en la que se analizan los
      <code>Aliases</code> y <code>DocumentRoots</code> para calcular
      las correspondencias entre URLs y nombres de ficheros) se
      ejecuta una secuencia
      <code>&lt;Location&gt;</code>/<code>&lt;LocationMatch&gt;</code>. Los
      resultados de esta secuencia se desechan despu&#233;s de 
      ejecutar la traducci&#243;n.  </note>

<section id="merge-examples"><title>Algunos ejemplos</title>

<p>Abajo se muestra un ejemplo para que se vea claramente cu&#225;l es
el orden de fusi&#243;n. Asumiendo que todas las secciones se aplican
a la petici&#243;n, las de este ejemplo se aplicar&#237;an en el orden
A &gt; B &gt; C &gt; D &gt; E.</p>

<example>
&lt;Location /&gt;<br />
E<br />
&lt;/Location&gt;<br />
<br />
&lt;Files f.html&gt;<br />
D<br />
&lt;/Files&gt;<br />
<br />
&lt;VirtualHost *&gt;<br />
&lt;Directory /a/b&gt;<br />
B<br />
&lt;/Directory&gt;<br />
&lt;/VirtualHost&gt;<br />
<br />
&lt;DirectoryMatch "^.*b$"&gt;<br />
C<br />
&lt;/DirectoryMatch&gt;<br />
<br />
&lt;Directory /a/b&gt;<br />
A<br />
&lt;/Directory&gt;<br />
<br />
</example>

<p>A continuaci&#243;n se muestra un ejemplo m&#225;s concreto.
Independientemente de las restricciones de acceso que se hayan
establecido en las secciones <directive module="core"
type="section">Directory</directive>, la secci&#243;n <directive
module="core" type="section">Location</directive> ser&#225; evaluada
al final y se permitir&#225; acceso sin restricciones al servidor.  En
otras palabras, el orden de fusi&#243;n es importante, de modo que
ponga atenci&#243;n.</p>

<example>
&lt;Location /&gt;<br /> Order deny,allow<br /> Allow from all<br />
&lt;/Location&gt;<br /> <br /> 
# Esta secci&#243;n &lt;Directory&gt; no tendr&#225; efecto<br /> 
&lt;Directory /&gt;<br /> 
Order allow,deny<br /> 
Allow from all<br /> 
Deny from badguy.example.com<br /> 
&lt;/Directory&gt;
</example>

</section>

</section>
</manualpage>

