<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE manualpage SYSTEM "../style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933071:1933622 (outdated) -->

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

<manualpage metafile="avoid.xml.meta">
  <parentdocument href="./">Rewrite</parentdocument>

<title>Cuándo no usar mod_rewrite</title>

<summary>

<p>Este documento complementa la <module>mod_rewrite</module>
<a href="../mod/mod_rewrite.html">documentación de referencia</a>. Describe
quizás uno de los conceptos más importantes sobre <module>mod_rewrite</module> - concretamente,
cuándo evitar usarlo.</p>

<p><module>mod_rewrite</module> debería considerarse como último recurso, cuando otras
alternativas resultan insuficientes. Usarlo cuando hay alternativas más simples
lleva a configuraciones que son confusas, frágiles y
difíciles de mantener. Entender qué otras alternativas están disponibles es
un paso muy importante hacia el dominio de <module>mod_rewrite</module>.</p>

<p>Tenga en cuenta que muchos de estos ejemplos no funcionarán sin cambios en su
configuración particular del servidor, por lo que es importante que los
entienda, en lugar de simplemente copiar y pegar los ejemplos en su
configuración.</p>

<p>La situación más común en la que <module>mod_rewrite</module> es
la herramienta correcta es cuando la mejor solución requiere acceso a los
archivos de configuración del servidor, y usted no tiene ese acceso. Algunas
directivas de configuración solo están disponibles en el archivo de configuración
del servidor. Así que si está en una situación de alojamiento donde solo tiene archivos .htaccess
con los que trabajar, puede necesitar recurrir a
<module>mod_rewrite</module>.</p>

</summary>
<seealso><a href="../mod/mod_rewrite.html">Documentación del módulo</a></seealso>
<seealso><a href="intro.html">Introducción a mod_rewrite</a></seealso>
<seealso><a href="remapping.html">Redirección y remapeo</a></seealso>
<seealso><a href="access.html">Control de acceso</a></seealso>
<seealso><a href="vhosts.html">Hosts virtuales</a></seealso>
<seealso><a href="proxy.html">Proxy</a></seealso>
<seealso><a href="rewritemap.html">Uso de RewriteMap</a></seealso>
<seealso><a href="advanced.html">Técnicas avanzadas</a></seealso>
<!--<seealso><a href="avoid.html">Cuándo no usar mod_rewrite</a></seealso>-->

<section id="redirect">
<title>Redirección Simple</title>

<p><module>mod_alias</module> proporciona las directivas <directive
module="mod_alias">Redirect</directive> y <directive
module="mod_alias">RedirectMatch</directive>, que proporcionan un
medio para redirigir una URL a otra. Este tipo de redirección simple de
una URL, o una clase de URLs, a otro lugar, debería realizarse
usando estas directivas en lugar de <directive
module="mod_rewrite">RewriteRule</directive>. <code>RedirectMatch</code>
le permite incluir una expresión regular en sus criterios de redirección,
proporcionando muchos de los beneficios de usar <code>RewriteRule</code>.</p>

<p>Un uso común de <code>RewriteRule</code> es redirigir toda una
clase de URLs. Por ejemplo, todas las URLs en el directorio <code>/one</code>
deben ser redirigidas a <code>http://one.example.com/</code>, o quizás
todas las solicitudes <code>http</code> deben ser redirigidas a
<code>https</code>.</p>

<p>Estas situaciones se manejan mejor con la directiva <code>Redirect</code>.
Recuerde que <code>Redirect</code> preserva la información de
ruta. Es decir, una redirección para una URL <code>/one</code> también
redirigirá todas las URLs bajo ella, como <code>/one/two.html</code>
y <code>/one/three/four.html</code>.</p>

<p>Para redirigir URLs bajo <code>/one</code> a
<code>http://one.example.com</code>, haga lo siguiente:</p>

<highlight language="config">
Redirect "/one/" "http://one.example.com/"
</highlight>

<p>Para redirigir un nombre de host a otro, por ejemplo
<code>example.com</code> a <code>www.example.com</code>, vea la
receta de <a href="remapping.html#canonicalhost">Nombres de Host Canónicos</a>.</p>

<p>Para redirigir URLs <code>http</code> a <code>https</code>, haga lo
siguiente:</p>

<highlight language="config">
&lt;VirtualHost *:80&gt;
    ServerName www.example.com
    Redirect "/" "https://www.example.com/"
&lt;/VirtualHost&gt;

&lt;VirtualHost *:443&gt;
    ServerName www.example.com
    # ... la configuración SSL va aquí
&lt;/VirtualHost&gt;
</highlight>

<p>El uso de <code>RewriteRule</code> para realizar esta tarea puede ser
apropiado si hay otras directivas <code>RewriteRule</code> en
el mismo ámbito. Esto se debe a que, cuando hay directivas <code>Redirect</code>
y <code>RewriteRule</code> en el mismo ámbito, las
directivas <code>RewriteRule</code> se ejecutarán primero, independientemente del
orden de aparición en el archivo de configuración.</p>

<p>En el caso de la redirección de <em>http-a-https</em>, el uso de
<code>RewriteRule</code> sería apropiado si no tiene acceso
al archivo de configuración principal del servidor, y está obligado a realizar esta
tarea en un archivo <code>.htaccess</code> en su lugar.</p>

</section>

<section id="alias"><title>Alias de URL</title>
<p>La directiva <directive module="mod_alias">Alias</directive>
proporciona mapeo de un URI a un directorio - generalmente un directorio fuera
de su <directive module="core">DocumentRoot</directive>. Aunque es
posible realizar este mapeo con <module>mod_rewrite</module>,
<directive module="mod_alias">Alias</directive> es el método preferido, por
razones de simplicidad y rendimiento.</p>

<example><title>Usando Alias</title>
<highlight language="config">
Alias "/cats" "/var/www/virtualhosts/felines/htdocs"
</highlight>
</example>

<p>
El uso de <module>mod_rewrite</module> para realizar este mapeo puede ser
apropiado cuando no tiene acceso a los archivos de configuración
del servidor. Alias solo puede usarse en contexto de servidor o virtualhost, y no
en un archivo <code>.htaccess</code>.
</p>

<p>Los enlaces simbólicos serían otra forma de lograr lo mismo, si
tiene <code>Options FollowSymLinks</code> habilitado en su
servidor.</p>
</section>

<section id="vhosts"><title>Alojamiento Virtual</title>
<p>Aunque es posible manejar <a href="vhosts.html">hosts virtuales
con mod_rewrite</a>, rara vez es la forma correcta. Crear bloques
<directive module="core" type="section">VirtualHost</directive> individuales es
casi siempre la forma correcta de proceder. En el
caso de que tenga un número enorme de hosts virtuales, considere usar
<module>mod_vhost_alias</module> para crear estos hosts automáticamente.</p>

<p>Módulos como <module>mod_macro</module> también son
útiles para crear un gran número de hosts virtuales dinámicamente.</p>

<p>Usar <module>mod_rewrite</module> para la creación de hosts virtuales puede ser
apropiado si está usando un servicio de alojamiento que no le proporciona
acceso a los archivos de configuración del servidor, y por lo tanto está
restringido a la configuración usando archivos <code>.htaccess</code>.</p>

<p>Vea el documento de <a href="vhosts.html">hosts virtuales con mod_rewrite</a>
para más detalles sobre cómo podría lograr esto si aún
parece ser el enfoque correcto.</p>

</section>

<section id="proxy"><title>Proxy Simple</title>

<p><directive module="mod_rewrite">RewriteRule</directive> proporciona la bandera <a
href="flags.html#flag_p">[P]</a> para pasar URIs reescritas a través de
<module>mod_proxy</module>.</p>

<highlight language="config">
RewriteRule "^/?images(.*)" "http://imageserver.local/images$1" [P]
</highlight>

<p>Sin embargo, en muchos casos, cuando no hay necesidad real de coincidencia
de patrones, como en el ejemplo mostrado arriba, la directiva <directive
module="mod_proxy">ProxyPass</directive> es una mejor opción.
El ejemplo aquí podría expresarse como:</p>

<highlight language="config">
ProxyPass "/images/" "http://imageserver.local/images/"
</highlight>

<p>Tenga en cuenta que ya sea que use <directive
module="mod_rewrite">RewriteRule</directive> o <directive
module="mod_proxy">ProxyPass</directive>, todavía necesitará usar la
directiva <directive module="mod_proxy">ProxyPassReverse</directive> para
capturar redirecciones emitidas por el servidor backend:</p>

<highlight language="config">
ProxyPassReverse "/images/" "http://imageserver.local/images/"
</highlight>

<p>Puede necesitar usar <code>RewriteRule</code> en su lugar cuando hay
otras <code>RewriteRule</code>s en efecto en el mismo ámbito, ya que una
<code>RewriteRule</code> generalmente tendrá efecto antes que un
<code>ProxyPass</code>, y por lo tanto puede anticiparse a lo que está intentando
lograr.</p>

</section>

<section id="setenv"><title>Prueba de Variables de Entorno</title>

<p><module>mod_rewrite</module> se usa frecuentemente para tomar una acción particular
basada en la presencia o ausencia de una variable de entorno particular
o cabecera de solicitud. Esto puede hacerse de manera más eficiente usando la
directiva <directive module="core" type="section">If</directive>.</p>

<p>Considere, por ejemplo, el escenario común donde
<directive>RewriteRule</directive> se usa para imponer un nombre de
host canónico, como <code>www.example.com</code> en lugar de
<code>example.com</code>. Esto puede hacerse usando la directiva <directive
module="core" type="section">If</directive>, como se muestra aquí:</p>

<highlight language="config">
&lt;If "req('Host') != 'www.example.com'"&gt;
    Redirect "/" "http://www.example.com/"
&lt;/If&gt;
</highlight>

<p>Esta técnica puede usarse para tomar acciones basadas en cualquier cabecera de
solicitud, cabecera de respuesta o variable de entorno, reemplazando
<module>mod_rewrite</module> en muchos escenarios comunes.</p>

<p>Vea especialmente la <a href="../expr.html">documentación de evaluación
de expresiones</a> para una visión general de qué tipos de expresiones puede
usar en secciones <directive module="core" type="section">If</directive>,
y en ciertas otras directivas.</p>

</section>

</manualpage>
