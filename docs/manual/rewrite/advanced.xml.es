<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE manualpage SYSTEM "../style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933067 -->

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

<manualpage metafile="advanced.xml.meta">
  <parentdocument href="./">Rewrite</parentdocument>

<title>Técnicas avanzadas con mod_rewrite</title>

<summary>

<p>Este documento complementa la <module>mod_rewrite</module>
<a href="../mod/mod_rewrite.html">documentación de referencia</a>. Proporciona
algunas técnicas avanzadas usando <module>mod_rewrite</module>.</p>

<!--
Cuestiono si algo de lo que queda en este documento califica como
"avanzado". Probablemente es hora de hacer un inventario de los ejemplos que
tenemos en los diversos documentos, y considerar una reorganización del material en este
directorio. De nuevo.
-->

<note type="warning">Tenga en cuenta que muchos de estos ejemplos no funcionarán sin cambios en su
configuración particular del servidor, por lo que es importante que los
entienda, en lugar de simplemente copiar y pegar los ejemplos en su
configuración.</note>

</summary>
<seealso><a href="../mod/mod_rewrite.html">Documentación del módulo</a></seealso>
<seealso><a href="intro.html">Introducción a mod_rewrite</a></seealso>
<seealso><a href="remapping.html">Redirección y remapeo</a></seealso>
<seealso><a href="access.html">Control de acceso</a></seealso>
<seealso><a href="vhosts.html">Hosts virtuales</a></seealso>
<seealso><a href="proxy.html">Proxy</a></seealso>
<seealso><a href="rewritemap.html">Uso de RewriteMap</a></seealso>
<!--<seealso><a href="advanced.html">Técnicas avanzadas</a></seealso>-->
<seealso><a href="avoid.html">Cuándo no usar mod_rewrite</a></seealso>

<section id="sharding">

  <title>Fragmentación basada en URL entre múltiples backends</title>

  <dl>
    <dt>Descripción:</dt>

    <dd>
      <p>Una técnica común para distribuir la carga del
      servidor o el espacio de almacenamiento se llama "fragmentación" (sharding).
      Al usar este método, un servidor front-end usará la
      URL para "fragmentar" consistentemente usuarios u objetos a servidores
      backend separados.</p>
    </dd>

    <dt>Solución:</dt>

    <dd>
      <p>Se mantiene un mapeo, de usuarios a servidores destino, en
      archivos de mapa externos. Tienen este aspecto:</p>

<example>
user1  physical_host_of_user1<br />
user2  physical_host_of_user2<br />
# ... y así sucesivamente
</example>

  <p>Colocamos esto en un archivo <code>map.users-to-hosts</code>. El
    objetivo es mapear;</p>

<example>
/u/user1/anypath
</example>

  <p>a</p>

<example>
http://physical_host_of_user1/u/user/anypath
</example>

      <p>por lo que no es necesario que cada ruta URL sea válida en cada host físico
      backend. El siguiente conjunto de reglas hace esto por nosotros con la ayuda de los
      archivos de mapa, asumiendo que server0 es un servidor predeterminado que se usará si
      un usuario no tiene entrada en el mapa:</p>

<highlight language="config">
RewriteEngine on
RewriteMap    users-to-hosts      "txt:/path/to/map.users-to-hosts"
RewriteRule   "^/u/([^/]+)/?(.*)" "http://${users-to-hosts:$1|server0}/u/$1/$2"
</highlight>
    </dd>
  </dl>

  <p>Consulte la documentación de la directiva <directive module="mod_rewrite">RewriteMap</directive>
  y el <a href="./rewritemap.html">Cómo usar RewriteMap</a>
  para más discusión de la sintaxis de esta directiva.</p>

</section>

<section id="on-the-fly-content">

  <title>Regeneración de Contenido sobre la marcha</title>

  <dl>
    <dt>Descripción:</dt>

    <dd>
      <p>Deseamos generar contenido dinámicamente, pero almacenarlo
      estáticamente una vez que se ha generado. Esta regla verificará la
      existencia del archivo estático, y si no está allí, lo generará.
      Los archivos estáticos pueden eliminarse periódicamente, si se desea (digamos,
      mediante cron) y se regenerarán bajo demanda.</p>
    </dd>

    <dt>Solución:</dt>

    <dd>
      Esto se hace mediante el siguiente conjunto de reglas:

<highlight language="config">
# This example is valid in per-directory context only
RewriteCond "%{REQUEST_URI}"   !-U
RewriteRule "^(.+)\.html$"     "/regenerate_page.cgi"   [PT,L]
</highlight>

    <p>El operador <code>-U</code> determina si la cadena de prueba
    (en este caso, <code>REQUEST_URI</code>) es una URL válida. Lo hace
    mediante una sub-solicitud. En el caso de que esta sub-solicitud falle -
    es decir, el recurso solicitado no existe - esta regla invoca
    el programa CGI <code>/regenerate_page.cgi</code>, que genera
    el recurso solicitado y lo guarda en el directorio de documentos, de modo
    que la próxima vez que se solicite, se pueda servir una copia estática.</p>

    <p>De esta manera, documentos que se actualizan con poca frecuencia pueden servirse en
    forma estática. Si los documentos necesitan actualizarse, pueden eliminarse
    del directorio de documentos, y se regenerarán la
    próxima vez que se soliciten.</p>
    </dd>
  </dl>

</section>

<section id="load-balancing">

  <title>Balanceo de Carga</title>

  <dl>
    <dt>Descripción:</dt>

    <dd>
      <p>Deseamos distribuir aleatoriamente la carga entre varios servidores
      usando <module>mod_rewrite</module>.</p>
    </dd>

    <dt>Solución:</dt>

    <dd>
      <p>Usaremos <directive
      module="mod_rewrite">RewriteMap</directive> y una lista de servidores
      para lograr esto.</p>

<highlight language="config">
RewriteEngine on
RewriteMap  lb       "rnd:/path/to/serverlist.txt"
RewriteRule "^/(.*)" "http://${lb:servers}/$1"     [P,L]
</highlight>

<p><code>serverlist.txt</code> contendrá una lista de los servidores:</p>

<example>
## serverlist.txt<br />
<br />
servers one.example.com|two.example.com|three.example.com<br />
</example>

<p>Si desea que un servidor particular reciba más carga que los
otros, agreguelo más veces a la lista.</p>

   </dd>

   <dt>Discusión</dt>
   <dd>
<p>Apache viene con un módulo de balanceo de carga -
<module>mod_proxy_balancer</module> - que es mucho más flexible y
con más funcionalidades que cualquier cosa que pueda construir usando <module>mod_rewrite</module>.</p>
   </dd>
  </dl>

</section>

<section id="structuredhomedirs">

  <title>Directorios de Usuario Estructurados</title>

  <dl>
    <dt>Descripción:</dt>

    <dd>
      <p>Algunos sitios con miles de usuarios usan una
      disposición de directorio personal estructurada, <em>es decir,</em> cada directorio personal está en un
      subdirectorio que comienza (por ejemplo) con el primer
      carácter del nombre de usuario. Así, <code>/~larry/anypath</code>
      es <code>/home/<strong>l</strong>/larry/public_html/anypath</code>
      mientras que <code>/~waldo/anypath</code> es
      <code>/home/<strong>w</strong>/waldo/public_html/anypath</code>.</p>
    </dd>

    <dt>Solución:</dt>

    <dd>
      <p>Usamos el siguiente conjunto de reglas para expandir las URLs de tilde
      a la disposición anterior.</p>

<highlight language="config">
RewriteEngine on
RewriteRule   "^/~(<strong>([a-z])</strong>[a-z0-9]+)(.*)"  "/home/<strong>$2</strong>/$1/public_html$3"
</highlight>
    </dd>
  </dl>

</section>

<section id="redirectanchors">

  <title>Redireccionando Anclas</title>

  <dl>
    <dt>Descripción:</dt>

    <dd>
    <p>Por defecto, redirigir a un ancla HTML no funciona,
    porque <module>mod_rewrite</module> escapa el carácter <code>#</code>,
    convirtiéndolo en <code>%23</code>. Esto, a su vez, rompe la
    redirección.</p>
    </dd>

    <dt>Solución:</dt>

    <dd>
      <p>Use la bandera <code>[NE]</code> en la
      <code>RewriteRule</code>. NE significa No Escapar.
      </p>
    </dd>

    <dt>Discusión:</dt>
    <dd>Esta técnica por supuesto también funcionará con otros
    caracteres especiales que <module>mod_rewrite</module>, por defecto, codifica en URL.</dd>
  </dl>

</section>

<section id="time-dependent">

  <title>Reescritura Dependiente del Tiempo</title>

  <dl>
    <dt>Descripción:</dt>

    <dd>
      <p>Deseamos usar <module>mod_rewrite</module> para servir contenido diferente basado en
      la hora del día.</p>
    </dd>

    <dt>Solución:</dt>

    <dd>
      <p>Hay muchas variables llamadas <code>TIME_xxx</code>
      para condiciones de reescritura. En conjunto con los patrones
      especiales de comparación lexicográfica <code>&lt;STRING</code>,
      <code>&gt;STRING</code> y <code>=STRING</code> podemos
      hacer redirecciones dependientes del tiempo:</p>

<highlight language="config">
RewriteEngine on
RewriteCond   "%{TIME_HOUR}%{TIME_MIN}" &gt;0700
RewriteCond   "%{TIME_HOUR}%{TIME_MIN}" &lt;1900
RewriteRule   "^foo\.html$"             "foo.day.html" [L]
RewriteRule   "^foo\.html$"             "foo.night.html"
</highlight>

      <p>Esto proporciona el contenido de <code>foo.day.html</code>
      bajo la URL <code>foo.html</code> de
      <code>07:01-18:59</code> y en el tiempo restante el
      contenido de <code>foo.night.html</code>.</p>

      <note type="warning"><module>mod_cache</module>, proxies intermedios
      y navegadores pueden cada uno almacenar en caché las respuestas y causar que cualquiera de las páginas se
      muestre fuera de la ventana de tiempo configurada.
      Se puede usar <module>mod_expires</module> para controlar este
      efecto. Por supuesto, es mucho mejor simplemente servir el
      contenido dinámicamente y personalizarlo basándose en la hora del día.</note>

    </dd>
  </dl>

</section>

<section id="setenvvars">

  <title>Establecer Variables de Entorno Basadas en Partes de la URL</title>

  <dl>
    <dt>Descripción:</dt>

    <dd>
      <p>A veces, queremos mantener algún tipo de estado cuando
      realizamos una reescritura. Por ejemplo, desea tomar nota de que
      ha realizado esa reescritura, para poder verificar más tarde si una
      solicitud llegó a través de esa reescritura. Una forma de hacer esto es estableciendo una
      variable de entorno.</p>
    </dd>

    <dt>Solución:</dt>

    <dd>
      <p>Use la bandera [E] para establecer una variable de entorno.</p>

<highlight language="config">
RewriteEngine on
RewriteRule   "^/horse/(.*)"   "/pony/$1" [E=<strong>rewritten:1</strong>]
</highlight>

    <p>Más adelante en su conjunto de reglas puede verificar esta variable
    de entorno usando una RewriteCond:</p>

<highlight language="config">
RewriteCond "%{ENV:rewritten}"  =1
</highlight>

    <p>Tenga en cuenta que las variables de entorno no sobreviven a una
    redirección externa. Podría considerar usar la bandera [CO] para establecer una
    cookie. Para reescrituras en contexto per-directorio y htaccess, donde la sustitución
    final se procesa como una redirección interna, las variables
    de entorno de la ronda anterior de reescritura se prefijan con
    "REDIRECT_". </p>

    </dd>
  </dl>

</section>

</manualpage>
