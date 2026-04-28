<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE manualpage SYSTEM "../style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933060 -->

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

<manualpage metafile="access.xml.meta">
  <parentdocument href="./">Rewrite</parentdocument>

<title>Uso de mod_rewrite para control de acceso</title>

<summary>

<p>Este documento complementa la <module>mod_rewrite</module>
<a href="../mod/mod_rewrite.html">documentación de referencia</a>. Describe
cómo puede usar <module>mod_rewrite</module> para controlar el acceso a
varios recursos, y otras técnicas relacionadas.
Esto incluye muchos ejemplos de usos comunes de <module>mod_rewrite</module>,
incluyendo descripciones detalladas de cómo funciona cada uno.</p>

<note type="warning">Tenga en cuenta que muchos de estos ejemplos no funcionarán sin cambios en su
configuración particular del servidor, por lo que es importante que los
entienda, en lugar de simplemente copiar y pegar los ejemplos en su
configuración.</note>

</summary>
<seealso><a href="../mod/mod_rewrite.html">Documentación del módulo</a></seealso>
<seealso><a href="intro.html">Introducción a mod_rewrite</a></seealso>
<seealso><a href="remapping.html">Redirección y remapeo</a></seealso>
<!-- <seealso><a href="access.html">Control de acceso</a></seealso> -->
<seealso><a href="vhosts.html">Hosts virtuales</a></seealso>
<seealso><a href="proxy.html">Proxy</a></seealso>
<seealso><a href="rewritemap.html">Uso de RewriteMap</a></seealso>
<seealso><a href="advanced.html">Técnicas avanzadas</a></seealso>
<seealso><a href="avoid.html">Cuándo no usar mod_rewrite</a></seealso>

    <section id="blocked-inline-images">

      <title>Prohibir el &quot;Hotlinking&quot; de imágenes</title>

      <dl>
        <dt>Descripción:</dt>

        <dd>
          <p>La siguiente técnica prohíbe la práctica de que otros sitios
          incluyan sus imágenes en línea en sus páginas. Esta práctica se
          conoce a menudo como &quot;hotlinking&quot;, y resulta en que
          su ancho de banda se use para servir contenido del sitio de
          otra persona.</p>
        </dd>

        <dt>Solución:</dt>

        <dd>
          <p>Esta técnica se basa en el valor de la
          variable <code>HTTP_REFERER</code>, que es opcional. Como
          tal, es posible que algunas personas eviten esta
          limitación. Sin embargo, la mayoría de los usuarios experimentarán la
          solicitud fallida, lo que debería, con el tiempo, resultar en que la
          imagen sea eliminada del otro sitio.</p>
          <p>Hay varias formas en las que puede manejar esta
          situación.</p>

    <p>En este primer ejemplo, simplemente denegamos la solicitud, si no se
    originó desde una página en nuestro sitio. Para el propósito de este ejemplo,
    asumimos que nuestro sitio es <code>www.example.com</code>.</p>

<!-- TODO: Añadir discusión aquí de por qué tenemos !^$ ahí. -->

<highlight language="config">
RewriteCond "%{HTTP_REFERER}"  "!^$"
RewriteCond "%{HTTP_REFERER}"  "!www.example.com" [NC]
RewriteRule "\.(gif|jpg|png)$" "-"                [F,NC]
</highlight>

    <p>En este segundo ejemplo, en lugar de denegar la solicitud, mostramos
    una imagen alternativa en su lugar.</p>

<highlight language="config">
RewriteCond "%{HTTP_REFERER}"  "!^$"
RewriteCond "%{HTTP_REFERER}"  "!www.example.com"      [NC]
RewriteRule "\.(gif|jpg|png)$" "/images/go-away.png"   [R,NC]
</highlight>

    <p>En el tercer ejemplo, redirigimos la solicitud a una imagen en algún
    otro sitio.</p>

<highlight language="config">
RewriteCond "%{HTTP_REFERER}"  "!^$"
RewriteCond "%{HTTP_REFERER}"  "!www.example.com"                    [NC]
RewriteRule "\.(gif|jpg|png)$" "http://other.example.com/image.gif"  [R,NC]
</highlight>

    <p>De estas técnicas, las dos últimas tienden a ser las más efectivas
    para lograr que la gente deje de hacer hotlinking de sus imágenes, porque
    simplemente no verán la imagen que esperaban ver.</p>

        </dd>

        <dt>Discusión:</dt>

        <dd>
        <p>Si todo lo que desea hacer es denegar el acceso al recurso, en lugar
        de redirigir esa solicitud a otro lugar, esto se puede
        lograr sin el uso de <module>mod_rewrite</module>:</p>

        <highlight language="config">
SetEnvIf Referer example\.com localreferer
&lt;FilesMatch "\.(jpg|png|gif)$"&gt;
    Require env localreferer
&lt;/FilesMatch&gt;
        </highlight>
        </dd>
      </dl>

    </section>

    <section id="blocking-of-robots">

      <title>Bloqueo de Robots</title>

      <dl>
        <dt>Descripción:</dt>

        <dd>
        <p>
        En esta receta, discutimos cómo bloquear solicitudes persistentes de
        un robot o agente de usuario en particular.</p>

        <p>El estándar para exclusión de robots define un archivo,
        <code>/robots.txt</code> que especifica aquellas partes de su
        sitio web donde desea excluir robots. Sin embargo, algunos robots
        no respetan estos archivos.
        </p>

        <p>Tenga en cuenta que hay métodos para lograr esto que no
        usan <module>mod_rewrite</module>. Tenga en cuenta también que cualquier técnica que dependa
        de la cadena <code>USER_AGENT</code> del cliente puede ser evitada
        muy fácilmente, ya que esa cadena puede cambiarse.</p>
        </dd>

        <dt>Solución:</dt>

        <dd>
        <p>Usamos un conjunto de reglas que especifica el directorio a ser
        protegido, y el <code>USER_AGENT</code> del cliente que
        identifica al robot malicioso o persistente.</p>

        <p>En este ejemplo, estamos bloqueando un robot llamado
        <code>NameOfBadRobot</code> de una ubicación
        <code>/secret/files</code>. También puede especificar un rango de
        direcciones IP, si está intentando bloquear ese agente de usuario solo desde
        la fuente particular.</p>

<highlight language="config">
RewriteCond "%{HTTP_USER_AGENT}"   "^NameOfBadRobot"
RewriteCond "%{REMOTE_ADDR}"       "=123\.45\.67\.[8-9]"
RewriteRule "^/secret/files/"      "-"                   [F]
</highlight>
        </dd>

      <dt>Discusión:</dt>

      <dd>
      <p>
        En lugar de usar <module>mod_rewrite</module> para esto, puede lograr el
        mismo resultado usando medios alternativos, como se ilustra aquí:
      </p>
      <highlight language="config">
SetEnvIfNoCase User-Agent ^NameOfBadRobot goaway
&lt;Location "/secret/files"&gt;
    &lt;RequireAll&gt;
        Require all granted
        Require not env goaway
    &lt;/RequireAll&gt;
&lt;/Location&gt;
      </highlight>
      <p>
      Como se indicó anteriormente, esta técnica es trivial de evadir, simplemente
      modificando la cabecera de solicitud <code>USER_AGENT</code>. Si
      está experimentando un ataque sostenido, debería considerar bloquearlo
      a un nivel superior, como en su firewall.
      </p>

      </dd>

      </dl>

    </section>

<section id="host-deny">

  <title>Denegación de Hosts en una Lista de Rechazo</title>

  <dl>
    <dt>Descripción:</dt>

    <dd>
      <p>Deseamos mantener una lista de hosts, similar a
      <code>hosts.deny</code>, y hacer que esos hosts sean bloqueados
      del acceso a nuestro servidor.</p>
    </dd>

    <dt>Solución:</dt>

    <dd>
<highlight language="config">
RewriteEngine on
RewriteMap    hosts-deny  "txt:/path/to/hosts.deny"
RewriteCond   "${hosts-deny:%{REMOTE_ADDR}|NOT-FOUND}" "!=NOT-FOUND" [OR]
RewriteCond   "${hosts-deny:%{REMOTE_HOST}|NOT-FOUND}" "!=NOT-FOUND"
RewriteRule   "^"                                      "-"           [F]
</highlight>

<example>
##<br />
##  hosts.deny<br />
##<br />
##  ¡ATENCIÓN! Esto es un mapa, no una lista, incluso cuando lo tratamos como tal.<br />
##             mod_rewrite lo analiza buscando pares clave/valor, así que al menos un<br />
##             valor ficticio "-" debe estar presente para cada entrada.<br />
##<br />
<br />
193.102.180.41 -<br />
bsdti1.sdm.de  -<br />
192.76.162.40  -<br />
</example>
    </dd>

    <dt>Discusión:</dt>
    <dd>
    <p>
    La segunda RewriteCond asume que tiene HostNameLookups activado,
    de modo que las direcciones IP de los clientes sean resueltas. Si ese no es el
    caso, debería eliminar la segunda RewriteCond, y eliminar la
    bandera <code>[OR]</code> de la primera RewriteCond.
    </p>
    </dd>
  </dl>

</section>

<section id="referer-deflector">

  <title>Deflector basado en Referer</title>

  <dl>
    <dt>Descripción:</dt>

    <dd>
      <p>Redirigir solicitudes basadas en el Referer del cual provino la solicitud,
      con diferentes destinos por Referer.</p>
    </dd>

    <dt>Solución:</dt>

    <dd>
  <p>El siguiente conjunto de reglas usa un archivo de mapa para asociar cada Referer
  con un destino de redirección.</p>

<highlight language="config">
RewriteMap  deflector "txt:/path/to/deflector.map"

RewriteCond "%{HTTP_REFERER}"              !=""
RewriteCond "${deflector:%{HTTP_REFERER}}" =-
RewriteRule "^"                            "%{HTTP_REFERER}" [R,L]

RewriteCond "%{HTTP_REFERER}"              !=""
RewriteCond "${deflector:%{HTTP_REFERER}|NOT-FOUND}" "!=NOT-FOUND"
RewriteRule "^"                            "${deflector:%{HTTP_REFERER}}" [R,L]
</highlight>

      <p>El archivo de mapa lista los destinos de redirección para cada referer, o, si
      simplemente deseamos redirigir de vuelta a donde vinieron, se coloca un "-"
      en el mapa:</p>

<highlight language="config">
##
##  deflector.map
##

http://badguys.example.com/bad/index.html    -
http://badguys.example.com/bad/index2.html   -
http://badguys.example.com/bad/index3.html   http://somewhere.example.com/
</highlight>

    </dd>
  </dl>

</section>

</manualpage>
