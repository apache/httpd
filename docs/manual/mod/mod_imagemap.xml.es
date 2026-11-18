<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1936574 -->
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

<modulesynopsis metafile="mod_imagemap.xml.meta">

<name>mod_imagemap</name>
<description>Procesamiento de mapas de imagen en el lado del servidor</description>
<status>Deprecated</status>
<sourcefile>mod_imagemap.c</sourcefile>
<identifier>imagemap_module</identifier>

<summary>
    <p>Este módulo procesa archivos <code>.map</code>, sustituyendo
    así la funcionalidad del programa CGI <code>imagemap</code>. Cualquier
    directorio o tipo de documento configurado para usar el
    manejador <code>imap-file</code> (usando ya sea
    <directive module="mod_mime">AddHandler</directive> o
    <directive module="core">SetHandler</directive>)
    será procesado por este módulo.</p>

    <p>La siguiente directiva activará los archivos terminados en
    <code>.map</code> como archivos de mapa de imagen:</p>

    <highlight language="config">
AddHandler imap-file map
    </highlight>

    <p>Tenga en cuenta que lo siguiente todavía es compatible:</p>

    <highlight language="config">
AddType application/x-httpd-imap map
    </highlight>

    <p>Sin embargo, estamos intentando eliminar progresivamente los "tipos
    MIME mágicos", por lo que estamos marcando este método como obsoleto.</p>
</summary>

<section id="features"><title>Nuevas características</title>

    <p>El módulo imagemap añade algunas características nuevas que no
    eran posibles con los programas de mapas de imagen distribuidos
    anteriormente.</p>

    <ul>
      <li>Referencias de URL relativas a la información de Referer.</li>

      <li>Asignación por defecto de <code>&lt;base&gt;</code> a través de una nueva
      directiva de mapa, <code>base</code>.</li>

      <li>No es necesario el archivo <code>imagemap.conf</code>.</li>

      <li>Referencias de puntos.</li>

      <li>Generación configurable de menús de mapas de imagen.</li>
    </ul>
</section>

<section id="imapfile"><title>Archivo de mapa de imagen</title>

    <p>Las líneas de los archivos de mapa de imagen pueden tener uno de
    varios formatos:</p>

    <example>
      directiva valor [<var>x</var>,<var>y</var> ...]<br />
      directiva valor "<var>Texto del menú</var>" [<var>x</var>,<var>y</var>
      ...]<br />
      directiva valor <var>x</var>,<var>y</var> ... "<var>Texto del menú</var>"
    </example>

    <p>La directiva es una de <code>base</code>,
    <code>default</code>, <code>poly</code>, <code>circle</code>,
    <code>rect</code> o <code>point</code>. El valor es una
    URL absoluta o relativa, o uno de los valores especiales listados
    a continuación. Las coordenadas son pares
    <code><var>x</var>,<var>y</var></code> separados por espacios en
    blanco. El texto entre comillas se usa como el texto del
    enlace si se genera un menú de mapa de imagen. Las líneas que comienzan
    con '#' son comentarios.</p>

    <section id="imapfile.directives"><title>Directivas del archivo de mapa de imagen</title>
      <p>Hay seis directivas permitidas en el archivo de mapa de imagen. Las
      directivas pueden aparecer en cualquier orden, pero se procesan en el
      orden en que se encuentran en el archivo de mapa de imagen.</p>

      <dl>
      <dt>Directiva <code>base</code></dt>

      <dd><p>Tiene el efecto de <code>&lt;base href="<var>valor</var>"&gt;
      </code>. Las URL no absolutas del archivo de mapa se toman relativas
      a este valor. La directiva <code>base</code> tiene prioridad sobre
      <directive module="mod_imagemap">ImapBase</directive> tal y como se
      establece en un archivo <code>.htaccess</code> o en los archivos de
      configuración del servidor. En ausencia de una directiva de
      configuración <directive>ImapBase</directive>, <code>base</code> toma
      por defecto el valor <code>http://server_name/</code>.</p>
      <p><code>base_uri</code> es sinónimo de <code>base</code>.
      Tenga en cuenta que una barra final en la URL es significativa.</p></dd>

      <dt>Directiva <code>default</code></dt>

      <dd>La acción que se lleva a cabo si las coordenadas proporcionadas no
      encajan en ninguna de las directivas <code>poly</code>, <code>circle</code> o
      <code>rect</code>, y no hay
      directivas <code>point</code>. Por defecto es <code>nocontent</code>
      en ausencia de un valor de configuración <directive module="mod_imagemap"
      >ImapDefault</directive>, lo que provoca que se devuelva un código de
      estado <code>204 No Content</code>. El cliente
      debería mantener visualizada la misma página.</dd>

      <dt>Directiva <code>poly</code></dt>

      <dd>Toma entre tres y cien puntos, y se obedece si las
      coordenadas seleccionadas por el usuario caen dentro del polígono definido por
      estos puntos.</dd>

      <dt><code>circle</code></dt>

      <dd>Toma las coordenadas del centro de un círculo y un punto sobre
      el círculo. Se obedece si el punto seleccionado por el usuario está dentro del
      círculo.</dd>

      <dt>Directiva <code>rect</code></dt>

      <dd>Toma las coordenadas de dos esquinas opuestas de un
      rectángulo. Se obedece si el punto seleccionado está dentro de este
      rectángulo.</dd>

      <dt>Directiva <code>point</code></dt>

      <dd>Toma un único punto. La directiva point más cercana al
      punto seleccionado por el usuario se obedece si no se satisface ninguna otra
      directiva. Tenga en cuenta que <code>default</code> no se
      seguirá si hay presente una directiva <code>point</code> y
      se dan coordenadas válidas.</dd>
      </dl>
    </section>

    <section id="imapfile.values"><title>Valores</title>

      <p>Los valores de cada una de las directivas pueden ser cualquiera de
      los siguientes:</p>

      <dl>
      <dt>una URL</dt>

      <dd><p>La URL puede ser una URL relativa o absoluta. Las URL relativas
      pueden contener la sintaxis '..' y se resolverán en relación a
      el valor de <code>base</code>.</p>
      <p><code>base</code> por sí mismo no se resolverá según el
      valor actual. Una instrucción <code>base mailto:</code> sí
      funcionará correctamente.</p></dd>

      <dt><code>map</code></dt>

      <dd>Equivalente a la URL del propio archivo de mapa de imagen. No
      se envían coordenadas con esto, por lo que se generará un menú a menos que
      <directive module="mod_imagemap">ImapMenu</directive> esté establecido en
      <code>none</code>.</dd>

      <dt><code>menu</code></dt>
      <dd>Sinónimo de <code>map</code>.</dd>

      <dt><code>referer</code></dt>

      <dd>Equivalente a la URL del documento que hace referencia. Por defecto
      es <code>http://servername/</code> si no estaba presente ninguna cabecera
      <code>Referer:</code>.</dd>

      <dt><code>nocontent</code></dt>

      <dd>Envía un código de estado <code>204 No Content</code>,
      indicando al cliente que mantenga visualizada la misma página. Válido para
      todo excepto <code>base</code>.</dd>

      <dt><code>error</code></dt>

      <dd>Falla con un <code>500 Server Error</code>. Válido para todo
      excepto <code>base</code>, aunque algo absurdo para cualquier cosa que no sea
      <code>default</code>.</dd>
      </dl>
    </section>

    <section id="imapfile.coords"><title>Coordenadas</title>

      <dl>
      <dt><code>0,0 200,200</code></dt>

      <dd>Una coordenada consiste en un valor <var>x</var> y un valor
      <var>y</var> separados por una coma. Las coordenadas se separan
      entre sí por espacios en blanco. Para adaptarse a la forma en que Lynx
      gestiona los mapas de imagen, si un usuario selecciona la coordenada
      <code>0,0</code>, se trata como si no se hubiera seleccionado
      ninguna coordenada.</dd>
      </dl>

    </section>

    <section id="imapfile.quotedtext"><title>Texto entre comillas</title>

      <dl>
      <dt><code>"<var>Texto del menú</var>"</code></dt>

      <dd><p>Después del valor o después de las coordenadas, la línea
      opcionalmente puede contener texto entre comillas dobles. Esta cadena
      se usa como texto del enlace si se genera un
      menú:</p>

      <example>
        &lt;a href="http://example.com/"&gt;<var>Texto del menú</var>&lt;/a&gt;
      </example>

      <p>Si no hay presente ningún texto entre comillas, se usará como texto
      el nombre del enlace:</p>

      <example>
        &lt;a href="http://example.com/"&gt;http://example.com&lt;/a&gt;
      </example>

      <p>Si quiere usar comillas dobles dentro de este texto, tiene que
      escribirlas como <code>&amp;quot;</code>.</p></dd>
      </dl>

    </section>
</section>

<section id="example"><title>Ejemplo de archivo de mapa</title>

    <example>
      #Los comentarios se imprimen en un menú 'formatted' o 'semiformatted'.<br />
      #Y pueden contener etiquetas html. &lt;hr&gt;<br />
      base referer<br />
      poly map "¿Puedo tener un menú, por favor?" 0,0 0,10 10,10 10,0<br />
      rect .. 0,0 77,27 "el directorio del referer"<br />
      circle http://www.inetnebr.example.com/lincoln/feedback/ 195,0 305,27<br />
      rect another_file "en el mismo directorio que el referer" 306,0 419,27<br />
      point http://www.zyzzyva.example.com/ 100,100<br />
      point http://www.tripod.example.com/ 200,200<br />
      rect mailto:nate@tripod.example.com 100,150 200,0 "¿Errores?"<br />
    </example>

</section>

<section id="referencing"><title>Haciendo referencia a su archivo de mapa</title>

    <example><title>Ejemplo HTML</title>
      &lt;a href="/maps/imagemap1.map"&gt;<br />
      <indent>
        &lt;img ismap src="/images/imagemap1.gif"&gt;<br />
      </indent>
      &lt;/a&gt;
    </example>

    <example><title>Ejemplo XHTML</title>
      &lt;a href="/maps/imagemap1.map"&gt;<br />
      <indent>
        &lt;img ismap="ismap" src="/images/imagemap1.gif" /&gt;<br />
      </indent>
      &lt;/a&gt;
    </example>

</section>

<directivesynopsis>
<name>ImapMenu</name>
<description>Acción si no se dan coordenadas al llamar a
un mapa de imagen</description>
<syntax>ImapMenu none|formatted|semiformatted|unformatted</syntax>
<default>ImapMenu formatted</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>Indexes</override>

<usage>
    <p>La directiva <directive>ImapMenu</directive> determina la
    acción que se lleva a cabo si se llama a un archivo de mapa de imagen sin
    coordenadas válidas.</p>

    <dl>
      <dt><code>none</code></dt>
      <dd>Si ImapMenu es <code>none</code>, no se genera ningún menú,
      y se realiza la acción <code>default</code>.</dd>

      <dt><code>formatted</code></dt>
      <dd>Un menú <code>formatted</code> es el menú más sencillo.
      Los comentarios en el archivo de mapa de imagen se ignoran. Se imprime un
      encabezado de nivel uno, luego una línea horizontal, y después los enlaces cada uno en una línea
      distinta. El menú tiene un aspecto consistente y sencillo, próximo al de
      un listado de directorio.</dd>

      <dt><code>semiformatted</code></dt>
      <dd>En el menú <code>semiformatted</code>, los comentarios se
      imprimen donde aparecen en el archivo de mapa de imagen. Las líneas en blanco
      se convierten en saltos de línea HTML. No se imprime ningún encabezado ni línea
      horizontal, pero por lo demás el menú es igual que un menú
      <code>formatted</code>.</dd>

      <dt><code>unformatted</code></dt>
      <dd>Los comentarios se imprimen, las líneas en blanco se ignoran. No se
      imprime nada que no aparezca en el archivo de mapa de imagen. Todos los saltos
      de línea y encabezados deben incluirse como comentarios en el archivo de mapa
      de imagen. Esto le da la máxima flexibilidad sobre la apariencia
      de sus menús, pero requiere que trate sus archivos de mapa como
      HTML en lugar de texto plano.</dd>
    </dl>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ImapDefault</name>
<description>Acción por defecto cuando se llama a un mapa de imagen con coordenadas
que no están mapeadas explícitamente</description>
<syntax>ImapDefault error|nocontent|map|referer|<var>URL</var></syntax>
<default>ImapDefault nocontent</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>Indexes</override>

<usage>
    <p>La directiva <directive>ImapDefault</directive> establece el valor
    por defecto de <code>default</code> usado en los archivos de mapa de imagen. Su valor es
    sobreescrito por una directiva <code>default</code> dentro del
    archivo de mapa de imagen. Si no está presente, la acción <code>default</code>
    es <code>nocontent</code>, lo que significa que se envía al cliente un
    <code>204 No Content</code>. En este caso, el cliente
    debería continuar mostrando la página original.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ImapBase</name>
<description><code>base</code> por defecto para los archivos de mapa de imagen</description>
<syntax>ImapBase map|referer|<var>URL</var></syntax>
<default>ImapBase http://servername/</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>Indexes</override>

<usage>
    <p>La directiva <directive>ImapBase</directive> establece el valor
    por defecto de <code>base</code> usado en los archivos de mapa de imagen. Su valor es
    sobreescrito por una directiva <code>base</code> dentro del archivo de
    mapa de imagen. Si no está presente, <code>base</code> toma por defecto
    el valor <code>http://<var>servername</var>/</code>.</p>
</usage>
<seealso><directive module="core">UseCanonicalName</directive></seealso>
</directivesynopsis>

</modulesynopsis>
