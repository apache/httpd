<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1818953 -->
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

<modulesynopsis metafile="mod_ext_filter.xml.meta">

<name>mod_ext_filter</name>
<description>Pasa el cuerpo de la respuesta a través de un programa externo antes
de entregarlo al cliente</description>
<status>Extension</status>
<sourcefile>mod_ext_filter.c</sourcefile>
<identifier>ext_filter_module</identifier>

<summary>
    <p><module>mod_ext_filter</module> presenta un modelo de programación
    sencillo y familiar para <a href="../filter.html">filtros</a>. Con
    este módulo, un programa que lee de stdin y escribe en stdout
    (es decir, un comando de filtro al estilo Unix) puede ser un filtro
    para Apache. Este mecanismo de filtrado es mucho más lento que usar un
    filtro escrito específicamente para la API de Apache y que se ejecuta
    dentro del proceso del servidor Apache, pero sí tiene los
    siguientes beneficios:</p>

    <ul>
      <li>el modelo de programación es mucho más sencillo</li>

      <li>puede usarse cualquier lenguaje de programación o de scripting,
      siempre que permita que el programa lea de la entrada estándar y
      escriba en la salida estándar</li>

      <li>los programas existentes pueden usarse sin modificar como
      filtros de Apache</li>
    </ul>

    <p>Incluso cuando las características de rendimiento no son adecuadas
    para uso en producción, <module>mod_ext_filter</module> puede usarse como
    un entorno de prototipado para filtros.</p>

</summary>
<seealso><a href="../filter.html">Filtros</a></seealso>

<section id="examples"><title>Ejemplos</title>

    <section><title>Generar HTML a partir de otro tipo de respuesta</title>
      <highlight language="config">
# directiva mod_ext_filter para definir un filtro
# que convierta a HTML los archivos text/c usando el
# programa externo /usr/bin/enscript, con el tipo del
# resultado establecido en text/html
ExtFilterDefine c-to-html mode=output \
    intype=text/c outtype=text/html \
    cmd="/usr/bin/enscript --color -w html -Ec -o -"

&lt;Directory "/export/home/trawick/apacheinst/htdocs/c"&gt;
    # directiva del core para hacer que el nuevo filtro
    # se ejecute en la salida
    SetOutputFilter c-to-html

    # directiva de mod_mime para establecer el tipo de los
    # archivos .c como text/c
    AddType text/c .c
&lt;/Directory&gt;
      </highlight>
    </section>

    <section><title>Implementar un filtro de codificación de contenido</title>
      <p>Nota: este ejemplo de gzip es solo con fines ilustrativos.
      Para una implementación práctica, consulte <module>mod_deflate</module>.</p>

      <highlight language="config">
# directiva mod_ext_filter para definir el filtro externo
ExtFilterDefine gzip mode=output cmd=/bin/gzip

&lt;Location "/gzipped"&gt;

    # directiva del core para hacer que el filtro gzip
    # se ejecute en la salida
    SetOutputFilter gzip

    # directiva de mod_headers para añadir
    # el campo de cabecera "Content-Encoding: gzip"
    Header set Content-Encoding gzip
&lt;/Location&gt;
      </highlight>
    </section>

    <section><title>Ralentizar el servidor</title>
      <highlight language="config">
# directiva mod_ext_filter para definir un filtro
# que hace pasar todo por cat; cat no
# modifica nada; solo introduce longitud de ruta
# adicional y consume más recursos
ExtFilterDefine slowdown mode=output cmd=/bin/cat \
    preservescontentlength

&lt;Location "/"&gt;
    # directiva del core para hacer que el filtro slowdown
    # se ejecute varias veces en la salida
    #
    SetOutputFilter slowdown;slowdown;slowdown
&lt;/Location&gt;
      </highlight>
    </section>

    <section><title>Usar sed para sustituir texto en la respuesta</title>
      <highlight language="config">
# directiva mod_ext_filter para definir un filtro que
# sustituye texto en la respuesta
#
ExtFilterDefine fixtext mode=output intype=text/html \
    cmd="/bin/sed s/verdana/arial/g"

&lt;Location "/"&gt;
    # directiva del core para hacer que el filtro fixtext
    # se ejecute en la salida
    SetOutputFilter fixtext
&lt;/Location&gt;
      </highlight>

<note>
<p>Puede hacer lo mismo usando <module>mod_substitute</module>
sin invocar un proceso externo.</p>
</note>
    </section>

    <section><title>Rastrear otro filtro</title>
      <highlight language="config">
# Rastrea los datos leídos y escritos por mod_deflate
# para un cliente concreto (IP 192.168.1.31)
# que experimenta problemas de compresión.
# Este filtro rastreará lo que entra en mod_deflate.
ExtFilterDefine tracebefore \
    cmd="/bin/tracefilter.pl /tmp/tracebefore" \
    EnableEnv=trace_this_client

# Este filtro rastreará lo que sale después de mod_deflate.
# Tenga en cuenta que sin el parámetro ftype, el tipo
# de filtro por defecto AP_FTYPE_RESOURCE haría que el
# filtro se colocara *antes* de mod_deflate en la cadena
# de filtros. Darle un valor numérico algo mayor que
# AP_FTYPE_CONTENT_SET asegurará que se coloque
# después de mod_deflate.
ExtFilterDefine traceafter \
    cmd="/bin/tracefilter.pl /tmp/traceafter" \
    EnableEnv=trace_this_client ftype=21

&lt;Directory "/usr/local/docs"&gt;
    SetEnvIf Remote_Addr 192.168.1.31 trace_this_client
    SetOutputFilter tracebefore;deflate;traceafter
&lt;/Directory&gt;
      </highlight>

      <example><title>Este es el filtro que rastrea los datos:</title>
      <highlight language="perl">
#!/usr/local/bin/perl -w
use strict;

open(SAVE, "&gt;$ARGV[0]")
    or die "can't open $ARGV[0]: $?";

while (&lt;STDIN&gt;) {
    print SAVE $_;
    print $_;
}

close(SAVE);
        </highlight>
      </example>
    </section>
</section> <!-- /Examples -->

<directivesynopsis>
<name>ExtFilterDefine</name>
<description>Define un filtro externo</description>
<syntax>ExtFilterDefine <var>filtername</var> <var>parameters</var></syntax>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>La directiva <directive>ExtFilterDefine</directive> define las
    características de un filtro externo, incluyendo el programa a
    ejecutar y sus argumentos.</p>

    <p><var>filtername</var> especifica el nombre del filtro que se está
    definiendo. Este nombre puede usarse después en directivas <directive module="core"
    >SetOutputFilter</directive>.
    Debe ser único entre todos los filtros registrados.
    <em>Actualmente, la API de registro de filtros no informa de ningún
    error, por lo que un problema de nombres duplicados no se notifica
    al usuario.</em></p>

    <p>Los parámetros siguientes pueden aparecer en cualquier orden y
    definen el comando externo a ejecutar y otras características. El
    único parámetro obligatorio es <code>cmd=</code>. Estos parámetros
    son:</p>

    <dl>
      <dt><code>cmd=<var>cmdline</var></code></dt>

      <dd>La palabra clave <code>cmd=</code> le permite especificar el
      comando externo a ejecutar. Si hay argumentos después del
      nombre del programa, la línea de comandos debe ir rodeada de
      comillas (<em>p. ej.</em>, <code>cmd="<var>/bin/mypgm</var>
      <var>arg1</var> <var>arg2</var>"</code>.) No es necesario el entrecomillado
      normal del shell, ya que el programa se ejecuta directamente, sin
      pasar por el shell. Los argumentos del programa se delimitan con
      espacios en blanco. Puede usarse una barra invertida para escapar
      espacios en blanco que deban formar parte de un argumento del
      programa. Cualquier barra invertida que forme parte del argumento
      debe escaparse a su vez con una barra invertida. Además de las
      variables de entorno CGI estándar, también se establecerán para
      el programa DOCUMENT_URI, DOCUMENT_PATH_INFO y
      QUERY_STRING_UNESCAPED.</dd>

      <dt><code>mode=<var>mode</var></code></dt>

      <dd>Use <code>mode=output</code> (el valor por defecto) para filtros que
      procesan la respuesta. Use <code>mode=input</code> para filtros
      que procesan la petición. <code>mode=input</code> está disponible
      en Apache 2.1 y posteriores.</dd>

      <dt><code>intype=<var>imt</var></code></dt>

      <dd>Este parámetro especifica el tipo de medio de Internet (<em>es
      decir</em>, el tipo MIME) de los documentos que deben filtrarse. Por
      defecto, se filtran todos los documentos. Si se
      especifica <code>intype=</code>, el filtro se desactivará para
      documentos de otros tipos.</dd>

      <dt><code>outtype=<var>imt</var></code></dt>

      <dd>Este parámetro especifica el tipo de medio de Internet (<em>es
      decir</em>, el tipo MIME) de los documentos filtrados. Es útil
      cuando el filtro cambia el tipo de medio de Internet como parte
      de la operación de filtrado. Por defecto, el tipo de medio de
      Internet no cambia.</dd>

      <dt><code>PreservesContentLength</code></dt>

      <dd>La palabra clave <code>PreservesContentLength</code> especifica
      que el filtro conserva la longitud del contenido. Esto no es el
      valor por defecto, ya que la mayoría de los filtros cambian la
      longitud del contenido. En caso de que el filtro no modifique la
      longitud, debe especificarse esta palabra clave.</dd>

      <dt><code>ftype=<var>filtertype</var></code></dt>

      <dd>Este parámetro especifica el valor numérico del tipo de filtro
      con el que debe registrarse el filtro. El valor por defecto,
      AP_FTYPE_RESOURCE, es suficiente en la mayoría de los casos. Si el
      filtro necesita operar en un punto distinto de la cadena de filtros
      al de los filtros de recurso, este parámetro será necesario. Vea
      las definiciones AP_FTYPE_foo en util_filter.h para conocer los
      valores apropiados.</dd>

      <dt><code>disableenv=<var>env</var></code></dt>

      <dd>Este parámetro especifica el nombre de una variable de entorno
      que, si está establecida, desactivará el filtro.</dd>

      <dt><code>enableenv=<var>env</var></code></dt>

      <dd>Este parámetro especifica el nombre de una variable de entorno
      que debe estar establecida, o el filtro se desactivará.</dd>
    </dl>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ExtFilterOptions</name>
<description>Configura las opciones de <module>mod_ext_filter</module></description>
<syntax>ExtFilterOptions <var>option</var> [<var>option</var>] ...</syntax>
<default>ExtFilterOptions NoLogStderr</default>
<contextlist><context>directory</context></contextlist>

<usage>
    <p>La directiva <directive>ExtFilterOptions</directive> especifica
    opciones de procesamiento especiales para <module>mod_ext_filter</module>.
    <var>Option</var> puede ser una de las siguientes</p>

    <dl>
      <dt><code>LogStderr | NoLogStderr</code></dt>

      <dd>La palabra clave <code>LogStderr</code> especifica que
      los mensajes escritos en la salida de error estándar por el
      programa de filtro externo se guardarán en el log de errores de
      Apache. <code>NoLogStderr</code> desactiva esta función.</dd>

      <dt><code>Onfail=[abort|remove]</code></dt>
      <dd>Determina cómo proceder si el programa de filtro externo no
      puede iniciarse. Con <code>abort</code> (el valor por defecto),
      la petición se abortará. Con <code>remove</code>, el
      filtro se elimina y la petición continúa sin él.</dd>
    </dl>

    <highlight language="config">
      ExtFilterOptions LogStderr
    </highlight>

    <p>Los mensajes escritos en la salida de error estándar del filtro se
    almacenarán en el log de errores de Apache.</p>
</usage>
</directivesynopsis>

</modulesynopsis>
