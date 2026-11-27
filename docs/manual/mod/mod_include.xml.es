<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1939369 -->
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

<modulesynopsis metafile="mod_include.xml.meta">

<name>mod_include</name>
<description>Documentos html analizados en el servidor (Server Side Includes)</description>
<status>Base</status>
<sourcefile>mod_include.c</sourcefile>
<identifier>include_module</identifier>

<summary>
    <p>Este módulo proporciona un filtro que procesa los ficheros
    antes de enviarlos al cliente. El procesamiento se
    controla mediante comentarios SGML con un formato especial, denominados
    <dfn>elementos</dfn>. Estos elementos permiten texto condicional, la
    inclusión de otros ficheros o programas, así como el establecimiento y
    la impresión de variables de entorno.</p>
</summary>
<seealso><directive module="core">Options</directive></seealso>
<seealso><directive module="core">AcceptPathInfo</directive></seealso>
<seealso><a href="../filter.html">Filtros</a></seealso>
<seealso><a href="../howto/ssi.html">Tutorial de SSI</a></seealso>

<section id="enabling">
    <title>Activar los Server Side Includes</title>

    <p>Los Server Side Includes se implementan mediante el
    <a href="../filter.html">filtro</a> <code>INCLUDES</code>. Si
    los documentos que contienen directivas de server-side include tienen
    la extensión .shtml, las siguientes directivas harán que Apache
    los analice y asigne al documento resultante el tipo mime
    <code>text/html</code>:</p>

    <highlight language="config">
AddType text/html .shtml
AddOutputFilter INCLUDES .shtml
    </highlight>

    <p>Debe especificarse la siguiente directiva para los directorios
    que contienen los ficheros shtml (normalmente en una sección
    <directive module="core" type="section">Directory</directive>,
    pero esta directiva también es válida en ficheros <code>.htaccess</code>
    si <directive module="core">AllowOverride</directive> <code>Options</code>
    está activado):</p>

    <highlight language="config">
Options +Includes
    </highlight>

    <p>Por compatibilidad con versiones anteriores, el
    <a href="../handler.html">manejador</a> <code>server-parsed</code>
    también activa el filtro INCLUDES. Asimismo, Apache activará el filtro
    INCLUDES para cualquier documento con el tipo mime
    <code>text/x-server-parsed-html</code> o
    <code>text/x-server-parsed-html3</code> (y el resultado
    tendrá el tipo mime <code>text/html</code>).</p>

    <p>Para más información, consulte nuestro <a
    href="../howto/ssi.html">Tutorial sobre Server Side Includes</a>.</p>
</section> <!-- /enabling -->

<section id="pathinfo">
    <title>PATH_INFO con Server Side Includes</title>

    <p>Los ficheros procesados para server-side includes ya no aceptan,
    por defecto, peticiones con <code>PATH_INFO</code> (información de ruta final).
    Puede usar la directiva <directive
    module="core">AcceptPathInfo</directive> para
    configurar el servidor de forma que acepte peticiones con <code>PATH_INFO</code>.</p>
</section> <!-- /pathinfo -->

<section id="elements"><title>Elementos disponibles</title>
    <p>El documento se analiza como un documento HTML, con comandos
    especiales incrustados como comentarios SGML. Un comando tiene la sintaxis: </p>

    <example>
      &lt;!--#<var>elemento</var> <var>atributo</var>=<var>valor</var>
      <var>atributo</var>=<var>valor</var> ... --&gt;
    </example>

    <p>El valor suele ir entre comillas dobles, pero también son posibles
    las comillas simples (<code>'</code>) y los acentos graves (<code>`</code>). Muchos
    comandos solo admiten un único par atributo-valor.
    Tenga en cuenta que el terminador del comentario (<code>--&gt;</code>) debe
    ir precedido de un espacio en blanco para garantizar que no se considere parte
    de un token SSI. Tenga en cuenta también que el <code>&lt;!--#</code> inicial es <em>un único</em>
    token y no puede contener espacios en blanco.</p>

    <p>Los elementos permitidos se muestran en la siguiente tabla:</p>

    <table border="1">
    <tr><th>Elemento</th><th>Descripción</th></tr>
    <tr><td><code><a href="#element.comment">comment</a></code></td>
        <td>Comentario SSI</td></tr>
    <tr><td><code><a href="#element.config">config</a></code></td>
        <td>configura los formatos de salida</td></tr>
    <tr><td><code><a href="#element.echo">echo</a></code></td>
        <td>imprime variables</td></tr>
    <tr><td><code><a href="#element.exec">exec</a></code></td>
        <td>ejecuta programas externos</td></tr>
    <tr><td><code><a href="#element.fsize">fsize</a></code></td>
        <td>imprime el tamaño de un fichero</td></tr>
    <tr><td><code><a href="#element.flastmod">flastmod</a></code></td>
        <td>imprime la fecha de última modificación de un fichero</td></tr>
    <tr><td><code><a href="#element.include">include</a></code></td>
        <td>incluye un fichero</td></tr>
    <tr><td><code><a href="#element.printenv">printenv</a></code></td>
        <td>imprime todas las variables disponibles</td></tr>
    <tr><td><code><a href="#element.set">set</a></code></td>
        <td>establece el valor de una variable</td></tr>
    </table>

    <p>Los elementos SSI pueden ser definidos por módulos distintos de
    <module>mod_include</module>. De hecho, el elemento <code><a
    href="#element.exec">exec</a></code> lo proporciona
    <module>mod_cgi</module>, y solo estará disponible si este
    módulo está cargado.</p>

    <section id="element.comment"><title>El elemento comment</title>
      <p>Este comando no genera ninguna salida. Su único uso es
      añadir comentarios dentro de un fichero. Estos comentarios no se
      imprimen.</p>

      <p>Esta sintaxis está disponible desde la versión 2.4.21.</p>

      <example>
      &lt;!--#comment Blah Blah Blah --&gt;<br/>
      &nbsp;&nbsp;&nbsp;o bien<br/>
      &lt;!--#comment text="Blah Blah Blah" --&gt;
      </example>
    </section> <!-- /comment -->

    <section id="element.config"><title>El elemento config</title>
      <p>Este comando controla varios aspectos del análisis. Los
      atributos válidos son:</p>

      <dl>
      <dt><code>echomsg</code> (<em>Apache 2.1 y posteriores</em>)</dt>
      <dd><p>El valor es un mensaje que se envía de vuelta al
      cliente si el elemento <code><a href="#element.echo">echo</a></code>
      intenta mostrar una variable no definida. Esto tiene prioridad sobre cualquier directiva
      <directive module="mod_include">SSIUndefinedEcho</directive>.</p>

      <example>
        &lt;!--#config echomsg="[Value Undefined]" --&gt;
      </example>
      </dd>

      <dt><code>errmsg</code></dt>
      <dd><p>El valor es un mensaje que se envía de vuelta al
      cliente si se produce un error al analizar el
      documento. Esto tiene prioridad sobre cualquier directiva
      <directive module="mod_include">SSIErrorMsg</directive>.</p>

      <example>
       &lt;!--#config errmsg="[Oops, something broke.]" --&gt;
      </example>
      </dd>

      <dt><code>sizefmt</code></dt>
      <dd><p>El valor establece el formato que se usará al mostrar
      el tamaño de un fichero. Los valores válidos son <code>bytes</code>
      para un recuento en bytes, o <code>abbrev</code> para un recuento
      en Kb o Mb según corresponda; por ejemplo, un tamaño de 1024 bytes
      se mostrará como "1K".</p>

      <example>
      &lt;!--#config sizefmt="abbrev" --&gt;
      </example>

      </dd>

      <dt><code>timefmt</code></dt>
      <dd><p>El valor es una cadena que usará la rutina de biblioteca
      <code>strftime(3)</code> al mostrar
      fechas.</p>

      <example>
      &lt;!--#config timefmt=""%R, %B %d, %Y"" --&gt;
      </example>

      </dd>
      </dl>
    </section> <!-- /config -->

    <section id="element.echo"><title>El elemento echo</title>
      <p>Este comando imprime una de las <a href="#includevars">variables
      include</a> definidas más abajo. Si la variable no está definida, el resultado
      lo determina la directiva <directive module="mod_include"
      >SSIUndefinedEcho</directive>. Las fechas que se impriman
      estarán sujetas al <code>timefmt</code> configurado en ese momento.</p>

      <p>Atributos:</p>

      <dl>
      <dt><code>var</code></dt>
      <dd>El valor es el nombre de la variable que se va a imprimir.</dd>

      <dt><code>decoding</code></dt>
      <dd><p>Especifica si Apache debe eliminar una codificación de
      la variable antes de seguir procesándola. El valor por defecto
      es <code>none</code>, con el que no se realiza ninguna decodificación. Si se
      establece a <code>url</code>, se realizará decodificación de URL (también
      conocida como codificación por %; esto es apropiado para su uso dentro de
      URLs en enlaces, etc.). Si se establece a <code>urlencoded</code>, se
      eliminará la codificación compatible con
      application/x-www-form-urlencoded (presente en cadenas de consulta). Si se
      establece a <code>base64</code>, se decodificará en base64, y si se
      establece a <code>entity</code>, se eliminará la codificación de entidades
      HTML. La decodificación se realiza antes de aplicar cualquier
      codificación posterior sobre la variable. Pueden eliminarse varias
      codificaciones indicando más de una separadas por comas.
      El ajuste de decodificación permanecerá vigente hasta el siguiente
      atributo de decodificación que se encuentre, o hasta que termine el elemento.</p>

      <p>El atributo <code>decoding</code> debe <em>preceder</em> al
      atributo <code>var</code> correspondiente para ser efectivo.</p>
      </dd>

      <dt><code>encoding</code></dt>
      <dd><p>Especifica cómo debe codificar Apache los caracteres especiales
      contenidos en la variable antes de mostrarlos. Si se establece
      a <code>none</code>, no se realizará ninguna codificación. Si se establece
      a <code>url</code>, se realizará codificación de URL (también conocida
      como codificación por %; esto es apropiado para su uso dentro de
      URLs en enlaces, etc.). Si se establece a <code>urlencoded</code>, se
      realizará en su lugar codificación compatible con
      application/x-www-form-urlencoded, que debería usarse con cadenas de
      consulta. Si se establece a <code>base64</code>, se realizará codificación
      en base64. Al comienzo de un elemento <code>echo</code>, el valor por
      defecto es <code>entity</code>, lo que da como resultado codificación de
      entidades (que es apropiada en el contexto de un elemento HTML de
      bloque, <em>por ejemplo</em> un párrafo de texto). Esto puede cambiarse
      añadiendo un atributo <code>encoding</code>, que permanecerá vigente
      hasta que se encuentre el siguiente atributo <code>encoding</code> o
      termine el elemento, lo que ocurra primero.</p>

      <p>El atributo <code>encoding</code> debe <em>preceder</em> al
      atributo <code>var</code> correspondiente para ser efectivo.</p>

      <note type="warning">
        Para evitar problemas de cross-site scripting, siempre debería
        codificar los datos suministrados por el usuario.
      </note>

      <example><title>Ejemplo</title>
        &lt;!--#echo encoding="entity" var="QUERY_STRING" --&gt;
      </example>
      </dd>
      </dl>
    </section> <!-- /echo -->

    <section id="element.exec"><title>El elemento exec</title>
      <p>El comando <code>exec</code> ejecuta un comando de shell o
      un script CGI indicado. Requiere que <module>mod_cgi</module> esté presente
      en el servidor. Si <directive module="core">Options</directive>
      <code>IncludesNOEXEC</code> está activado, este comando se
      desactiva completamente. Los atributos válidos son:</p>

      <dl>
      <dt><code>cgi</code></dt>
      <dd><p>El valor especifica una ruta URL (codificada con %) al
      script CGI. Si la ruta no comienza con una barra (/),
      se considera relativa al
      documento actual. El documento referenciado por esta ruta se
      invoca como un script CGI, incluso si el servidor en condiciones
      normales no lo reconocería como tal. Sin embargo, el directorio
      que contiene el script debe tener habilitados los scripts CGI
      (con <directive module="mod_alias">ScriptAlias</directive>
      o <directive module="core">Options</directive>
      <code>ExecCGI</code>).</p>

      <p>Al script CGI se le pasan el <code>PATH_INFO</code> y la cadena
      de consulta (<code>QUERY_STRING</code>) de la petición original del
      cliente; estos <em>no pueden</em> especificarse en la ruta URL. Las
      variables include estarán disponibles para el script además del
      entorno <a href="mod_cgi.html">CGI</a> estándar.</p>

      <example><title>Ejemplo</title>
        &lt;!--#exec cgi="/cgi-bin/example.cgi" --&gt;
      </example>

      <p>Si el script devuelve una cabecera <code>Location:</code> en lugar de
      una salida, esta se traducirá en un anchor HTML.</p>

      <p>Debería usarse el elemento <code><a href="#includevirtual">include
      virtual</a></code> en lugar de <code>exec cgi</code>. En
      particular, si necesita pasar argumentos adicionales a un programa CGI
      usando la cadena de consulta, esto no puede hacerse con <code>exec
      cgi</code>, pero sí con <code>include virtual</code>, como se
      muestra aquí:</p>

      <example>
        &lt;!--#include virtual="/cgi-bin/example.cgi?argument=value" --&gt;
      </example>
      </dd>

      <dt><code>cmd</code></dt>
      <dd><p>El servidor ejecutará la cadena indicada usando
      <code>/bin/sh</code>. Las <a href="#includevars"
      >variables include</a> están disponibles para el comando, además
      del conjunto habitual de variables CGI.</p>

      <p>El uso de <code><a href="#includevirtual"
      >#include virtual</a></code> es casi siempre preferible a usar
      <code>#exec cgi</code> o <code>#exec cmd</code>. El primero
      (<code>#include virtual</code>) usa el mecanismo estándar de
      subpeticiones de Apache para incluir ficheros o scripts. Está
      mucho mejor probado y mantenido.</p>

      <p>Además, en algunas plataformas, como Win32, y en unix cuando se usa
      <a href="../suexec.html">suexec</a>, no se pueden pasar argumentos
      a un comando en una directiva <code>exec</code>, ni incluir espacios en
      el comando de ninguna otra forma. Así, aunque lo siguiente funcionará en una
      configuración sin suexec en unix, no producirá el resultado deseado en
      Win32, ni al ejecutar suexec:</p>

      <example>
        &lt;!--#exec cmd="perl /path/to/perlscript arg1 arg2" --&gt;
      </example>
      </dd>
      </dl>
    </section> <!-- /exec -->

    <section id="element.fsize"><title>El elemento fsize</title>
      <p>Este comando imprime el tamaño del fichero especificado, sujeto
      a la especificación de formato <code>sizefmt</code>. Atributos:</p>

      <dl>
      <dt><code>file</code></dt>
      <dd>El valor es una ruta relativa al directorio que
      contiene el documento actual que se está analizando.

    <example>
        This file is &lt;!--#fsize file="mod_include.html" --&gt; bytes.
    </example>

    El valor de <code>file</code> no puede comenzar con una barra
    (<code>/</code>), ni puede contener <code>../</code> para
    referirse a un fichero por encima del directorio actual o fuera de la
    raíz de documentos. Intentarlo producirá el mensaje de error:
    <code>The given path was above the root path</code>.
      </dd>

      <dt><code>virtual</code></dt>
      <dd>El valor es una ruta URL (codificada con %). Si no comienza con
      una barra (/), se considera relativa al documento actual.
      Tenga en cuenta que esto <em>no</em> imprime el tamaño de ninguna salida
      CGI, sino el tamaño del propio script CGI.</dd>
      </dl>

    <example>
        This file is &lt;!--#fsize virtual="/docs/mod/mod_include.html" --&gt; bytes.
    </example>

      <p>Tenga en cuenta que, en muchos casos, ambas cosas son exactamente lo mismo.
      Sin embargo, el atributo <code>file</code> no respeta los alias en el
      espacio de URLs.</p>
    </section> <!-- /fsize -->

    <section id="element.flastmod"><title>El elemento flastmod</title>
      <p>Este comando imprime la fecha de última modificación del
      fichero especificado, sujeta a la especificación de formato
      <code>timefmt</code>. Los atributos son los mismos que para
      el comando <code><a href="#element.fsize">fsize</a></code>.</p>
    </section> <!-- /flastmod -->

    <section id="element.include"><title>El elemento include</title>
      <p>Este comando inserta el texto de otro documento o fichero
      en el fichero analizado. Cualquier fichero incluido está sujeto al
      control de acceso habitual. Si el directorio que contiene el fichero
      analizado tiene activado <a href="core.html#options">Options</a>
      <code>IncludesNOEXEC</code>, solo se incluirán los documentos con un
      <glossary>MIME-type</glossary> de texto (<code>text/plain</code>,
      <code>text/html</code>, etc.). En caso contrario, los scripts CGI se
      invocan de forma normal usando la URL completa indicada en el
      comando, incluyendo cualquier cadena de consulta.</p>

      <p>Un atributo define la ubicación del documento, y puede
      aparecer más de una vez en un elemento include; se realiza una
      inclusión por cada atributo indicado, en el orden en que aparecen,
      en el comando include. Los atributos válidos son:</p>

      <dl>
      <dt><code>file</code></dt>
      <dd>El valor es una ruta relativa al directorio que
      contiene el documento actual que se está analizando. No puede
      contener <code>../</code>, ni puede ser una ruta absoluta.
      Por lo tanto, no puede incluir ficheros que estén fuera de la
      raíz de documentos, o por encima del documento actual en la estructura
      de directorios. Siempre debería preferirse el atributo <code>virtual</code>
      a este.</dd>

      <dt><code><a id="includevirtual" name="includevirtual"
      >virtual</a></code></dt>
      <dd><p>El valor es una ruta URL (codificada con %). La URL no puede
      contener un esquema ni un nombre de host, solo una ruta y, opcionalmente,
      una cadena de consulta. Si no comienza con una barra (/), se considera
      relativa al documento actual.</p>

      <p>A partir del atributo se construye una URL, y la salida que el
      servidor devolvería si el cliente accediera a esa URL se
      incluye en el resultado analizado. Así, los ficheros incluidos pueden anidarse.</p>

      <p>Si la URL especificada corresponde a un programa CGI, el programa se
      ejecutará y su salida se insertará en el lugar de la directiva en el
      fichero analizado. Puede incluir una cadena de consulta en una URL CGI:</p>

      <example>
        &lt;!--#include virtual="/cgi-bin/example.cgi?argument=value" --&gt;
      </example>

      <p>Debería usarse <code>include virtual</code> en lugar
      de <code>exec cgi</code> para incluir la salida de programas CGI
      en un documento HTML.</p>

      <p>Si la directiva <directive module="mod_request">KeptBodySize</directive>
      está configurada correctamente y es válida para este fichero incluido,
      los intentos de enviar peticiones POST al documento HTML que lo
      contiene se transmitirán a las subpeticiones también como peticiones
      POST. Sin la directiva, todas las subpeticiones se procesan como
      peticiones GET.</p>

      </dd>

      <dt><code>onerror</code></dt>
      <dd><p>El valor es una ruta URL (codificada con %) que se muestra en caso
      de que falle un intento anterior de incluir un atributo file o virtual.
      Para que sea efectivo, este atributo debe especificarse después de los
      atributos file o virtual a los que se aplica. Si el intento de
      incluir la ruta de onerror también falla, o si no se especifica onerror, se
      incluirá el mensaje de error por defecto.</p>

      <example>
<highlight language="html">
# Ejemplo sencillo
&lt;!--#include virtual="/not-exist.html" onerror="/error.html" --&gt;
</highlight>
      </example>

      <example>
<highlight language="html">
# Rutas onerror dedicadas
&lt;!--#include virtual="/path-a.html" onerror="/error-a.html" virtual="/path-b.html" onerror="/error-b.html" --&gt;
</highlight>
      </example>

      </dd>
      </dl>
    </section> <!-- /include -->

    <section id="element.printenv"><title>El elemento printenv</title>
      <p>Esto imprime un listado en texto plano de todas las variables
      existentes y sus valores. Los caracteres especiales se codifican como
      entidades (vea el elemento <code><a
      href="#element.echo">echo</a></code> para más detalles)
      antes de generar la salida. No tiene atributos.</p>

      <example><title>Ejemplo</title>
        &lt;pre&gt;
          &lt;!--#printenv --&gt;
        &lt;/pre&gt;
      </example>
    </section> <!-- /printenv -->

    <section id="element.set"><title>El elemento set</title>
      <p>Esto establece el valor de una variable. Atributos:</p>

      <dl>
      <dt><code>var</code></dt>
      <dd>El nombre de la variable a establecer.</dd>

      <dt><code>value</code></dt>
      <dd>El valor que se asignará a la variable.</dd>

      <dt><code>decoding</code></dt>
      <dd><p>Especifica si Apache debe eliminar una codificación de
      la variable antes de seguir procesándola. El valor por defecto
      es <code>none</code>, con el que no se realiza ninguna decodificación. Si se
      establece a <code>url</code>, <code>urlencoded</code>, <code>base64</code>
      o <code>entity</code>, se realizará respectivamente decodificación de URL,
      decodificación application/x-www-form-urlencoded, decodificación base64 o
      decodificación de entidades HTML. Puede indicarse más de una
      decodificación separándolas con comas. El ajuste de decodificación
      permanecerá vigente hasta que se encuentre el siguiente atributo de
      decodificación, o hasta que termine el elemento. El atributo
      <code>decoding</code> debe <em>preceder</em> al atributo
      <code>var</code> correspondiente para ser efectivo.</p>
      </dd>

      <dt><code>encoding</code></dt>
      <dd><p>Especifica cómo debe codificar Apache los caracteres especiales
      contenidos en la variable antes de establecerlos. El valor por defecto es
      <code>none</code>, con el que no se realiza ninguna codificación. Si se
      establece a <code>url</code>, <code>urlencoding</code>, <code>base64</code>
      o <code>entity</code>, se realizará respectivamente codificación de URL,
      codificación application/x-www-form-urlencoded, codificación base64 o
      codificación de entidades HTML. Puede indicarse más de
      una codificación separándolas con comas. El ajuste de
      codificación permanecerá vigente hasta que se encuentre el siguiente
      atributo de codificación, o hasta que termine el elemento. El
      atributo <code>encoding</code> debe <em>preceder</em> al
      atributo <code>var</code> correspondiente para ser efectivo.
      Las codificaciones se aplican después de haber eliminado todas
      las decodificaciones.</p>
      </dd>
      </dl>

      <example><title>Ejemplo</title>
        &lt;!--#set var="category" value="help" --&gt;
      </example>
    </section> <!-- /set -->
</section> <!-- /basic elements -->

<section id="includevars">
    <title>Variables include</title>

    <p>Además de las variables del entorno CGI estándar,
    estas están disponibles para el comando <code>echo</code>, para
    <code>if</code> y <code>elif</code>, y para cualquier programa
    invocado por el documento.</p>

    <dl>
      <dt><code>DATE_GMT</code></dt>
      <dd>La fecha actual en el meridiano de Greenwich (GMT).</dd>

      <dt><code>DATE_LOCAL</code></dt>
      <dd>La fecha actual en la zona horaria local.</dd>

      <dt><code>DOCUMENT_ARGS</code></dt>
      <dd>Esta variable contiene la cadena de consulta del documento SSI
      activo, o una cadena vacía si no se incluye una cadena de
      consulta. En las subpeticiones invocadas mediante la
      directiva SSI <code>include</code>, <code>QUERY_STRING</code>
      representará la cadena de consulta de la subpetición y
      <code>DOCUMENT_ARGS</code> representará la cadena de consulta
      del documento SSI. (Disponible en Apache HTTP Server 2.4.19 y
      posteriores.)</dd>

      <dt><code>DOCUMENT_NAME</code></dt>
      <dd>El nombre de fichero (sin incluir directorios) del documento
      solicitado por el usuario.</dd>

      <dt><code>DOCUMENT_PATH_INFO</code></dt>
      <dd>La información de ruta final. Vea la directiva <directive
      module="core">AcceptPathInfo</directive> para más información
      sobre <code>PATH_INFO</code>.</dd>

      <dt><code>DOCUMENT_URI</code></dt>
      <dd>La ruta URL (decodificada de %) del documento solicitado por
      el usuario. Tenga en cuenta que, en el caso de ficheros include
      anidados, esta <em>no</em> es la URL del documento actual. Tenga en
      cuenta también que, si la URL se modifica internamente (por ejemplo,
      mediante un <directive
      module="mod_alias">alias</directive> o un <directive
      module="mod_dir">directoryindex</directive>), se muestra la
      URL modificada.</dd>

      <dt><code>LAST_MODIFIED</code></dt>
      <dd>La fecha de última modificación del documento solicitado
      por el usuario.</dd>

      <dt><code>QUERY_STRING_UNESCAPED</code></dt>
      <dd>Si hay una cadena de consulta presente en la petición del
      documento SSI activo, esta variable contiene la cadena de
      consulta (decodificada de %), que se <em>escapa</em> para su uso en
      shell (los caracteres especiales como <code>&amp;</code>, etc., van
      precedidos de barras invertidas). No se establece si no hay
      presente una cadena de consulta. Use <code>DOCUMENT_ARGS</code>
      si no desea el escapado de shell.</dd>

      <dt><code>USER_NAME</code></dt>
      <dd>El nombre de usuario del propietario del fichero.</dd>
    </dl>
</section>

<section id="substitution"><title>Sustitución de variables</title>

    <p>La sustitución de variables se realiza dentro de cadenas entre comillas
    en la mayoría de los casos en los que pueden aparecer razonablemente como
    argumento de una directiva SSI. Esto incluye las directivas <code>config</code>,
    <code>exec</code>, <code>flastmod</code>, <code>fsize</code>,
    <code>include</code>, <code>echo</code> y <code>set</code>. Si
    <directive module="mod_include"
    >SSILegacyExprParser</directive> está activada (<code>on</code>),
    la sustitución también se produce en los argumentos de los operadores
    condicionales. Puede insertar un signo de dólar literal en la cadena
    escapándolo con una barra invertida:</p>

    <example>
      &lt;!--#set var="cur" value="\$test" --&gt;
    </example>

    <p>Si es necesario sustituir una referencia a variable en
    mitad de una secuencia de caracteres que, de otro modo, podría
    considerarse un identificador válido por sí misma, puede
    eliminarse la ambigüedad encerrando la referencia entre llaves,
    <em>al estilo</em> de la sustitución de shell:</p>

    <example>
      &lt;!--#set var="Zed" value="${REMOTE_HOST}_${REQUEST_METHOD}" --&gt;
    </example>

    <p>Esto hará que la variable <code>Zed</code> tome el valor
    "<code>X_Y</code>" si <code>REMOTE_HOST</code> es
    "<code>X</code>" y <code>REQUEST_METHOD</code> es
    "<code>Y</code>".</p>
</section>

<section id="flowctrl">
    <title>Elementos de control de flujo</title>

    <p>Los elementos básicos de control de flujo son:</p>

    <example>
<highlight language="html">
&lt;!--#if expr="test_condition" --&gt;
&lt;!--#elif expr="test_condition" --&gt;
&lt;!--#else --&gt;
&lt;!--#endif --&gt;
</highlight>
    </example>

    <p>El elemento <code>if</code> funciona como una sentencia if en un
    lenguaje de programación. Se evalúa la condición de prueba y, si
    el resultado es verdadero, el texto hasta el siguiente elemento
    <code>elif</code>, <code>else</code> o <code>endif</code> se incluye en
    el flujo de salida.</p>

    <p>Las sentencias <code>elif</code> o <code>else</code> se usan
    para colocar texto en el flujo de salida si la
    <var>test_condition</var> original era falsa. Estos elementos son opcionales.</p>

    <p>El elemento <code>endif</code> termina el elemento <code>if</code>
    y es obligatorio.</p>

    <p><var>test_condition</var> es una expresión booleana que sigue la
    sintaxis de <a href="../expr.html">ap_expr</a>. La sintaxis puede cambiarse
    para que sea compatible con Apache HTTPD 2.2.x usando la directiva
    <directive module="mod_include">SSILegacyExprParser</directive>.</p>

    <p>Las variables SSI establecidas con el elemento <code>var</code> se exportan
    al entorno de la petición y pueden consultarse con la función
    <code>reqenv</code>. Como atajo, el nombre de función
    <code>v</code> también está disponible dentro de <module>mod_include</module>.</p>

    <p>El siguiente ejemplo imprimirá "from local net" si la dirección IP del
    cliente pertenece a la subred 10.0.0.0/8.</p>

    <example>
<highlight language="html">
&lt;!--#if expr='-R "10.0.0.0/8"' --&gt;
  from local net
&lt;!--#else --&gt;
  from somewhere else
&lt;!--#endif --&gt;
</highlight>
    </example>

    <p>El siguiente ejemplo imprimirá "foo is bar" si la variable
    <code>foo</code> está establecida al valor "bar".</p>

    <example>
<highlight language="html">
&lt;!--#if expr='v("foo") = "bar"' --&gt;
  foo is bar
&lt;!--#endif --&gt;
</highlight>
    </example>

    <note><title>Documentación de referencia</title>
    <p>Vea también: <a href="../expr.html">Expresiones en Apache HTTP Server</a>,
    para una referencia completa con ejemplos. Las funciones <em>restringidas</em>
    no están disponibles dentro de <module>mod_include</module></p>
    </note>
</section>

<section id="legacyexpr">
    <title>Sintaxis de expresiones heredada</title>

    <p>Esta sección describe la sintaxis del elemento <code>#if expr</code>
    cuando <directive module="mod_include">SSILegacyExprParser</directive>
    está activada (<code>on</code>).</p>

    <dl>
      <dt><code><var>string</var></code></dt>
      <dd>verdadero si <var>string</var> no está vacía</dd>

      <dt><code><var>-A string</var></code></dt>
      <dd><p>verdadero si la URL representada por la cadena es accesible según
      la configuración, falso en caso contrario. Esto resulta útil cuando el
      contenido de una página debe ocultarse a usuarios que no están autorizados
      a ver la URL, como por ejemplo un enlace a esa URL. Tenga en cuenta que
      la URL solo se comprueba para determinar si se concedería el acceso, no si
      la URL existe.</p>

      <example><title>Ejemplo</title>
<highlight language="html">
&lt;!--#if expr="-A /private" --&gt;
  Click &lt;a href="/private"&gt;here&lt;/a&gt; to access private
  information.
&lt;!--#endif --&gt;
</highlight>
      </example>
      </dd>

      <dt><code><var>string1</var> = <var>string2</var><br />
      <var>string1</var> == <var>string2</var><br />
      <var>string1</var> != <var>string2</var></code></dt>

      <dd><p>Compara <var>string1</var> con <var>string2</var>. Si
      <var>string2</var> tiene la forma <code>/<var>string2</var>/</code>,
      se trata como una expresión regular. Las expresiones regulares están
      implementadas por el motor <a href="http://www.pcre.org">PCRE</a> y
      tienen la misma sintaxis que las de <a href="http://www.perl.com">perl
      5</a>. Tenga en cuenta que <code>==</code> es simplemente un alias de
      <code>=</code> y se comporta exactamente igual.</p>

      <p>Si realiza una comparación positiva (<code>=</code> o <code>==</code>),
      puede capturar partes agrupadas de la expresión regular. Las partes
      capturadas se almacenan en las variables especiales <code>$1</code> ..
      <code>$9</code>. La cadena completa coincidente con la expresión regular se
      almacena en la variable especial <code>$0</code></p>

      <example><title>Ejemplo</title>
<highlight language="html">
&lt;!--#if expr="$QUERY_STRING = /^sid=([a-zA-Z0-9]+)/" --&gt;
  &lt;!--#set var="session" value="$1" --&gt;
&lt;!--#endif --&gt;
</highlight>
      </example>
      </dd>

      <dt><code><var>string1</var> &lt; <var>string2</var><br />
       <var>string1</var> &lt;= <var>string2</var><br />
       <var>string1</var> &gt; <var>string2</var><br />
       <var>string1</var> &gt;= <var>string2</var></code></dt>

      <dd>Compara <var>string1</var> con <var>string2</var>. Tenga en cuenta
      que las cadenas se comparan <em>literalmente</em> (usando
      <code>strcmp(3)</code>). Por tanto, la cadena "100" es menor que
      "20".</dd>

      <dt><code>( <var>test_condition</var> )</code></dt>
      <dd>verdadero si <var>test_condition</var> es verdadero</dd>

      <dt><code>! <var>test_condition</var></code></dt>
      <dd>verdadero si <var>test_condition</var> es falso</dd>

      <dt><code><var>test_condition1</var> &amp;&amp;
        <var>test_condition2</var></code></dt>
      <dd>verdadero si tanto <var>test_condition1</var> como
      <var>test_condition2</var> son verdaderas</dd>

      <dt><code><var>test_condition1</var> ||
        <var>test_condition2</var></code></dt>
      <dd>verdadero si <var>test_condition1</var> o
      <var>test_condition2</var> es verdadera</dd>
    </dl>

    <p>"<code>=</code>" y "<code>!=</code>" se asocian con más fuerza que
    "<code>&amp;&amp;</code>" y "<code>||</code>". "<code>!</code>" se asocia
    con la mayor fuerza. Así, las siguientes expresiones son equivalentes:</p>

    <example>
<highlight language="html">
&lt;!--#if expr="$a = test1 &amp;&amp; $b = test2" --&gt;
&lt;!--#if expr="($a = test1) &amp;&amp; ($b = test2)" --&gt;
</highlight>
    </example>

    <p>Los operadores booleanos <code>&amp;&amp;</code> y <code>||</code>
    comparten la misma prioridad. Así que, si desea que un operador de este
    tipo se asocie con más fuerza, debe usar paréntesis.</p>

    <p>Todo aquello que no se reconozca como una variable o un operador
    se trata como una cadena. Las cadenas también pueden ir entre comillas:
    <code>'string'</code>. Las cadenas sin comillas no pueden contener
    espacios en blanco (espacios y tabuladores) porque se usan para separar
    tokens como las variables. Si se encuentran varias cadenas consecutivas,
    se concatenan usando espacios en blanco. Así,</p>

    <example>
      <p><code><var>string1</var>&nbsp;&nbsp;&nbsp;&nbsp;<var
      >string2</var></code> da como resultado <code><var>string1</var>&nbsp;<var
      >string2</var></code><br />
      <br />
      y<br />
      <br />
      <code>'<var>string1</var>&nbsp;&nbsp;&nbsp;&nbsp;<var
      >string2</var>'</code> da como resultado <code><var
      >string1</var>&nbsp;&nbsp;&nbsp;&nbsp;<var>string2</var></code>.</p>
    </example>

    <note><title>Optimización de expresiones booleanas</title>
      <p>Si las expresiones se vuelven más complejas y ralentizan el
      procesamiento de forma significativa, puede intentar optimizarlas según
      las reglas de evaluación:</p>
      <ul>
      <li>Las expresiones se evalúan de izquierda a derecha</li>
      <li>Los operadores booleanos binarios (<code>&amp;&amp;</code> y <code>||</code>)
          se cortocircuitan siempre que sea posible. En conjunción con la regla
          anterior, esto significa que <module>mod_include</module> evalúa primero
          la expresión de la izquierda. Si el resultado de la izquierda es
          suficiente para determinar el resultado final, el procesamiento se
          detiene ahí. En caso contrario, evalúa el lado derecho y calcula el
          resultado final a partir de los resultados de ambos lados.</li>
      <li>La evaluación en cortocircuito se desactiva mientras queden
          expresiones regulares por procesar. Estas deben evaluarse para
          rellenar las variables de referencia inversa (<code>$1</code> ..
          <code>$9</code>).</li>
      </ul>
      <p>Si quiere ver cómo se trata una expresión en particular, puede
      recompilar <module>mod_include</module> usando la opción del compilador
      <code>-DDEBUG_INCLUDE</code>. Esto inserta, para cada expresión analizada,
      información del tokenizador, el árbol de análisis sintáctico y cómo se
      evalúa, en la salida que se envía al cliente.</p>
    </note>

    <note><title>Escapar barras en cadenas de expresión regular</title>
     <p>Todas las barras que no estén destinadas a actuar como delimitadores en
     su expresión regular deben escaparse. Esto es así independientemente de su
     significado para el motor de expresiones regulares.</p>
    </note>

</section>

<directivesynopsis>
<name>SSIEndTag</name>
<description>Cadena que termina un elemento include</description>
<syntax>SSIEndTag <var>tag</var></syntax>
<default>SSIEndTag &quot;--&gt;&quot;</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>Esta directiva cambia la cadena que <module>mod_include</module>
    busca para marcar el final de un elemento include.</p>

    <highlight language="config">
SSIEndTag "%&gt;"
    </highlight>

    <note type="warning">
    El valor no puede incluir ningún espacio en blanco.
    </note>

</usage>
<seealso><directive module="mod_include">SSIStartTag</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>SSIUndefinedEcho</name>
<description>Cadena que se muestra cuando se ejecuta echo sobre una variable no definida</description>
<syntax>SSIUndefinedEcho <var>string</var></syntax>
<default>SSIUndefinedEcho &quot;(none)&quot;</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>All</override>

<usage>
    <p>Esta directiva cambia la cadena que <module>mod_include</module>
    muestra cuando una variable no está establecida y se &quot;muestra con echo&quot;.</p>

    <highlight language="config">
SSIUndefinedEcho "&lt;!-- undef --&gt;"
    </highlight>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSIErrorMsg</name>
<description>Mensaje de error que se muestra cuando se produce un error de SSI</description>
<syntax>SSIErrorMsg <var>message</var></syntax>
<default>SSIErrorMsg &quot;[an error occurred while processing this
directive]&quot;</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>All</override>

<usage>
    <p>La directiva <directive>SSIErrorMsg</directive> cambia el mensaje de
    error que se muestra cuando <module>mod_include</module> encuentra un
    error. Para servidores en producción, puede considerar cambiar el mensaje
    de error por defecto a <code>&quot;&lt;!-- Error --&gt;&quot;</code> para que
    el mensaje no se muestre al usuario.</p>

    <p>Esta directiva tiene el mismo efecto que el elemento <code>&lt;!--#config
    errmsg=<var>message</var> --&gt;</code>.</p>

    <highlight language="config">
SSIErrorMsg "&lt;!-- Error --&gt;"
    </highlight>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSIStartTag</name>
<description>Cadena que inicia un elemento include</description>
<syntax>SSIStartTag <var>tag</var></syntax>
<default>SSIStartTag &quot;&lt;!--#&quot;</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>Esta directiva cambia la cadena que <module>mod_include</module>
    busca para marcar un elemento include que debe procesarse.</p>

    <p>Puede querer usar esta opción si tiene 2 servidores analizando la
    salida de un fichero, procesando cada uno comandos distintos (posiblemente en
    momentos distintos).</p>

    <highlight language="config">
SSIStartTag "&lt;%"
SSIEndTag   "%&gt;"
    </highlight>

    <note type="warning">
    El valor no puede incluir ningún espacio en blanco.
    </note>

    <p>El ejemplo anterior, que además especifica un
    <directive module="mod_include">SSIEndTag</directive> correspondiente,
    le permitirá usar directivas SSI como se muestra en el
    ejemplo siguiente:</p>

    <example><title>Directivas SSI con tags de inicio y fin alternativos</title>
      &lt;%printenv %&gt;
    </example>
</usage>
<seealso><directive module="mod_include">SSIEndTag</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>SSITimeFormat</name>
<description>Configura el formato en el que se muestran las cadenas de
fecha</description>
<syntax>SSITimeFormat <var>formatstring</var></syntax>
<default>SSITimeFormat &quot;%A, %d-%b-%Y %H:%M:%S %Z&quot;</default>
<contextlist>
<context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>All</override>

<usage>
<p>Esta directiva cambia el formato en el que se muestran las cadenas de fecha
    al mostrar con echo las variables de entorno <code>DATE</code>. La
    <var>formatstring</var> es como en <code>strftime(3)</code> de la
    biblioteca estándar de C.</p>

    <p>Esta directiva tiene el mismo efecto que el elemento <code>&lt;!--#config
    timefmt=<var>formatstring</var> --&gt;</code>.</p>

    <highlight language="config">
SSITimeFormat "%R, %B %d, %Y"
    </highlight>

    <p>La directiva anterior haría que las horas se mostraran con el
    formato "22:26, June 14, 2002".</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSIETag</name>
<description>Controla si el servidor genera ETags.</description>
<syntax>SSIETag on|off</syntax>
<default>SSIETag off</default>
<contextlist><context>directory</context><context>.htaccess</context></contextlist>
<compatibility>Disponible en la versión 2.2.15 y posteriores.</compatibility>

<usage>
      <p>En circunstancias normales, un fichero filtrado por <module>mod_include</module>
        puede contener elementos que se generan de forma dinámica, o que pueden
        haber cambiado de forma independiente al fichero original. Como resultado, por defecto
        se solicita al servidor que no genere una cabecera <code>ETag</code> para la
        respuesta, añadiendo <code>no-etag</code> a las notas de la petición.</p>

      <p>La directiva <directive>SSIETag</directive> suprime este
        comportamiento, y permite que el servidor genere una cabecera <code>ETag</code>.
        Esto puede usarse para habilitar el cacheo de la salida. Tenga en cuenta que un servidor
        de backend o un generador de contenido dinámico puede generar su propio ETag, ignorando
        <code>no-etag</code>, y este ETag será transmitido por
        <module>mod_include</module> independientemente del valor de este ajuste.
        <directive>SSIETag</directive> puede tomar los siguientes valores:</p>

      <dl>

        <dt><code>off</code></dt>
        <dd>Se añadirá <code>no-etag</code> a las notas de la petición, y se
          solicitará al servidor que no genere un ETag. Cuando un servidor ignore el valor de
          <code>no-etag</code> y genere un ETag de todos modos, dicho ETag se
          respetará.</dd>

        <dt><code>on</code></dt>
        <dd>Se respetarán los ETags existentes, y los ETags generados por el servidor se
          transmitirán en la respuesta.</dd>

      </dl>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSILastModified</name>
<description>Controla si el servidor genera cabeceras
<code>Last-Modified</code>.</description>
<syntax>SSILastModified on|off</syntax>
<default>SSILastModified off</default>
<contextlist><context>directory</context><context>.htaccess</context></contextlist>
<compatibility>Disponible en la versión 2.2.15 y posteriores.</compatibility>

<usage>
      <p>En circunstancias normales, un fichero filtrado por <module>mod_include</module>
        puede contener elementos que se generan de forma dinámica, o que pueden
        haber cambiado de forma independiente al fichero original. Como resultado, por defecto
        la cabecera <code>Last-Modified</code> se elimina de la respuesta.</p>

      <p>La directiva <directive>SSILastModified</directive> anula este
        comportamiento, y permite que se respete la cabecera <code>Last-Modified</code>
        si ya está presente, o que se establezca si la cabecera no está ya presente. Esto puede
        usarse para habilitar el cacheo de la salida. <directive>SSILastModified</directive>
        puede tomar los siguientes valores:</p>

      <dl>

        <dt><code>off</code></dt>
        <dd>La cabecera <code>Last-Modified</code> se eliminará de las respuestas,
          salvo que la directiva <directive module="mod_include">XBitHack</directive>
          esté establecida a <code>full</code> como se describe más abajo.</dd>

        <dt><code>on</code></dt>
        <dd>La cabecera <code>Last-Modified</code> se respetará si ya está
          presente en una respuesta, y se añadirá a la respuesta si la respuesta es un
          fichero y falta la cabecera. La directiva
          <directive module="mod_include">SSILastModified</directive>
          tiene prioridad sobre <directive module="mod_include">XBitHack</directive>.</dd>

      </dl>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSILegacyExprParser</name>
<description>Activa el modo de compatibilidad para expresiones condicionales.</description>
<syntax>SSILegacyExprParser on|off</syntax>
<default>SSILegacyExprParser off</default>
<contextlist><context>directory</context><context>.htaccess</context></contextlist>
<compatibility>Disponible en la versión 2.3.13 y posteriores.</compatibility>

<usage>
    <p>A partir de la versión 2.3.13, <module>mod_include</module> ha pasado a usar
    la nueva sintaxis <a href="../expr.html">ap_expr</a> para las expresiones condicionales
    en los elementos de control de flujo <code>#if</code>. Esta directiva permite
    cambiar a la <a href="#legacyexpr">sintaxis antigua</a>, compatible
    con la versión 2.2.x de Apache HTTPD y anteriores.
    </p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>XBitHack</name>
<description>Analiza las directivas SSI en ficheros con el bit de ejecución
activado</description>
<syntax>XBitHack on|off|full</syntax>
<default>XBitHack off</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>Options</override>

<usage>
    <p>La directiva <directive>XBitHack</directive> controla el análisis
    de los documentos html ordinarios. Esta directiva solo afecta a los ficheros
    asociados con el <glossary>MIME-type</glossary> <code>text/html</code>. <directive
    >XBitHack</directive> puede tomar los siguientes valores:</p>

    <dl>
      <dt><code>off</code></dt>
      <dd>Ningún tratamiento especial para ficheros ejecutables.</dd>

      <dt><code>on</code></dt>
      <dd>Cualquier fichero <code>text/html</code> que tenga activado el bit
      de ejecución de usuario se tratará como un documento html analizado por el
      servidor.</dd>

      <dt><code>full</code></dt>
      <dd>Como <code>on</code>, pero además comprueba el bit de ejecución de
      grupo. Si está activado, se establece la fecha <code>Last-modified</code>
      del fichero devuelto como la fecha de última modificación del fichero. Si
      no está activado, no se envía ninguna fecha de última modificación. Activar
      este bit permite a los clientes y proxies cachear el resultado de
      la petición.

      <note><title>Nota</title>
      <p>No debería usar la opción full a menos que se asegure de que el bit de
      ejecución de grupo está desactivado en todos los scripts SSI que puedan
      hacer <code>#include</code> de un CGI o que, de cualquier otro modo, produzcan
      una salida distinta en cada petición (o que puedan cambiar en peticiones
      posteriores).</p>

      <p>La directiva <directive module="mod_include">SSILastModified</directive>
      tiene prioridad sobre la directiva
      <directive module="mod_include">XBitHack</directive> cuando
      <directive module="mod_include">SSILastModified</directive> está establecida a
      <code>on</code>.</p>
      </note>

      </dd>
    </dl>

</usage>
</directivesynopsis>

</modulesynopsis>
