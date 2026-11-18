<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933740 -->
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

<modulesynopsis metafile="mod_headers.xml.meta">

<name>mod_headers</name>
<description>Personalización de las cabeceras de petición y de
respuesta HTTP</description>
<status>Extension</status>
<sourcefile>mod_headers.c</sourcefile>
<identifier>headers_module</identifier>

<summary>
    <p>Este módulo proporciona directivas para controlar y modificar
    las cabeceras de petición y de respuesta HTTP. Las cabeceras se
    pueden combinar, reemplazar o eliminar.</p>
</summary>

<section id="order"><title>Orden de procesamiento</title>

    <p>Las directivas proporcionadas por <module>mod_headers</module>
    pueden aparecer en casi cualquier parte de la configuración del
    servidor, y su ámbito puede limitarse encerrándolas en <a
    href="../sections.html">secciones de configuración</a>.</p>

    <p>El orden de procesamiento es importante y se ve afectado tanto
    por el orden en el archivo de configuración como por su posición
    en las <a href="../sections.html#merging">secciones de
    configuración</a>. Estas dos directivas tienen un efecto
    diferente si se invierten:</p>

    <highlight language="config">
RequestHeader append MirrorID "mirror 12"
RequestHeader unset MirrorID
    </highlight>

    <p>De esta forma, la cabecera <code>MirrorID</code> no se
    establece. Si se invierten, la cabecera MirrorID se establece con
    el valor "mirror 12".</p>
</section>

<section id="early"><title>Procesamiento temprano y tardío</title>
    <p><module>mod_headers</module> puede aplicarse de forma temprana
    o tardía en la petición. El modo normal es el tardío, en el que
    las cabeceras de <em>petición</em> se establecen justo antes de
    ejecutar el generador de contenido, y las cabeceras de
    <em>respuesta</em> justo cuando la respuesta se envía por la red.
    Use siempre el modo tardío en un servidor en producción.</p>

    <p>El modo temprano está diseñado como ayuda de pruebas/depuración
    para desarrolladores. Las directivas definidas con la palabra
    clave <code>early</code> se establecen justo al principio del
    procesamiento de la petición. Esto significa que pueden usarse
    para simular distintas peticiones y preparar casos de prueba,
    pero también significa que las cabeceras pueden ser modificadas
    en cualquier momento por otros módulos antes de generar una
    respuesta.</p>

    <p>Dado que las directivas tempranas se procesan antes de recorrer
    la configuración de la ruta de la petición, las cabeceras
    tempranas solo pueden establecerse en el contexto de un servidor
    principal o de un host virtual. Las directivas tempranas no
    pueden depender de una ruta de petición, por lo que fallarán en
    contextos como <directive type="section" module="core">Directory</directive>
    o <directive type="section" module="core">Location</directive>.</p>
</section>

<section id="examples"><title>Ejemplos</title>

    <ol>
      <li>
        Copiar todas las cabeceras de petición que comiencen por "TS"
        a las cabeceras de respuesta:

        <highlight language="config">
          Header echo ^TS
        </highlight>
      </li>

      <li>
        Añadir una cabecera, <code>MyHeader</code>, a la respuesta
        que incluya una marca de tiempo de cuándo se recibió la
        petición y cuánto tardó en empezar a servirse. Esta cabecera
        puede usarla el cliente para deducir la carga del servidor o
        para aislar cuellos de botella entre el cliente y el
        servidor.

        <highlight language="config">
          Header set MyHeader "%D %t"
        </highlight>

        <p>da como resultado que se añada esta cabecera a la respuesta:</p>

        <example>
          MyHeader: D=3775428 t=991424704447256
        </example>
      </li>

      <li>
        Saludar a Joe

        <highlight language="config">
Header set MyHeader "Hello Joe. It took %D microseconds for Apache to serve this request."
        </highlight>

        <p>da como resultado que se añada esta cabecera a la respuesta:</p>

        <example>
          MyHeader: Hello Joe. It took D=3775428 microseconds for Apache
          to serve this request.
        </example>
      </li>

      <li>
        Enviar <code>MyHeader</code> en la respuesta de forma
        condicional, solo si la cabecera <code>MyRequestHeader</code>
        está presente en la petición. Esto es útil para construir
        cabeceras en respuesta a algún estímulo del cliente. Tenga en
        cuenta que este ejemplo requiere los servicios del módulo
        <module>mod_setenvif</module>.

        <highlight language="config">
SetEnvIf MyRequestHeader myvalue HAVE_MyRequestHeader
Header set MyHeader "%D %t mytext" env=HAVE_MyRequestHeader
        </highlight>

        <p>Si la cabecera <code>MyRequestHeader: myvalue</code> está
        presente en la petición HTTP, la respuesta contendrá la
        siguiente cabecera:</p>

        <example>
          MyHeader: D=3775428 t=991424704447256 mytext
        </example>
      </li>

      <li>
        Habilitar que DAV funcione con Apache ejecutando HTTP a
        través de hardware SSL (<a href="http://svn.haxx.se/users/archive-2006-03/0549.shtml">descripción
        del problema</a>) reemplazando <var>https:</var> por
        <var>http:</var> en la cabecera <var>Destination</var>:

        <highlight language="config">
          RequestHeader edit Destination ^https: http: early
        </highlight>
      </li>

      <li>
        Establecer el mismo valor de cabecera bajo múltiples
        condiciones no exclusivas, pero sin duplicar el valor en la
        cabecera final. Si todas las condiciones siguientes se
        aplicaran a una petición (es decir, si las variables de
        entorno <code>CGI</code>, <code>NO_CACHE</code> y
        <code>NO_STORE</code> existieran todas para la petición):

        <highlight language="config">
Header merge Cache-Control no-cache env=CGI
Header merge Cache-Control no-cache env=NO_CACHE
Header merge Cache-Control no-store env=NO_STORE
        </highlight>

        <p>entonces la respuesta contendría la siguiente cabecera:</p>

        <example>
          Cache-Control: no-cache, no-store
        </example>

        <p>Si se hubiera usado <code>append</code> en lugar de
        <code>merge</code>, la respuesta contendría la siguiente
        cabecera:</p>

        <example>
          Cache-Control: no-cache, no-cache, no-store
        </example>
      </li>
      <li>
        Establecer una cookie de prueba solo si el cliente no nos
        envió una cookie
        <highlight language="config">
          Header set Set-Cookie testcookie "expr=-z %{req:Cookie}"
        </highlight>
      </li>
      <li>
        Añadir una cabecera de caché para las respuestas con código
        de estado HTTP 200
        <highlight language="config">
          Header append Cache-Control s-maxage=600 "expr=%{REQUEST_STATUS} == 200"
        </highlight>
      </li>

    </ol>
</section>

<directivesynopsis>
<name>RequestHeader</name>
<description>Configura las cabeceras de petición HTTP</description>
<syntax>RequestHeader add|append|edit|edit*|merge|set|setifempty|unset
<var>header</var> [[expr=]<var>value</var> [<var>replacement</var>]
[early|env=[!]<var>varname</var>|expr=<var>expression</var>]]
</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>FileInfo</override>
<compatibility>SetIfEmpty disponible en la versión 2.4.7 y posteriores, expr=value
disponible en la versión 2.4.10 y posteriores</compatibility>

<usage>
    <p>Esta directiva puede reemplazar, combinar, cambiar o eliminar
    cabeceras de petición HTTP. La cabecera se modifica justo antes
    de que se ejecute el manejador de contenido, lo que permite
    modificar las cabeceras entrantes. La acción que realiza viene
    determinada por el primer argumento. Puede ser uno de los
    siguientes valores:</p>

    <dl>

    <dt><code>add</code></dt>
    <dd>La cabecera de petición se añade al conjunto existente de
    cabeceras, incluso si esa cabecera ya existe. Esto puede dar
    lugar a que haya dos (o más) cabeceras con el mismo nombre. Esto
    puede provocar consecuencias imprevistas, y en general deberían
    usarse <code>set</code>, <code>append</code> o <code>merge</code>
    en su lugar.</dd>

    <dt><code>append</code></dt>
    <dd>La cabecera de petición se añade a cualquier cabecera
    existente con el mismo nombre. Cuando se combina un valor nuevo
    con una cabecera existente, se separa de la cabecera existente
    con una coma. Esta es la forma estándar en HTTP de dar varios
    valores a una cabecera.</dd>

    <dt><code>edit</code></dt>
    <dt><code>edit*</code></dt>
    <dd>Si esta cabecera de petición existe, su valor se transforma
    según una operación de búsqueda y sustitución con una <glossary
    ref="regex">expresión regular</glossary>. El argumento
    <var>value</var> es una <glossary ref="regex">expresión
    regular</glossary>, y <var>replacement</var> es una cadena de
    sustitución, que puede contener referencias inversas o
    especificadores de formato. La forma <code>edit</code>
    coincidirá y sustituirá exactamente una vez en un valor de
    cabecera, mientras que la forma <code>edit*</code> sustituirá
    <em>todas</em> las apariciones del patrón de búsqueda si aparece
    más de una vez.</dd>

    <dt><code>merge</code></dt>
    <dd>La cabecera de petición se añade a cualquier cabecera
    existente con el mismo nombre, a menos que el valor que se va a
    añadir ya aparezca en la lista de valores separados por comas de
    la cabecera existente. Cuando se combina un valor nuevo con una
    cabecera existente, se separa de la cabecera existente con una
    coma. Esta es la forma estándar en HTTP de dar varios valores a
    una cabecera. Los valores se comparan distinguiendo mayúsculas y
    minúsculas, y después de haber procesado todos los
    especificadores de formato. Los valores entre comillas dobles se
    consideran distintos de valores idénticos sin comillas.</dd>

    <dt><code>set</code></dt>
    <dd>La cabecera de petición se establece, reemplazando cualquier
    cabecera anterior con este nombre</dd>

    <dt><code>setifempty</code></dt>
    <dd>La cabecera de petición se establece, pero solo si no hay
    ninguna cabecera anterior con este nombre.<br />
    Disponible en la versión 2.4.7 y posteriores.</dd>

    <dt><code>unset</code></dt>
    <dd>Se elimina la cabecera de petición con este nombre, si
    existe. Si hay varias cabeceras con el mismo nombre, se
    eliminarán todas. <var>value</var> debe omitirse.</dd>
    </dl>

    <p>A este argumento le sigue un nombre de cabecera, que puede
    incluir los dos puntos finales, aunque no es obligatorio. No se
    distingue entre mayúsculas y minúsculas. Para <code>set</code>,
    <code>append</code>, <code>merge</code> y <code>add</code> se da
    un <var>value</var> como tercer argumento. Si un <var>value</var>
    contiene espacios, debe ir entre comillas dobles. Para
    <code>unset</code>, no debe darse ningún <var>value</var>.
    <var>value</var> puede ser una cadena de caracteres, una cadena
    que contenga especificadores de formato, o una combinación de
    ambos. Los especificadores de formato admitidos son los mismos
    que para <directive module="mod_headers">Header</directive>;
    consulte esa directiva para más detalles. Para <code>edit</code>
    se requieren tanto un <var>value</var> como un
    <var>replacement</var>, que son respectivamente una <glossary
    ref="regex">expresión regular</glossary> y una cadena de
    sustitución.</p>

    <p>A la directiva <directive>RequestHeader</directive> puede
    seguirle un argumento adicional, que puede ser cualquiera de
    estos:</p>
    <dl>
    <dt><code>early</code></dt>
    <dd>Especifica el <a href="#early">procesamiento temprano</a>.</dd>
    <dt><code>env=[!]<var>varname</var></code></dt>
    <dd>La directiva se aplica solo si la <a href="../env.html"
        >variable de entorno</a> <code>varname</code> existe.
        Un <code>!</code> delante de <code>varname</code> invierte la
        comprobación, de modo que la directiva se aplica solo si
        <code>varname</code> no está definida.</dd>
    <dt><code>expr=<var>expression</var></code></dt>
    <dd>La directiva se aplica solo si <var>expression</var> evalúa a
        verdadero. Los detalles de la sintaxis y evaluación de
        expresiones se documentan en <a href="../expr.html">ap_expr</a>.</dd>
    </dl>

    <p>Excepto en modo <a href="#early">early</a>, la directiva
    <directive>RequestHeader</directive> se procesa justo antes de
    que la petición sea ejecutada por su manejador en la fase de
    fixup. Esto debería permitir que las cabeceras generadas por el
    navegador, o por los filtros de entrada de Apache, puedan ser
    sobrescritas o modificadas.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>Header</name>
<description>Configura las cabeceras de respuesta HTTP</description>
<syntax>Header [<var>condition</var>] add|append|echo|edit|edit*|merge|set|setifempty|unset|note
<var>header</var> [[expr=]<var>value</var> [<var>replacement</var>]
[early|env=[!]<var>varname</var>|expr=<var>expression</var>]]
</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>FileInfo</override>
<compatibility>SetIfEmpty disponible en la versión 2.4.7 y posteriores, expr=value
disponible en la versión 2.4.10 y posteriores</compatibility>

<usage>
    <p>Esta directiva puede reemplazar, combinar o eliminar cabeceras
    de respuesta HTTP. La cabecera se modifica justo después de que
    se ejecuten el manejador de contenido y los filtros de salida, lo
    que permite modificar las cabeceras salientes.</p>

    <p> El argumento opcional <var>condition</var> determina contra
    qué tabla interna de cabeceras de respuesta operará esta
    directiva: <code>onsuccess</code> (por defecto, puede omitirse) o
    <code>always</code>. La diferencia entre ambas listas es que las
    cabeceras contenidas en la segunda se añaden a la respuesta
    incluso en caso de error, y persisten a través de redirecciones
    internas (por ejemplo, manejadores de ErrorDocument).

    Tenga en cuenta también que repetir esta directiva con ambas
    condiciones tiene sentido en algunos escenarios, porque
    <code>always</code> no es un superconjunto de <code>onsuccess</code>
    respecto a las cabeceras existentes:</p>

    <ul>
       <li> Está añadiendo una cabecera a una respuesta no exitosa (no 2xx)
            generada localmente, como una redirección, en cuyo caso en la
            respuesta final solo se usa la tabla correspondiente a
            <code>always</code>.</li>
       <li> Está modificando o eliminando una cabecera generada por un
            script CGI o por <module>mod_proxy_fcgi</module>, en cuyo caso
            las cabeceras de los scripts CGI están en la tabla
            correspondiente a <code>always</code> y no en la tabla por
            defecto.</li>
       <li> Está modificando o eliminando una cabecera generada por alguna
            parte del servidor, pero esa cabecera no se encuentra con la
            condición <code>onsuccess</code> por defecto.</li>
    </ul>

    <p>Esta diferencia entre <code>onsuccess</code> y <code>always</code>
    es una característica que resulta de cómo httpd almacena internamente
    las cabeceras de una respuesta HTTP, ya que no ofrece ninguna lista
    "normalizada" única de cabeceras. El principal problema que puede
    surgir si no se tiene en cuenta este concepto al escribir la
    configuración es que algunas respuestas HTTP pueden acabar con la
    misma cabecera duplicada (confundiendo a los usuarios o incluso a
    veces a los clientes HTTP). Por ejemplo, suponga que tiene una
    configuración sencilla de proxy PHP con <module>mod_proxy_fcgi</module>
    y que sus scripts PHP de backend añaden la cabecera
    <code>X-Foo: bar</code> a cada respuesta HTTP. Como se describió antes,
    <module>mod_proxy_fcgi</module> usa la tabla <code>always</code> para
    almacenar cabeceras, así que una configuración como la siguiente acaba
    dando un resultado incorrecto, concretamente con la cabecera duplicada
    con ambos valores:</p>

    <highlight language="config">
# El valor de X-Foo se establece en la tabla de cabeceras 'onsuccess'
Header set X-Foo: baz
    </highlight>

    <p>Para evitar esta limitación, hay algunos patrones de configuración
    conocidos que pueden ayudar, como el siguiente:</p>

        <highlight language="config">
# 'onsuccess' puede omitirse ya que es el valor por defecto
Header onsuccess unset X-Foo
Header always set X-Foo "baz"
        </highlight>

    <p>Aparte del parámetro <var>condition</var> descrito antes, puede
    limitar una acción según códigos de estado HTTP, por ejemplo para
    peticiones proxied o CGI. Vea el ejemplo que usa %{REQUEST_STATUS}
    en la sección anterior.</p>

    <p>La acción que realiza viene determinada por el primer argumento
    (segundo argumento si se especifica una <var>condition</var>). Puede
    ser uno de los siguientes valores:</p>

    <note type="warning"><title>Advertencia</title>
        <p>Lea la diferencia entre las listas de cabeceras
        <code>always</code> y <code>onsuccess</code> descrita antes,
        antes de empezar a leer la lista de acciones, ya que ese
        concepto importante sigue aplicándose. De hecho, cada acción
        funciona como se describe, pero solo sobre la lista de
        cabeceras de destino.</p>
    </note>

    <dl>
    <dt><code>add</code></dt>
    <dd>La cabecera de respuesta se añade al conjunto existente de
    cabeceras, incluso si esa cabecera ya existe. Esto puede dar
    lugar a que haya dos (o más) cabeceras con el mismo nombre. Esto
    puede provocar consecuencias imprevistas, y en general deberían
    usarse <code>set</code>, <code>append</code> o <code>merge</code>
    en su lugar.</dd>

    <dt><code>append</code></dt>
    <dd>La cabecera de respuesta se añade a cualquier cabecera
    existente con el mismo nombre. Cuando se combina un valor nuevo
    con una cabecera existente, se separa de la cabecera existente
    con una coma. Esta es la forma estándar en HTTP de dar varios
    valores a una cabecera. Tenga en cuenta que la cabecera
    <code>Set-Cookie</code> es una excepción: <rfc>6265</rfc> exige
    varias cabeceras <code>Set-Cookie</code> en lugar de combinar los
    valores con comas. Use <code>add</code> en lugar de
    <code>append</code> para <code>Set-Cookie</code>.</dd>

    <dt><code>echo</code></dt>
    <dd>Las cabeceras de petición con este nombre se repiten en las
    cabeceras de respuesta. <var>header</var> puede ser una
    <glossary ref="regex">expresión regular</glossary>.
    <var>value</var> debe omitirse.</dd>

    <dt><code>edit</code></dt>
    <dt><code>edit*</code></dt>
    <dd>Si esta cabecera de respuesta existe, su valor se transforma
    según una operación de búsqueda y sustitución con una <glossary
    ref="regex">expresión regular</glossary>. El argumento
    <var>value</var> es una <glossary ref="regex">expresión
    regular</glossary>, y <var>replacement</var> es una cadena de
    sustitución, que puede contener referencias inversas o
    especificadores de formato. La forma <code>edit</code>
    coincidirá y sustituirá exactamente una vez en un valor de
    cabecera, mientras que la forma <code>edit*</code> sustituirá
    <em>todas</em> las apariciones del patrón de búsqueda si aparece
    más de una vez.</dd>

    <dt><code>merge</code></dt>
    <dd>La cabecera de respuesta se añade a cualquier cabecera
    existente con el mismo nombre, a menos que el valor que se va a
    añadir ya aparezca en la lista de valores separados por comas de
    la cabecera. Cuando se combina un valor nuevo con una cabecera
    existente, se separa de la cabecera existente con una coma. Esta
    es la forma estándar en HTTP de dar varios valores a una
    cabecera. Los valores se comparan distinguiendo mayúsculas y
    minúsculas, y después de haber procesado todos los
    especificadores de formato. Los valores entre comillas dobles se
    consideran distintos de valores idénticos sin comillas.</dd>

    <dt><code>set</code></dt>
    <dd>La cabecera de respuesta se establece, reemplazando cualquier
    cabecera anterior con este nombre. El <var>value</var> puede ser
    una cadena de formato.</dd>

    <dt><code>setifempty</code></dt>
    <dd>La cabecera de petición se establece, pero solo si no hay
    ninguna cabecera anterior con este nombre.
    <note>
    La cabecera Content-Type es un caso especial, ya que puede ocurrir
    que su valor ya se haya determinado pero la cabecera todavía no
    forme parte de la respuesta cuando se evalúa
    <code>setifempty</code>. Es más seguro usar <code>set</code> para
    este caso, como en el siguiente ejemplo:
    <highlight language="config">
    Header set Content-Type "text/plain" "expr=-z %{CONTENT_TYPE}"
    </highlight>
    </note></dd>


    <dt><code>unset</code></dt>
    <dd>Se elimina la cabecera de respuesta con este nombre, si
    existe. Si hay varias cabeceras con el mismo nombre, se
    eliminarán todas. <var>value</var> debe omitirse.</dd>

    <dt><code>note</code></dt>
    <dd>El valor de la <var>header</var> de respuesta indicada se
    copia en una nota interna cuyo nombre viene dado por
    <var>value</var>. Esto es útil si una cabecera enviada por un CGI
    o un recurso proxied se configura para eliminarse, pero también
    debería registrarse.<br />
    Disponible en la versión 2.4.7 y posteriores.</dd>

    </dl>

    <p>A este argumento le sigue un nombre de <var>header</var>, que
    puede incluir los dos puntos finales, aunque no es obligatorio.
    No se distingue entre mayúsculas y minúsculas para
    <code>set</code>, <code>append</code>, <code>merge</code>,
    <code>add</code>, <code>unset</code> y <code>edit</code>. El
    nombre de <var>header</var> para <code>echo</code> distingue
    entre mayúsculas y minúsculas y puede ser una <glossary
    ref="regex">expresión regular</glossary>.</p>

    <p>Para <code>set</code>, <code>append</code>, <code>merge</code>
    y <code>add</code> se especifica un <var>value</var> como
    siguiente argumento. Si <var>value</var> contiene espacios, debe
    ir entre comillas dobles. <var>value</var> puede ser una cadena
    de caracteres, una cadena que contenga especificadores de
    formato propios de <module>mod_headers</module> (y literales de
    caracteres), o una expresión de <a href="../expr.html">ap_expr</a>
    precedida de <em>expr=</em></p>

    <p> Se admiten los siguientes especificadores de formato en <var>value</var>:</p>

    <table border="1" style="zebra">
    <columnspec><column width=".25"/><column width=".75"/></columnspec>
    <tr><th>Formato</th><th>Descripción</th></tr>
    <tr><td><code>%%</code></td>
        <td>El signo de porcentaje</td></tr>

    <tr><td><code>%t</code></td>
        <td>El momento en que se recibió la petición en tiempo
        universal coordinado desde la época (1 de enero de 1970),
        medido en microsegundos. El valor va precedido de
        <code>t=</code>.</td></tr>

    <tr><td><code>%D</code></td>
        <td>El tiempo transcurrido desde que se recibió la petición
        hasta que las cabeceras se envían por la red. Esto es una
        medida de la duración de la petición. El valor va precedido
        de <code>D=</code>. El valor se mide en microsegundos.</td></tr>

    <tr><td><code>%l</code></td>
        <td>Las cargas medias actuales del propio servidor. Está
        diseñado para exponer los valores obtenidos mediante
        <code>getloadavg()</code>, y representa la carga media
        actual, la media de 5 minutos y la media de 15 minutos. El
        valor va precedido de <code>l=</code>, separando cada media
        con <code>/</code>.<br />
        Disponible en la versión 2.4.4 y posteriores.
        </td></tr>

    <tr><td><code>%i</code></td>
        <td>El porcentaje actual de inactividad de httpd (de 0 a 100)
        según los procesos e hilos disponibles. El valor va precedido
        de <code>i=</code>.<br />
        Disponible en la versión 2.4.4 y posteriores.
        </td></tr>

    <tr><td><code>%b</code></td>
        <td>El porcentaje actual de ocupación de httpd (de 0 a 100)
        según los procesos e hilos disponibles. El valor va precedido
        de <code>b=</code>.<br />
        Disponible en la versión 2.4.4 y posteriores.
        </td></tr>

    <tr><td><code>%{VARNAME}e</code></td>
        <td>El contenido de la <a href="../env.html">variable de
        entorno</a> <code>VARNAME</code>.</td></tr>

    <tr><td><code>%{VARNAME}s</code></td>
        <td>El contenido de la <a href="mod_ssl.html#envvars">variable
        de entorno SSL</a> <code>VARNAME</code>, si
        <module>mod_ssl</module> está habilitado.</td></tr>

    </table>

    <note><title>Nota</title>
      <p>El especificador de formato <code>%s</code> solo está
      disponible en Apache 2.1 y posteriores; puede usarse en lugar
      de <code>%e</code> para evitar la sobrecarga de habilitar
      <code>SSLOptions +StdEnvVars</code>. Si de todos modos debe
      habilitarse <code>SSLOptions +StdEnvVars</code> por algún otro
      motivo, <code>%e</code> será más eficiente que
      <code>%s</code>.</p>
    </note>

    <note><title>Nota sobre los valores de expresión</title>
    <p> Cuando el parámetro value usa el analizador de <a href="../expr.html">ap_expr</a>,
    parte de la sintaxis de expresión difiere de los ejemplos que
    evalúan expresiones <em>booleanas</em>, como &lt;If&gt;:</p>
    <ul>
      <li>El punto de partida de la gramática es 'string' en lugar de 'expr'.</li>
      <li>Las llamadas a función usan la sintaxis %{nombrefuncion:arg}
          en lugar de nombrefuncion(arg).</li>
      <li>Las funciones con múltiples argumentos no son actualmente
          accesibles desde este punto de partida</li>
      <li>Encierre entre comillas todo el parámetro, como en
          <highlight language="config">
        Header set foo-checksum "expr=%{md5:foo}"
          </highlight>
       </li>

    </ul>
    </note>

    <p>Para <code>edit</code> existen tanto un argumento
    <var>value</var>, que es una <glossary ref="regex">expresión
    regular</glossary>, como una cadena <var>replacement</var>
    adicional. A partir de la versión 2.4.7 la cadena de sustitución
    también puede contener especificadores de formato.</p>

    <p>A la directiva <directive>Header</directive> puede seguirle un
    argumento adicional, que puede ser cualquiera de estos:</p>
    <dl>
    <dt><code>early</code></dt>
    <dd>Especifica el <a href="#early">procesamiento temprano</a>.</dd>
    <dt><code>env=[!]<var>varname</var></code></dt>
    <dd>La directiva se aplica solo si la <a href="../env.html"
        >variable de entorno</a> <code>varname</code> existe.
        Un <code>!</code> delante de <code>varname</code> invierte la
        comprobación, de modo que la directiva se aplica solo si
        <code>varname</code> no está definida.</dd>
    <dt><code>expr=<var>expression</var></code></dt>
    <dd>La directiva se aplica solo si <var>expression</var> evalúa a
        verdadero. Los detalles de la sintaxis y evaluación de
        expresiones se documentan en <a href="../expr.html">ap_expr</a>.
        <highlight language="config">
# Esto retrasa la evaluación de la cláusula de condición en comparación con &lt;If&gt;
Header always set CustomHeader my-value "expr=%{REQUEST_URI} =~ m#^/special_path.php$#"
        </highlight>
        </dd>
    </dl>

    <p>Excepto en modo <a href="#early">early</a>, las directivas
    <directive>Header</directive> se procesan justo antes de que la
    respuesta se envíe a la red. Esto significa que es posible
    establecer y/o sobrescribir la mayoría de las cabeceras, excepto
    algunas cabeceras añadidas por el filtro de cabeceras HTTP. Antes
    de la versión 2.2.12, no era posible cambiar la cabecera
    Content-Type con esta directiva.</p>

</usage>
</directivesynopsis>

</modulesynopsis>
