<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
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

<modulesynopsis metafile="mod_filter.xml.meta">

<name>mod_filter</name>
<description>Módulo de configuración de filtros inteligentes sensibles al contexto</description>
<status>Base</status>
<sourcefile>mod_filter.c</sourcefile>
<identifier>filter_module</identifier>

<summary>
    <p>Este módulo permite una configuración inteligente y sensible al contexto de
    los filtros de contenido de salida. Por ejemplo, apache puede configurarse para
    procesar distintos tipos de contenido a través de distintos filtros, incluso
    cuando el tipo de contenido no se conoce de antemano (por ejemplo, en un proxy).</p>

    <p><module>mod_filter</module> funciona introduciendo una indirección en
    la cadena de filtros. En lugar de insertar filtros en la cadena, se inserta
    un arnés de filtro ("filter harness") que a su vez despacha condicionalmente
    a un proveedor de filtro. Cualquier filtro de contenido puede usarse como proveedor
    de <module>mod_filter</module>; no se requiere ningún cambio en los módulos de
    filtro existentes (aunque podría ser posible simplificarlos).</p>
</summary>

<section id="smart"><title>Filtrado inteligente</title>
    <p>En el modelo de filtrado tradicional, los filtros se insertan incondicionalmente
    mediante <directive module="mod_mime">AddOutputFilter</directive> y similares.
    Cada filtro necesita entonces determinar si debe ejecutarse, y los administradores del
    servidor disponen de poca flexibilidad para permitir que la cadena se
    configure dinámicamente.</p>

    <p>Por el contrario, <module>mod_filter</module> ofrece a los administradores del servidor
    una gran flexibilidad a la hora de configurar la cadena de filtros. De hecho,
    los filtros pueden insertarse en función de <a href="../expr.html">expresiones</a>
    booleanas complejas. Esto generaliza la limitada
    flexibilidad que ofrece <directive>AddOutputFilterByType</directive>.</p>
</section>

<section id="terms"><title>Declaraciones de filtro, proveedores y cadenas</title>
    <p class="figure">
    <img src="../images/mod_filter_old.gif" width="160" height="310"
    alt="[Esta imagen muestra el modelo de filtro tradicional]"/><br />
    <dfn>Figura 1:</dfn> El modelo de filtro tradicional</p>

    <p>En el modelo tradicional, los filtros de salida son una simple cadena
    desde el generador de contenido (handler) hasta el cliente. Esto funciona bien
    siempre que la cadena de filtros pueda configurarse correctamente, pero presenta
    problemas cuando los filtros necesitan configurarse dinámicamente en función
    del resultado del handler.</p>

    <p class="figure">
    <img src="../images/mod_filter_new.gif" width="423" height="331"
    alt="[Esta imagen muestra el modelo de mod_filter]"/><br />
    <dfn>Figura 2:</dfn> El modelo de <module>mod_filter</module></p>

    <p><module>mod_filter</module> funciona introduciendo una indirección en
    la cadena de filtros. En lugar de insertar filtros en la cadena, se inserta
    un arnés de filtro que a su vez despacha condicionalmente
    a un proveedor de filtro. Cualquier filtro de contenido puede usarse como proveedor
    de <module>mod_filter</module>; no se requiere ningún cambio en los módulos de
    filtro existentes (aunque podría ser posible simplificarlos). Puede haber
    varios proveedores para un mismo filtro, pero no se ejecutará más de un proveedor
    para una misma petición.</p>

    <p>Una cadena de filtros está formada por cualquier número de instancias del arnés
    de filtro, cada una de las cuales puede tener cualquier número de proveedores. Un caso
    especial es el de un único proveedor con despacho incondicional: esto
    equivale a insertar el filtro proveedor directamente en la cadena.</p>
</section>

<section id="config"><title>Configuración de la cadena</title>
    <p>Configurar una cadena de filtros con
    <module>mod_filter</module> consta de tres etapas. Para más detalles sobre las
    directivas, vea más abajo.</p>

    <dl>
    <dt>Declarar filtros</dt>
    <dd>La directiva <directive module="mod_filter">FilterDeclare</directive>
        declara un nuevo filtro inteligente, asignándole un nombre y un tipo de
        filtro opcional.</dd>
    <dt>Registrar proveedores</dt>
    <dd>La directiva <directive module="mod_filter"
    >FilterProvider</directive> registra un proveedor para un filtro. El filtro puede
    haberse declarado con <directive module="mod_filter"
    >FilterDeclare</directive>; si no, FilterProvider lo declarará implícitamente.
    El proveedor debe haberse
    registrado mediante <code>ap_register_output_filter</code> por algún módulo.
    El último argumento de <directive module="mod_filter"
    >FilterProvider</directive> es una expresión: el proveedor se
    seleccionará para ejecutarse en una petición si y solo si la expresión
    se evalúa como verdadera. La expresión puede evaluar cabeceras de petición o
    respuesta HTTP, variables de entorno o el Handler usado por esa petición.
    A diferencia de versiones anteriores, mod_filter ahora admite expresiones complejas
    que combinan varios criterios con lógica AND / OR (&amp;&amp; / ||)
    y paréntesis. Los detalles de la sintaxis de las expresiones se describen en
    la <a href="../expr.html">documentación de ap_expr</a>.</dd>

    <dt>Configurar la cadena</dt>
    <dd>Las directivas anteriores construyen componentes de una cadena de filtro
    inteligente, pero no la configuran para que se ejecute. La directiva <directive module="mod_filter"
    >FilterChain</directive> construye una cadena de filtros a partir de los filtros
    inteligentes declarados, ofreciendo la flexibilidad de insertar filtros al
    principio o al final de la cadena, eliminar un filtro o vaciar la cadena.</dd>
</dl>
</section>
<section id="errordocs"><title>Filtrado y estado de la respuesta</title>
    <p>Normalmente, mod_filter solo ejecuta filtros en respuestas con
    estado HTTP 200 (OK). Si desea filtrar documentos con
    otros estados de respuesta, puede establecer la variable de entorno
    <var>filter-errordocs</var>, y funcionará en todas las respuestas
    independientemente de su estado. Para refinar esto aún más, puede usar
    condiciones de expresión con <directive>FilterProvider</directive>.</p>
</section>
<section id="upgrade"><title>Actualización desde la configuración de Apache HTTP Server 2.2</title>
    <p>La directiva <directive module="mod_filter">FilterProvider</directive>
    ha cambiado desde httpd 2.2: los argumentos <var>match</var> y
    <var>dispatch</var> se sustituyen por una única
    <var>expression</var>, más versátil. En general, puede convertir
    un par match/dispatch en los dos lados de una expresión, usando
    algo como:</p>
    <example>"dispatch = 'match'"</example>
    <p>Las cabeceras de petición, las cabeceras de respuesta y las variables de entorno
    ahora se interpretan con la sintaxis <var>%{req:foo}</var>,
    <var>%{resp:foo}</var> y <var>%{env:foo}</var> respectivamente.
    También se admiten las variables <var>%{HANDLER}</var> y <var>%{CONTENT_TYPE}</var>.</p>
    <p>Tenga en cuenta que la coincidencia ya no admite coincidencias de subcadena. Pueden
    sustituirse por coincidencias de expresión regular.</p>
</section>

<section id="examples"><title>Ejemplos</title>
    <dl>
    <dt>Server Side Includes (SSI)</dt>
    <dd>Un caso sencillo que sustituye a <directive>AddOutputFilterByType</directive>.
        Este ejemplo crea un nuevo filtro inteligente llamado "SSI" que aprovecha condicionalmente
        el filtro "INCLUDES" de <module>mod_include</module> como proveedor.
    <highlight language="config">
FilterDeclare SSI
FilterProvider SSI INCLUDES "%{CONTENT_TYPE} =~ m|^text/html|"
FilterChain SSI
    </highlight>
    </dd>

    <dt>Server Side Includes (SSI)</dt>
    <dd>Lo mismo que el anterior, pero despachando según el handler (comportamiento
    clásico de SSI; se procesan los archivos .shtml).
    <highlight language="config">
FilterProvider SSI INCLUDES "%{HANDLER} = 'server-parsed'"
FilterChain SSI
    </highlight>
    </dd>

    <dt>Emular mod_gzip con mod_deflate</dt>
    <dd>Este ejemplo muestra las propiedades dinámicas que se otorgan a los filtros
        tradicionales cuando se construye un filtro inteligente alrededor de ellos. Se crea
        un nuevo filtro inteligente llamado "gzip" que inserta dinámicamente el filtro
        INFLATE de <module>mod_deflate</module> solo si "gzip" NO está en la cabecera Accept-Encoding.
        El filtro inteligente gzip se ejecuta con el tipo CONTENT_SET.
    <highlight language="config">
FilterDeclare gzip CONTENT_SET
FilterProvider gzip INFLATE "%{req:Accept-Encoding} !~ /gzip/"
FilterChain gzip
    </highlight>
    </dd>

    <dt>Reducción de resolución de imágenes</dt>
    <dd>Este ejemplo muestra otras posibilidades que ofrece el filtrado inteligente.
        Supongamos que queremos reducir la resolución de todas las imágenes web, y tener distintos
        proveedores de filtro para manipular GIF, JPEG y PNG.
        La configuración define los filtros inteligentes "unpack" y "repack" mediante
        el arnés que invoca a los proveedores de filtro subyacentes adecuados en función de
        el tipo de contenido en tiempo de ejecución.
    <highlight language="config">
FilterProvider unpack jpeg_unpack "%{CONTENT_TYPE} = 'image/jpeg'"
FilterProvider unpack gif_unpack  "%{CONTENT_TYPE} = 'image/gif'"
FilterProvider unpack png_unpack  "%{CONTENT_TYPE} = 'image/png'"

FilterProvider downsample downsample_filter "%{CONTENT_TYPE} = m|^image/(jpeg|gif|png)|"
FilterProtocol downsample "change=yes"

FilterProvider repack jpeg_pack "%{CONTENT_TYPE} = 'image/jpeg'"
FilterProvider repack gif_pack  "%{CONTENT_TYPE} = 'image/gif'"
FilterProvider repack png_pack  "%{CONTENT_TYPE} = 'image/png'"
&lt;Location "/image-filter"&gt;
    FilterChain unpack downsample repack
&lt;/Location&gt;
    </highlight>
    </dd>
    </dl>
</section>

<section id="protocol"><title>Manejo del protocolo</title>
    <p>Históricamente, cada filtro es responsable de asegurar que los cambios que
    introduce se reflejen correctamente en las cabeceras de la respuesta HTTP,
    y de no ejecutarse cuando eso suponga un cambio ilegal. Esto
    impone a los autores de filtros la carga de reimplementar cierta funcionalidad
    común en cada filtro:</p>

    <ul>
    <li>Muchos filtros cambian el contenido, invalidando etiquetas de contenido,
    sumas de comprobación, hashes y longitudes existentes.</li>

    <li>Los filtros que necesitan una respuesta completa e ininterrumpida como entrada deben
    asegurarse de no recibir rangos de bytes (byteranges) de un backend.</li>

    <li>Los filtros que transforman la salida deben asegurarse de no
    incumplir una cabecera <code>Cache-Control: no-transform</code> del
    backend.</li>

    <li>Los filtros pueden hacer que las respuestas no se puedan cachear.</li>
    </ul>

    <p><module>mod_filter</module> pretende ofrecer un manejo genérico de estos
    detalles de implementación de filtros, reduciendo la complejidad requerida en los
    módulos de filtro de contenido. Esto es un trabajo en curso; la directiva
    <directive module="mod_filter">FilterProtocol</directive> implementa
    parte de esta funcionalidad por compatibilidad con módulos de Apache 2.0.
    Para httpd 2.1 y posteriores, la API
    <code>ap_register_output_filter_protocol</code> y
    <code>ap_filter_protocol</code> permite a los módulos de filtro
    declarar su propio comportamiento.</p>

    <p>Al mismo tiempo, <module>mod_filter</module> no debería interferir
    con un filtro que quiera gestionar todos los aspectos del protocolo. Por
    defecto (es decir, en ausencia de cualquier directiva <directive module="mod_filter"
    >FilterProtocol</directive>), <module>mod_filter</module>
    dejará las cabeceras intactas.</p>

    <p>En el momento de escribir esto, esta funcionalidad apenas está probada,
    ya que los módulos de uso común están diseñados para funcionar con 2.0.
    Los módulos que la usen deben probarla cuidadosamente.</p>
</section>

<directivesynopsis>
<name>AddOutputFilterByType</name>
<description>asigna un filtro de salida a un tipo de medio concreto</description>
<syntax>AddOutputFilterByType <var>filter</var>[;<var>filter</var>...]
<var>media-type</var> [<var>media-type</var>] ...</syntax>
<contextlist><context>server config</context>
<context>virtual host</context><context>directory</context>
<context>.htaccess</context></contextlist>
<override>FileInfo</override>
<compatibility>Tenía limitaciones importantes antes de
pasar a <module>mod_filter</module> en la versión 2.3.7</compatibility>

<usage>
    <p>Esta directiva activa un <a
    href="../filter.html">filtro</a> de salida concreto para una petición en función del
    <glossary>media-type</glossary> de la respuesta.</p>

    <p>El siguiente ejemplo usa el filtro <code>DEFLATE</code>, que
    proporciona <module>mod_deflate</module>. Comprimirá toda la
    salida (ya sea estática o dinámica) etiquetada como
    <code>text/html</code> o <code>text/plain</code> antes de enviarla
    al cliente.</p>

    <highlight language="config">
      AddOutputFilterByType DEFLATE text/html text/plain
    </highlight>

    <p>Si desea que el contenido sea procesado por más de un filtro, sus
    nombres deben separarse con punto y coma. También es posible usar una
    directiva <directive>AddOutputFilterByType</directive> para cada uno de
    esos filtros.</p>

    <p>La siguiente configuración hace que toda la salida de scripts etiquetada como
    <code>text/html</code> se procese primero por el
    filtro <code>INCLUDES</code> y después por el filtro
    <code>DEFLATE</code>.</p>

    <highlight language="config">
&lt;Location "/cgi-bin/"&gt;
    Options Includes
    AddOutputFilterByType INCLUDES;DEFLATE text/html
&lt;/Location&gt;
    </highlight>

    <p>Tenga en cuenta que las directivas <directive>AddOutputFilterByType</directive>
    dentro de un mismo contexto son aditivas, pero una definición en un contexto
    más específico (como una sección
    <directive type="section" module="core">VirtualHost</directive>,
    <directive type="section" module="core">Directory</directive>, o
    <directive type="section" module="core">Location</directive>)
    sustituirá —en lugar de añadirse a— cualquier definición heredada de un
    contexto más amplio. Este es el mismo comportamiento que tiene
    <directive module="mod_mime">AddOutputFilter</directive>.</p>

    <highlight language="config">
# Contexto de servidor: comprime text/html y text/plain
AddOutputFilterByType DEFLATE text/html text/plain
&lt;VirtualHost *:80&gt;
    # Sustituye la definición a nivel de servidor para este vhost;
    # aquí solo se comprimirá text/css:
    AddOutputFilterByType DEFLATE text/css
&lt;/VirtualHost&gt;
    </highlight>

    <note type="warning"><title>Limitación con filtros definidos por el usuario</title>
    <p><directive>AddOutputFilterByType</directive> funciona con los
        filtros estándar compilados, como <code>DEFLATE</code> e
        <code>INCLUDES</code>, pero no funciona con filtros que buscan
        su configuración por nombre de filtro, como los definidos por
        <module>mod_ext_filter</module> o <code>LuaOutputFilter</code> de
        <module>mod_lua</module>. Esto es porque internamente el
        nombre del filtro se modifica con un prefijo <code>BYTYPE:</code>.
        Para filtros definidos por el usuario, use
        <directive>FilterDeclare</directive> y
        <directive>FilterProvider</directive> con una expresión
        que coincida con <code>%{CONTENT_TYPE}</code>.</p></note>

</usage>

<seealso><directive module="mod_mime">AddOutputFilter</directive></seealso>
<seealso><directive module="core">SetOutputFilter</directive></seealso>
<seealso><a href="../filter.html">filtros</a></seealso>
</directivesynopsis>

<directivesynopsis>
<name>FilterDeclare</name>
<description>Declara un filtro inteligente</description>
<syntax>FilterDeclare <var>smart-filter-name</var> <var>[type]</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>Options</override>

<usage>
    <p>Esta directiva declara un filtro de salida junto con una
    cabecera o variable de entorno que determinará su configuración en
    tiempo de ejecución. El primer argumento es un <var>smart-filter-name</var>
    para usar en las directivas <directive module="mod_filter">FilterProvider</directive>,
    <directive module="mod_filter">FilterChain</directive> y
    <directive module="mod_filter">FilterProtocol</directive>.</p>

    <p>El último argumento (opcional)
    es el tipo de filtro, y toma valores de <code>ap_filter_type</code>
    —concretamente <code>RESOURCE</code> (el valor por defecto), <code>CONTENT_SET</code>,
    <code>PROTOCOL</code>, <code>TRANSCODE</code>, <code>CONNECTION</code>
    o <code>NETWORK</code>.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>FilterProvider</name>
<description>Registra un filtro de contenido</description>
<syntax>FilterProvider <var>smart-filter-name</var> <var>provider-name</var>
 <var>expression</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>Options</override>

<usage>
    <p>Esta directiva registra un <em>proveedor</em> para el filtro inteligente.
    El proveedor se invocará si y solo si la <var>expression</var>
    declarada se evalúa como verdadera la primera vez que se invoca el arnés.</p>

    <p>
    <var>provider-name</var> debe haberse registrado al cargar
    un módulo que registre el nombre con
    <code>ap_register_output_filter</code>.
    </p>

    <p><var>expression</var> es una
    <a href="../expr.html">ap_expr</a>.</p>

</usage>
<seealso><a href="../expr.html">Expresiones en Apache HTTP Server</a>,
para una referencia completa y ejemplos.</seealso>
<seealso><module>mod_include</module></seealso>
</directivesynopsis>

<directivesynopsis>
<name>FilterChain</name>
<description>Configura la cadena de filtros</description>
<syntax>FilterChain [+=-@!]<var>smart-filter-name</var> <var>...</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>Options</override>

<usage>
    <p>Esto configura una cadena de filtros real, a partir de los filtros
    declarados. <directive>FilterChain</directive> admite cualquier número de argumentos,
    cada uno precedido opcionalmente por un único carácter de control que
    determina qué hacer:</p>

    <dl>
    <dt><code>+<var>smart-filter-name</var></code></dt>
    <dd>Añade <var>filter-name</var> al final de la cadena de filtros</dd>

    <dt><code>@<var>smart-filter-name</var></code></dt>
    <dd>Inserta <var>smart-filter-name</var> al principio de la cadena de filtros</dd>

    <dt><code>-<var>smart-filter-name</var></code></dt>
    <dd>Elimina <var>smart-filter-name</var> de la cadena de filtros</dd>

    <dt><code>=<var>smart-filter-name</var></code></dt>
    <dd>Vacía la cadena de filtros e inserta <var>smart-filter-name</var></dd>

    <dt><code>!</code></dt>
    <dd>Vacía la cadena de filtros</dd>

    <dt><code><var>smart-filter-name</var></code></dt>
    <dd>Equivale a <code>+<var>smart-filter-name</var></code></dd>
    </dl>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>FilterProtocol</name>
<description>Se ocupa del manejo correcto del protocolo HTTP</description>
<syntax>FilterProtocol <var>smart-filter-name</var> [<var>provider-name</var>]
    <var>proto-flags</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>Options</override>

<usage>
    <p>Esto indica a <module>mod_filter</module> que se ocupe de asegurar que el
    filtro no se ejecute cuando no debería, y que las cabeceras de la respuesta
    HTTP se establezcan correctamente teniendo en cuenta los efectos del
    filtro.</p>

    <p>Hay dos formas de esta directiva. Con tres argumentos, se
    aplica específicamente a un <var>smart-filter-name</var> y a un
    <var>provider-name</var> para ese filtro.
    Con dos argumentos, se aplica a un <var>smart-filter-name</var> cada vez que el
    filtro ejecuta <em>cualquier</em> proveedor.</p>

    <p>Las marcas especificadas con esta directiva se combinan con las marcas
    que los proveedores subyacentes puedan haber registrado con
    <module>mod_filter</module>. Por ejemplo, un filtro puede especificar internamente
    el equivalente a <code>change=yes</code>, pero una configuración concreta
    del módulo puede sobrescribirlo con <code>change=no</code>.
    </p>

    <p><var>proto-flags</var> es uno o más de los siguientes</p>

    <dl>
    <dt><code>change=yes|no</code></dt>
    <dd>Especifica si el filtro cambia el contenido, incluyendo posiblemente
    la longitud del contenido. El argumento "no" se admite desde la versión 2.4.7.</dd>

    <dt><code>change=1:1</code></dt>
    <dd>El filtro cambia el contenido, pero no cambiará la longitud
    del contenido</dd>

    <dt><code>byteranges=no</code></dt>
    <dd>El filtro no puede trabajar con rangos de bytes (byteranges) y requiere la entrada completa</dd>

    <dt><code>proxy=no</code></dt>
    <dd>El filtro no debería ejecutarse en un contexto de proxy</dd>

    <dt><code>proxy=transform</code></dt>
    <dd>El filtro transforma la respuesta de una manera incompatible con
    la cabecera HTTP <code>Cache-Control: no-transform</code>.</dd>

    <dt><code>cache=no</code></dt>
    <dd>El filtro hace que la salida no se pueda cachear (por ejemplo, introduciendo
    cambios de contenido aleatorios)</dd>
    </dl>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>FilterTrace</name>
<description>Obtiene información de depuración/diagnóstico de
    <module>mod_filter</module></description>
<syntax>FilterTrace <var>smart-filter-name</var> <var>level</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>

<usage>
    <p>Esta directiva genera información de depuración de
    <module>mod_filter</module>.
    Está diseñada para ayudar a probar y depurar proveedores (módulos de filtro), aunque
    también puede ayudar con el propio <module>mod_filter</module>.</p>

    <p>La salida de depuración depende del <var>level</var> establecido:</p>
    <dl>
    <dt><code>0</code> (por defecto)</dt>
    <dd>No se genera información de depuración.</dd>

    <dt><code>1</code></dt>
    <dd><module>mod_filter</module> registrará en el log de errores los buckets y brigades
    que pasen por el filtro, antes de que el proveedor los haya
    procesado. Esto es similar a la información que genera
    <a href="http://apache.webthing.com/mod_diagnostics/">mod_diagnostics</a>.
    </dd>

    <dt><code>2</code> (aún no implementado)</dt>
    <dd>Volcará todos los datos que pasen a un archivo temporal antes del
    proveedor. <strong>Solo para depuración de un único usuario</strong>; esto no
    admitirá peticiones concurrentes.</dd>
    </dl>
</usage>
</directivesynopsis>

</modulesynopsis>
