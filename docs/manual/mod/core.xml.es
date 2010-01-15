<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 151420:890374 (outdated) -->

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

<modulesynopsis metafile="core.xml.meta">

<name>core</name>
<description>Funcionalidades b&#225;sicas del servidor HTTP Apache que
est&#225;n siempre presentes</description>
<status>Core</status>

<directivesynopsis>
<name>AcceptPathInfo</name>
<description>Especifica si los recursos aceptan informaci&#243;n de
path a&#241;adida (trailing pathname information)</description>
<syntax>AcceptPathInfo On|Off|Default</syntax>
<default>AcceptPathInfo Default</default>
<contextlist><context>server config</context>
<context>virtual host</context><context>directory</context>
<context>.htaccess</context></contextlist>
<override>FileInfo</override>
<compatibility>Disponible en la versiones de Apache 2.0.30 y posteriores</compatibility>

<usage>

    <p>Esta directiva controla si las peticiones que contienen
    informaci&#243;n de path a&#241;adida (trailing pathname
    information) a continuaci&#243;n de un nombre de fichero existente
    (o no existente en un directorio que s&#237; existe) ser&#225;n
    aceptadas o rechazadas. La informaci&#243;n de path a&#241;adida
    (trailing pathname information) puede pasarse a los scripts en la
    variable de entorno <code>PATH_INFO</code>.</p>

    <p>Por ejemplo, suponga que la ubicaci&#243;n <code>/test/</code>
    se refiere a un directorio que contiene un &#250;nico fichero:
    <code>here.html</code>.  Entonces, tanto las peticiones a
    <code>/test/here.html/more</code> como las peticiones a
    <code>/test/nothere.html/more</code> toman <code>/more</code> como
    <code>PATH_INFO</code>.</p>

    <p>Los tres argumentos que puede tomar la directiva
    <directive>AcceptPathInfo</directive> son:</p>
    <dl>
    <dt><code>Off</code></dt><dd>Una petici&#243;n ser&#225; aceptada
    solamente si se refiere literalmente a una ruta que existe.  Por
    tanto, una petici&#243;n con informaci&#243;n de path a&#241;adida
    (trailing pathname information) despu&#233;s de un nombre de
    fichero que existe, del tipo <code>/test/here.html/more</code>
    como en el ejemplo de arriba, devolver&#225; el mensaje de error
    404 NOT FOUND.</dd>

    <dt><code>On</code></dt><dd>Una petici&#243;n ser&#225; aceptada
    si la componente anterior a la informaci&#243;n de path
    a&#241;adida (trailing pathname information) se refiere a un
    fichero que existe.  El ejemplo de arriba
    <code>/test/here.html/more</code> ser&#225; aceptado si
    <code>/test/here.html</code> se refiere a un fichero
    v&#225;lido.</dd>

    <dt><code>Default</code></dt><dd>El tratamiento de las peticiones
    con informaci&#243;n de path a&#241;adida (trailing pathname
    information) est&#225; determinado por el <a
    href="../handler.html">handler</a> responsable de la
    petici&#243;n.  El handler b&#225;sico para ficheros normales
    rechaza por defecto las peticiones de <code>PATH_INFO</code>. Los
    handlers que sirven scripts, como <a
    href="mod_cgi.html">cgi-script</a> e <a
    href="mod_isapi.html">isapi-handler</a>, generalmente aceptan
    <code>PATH_INFO</code> por defecto.</dd>
    </dl>

    <p>El prop&#243;sito principal de la directiva
    <code>AcceptPathInfo</code> es permitirle hacer prevalecer su
    propio criterio sobre el del handler acerca de si se debe aceptar
    o rechazar <code>PATH_INFO</code>. Esto es necesario por ejemplo,
    cuando use un <a href="../filter.html">filtro</a>, como <a
    href="mod_include.html">INCLUDES</a>, para generar contenido
    basado en <code>PATH_INFO</code>.  El handler b&#225;sico
    rechazar&#237;a normalmente la petici&#243;n. Puede usar la
    siguiente configuraci&#243;n para activar dicho script:</p>

    <example>
      &lt;Files "mypaths.shtml"&gt;<br />
      <indent>
        Options +Includes<br />
        SetOutputFilter INCLUDES<br />
        AcceptPathInfo On<br />
      </indent>
      &lt;/Files&gt;
    </example>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>AccessFileName</name>
<description>Nombre del fichero de configuraci&#243;n distribuida</description>
<syntax>AccessFileName <var>filename</var> [<var>filename</var>] ...</syntax>
<default>AccessFileName .htaccess</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>Durante el procesamiento de una petici&#243;n el servidor busca
    el primer fichero de configuraci&#243;n de esta lista de nombres
    en cada directorio de la ruta del documento, siempre y cuando los
    ficheros de configuraci&#243;n distribuida est&#233;n <a
    href="#allowoverride">activados para ese directorio</a>. Por
    ejemplo:</p>

    <example>
      AccessFileName .acl
    </example>

    <p>Antes de devolver el documento
    <code>/usr/local/web/index.html</code>, el servidor leer&#225;
    <code>/.acl</code>, <code>/usr/.acl</code>,
    <code>/usr/local/.acl</code> y <code>/usr/local/web/.acl</code>
    buscando directivas, a menos que hayan sido desactivados con</p>

    <example>
      &lt;Directory /&gt;<br />
      <indent>
        AllowOverride None<br />
      </indent>
      &lt;/Directory&gt;
    </example>
</usage>
<seealso><directive module="core">AllowOverride</directive></seealso>
<seealso><a href="../configuring.html">Ficheros de Configuraci&#243;n</a></seealso>
<seealso><a href="../howto/htaccess.html">Ficheros .htaccess</a></seealso>
</directivesynopsis>

<directivesynopsis>
<name>AddDefaultCharset</name>
<description>Par&#225;metro del conjunto de caracteres que se
a&#241;ade cuando el tipo de contenido de una respuesta es
<code>text/plain</code> o <code>text/html</code></description>
<syntax>AddDefaultCharset On|Off|<var>charset</var></syntax>
<default>AddDefaultCharset Off</default>
<contextlist><context>server config</context>
<context>virtual host</context><context>directory</context>
<context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>
    <p>Esta directiva especifica un valor por defecto para el
    par&#225;metro del conjunto de caracteres que se a&#241;ade
    a&#241;ade si solo si el tipo de contenido de una respuesta es
    <code>text/plain</code> o <code>text/html</code>. EL valor
    pecificado en esta directiva no prevalecer&#225; si cualquier otro
    conjunto de caracteres es especificado en el cuerpo del documento
    por medio de una etiqueta <code>META</code>, aunque a menudo, el
    comportamiento exacto est&#225; determinado por la
    configuraci&#243;n del cliente. Si se especifica
    <code>AddDefaultCharset Off</code>, se desactiva esta
    funcionalidad. <code>AddDefaultCharset On</code> activa el uso del
    conjunto de caracteres por defecto interno de Apache,
    <code>iso-8859-1</code>. Cualquier otro valor se asume que es el
    <var>charset</var> a usar, que ser&#225; uno los <a
    href="http://www.iana.org/assignments/character-sets">registrados
    por la IANA</a> como tipos MIME. Por ejemplo:</p>

    <example>
      AddDefaultCharset utf-8
    </example>

    <p><directive>AddDefaultCharset</directive> debe ser usada solo
    cuando todos los recursos de texto a los que se aplican se saben
    que usan un determiando conjunto de caracteres (character
    encoding) y no es conveniente etiquetar los documentos
    individualmente. Un ejemplo es su uso en recursos que contienen
    contenido generado, como CGIs antiguos, que puede ser vulnerables
    a ataques debidos a que se incluye en el resultado datos
    suministrados por el usuario. Tenga en cuenta, sin embargo, que
    una mejor soluci&#243;n es simplemente modificar (o borrar) esos
    scripts, porque especificar un conjunto de caracteres por defecto
    no protege a los usuarios que tengan activada en su navegador la
    opci&#243;n "auto-detect character encoding".</p>
</usage>
<seealso><directive module="mod_mime">AddCharset</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>AddOutputFilterByType</name> 
<description>Asigna un filtro de
salida a un tipo MIME en particular</description>
<syntax>AddOutputFilterByType <var>filter</var>[;<var>filter</var>...]
<var>MIME-type</var> [<var>MIME-type</var>] ...</syntax>
<contextlist><context>server config</context> <context>virtual
host</context><context>directory</context>
<context>.htaccess</context></contextlist>
<override>FileInfo</override> 
<compatibility>Disponible en las
versiones de Apache 2.0.33 y posteriores</compatibility>

<usage>
    <p>Esta directiva activa un <a href="../filter.html">filtro</a> de
    salida en particular para las peticiones en funci&#243;n del tipo
    MIME de la respuesta.</p>

    <p>El siguiente ejemplo usa el filtro <code>DEFLATE</code>, del
    m&#243;dulo <module>mod_deflate</module>. Este filtro comprime la
    parte de la respuesta de la petici&#243;n (ya sea est&#225;tica o
    din&#225;mica) que est&#233; etiquetada como
    <code>text/html</code> o <code>text/plain</code> antes de ser
    enviada al cliente.</p>

    <example>
      AddOutputFilterByType DEFLATE text/html text/plain
    </example>

    <p>Si quiere que los contenidos sean procesados por m&#225;s de un
    filtro, debe separar sus nombres con puntos y comas
    (;). Tamb&#233;n es posible usar la directiva
    <directive>AddOutputFilterByType</directive> para cada uno de los
    filtros.</p>

    <p>La configuraci&#243;n que se muestra m&#225;s abajo hace que
    todos los scripts etiquetados como <code>text/html</code> sean
    procesados primero por el filtro <code>INCLUDES</code> y
    posteriormente por el filtro <code>DEFLATE</code>.</p>

    <example>
    &lt;Location /cgi-bin/&gt;<br />
    <indent>
      Options Includes<br />
      AddOutputFilterByType INCLUDES;DEFLATE text/html<br />
    </indent>
    &lt;/Location&gt;
    </example>

    <note type="warning"><title>Nota</title> <p>Activar filtros con la
      directiva <directive>AddOutputFilterByType</directive> puede no
      funcionar parcial o totalmente. Por ejemplo, no se aplica
      ning&#250;n filtro si es posible determinar el tipo MIME y se
      aplica en su lugar <directive
      module="core">DefaultType</directive>, incluso si el <directive
      module="core">DefaultType</directive> es el mismo.</p>

      <p>Si quiere estar seguro de que se apliquen los filtros, asigne
      el tipo de contenido a un recurso expl&#237;citamente, por ejemplo
      con la directiva <directive
      module="mod_mime">AddType</directive> o con <directive
      module="core">ForceType</directive>. Determinar el tipo de
      contenido dentro de un script CGI (que no sea del tipo nph)
      tambi&#233;n es seguro.</p>

      <p>Los filtros de salida por tipo no se aplican nunca en
      peticiones proxy.</p>
    </note>
</usage>

<seealso><directive module="mod_mime">AddOutputFilter</directive></seealso>
<seealso><directive module="core">SetOutputFilter</directive></seealso>
<seealso><a href="../filter.html">Filtros</a></seealso>
</directivesynopsis>

<directivesynopsis>
<name>AllowEncodedSlashes</name>
<description>Determina si se acepta el uso de separadores de
ubicaci&#243;n codificados en las URLs</description>
<syntax>AllowEncodedSlashes On|Off</syntax>
<default>AllowEncodedSlashes Off</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>
<compatibility>Disponible en las versines de Apache 2.0.46 y posteriores</compatibility>

<usage>
    <p>La directiva <directive>AllowEncodedSlashes</directive>
    perimite usar URLs que contienen separadores de ubicaci&#243;n
    codificados (<code>%2F</code> para <code>/</code> y 
    <code>%5C</code> para <code>\</code> en funci&#243;n del
    sistema). Normalmente, tales URLs se rechazan y se devuelve un
    mensaje de error 404 (Not found).</p>

    <p>Especificar el valor <code>On</code> en la directiva
    <directive>AllowEncodedSlashes</directive> es &#250;til sobre todo
    cuando se usa junto con <code>PATH_INFO</code>.</p>

    <note><title>Nota</title> <p>Permitir barras codificadas
      <em>no</em> implica su <em>decodificado</em>.  La aparici&#243;n
      de <code>%2F</code> o <code>%5C</code> (seg&#250;n el sistemas
      de que se trate) se dejar&#225; como tal en la cadena de
      caracteres que conforma la de otra manera URL decodificada.</p>
    </note>
</usage>
<seealso><directive module="core">AcceptPathInfo</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>AllowOverride</name>
<description>Tipos de directivas que cuyo uso est&#225; permitido en los ficheros <code>.htaccess</code></description>
<syntax>AllowOverride All|None|<var>directive-type</var>
[<var>directive-type</var>] ...</syntax>
<default>AllowOverride All</default>
<contextlist><context>directory</context></contextlist>

<usage>
    <p>Cuando el servidor encuentra un fichero <code>.htaccess</code>
    (como se explica en la directiva <directive
    module="core">AccessFileName</directive>) es necesario saber que
    directivas presentes en ese fichero pueden prevalecer sobre
    las directivas de configuraci&#243;n previas.</p>

    <note><title>Solamente disponible en las secciones
    &lt;Directory&gt;</title>
    
    <directive>AllowOverride</directive> puede usarse solo en las
    secciones <directive type="section"
    module="core">Directory</directive> especificadas sin expresiones
    regulares, nunca en las secciones <directive type="section"
    module="core">Location</directive>, <directive module="core"
    type="section">DirectoryMatch</directive> o <directive
    type="section" module="core">Files</directive>.
    </note>

    <p>Cuando el valor de esta directiva es <code>None</code>,
    entonces los ficheros <a href="#accessfilename">.htaccess</a> son
    ignorados completamente. En ese caso, el servidor ni siquiera
    intentar&#225; leer los archivos <code>.htaccess</code>
    existentes.</p>

    <p>Cuando el valor especificado en esta directiva es
    <code>All</code>, entonces cualquier directiva que tenga <a
    href="directive-dict.html#Context">Context</a> .htaccess puede ser
    usada en los ficheros <code>.htaccess</code>.</p>

    <p>El <var>tipo de directiva</var> puede ser uno de los siguientes
    grupos de directivas.</p>

    <dl>
      <dt>AuthConfig</dt>

      <dd>

      Permite usar directivas de autentificaci&#243;n (<directive
      module="mod_auth_dbm">AuthDBMGroupFile</directive>, <directive
      module="mod_auth_dbm">AuthDBMUserFile</directive>, <directive
      module="mod_auth">AuthGroupFile</directive>, <directive
      module="core">AuthName</directive>, <directive
      module="core">AuthType</directive>, <directive
      module="mod_auth">AuthUserFile</directive>, <directive
      module="core">Require</directive>, <em>etc.</em>).</dd>

      <dt>FileInfo</dt>

      <dd>
      Permite usar directivas que controlan los tipos de documento
      (<directive module="core">DefaultType</directive>, <directive
      module="core">ErrorDocument</directive>, <directive
      module="core">ForceType</directive>, <directive
      module="mod_negotiation">LanguagePriority</directive>,
      <directive module="core">SetHandler</directive>, <directive
      module="core">SetInputFilter</directive>, <directive
      module="core">SetOutputFilter</directive>, y
      <module>mod_mime</module> las directivas Add* y Remove*,
      <em>etc.</em>).</dd>

      <dt>Indexes</dt>

      <dd>
      Permite el uso de directivas que controlan el indexado de
      directorios (<directive
      module="mod_autoindex">AddDescription</directive>, <directive
      module="mod_autoindex">AddIcon</directive>, <directive
      module="mod_autoindex">AddIconByEncoding</directive>, <directive
      module="mod_autoindex">AddIconByType</directive>, <directive
      module="mod_autoindex">DefaultIcon</directive>, <directive
      module="mod_dir">DirectoryIndex</directive>, <directive
      module="mod_autoindex">FancyIndexing</directive>, <directive
      module="mod_autoindex">HeaderName</directive>, <directive
      module="mod_autoindex">IndexIgnore</directive>, <directive
      module="mod_autoindex">IndexOptions</directive>, <directive
      module="mod_autoindex">ReadmeName</directive>,
      <em>etc.</em>).</dd>

      <dt>Limit</dt>

      <dd>
      Permite el uso de directivas que controlan el acceso al host
      (<directive module="mod_access">Allow</directive>, <directive
      module="mod_access">Deny</directive> y <directive
      module="mod_access">Order</directive>).</dd>

      <dt>Options</dt>

      <dd>
      Permite usar directivas que controlan funcionalidades
      espec&#237;ficas de directorios (<directive
      module="core">Options</directive> y <directive
      module="mod_include">XBitHack</directive>).</dd>
    </dl>

    <p>Ejemplo:</p>

    <example>
      AllowOverride AuthConfig Indexes
    </example>

    <p>En el ejemplo de arriba todas las directivas que no est&#225;n
    en el grupo <code>AuthConfig</code> ni en el grupo
    <code>Indexes</code> provocan un error interno del servidor.</p>
</usage>

<seealso><directive module="core">AccessFileName</directive></seealso>
<seealso><a href="../configuring.html">Ficheros de
Configuraci&#243;n</a></seealso>
<seealso><a href="../howto/htaccess.html">Ficheros .htaccess</a></seealso>
</directivesynopsis>

<directivesynopsis>
<name>AuthName</name>
<description>&#65;mbito de autorizaci&#243;n para su uso en
autentificaci&#243;n HTTP</description>
<syntax>AuthName <var>auth-domain</var></syntax>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>Esta directiva especifica el nombre de dominio que se muestra
     al solicitar autorizaci&#243;n para acceder a un directorio. Este
     nombre de dominio se muestra al cliente para que el usuario sepa
     qu&#233; nombre de usuario y contrase&#241;a ha de introducir.
     <directive>AuthName</directive> toma solamente un argumento; si
     el nombre de dominio contiene alg&#250;n espacio, debe escribirse
     entre comillas. Para que funcione correctamente, esta directiva
     debe usarse junto con las directivas <directive
     module="core">AuthType</directive> y <directive
     module="core">Require</directive>, y con directivas como
     <directive module="mod_auth">AuthUserFile</directive> y
     <directive module="mod_auth">AuthGroupFile</directive>.</p>

   <p>Por ejemplo:</p>

   <example>
     AuthName "Top Secret"
   </example>

    <p>La cadena de caracteres que se especifique como valor de
    <code>AuthName</code> ser&#225; lo que aparecer&#225; en el cuadro
    de di&#225;logo de acceso de la mayor&#237;a de los
    navegadores.</p>
</usage>
<seealso>
    <a href="../howto/auth.html">Autentificaci&#243;n, Autorizaci&#243;n y
    Control de Acceso</a></seealso>
</directivesynopsis>

<directivesynopsis>
<name>AuthType</name>
<description>Tipo de autentificaci&#243;n de usuarios</description>
<syntax>AuthType Basic|Digest</syntax>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>Esta directiva selecciona el tipo de autentificaci&#243;n de
    usuarios que usar&#225; para un directorio. Actualmente solamente
    est&#225;n implementadas las opciones <code>Basic</code> y
    <code>Digest</code>.

     Para que funcione correctamente, esta directiva tiene que ir
     acompa&#241;ada por las directivas <directive
     module="core">AuthName</directive> y <directive
     module="core">Require</directive>, y de directivas como
     <directive module="mod_auth">AuthUserFile</directive> y
     <directive module="mod_auth">AuthGroupFile</directive>.</p>
</usage>
<seealso><a href="../howto/auth.html">>Autentificaci&#243;n, Autorizaci&#243;n y
Control de Acceso</a></seealso>
</directivesynopsis>

<directivesynopsis>
<name>CGIMapExtension</name> <description>T&#233;cnica para localizar
un int&#233;rprete de scripts CGI</description>
<syntax>CGIMapExtension <var>cgi-path</var>
<var>.extension</var></syntax>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>FileInfo</override>
<compatibility>Solamente NetWare</compatibility>

<usage>
    <p>Esta directiva se usa para controlar la forma en que Apache
    encuentra el int&#233;rprete para ejecutar scripts CGI. Por
    ejemplo, si usa <code>CGIMapExtension sys:\foo.nlm .foo</code>,
    todos los scripts CGI con extensi&#243;n <code>.foo</code> se
    pasar&#225;n al int&#233;rprete FOO.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ContentDigest</name>
<description>Activa la generaci&#243;n de cabeceras de respuesta HTTP
<code>Content-MD5</code></description>
<syntax>ContentDigest On|Off</syntax>
<default>ContentDigest Off</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>Options</override>
<status>Experimental</status>

<usage>
    <p>Esta directiva permite la generaci&#243;n de cabeceras
    <code>Content-MD5</code> seg&#250;n se definen en RFC1864 y
    RFC2068.</p>

    <p>MD5 es un algoritmo que genera una cadena de caracteres
    ("message digest", a veces llamado "huella dactilar") a partir de
    unos datos de longitud arbitraria. La forma en que funciona este
    algoritmo hace que con casi toda seguridad, si se producen
    alteraciones en los datos originales, el "message digest" generado
    tambi&#233;n ser&#225; diferente.</p>

    <p>La cabecera <code>Content-MD5</code> es una forma de comprobar
    la integridad de un mensaje de principio a fin (MIC) para los
    mensajes HTTP (entity-body). Un proxy o un cliente pueden
    comprobar esta cabecera para detectar modificaciones accidentales
    en el mensaje HTTP (entity-body) en tr&#225;nsito. Cabecera de
    ejemplo:</p>

    <example>
      Content-MD5: AuLb7Dp1rqtRtxz2m9kRpA==
    </example>

    <p>Tenga en cuenta que el uso de esta directiva puede provocar un
    menor rendimiento de su servidor porque el "message digest" se
    genera en cada petici&#243;n (los valores no se guardan).</p>

    <p>La cebecera <code>Content-MD5</code> se env&#237;a solamente
    cuando un documento es servido por <module>core</module>. Si el
    documento es servido con cuaquier otro m&#243;dulo, no se
    env&#237;a. Por ejemplo, los documentos SSI, las salidas de
    scripts CGI, y las respuesta parciales (byte range responses) no
    tienen esta cabecera.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>DefaultType</name>
<description>Tipo de contenido MIME por defecto que usar&#225; el servidor si no
puede determinar el tipo MIME en concreto del documento a servir</description>
<syntax>DefaultType <var>MIME-type</var></syntax>
<default>DefaultType text/plain</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>FileInfo</override>

<usage>
    <p>Hay veces en las que se pide al servidor que devuelva un
    documento cuyo tipo MIME no puede determinar.</p>

    <p>El servidor tiene que informar al cliente del tipo de contenido
    del documento. En el caso de que se trate de un tipo desconocido,
    se usa el tipo <code>DefaultType</code>. Por ejemplo:</p>

    <example>
      DefaultType image/gif
    </example>

    <p>ser&#237;a apropiado para un directorio que contenga muchas
    imagenes tipo GIF cuyos nombres de fichero no tengan la
    extensi&#243;n <code>.gif</code>.</p>

    <p>Tenga en cuenta que a diferencia de <directive
    module="core">ForceType</directive>, esta directiva solamente
    indica el tipo MIME por defecto. El resto de definiciones de tipos
    MIME, incluidas las extensiones de fichero, que pueden identificar
    el tipo MIME de que se trata prevalecen sobre esta opci&#243;n por
    defecto.</p>
</usage>
</directivesynopsis>

<directivesynopsis type="section">
<name>Directory</name> <description>Engloba a un grupo de directivas
que se aplicar&#225;n solamente al directorio del sistema de ficheros
especificado y a sus subdirectorios</description>
<syntax>&lt;Directory <var>directory-path</var>&gt;
... &lt;/Directory&gt;</syntax> <contextlist><context>server
config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>Las directivas <directive type="section">Directory</directive>
    y <code>&lt;/Directory&gt;</code> se usan para englobar un grupo
    de directivas que se aplicar&#225;n solamente al directorio
    especificado y a sus subdirectorios. Puede incluir a cualquier
    directiva cuyo uso est&#233; permitido en un contexto
    &lt;directory&gt;. <var>Directory-path</var> puede ser tanto la
    ruta completa a un directorio, como una cadena de caracteres
    comod&#237;n que use las reglas de equivalencia de los shells de
    Unix. En una cadena de caracteres comod&#237;n, el car&#225;cter
    <code>?</code> equivale a cualquier car&#225;cter individual, y
    <code>*</code> equivale a cualquier secuencia de
    caracteres. Tambi&#233;n puede usar <code>[]</code> para expresar
    rangos de caracteres. Ninguno de los caracteres comod&#237;n
    equivale al car&#225;cter `/', de modo que <code>&lt;Directory
    /*/public_html&gt;</code> no equivale a
    <code>/home/user/public_html</code>, pero s&#237; a
    <code>&lt;Directory /home/*/public_html&gt;</code>. Ejemplo:</p>

    <example>
      &lt;Directory /usr/local/httpd/htdocs&gt;<br />
      <indent>
        Options Indexes FollowSymLinks<br />
      </indent>
      &lt;/Directory&gt;
    </example>

    <note>
      <p>Tenga especial cuidado con los argumentos de
      <var>directory-path</var>: tienen que equivaler literalmente a
      la ruta del sistema de ficheros que Apache usa para acceder a
      los ficheros. Las directivas aplicadas a un
      <code>&lt;Directory&gt;</code> en particular no se
      aplicar&#225;n a los ficheros de ese mismo directorio pero que
      sean accedidos mediante una ruta diferente, como por ejemplo
      mediante enlaces simb&#243;licos diferentes.</p>
    </note>

    <p>Tambi&#233;n pueden usar expresiones regulares extendidas,
    a&#241;adiendo el car&#225;cter <code>~</code>. Por ejemplo:</p>

    <example>
      &lt;Directory ~ "^/www/.*/[0-9]{3}"&gt;
    </example>

    <p>equivaldr&#237;a a los directorios en <code>/www/</code> cuyo
    nombres consistan en tres n&#250;meros.</p>

    <p>Si varias (expresiones no regulares) secciones <directive
    type="section">Directory</directive> equivalen al directorio (o a
    uno de los directorios de los que es subdirectorio) que contiene
    un documento, entonces las directivas se aplican seg&#250;n el
    criterio de la ruta equivalente m&#225;s corta, junto con las
    directivas de los archivos <a
    href="#accessfilename">.htaccess</a>. Por ejemplo, con</p>

    <example>
      &lt;Directory /&gt;<br />
      <indent>
        AllowOverride None<br />
      </indent>
      &lt;/Directory&gt;<br />
      <br />
      &lt;Directory /home/&gt;<br />
      <indent>
        AllowOverride FileInfo<br />
      </indent>
      &lt;/Directory&gt;
    </example>

    <p>para acceder al documento <code>/home/web/dir/doc.html</code>
    los pasos son:</p>

    <ul>
      <li>Se aplica la directiva <code>AllowOverride None</code>
      (desactivando los ficheros <code>.htaccess</code>).</li>

      <li>Se aplica la directiva <code>AllowOverride FileInfo</code>
      (para el directorio <code>/home</code>).</li>

      <li>Se aplica cualquier directiva <code>FileInfo</code> en
      <code>/home/.htaccess</code>, <code>/home/web/.htaccess</code> y
      <code>/home/web/dir/.htaccess</code> por ese orden.</li>
    </ul>

    <p>Las expresiones regulares no se tienen en cuenta hasta que
    todas las secciones normales hayan sido aplicadas. En ese momento
    todas se eval&#250;an las expresiones regulares en el orden en que
    aparecen en el fichero de configuraci&#243;n. Por ejemplo, con</p>

    <example>
      &lt;Directory ~ abc$&gt;<br />
      <indent>
        # ... directivas aqu&#237; ...<br />
      </indent>
      &lt;/Directory&gt;
    </example>

    <p>la secci&#243;n de expresiones regulares no ser&#225;
    considerada hasta despu&#233;s de que todas las directivas
    <directive type="section">Directory</directive> y los ficheros
    <code>.htaccess</code> hayan sido aplicados. Solamente entonces
    las expresiones regulares que tengan una equivalencia con
    <code>/home/abc/public_html/abc</code> y la correspondiente
    directiva <directive type="section">Directory</directive>
    ser&#225;n aplicadas.</p>

   <p><strong>Tenga en cuenta que por defecto el acceso de Apache a
    <code>&lt;Directory /&gt;</code> es <code>Allow from All</code>.
    Esto significa que Apache servir&#225; cualquier fichero que se
    corresponda con una URL. Se recomienda que modifique este
    comportamiento con un bloque del siguiente tipo</strong></p>

    <example>
      &lt;Directory /&gt;<br />
      <indent>
        Order Deny,Allow<br />
        Deny from All<br />
      </indent>
      &lt;/Directory&gt;
    </example>

    <p><strong>y haga prevalecer una configuraci&#243;n diferente para
    los solamente para los directorios que usted <em>quiera</em> que
    sean accesibles. Consulte la secci&#243;n <a
    href="../misc/security_tips.html">Consejos de seguridad</a> para
    obtener m&#225;s informaci&#243;n.</strong></p>

    <p>Las secciones "directory" se usan en el archivo
    <code>httpd.conf</code>.  Las directivas <directive
    type="section">Directory</directive> no pueden anidarse, y no
    pueden aparecer en una secci&#243;n de tipo <directive
    module="core" type="section">Limit</directive> o <directive
    module="core" type="section">LimitExcept</directive>.</p>
</usage>
<seealso><a href="../sections.html">Documentaci&#243;n de
    c&#243;mo funcionan las secciones &lt;Directory&gt;,
    &lt;Location&gt; y &lt;Files&gt;</a> para obtener m&#225;s
    informaci&#243;n sobre la forma en que se combinan estas secciones
    cuando se recibe una petici&#243;n</seealso>
</directivesynopsis>

<directivesynopsis type="section">
<name>DirectoryMatch</name> <description>Incluye las directivas que se
aplican a los directorios y subdirectorios del sistema de ficheros que
equivalen a una expresi&#243;n regular</description>
<syntax>&lt;DirectoryMatch <var>regex</var>&gt;
... &lt;/DirectoryMatch&gt;</syntax> <contextlist><context>server
config</context><context>virtual host</context>
</contextlist>

<usage>
    <p><directive type="section">DirectoryMatch</directive> y
    <code>&lt;/DirectoryMatch&gt;</code> se usan para englobar a un
    grupo de directivas que se aplicar&#225;n solamente al directorio
    (y los subdirectorios de &#233;ste) especificado, al igual que
    <directive module="core" type="section">Directory</directive>. Sin
    embargo, en ese caso la directiva toma como argumento una
    expresi&#243;n regular. Por ejemplo:</p>

    <example>
      &lt;DirectoryMatch "^/www/.(.+)?[0-9]{3}"&gt;
    </example>

    <p>equivaldr&#225; a los directorios en <code>/www/</code> cuyo nombre
    consista en tres n&#250;meros.</p>
</usage>
<seealso><directive type="section" module="core">Directory</directive>
si quiere una descripci&#243;n completa de c&#243;mo se usan
conjuntamente las expresiones regulares con la directiva <directive
type="section">Directory</directive></seealso> <seealso><a
href="../sections.html">Modo de funcionamiento de las secciones
&lt;Directory&gt;, &lt;Location&gt; y &lt;Files&gt;</a> para obtener
m&#225;s informaci&#243;n sobre como se combinan estas secciones
cuando se recibe una petici&#243;n</seealso>
</directivesynopsis>

<directivesynopsis>
<name>DocumentRoot</name>
<description>Directorio principal que contiene la estructura de
directorios visible desde la web</description>
<syntax>DocumentRoot <var>directory-path</var></syntax>
<default>DocumentRoot /usr/local/apache/htdocs</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>Esta directiva especifica el directorio desde el cu&#225;l
    <program>httpd</program> servir&#225; los ficheros. A menos que
    especifique alguna otra equivalencia mediante una directiva
    <directive module="mod_alias">Alias</directive>, el servidor
    a&#241;ade la ruta de la URL solicitada a este directorio para
    construir la ruta del documento a servir. Ejemplo:</p>

    <example>
      DocumentRoot /usr/web
    </example>

    <p>esto quiere decir que una petici&#243;n de acceso a
    <code>http://www.my.host.com/index.html</code> se refiere a
    <code>/usr/web/index.html</code> en el sistema de ficheros.</p>

    <p>El directorio que especifique en
    <directive>DocumentRoot</directive> debe escribirlo sin barra al
    final.</p>
</usage>
<seealso><a href="../urlmapping.html">C&#243;mo traducir URLs a
ubicaciones del sistema de ficheros</a></seealso>
</directivesynopsis>

<directivesynopsis>
<name>EnableMMAP</name>
<description>Permite el uso de mapeo de memoria para leer archivos mientras se
sirven</description>
<syntax>EnableMMAP On|Off</syntax>
<default>EnableMMAP On</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>FileInfo</override>

<usage>
    <p>Esta directiva controla si <program>httpd</program> puede usar
    mapeo de memoria en caso de ser necesario para leer los contenidos
    de un archivo al servirlo.  Por defecto, cuando el tratamiento de
    una petici&#243;n requiere acceder a los datos dentro de un
    fichero -- por ejemplo, cuando se sirve un fichero analizado
    sint&#225;cticamente por el servidor con el m&#243;dulo
    <module>mod_include</module> -- Apache mapea en memoria el archivo
    si el sistema operativo soporta esa operaci&#243;n.</p>

    <p>El mapeo de memoria supone a veces una mejora en el
    rendimiento. Sin embargo, en ciertos entornos, es mejor desactivar
    el mapeo de memoria para evitar problemas operacionales:</p>

    <ul>
    <li>En algunos sistemas con m&#225;s de un procesador, el mapeo de
    memoria puede reducir el rendimiento de
    <program>httpd</program>.</li> <li>Con un <directive
    module="core">DocumentRoot</directive> montado en NFS,
    <program>httpd</program> podr&#237;a abortar su ejecuci&#243;n
    debido a un fallo de segmentaci&#243;n si el fichero se borra o se
    trunca mientras que <program>httpd</program> lo tiene mapeado en
    memoria.</li>
    </ul>

    <p>Para configuraciones del servidor que son sensibles a estos
    problemas, debe desactivar el uso del mapeo en memoria
    especificando:</p>

    <example>
      EnableMMAP Off
    </example>

    <p>Para ficheros montados en NFS, puede desactivar esta
    funcionalidad expl&#237;citamente para los archivos implicados
    especificando:</p>

    <example>
      &lt;Directory "/path-to-nfs-files"&gt;
      <indent>
        EnableMMAP Off
      </indent>
      &lt;/Directory&gt;
    </example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>EnableSendfile</name>
<description>Permite el uso del soporte de sendfile del kernel para servir ficheros @@@@@ Use the kernel sendfile support to deliver files to the client @@@@@ </description>
<syntax>EnableSendfile On|Off</syntax>
<default>EnableSendfile On</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>FileInfo</override> 
<compatibility>Disponible en las versiones de Apache 2.0.44 y
posteriores</compatibility>

<usage>
    <p>Esta directiva controla si <program>httpd</program> puede usar
    el soporte de sendfile del kernel para transmitir contenidos de
    ficheros al cliente.  Por defecto, cuando se est&#225; procesando
    una petici&#243;n que no requiere acceso a los datos de un fichero
    -- por ejemplo, cuando se sirve un fichero est&#225;tico -- Apache
    usa sendfile para servir los contenidos del fichero directamente a
    la red, sin leer el fichero si el sistema operativo lo
    permite.</p>

    <p>El mecanismo sendfile evita operaciones separadas de lectura y
    env&#237;o, y reservas de buffer. Sin embargo, en algunas
    plataformas o en algunos sistemas de ficheros, es mejor desactivar
    esa funcionalidad para evitar problemas operacionales:</p>

    <ul>
    <li>En algunas plataformas puede que el soporte de sendfile no
    funcione porque al compilar Apache no se detect&#243;
    correctamente, especialmente si los binarios fueron construidos en
    una m&#225;quina y despu&#233;s se han trasladado a otra cuando el
    soporte para sendfile ya no funcionaba.</li>

    <li>En Linux, el uso de send file provoca fallos de
    comprobaci&#243;n de TCP_checksum en ciertas tarjetas de red que
    usan IPv6</li> 

    <li>Si <directive module="core">DocumentRoot</directive> est&#225;
    montado en red (por ejemplo, NFS o SMB), el kernel puede que no
    sea capaz de servir el fichero de red a trav&#233;s de su
    cache.</li>
    </ul>

    <p>Para configuraciones del servidor que son sensibles a estos
    problemas, debe desactivar esta funcionalidad especificando:</p>

    <example>
      EnableSendfile Off
    </example>

    <p>Para archivos montados en NFS o SMB, esta funcionalidad puede
    ser desactivada expl&#237;citamente para los ficheros que puedan
    ocasionar problemas mediante:</p>

    <example>
      &lt;Directory "/path-to-nfs-files"&gt;
      <indent>
        EnableSendfile Off
      </indent>
      &lt;/Directory&gt;
    </example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ErrorDocument</name> 
<description>Es lo que el servidor devuelve al cliente si se produce
alg&#250;n error</description>
<syntax>ErrorDocument <var>error-code</var>
<var>document</var></syntax> <contextlist><context>server
config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>FileInfo</override> <compatibility>El uso de las comillas
(") en los mensajes de texto es diferente en Apache
2.0</compatibility>

<usage>
    <p>En el caso de que aparezca un problema o error, puede
    configurar Apache para hacer una de las siguientes cuatro
    cosas,</p>

    <ol>
      <li>devolver un mensaje de error est&#225;ndar</li>

      <li>devolver un mensaje de error personalizado</li>

      <li>redireccionar la petici&#243;n a una <var>ruta-URL</var>
      local</li>

      <li>redireccionar la petici&#243;n a una <var>URL</var> externa</li>
    </ol>

    <p>La primera opci&#243;n es la que se usa por defecto, mientras
    que el resto se pueden configurar usando la directiva
    <directive>ErrorDocument</directive>, la cual ha de seguirse del
    c&#243;digo de respuesta HTTP y una URL o un mensaje. Apache
    ofrece a veces otra informaci&#243;n adicional sobre el problema o
    error.</p>

    <p>Las URLs pueden empezar por una barra (/) para URLs locales, o
    pueden ser una URL completa que el cliente pueda
    resolver. Tambi&#233;n se puede hacer que el nevagador despliegue
    un mensaje. Ejemplos:</p>

    <example>
      ErrorDocument 500 http://foo.example.com/cgi-bin/tester<br />
      ErrorDocument 404 /cgi-bin/bad_urls.pl<br /> 
      ErrorDocument 401 /subscription_info.html<br /> 
      ErrorDocument 403 "Lo sentimos no  podemos permitirle el acceso a esta p&#225;gina hoy"
    </example>

    <p>Adicionalmente, el valor especial <code>default</code> puede
    ser usado para que Apache use los mensajes literales que trae por
    defecto. Aunque bajo circunstancias normales no es necesario,
    <code>default</code> restaura los mensajes literales de Apache en
    configuraciones que de otra manera heredan una directiva
    <directive>ErrorDocument</directive> ya existente.</p>

    <example>
      ErrorDocument 404 /cgi-bin/bad_urls.pl<br /><br />
      &lt;Directory /web/docs&gt;<br />
      <indent>
        ErrorDocument 404 default<br />
      </indent>
      &lt;/Directory&gt;
    </example>

    <p>Tenga en cuenta que si usted especifica en
    <directive>ErrorDocument</directive> un contenido que apunta a una
    URL remota (por ejemplo, cualquier cosa que empiece por
    <code>http</code>), Apache redireccionar&#225; al cliente, incluso
    si al final, el documento al que redirecciona est&#225; en el
    mismo servidor. Esto tiene varias implicaciones, la m&#225;s
    importante es que el cliente no recibir&#225; el c&#243;digo de
    error original, sino que en su lugar recibir&#225; el c&#243;digo
    de estado del redireccionamiento. Esto puede confundir a los
    robots web y otros clientes que tratan de determinar si una URL es
    v&#225;lida usando el c&#243;digo de estado. Adem&#225;s, si usa
    una URL remota en un <code>ErrorDocument 401</code>, el cliente no
    sabr&#225; pedir contrase&#241;as al usuario porque no
    recibir&#225; el c&#243;digo de estado 401. Por tanto, <strong>si
    usa una directiva <code>ErrorDocument 401</code> entonces
    debe referirse a un documento local.</strong></p>

    <p>Microsoft Internet Explorer (MSIE) ignorar&#225; por defecto
    los mensajes de error generados por el servidor cuando sean
    "demasiado peque&#241;os" y los sustituir&#225; por mensajes de
    error propios. El tama&#241;o se considera peque&#241;o seg&#250;n
    el tipo de error de que se trate, pero en general, si su mensaje
    de error es de m&#225;s de 512 bytes, MSIE mostrar&#225; en
    mensaje del error generado por el servidor y no el suyo. Puede
    encontrar m&#225;s informaci&#243;n sobre este asunto en el
    art&#237;culo de la Base de Datos de Conocimiento de Microsoft <a
    href="http://support.microsoft.com/default.aspx?scid=kb;en-us;Q294807"
    >Q294807</a>.</p>

    <p>En las versiones de Apache anteriores a la 2.0, los mensajes se
    indicaban a&#241;adiendoles dobles comillas (") al principio que
    no se cerraban al final del mensaje.</p>
</usage>

<seealso><a href="../custom-error.html">Documentaci&#243;n sobre
personalizaci&#243;n de respuestas</a></seealso>
</directivesynopsis>

<directivesynopsis>
<name>ErrorLog</name>
<description>Ubicaci&#243;n del fichero en
el que se almacenan los mensajes de error</description>
<syntax> ErrorLog <var>file-path</var>|syslog[:<var>facility</var>]</syntax>
<default>ErrorLog logs/error_log (Unix) ErrorLog logs/error.log (Windows y OS/2)</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive>ErrorLog</directive> determina el
    nombre del fichero en el cual el servidor almacenar&#225; los
    mensajes de error en caso de que ocurra alguno. Si el
    <var>file-path</var> no es absoluto, entonces se asume que es
    relativo al valor especificado en la directiva <directive
    module="core">ServerRoot</directive>.</p>

    <example><title>Ejemplo</title>
    ErrorLog /var/log/httpd/error_log
    </example>

    <p>Si el <var>file-path</var> empieza con un barra vertical (|)
    entonces se asume que es un comando para procesar el registro de
    errores (error_log).</p>

    <example><title>Ejemplo</title>
    ErrorLog "|/usr/local/bin/httpd_errors"
    </example>

    <p>Usar <code>syslog</code> en lugar de un nombre de fichero
    permite almanecer los mesajes mediante syslogd(8) si el sistema lo
    soporta. Por defecto se usa la utilidad de syslog
    <code>local7</code>, pero puede cambiar esto usando
    <code>syslog:<var>facility</var></code> donde <var>facility</var>
    es cualquiera de los nombres normalmente documentados en
    syslog(1).</p>

    <example><title>Ejemplo</title>
    ErrorLog syslog:user
    </example>

    <p>SEGURIDAD: Consulte la secci&#243;n <a
    href="../misc/security_tips.html#serverroot">consejos sobre
    seguridad</a> para obtener m&#225;s informaci&#243;n sobre c&#243;mo se
    compromete la seguridad de su sistema si sobre el directorio en
    que se almacenan los ficheros log tiene permisos cualquier usuario
    que no sea &#250;nicamente el que arranca el servidor.</p> <note
    type="warning">

    <title>Nota</title> <p>Cuando se especifica una ruta a un fichero
    en una plataforma que no es Unix, hay que tener cuidado de usar
    solo barras (/) aunque el sistema permita barras invertidas
    (\). En general, lo mejor es usar siempre barras / en los ficheros
    de configuraci&#243;n.</p>
    </note>
</usage>
<seealso><directive module="core">LogLevel</directive></seealso>
<seealso><a href="../logs.html">Archivos Log de Apache</a></seealso>
</directivesynopsis>

<directivesynopsis>
<name>FileETag</name>
<description>Atributos de fichero usados para crear la ETAG de la
cabecera de respuesta HTTP</description>
<syntax>FileETag <var>component</var> ...</syntax>
<default>FileETag INode MTime Size</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>FileInfo</override>

<usage>
    <p>
    La directiva <directive>FileETag</directive> configura los
    atributos de fichero que se usan para crear la <code>ETag</code>
    (etiqueta de entidad) del campo cabecera de respuesta cuando el
    documento est&#225; basado en un fichero. (El valor de
    <code>ETag</code> se usa en la gesti&#243;n de cache para ahorrar
    ancho de banda.) En Apache 1.3.22 y en versiones anteriores, el
    valor de <code>ETag</code> se formaba <em>siempre</em> a partir
    del inodo del fichero, su tama&#241;o y la hora y la fecha en que
    se modific&#243; por &#250;ltima vez (mtime). La directiva
    <directive>FileETag</directive> permite elegir cu&#225;l de esos
    elementos quiere usar -- si es que se quiere usar alguno. Las
    palabras clave reconocidas son:
    </p>

    <dl>
     <dt><strong>INode</strong></dt>
     <dd>Para incluir el n&#250;mero de inodo en el c&#225;lculo</dd>
     <dt><strong>MTime</strong></dt>
     <dd>Para incluir en el c&#225;lculo la hora y la fecha en que el
     fichero fue modificado por &#250;ltima vez</dd>
     <dt><strong>Size</strong></dt>
     <dd>Para incluir en el c&#225;lculo el n&#250;mero de bytes que ocupa el fichero</dd>
     <dt><strong>All</strong></dt>
     <dd>Para incluir en el c&#225;lculo todos los campos disponibles. Esto es
     equivalente a:
         <example>FileETag INode MTime Size</example></dd>
     <dt><strong>None</strong></dt>
     <dd>Si el documento est&#225; basado en un fichero, ning&#250;n campo
     <code>ETag</code> ser&#225; incluido en la respuesta</dd>
    </dl>

    <p>Las palabras clave <code>INode</code>, <code>MTime</code>, y
    <code>Size</code> pueden ir precedidas por <code>+</code> o
    <code>-</code>, lo cual permite hacer cambios en la configuraci&#243;n
    heredada de un &#225;mbito m&#225;s amplio. Cualquier palabra clave que
    aparezca sin un prefijo cancela inmediatamente la configuraci&#243;n
    heredada.</p>

    <p>Si la configuraci&#243;n para un directorio incluye
    <code>FileETag INode MTime Size</code>, y la de un subdirectorio
    incluye <code>FileETag -INode</code>, la configuraci&#243;n para
    ese subdirectorio (que ser&#225; heredada por cualquier
    subdirectorio que no tenga un configuraci&#243;n propia) ser&#225;
    equivalente a <code>FileETag MTime Size</code>.</p>
</usage>
</directivesynopsis>

<directivesynopsis type="section">
<name>Files</name>
<description>Contiene directivas que se aplican a los ficheros cuyos
nombres coincidan con los que se especifiquen</description>
<syntax>&lt;Files <var>filename</var>&gt; ... &lt;/Files&gt;</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>All</override>

<usage>
    <p>La directiva <directive type="section">Files</directive> limita el &#225;mbito de aplicaci&#243;n de las directivas que incluye seg&#250;n el nombre de los ficheros. Es
    comparable a <directive module="core"
    type="section">Directory</directive> y <directive module="core"
    type="section">Location</directive>. Debe cerrarse con <code>&lt;/Files&gt;</code>. Las directivas usadas en
    esta secci&#243;n se aplicar&#225;n a cualquier objeto con un nombre base
    (&#250;ltimo componente del nombre de fichero) que coincida con el nombre de fichero especificado. Las
    secciones <directive type="section">Files</directive> se
    procesan en el orden en que aparecen en el fichero de
    configuraci&#243;n, despu&#233;s de las secciones <directive
    module="core" type="section">Directory</directive> y de leer los
    ficheros <code>.htaccess</code>, pero antes de las secciones
    <directive type="section" module="core">Location</directive>. Tenga en cuenta que las directivas <directive type="section">Files</directive>
    pueden anidarse dentro de las secciones <directive type="section"
    module="core">Directory</directive> para restringir la parte del
    sistema de ficheros a la que se aplican.</p>

    <p>El argumento <var>filename</var> puede incluir un nombre de
    fichero, o una cadena de car&#225;cteres comod&#237;n, donde <code>?</code>
    equivale a cualquier car&#225;cter individual, y <code>*</code>
    equivale a cualquier secuencia de caracteres. Tambi&#233;n pueden
    usarse expresiones regulares extendidas, con la ventaja de que
    tambien se puede usar el car&#225;cter <code>~</code>. Por
    ejemplo:</p>

    <example>
      &lt;Files ~ "\.(gif|jpe?g|png)$"&gt;
    </example>

    <p>equivaldr&#237;a a la mayor&#237;a de los formatos gr&#225;ficos de
    Internet. No obstante, es mejor usar <directive module="core"
    type="section">FilesMatch</directive>.</p>

    <p>Tenga en cuenta que a diferencia de las secciones <directive
    type="section" module="core">Directory</directive> y <directive
    type="section" module="core">Location</directive>, las secciones
    <directive type="section">Files</directive> pueden usarse dentro
    de los ficheros <code>.htaccess</code>. Esto permite a los
    usuarios controlar el acceso a sus propios archivos, a un nivel de
    fichero a fichero.</p>

</usage>
<seealso><a href="../sections.html">C&#243;mo funcionan las secciones
    &lt;Directory&gt;, &lt;Location&gt; and &lt;Files&gt; </a> para
    obtener una informaci&#243;n m&#225;s detallada sobre c&#243;mo se combinan estas
    diferentes secciones cuando se recibe una petici&#243;n
</seealso>
</directivesynopsis>

<directivesynopsis type="section">
<name>FilesMatch</name>
<description>Contiene las directivas que se aplican a los ficheros
cuyos nombres equivalen a las expresiones regulares que se especifiquen</description>
<syntax>&lt;FilesMatch <var>regex</var>&gt; ... &lt;/FilesMatch&gt;</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>Todas</override>

<usage>
    <p>La directiva <directive type="section">FilesMatch</directive>
    limita el rango de las directivas incluidas seg&#250;n el nombre de los
    ficheros, como hace la directiva <directive module="core"
    type="section">Files</directive>. Sin embargo, acepta
    expresiones regulares. Por ejemplo:</p>

    <example>
      &lt;FilesMatch "\.(gif|jpe?g|png)$"&gt;
    </example>

    <p>equivaldr&#237;a a la mayor&#237;a de los formatos gr&#225;ficos de Internet.</p>
</usage>

<seealso><a href="../sections.html">C&#243;mo funcionan las secciones
    &lt;Directory&gt;, &lt;Location&gt; and &lt;Files&gt;</a> para
    obtener informaci&#243;n detallada sobre la forma en que estas
    secciones se combinan cuando se recibe una petici&#243;n
</seealso>
</directivesynopsis>

<directivesynopsis>
<name>ForceType</name>
<description>Hace que todos los ficheros cuyos nombres tengan una equivalencia con con lo que se especifique sean
servidos como contenido del tipo MIME que se establezca</description>
<syntax>ForceType <var>MIME-type</var>|None</syntax>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>FileInfo</override>
<compatibility>Perteneciente al n&#250;cleo del servidor a partir de la
versi&#243;n de Apache 2.0</compatibility>

<usage>
    <p>Cuando se usa en un fichero <code>.htaccess</code> o en una
    secci&#243;n <directive type="section"
    module="core">Directory</directive>, <directive type="section"
    module="core">Location</directive> o <directive type="section"
    module="core">Files</directive>, esta directiva hace que todos los
    ficheros cuyos nombres guarden una equivalencia con lo
    especificado sean servidos como contenido
    <var>MIME-type</var>. Por ejemplo, si tiene un directorio lleno de
    ficheros GIF, pero no quiere etiquetarlos con <code>.gif</code>,
    puede usar:</p>

    <example>
      ForceType image/gif
    </example>

    <p>Tenga en cuenta que a diferencia de <directive
    module="core">DefaultType</directive>, esta directiva prevalece sobre
    todas las asociaciones de tipo MIME, incluidas las extensiones de
    nombre de fichero que puedan identificar de qu&#233; tipo es un fichero.</p>

    <p>Puede hacer que <directive>ForceType</directive> no prevalezca sobre el resto de directivas usando el valor <code>None</code>:</p>

    <example>
      # forzar a todos los tipos de fichero a ser tratados como imagen/gif:<br />
      &lt;Location /images&gt;<br />
        <indent>
          ForceType image/gif<br />
        </indent>
      &lt;/Location&gt;<br />
      <br />
      # pero permitir la asociaci&#243;n de tipos MIME normal aqu&#237;:<br />
      &lt;Location /images/mixed&gt;<br />
      <indent>
        ForceType None<br />
      </indent>
      &lt;/Location&gt;
    </example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>HostnameLookups</name> <description>Activa la resoluci&#243;n de
DNS de las direcciones IP de los clientes</description>
<syntax>HostnameLookups On|Off|Double</syntax>
<default>HostnameLookups Off</default> <contextlist><context>server
config</context><context>virtual host</context>
<context>directory</context></contextlist>

<usage>
    <p>Esta directiva activa la resoluci&#243;n de DNS de manera que
    los nombres de host puedan ser guardados en los archivos log (y
    pasados a CGIs/SSIs en <code>REMOTE_HOST</code>).  El valor
    <code>Double</code> se refiere a hacer una busqueda de DNSs
    inversa doble. Esto es, despu&#233;s de hacer una busqueda
    inversa, se hace una busqueda normal posteriormente sobre ese
    resultado. Al menos una de las direcciones IP en la b&#250;squeda
    posterior debe equivaler a la direcci&#243;n IP original. (En
    terminolog&#237;a de "tcpwrappers" se llama
    <code>PARANOID</code>.)</p>

    <p>Independientemente de lo que se especifique, cuando
    <module>mod_access</module> se usa para controlar el acceso por
    nombre de host, se har&#225; una consulta inversa doble.  Esto se
    hace por seguridad. Tenga en cuenta que el resultado de una
    busqueda inversa doble no est&#225; disponible generalmente a no
    ser que especifique <code>HostnameLookups Double</code>. Por
    ejemplo, si especifica solo <code>HostnameLookups On</code> y se
    hace una petici&#243;n a un objeto protegido por restricciones de
    nombre de host, independientemente de si la consulta inversa doble
    falla o no, el resultado de la consulta inversa simple se
    pasar&#225; a los CGIs en <code>REMOTE_HOST</code>.</p>

    <p>El valor por defecto es <code>Off</code> para ahorrar
    tr&#225;fico de red en aquellos sitios web que realmente no
    necesitan hacer b&#250;squedas inversas dobles. Tambi&#233;n es
    mejor para los usuarios finales porque no tienen que sufrir el
    retardo adicional que introducen las b&#250;squedas.  Los sitios
    web con mucha carga deben usar en esta directiva el valor
    <code>Off</code>, porque las b&#250;squedas de DNSs pueden
    consumir una cantidad de tiempo considerable. La utilidad
    <program>logresolve</program>, compilada por defecto en el
    subdirectorio <code>bin</code> de su directorio de
    instalaci&#243;n, puede usarse m&#225;s tarde para buscar nombres
    de host en direcciones IP que est&#233;n en los logs cuando no
    est&#233; en l&#237;nea.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>IdentityCheck</name>
<description>Activa que se registre en los archivos log la entidad RFC1413 del usuario remoto</description>
<syntax>IdentityCheck On|Off</syntax>
<default>IdentityCheck Off</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>
<usage>
    <p>Esta directiva permite el almacenamiento en logs, seg&#250;n se
    especifica en el RFC1413, del nombre de usuario remoto para casda
    conexi&#243;n cuando la m&#225;quina del cliente corra
    &quot;identd&quot; o un programa similar. Esta informaci&#243;n se
    registra en el log de acceso.</p>

    <p>La informaci&#243;n que se registra con este procedimiento no
    debe ser considerada como fiable excepto para controles
    rudimentarios.</p>

    <p>Tenga en cuenta que esto puede provocar serios problemas de
    retardo en los accesos a su servidor porque para cada
    petici&#243;n hay que ejecutar una consulta de este tipo. Cuando
    hay firewalls involucrados, cada b&#250;squeda puede probablemente
    fallar y a&#241;adir 30 segundos de retardo cada vez que se
    intenta un acceso. De modo que en general, su uso no es muy
    &#250;til en servidores p&#250;blicos accesibles desde
    Internet.</p>
</usage>
</directivesynopsis>

<directivesynopsis type="section">
<name>IfDefine</name>
<description>Engloba directivas que ser&#225;n procesadas solo si se
cumple una determinada condici&#243;n al iniciar el servidor</description>
<syntax>&lt;IfDefine [!]<var>parameter-name</var>&gt; ...
    &lt;/IfDefine&gt;</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>All</override>

<usage>
    <p>La secci&#243;n <code>&lt;IfDefine
    <var>test</var>&gt;...&lt;/IfDefine&gt; </code> se usa para marcar
    directivas que son condicionales. Las directivas que hay dentro de
    una secci&#243;n <directive type="section">IfDefine</directive> se
    procesan solo si <var>test</var> devuelve un resultado
    positivo. Si el <var> test</var> produce un resultado negativo,
    todo lo que haya entre los marcadores de comienzo y final
    ser&#225; ignorado.</p>

    <p>El <var>test</var> en la secci&#243;n de directivas <directive
    type="section" >IfDefine</directive> puede tomar una de las
    siguientes dos formas:</p>

    <ul>
      <li><var>parameter-name</var></li>

      <li><code>!</code><var>parameter-name</var></li>
    </ul>

    <p>En el primer caso, las directivas entre los marcadores de
    comienzo y final se procesan solo si el par&#225;metro llamado
    <var>parameter-name</var> est&#225; definido. El segundo formato
    hace lo contrario, y procesa las directivas solo si
    <var>parameter-name</var> <strong>no</strong> est&#225;
    definido.</p>

    <p>El argumento <var>parameter-name</var> se define cuando se
    ejecuta <program>httpd</program> por la l&#237;nea de comandos con la opci&#243;n
    <code>-D<var>parameter</var></code>, al iniciar el servidor.</p>

    <p>Las secciones <directive type="section">IfDefine</directive>
    son anidables, lo cual puede usarse para implementar tests
    simples con varios par&#225;metros. Ejemplo:</p>

    <example>
      httpd -DReverseProxy ...<br />
      <br />
      # httpd.conf<br />
      &lt;IfDefine ReverseProxy&gt;<br />
      <indent>
        LoadModule rewrite_module modules/mod_rewrite.so<br />
        LoadModule proxy_module   modules/libproxy.so<br />
      </indent>
      &lt;/IfDefine&gt;
    </example>
</usage>
</directivesynopsis>

<directivesynopsis type="section">
<name>IfModule</name>
<description>Engloba directivas que se procesan de forma condicional
seg&#250;n est&#233; presente o ausente un m&#243;dulo espec&#237;fico</description>
<syntax>&lt;IfModule [!]<var>module-name</var>&gt; ...
    &lt;/IfModule&gt;</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>Todas</override>

<usage>
    <p>La secci&#243;n <code>&lt;IfModule
    <var>test</var>&gt;...&lt;/IfModule&gt;</code> se usa para marcar
    las directivas que se aplican si est&#225; presente un m&#243;dulo
    espec&#237;fico. Las directivas dentro de una secci&#243;n <directive
    type="section" >IfModule</directive> solo se procesan si el
    <var>test</var> produce un resultado positivo. Si el <var>test</var> da falso, todo
    lo que haya entre los marcadores de inicio y final es
    ignorado.</p>

    <p>El <var>test</var> de las secciones <directive type="section"
    >IfModule</directive> puede tomar una de las siguientes
    formas:</p>

    <ul>
      <li><var>module name</var></li>

      <li>!<var>module name</var></li>
    </ul>

    <p>En el primer caso, las directivas entre los marcadores de
    comienzo y final son procesados solo si el m&#243;dulo llamado
    <var>module name</var> est&#225; incluido en Apache -- ya sea
    porque est&#225; compilado en el servidor o porque est&#233;
    cargado din&#225;micamente usando <directive module="mod_so"
    >LoadModule</directive>. El segundo formato hace lo contrario, y
    solo se procesan las directivas si el m&#243;dulo <var>module
    name</var> <strong>no</strong> est&#225; incluido.</p>

    <p>El argumento <var>module name</var> es  el nombre del fichero del
    m&#243;dulo en el momento en que fue compilado. Por ejemplo,
    <code>mod_rewrite.c</code>.  Si un m&#243;dulo consiste en varios
    archivos fuente, use el nombre del fichero que contenga la cadena
    de caracteres <code>STANDARD20_MODULE_STUFF</code>.</p>

    <p>Las secciones <directive type="section">IfModule</directive>
    son anidables, lo cual puede usarse para implementar tests simples
    con varios m&#243;dulos.</p>

    <note>Esta secci&#243;n debe usarse solo si necesita tener un
    fichero de configuraci&#243;n que funcione tanto si est&#225; como
    si no est&#225; un determinado m&#243;dulo disponible. En
    condiciones normales, no es necesario usar directivas en
    secciones <directive type="section">IfModule</directive>.</note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>Include</name>
<description>Incluye otros ficheros de configuraci&#243;n dentro de
los ficheros de configuraci&#243;n del servidor</description>
<syntax>Include <var>file-path</var>|<var>directory-path</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context>
</contextlist>
<compatibility>Se pueden usar caracteres comod&#237;n para encontrar
equivalencias en las versiones de Apache 2.0.41 y posteriores</compatibility>

<usage>
    <p>Esta directiva permite la inclusi&#243;n de otros ficheros de
    configuraci&#243;n  dentro de los ficheros de configuraci&#243;n del
    servidor.</p>

    <p>Los caracteres comod&#237;n de tipo shell (<code>fnmatch()</code>)
    pueden usarse para incluir varios ficheros de una vez por orden
    alfab&#233;tico. Adem&#225;s, si <directive>Include</directive> apunta a un
    directorio, en lugar de a un fichero, Apache leer&#225; todos los
    ficheros en ese directorio y sus subdirectorios. Sin embargo, no se
    recomienda incluir subdirectorios enteros, porque es f&#225;cil dejar
    accidentalmente ficheros temporales en un directorio y esto
    provocar&#225; que <program>httpd</program> aborte.</p>

    <p>La ruta del fichero especificada puede ser absoluta, o relativa
    a un directorio respecto al valor especificado en <directive
    module="core">ServerRoot</directive>.</p>

    <p>Ejemplos:</p>

    <example>
      Include /usr/local/apache2/conf/ssl.conf<br />
      Include /usr/local/apache2/conf/vhosts/*.conf
    </example>

    <p>O especificando rutas relativas al directorio <directive
    module="core">ServerRoot</directive>:</p>

    <example>
      Include conf/ssl.conf<br />
      Include conf/vhosts/*.conf
    </example>

    <p>Si ejecuta <code>apachectl configtest</code> le aparecer&#225;
    una lista con los ficheros que est&#225;n siendo procesados
    durante la comprobaci&#243;n de la configuraci&#243;n:</p>

    <example>
      root@host# apachectl configtest<br />
      Processing config file: /usr/local/apache2/conf/ssl.conf<br />
      Processing config file: /usr/local/apache2/conf/vhosts/vhost1.conf<br />
      Processing config file: /usr/local/apache2/conf/vhosts/vhost2.conf<br />
      Syntax OK
    </example>
</usage>

<seealso><program>apachectl</program></seealso>
</directivesynopsis>

<directivesynopsis>
<name>KeepAlive</name>
<description>Permite que se establezcan conexiones HTTP
persistentes</description>
<syntax>KeepAlive On|Off</syntax>
<default>KeepAlive On</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La extensi&#243;n Keep-Alive de HTTP/1.0 y la funcionalidad de
    conexi&#243;n persistente de HTTP/1.1 facilitan la posibilidad de
    que se establezcan sesiones HTTP de larga duraci&#243;n que
    permiten que se puedan enviar m&#250;ltiples peticiones sobre la
    misma conexi&#243;n TCP. En algunos casos, esto tiene como
    resultado una reducci&#243;n de casi el 50% en los tiempos de
    retardo en el caso de documentos con muchas im&#225;genes. Para
    activar las conexiones Keep-Alive, especifique <code>KeepAlive
    On</code>.</p>

    <p>Para clientes HTTP/1.0, las conexiones Keep-Alive se
    usar&#225;n solo si el cliente lo solicita
    espec&#237;ficamente. Adem&#225;s, una conexi&#243;n Keep-Alive
    con un cliente HTTP/1.0 puede usarse solo cuando el tama&#241;o
    del contenido es conocido con antelaci&#243;n. Esto implica que el
    contenido din&#225;mico, como puede ser el resultado de un CGI,
    p&#225;ginas SSI y listados de directorios generados por el
    servidor, no usar&#225;n por lo general conexiones Keep-Alive para
    clientes HTTP/1.0.  Para clientes HTTP/1.1, las conexiones
    persistentes son las que se usan por defecto a no ser que se
    especifique lo contrario. Si el cliente lo solicita, se usar&#225;
    @@@@@ chunked encoding @@@@@ para enviar contenido de tama&#241;o
    desconocido sobre conexiones persistentes.</p>
</usage>

<seealso><directive module="core">MaxKeepAliveRequests</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>KeepAliveTimeout</name>
<description>Tiempo que el servidor esperar&#225; peticiones subsiguientes
en conexiones persistentes</description>
<syntax>KeepAliveTimeout <var>seconds</var></syntax>
<default>KeepAliveTimeout 15</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>Es el tiempo en segundos que Apache esperar&#225; peticiones
    subsiguientes antes de cerrar una conexi&#243;n persistente. Una
    vez que una petici&#243;n ha sido recibida, se aplica el valor
    especificado en la directiva <directive
    module="core">Timeout</directive> para cerrar la
    conexi&#243;n.</p>

    <p>Espeficificar un valor alto para
    <directive>KeepAliveTimeout</directive> puede provocar un menor
    rendimiento en servidores con mucha carga. Cuanto mayor sea el
    valor de timeout, mayor ser&#225; el n&#250;mero de procesos del
    servidor se mantendr&#225;n ocupados esperando en conexiones con
    clientes no activos.</p>
</usage>
</directivesynopsis>

<directivesynopsis type="section">
<name>Limit</name>
<description>Restringe la aplicaci&#243;n de los controles de acceso incluidos a solo ciertos m&#233;todos HTTP</description>
<syntax>&lt;Limit <var>method</var> [<var>method</var>] ... &gt; ...
    &lt;/Limit&gt;</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>Todas</override>

<usage>
    <p>Los controles de acceso se aplican normalmente a
    <strong>todos</strong> los m&#233;todos de acceso, y este es el
    comportamiento que se busca casi siempre. <strong>En general, las
    directivas de control de acceso no deben estar dentro de una
    secci&#243;n <directive type="section">Limit</directive>.</strong></p>

    <p>El prop&#243;sito <directive type="section">Limit</directive>
    es restringir el efecto de los controles de acceso a los
    m&#233;todos HTTP que se especifiquen. Para los dem&#225;s
    m&#233;todos, las restricciones de acceso que est&#233;n incluidas
    en <directive type="section">Limit</directive> <strong>no
    tendr&#225;n efecto</strong>. Los siguientes ejemplos aplican el
    control de acceso solo a los m&#233;todos <code>POST</code>,
    <code>PUT</code>, y <code>DELETE</code>, no afectando al resto de
    m&#233;todos:</p>

    <example>
      &lt;Limit POST PUT DELETE&gt;<br />
      <indent>
        Require valid-user<br />
      </indent>
      &lt;/Limit&gt;
    </example>

    <p>Los m&#233;todos incluidos en la lista pueden ser uno o
    m&#225;s de los siguientes: <code>GET</code>,
    <code>POST</code>, <code>PUT</code>, <code>DELETE</code>,
    <code>CONNECT</code>, <code>OPTIONS</code>, <code>PATCH</code>,
    <code>PROPFIND</code>, <code>PROPPATCH</code>, <code>MKCOL</code>,
    <code>COPY</code>, <code>MOVE</code>, <code>LOCK</code>, y
    <code>UNLOCK</code>. <strong>Los nombres de los m&#233;todos
    distinguen may&#250;sculas de min&#250;sculas.</strong> Si usa
    <code>GET</code> tambi&#233;n se restringir&#225;n las peticiones
    <code>HEAD</code>. El m&#233;todo <code>TRACE</code> no puede
    limitarse.</p>

    <note type="warning">Es mejor usar una secci&#243;n <directive
    type="section" module="core">LimitExcept</directive> en lugar de
    una secci&#243;n <directive type="section"
    module="core">Limit</directive> cuando se quiere restringir el
    acceso, porque una secci&#243;n <directive type="section"
    module="core">LimitExcept</directive> protege contra m&#233;todos
    arbitrarios.</note>

</usage>
</directivesynopsis>

<directivesynopsis type="section">
<name>LimitExcept</name>
<description>Restringe los controles de acceso a todos los m&#233;todos
HTTP excepto a los que se especifiquen</description>
<syntax>&lt;LimitExcept <var>method</var> [<var>method</var>] ... &gt;
    ...  &lt;/LimitExcept&gt;</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>Todas</override>

<usage>
    <p><directive type="section">LimitExcept</directive> y
    <code>&lt;/LimitExcept&gt;</code> se usan para englobar un grupo
    de directivas de control de acceso que se aplicar&#225;n a
    cualquier m&#233;todo de acceso HTTP <strong>no</strong>
    especificado en los argumentos; es lo contrario a lo
    que hace una secci&#243;n <directive type="section"
    module="core">Limit</directive> y puede usarse para controlar
    tanto m&#233;todos est&#225;ndar como no est&#225;ndar o
    m&#233;todos no reconocidos. Consulte la documentaci&#243;n de
    <directive module="core" type="section">Limit</directive> para
    m&#225;s detalles.</p>

    <p>Por ejemplo:</p>

    <example>
      &lt;LimitExcept POST GET&gt;<br />
      <indent>
        Require valid-user<br />
      </indent>
      &lt;/LimitExcept&gt;
    </example>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>LimitInternalRecursion</name>
<description>Determina el n&#250;mero m&#225;ximo de redirecciones internas y
subpeticiones anidadas</description>
<syntax>LimitInternalRecursion <var>number</var> [<var>number</var>]</syntax>
<default>LimitInternalRecursion 10</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>
<compatibility>Disponible en las versiones Apache 2.0.47 y posteriores</compatibility>

<usage>
    <p>Una redirecci&#243;n interna ocurre, por ejemplo, cuando se usa
    la directiva <directive module="mod_actions">Action</directive>,
    la cual internamente redirige la petici&#243;n original a un
    script CGI. Una subpetici&#243;n es un mecanismo de Apache para
    saber qu&#233; ocurrir&#237;a si se produjera una petici&#243;n a
    una URI.  Por ejemplo, <module>mod_dir</module> usa subpeticiones
    para buscar archivos especificados en la directiva <directive
    module="mod_dir">DirectoryIndex</directive>.</p>

    <p><directive>LimitInternalRecursion</directive> hace que el
    servidor no sufra un error irrecuperable cuando entra en un ciclo
    infinito de redirecciones internas o subpeticiones. Tales ciclos
    se producen normalmente por errores de configuraci&#243;n.</p>

    <p>La directiva guarda dos l&#237;mites diferentes, los cuales se
    eval&#250;an en para cada petici&#243;n. El primer
    <var>n&#250;mero</var> es el n&#250;mero m&#225;ximo de
    redirecciones internas, que pueden producirse una detr&#225;s de
    otra. El segundo <var>n&#250;mero</var> determina, la profundidad
    a la que subpeticiones pueden anidarse. Si especifica solo un
    <var>n&#250;mero</var>, se asignar&#225; a ambos l&#237;mites.</p>

    <example><title>Ejemplo</title>
      LimitInternalRecursion 5
    </example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>LimitRequestBody</name>
<description>Restringe el tama&#241;o total del cuerpo de las peticiones
HTTP enviadas desde el cliente</description>
<syntax>LimitRequestBody <var>bytes</var></syntax>
<default>LimitRequestBody 0</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>Todas</override>

<usage>
    <p>Esta directiva especifica el n&#250;mero de <var>bytes</var>
    desde 0 (que significa sin l&#237;mite) hasta 2147483647 (2GB) que
    se permite que tenga el cuerpo de una petici&#243;n.</p>

    <p>La directiva <directive>LimitRequestBody</directive> permite al
    usuario especificar un l&#237;mite al tama&#241;o del cuerpo del
    mensaje de las peticiones dentro del contexto en el que la
    directiva aparece (server, per-directory, per-file o
    per-location). Si la petici&#243;n del cliente excede ese
    l&#237;mite, el servidor devolver&#225; una respuesta de error en
    lugar de servir la petici&#243;n. El tama&#241;o del cuerpo del
    mensaje de una petici&#243;n normal var&#237;a mucho en
    funci&#243;n de la naturaleza del recurso y los m&#233;todos
    permitidos para ese recurso. Los scripts CGI usan normamente el
    cuerpo del mensaje para acceder la informaci&#243;n de formularios
    HTML.  Las implementaciones del m&#233;todo <code>PUT</code>
    requerir&#225;n un valor al menos del mismo tama&#241;o que
    cualquier representaci&#243;n que el servidor desee aceptar para
    ese recurso.</p>

    <p>Esta directiva le da al administrador del servidor un mayor
    control sobre el comportamiento anormal de peticiones de clientes,
    lo cual puede ser &#250;til para evitar algunos tipos de ataques de
    denegaci&#243;n de servicio.</p>

    <p>Si, por ejemplo, permite que se suban archivos a una ubicaci&#243;n
    en concreto, y quiere limitar el tama&#241;o de los ficheros que se
    suban a 100K, puede usar la siguiente directiva:</p>

    <example>
      LimitRequestBody 102400
    </example>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>LimitRequestFields</name>
<description>Limita el n&#250;mero de campos de la cabecera de las
peticiones HTTP del cliente que ser&#225;n aceptadas</description>
<syntax>LimitRequestFields <var>number</var></syntax>
<default>LimitRequestFields 100</default>
<contextlist><context>server config</context></contextlist>

<usage>
    <p><var>Number</var> es un entero entre 0 (sin l&#237;mite) hasta
    32767. El valor por defecto se define por la constante
    <code>DEFAULT_LIMIT_REQUEST_FIELDS</code> al compilar (y es de 100
    campos para la cabecera).</p>

    <p>La directiva <directive>LimitRequestFields</directive> permite
    al administrador del servidor modificar el l&#237;mite del
    n&#250;mero de campos de la cabecera permitidos en una
    petici&#243;n HTTP. Este valor tiene que ser mayor que el
    n&#250;mero de campos que tiene la cabecera de una petici&#243;n
    normal de un cliente. El n&#250;mero de campos de la cabecera de
    una petici&#243;n usados por un cliente raramente pasa de 20, pero
    esto puede variar seg&#250;n las diferentes implementaciones, a
    menudo dependiendo incluso de la configuraci&#243;n que un usuario
    haya hecho de su navegador para soportar negociaci&#243;n de
    contenidos detallada. Las extensiones opcionales de HTTP se
    expresan muchas veces usando campos de cabecera de
    petici&#243;n.</p>

    <p>Esta directiva le da al administrador del servidor un mayor
    control sobre el comportamiento anormal de peticiones de clientes,
    lo cual puede ser &#250;til para evitar algunos tipos de ataques
    de denegaci&#243;n de servicio. Debe incrementar el valor que se
    especifica en esta directiva si a los clientes normales les llegan
    mensajes de error que indican que se han enviado demasiados campos
    de cabecera en la petici&#243;n.</p>

    <p>Por ejemplo:</p>

    <example>
      LimitRequestFields 50
    </example>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>LimitRequestFieldSize</name>
<description>Limita el tama&#241;o permitido de las cabeceras de las peticiones HTTP de los clientes</description>
<syntax>LimitRequestFieldsize <var>bytes</var></syntax>
<default>LimitRequestFieldsize 8190</default>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>Esta directiva especifica el n&#250;mero de <var>bytes</var>
    desde 0 hasta el valor de la constante definida al compilar
    <code>DEFAULT_LIMIT_REQUEST_FIELDSIZE</code> (8190 por defecto)
    que ser&#225; permitido para una cabecera de las peticiones
    HTTP.</p>

    <p>La directiva <directive>LimitRequestFieldSize</directive>
    permite al administrador del servidor reducir el l&#237;mite del
    tama&#241;o permitido de una cabecera de las peticiones HTTP por
    debajo del tama&#241;o del buffer de entrada compilado en el
    servidor. Este valor tiene que ser lo suficientemente grande para
    que no quede por debajo del tama&#241;o normal de una cabecera de
    petici&#243;n de un cliente. El tama&#241;o de una cabecera de una
    petici&#243;n var&#237;a mucho en funci&#243;n de la
    implementaci&#243;n del cliente, a menudo depende incluso de la
    configuraci&#243;n del navegador que haya hecho el usuario para
    soportar negociaci&#243;n de contenido detallada.</p>

    <p>Esta directiva le da al administrador del servidor un mayor
    control sobre el comportamiento anormal de peticiones de clientes,
    lo cual puede ser &#250;til para evitar algunos tipos de ataques de
    denegaci&#243;n de servicio.</p>

    <p>Por ejemplo:</p>

    <example>
      LimitRequestFieldSize 4094
    </example>

    <note>En condiciones normales, no debe modificarse el valor que
    viene por defecto.</note>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>LimitRequestLine</name>
<description>Limita el tama&#241;o la l&#237;nea de petici&#243;n HTTP que ser&#225;
aceptada</description>
<syntax>LimitRequestLine <var>bytes</var></syntax>
<default>LimitRequestLine 8190</default>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>Esta directiva especifica el n&#250;mero de <var>bytes</var> de
    0 hasta el valor de la constante definida al compilar
    <code>DEFAULT_LIMIT_REQUEST_LINE</code> ( @@@@ 8190 as distributed @@@@ ) que
    se permitir&#225; para la l&#237;nea de petici&#243;n HTTP.</p>

    <p>La directiva <directive>LimitRequestLine</directive> permite al
    administrador del servidor reducir el l&#237;mite de tama&#241;o
    permitido de la l&#237;nea de petici&#243;n de las peticiones HTTP
    de los clientes por debajo del tama&#241;o del buffer de entrada
    compilado con el servidor. Como la l&#237;nea de petici&#243;n
    consiste en el m&#233;todo HTTP, la URI y la versi&#243;n del
    protocolo, la directiva <directive>LimitRequestLine</directive>
    impone una restricci&#243;n en la longitud de la URI de la
    petici&#243;n permitida por el servidor. Este valor tiene que ser
    lo suficientemente grande como para que admita el tama&#241;o de
    sus nombres de recurso, incluida la informaci&#243;n que puede
    ser pasada como parte de consulta de una petici&#243;n
    <code>GET</code>.</p>

    <p>Esta directiva le da al administrador del servidor un mayor
    control sobre el comportamiento anormal de peticiones de clientes,
    lo cual puede ser &#250;til para evitar algunos tipos de ataques de
    denegaci&#243;n de servicio.</p>

    <p>Por ejemplo:</p>

    <example>
      LimitRequestLine 4094
    </example>

    <note>En condiciones normales, no debe modificarse el valor que
    viene por defecto.</note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>LimitXMLRequestBody</name>
<description>Limita el tama&#241;o del cuerpo de una petici&#243;n XML</description>
<syntax>LimitXMLRequestBody <var>bytes</var></syntax>
<default>LimitXMLRequestBody 1000000</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>All</override>

<usage>
    <p>L&#237;mite (en bytes) o tama&#241;o m&#225;ximo del cuerpo de una petici&#243;n
    basada en XML. Si se especifica el valor <code>0</code> se
    desactiva este control.</p>

    <p>Ejemplo:</p>

    <example>
      LimitXMLRequestBody 0
    </example>

</usage>
</directivesynopsis>

<directivesynopsis type="section">
<name>Location</name>
<description>Aplica las directivas que contiene solo a las URLs que tengan una equivalencia con los valores que se especifiquen</description>
<syntax>&lt;Location
    <var>URL-path</var>|<var>URL</var>&gt; ... &lt;/Location&gt;</syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>Una secci&#243;n <directive type="section">Location</directive>
    aplica las directivas que contiene seg&#250;n la URL de que se
    trate. Es parecida a la directiva <directive type="section"
    module="core">Directory</directive>, y tiene que terminar con una
    directiva <code>&lt;/Location&gt;</code>. Las secciones <directive
    type="section">Location</directive> se procesan en el orden en que
    aparecen en el fichero de configuraci&#243;n, despu&#233;s de leer
    las secciones <directive type="section"
    module="core">Directory</directive> y los ficheros
    <code>.htaccess</code>, y despu&#233;s de las secciones <directive
    type="section" module="core">Files</directive>.</p>

    <p>Las secciones <directive type="section">Location</directive>
    operan completamente fuera del sistema de ficheros.  Esto tiene
    varias consecuencias. La m&#225;s importante, es que las
    directivas <directive type="section">Location</directive> no deben
    usarse para controlar el acceso a ubicaciones del sistema de
    ficheros. Como diferentes URLs pueden corresponderse con una misma
    ubicaci&#243;n de un sistema de ficheros, tales controles de
    acceso pueden ser burlados.</p>

    <note><title>Cu&#225;ndo usar <directive
    type="section">Location</directive></title>

    <p>Use <directive type="section">Location</directive> para aplicar
    las directivas que va a incluir a contenido que est&#225; fuera
    del sistema de ficheros.  Para el contenido que est&#233; en el
    sistema de ficheros, use <directive type="section"
    module="core">Directory</directive> y <directive type="section"
    module="core">Files</directive>.  Una excepci&#243;n a esto es el
    uso de <code>&lt;Location /&gt;</code>, que es un modo f&#225;cil
    de aplicar una configuraci&#243;n a un servidor entero.</p>
    </note>

    <p>Para todas las peticiones que no provengan de servidores proxy,
    la URL de la que se buscan equivalencias es una ruta URL de la
    forma <code>/path/</code>.  Ning&#250;n esquema, nombre de host,
    puerto o cadena de consulta puede incluirse.  Para peticiones
    provenientes de servidores proxy, la URL de la que se buscan
    euivalencias es de la forma <code>scheme://servername/path</code>,
    y debe incluir el prefijo.</p>

    <p>La URL puede usar caracteres comod&#237;n. En una cadena de
    caracteres comod&#237;n, <code>?</code> equivale a cualquier
    car&#225;cter, y <code>*</code> equivale a cualquier secuencia de
    caracteres.</p>

    <p>Tambi&#233;n pueden usarse expresiones regulares extendidas,
    con el car&#225;cter adicional <code>~</code>. Por ejemplo:</p>

    <example>
      &lt;Location ~ "/(extra|special)/data"&gt;
    </example>

    <p>equivaldr&#225; a las URLs que contengan la subcadena
    <code>/extra/data</code> o <code>/special/data</code>. La
    directiva <directive type="section"
    module="core">LocationMatch</directive> se comporta de igual modo
    que la versi&#243;n de regex de <directive
    type="section">Location</directive>.</p>

    <p>El uso de <directive type="section">Location</directive> es
    especialmente &#250;til cuando se combina con la directiva
    <directive module="core">SetHandler</directive>. Por ejemplo, para
    permitir peticiones de status, pero solo de navegadores que
    intenten acceder a <code>foo.com</code>, puede usar:</p>

    <example>
      &lt;Location /status&gt;<br />
      <indent>
        SetHandler server-status<br />
        Order Deny,Allow<br />
        Deny from all<br />
        Allow from .foo.com<br />
      </indent>
      &lt;/Location&gt;
    </example>

    <note><title>Comentarios sobre la barra : /</title> <p>El
      car&#225;cter de la barra tiene un significado especial
      dependiendo del lugar donde aparece en una URL. Los usuarios
      puede estar no estar acostumbrada a que la barra tenga distintos
      significados, por ejemplo, en los sistemas de ficheros, varias
      barras consecutivas tienen el mismo significado que una sola
      barra (por ejemplo, <code>/home///foo</code> es lo mismo que
      <code>/home/foo</code>). Para las URL's esto no se cumple.  La
      directiva <directive type="section"
      module="core">LocationMatch</directive> y la versi&#243;n de
      regex de <directive type="section">Location</directive>
      requieren que se especifiquen expl&#237;citamente m&#250;ltiples
      barras solo si esa es su intenci&#243;n.</p>

      <p>Por ejemplo, <code>&lt;LocationMatch ^/abc&gt;</code>
      podr&#237;a equivaler a la petici&#243;n de la URL
      <code>/abc</code> pero no a la petici&#243;n de la URL <code>
      //abc</code>. La directiva (no regex) <directive type="section"
      >Location</directive> se comporta de manera similar cuando se
      usa para peticiones provenientes de servidores proxy. Sin
      embargo, cuando la directiva (no regex) <directive
      type="section" >Location</directive> se usa para peticiones no
      provenientes de servidores proxy, a efectos de encontrar
      equivalencias, m&#250;ltiples barras equivaldr&#225;n a una
      sola. Por ejemplo, si especifica <code>&lt;Location
      /abc/def&gt;</code> y la petici&#243;n es a
      <code>/abc//def</code> se producir&#225; equivalencia.</p>
    </note>
</usage>
<seealso><a href="../sections.html">C&#243;mo funcionan las secciones
    &lt;Directory&gt;, &lt;Location&gt; y &lt;Files&gt; </a> si quiere
    obtener una informaci&#243;n detallada sobre c&#243;mo se combinan
    esas secciones cuando se recibe una petici&#243;n</seealso>
</directivesynopsis>

<directivesynopsis type="section">
<name>LocationMatch</name>
<description>Aplica las directiva que incluye solo a las URLs que tengan equivalencia con alguna de las expresiones regulares que se especifiquen</description>
<syntax>&lt;LocationMatch
    <var>regex</var>&gt; ... &lt;/LocationMatch&gt;</syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive
    type="section">LocationMatch</directive> limita la aplicaci&#243;n
    de las directivas que incluye a URLs que tengan equivalencia con
    alguna de las expresiones regulares que se especifican, de manera
    id&#233;ntica a como lo hace <directive module="core"
    type="section">Location</directive>. Sin embargo, toma las
    expresiones regulares como argumentos en lugar de como una cadena
    de caracteres. Por ejemplo:</p>

    <example>
      &lt;LocationMatch "/(extra|special)/data"&gt;
    </example>

    <p>equivaldr&#237;a a las URLs que contengan la subcadena
    <code>/extra/data</code> &#243; <code>/special/data</code>.</p>
</usage>

<seealso><a href="../sections.html">C&#243;mo funcionan las secciones
    &lt;Directory&gt;, &lt;Location&gt; y &lt;Files&gt; </a> si quiere
    obtener una explicaci&#243;n detallada de c&#243;mo se combinan
    esas secciones cuando se recibe una petici&#243;n</seealso>
</directivesynopsis>

<directivesynopsis>
<name>LogLevel</name>
<description>Controla la extensi&#243;n de los mensajes que se almacenan
en el ErrorLog</description>
<syntax>LogLevel <var>level</var></syntax>
<default>LogLevel warn</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p><directive>LogLevel</directive> especifica el nivel al que se
    detallan los errores que se almacenan en los logs de errores
    (consulte la directiva <directive
    module="core">ErrorLog</directive>). Los <var>niveles</var>
    (levels) disponibles son, por orden decreciente:</p>

    <table border="1">
    <columnspec><column width=".2"/><column width=".3"/><column width=".5"/>
    </columnspec>
      <tr>
        <th><strong>Level</strong> </th>

        <th><strong>Description</strong> </th>

        <th><strong>Example</strong> </th>
      </tr>

      <tr>
        <td><code>emerg</code> </td>

        <td>Emergencias - sistema inutilizable.</td>

        <td>"Un proceso hijo no puede abrir el fichero de lock (lock
        file). El programa va a terminar"</td>
      </tr>

      <tr>
        <td><code>alert</code> </td>

        <td>Debe hacer algo inmediatamente.</td>

        <td>"getpwuid: no pudo determinar el nombre de usuario a partir del uid"</td>
      </tr>

      <tr>
        <td><code>crit</code> </td>

        <td>Condiciones cr&#237;ticas.</td>

        <td>"socket: No se encontr&#243; un socket adecuado, el proceso hijo va a terminar"</td>
      </tr>

      <tr>
        <td><code>error</code> </td>

        <td>Condiciones de error.</td>

        <td>"Final prematuro de la cabecera del script""</td>
      </tr>

      <tr>
        <td><code>warn</code> </td>

        <td>Condiciones de advertencia.</td>

        <td>"el proceso hijo 1234 no ha terminado, enviando otra vez
        SIGHUP"</td>
      </tr>

      <tr>
        <td><code>notice</code> </td>

        <td>Condici&#243;n normal, pero significativa.</td>

        <td>"httpd: interceptada se&#241;al SIGBUS, intentando hacer
        un volcado de memoria en ..."</td>
      </tr>

      <tr>
        <td><code>info</code> </td>

        <td>Informaci&#243;n.</td>

        <td>"El servidor parece estar ocupado, (puede que necesite incrementar
        StartServers, o Min/MaxSpareServers)..."</td>
      </tr>

      <tr>
        <td><code>debug</code> </td>

        <td>Mensajes de nivel debug</td>

        <td>"Abriendo el fichero de configuraci&#243;n ..."</td>
      </tr>
    </table>

    <p>Cuando se especifica un determinado nivel, se escriben en el
    log tambi&#233;n los mensajes de todos los dem&#225;s niveles por
    encima.  Por ejemplo, cuando se especifica <code>LogLevel
    info</code>, tambi&#233;n se escribir&#225;n en el log los
    mensajes de los niveles <code>notice</code> y
    <code>warn</code>.</p>

    <p>Se recomienda usar, al menos, el nivel <code>crit</code>.</p>

    <p>Por ejemplo:</p>

    <example>
      LogLevel notice
    </example>

    <note><title>Nota</title> <p>Cuando el fichero log es un fichero
      normal y se escriben en el mensajes de nivel
      <code>notice</code>, estos mensajes no podr&#225;n ser
      borrados. Sin embargo, esto no se aplica cuando se usa
      <code>syslog</code>.</p>
    </note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>MaxKeepAliveRequests</name>
<description>N&#250;mero de peticiones permitidas en una conexi&#243;n
persistente</description>
<syntax>MaxKeepAliveRequests <var>number</var></syntax>
<default>MaxKeepAliveRequests 100</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive>MaxKeepAliveRequests</directive> limita
    el n&#250;mero de peticiones permitidas por conexi&#243;n cuando
    <directive module="core" >KeepAlive</directive> est&#225;
    activado. Si se especifica el valor <code>0</code>, el n&#250;mero
    de peticiones permitidas es ilimitado. Se recomienda que en esta
    directiva se especifique un valor alto para obtener el m&#225;ximo
    rendimiento del servidor.</p>

    <p>Por ejemplo:</p>

    <example>
      MaxKeepAliveRequests 500
    </example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>NameVirtualHost</name>
<description>Designa una direcci&#243;n IP para usar hosting virtual basado en nombres</description>
<syntax>NameVirtualHost <var>addr</var>[:<var>port</var>]</syntax>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>Es necesario usar la directiva
    <directive>NameVirtualHost</directive> es necesario usarla si
    quiere configurar <a href="../vhosts/">hosts virtuales basados en
    nombres</a>.</p>

    <p>Aunque <var>addr</var> puede ser un nombre de host, se
    recomienda que use siempre una direcci&#243;n IP, por ejemplo:</p>

    <example>
      NameVirtualHost 111.22.33.44
    </example>

    <p>Con la directiva <directive>NameVirtualHost</directive> se
    especifica la direcci&#243;n IP en la cual el servidor
    recibir&#225; las peticiones para los hosts virtuales basados en
    nombres. &#66;sta ser&#225; normalmente la direcci&#243;n a la cual su
    host virtual basado en nombres se resuelve. En los casos en que en
    las peticiones las recibe un firewall (cortafuegos) o un proxy y
    las redirige a una direcci&#243;n IP diferente del servidor, debe
    especificar la direcci&#243;n IP del adaptador de red f&#237;sico
    de la m&#225;quina que servir&#225; las peticiones. Si tiene
    m&#250;ltiples hosts basados en nombres o m&#250;ltiples
    direcciones, repita la directiva para cada direcci&#243;n.</p>

    <note><title>Nota</title>
       <p>Tenga en cuenta, que el "servidor principal" y cualquier
      servidor <code>_default_</code> <strong>nunca</strong>
      servir&#225;n una petici&#243;n a un direcci&#243;n IP
      <directive>NameVirtualHost</directive> (a menos que por alguna
      raz&#243;n use <directive>NameVirtualHost</directive> pero no
      especifique ning&#250;n <directive>VirtualHost</directive> para
      esa direcci&#243;n).</p>
    </note>

    <p>De manera opcional puede especificar un n&#250;mero de puerto en
    el que debe usarse el host virtual basado en el nombre, por
    ejemplo</p>

    <example>
      NameVirtualHost 111.22.33.44:8080
    </example>

    <p>Las direcciones IPv6 deben escribirse entre corchetes, como se
    muestra en el siguiente ejemplo:</p>

    <example>
      NameVirtualHost [2001:db8::a00:20ff:fea7:ccea]:8080
    </example>

    <p>Para recibir peticiones en todas las interfaces de red, puede
    usar <code>*</code> como argumento</p>

    <example>
      NameVirtualHost *
    </example>

    <note><title>Argumento de la directiva <directive  type="section">VirtualHost</directive></title>
      <p>Tenga en cuenta que el argumento de la directiva <directive
       type="section">VirtualHost</directive> debe coincidir
       exactamente con el de la directiva <directive
       >NameVirtualHost</directive>.</p>

      <example>
        NameVirtualHost 1.2.3.4<br />
        &lt;VirtualHost 1.2.3.4&gt;<br />
        # ...<br />
        &lt;/VirtualHost&gt;<br />
      </example>
    </note>
</usage>

<seealso><a href="../vhosts/">Documentaci&#243;n sobre hosting
virtual</a></seealso>

</directivesynopsis>

<directivesynopsis>
<name>Options</name>
<description>Configura las funcionalidades disponibles en un directorio en particular</description>
<syntax>Options
    [+|-]<var>option</var> [[+|-]<var>option</var>] ...</syntax>
<default>Options All</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>Options</override>

<usage>
    <p>La directiva <directive>Options</directive> controla qu&#233;
    funcionalidades del servidor est&#225;n disponibles en un
    directorio en particular.</p>

    <p>En <var>option</var> puede especificar <code>None</code>, en
    cuyo caso ninguna funcionalidad adicional estar&#225; activada, o
    puede especificar una o m&#225;s de las siguientes opciones:</p>

    <dl>
      <dt><code>All</code></dt>

      <dd>Todas las opciones excepto <code>MultiViews</code>. Este es
      el valor por defecto.</dd>

      <dt><code>ExecCGI</code></dt>

      <dd>Se permite la ejecuci&#243;n de scripts CGI usando
      <module>mod_cgi</module>.</dd>

      <dt><code>FollowSymLinks</code></dt>

      <dd>

      El servidor seguir&#225; los enlaces simb&#243;licos en este
      directorio
      <note>
      <p>Aunque el servidor siga los enlaces simb&#243;licos, eso
      <em>no</em> cambia la ruta usada para encontrar equivalencias en
      las secciones <directive type="section"
      module="core">Directory</directive>.</p> <p>Tenga en cuenta
      tambi&#233;n que esta opci&#243;n <strong>es ignorada</strong> si est&#225;
      dentro de una secci&#243;n <directive type="section"
      module="core">Location</directive>.</p> </note></dd>

      <dt><code>Includes</code></dt>

      <dd>
      Permite el uso de Server-side includes, del m&#243;dulo <module>mod_include</module>.</dd>

      <dt><code>IncludesNOEXEC</code></dt>

      <dd>

      Permite el uso de Server-side includes, pero <code>#exec cmd</code>
      y <code>#exec cgi</code> son desactivados. Aunque es posible
      <code>#include virtual</code> (incluir de forma virtual) scripts
      CGI desde directorios especificados con <directive
      module="mod_alias">ScriptAlias</directive>.</dd>

      <dt><code>Indexes</code></dt>

      <dd>
      Si se produce una petici&#243;n a una URL que se corresponde con un directorio,
      y no hay <directive module="mod_dir">DirectoryIndex</directive>
      (por ejemplo, <code>index.html</code>) en ese directorio,
      entonces <module>mod_autoindex</module> devolver&#225; una lista con
      los contenidos del directorio.</dd>

      <dt><code>MultiViews</code></dt>

      <dd>
      Se permiten "MultiViews" de <a
      href="../content-negotiation.html">contenido negociado</a>
      "MultiViews" usando <module>mod_negotiation</module>.</dd>

      <dt><code>SymLinksIfOwnerMatch</code></dt>

      <dd>El servidor seguir&#225; los enlaces simb&#243;licos en los que el
      fichero o directorio final pertenezca al mismo usuario que el
      enlace.

      <note><title>Nota</title> Esta opci&#243;n es ignorada si se pone
      dentro de una secci&#243;n <directive module="core"
      type="section">Location</directive>.</note>
      </dd>
    </dl>

    <p>Normalmente, si se pueden aplicar m&#250;ltiples
    <directive>Options</directive> a un directorio, entonces la
    m&#225;s espec&#237;fica se aplica y las dem&#225;s se ignoran;
    las opciones no se fusionan. (Consulte <a
    href="../sections.html#mergin">c&#243;mo se fusionan las
    secciones</a>.)  Sin embargo, si <em>todas</em> las opciones en la
    directiva <directive>Options</directive> van precedidas de un
    s&#237;mbolo <code>+</code> o <code>-</code>, las opciones se
    fusionan. Cualquier opci&#243;n precedida de un <code>+</code> se
    a&#241;ade a las opciones en ese momento activas, y las opciones
    precedidas de un <code>-</code> se quitan de las activas en ese
    momento. </p>

    <p>Por ejemplo, sin ning&#250;n s&#237;mbolo <code>+</code> o
    <code>-</code>:</p>

    <example>
      &lt;Directory /web/docs&gt;<br />
      <indent>
        Options Indexes FollowSymLinks<br />
      </indent>
      &lt;/Directory&gt;<br />
      <br />
      &lt;Directory /web/docs/spec&gt;<br />
      <indent>
        Options Includes<br />
      </indent>
      &lt;/Directory&gt;
    </example>

    <p>entoces solo <code>Includes</code> tendr&#225; efecto para el
    directorio <code>/web/docs/spec</code>. Sin embargo, si la segunda
    directiva <directive>Options</directive> usara un s&#237;mbolo
    <code>+</code> y otro <code>-</code>:</p>

    <example>
      &lt;Directory /web/docs&gt;<br />
      <indent>
        Options Indexes FollowSymLinks<br />
      </indent>
      &lt;/Directory&gt;<br />
      <br />
      &lt;Directory /web/docs/spec&gt;<br />
      <indent>
        Options +Includes -Indexes<br />
      </indent>
      &lt;/Directory&gt;
    </example>

    <p>entonces las opciones <code>FollowSymLinks</code> e
    <code>Includes</code> estar&#225;n activas para el directorio
    <code>/web/docs/spec</code>.</p>


    <note><title>Nota</title>
      <p>El uso de <code>-IncludesNOEXEC</code> o <code>-Includes</code>
      desactiva server-side includes completamente independientemente
      de la configuraci&#243;n anterior.</p>
    </note>

    <p>El comportamiento por defecto en ausencia de ninguna
    configuraci&#243;n es <code>All</code>.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>Require</name>
<description>Selecciona qu&#233; usuarios autentificados pueden acceder a
un recurso</description>
<syntax>Require <var>entity-name</var> [<var>entity-name</var>] ...</syntax>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>Esta directiva selecciona qu&#233; usuarios autentificados pueden
    acceder a un recurso. La sintaxis a usar es:</p>

    <dl>
      <dt><code>Require user <var>userid</var> [<var>userid</var>]
      ...</code></dt>
      <dd>Solo los usuarios mencionados pueden acceder al
      recurso.</dd>

      <dt><code>Require group <var>group-name</var> [<var>group-name</var>]
      ...</code></dt>
      <dd>Solo los usuarios pertenecientes a los grupos mencionados
      pueden acceder al recurso.</dd>

      <dt><code>Require valid-user</code></dt>
      <dd>Todos los usarios pueden acceder al recurso.</dd>
    </dl>

    <p><directive>Require</directive> debe ser usada de forma conjunta
    con las directivas <directive module="core">AuthName</directive>,
    <directive module="core">AuthType</directive>, y con directivas
    como <directive module="mod_auth">AuthUserFile</directive> y
    <directive module="mod_auth">AuthGroupFile</directive> (para
    definir usuarios y grupos) para funcionar
    correctamente. Ejemplo:</p>

    <example>
       AuthType Basic<br />
       AuthName "Restricted Resource"<br />
       AuthUserFile /web/users<br />
       AuthGroupFile /web/groups<br />
       Require group admin
    </example>

    <p>Los controles de acceso que se aplican de esta manera son
    efectivos para <strong>todos</strong> los
    m&#233;todos. <strong>Esto es lo que normalmente se
    quiere.</strong> Si quiere aplicar controles de acceso solo a
    m&#233;todos espec&#237;ficos, mientras se dejan otros
    m&#233;todos sin protecci&#243;n, use la directiva
    <directive>Require</directive> en una secci&#243;n <directive
    module="core" type="section">Limit</directive>.</p>
</usage>
<seealso><directive module="core">Satisfy</directive></seealso>
<seealso><module>mod_access</module></seealso>
</directivesynopsis>

<directivesynopsis>
<name>RLimitCPU</name>
<description>Limita el consumo de tiempo de CPU que pueden hacer proceses creados
por procesos hijo de Apache</description>
<syntax>RLimitCPU <var>seconds</var>|max [<var>seconds</var>|max]</syntax>
<default>Unset; usa el valor por defecto del sistema operativo</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>Todas</override>

<usage>
    <p>Toma 1 &#243; 2 par&#225;metros. El primer par&#225;metro
    se refiere al l&#237;mite flexible de recursos para todos los
    procesos y el segundo par&#225;metro especifica el l&#237;mite
    m&#225;ximo de recursos. Cada uno de los par&#225;metros puede ser
    un n&#250;mero, &#243; <code>max</code> para indicarle al servidor que
    el l&#237;mite debe fijarse al m&#225;ximo permitido por la
    configuraci&#243;n del sistema operativo. Para elevar el
    l&#237;mite m&#225;ximo de recursos es necesario que se est&#233;
    ejecutando el servidor como ususario <code>root</code>, o estar en
    la fase inicial del arranque.</p>

    <p>Esto se aplica a procesos nacidos de procesos hijo de Apache
    que est&#225;n sirviendo peticiones, no a los procesos hijo de
    Apache propiamente dichos. Esto incluye a los scripts CGI y a los
    comandos de ejecuci&#243;n SSI, pero no a procesos nacidos del
    proceso padre Apache tales como ficheros de registro
    redireccionados (piped logs).</p>

    <p>Los l&#237;mites de consumo de tiempo de la CPU se expresan en
    segundos por proceso.</p>
</usage>
<seealso><directive module="core">RLimitMEM</directive></seealso>
<seealso><directive module="core">RLimitNPROC</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>RLimitMEM</name>
<description>Limita el consumo de memoria que pueden hacer procesos creados por procesos hijo de Apache</description>
<syntax>RLimitMEM <var>bytes</var>|max [<var>bytes</var>|max]</syntax>
<default>Unset; usa el valor por defecto del sistema operativo</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>Todas</override>

<usage>
    <p>Toma 1 &#243; 2 par&#225;metros. El primer par&#225;metro
    especifica el l&#237;mite flexible de recursos para todos los
    procesos y el segundo par&#225;metro especifica el l&#237;mite
    m&#225;ximo de recursos. Cada uno de los par&#225;metros puede ser
    un n&#250;mero, &#243; <code>max</code> para indicarle al servidor que
    el l&#237;mite debe fijarse al m&#225;ximo permitido por la
    configuraci&#243;n del sistema operativo. Para elevar el
    l&#237;mite m&#225;ximo de recursos es necesario que se est&#233;
    ejecutando el servidor como ususario <code>root</code>, o estar en
    la fase inicial del arranque.</p>

    <p>Esto se aplica a procesos nacidos de procesos hijo de Apache
    que est&#225;n sirviendo peticiones, no a los procesos hijo de
    Apache propiamente dichos. Esto incluye a los scripts CGI y a los
    comandos de ejecuci&#243;n SSI, pero no a procesos nacidos del
    proceso padre Apache tales como ficheros de registro
    redireccionados (piped logs).</p>

    <p>Los l&#237;mites de consumo de memoria se expresan en bytes por
    proceso.</p>
</usage>
<seealso><directive module="core">RLimitCPU</directive></seealso>
<seealso><directive module="core">RLimitNPROC</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>RLimitNPROC</name>
<description>Limita el n&#250;mero de procesos que pueden crearse por parte de 
procesos creados por procesos hijo de Apache</description>
<syntax>RLimitNPROC <var>number</var>|max [<var>number</var>|max]</syntax>
<default>Unset; usa el valor por defecto del sistema operativo</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>Todas</override>

<usage>
    <p>Toma 1 &#243; 2 par&#225;metros. El primer par&#225;metro
    especifica el l&#237;mite flexible de recursos para todos los
    procesos y el segundo par&#225;metro especifica el l&#237;mite
    m&#225;ximo de recursos. Cada uno de los par&#225;metros puede ser
    un n&#250;mero, &#243; <code>max</code> para indicarle al servidor que
    el l&#237;mite debe fijarse al m&#225;ximo permitido por la
    configuraci&#243;n del sistema operativo. Para elevar el
    l&#237;mite m&#225;ximo de recursos es necesario que se est&#233;
    ejecutando el servidor como usuario <code>root</code>, o estar en
    la fase inicial del arranque.</p>

    <p>Esto se aplica a procesos nacidos de la divisi&#243;n de
    procesos hijo de Apache que est&#225;n sirviendo peticiones, no a
    los procesos hijo de Apache propiamente dichos. Esto incluye a los
    scripts CGI y a los comandos de ejecuci&#243;n SSI, pero no a procesos
    nacidos de la divisi&#243;n del proceso padre Apache tales como
    ficheros de registro
    redireccionados (piped logs).</p>

    <p>Limita el n&#250;mero de procesos por usuario.</p>

    <note><title>Nota</title> <p>Si los procesos CGI
      <strong>no</strong> est&#225;n siendo ejecutados por
      identificadores de usuario diferentes del identificador de
      usuario que est&#225; ejecutando el servidor web, esta directiva
      limitar&#225; el n&#250;mero de procesos que el servidor puede
      crear. Como resultado de esta situaci&#243;n, en el
      <code>error_log</code> aparecer&#225;n mensajes del tipo
      <strong><code>cannot fork</code></strong>.</p>
    </note>
</usage>
<seealso><directive module="core">RLimitMEM</directive></seealso>
<seealso><directive module="core">RLimitCPU</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>Satisfy</name>
<description>Interacci&#243;n entre el control de acceso basado en host
y la autentificaci&#243;n de usuarios</description>
<syntax>Satisfy Any|All</syntax>
<default>Satisfy All</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>
<compatibility>Influenciada por <directive module="core"
type="section">Limit</directive> y <directive module="core"
type="section">LimitExcept</directive> en las versiones de Apache 2.0.51 y
posteriores</compatibility>

<usage>
    <p>Especifica la pol&#237;tica de acceso a seguir cuando se usan tanto
    <directive module="mod_access">Allow</directive> como <directive
    module="core">Require</directive>. El par&#225;metro puede ser
    <code>All</code> o <code>Any</code>. Esta directiva es solo &#250;til
    si se va restringir el acceso a un &#225;rea concreta con un nombre de
    usuario/contrase&#241;a <em>y</em> direcci&#243;n del cliente. En este caso
    el comportamiento por defecto (<code>All</code>) es para requerir
    que el cliente pase la restricci&#243;n referente a la direcci&#243;n
    <em>e</em> introduzca un nombre de usuario y contrase&#241;a
    v&#225;lidos. Con la opci&#243;n <code>Any</code> el cliente podr&#225; acceder
    si cumple la restricci&#243;n referente a la direcci&#243;n o si introduce un
    nombre de usuario y contrase&#241;as v&#225;lidos. Esto puede usarse para
    restringir el acceso a una zona con una contrase&#241;a, pero permitir
    a los clientes de algunas direcciones en concreto que accedan sin
    tener que introducir contrase&#241;a alguna.</p>

    <p>Por ejemplo, si quiere permitir que todo el mundo tenga acceso
    total a su intranet o a una parte de si sitio web, pero requerir que
    los visitantes de fuera de su intranet introduzcan una
    contrase&#241;a, puede usar una configuraci&#243;n similar a la
    siguiente:</p>

    <example>
      Require valid-user<br />
      Allow from 192.168.1<br />
      Satisfy Any
    </example>

    <p>A partir de la versi&#243;n de Apache 2.0.51, puede limitarse
    la aplicaci&#243;n de las directivas
    <directive>Satisfy</directive> a determinados m&#243;todos en
    particular mediante secciones <directive module="core"
    type="section">Limit</directive> y <directive module="core"
    type="section" >LimitExcept</directive>.</p>


</usage>
   <seealso><directive module="mod_access">Allow</directive></seealso>
   <seealso><directive module="core">Require</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>ScriptInterpreterSource</name>
<description>T&#233;cnica para ubicar el int&#233;rprete de scripts CGI's</description>
<syntax>ScriptInterpreterSource Registry|Registry-Strict|Script</syntax>
<default>ScriptInterpreterSource Script</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>FileInfo</override>
<compatibility>Solo sistemas Windows; la opci&#243;
<code>Registry-Strict</code> est&#225; disponible en las versiones de
Apache 2.0 y posteriores</compatibility>

<usage>
    <p>Esta directiva se usa para controlar la manera que Apache
    encuentra el int&#233;rprete usado para ejecutar scripts CGI. La
    configuraci&#243;n por defecto es <code>Script</code>. Esto hace que
    Apache use el int&#233;rprete que aparece en la primera l&#237;nea, la que
    empieza por <code>#!</code>) en el script. En los sistemas Win32
    esta l&#237;nea tiene un aspecto similar a:</p>

    <example>
      #!C:/Perl/bin/perl.exe
    </example>

    <p>o, si <code>perl</code> est&#225; en el <code>PATH</code>,
    simplemente:</p>

    <example>
      #!perl
    </example>

    <p>Usar <code>ScriptInterpreterSource Registry</code> har&#225;
    que se busque en el Registro de Windows, en
    <code>HKEY_CLASSES_ROOT</code> con la extensi&#243;n del fichero
    de script (por ejemplo, <code>.pl</code>) como clave de
    b&#250;squeda. El comando definido por la subclave del registro de
    Windows <code>Shell\ExecCGI\Command</code> o, si esta no existe,
    por la subclave <code>Shell\Open\Command</code> se usa para abrir
    el script. Si no se encuentra ning&#250;n resutlado, Apache
    recurre al comportamiento de la opci&#243;n
    <code>Script</code>.</p>

    <note type="warning"><title>Seguridad</title> <p>Tenga cuidado
    cuando use <code>ScriptInterpreterSource Registry</code> con
    <directive module="mod_alias">ScriptAlias</directive> para
    directorios, porque Apache intentar&#225; ejecutar
    <strong>cada</strong> fichero dentro de ese directorio. Lo
    especificado en <code>Registry</code> puede causar llamadas
    indeseadas a programas que normalmente no se ejecutan. Por
    ejemplo, el programa por defecto para abrir ficheros
    <code>.htm</code> en la mayor&#237;a de los sistemas Windows es
    Microsoft Internet Explorer, entonces cualquier petici&#243;n HTTP
    de un fichero <code>.htm</code> que exista dentro del script del
    directorio har&#225; que el ejecute de fondo el navegador en el
    servidor. Con esto el servidor se bloquear&#225; en m&#225;s o
    menos un minuto.</p>
    </note>

    <p>La opci&#243;n <code>Registry-Strict</code> que es nueva en
    Apache 2.0 hace lo mismo que <code>Registry</code> pero usa solo
    la subclave <code>Shell\ExecCGI\Command</code>. La clave
    <code>ExecCGI</code> no es de uso com&#250;n. Debe ser configurada
    manualmente en el registro de Windows y por tanto previene la
    ejecuci&#243;n accidental de procesos en su sistema.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ServerAdmin</name>
<description>Direcci&#243;n de email que el servidor incluye en los
mensajes de error que se env&#237;an al cliente</description>
<syntax>ServerAdmin <var>email-address</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p><directive>ServerAdmin</directive> especifica la direcci&#243;n de
    e-mail que el servidor incluye en cualquier mensaje de error que
    env&#237;a al cliente.</p>

    <p>Ser&#237;a conveniente tener una direcci&#243;n de email solo para esto, por ejemplo</p>

    <example>
      ServerAdmin www-admin@foo.example.com
    </example>
    <p>ya que los usuarios no siempre mencionan que est&#225;n hablando
    del servidor!</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ServerAlias</name>
<description>Nombres alternativos usados para un host cuando se
intentan encontrar equivalencias a hosts virtuales basados en el
nombre</description>
<syntax>ServerAlias <var>hostname</var> [<var>hostname</var>] ...</syntax>
<contextlist><context>virtual host</context></contextlist>

<usage>
    <p><directive>ServerAlias</directive> especifica los nombres
    alternativos para un host, para usarlo con <a
    href="../vhosts/name-based.html">hosts virtuales basados en el
    nombre</a>.</p>

    <example>
      &lt;VirtualHost *&gt;<br />
      ServerName example.com<br />
      ServerAlias example.com server2<br />
      # ...<br />
      &lt;/VirtualHost&gt;
    </example>
</usage>
<seealso><a href="../vhosts/">Documentaci&#243;n sobre hosting virtual con
Apache</a></seealso>
</directivesynopsis>

<directivesynopsis>
<name>ServerName</name>
<description>Nombre de host y n&#250;mero de puerto que el servidor usa
para identificarse</description>
<syntax>ServerName <var>fully-qualified-domain-name</var>[:<var>port</var>]</syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>
<compatibility>En la versi&#243;n 2.0, esta directiva sustituye la
     funcionalidad de la direciva <directive>Port</directive> de la
     versi&#243;n 1.3.</compatibility>

<usage>
    <p>La directiva <directive>ServerName</directive> especifica el
    nombre de host y el puerto que usa el servidor para
    identificarse. Esto se usa cuando se hace redirecci&#243;n de URLs. Por
    ejemplo, si el nombre de la maquina del servidor web es
    <code>simple.example.com</code>, pero el la maquina tambi&#233;n tiene
    el alias DNS <code>www.example.com</code> y quiere que el servidor
    web se identifique as&#237;, debe usar la siguiente directiva:</p>

    <example>
      ServerName www.example.com:80
    </example>

    <p>Si no especifa <directive>ServerName</directive>, entonces el
    servidor intentar&#225; deducir en nombre de host haciendo una
    busqueda reversa en la direcci&#243;n IP. Si no se especifica
    ning&#250;n puerto en <directive>ServerName</directive>, entonces
    el servidor usar&#225; el puerto para las peticiones
    entrantes. Para disfrutar de la m&#225;xima fiabilidad y
    predictibilidad, debe especificar explicitamente un nombre de host
    y un puerto usando la directiva
    <directive>ServerName</directive>.</p>

    <p>Si est&#225; usando <a href="../vhosts/name-based.html">hosts
    virtuales basados en el nombre</a>, la directiva
    <directive>ServerName</directive> dentro de una secci&#243;n <directive
    type="section" module="core">VirtualHost</directive> especifica
    qu&#233; nombre de host debe aparecer en la cabecera de petici&#243;n
    <code>Host:</code> para coincidir con ese host virtual.</p>

    <p>Consulte la descripci&#243;n de la directiva <directive
    module="core">UseCanonicalName</directive> para configuraciones
    que determinan si URLs autoreferenciadas (por ejemplo, por el
    m&#243;dulo <module>mod_dir</module> module) se referir&#225;n al puerto
    especificado, o al n&#250;mero de puerto dado en la petici&#243;n del
    cliente.
    </p>
</usage>

<seealso><a href="../dns-caveats.html">Problemas relacionados en DNS y
Apache</a></seealso>
<seealso><a href="../vhosts/">Documentaci&#243;n sobre hosting
virtual</a></seealso>
<seealso><directive module="core">UseCanonicalName</directive></seealso>
<seealso><directive module="core">NameVirtualHost</directive></seealso>
<seealso><directive module="core">ServerAlias</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>ServerPath</name>
<description>URL que se usar&#225; para hosts virtuales basados en
nombre que son accedidos con un navegador incompatible</description>
<syntax>ServerPath <var>URL-path</var></syntax>
<contextlist><context>virtual host</context></contextlist>

<usage>
    <p>The <directive>ServerPath</directive> directive sets the legacy
    URL pathname for a host, for use with <a
    href="../vhosts/">name-based virtual hosts</a>.</p>
</usage>
<seealso><a href="../vhosts/">Documentaci&#243;n sobre hosting virtual</a></seealso>
</directivesynopsis>

<directivesynopsis>
<name>ServerRoot</name>
<description>Directorio base de la instalaci&#243;n del servidor</description>
<syntax>ServerRoot <var>directory-path</var></syntax>
<default>ServerRoot /usr/local/apache</default>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>La directiva <directive>ServerRoot</directive> especifica el
    directorio en el que ha sido instalado el servidor. Normalmente
    contendr&#225; los subdirectorios <code>conf/</code> y
    <code>logs/</code>. Las rutas que se especifican en otras
    directivas (por ejemplo en <directive
    module="core">Include</directive> o <directive
    module="mod_so">LoadModule</directive>) se toman como relativas a
    este directorio.</p>

    <example><title>Example</title>
      ServerRoot /home/httpd
    </example>

</usage>
<seealso><a href="../invoking.html">la opci&#243;n <code>-d</code> de
    <code>httpd</code></a></seealso> <seealso><a
    href="../misc/security_tips.html#serverroot">consejos se
    seguridad</a> para m&#225;s informaci&#243;n de como establecer
    adecuadamente los permisos en
    <directive>ServerRoot</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>ServerSignature</name>
<description>Configura el pie de p&#225;gina en documentos generados
por el servidor</description>
<syntax>ServerSignature On|Off|EMail</syntax>
<default>ServerSignature Off</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>All</override>

<usage>
    <p>La directiva <directive>ServerSignature</directive> permite la
    configuraci&#243;n de un pie de p&#225;gina que se
    a&#241;adir&#225; a documentos generados por el sevidor (mensajes
    de error, listado de directorios generados por
    <module>mod_proxy</module>, salida de
    <module>mod_info</module>...). La raz&#243;n por la que puede no
    querer a&#241;adir este pie de p&#225;gina, es que en una cadena
    de proxies, el usuario a menudo no tiene posibilidad de establecer
    cual de los servidores encadenados ha retornado un mensaje de
    error.</p>

    <p>Esta directiva usa por defecto el valor <code>Off</code>, que
    suprime la generaci&#243;n del pie de p&#225;gina (y por tanto, es
    compatible con el comportamiento de Apache 1.2 y las versiones
    anteriores). Si usa el valor <code>On</code> simplemte se
    a&#241;ade una l&#237;nea con el n&#250;mero de versi&#243;n y el
    valor de <directive module="core">ServerName</directive> para el
    host virtual que est&#225; respondiendo la petici&#243;n, y el
    valor <code>EMail</code> crea las referencias adicionales
    "mailto:" a lo especificado en la directiva <directive
    module="core">ServerAdmin</directive>.</p>

    <p>En las versiones 2.0.44 y posteriores, los detalles del n&#250;mero
    de la versi&#243;n del servidor son controlados por la directiva
    <directive module="core">ServerTokens</directive>.</p>
</usage>
<seealso><directive module="core">ServerTokens</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>ServerTokens</name>
<description>Configura la cabecera de respuesta HTTP
<code>Server</code></description>
<syntax>ServerTokens Major|Minor|Min[imal]|Prod[uctOnly]|OS|Full</syntax>
<default>ServerTokens Full</default>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>Esta directiva controla si el campo <code>Server</code> de las
    cabeceras de las respuestas que se env&#237;an de vuelta a los clientes
    incluye una descripci&#243;n del sistema operativo gen&#233;rico del
    servidor as&#237; como informaci&#243;n sobre los modulos compilados en el
    servidor.</p>

    <dl>
      <dt><code>ServerTokens Prod[uctOnly]</code></dt>

      <dd>El servidor env&#237;a (por ejemplo): <code>Server:
      Apache</code></dd>

      <dt><code>ServerTokens Major</code></dt>

      <dd>El servidor env&#237;a (por ejemplo): <code>Server:
      Apache/2</code></dd>

      <dt><code>ServerTokens Minor</code></dt>

      <dd>El servidor env&#237;a (por ejemplo): <code>Server:
      Apache/2.0</code></dd>

      <dt><code>ServerTokens Min[imal]</code></dt>

      <dd>El servidor env&#237;a (por ejemplo): <code>Server:
      Apache/2.0.41</code></dd>

      <dt><code>ServerTokens OS</code></dt>

      <dd>El servidor env&#237;a (por ejemplo): <code>Server: Apache/2.0.41
      (Unix)</code></dd>

      <dt><code>ServerTokens Full</code> (or not specified)</dt>

      <dd>El servidor env&#237;a (por ejemplo): <code>Server: Apache/2.0.41
      (Unix) PHP/4.2.2 MyMod/1.2</code></dd>
    </dl>

    <p>Esta configuraci&#243;n se aplica al servidor entero, y no puede ser
    activada o desactivada para unos hosts virtuales s&#237; y para otros
    no.</p>

    <p>En las versiones posteriores a la 2.0.44, esta directiva
    tambi&#233;n controla la informaci&#243;n especificada en la directiva
    <directive module="core">ServerSignature</directive>.</p>
</usage>
<seealso><directive module="core">ServerSignature</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>SetHandler</name>
<description>Hace que todos los ficheros que correspondan con el valor
especificado sean procesados obligatoriamente por un
handler</description>
<syntax>SetHandler <var>handler-name</var>|None</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>FileInfo</override>
<compatibility>Trasladado al n&#250;cleo del servidor en Apache
2.0</compatibility>

<usage>
    <p>Cuando se usa en un fichero <code>.htaccess</code> o en una
    secci&#243;n <directive type="section"
    module="core">Directory</directive> r <directive type="section"
    module="core">Location</directive>, esta directiva hace que todos
    los ficheros cuyo nombre tenga equivalencia con el valor que
    especifica sean tratados por el <a
    href="../handler.html">handler</a> dado en
    <var>handler-name</var>. Por ejemplo, si tiene un directorio cuyo
    contenido quiere que sea tratado como as fichero de reglas de
    mapas de im&#225;genes, independientemente de las extensiones,
    puede poner lo siguiente en un fichero <code>.htaccess</code> en
    ese directorio:</p>

    <example>
      SetHandler imap-file
    </example>

    <p>Otro ejemplo: si quiere que el servidor despliegue un resumen
    de su estado cuando se llame a una URL de
    <code>http://servername/status</code>, puede poner lo siguiente en
    el fichero <code>httpd.conf</code>:</p>

    <example>
      &lt;Location /status&gt;<br />
      <indent>
        SetHandler server-status<br />
      </indent>
      &lt;/Location&gt;
    </example>

    <p>Puede evitar que se aplique lo especificado anteriormente en
    una directiva <directive>SetHandler</directive> usando el valor
    <code>None</code>.</p>
</usage>

<seealso><directive module="mod_mime">AddHandler</directive></seealso>

</directivesynopsis>

<directivesynopsis>
<name>SetInputFilter</name>
<description>Especifica los filtros que procesar&#225;n las peticiones de
los clientes y el contenido de peticiones POST</description>
<syntax>SetInputFilter <var>filter</var>[;<var>filter</var>...]</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>FileInfo</override>

<usage>
    <p>La directiva <directive>SetInputFilter</directive> espcifica el
    filtro o filtros que procesar&#225;n las peticiones de los
    clientes y el contenido de peticiones POST cuando son recibidas
    por el servidor. El filtro o filtros especificados en esta
    directiva se aplican adem&#225;s de los definidos en otras partes,
    incluyendo los especificados en la directiva <directive
    module="mod_mime">AddInputFilter</directive>.</p>

    <p>Si se especifica m&#225;s de un filtro, deben separarse con puntos y
    comas en el orden en que deban procesar los contenidos.</p>
</usage>
<seealso>Documentaci&#243;n sobre <a href="../filter.html">Filtros</a></seealso>
</directivesynopsis>

<directivesynopsis>
<name>SetOutputFilter</name>
<description>Especifica los filtros que procesar&#225;n las respuestas del
servidor</description>
<syntax>SetOutputFilter <var>filter</var>[;<var>filter</var>...]</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>FileInfo</override>

<usage>
    <p>La directiva <directive>SetOutputFilter</directive> especifica
    los filtros se usar&#225;n para procesar las respuestas del servidor
    antes de enviarlas al cliente. Esto es adem&#225;s de los filtros
    definidos en otras partes, incluidos los de la directiva
    <directive module="mod_mime">AddOutputFilter</directive>.</p>

    <p>Por ejemplo, la siguiente configuraci&#243;n procesar&#225; todos los
    archivos en el directorio <code>/www/data/</code> con server-side
    includes.</p>

    <example>
      &lt;Directory /www/data/&gt;<br />
      <indent>
        SetOutputFilter INCLUDES<br />
      </indent>
      &lt;/Directory&gt;
    </example>

    <p>Si se especifica m&#225;s de un filtro, deben separarse con puntos y
    comas en el orden en que deban procesar los contenidos.</p>
</usage>
<seealso>Documentaci&#243;n sobre <a
href="../filter.html">Filtros</a></seealso>
</directivesynopsis>

<directivesynopsis>
<name>TimeOut</name>
<description>Cantidad de tiempo que el servidor esperar&#225; para que
ocurran determinados eventos antes de cerrar una
petici&#243;n</description>
<syntax>TimeOut <var>seconds</var></syntax>
<default>TimeOut 300</default>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>La directiva <directive>TimeOut</directive> define ahora la
    cantidad de tiempo que Apache esperar&#225; para tres cosas:</p>

    <ol>
      <li>La cantidad de tiempo que tarda en recibir una
      petici&#243;n GET.</li>

      <li>La cantidad de tiempo entre la recepci&#243;n de paquetes TCP
      packets en una petici&#243;n POST o PUT.</li>

      <li>La cantidad de tiempo entre ACKs en transmisiones de
      paquetes TCP en las respuestas.</li>
    </ol>

    <p>Lo planeado es hacer configurable por separado cada una de
    estas cosas. La cantidad de tiempo por defecto de 1200 usada antes
    de la versi&#243;n 1.2, ha sido reducida hasta 300, que es en la mayor
    parte de las situaciones m&#225;s de lo necesario. El tiempo usado por
    defecto no es menor porque puede que haya alguna parte del c&#243;digo
    en que el contador de tiempo no se pone a cero como deber&#237;a cuando
    se env&#237;a un paquete. </p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>UseCanonicalName</name>
<description>Configura la forma en que el servidor determina su propio
nombre u puerto</description>
<syntax>UseCanonicalName On|Off|DNS</syntax>
<default>UseCanonicalName On</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>

<usage>
    <p>En muchas ocasiones, Apache tiene que construir una URL
    <em>autoreferenciada</em> -- esto es, una URL que se refiere de
    vuelta al mismo servidor. Con <code>UseCanonicalName On</code>
    Apache usar&#225; el nombre de host y puerto que est&#233;n especificados en
    la directiva <directive module="core">ServerName</directive> para
    construir el nombre can&#243;nico del servidor. Este nombre se usa en
    todas las URLs autoreferenciadas, y para los valores de
    <code>SERVER_NAME</code> y <code>SERVER_PORT</code> en los
    CGIs.</p>

    <p>Con <code>UseCanonicalName Off</code> Apache formar&#225; las
    URLs autoreferenciadas usando el nombre de host y puerto
    suministrados por el cliente. Si se ha suministrado esa
    informaci&#243;n (si no se ha suministrado, se usar&#225; el
    nombre can&#243;nico, tal y como se ha definido arriba). Estos
    valores son los mismos que se usan para implementar <a
    href="../vhosts/name-based.html">hosting virtual basado en
    nombres</a>, y est&#225;n disponibles con los mismos clientes. Las
    variables de CGI <code>SERVER_NAME</code> y
    <code>SERVER_PORT</code> se construir&#225;n con la
    informaci&#243;n suministrada por los clientes.</p>

    <p>Un ejemplo de donde esto puede ser &#250;til es en un servidor de
    una intranet, donde los usuarios se conectan a la m&#225;quina usando
    nombres cortos como <code>www</code>. Se dar&#225; cuenta de que si los
    usuarios teclean un nombre corto, y una URL que es un directorio,
    tal como <code>http://www/splat</code>, <em>sin una barra al
    final</em> entonces Apache los rediccionar&#225; a
    <code>http://www.domain.com/splat/</code>. Si tiene la
    autenfificaci&#243;n activada, esto har&#225; que el usuario se tenga que
    autentificar dos veces (una para <code>www</code> y otra para
    <code>www.domain.com</code> -- consulte <a
    href="http://httpd.apache.org/docs/misc/FAQ.html#prompted-twice">las
    preguntas m&#225;s frecuentes sobre este asunto para obtener m&#225;s
    informaci&#243;n</a>). Pero si especifica el valor <code>Off</code> en
    la directiva <directive>UseCanonicalName</directive>, entonces
    Apache redireccionar&#225; a <code>http://www/splat/</code>.</p>

    <p>Hay una tercera opci&#243;n, <code>UseCanonicalName DNS</code>, para
    el caso en que se usa hosting virtual masivo basado en IP para
    soportar clientes antiguos que no env&#237;an la cabecera
    <code>Host:</code>. Con esta opci&#243;n Apache hace una busqueda de
    DNS reversa en la direcci&#243;n IP del servidor al que el cliente se
    conect&#243; para hacer funcionar las URLs autoreferenciadas.</p>

    <note type="warning"><title>Advertencia</title>

    <p>Si los CGIs asumen los valores de <code>SERVER_NAME</code>,
    puede que no funcionen con esta opci&#243;n. El cliente es
    esencialmente libre de dar cualquier valor que quiera como nombre
    de host. Pero si el CGI solo usa <code>SERVER_NAME</code> para
    constrir URLs autoreferenciadas, entonces no debe haber ning&#250;n
    problema.</p>
    </note>
</usage>
<seealso><directive module="core">ServerName</directive></seealso>
<seealso><directive module="mpm_common">Listen</directive></seealso>
</directivesynopsis>

<directivesynopsis type="section">
<name>VirtualHost</name>
<description>Contiene las directivas que se aplican solo a un nombre
de host espec&#237;fico o direcci&#243;n IP</description>
<syntax>&lt;VirtualHost
    <var>addr</var>[:<var>port</var>] [<var>addr</var>[:<var>port</var>]]
    ...&gt; ... &lt;/VirtualHost&gt;</syntax>
<contextlist><context>server config</context></contextlist>

<usage>
    <p><directive type="section">VirtualHost</directive> y
    <code>&lt;/VirtualHost&gt;</code> se usan para incluir un grupo de
    directivas que se aplicar&#225;n solo a un host virtual en
    particular. Cualquier directiva que est&#233; permitido usar en un
    contexto virtual host puede usarse. Cuando el servidor recibe una
    petici&#243;n de un documento de un host virtual en concreto, usa las
    directivas de configuraci&#243;n incluidas en la secci&#243;n <directive
    type="section">VirtualHost</directive>. <var>Addr</var> puede
    ser:</p>

    <ul>
      <li>La direcci&#243;n IP del host virtual;</li>

      <li>Un nombre de dominio completo para la direcci&#243;n IP del host
      virtual;</li>

      <li>El car&#225;cter <code>*</code>, el cual puede usarse en
      combinaci&#243;n con <code>NameVirtualHost *</code> para que
      equivalga a todas las direcciones IP; o</li>

      <li>La cadena de caracteres <code>_default_</code>, que se usa
      solo con hosting virtual IP para detectar direcciones IP sin
      emparejar.</li>
    </ul>

    <example><title>Ejemplo</title>
      &lt;VirtualHost 10.1.2.3&gt;<br />
      <indent>
        ServerAdmin webmaster@host.foo.com<br />
        DocumentRoot /www/docs/host.foo.com<br />
        ServerName host.foo.com<br />
        ErrorLog logs/host.foo.com-error_log<br />
        TransferLog logs/host.foo.com-access_log<br />
      </indent>
      &lt;/VirtualHost&gt;
    </example>


    <p>Las direcciones IPv6 deben especificarse entre corchetes porque
    el n&#250;mero de puerto opcional no podr&#237;a determinarse si no se hace
    as&#237;. Un ejemplo de direcci&#243;n IPv6 se mustra aqu&#237; abajo:</p>

    <example>
      &lt;VirtualHost [2001:db8::a00:20ff:fea7:ccea]&gt;<br />
      <indent>
        ServerAdmin webmaster@host.example.com<br />
        DocumentRoot /www/docs/host.example.com<br />
        ServerName host.example.com<br />
        ErrorLog logs/host.example.com-error_log<br />
        TransferLog logs/host.example.com-access_log<br />
      </indent>
      &lt;/VirtualHost&gt;
    </example>

    <p>Cada host virtual se corresponde con una direcci&#243;n IP
    diferente, un n&#250;mero de puerto diferente o un nombre de host
    diferente para el servidor, en el primer caso la m&#225;quina del
    servidor debe estar configurada para aceptar paquetes IP para
    m&#250;ltiples direcciones. (Si la m&#225;quina no tiene m&#250;ltiples infaces
    de red, entonces esto puede conseguirse con el comando
    <code>ifconfig alias</code> -- si su sistema operativo lo
    soporta).</p>

    <note><title>Nota</title> <p>El uso de <directive
    type="section">VirtualHost</directive> <strong>no</strong> afecta
    a las direcciones en las que escucha Apache. Puede que necesite
    asegurarse de que Apache est&#225; escuchando en la direcci&#243;n correcta
    usando <directive module="mpm_common">Listen</directive>.</p>
    </note>

    <p>Cuando se usa hosting virtual basado en IP, puede
    especificarse el nombre especial <code>_default_</code>, en cuyo
    caso, este host virtual equivaldr&#225; a cualquier direcci&#243;n IP que no
    est&#233; especificamente listada en otro host virtual. En ausencia de
    un host virtual <code>_default_</code> el server config
    "principal", consistente en todas las definiciones fuera de una
    secci&#243;n VirtualHost, se usa cuando la IP no coincide con ninguna.
    (Pero tenga en cuenta que cualquier direcci&#243;n IP que equivalga a
    la directiva <directive module="core">NameVirtualHost</directive>
    no usar&#225; ni el server config "principal" ni el host virtual
    <code>_default_</code> virtual host.  Consulte la documentaci&#243;n de
    <a href="../vhosts/name-based.html">hosting virtual basado en
    nombres</a> para obtener m&#225;s informaci&#243;n.)</p>

    <p>Puede especificar <code>:port</code> para cambiar el puerto
    de equivalencia. Si no especifica ninguno, entonces por defecto se
    usa el mismo puerto de la directiva <directive
    module="mpm_common">Listen</directive> mas reciente del servidor
    principal. Tambi&#233;n puede especificar <code>:*</code> para hacer
    coincidir con todos los puertos en esa direcci&#243;n. (Esto se
    recomienda cuando se usa con <code>_default_</code>.)</p>

    <note type="warning"><title>Seguridad</title>
    <p>Consulte la documentaci&#243;n de <a
    href="../misc/security_tips.html">consejos de seguridad</a> para
    obtener m&#225;s informaci&#243;n sobre por qu&#233; pone en riesgo la seguridad
    si en el directorio donde almacena los archivos log tiene permisos
    de escritura alguien que no sea el usuario que inicia el
    servidor.</p>
    </note>
</usage>
<seealso><a href="../vhosts/">Documentaci&#243;n sobre hosting virtual</a></seealso>
<seealso><a href="../dns-caveats.html">Problemas relacionados con DNS y Apache</a></seealso>
<seealso><a href="../bind.html">Especificar las direcciones y puertos que usa Apache</a></seealso>
<seealso><a href="../sections.html">C&#243;mo funcionan las secciones
    &lt;Directory&gt;, &lt;Location&gt; y &lt;Files&gt;</a> si quiere
    una explicaci&#243;n completa de como se combinan esas secciones cuando
    se recibe una petici&#243;n</seealso>
</directivesynopsis>

</modulesynopsis>
