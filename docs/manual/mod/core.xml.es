<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- Translated by Luis Gil de Bernabé Pfeiffer lgilbernabe[AT]apache.org -->
<!-- Reviewed by Sergio Ramos-->
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
<description>Funcionalides básicas del Servidor HTTP Apache que siempre están presentes.</description>
<status>Core</status>

<directivesynopsis>
<name>AcceptFilter</name>
<description>Configura mejoras para un Protocolo de Escucha de Sockets</description>
<syntax>AcceptFilter <var>protocol</var> <var>accept_filter</var></syntax>
<contextlist><context>server config</context></contextlist>


<usage>
    <p>Esta directiva hace posible mejoras específicas a nivel de sistema operativo
       y a través del tipo de Protocolo para un socket que escucha.
       La premisa básica es que el kernel no envíe un socket al servidor
       hasta que o bien los datos se hayan recibido o bien se haya almacenado
       en el buffer una Respuesta HTTP completa.  
       Actualmente sólo están soportados
       <a href="http://www.freebsd.org/cgi/man.cgi?query=accept_filter&amp;sektion=9">
       Accept Filters</a> sobre FreeBSD, <code>TCP_DEFER_ACCEPT</code> sobre Linux, 
       y AcceptEx() sobre Windows.</p>

    <p>El uso de <code>none</code> para un argumento desactiva cualquier filtro 
       aceptado para ese protocolo. Esto es útil para protocolos que requieren que un
       servidor envíe datos primeros, tales como <code>ftp:</code> o <code>nntp</code>:</p>
    <highlight language="config">
AcceptFilter nntp none
    </highlight>

    <p>Los nombres de protocolo por defecto son <code>https</code> para el puerto 443
       y <code>http</code> para todos los demás puertos. Para especificar que se está
       utilizando otro protocolo con un puerto a la escucha, añade el argumento <var>protocol</var>
       a la directiva <directive module="mpm_common">Listen</directive>.</p>

    <p>Los valores por defecto de FreeBDS son:</p>
    <highlight language="config">
AcceptFilter http httpready
AcceptFilter https dataready
    </highlight>
    
    <p>El filtro <code>httpready</code> almacena en el buffer peticiones HTTP completas
       a nivel de kernel.  Una vez que la petición es recibida, el kernel la envía al servidor. 
       Consulta la página man de
       <a href="http://www.freebsd.org/cgi/man.cgi?query=accf_http&amp;sektion=9">
       accf_http(9)</a> para más detalles.  Puesto que las peticiones HTTPS
       están encriptadas, sólo se utiliza el filtro
       <a href="http://www.freebsd.org/cgi/man.cgi?query=accf_data&amp;sektion=9">accf_data(9)</a>.</p>

    <p>Los valores por defecto en Linux son:</p>
    <highlight language="config">
AcceptFilter http data
AcceptFilter https data
    </highlight>

    <p>En Linux, <code>TCP_DEFER_ACCEPT</code> no soporta el buffering en peticiones http.
       Cualquier valor además de <code>none</code> habilitará 
       <code>TCP_DEFER_ACCEPT</code> en ese socket. Para más detalles 
       ver la página man de Linux
       <a href="http://man7.org/linux/man-pages/man7/tcp.7.html">
       tcp(7)</a>.</p>

    <p>Los valores por defecto en Windows son:</p>
    <highlight language="config">
AcceptFilter http connect
AcceptFilter https connect
    </highlight>

    <p>El mpm_winnt de Windows interpreta AcceptFilter para conmutar la
       API AcceptEx(), y no soporta el buffering del protocolo http.
       <code>connect</code> usará la API AcceptEx(), y también
       recuperará las direcciones del extremo de red, pero al igual
       que <code>none</code>, la opción <code>connect</code> no espera
       a la transmisión inicial de los datos.</p>

    <p>Sobre Windows, <code>none</code> usa accept() en lugar de
       AcceptEx() y no reciclará sockets entre conexiones. Esto es útil
       para los adaptadores de red con un soporte precario de drivers,
       así como para algunos proveedores de red virtuales, como
       drivers vpn, o filtros de spam, de virus o de spyware.</p>

    <note type="warning">
      <title>El AcceptFilter <code>data</code> (Windows)</title>

      <p>Para las versiones 2.4.23 y anteriores, el filtro de
         aceptación <code>data</code> de Windows esperaba hasta que se
         habían transmitido datos y se habían recuperado el buffer de
         datos inicial y las direcciones del extremo de red a partir
         de una única invocación de AcceptEx(). Esta implementación
         estaba expuesta a un ataque de denegación de servicio y se ha
         desactivado.</p>

      <p>Las versiones actuales de httpd usan por defecto el filtro
         <code>connect</code> en Windows, y recurrirán a
         <code>connect</code> si se especifica <code>data</code>. Se
         recomienda a los usuarios de versiones anteriores que añadan
         un ajuste explícito de <code>connect</code> para su
         AcceptFilter, como se muestra arriba.</p>
    </note>

</usage>
<seealso><directive module="core">Protocol</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>AcceptPathInfo</name>
<description>Los recursos aceptan información sobre su ruta</description>
<syntax>AcceptPathInfo On|Off|Default</syntax>
<default>AcceptPathInfo Default</default>
<contextlist><context>server config</context>
<context>virtual host</context><context>directory</context>
<context>.htaccess</context></contextlist>
<override>FileInfo</override>


<usage>

    <p>Esta directiva controla si las peticiones que contienen información sobre la ruta
    que sigue un fichero que existe (o un fichero que no existe pero en un directorio que
    sí existe) serán aceptadas o denegadas. La información de ruta puede estar disponible
    para los scripts en la variable de entorno <code>PATH_INFO</code>.</p>

    <p>Por ejemplo, asumamos que la ubicación <code>/test/</code> apunta a
    un directorio que contiene únicamente el fichero
    <code>here.html</code>. Entonces, las peticiones tanto para
    <code>/test/here.html/more</code> como para
    <code>/test/nothere.html/more</code> recogen
    <code>/more</code> como <code>PATH_INFO</code>.</p>

    <p>Los tres posibles argumentos para la directiva
    <directive>AcceptPathInfo</directive> son los siguientes:</p>
    <dl>
    <dt><code>Off</code></dt><dd>Una petición sólo será aceptada si
    se corresponde con una ruta literal que existe. Por lo tanto, una petición
    con una información de ruta después del nombre de fichero tal como
    <code>/test/here.html/more</code> en el ejemplo anterior devolverá
    un error 404 NOT FOUND.</dd>

    <dt><code>On</code></dt><dd>Una petición será aceptada si una
    ruta principal de acceso se corresponde con un fichero que existe. El ejemplo
    anterior <code>/test/here.html/more</code> será aceptado si
    <code>/test/here.html</code> corresponde a un fichero válido.</dd>

    <dt><code>Default</code></dt><dd>La gestión de las peticiones
    con información de ruta está determinada por el <a
    href="../handler.html">controlador</a> responsable de la petición.
    El controlador principal para para ficheros normales rechaza por defecto
    peticiones <code>PATH_INFO</code>. Los controladores que sirven scripts, tales como <a
    href="mod_cgi.html">cgi-script</a> e <a
    href="mod_isapi.html">isapi-handler</a>, normalmente aceptan
    <code>PATH_INFO</code> por defecto.</dd>
    </dl>

    <p>El objetivo principal de la directiva <code>AcceptPathInfo</code>
    es permitirnos sobrescribir la opción del controlador
    de aceptar o rechazar <code>PATH_INFO</code>. Este tipo de reescritura se necesita,
    por ejemplo, cuando utilizas un <a href="../filter.html">filtro</a>, tal como
    <a href="mod_include.html">INCLUDES</a>, para generar contenido
    basado en <code>PATH_INFO</code>. El controlador principal normalmente rechazaría
    la petición, de modo que puedes utilizar la siguiente configuración para habilitarla
    como script:</p>

    <highlight language="config">
&lt;Files "mypaths.shtml"&gt;
  Options +Includes
  SetOutputFilter INCLUDES
  AcceptPathInfo On
&lt;/Files&gt;
    </highlight>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>AccessFileName</name>
<description>Nombre del fichero distribuido de configuración</description>
<syntax>AccessFileName <var>filename</var> [<var>filename</var>] ...</syntax>
<default>AccessFileName .htaccess</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva AccessFileName le permite cambiar el nombre del fichero
    que se tendrá en cuenta para las sobrescrituras de configuración por
    directorio, en caso de que <directive module="core">AllowOverride</directive>
    esté activada para ese directorio.</p>

    <note type="warning">No se recomienda que cambie este valor, y en
    particular que no indique varios posibles nombres de fichero, ya que esto
    dificulta la resolución de problemas a cualquiera que no esté familiarizado
    con su configuración local.</note>

    <p>Mientras procesa una petición, el servidor busca ficheros con el
    nombre (o nombres) definido en <code>AccessFileName</code>
    en cada directorio de la ruta del documento, si los ficheros distribuidos
    de configuración están <a href="#allowoverride">habilitados para ese
    directorio</a>. Por ejemplo, antes de devolver el documento
    <code>/usr/local/web/index.html</code>, el servidor leerá
    <code>/.htaccess</code>, <code>/usr/.htaccess</code>,
    <code>/usr/local/.htaccess</code> y <code>/usr/local/web/.htaccess</code>
    para las directivas.</p>

    <p>Por esta razón, el fichero de configuración por defecto contiene el
    siguiente bloque:</p>

    <highlight language="config">
&lt;Directory "/"&gt;
    AllowOverride None
&lt;/Directory&gt;
    </highlight>

    <p>Este bloque de configuración ayuda a evitar accesos a ficheros
    innecesarios en directorios fuera de su <directive
    module="core">DocumentRoot</directive>. Consulte también la nota al
    respecto en la documentación de la directiva
    <code>AllowOverride</code>.</p>

</usage>
<seealso><directive module="core">AllowOverride</directive></seealso>
<seealso><a href="../configuring.html">Ficheros de configuración</a></seealso>
<seealso><a href="../howto/htaccess.html">Fichero .htaccess</a></seealso>
</directivesynopsis>

<directivesynopsis>
<name>AddDefaultCharset</name>
<description>Juego de casrácteres que se le añade por defecto a una respuesta del tipo
	contenido "content-type" es <code>text/plain</code> o <code>text/html</code></description>
<syntax>AddDefaultCharset On|Off|<var>charset</var></syntax>
<default>AddDefaultCharset Off</default>
<contextlist><context>server config</context>
<context>virtual host</context><context>directory</context>
<context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>
    <p>Esta directiva especifica un valor por defecto para el tipo de soporte que 
    	se usa como parámetro del juego de carácteres (el nombre de una 
    	codificación de carácteres) para ser añadido a una respuesta si y solo si
    	el contenido de "content-type" es o <code>text/plain</code> o 
    	<code>text/html</code>. Esto debería sobreescribir cualquier juego de 
    	caracteres que se le especifique en el cuerpo de la respuesta mediante un  
    	elemento <code>META</code>, aunque el comportamiento exacto depende a menudo
    	de la confuguracion del usuario cliente. Una configuración de 
    	<code>AddDefaultCharset Off</code> deshabilita esta funcionalidad.
    	<code>AddDefaultCharset On</code> habilita un conjunto de caracteres por defecto
    	de <code>iso-8859-1</code>. Cualquier otro valor se asume que sea el <var>charset</var>
    	que va a ser usado, que debe ser uno de los juegos de carácteres  
    	<a href="http://www.iana.org/assignments/character-sets">registradas por el IANA
    </a> para su uso en los tipos de medios de Internet (MIME types).
    Por ejemplo:</p>
  	  
    <highlight language="config">
AddDefaultCharset utf-8
    </highlight>

    <p><directive>AddDefaultCharset</directive> debería ser utilizada sólo cuando
    se sepa que todo el texto del recurso al que se le aplica se sabe que va a 
    estar en ese juego de caracteres y es inconveniente etiquetar los 
    documentos individualmente. Un ejemplo de ello es añadir el juego de caracteres 
    a recursos con contenido autogenerado, tales como scripts legados de CGI, 
    que pueden ser vulnerables a ataques de tipo XSS (Cross-Site Scripting),
    debido a datos que incluye el usuario en la salida. Notese, sin embargo
    una mejor solución es arreglar (o eliminar) dichos scripts, ya que
    dejar por defecto un juego de carácteres no protege a los usuarios
    que han habilitado la funcionalidad "auto-detect character encoding" en sus 
    navegadores.
    </p>
</usage>
<seealso><directive module="mod_mime">AddCharset</directive></seealso>
</directivesynopsis> 
<directivesynopsis>
<name>AllowEncodedSlashes</name>
<description>Determina si se permite el paso de separadores de ruta
codificados en las URLs</description>
<syntax>AllowEncodedSlashes On|Off|NoDecode</syntax>
<default>AllowEncodedSlashes Off</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>
<compatibility>
La opción NoDecode está disponible desde la versión 2.3.12.</compatibility>

<usage>
    <p>La directiva <directive>AllowEncodedSlashes</directive> permite
    utilizar en la información de ruta URLs que contienen separadores de
    ruta codificados (<code>%2F</code> para <code>/</code> y, además,
    <code>%5C</code> para <code>\</code> en los sistemas que lo admiten).</p>

    <p>Con el valor predeterminado, <code>Off</code>, esas URLs se rechazan
    con un error 404 (No encontrado).</p>

    <p>Con el valor <code>On</code>, esas URLs se aceptan, y las barras
      codificadas se decodifican como el resto de caracteres codificados.</p>

    <p>Con el valor <code>NoDecode</code>, esas URLs se aceptan, pero las
      barras codificadas no se decodifican, sino que se dejan en su estado
      codificado.</p>

    <p>Activar <directive>AllowEncodedSlashes</directive> con <code>On</code>
    es útil sobre todo cuando se usa junto con <code>PATH_INFO</code>.</p>

    <note><title>Nota</title>
      <p>Si se necesitan barras codificadas en la información de ruta, se
      recomienda encarecidamente usar <code>NoDecode</code> como medida de
      seguridad. Permitir que las barras se decodifiquen podría dar lugar a
      rutas no seguras.</p>
    </note>
</usage>
<seealso><directive module="core">AcceptPathInfo</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>AllowOverride</name>
<description>Tipos de directivas que se permiten en los ficheros
<code>.htaccess</code></description>
<syntax>AllowOverride All|None|<var>tipo-de-directiva</var>
[<var>tipo-de-directiva</var>] ...</syntax>
<default>AllowOverride None</default>
<contextlist><context>directory</context></contextlist>

<usage>
    <p>Cuando el servidor encuentra un fichero de configuración
    distribuida (normalmente llamado <code>.htaccess</code>;
    configurable mediante <directive
    module="core">AccessFileName</directive>), necesita saber qué
    directivas declaradas en ese fichero pueden sobrescribir las
    directivas de configuración anteriores.</p>

    <note><title>Solo disponible en secciones &lt;Directory&gt;</title>
    <directive>AllowOverride</directive> solo es válida en secciones
    <directive type="section" module="core">Directory</directive>
    especificadas sin expresiones regulares, no en secciones <directive
    type="section" module="core">Location</directive>, <directive
    module="core" type="section">DirectoryMatch</directive> ni
    <directive type="section" module="core">Files</directive>.
    </note>

    <p>Cuando esta directiva se establece a <code>None</code> y
    <directive module="core">AllowOverrideList</directive> se establece
    a <code>None</code>, los ficheros
    <a href="#accessfilename">.htaccess</a> se ignoran por completo. En
    este caso, el servidor ni siquiera intentará leer los ficheros
    <code>.htaccess</code> del sistema de ficheros.</p>

    <p>Cuando esta directiva se establece a <code>All</code>, se
    permite en los ficheros <code>.htaccess</code> cualquier directiva
    que tenga el <a href="directive-dict.html#Context">Contexto</a>
    .htaccess.</p>

    <p><var>tipo-de-directiva</var> puede ser uno de los siguientes
    grupos de directivas. (Consulte el
    <a href="overrides.html">índice de clases de sobrescritura</a> para
    obtener una lista actualizada de qué directivas activa cada
    <var>tipo-de-directiva</var>.)</p>

    <dl>
      <dt><a href="overrides.html#override-authconfig">AuthConfig</a></dt>

      <dd>

      Permite el uso de las directivas de autorización (<directive
      module="mod_authz_dbm">AuthDBMGroupFile</directive>,
      <directive module="mod_authn_dbm">AuthDBMUserFile</directive>,
      <directive module="mod_authz_groupfile">AuthGroupFile</directive>,
      <directive module="mod_authn_core">AuthName</directive>,
      <directive module="mod_authn_core">AuthType</directive>, <directive
      module="mod_authn_file">AuthUserFile</directive>, <directive
      module="mod_authz_core">Require</directive>, <em>etc.</em>).</dd>

      <dt><a href="overrides.html#override-fileinfo">FileInfo</a></dt>

      <dd>
      Permite el uso de las directivas que controlan los tipos de
      documento (<directive module="core">ErrorDocument</directive>,
      <directive module="core">ForceType</directive>,
      <directive module="mod_negotiation">LanguagePriority</directive>,
      <directive module="core">SetHandler</directive>,
      <directive module="core">SetInputFilter</directive>,
      <directive module="core">SetOutputFilter</directive>, y las
      directivas Add* y Remove* de <module>mod_mime</module>),
      los metadatos del documento (<directive
      module="mod_headers">Header</directive>, <directive
      module="mod_headers">RequestHeader</directive>, <directive
      module="mod_setenvif">SetEnvIf</directive>, <directive
      module="mod_setenvif">SetEnvIfNoCase</directive>, <directive
      module="mod_setenvif">BrowserMatch</directive>, <directive
      module="mod_usertrack">CookieExpires</directive>, <directive
      module="mod_usertrack">CookieDomain</directive>, <directive
      module="mod_usertrack">CookieStyle</directive>, <directive
      module="mod_usertrack">CookieTracking</directive>, <directive
      module="mod_usertrack">CookieName</directive>),
      las directivas de <module>mod_rewrite</module> (<directive
      module="mod_rewrite">RewriteEngine</directive>, <directive
      module="mod_rewrite">RewriteOptions</directive>, <directive
      module="mod_rewrite">RewriteBase</directive>, <directive
      module="mod_rewrite">RewriteCond</directive>, <directive
      module="mod_rewrite">RewriteRule</directive>),
      las directivas de <module>mod_alias</module> (<directive
      module="mod_alias">Redirect</directive>, <directive
      module="mod_alias">RedirectTemp</directive>, <directive
      module="mod_alias">RedirectPermanent</directive>, <directive
      module="mod_alias">RedirectMatch</directive>), y
      <directive module="mod_actions">Action</directive> de
      <module>mod_actions</module>.
      </dd>

      <dt><a href="overrides.html#override-indexes">Indexes</a></dt>

      <dd>
      Permite el uso de las directivas que controlan el listado de
      directorios (<directive
      module="mod_autoindex">AddDescription</directive>,
      <directive module="mod_autoindex">AddIcon</directive>, <directive
      module="mod_autoindex">AddIconByEncoding</directive>,
      <directive module="mod_autoindex">AddIconByType</directive>,
      <directive module="mod_autoindex">DefaultIcon</directive>, <directive
      module="mod_dir">DirectoryIndex</directive>, <directive
      module="mod_dir">FallbackResource</directive>, <a href="mod_autoindex.html#indexoptions.fancyindexing"
      ><code>FancyIndexing</code></a>, <directive
      module="mod_autoindex">HeaderName</directive>, <directive
      module="mod_autoindex">IndexIgnore</directive>, <directive
      module="mod_autoindex">IndexOptions</directive>, <directive
      module="mod_autoindex">ReadmeName</directive>,
      <em>etc.</em>).</dd>

      <dt><a href="overrides.html#override-limit">Limit</a></dt>

      <dd>
      Permite el uso de las directivas heredadas de control de acceso
      por host (<directive
      module="mod_access_compat">Allow</directive>, <directive
      module="mod_access_compat">Deny</directive> y <directive
      module="mod_access_compat">Order</directive>). Para el
      equivalente moderno, consulte la directiva
      <directive module="mod_authz_core">Require</directive>, que se
      controla mediante <code>AuthConfig</code>. También incluye
      <directive module="mod_include">SSIETag</directive>,
      <directive module="mod_include">SSILastModified</directive>, y
      <directive module="mod_include">SSILegacyExprParser</directive>.</dd>


      <dt>Nonfatal=[Override|Unknown|All]</dt>

      <dd>
      Permite usar la opción AllowOverride para tratar las directivas
      no válidas (no reconocidas o no permitidas) en
      .htaccess como no fatales. En lugar de provocar un Error Interno
      del Servidor, las directivas no permitidas o no reconocidas se
      ignorarán y se registrará un aviso:
      <ul>
          <li><strong>Nonfatal=Override</strong> trata como no fatales
              las directivas prohibidas por AllowOverride.</li>
          <li><strong>Nonfatal=Unknown</strong> trata como no fatales
              las directivas desconocidas. Esto cubre errores
              tipográficos y directivas implementadas por un módulo que
              no está presente.</li>
          <li><strong>Nonfatal=All</strong> trata ambos casos
              anteriores como no fatales.</li>
      </ul>
      <p>Tenga en cuenta que un error de sintaxis en una directiva
      válida seguirá provocando un Error Interno del Servidor.</p>
      <note type="warning"><title>Seguridad</title>
          Los errores no fatales pueden tener implicaciones de
          seguridad para los usuarios de .htaccess. Por ejemplo, si
          AllowOverride no permite AuthConfig, la configuración de los
          usuarios diseñada para restringir el acceso a un sitio
          quedará desactivada.
      </note>
      </dd>

      <dt><a href="overrides.html#override-options">Options</a>[=<var>Opción</var>,...]</dt>

      <dd>
      Permite el uso de las directivas que controlan características
      específicas del directorio (<directive module="core">Options</directive>
      y <directive module="mod_include">XBitHack</directive>).
      Para restringir qué opciones se pueden sobrescribir, especifique
      un signo igual seguido de una lista separada por comas, sin
      espacios, de las opciones que se pueden establecer mediante la
      directiva <directive module="core">Options</directive>.

      <note type="warning"><title>Desactivación implícita de Options</title>
      <p>Esta restricción solo controla qué opciones puede
         <em>activar</em> un fichero <code>.htaccess</code>. No impide
         que las opciones heredadas sean <em>desactivadas</em>.</p>

      <p>Cuando una directiva <directive module="core">Options</directive>
         en <code>.htaccess</code> usa sintaxis absoluta (sin prefijos
         <code>+</code> ni <code>-</code>), <em>sustituye</em> todo el
         conjunto de opciones heredado. Cualquier opción previamente
         activa que no se liste se desactiva implícitamente&mdash;incluso
         opciones que no están en la lista permitida de
         <code>AllowOverride</code>.</p>

      <p>Por ejemplo, si la configuración del servidor establece:</p>
      <highlight language="config">
Options Indexes FollowSymLinks ExecCGI
AllowOverride Options=Indexes
      </highlight>
      <p>y un fichero <code>.htaccess</code> contiene:</p>
      <highlight language="config">
Options Indexes
      </highlight>
      <p>entonces <code>FollowSymLinks</code> y <code>ExecCGI</code> se
         desactivan implícitamente para ese directorio, aunque la
         línea <code>AllowOverride</code> solo permita establecer
         <code>Indexes</code>.</p>

      <p>En resumen, este mecanismo no puede forzar que una opción
         concreta permanezca <em>activada</em> mientras se permite
         activar otras.</p>
      </note>

      <highlight language="config">
      AllowOverride Options=Indexes,MultiViews
      </highlight>
      </dd>
    </dl>

    <p>Ejemplo:</p>

    <highlight language="config">
AllowOverride AuthConfig Indexes
    </highlight>

    <p>En el ejemplo anterior, todas las directivas que no pertenezcan
    al grupo <code>AuthConfig</code> ni al grupo <code>Indexes</code>
    provocarán un error interno del servidor.</p>

    <note><p>Por razones de seguridad y rendimiento, no establezca
    <code>AllowOverride</code> a nada que no sea <code>None</code> en
    su bloque <code>&lt;Directory "/"&gt;</code>. En su lugar, busque
    (o cree) el bloque <code>&lt;Directory&gt;</code> que se refiera al
    directorio donde realmente va a colocar un fichero
    <code>.htaccess</code>.</p>
    </note>
</usage>
<seealso><directive module="core">AccessFileName</directive></seealso>
<seealso><directive module="core">AllowOverrideList</directive></seealso>
<seealso><a href="../configuring.html">Ficheros de Configuración</a></seealso>
<seealso><a href="../howto/htaccess.html">Ficheros .htaccess</a></seealso>
<seealso><a href="overrides.html">Índice de Clases de Sobrescritura para .htaccess</a></seealso>
</directivesynopsis>

<directivesynopsis>
<name>AllowOverrideList</name>
<description>Directivas individuales que se permiten en los ficheros
<code>.htaccess</code></description>
<syntax>AllowOverrideList None|<var>directiva</var>
[<var>directiva</var>] ...</syntax>
<default>AllowOverrideList None</default>
<contextlist><context>directory</context></contextlist>

<usage>
    <p>Cuando el servidor encuentra un fichero <code>.htaccess</code> (según
    lo especificado por <directive module="core">AccessFileName</directive>),
    necesita saber qué directivas declaradas en ese fichero pueden
    sobrescribir las directivas de configuración anteriores.</p>

    <note><title>Solo disponible en secciones &lt;Directory&gt;</title>
    <directive>AllowOverrideList</directive> solo es válida en
    secciones <directive type="section" module="core">Directory</directive>
    especificadas sin expresiones regulares, no en secciones <directive
    type="section" module="core">Location</directive>, <directive
    module="core" type="section">DirectoryMatch</directive> ni
    <directive type="section" module="core">Files</directive>.
    </note>

    <p>Cuando esta directiva se establece a <code>None</code> y <directive
    module="core">AllowOverride</directive> también se establece a
    <code>None</code>, los ficheros <a href="#accessfilename">.htaccess</a>
    se ignoran por completo. En este caso, el servidor ni siquiera
    intentará leer los ficheros <code>.htaccess</code> del sistema de
    ficheros.</p>

    <note>
    <p>Un valor de <code>None</code> no se puede combinar con otros valores.
    Hacerlo producirá un error que abortará el análisis de la
    configuración.</p>
    </note>

    <p>Ejemplo:</p>

    <highlight language="config">
AllowOverride None
AllowOverrideList Redirect RedirectMatch
    </highlight>

    <p>En el ejemplo anterior, solo se permiten las directivas
    <code>Redirect</code> y <code>RedirectMatch</code>. Todas las
    demás producirán un Error Interno del Servidor.</p>

    <p>Ejemplo:</p>

    <highlight language="config">
AllowOverride AuthConfig
AllowOverrideList CookieTracking CookieName
    </highlight>

    <p>En el ejemplo anterior, <directive module="core">AllowOverride</directive>
    concede permiso al grupo de directivas <code>AuthConfig</code>
    y <directive>AllowOverrideList</directive> concede permiso solo a dos
    directivas del grupo de directivas <code>FileInfo</code>. El conjunto
    efectivo de directivas permitidas es la unión de ambos. Todas las
    demás producirán un Error Interno del Servidor.</p>

    <p>Además, ciertas directivas siempre están permitidas en los
    ficheros <code>.htaccess</code> cuando el mecanismo de sobrescritura
    está activado (es decir, cuando <directive module="core">AllowOverride</directive>
    no es <code>None</code>). Estas se listan en la sección
    <a href="overrides.html#override-all">All</a> del
    <a href="overrides.html">índice de clases de sobrescritura</a>.</p>
</usage>

<seealso><directive module="core">AccessFileName</directive></seealso>
<seealso><directive module="core">AllowOverride</directive></seealso>
<seealso><a href="../configuring.html">Ficheros de Configuración</a></seealso>
<seealso><a href="../howto/htaccess.html">Ficheros .htaccess</a></seealso>
</directivesynopsis>

<directivesynopsis>
    <name>AsyncFilter</name>
    <description>Establece el tipo de filtro mínimo elegible para el manejo
    asíncrono</description>
    <syntax>AsyncFilter request|connection|network</syntax>
    <default>AsyncFilter request</default>
    <contextlist><context>server config</context><context>virtual host</context></contextlist>
    <compatibility>Disponible solo a partir de Apache 2.5.0.</compatibility>

    <usage>
        <p>Esta directiva controla los niveles de filtro mínimos que son
        elegibles para el manejo asíncrono. Esto puede ser necesario para
        dar soporte a filtros externos heredados que no manejaban
        correctamente los "meta buckets".</p>

        <p>Si se establece a "network", el manejo asíncrono se limitará
        únicamente al filtro de red. Si se establece a "connection", todos
        los filtros de conexión y de red serán elegibles para el manejo
        asíncrono, incluyendo <module>mod_ssl</module>. Si se establece a
        "request", todos los filtros serán elegibles para el manejo
        asíncrono.</p>
    </usage>
</directivesynopsis>

<directivesynopsis>
<name>CGIMapExtension</name>
<description>Technique for locating the interpreter for CGI
scripts</description>
<syntax>CGIMapExtension <var>cgi-path</var> <var>.extension</var></syntax>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>FileInfo</override>
<compatibility>NetWare only</compatibility>

<usage>
    <p>Esta directiva se usa para controlar cómo encuentra Apache httpd el
    intérprete usado para ejecutar los scripts CGI. Por ejemplo, al
    establecer <code>CGIMapExtension sys:\foo.nlm .foo</code> se hará
    que todos los ficheros de script CGI con extensión <code>.foo</code>
    se pasen al intérprete FOO.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>CGIPassAuth</name>
<description>Permite pasar las cabeceras HTTP de autorización a los scripts
como variables CGI</description>
<syntax>CGIPassAuth On|Off</syntax>
<default>CGIPassAuth Off</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>
<compatibility>Disponible en Apache HTTP Server 2.4.13 y posteriores</compatibility>

<usage>
    <p><directive>CGIPassAuth</directive> permite a los scripts acceder a
    las cabeceras HTTP de autorización como <code>Authorization</code>, que
    es necesaria para los scripts que implementan autenticación HTTP
    Básica. Normalmente estas cabeceras HTTP se ocultan a los scripts.
    Esto es para impedir que los scripts vean los identificadores de
    usuario y las contraseñas usadas para acceder al servidor cuando la
    autenticación HTTP Básica está activada en el servidor web. Esta
    directiva debe usarse cuando se permite a los scripts implementar la
    autenticación HTTP Básica.</p>

    <p>Esta directiva se puede usar en lugar de la opción de compilación
    <code>SECURITY_HOLE_PASS_AUTHORIZATION</code>, disponible en versiones
    anteriores de Apache HTTP Server.</p>

    <p>Este ajuste es respetado por cualquier módulo que use
    <code>ap_add_common_vars()</code>, como <module>mod_cgi</module>,
    <module>mod_cgid</module>, <module>mod_proxy_fcgi</module>,
    <module>mod_proxy_scgi</module>, etc. En particular, afecta a módulos
    que no gestionan la petición en el sentido habitual pero que aun así
    usan esta API; ejemplos de esto son <module>mod_include</module>
    y <module>mod_ext_filter</module>. Los módulos de terceros que no usen
    <code>ap_add_common_vars()</code> pueden optar también por respetar
    este ajuste.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>CGIVar</name>
<description>Controla cómo se establecen algunas variables CGI</description>
<syntax>CGIVar <var>variable</var> <var>regla</var></syntax>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>FileInfo</override>
<compatibility>Disponible en Apache HTTP Server 2.4.21 y posteriores</compatibility>

<usage>
  <p>Esta directiva controla cómo se establecen ciertas variables de
  entorno CGI cuando las peticiones se pasan a scripts CGI u otros
  manejadores que reciben un entorno CGI. Actualmente, la única variable
  soportada es <code>REQUEST_URI</code>.</p>

  <p>Por defecto, la variable de entorno CGI <code>REQUEST_URI</code> se
  establece a la URI original de la línea de petición del cliente. Esto
  significa que incluso si <module>mod_rewrite</module> o una
  redirección interna cambia el recurso que realmente se está sirviendo,
  el script CGI sigue viendo la URI original enviada por el cliente.</p>

  <p>Con <code>CGIVar REQUEST_URI current-uri</code>, el valor se
  establece en cambio a la URI actual después de haberse aplicado
  cualquier reescritura o redirección interna.</p>

  <p><strong>Valores permitidos:</strong></p>
  <dl>
    <dt><code>original-uri</code> (por defecto)</dt>
    <dd>Establece <code>REQUEST_URI</code> a la URI de la petición
    original del cliente, independientemente de cualquier redirección o
    reescritura interna.</dd>
    <dt><code>current-uri</code></dt>
    <dd>Establece <code>REQUEST_URI</code> a la URI del recurso que se
    está procesando actualmente, que puede diferir de la petición
    original debido a redirecciones o reescrituras internas.</dd>
  </dl>

  <highlight language="config">
# Mostrar a los scripts CGI la URI reescrita en vez de la original
CGIVar REQUEST_URI current-uri
  </highlight>

  <note><title>Nota</title>
  <p>La variable de entorno CGI <code>REQUEST_URI</code> (en cualquiera de
  los dos modos) contiene la URI completa, incluida la cadena de
  consulta. Esto difiere de la variable del servidor
  <code>%{REQUEST_URI}</code> usada en <module>mod_rewrite</module> y
  <a href="../expr.html">ap_expr</a>, que contiene solo el componente de
  ruta (sin cadena de consulta).</p></note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>DefaultRuntimeDir</name>
<description>Directorio base para los ficheros de tiempo de ejecución del
servidor</description>
<syntax>DefaultRuntimeDir <var>directory-path</var></syntax>
<default>DefaultRuntimeDir DEFAULT_REL_RUNTIMEDIR (logs/)</default>
<contextlist><context>server config</context></contextlist>
<compatibility>Disponible en Apache 2.4.2 y posteriores</compatibility>

<usage>
    <p>La directiva <directive>DefaultRuntimeDir</directive> establece el
    directorio en el que el servidor creará varios ficheros de tiempo de
    ejecución (memoria compartida, locks, etc.). Si se establece como una
    ruta relativa, la ruta completa será relativa a
    <directive>ServerRoot</directive>.</p>

    <p><strong>Ejemplo</strong></p>
   <highlight language="config">
DefaultRuntimeDir scratch/
    </highlight>

    <p>La ubicación por defecto de <directive>DefaultRuntimeDir</directive>
    se puede modificar cambiando la macro <code>DEFAULT_REL_RUNTIMEDIR</code>
    en tiempo de compilación.</p>

   <p>Nota: <directive>ServerRoot</directive> debe especificarse antes de
   usar esta directiva. De lo contrario, se usará el valor por defecto de
   <directive>ServerRoot</directive> para establecer el directorio base.</p>

</usage>
<seealso><a href="../misc/security_tips.html#serverroot">los consejos de
    seguridad</a> para obtener información sobre cómo establecer
    correctamente los permisos en <directive>ServerRoot</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>DefaultStateDir</name>
<description>Directorio base para los ficheros de estado persistente</description>
<syntax>DefaultStateDir <var>directory-path</var></syntax>
<default>DefaultStateDir DEFAULT_REL_STATEDIR (state/)</default>
<contextlist><context>server config</context></contextlist>
<compatibility>Disponible en Apache 2.5.1 y posteriores</compatibility>

<usage>
    <p>La directiva <directive>DefaultStateDir</directive> establece el
    directorio en el que el servidor creará varios ficheros de estado
    persistente (bases de datos, cachés de larga duración, etc.). Si se
    establece como una ruta relativa, la ruta completa será relativa a
    <directive module="core">ServerRoot</directive>.</p>

    <p><strong>Ejemplo</strong></p>
   <highlight language="config">
DefaultStateDir state/
    </highlight>

    <p>La ubicación por defecto de <directive>DefaultStateDir</directive>
    se puede modificar cambiando la macro <code>DEFAULT_REL_STATEDIR</code>
    en tiempo de compilación.</p>

   <p>Nota: <directive module="core">ServerRoot</directive> debe
   especificarse antes de usar esta directiva. De lo contrario, se usará
   el valor por defecto de <directive module="core">ServerRoot</directive>
   para establecer el directorio base.</p>

</usage>
<seealso><a href="../misc/security_tips.html#serverroot">los consejos de
    seguridad</a> para obtener información sobre cómo establecer
    correctamente los permisos en <directive module="core">ServerRoot</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>DefaultType</name>
<description>Esta directiva no tiene otro efecto que emitir avisos
si el valor no es <code>none</code>. En versiones anteriores,
DefaultType permitía especificar un tipo de medio por defecto para
asignar al contenido de las respuestas para las que no se encontrara
ninguna otra configuración de tipo de medio.
</description>
<syntax>DefaultType <var>tipo-de-medio|none</var></syntax>
<default>DefaultType none</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>FileInfo</override>
<compatibility>El argumento <code>none</code> está disponible desde Apache httpd 2.2.7. El resto de opciones están DESHABILITADAS desde la versión 2.3.x.</compatibility>

<usage>
    <p>Esta directiva se ha deshabilitado. Por compatibilidad con
    ficheros de configuración anteriores, se puede especificar con el
    valor <code>none</code>, lo que significa que no hay tipo de medio
    por defecto. Por ejemplo:</p>

    <highlight language="config">
DefaultType None
    </highlight>

    <p><code>DefaultType None</code> solo está disponible desde
    httpd-2.2.7.</p>

    <p>Use el fichero de configuración mime.types y la directiva
    <directive module="mod_mime">AddType</directive> para configurar
    las asignaciones de tipo de medio a través de las extensiones de
    los ficheros, o la directiva <directive module="core">ForceType</directive>
    para configurar el tipo de medio de recursos concretos. En caso
    contrario, el servidor enviará la respuesta sin el campo de
    cabecera Content-Type, y el receptor podrá intentar adivinar el
    tipo de medio.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>Define</name>
<description>Define una variable</description>
<syntax>Define <var>nombre-de-parámetro</var> [<var>valor-de-parámetro</var>]</syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>En su forma de un solo parámetro, <directive>Define</directive>
    es equivalente a pasar el argumento <code>-D</code> a
    <program>httpd</program>. Se puede usar para activar o desactivar
    el uso de secciones <directive module="core"
    type="section">IfDefine</directive> sin necesidad de modificar los
    argumentos <code>-D</code> en ningún script de arranque.</p>

    <p>Además de eso, si se proporciona el segundo parámetro, se
    establece una variable de configuración con ese valor. La variable
    se puede usar en la configuración mediante la sintaxis
    <code>${VAR}</code>. La variable siempre se define globalmente y
    no está limitada al ámbito de la sección de configuración que la
    rodea.</p>

    <highlight language="config">
&lt;IfDefine TEST&gt;
  Define servername test.example.com
&lt;/IfDefine&gt;
&lt;IfDefine !TEST&gt;
  Define servername www.example.com
  Define SSL
&lt;/IfDefine&gt;

DocumentRoot "/var/www/${servername}/htdocs"
    </highlight>

    <p>Los nombres de variable no pueden contener el carácter de dos
    puntos ":", para evitar conflictos con la sintaxis de
    <directive module="mod_rewrite">RewriteMap</directive>.</p>

    <note><title>Ámbito en Host Virtual y riesgos</title>
      <p>Aunque esta directiva se soporta en el contexto de host
         virtual, los cambios que realiza son visibles para cualquier
         directiva de configuración posterior, más allá de cualquier
         host virtual que la contenga.</p>
    </note>
</usage>
<seealso><directive module="core">UnDefine</directive></seealso>
<seealso><directive module="core">IfDefine</directive></seealso>
</directivesynopsis>

<directivesynopsis type="section">
<name>Directory</name>
<description>Delimita un grupo de directivas que solo se aplican al
directorio del sistema de ficheros indicado, a sus subdirectorios y a
su contenido.</description>
<syntax>&lt;Directory <var>directory-path</var>&gt;
... &lt;/Directory&gt;</syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p><directive type="section">Directory</directive> y
    <code>&lt;/Directory&gt;</code> se usan para delimitar un grupo de
    directivas que solo se aplicarán al directorio indicado, a los
    subdirectorios de ese directorio y a los ficheros contenidos en
    los respectivos directorios. Puede usarse cualquier directiva
    permitida en un contexto de directorio. <var>Directory-path</var>
    es o bien la ruta completa a un directorio, o bien una cadena con
    comodines usando la sintaxis de coincidencia de los intérpretes de
    comandos Unix. En una cadena con comodines, <code>?</code>
    coincide con un único carácter cualquiera, y <code>*</code>
    coincide con cualquier secuencia de caracteres. También puede usar
    rangos de caracteres <code>[]</code>. Ninguno de los comodines
    coincide con el carácter '/', de forma que <code>&lt;Directory
    "/*/public_html"&gt;</code> no coincidirá con
    <code>/home/user/public_html</code>, pero <code>&lt;Directory
    "/home/*/public_html"&gt;</code> sí lo hará. Ejemplo:</p>

    <highlight language="config">
&lt;Directory "/usr/local/httpd/htdocs"&gt;
  Options Indexes FollowSymLinks
&lt;/Directory&gt;
    </highlight>

    <p>Las rutas de directorio <em>pueden</em> ir entre comillas si lo
    desea; sin embargo, <em>deben</em> ir entre comillas si la ruta
    contiene espacios. Esto es porque un espacio indicaría, si no, el
    final de un argumento.</p>

    <note>
      <p>Tenga cuidado con los argumentos <var>directory-path</var>:
      tienen que coincidir literalmente con la ruta del sistema de
      ficheros que usa Apache httpd para acceder a los ficheros. Las
      directivas aplicadas a un <code>&lt;Directory&gt;</code>
      concreto no se aplicarán a los ficheros a los que se acceda
      desde ese mismo directorio a través de una ruta distinta, como
      mediante enlaces simbólicos diferentes.</p>
    </note>

    <p>También se pueden usar <glossary ref="regex">expresiones
    regulares</glossary>, añadiendo el carácter <code>~</code>. Por
    ejemplo:</p>

    <highlight language="config">
&lt;Directory ~ "^/www/[0-9]{3}"&gt;

&lt;/Directory&gt;
    </highlight>

    <p>coincidiría con los directorios de <code>/www/</code> cuyo
    nombre consistiera en tres números.</p>

    <p>Si varias secciones <directive
    type="section">Directory</directive> (que no sean expresiones
    regulares) coinciden con el directorio (o con uno de sus
    directorios padre) que contiene un documento, las directivas se
    aplican en orden de coincidencia más corta primero, intercaladas
    con las directivas de los ficheros <a
    href="#accessfilename">.htaccess</a>. Por ejemplo, con</p>

    <highlight language="config">
&lt;Directory "/"&gt;
  AllowOverride None
&lt;/Directory&gt;

&lt;Directory "/home"&gt;
  AllowOverride FileInfo
&lt;/Directory&gt;
    </highlight>

    <p>para acceder al documento <code>/home/web/dir/doc.html</code>
    los pasos son:</p>

    <ul>
      <li>Aplicar la directiva <code>AllowOverride None</code>
      (deshabilitando los ficheros <code>.htaccess</code>).</li>

      <li>Aplicar la directiva <code>AllowOverride FileInfo</code>
      (para el directorio <code>/home</code>).</li>

      <li>Aplicar cualquier directiva <code>FileInfo</code> presente en
      <code>/home/.htaccess</code>, <code>/home/web/.htaccess</code> y
      <code>/home/web/dir/.htaccess</code>, en ese orden.</li>
    </ul>

    <p>Las expresiones regulares no se tienen en cuenta hasta que se
    hayan aplicado todas las secciones normales. Entonces se comprueban
    todas las expresiones regulares en el orden en que aparecen en el
    fichero de configuración. Por ejemplo, con</p>

    <highlight language="config">
&lt;Directory ~ "abc$"&gt;
  # ... directivas aquí ...
&lt;/Directory&gt;
    </highlight>

    <p>la sección con expresión regular no se tendrá en cuenta hasta
    que se hayan aplicado todas las secciones <directive
    type="section">Directory</directive> normales y los ficheros
    <code>.htaccess</code>. Entonces la expresión regular coincidirá
    con <code>/home/abc/public_html/abc</code> y se aplicará la
    correspondiente sección <directive
    type="section">Directory</directive>.</p>

    <note type="warning">
    <p>El acceso por defecto para <code>&lt;Directory "/"&gt;</code>
    es permitir todo el acceso. Esto significa que Apache httpd
    servirá cualquier fichero que se corresponda con una URL. Se
    recomienda que cambie esto con un bloque como</p>

    <highlight language="config">
&lt;Directory "/"&gt;
  Require all denied
&lt;/Directory&gt;
    </highlight>

    <p>y que después anule esto para los directorios a los que
    <em>quiera</em> que se pueda acceder. Consulte la página <a
    href="../misc/security_tips.html">Consejos de seguridad</a> para
    más detalles.</p>
    </note>

    <p>Las secciones de directorio aparecen en el fichero
    <code>httpd.conf</code>. Las directivas <directive
    type="section">Directory</directive> no pueden anidarse, ni pueden
    aparecer dentro de una sección <directive module="core"
    type="section">Limit</directive> o <directive module="core"
    type="section">LimitExcept</directive>.</p>
</usage>
<seealso><a href="../sections.html">Cómo funcionan las secciones
    &lt;Directory&gt;, &lt;Location&gt; y &lt;Files&gt;</a> para una
    explicación de cómo se combinan estas distintas secciones cuando
    se recibe una petición</seealso>
</directivesynopsis>

<directivesynopsis type="section">
<name>DirectoryMatch</name>
<description>Enclose directives that apply to
the contents of file-system directories matching a regular expression.</description>
<syntax>&lt;DirectoryMatch <var>regex</var>&gt;
... &lt;/DirectoryMatch&gt;</syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p><directive type="section">DirectoryMatch</directive> y
    <code>&lt;/DirectoryMatch&gt;</code> se usan para encerrar un
    grupo de directivas que se aplicarán a los directorios (y a los
    ficheros que contienen) cuya ruta en el sistema de ficheros
    coincida con la <glossary ref="regex">expresión regular</glossary>
    dada. A diferencia de <directive module="core" type="section">Directory</directive>,
    no se aplica automáticamente a los subdirectorios a menos que el
    patrón también coincida con ellos. Toma como argumento una
    expresión regular que se compara como subcadena — no está anclada
    al principio ni al final a menos que incluya explícitamente
    <code>^</code> o <code>$</code> en el patrón. Por ejemplo:</p>

    <highlight language="config">
&lt;DirectoryMatch "^/www/(.+/)?[0-9]{3}/"&gt;
    # ...
&lt;/DirectoryMatch&gt;
    </highlight>

    <p>coincide con los directorios en <code>/www/</code> (o
    cualquier subdirectorio de este) cuyo nombre consiste en tres
    números.</p>

   <note><title>Compatibilidad</title>
      Antes de la versión 2.3.9, esta directiva se aplicaba
      implícitamente a los subdirectorios (como
      <directive module="core" type="section">Directory</directive>)
      y no podía coincidir con el símbolo de fin de línea ($). En la
      versión 2.3.9 y posteriores, solo los directorios que coinciden
      con la expresión se ven afectados por las directivas que
      contiene.
    </note>

    <note><title>Barra final</title>
      Esta directiva se aplica a las peticiones de directorios que
      pueden terminar o no en una barra final. Si ancla su patrón con
      <code>$</code>, puede que necesite hacer coincidir ambas
      formas, p. ej., <code>&lt;DirectoryMatch "^/var/www/?$"&gt;</code>.
    </note>

    <p>A partir de la versión 2.4.8, los grupos con nombre y las
    referencias hacia atrás se capturan y se escriben en el entorno
    con el nombre correspondiente prefijado con "MATCH_" y en
    mayúsculas. Esto permite hacer referencia a elementos de las rutas
    desde <a href="../expr.html">expresiones</a> y módulos como
    <module>mod_rewrite</module>. Para evitar confusiones, las
    referencias hacia atrás numeradas (sin nombre) se ignoran. Use
    grupos con nombre en su lugar.</p>

    <highlight language="config">
&lt;DirectoryMatch "^/var/www/combined/(?&lt;sitename&gt;[^/]+)"&gt;
    Require ldap-group cn=%{env:MATCH_SITENAME},ou=combined,o=Example
&lt;/DirectoryMatch&gt;
    </highlight>
</usage>
<seealso><directive type="section" module="core">Directory</directive> for
a description of how regular expressions are mixed in with normal
<directive type="section">Directory</directive>s</seealso>
<seealso><a
href="../sections.html">How &lt;Directory&gt;, &lt;Location&gt; and
&lt;Files&gt; sections work</a> for an explanation of how these different
sections are combined when a request is received</seealso>
</directivesynopsis>

<directivesynopsis>
<name>DocumentRoot</name>
<description>Directorio que forma el árbol de documentos principal
visible desde la web</description>
<syntax>DocumentRoot <var>directory-path</var></syntax>
<default>DocumentRoot "/usr/local/apache/htdocs"</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>Esta directiva establece el directorio desde el que
    <program>httpd</program> servirá los ficheros. A menos que coincida
    con una directiva como <directive module="mod_alias">Alias</directive>,
    el servidor añade la ruta de la URL solicitada a la raíz de
    documentos para formar la ruta del documento. Ejemplo:</p>

    <highlight language="config">
DocumentRoot "/usr/web"
    </highlight>

    <p>entonces un acceso a
    <code>http://my.example.com/index.html</code> hace referencia a
    <code>/usr/web/index.html</code>. Si <var>directory-path</var> no
    es absoluta, se asume que es relativa a <directive
    module="core">ServerRoot</directive>.</p>

    <p><directive>DocumentRoot</directive> debe especificarse sin una
    barra final.</p>
</usage>
<seealso><a href="../urlmapping.html#documentroot">Mapeo de URLs a
ubicaciones del sistema de ficheros</a></seealso>
</directivesynopsis>

<directivesynopsis type="section">
<name>Else</name>
<description>Contiene directivas que se aplican solo si la condición de
una sección <directive type="section" module="core">If</directive> o
<directive type="section" module="core">ElseIf</directive> anterior no
se cumple en una petición en tiempo de ejecución</description>
<syntax>&lt;Else&gt; ... &lt;/Else&gt;</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>All</override>
<compatibility>Las condiciones anidadas se evalúan a partir de la versión
2.4.26</compatibility>

<usage>
    <p>La sección <directive type="section">Else</directive> aplica las
    directivas que contiene si y solo si la sección
    <directive type="section">If</directive> o
    <directive type="section">ElseIf</directive> más reciente en el
    mismo ámbito no se ha aplicado.
    Por ejemplo, en:</p>

    <highlight language="config">
&lt;If "-z req('Host')"&gt;
  # ...
&lt;/If&gt;
&lt;Else&gt;
  # ...
&lt;/Else&gt;
    </highlight>

    <p>La sección <directive type="section">If</directive> coincidiría
        con las peticiones HTTP/1.0 sin cabecera <var>Host:</var>, y la
        sección <directive type="section">Else</directive> coincidiría
        con las peticiones que sí tienen cabecera <var>Host:</var>.</p>

</usage>
<seealso><directive type="section" module="core">If</directive></seealso>
<seealso><directive type="section" module="core">ElseIf</directive></seealso>
<seealso><a href="../sections.html">Cómo funcionan las secciones
    &lt;Directory&gt;, &lt;Location&gt; y &lt;Files&gt;</a> para una
    explicación de cómo se combinan estas distintas secciones cuando se
    recibe una petición.
    <directive type="section">If</directive>,
    <directive type="section">ElseIf</directive> y
    <directive type="section">Else</directive> se aplican en último
    lugar.</seealso>
</directivesynopsis>

<directivesynopsis type="section">
<name>ElseIf</name>
<description>Contiene directivas que se aplican solo si se cumple una
condición en una petición en tiempo de ejecución, mientras que la
condición de una sección <directive type="section" module="core">If</directive>
o <directive type="section" module="core">ElseIf</directive> anterior no
se cumple</description>
<syntax>&lt;ElseIf <var>expresión</var>&gt; ... &lt;/ElseIf&gt;</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>All</override>
<compatibility>Las condiciones anidadas se evalúan a partir de la versión
2.4.26</compatibility>

<usage>
    <p>La sección <directive type="section">ElseIf</directive> aplica las
    directivas que contiene si y solo si la condición dada se evalúa
    como verdadera y, además, la sección <directive type="section">If</directive>
    o <directive type="section">ElseIf</directive> más reciente en el
    mismo ámbito no se ha aplicado. Por ejemplo, en:</p>

    <highlight language="config">
&lt;If "-R '10.1.0.0/16'"&gt;
  #...
&lt;/If&gt;
&lt;ElseIf "-R '10.0.0.0/8'"&gt;
  #...
&lt;/ElseIf&gt;
&lt;Else&gt;
  #...
&lt;/Else&gt;
    </highlight>

    <p>La sección <directive type="section">ElseIf</directive> coincidiría
    si la dirección remota de una petición pertenece a la subred
    10.0.0.0/8 pero no a la subred 10.1.0.0/16.</p>

</usage>
<seealso><a href="../expr.html">Expresiones en Apache HTTP Server</a>,
para una referencia completa y más ejemplos.</seealso>
<seealso><directive type="section" module="core">If</directive></seealso>
<seealso><directive type="section" module="core">Else</directive></seealso>
<seealso><a href="../sections.html">Cómo funcionan las secciones
    &lt;Directory&gt;, &lt;Location&gt; y &lt;Files&gt;</a> para una
    explicación de cómo se combinan estas distintas secciones cuando se
    recibe una petición.
    <directive type="section">If</directive>,
    <directive type="section">ElseIf</directive> y
    <directive type="section">Else</directive> se aplican en último
    lugar.</seealso>
</directivesynopsis>

<directivesynopsis>
<name>EnableMMAP</name>
<description>Usa mapeo en memoria para leer los ficheros durante su
envío</description>
<syntax>EnableMMAP On|Off</syntax>
<default>EnableMMAP On</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>FileInfo</override>

<usage>
    <p>Esta directiva controla si <program>httpd</program> puede usar
    el mapeo en memoria cuando necesita leer el contenido de un
    fichero durante su envío. Por defecto, cuando la gestión de una
    petición requiere acceder a los datos de un fichero -- por
    ejemplo, al servir un fichero procesado por el servidor usando
    <module>mod_include</module> -- Apache httpd mapea el fichero en
    memoria si el sistema operativo lo permite.</p>

    <p>Este mapeo en memoria a veces mejora el rendimiento. Pero en
    algunos entornos es mejor deshabilitarlo para evitar problemas
    operativos:</p>

    <ul>
    <li>En algunos sistemas multiprocesador, el mapeo en memoria puede
    reducir el rendimiento de <program>httpd</program>.</li>
    <li>Borrar o truncar un fichero mientras <program>httpd</program>
      lo tiene mapeado en memoria puede provocar que
      <program>httpd</program> falle con un error de segmentación.
    </li>
    </ul>

    <p>En configuraciones de servidor vulnerables a estos problemas,
    debería deshabilitar el mapeo en memoria de los ficheros servidos
    especificando:</p>

    <highlight language="config">
EnableMMAP Off
    </highlight>

    <p>Para ficheros montados por NFS, esta característica se puede
    deshabilitar explícitamente para los ficheros problemáticos
    especificando:</p>

    <highlight language="config">
&lt;Directory "/path-to-nfs-files"&gt;
  EnableMMAP Off
&lt;/Directory&gt;
    </highlight>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>EnableSendfile</name>
<description>Usa el soporte sendfile del núcleo para enviar los
ficheros al cliente</description>
<syntax>EnableSendfile On|Off</syntax>
<default>EnableSendfile Off</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>FileInfo</override>
<compatibility>El valor por defecto cambió a Off en la
versión 2.3.9.</compatibility>

<usage>
    <p>Esta directiva controla si <program>httpd</program> puede usar
    el soporte sendfile del núcleo para transmitir el contenido de los
    ficheros al cliente. Por defecto, cuando la gestión de una
    petición no requiere acceder a los datos de un fichero -- por
    ejemplo, al servir un fichero estático -- Apache httpd usa
    sendfile para enviar el contenido del fichero sin llegar a leerlo,
    si el sistema operativo lo permite. Si se usa SSL/TLS para la
    conexión, o si se configura algún <a href="../filter.html">filtro
    de salida</a> que inspeccione o modifique la salida, el mecanismo
    sendfile no se usará, independientemente de esta opción de
    configuración.</p>

    <p>Este mecanismo sendfile evita operaciones separadas de lectura
    y envío, así como asignaciones de búfer. Pero en algunas
    plataformas o dentro de algunos sistemas de ficheros, es mejor
    deshabilitar esta característica para evitar problemas operativos:</p>

    <ul>
    <li>Algunas plataformas pueden tener un soporte de sendfile
    defectuoso que el sistema de compilación no detectó, especialmente
    si los binarios se compilaron en otra máquina y se trasladaron a
    una máquina con un soporte de sendfile defectuoso.</li>
    <li>En Linux, el uso de sendfile desencadena errores de descarga
    de la suma de comprobación TCP en ciertas tarjetas de red cuando
    se usa IPv6.</li>
    <li>En Linux sobre Itanium, <code>sendfile</code> puede no ser
    capaz de gestionar ficheros de más de 2 GB.</li>
    <li>Con una <directive module="core">DocumentRoot</directive>
    montada por red (p. ej., NFS, SMB, CIFS, FUSE), puede que el
    núcleo no pueda servir el fichero de red a través de su propia
    caché.</li>
    </ul>

    <p>En configuraciones de servidor no vulnerables a estos
    problemas, puede habilitar esta característica especificando:</p>

    <highlight language="config">
EnableSendfile On
    </highlight>

    <p>Para ficheros montados por red, esta característica se puede
    deshabilitar explícitamente para los ficheros problemáticos
    especificando:</p>

    <highlight language="config">
&lt;Directory "/path-to-nfs-files"&gt;
  EnableSendfile Off
&lt;/Directory&gt;
    </highlight>
    <p>Tenga en cuenta que la configuración por directorio y en
       ficheros .htaccess de <directive>EnableSendfile</directive> no
       está soportada por <module>mod_cache_disk</module>. El módulo
       solo tiene en cuenta la definición global de
       <directive>EnableSendfile</directive>.
    </p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>HttpProtocolOptions</name>
<description>Modifica las restricciones sobre los mensajes de petición
HTTP</description>
<syntax>HttpProtocolOptions [Strict|Unsafe] [RegisteredMethods|LenientMethods]
 [Allow0.9|Require1.0]</syntax>
<default>HttpProtocolOptions Strict LenientMethods Allow0.9</default>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>
<compatibility>2.2.32 o 2.4.24 y posteriores</compatibility>

<usage>
    <p>Esta directiva cambia las reglas aplicadas a la línea de petición
    HTTP (<rfc section="3.1.1">7230</rfc>) y a los campos de cabecera de
    la petición HTTP (<rfc section="3.2">7230</rfc>), que ahora se
    aplican por defecto o usando la opción <code>Strict</code>. Debido a
    módulos heredados, aplicaciones o agentes de usuario personalizados
    que deben quedar obsoletos, se ha añadido la opción <code>Unsafe</code>
    para volver a los comportamientos heredados.</p>

    <p>Estas reglas se aplican antes del procesamiento de la petición,
    por lo que deben configurarse en la sección global o en la primera
    sección de host virtual que coincida (la por defecto), por interfaz
    IP/puerto (y no por nombre), para que se respeten.</p>

    <p>La directiva acepta tres parámetros de la siguiente lista de
       opciones, aplicando el valor por defecto a los que no se
       especifiquen:</p>

    <dl>
    <dt>Strict|Unsafe</dt>
    <dd>
      <p>Antes de la introducción de esta directiva, los analizadores de
      mensajes de petición de Apache HTTP Server toleraban varias formas
      de entrada que no se ajustaban al protocolo.
      <rfc section="9.4">7230</rfc> (Request Splitting) y
      <rfc section="9.5">7230</rfc> (Response Smuggling) señalan solo dos
      de los riesgos potenciales de aceptar mensajes de petición no
      conformes, mientras que <rfc section="3.5">7230</rfc> "Message
      Parsing Robustness" identifica los riesgos de aceptar espacios en
      blanco y formatos de mensaje de petición poco habituales. Desde la
      introducción de esta directiva, todas las reglas gramaticales de la
      especificación se aplican en el modo de funcionamiento por defecto
      <code>Strict</code>, y el tratamiento estricto de los espacios en
      blanco sugerido en la sección 3.5 se aplica y no se puede
      relajar.</p>

      <note type="warning"><title>Riesgos de seguridad de Unsafe</title>
        <p>Se recomienda encarecidamente a los usuarios que no activen el
        modo de funcionamiento <code>Unsafe</code>, en particular en
        despliegues de servidor accesibles públicamente desde el
        exterior. Si se necesita una interfaz para una monitorización
        defectuosa u otros consumidores de servicio personalizados que se
        ejecuten en una intranet, los usuarios deberían activar la opción
        Unsafe solo en un host virtual específico configurado para dar
        servicio a su red privada interna.</p>
      </note>

      <example>
        <title>Ejemplo de una petición que lleva a un HTTP 400 en modo Strict</title>
        # Falta el CRLF<br />
        GET / HTTP/1.0\n\n
      </example>
      <note type="warning"><title>Herramientas de línea de comandos y CRLF</title>
        <p>Algunas herramientas necesitan forzarse a usar CRLF; de lo
        contrario httpd devolverá una respuesta HTTP 400 como la descrita
        en el caso de uso anterior. Por ejemplo, <strong>OpenSSL s_client
        necesita el parámetro -crlf para funcionar correctamente</strong>.</p>
        <p>La directiva <directive module="mod_dumpio">DumpIOInput</directive>
        puede ayudar al revisar la petición HTTP para identificar
        problemas como la ausencia de CRLF.</p>
      </note>
    </dd>
    <dt>RegisteredMethods|LenientMethods</dt>
    <dd>
      <p><rfc section="4.1">7231</rfc> "Request Methods" "Overview" exige
      que los servidores de origen respondan con un código de estado
      HTTP 501 cuando se encuentre un método no soportado en la línea de
      petición. Esto ya sucede cuando se usa la opción
      <code>LenientMethods</code>, pero los administradores pueden
      querer activar la opción <code>RegisteredMethods</code> y
      registrar cualquier método no estándar usando la directiva
      <directive module="core">RegisterHttpMethod</directive>, en
      particular si se ha activado la opción <code>Unsafe</code>.</p>

      <note type="warning"><title>Compatibilidad con proxies de reenvío</title>
        <p>La opción <code>RegisteredMethods</code> <strong>no</strong>
        debería activarse para hosts proxy de reenvío, ya que los
        métodos soportados por los servidores de origen son desconocidos
        para el servidor proxy.</p>
      </note>

      <example>
        <title>Ejemplo de una petición que lleva a un HTTP 501 en modo LenientMethods</title>
        # Método HTTP desconocido<br />
        WOW / HTTP/1.0\r\n\r\n<br /><br />
        # Método HTTP en minúsculas<br />
        get / HTTP/1.0\r\n\r\n<br />
      </example>
      </dd>
      <dt>Allow0.9|Require1.0</dt>
      <dd>
      <p><rfc section="19.6">2616</rfc> "Compatibility With Previous
      Versions" animaba a los servidores HTTP a soportar peticiones
      HTTP/0.9 heredadas. La RFC 7230 sustituye esto indicando que "The
      expectation to support HTTP/0.9 requests has been removed" y
      ofrece comentarios adicionales en el
      <rfc anchor="appendix-A">7230</rfc> Apéndice A. La opción
      <code>Require1.0</code> permite al usuario eliminar el soporte del
      comportamiento de la opción por defecto <code>Allow0.9</code>.</p>

      <example>
        <title>Ejemplo de una petición que lleva a un HTTP 400 en modo Require1.0</title>
        # Versión HTTP no soportada<br />
        GET /\r\n\r\n
      </example>
    </dd>
    </dl>
    <p>Revisar los mensajes registrados en el
    <directive module="core">ErrorLog</directive>, configurado con el
    nivel <directive module="core">LogLevel</directive> <code>debug</code>,
    puede ayudar a identificar este tipo de peticiones defectuosas junto
    con su origen. Los usuarios deberían prestar especial atención a las
    respuestas 400 en el log de accesos para peticiones no válidas que
    se rechazaron de forma inesperada.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>Error</name>
<description>Interrumpe el procesamiento de la configuración con un
mensaje de error personalizado</description>
<syntax>Error <var>message</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>All</override>
<compatibility>2.3.9 y posteriores</compatibility>

<usage>
    <p>Si se puede detectar un error dentro de la configuración, esta
    directiva se puede usar para generar un mensaje de error
    personalizado e interrumpir el procesamiento de la configuración.
    El uso típico es para informar de módulos requeridos que faltan
    en la configuración.</p>

    <highlight language="config">
# Ejemplo
# asegurarse de que mod_include está cargado
&lt;IfModule !include_module&gt;
  Error "mod_include es necesario para mod_foo. Cárguelo con LoadModule."
&lt;/IfModule&gt;

# asegurarse de que se define exactamente una de SSL o NOSSL
&lt;IfDefine SSL&gt;
&lt;IfDefine NOSSL&gt;
  Error "Se han definido tanto SSL como NOSSL. Defina solo una de ellas."
&lt;/IfDefine&gt;
&lt;/IfDefine&gt;
&lt;IfDefine !SSL&gt;
&lt;IfDefine !NOSSL&gt;
  Error "Debe definirse SSL o NOSSL."
&lt;/IfDefine&gt;
&lt;/IfDefine&gt;
    </highlight>

    <note type="warning"><title>Nota</title>
        <p>Esta directiva se evalúa en el momento de procesar la
        configuración, no en tiempo de ejecución. Por ello, esta
        directiva no se puede evaluar condicionalmente encerrándola
        en una sección <directive type="section" module="core"
        >If</directive>.</p>
    </note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ErrorDocument</name>
<description>What the server will return to the client
in case of an error</description>
<syntax>ErrorDocument <var>error-code</var> <var>document</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>FileInfo</override>

<usage>
    <p>En caso de un problema o error, Apache httpd se puede
    configurar para hacer una de cuatro cosas:</p>

    <ol>
      <li>mostrar un mensaje de error simple y fijo</li>

      <li>mostrar un mensaje personalizado</li>

      <li>redirigir internamente a una <var>ruta-URL</var> local para
      gestionar el problema/error</li>

      <li>redirigir a una <var>URL</var> externa para gestionar el
      problema/error</li>
    </ol>

    <p>La primera opción es la de por defecto, mientras que las
    opciones 2 a 4 se configuran usando la directiva
    <directive>ErrorDocument</directive>, a la que sigue el código de
    respuesta HTTP y una URL o un mensaje. Apache httpd a veces
    ofrecerá información adicional sobre el problema/error.</p>

    <p>A partir de la versión 2.4.13, se puede usar la
    <a href="../expr.html">sintaxis de expresiones</a> dentro de la
    directiva para producir cadenas y URLs dinámicas.</p>

    <p>Las URLs pueden comenzar con una barra (/) para rutas web
    locales (relativas a <directive module="core">DocumentRoot</directive>),
    o ser una URL completa que el cliente pueda resolver. Como
    alternativa, se puede proporcionar un mensaje para que lo muestre
    el navegador. Tenga en cuenta que decidir si el parámetro es una
    URL, una ruta o un mensaje se hace antes de analizar cualquier
    expresión. Ejemplos:</p>

    <highlight language="config">
ErrorDocument 500 http://example.com/cgi-bin/server-error.cgi
ErrorDocument 404 /errors/bad_urls.php
ErrorDocument 401 /subscription_info.html
ErrorDocument 403 "Sorry, can't allow you access today"
ErrorDocument 403 Forbidden!
ErrorDocument 403 /errors/forbidden.py?referrer=%{escape:%{HTTP_REFERER}}
    </highlight>

    <p>Cuando el argumento es una cadena de texto (es decir, no una
    ruta o URL), se envía al cliente con un tipo de contenido
    <code>text/html</code>, así que puede incluir marcado HTML. Puede
    usar el carácter de continuación de línea con barra invertida
    para repartir el documento en varias líneas:</p>

    <highlight language="config">
ErrorDocument 403 "\
&lt;html&gt;&lt;head&gt;\
&lt;title&gt;403 Forbidden&lt;/title&gt;\
&lt;/head&gt;&lt;body&gt;\
&lt;h1&gt;Forbidden&lt;/h1&gt;\
&lt;p&gt;You do not have permission to access this resource.&lt;/p&gt;\
&lt;/body&gt;&lt;/html&gt;"
    </highlight>

    <p>Además, se puede usar el valor especial <code>default</code>
    para indicar el mensaje simple y fijo de Apache httpd. Aunque no
    es necesario en circunstancias normales, <code>default</code>
    restablecerá el mensaje simple y fijo de Apache httpd para
    configuraciones que de otro modo heredarían un
    <directive>ErrorDocument</directive> ya existente.</p>

    <highlight language="config">
ErrorDocument 404 /cgi-bin/bad_urls.pl

&lt;Directory "/web/docs"&gt;
  ErrorDocument 404 default
&lt;/Directory&gt;
    </highlight>

    <p>Tenga en cuenta que cuando especifica un
    <directive>ErrorDocument</directive> que apunta a una URL remota
    (es decir, cualquier cosa con un método como <code>http</code>
    por delante), Apache HTTP Server enviará una redirección al
    cliente para indicarle dónde encontrar el documento, incluso si el
    documento termina estando en el mismo servidor. Esto tiene varias
    implicaciones; la más importante es que el cliente no recibirá el
    código de estado de error original, sino que recibirá un código
    de estado de redirección. Esto, a su vez, puede confundir a los
    robots web y a otros clientes que intentan determinar si una URL
    es válida usando el código de estado. Además, si usa una URL
    remota en un <code>ErrorDocument 401</code>, el cliente no sabrá
    que debe pedir al usuario una contraseña, ya que no recibirá el
    código de estado 401. Por lo tanto, <strong>si usa una directiva
    <code>ErrorDocument 401</code>, debe hacer referencia a un
    documento local.</strong></p>

    <p>Aunque la mayoría de los mensajes de error se pueden
    sobrescribir, hay ciertas circunstancias en las que se usan los
    mensajes internos independientemente del ajuste de
    <directive module="core">ErrorDocument</directive>. En particular,
    si se detecta una petición mal formada, el procesamiento normal de
    la petición se detiene de inmediato y se devuelve el mensaje de
    error interno. Esto es necesario para protegerse de problemas de
    seguridad causados por peticiones incorrectas.</p>

    <p>Si está usando mod_proxy, puede que quiera activar
    <directive module="mod_proxy">ProxyErrorOverride</directive> para
    poder proporcionar mensajes de error personalizados en nombre de
    sus servidores de origen. Si no activa ProxyErrorOverride, Apache
    httpd no generará documentos de error personalizados para el
    contenido a través de proxy.</p>
</usage>

<seealso><a href="../custom-error.html">documentation of
    customizable responses</a></seealso>
</directivesynopsis>

<directivesynopsis>
<name>ErrorLog</name>
<description>Ubicación donde el servidor registrará los errores</description>
<syntax> ErrorLog <var>file-path</var>|syslog[:[<var>facility</var>][:<var>tag</var>]]</syntax>
<default>ErrorLog logs/error_log (Unix) ErrorLog logs/error.log (Windows y OS/2)</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive>ErrorLog</directive> establece el
    nombre del fichero en el que el servidor registrará cualquier
    error que encuentre. Si <var>file-path</var> no es absoluta, se
    asume que es relativa a <directive module="core">ServerRoot</directive>.</p>

    <highlight language="config">
ErrorLog "/var/log/httpd/error_log"
    </highlight>

    <p>Si <var>file-path</var> empieza con el carácter barra vertical
    "<code>|</code>", se asume que es un comando que se debe lanzar
    para gestionar el registro de errores.</p>

    <highlight language="config">
ErrorLog "|/usr/local/bin/httpd_errors"
    </highlight>

    <p>Consulte las notas sobre <a href="../logs.html#piped">registros
    por tubería</a> para más información.</p>

    <p>Usar <code>syslog</code> en lugar de un nombre de fichero
    habilita el registro a través de syslogd(8) si el sistema lo
    soporta y si <module>mod_syslog</module> está cargado. Por
    defecto se usa la categoría (facility) de syslog
    <code>local7</code>, pero puede cambiarla usando la sintaxis
    <code>syslog:<var>facility</var></code>, donde <var>facility</var>
    puede ser uno de los nombres documentados habitualmente en
    syslog(1). La categoría es, en la práctica, global, y si se
    cambia en hosts virtuales concretos, la última categoría
    especificada afecta a todo el servidor. Se aplican las mismas
    reglas a la etiqueta de syslog, que por defecto usa el nombre del
    binario de Apache, <code>httpd</code> en la mayoría de los casos.
    También puede cambiarla usando la sintaxis
    <code>syslog::<var>tag</var></code>.</p>

    <highlight language="config">
ErrorLog syslog:user
ErrorLog syslog:user:httpd.srv1
ErrorLog syslog::httpd.srv2
    </highlight>

    <p>Otros módulos pueden proporcionar sus propios proveedores de
    ErrorLog. La sintaxis es similar al ejemplo de <code>syslog</code>
    anterior.</p>

    <p>SEGURIDAD: Consulte el documento <a
    href="../misc/security_tips.html#serverroot">consejos de
    seguridad</a> para obtener detalles sobre por qué su seguridad
    podría verse comprometida si el directorio donde se almacenan los
    ficheros de registro puede ser escrito por alguien distinto del
    usuario que arranca el servidor.</p>
    <note type="warning"><title>Nota</title>
      <p>Al introducir una ruta de fichero en plataformas distintas de
      Unix, se debe tener cuidado de usar solo barras inclinadas
      hacia delante, aunque la plataforma permita el uso de barras
      invertidas. En general, es buena idea usar siempre barras
      inclinadas hacia delante en los ficheros de configuración.</p>
    </note>
</usage>
<seealso><directive module="core">LogLevel</directive></seealso>
<seealso><a href="../logs.html">Ficheros de registro de Apache HTTP
    Server</a></seealso>
</directivesynopsis>

<directivesynopsis>
<name>ErrorLogFormat</name>
<description>Especificación del formato de las entradas del log de
errores</description>
<syntax> ErrorLogFormat [connection|request] <var>formato</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p><directive>ErrorLogFormat</directive> permite especificar qué
    información adicional se registra en el log de errores además del
    mensaje de registro en sí.</p>

    <highlight language="config">
#Ejemplo sencillo
ErrorLogFormat "[%t] [%l] [pid %P] %F: %E: [client %a] %M"
    </highlight>

    <p>Especificar <code>connection</code> o <code>request</code> como
    primer parámetro permite especificar formatos adicionales, de
    manera que se registre información adicional cuando se registra el
    primer mensaje para una conexión o petición concreta,
    respectivamente. Esta información adicional solo se registra una
    vez por conexión/petición. Si una conexión o petición se procesa
    sin generar ningún mensaje de registro, la información adicional
    tampoco se registra.</p>

    <p>Puede ocurrir que algunos especificadores de formato no
    produzcan salida. Por ejemplo, la cabecera Referer solo está
    presente si el mensaje de registro está asociado a una petición y
    el mensaje de registro ocurre en un momento en que la cabecera
    Referer ya se ha leído del cliente. Si no se produce ninguna
    salida, el comportamiento por defecto es eliminar todo lo que haya
    entre el carácter de espacio anterior y el siguiente carácter de
    espacio. Esto significa que la cadena de formato se divide
    implícitamente en campos en las transiciones de no-espacio a
    espacio. Si un especificador de formato no produce salida, se omite
    el campo completo. Por ejemplo, si la dirección remota
    <code>%a</code> en el formato de registro
    <code>[%t] [%l] [%a] %M&nbsp;</code> no está disponible, los
    corchetes que la rodean tampoco se registran. Los caracteres de
    espacio se pueden escapar con una barra invertida para evitar que
    delimiten un campo. La combinación '%&nbsp;' (porcentaje espacio)
    es un delimitador de campo de ancho cero que no produce ninguna
    salida.</p>

    <p>El comportamiento anterior se puede cambiar añadiendo
    modificadores al elemento de la cadena de formato. Un modificador
    <code>-</code> (menos) hace que se registre un guion si el elemento
    correspondiente no produce ninguna salida. En los formatos de una
    vez por conexión/petición, también es posible usar el modificador
    <code>+</code> (más). Si un elemento con el modificador más no
    produce ninguna salida, se omite la línea completa.</p>

    <p>Un número como modificador se puede usar para asignar un nivel
    de severidad de registro a un elemento de formato. El elemento
    solo se registrará si el mensaje de registro tiene un nivel de
    severidad igual o más severo que el número especificado (es decir,
    el número de nivel del mensaje es menor o igual que el
    modificador). El número puede ir de 1 (alert), pasando por 4
    (warn) y 7 (debug), hasta 15 (trace8).</p>

    <p>Por ejemplo, esto es lo que ocurriría si añadiera modificadores
    al token <code>%{Referer}i</code>, que registra la cabecera de
    petición <code>Referer</code>.</p>

    <table border="1" style="zebra">
    <columnspec><column width=".3"/><column width=".7"/></columnspec>

    <tr><th>Token Modificado</th><th>Significado</th></tr>

    <tr>
    <td><code>%-{Referer}i</code></td>
    <td>Registra un <code>-</code> si <code>Referer</code> no está
    establecido.</td>
    </tr>

    <tr>
    <td><code>%+{Referer}i</code></td>
    <td>Omite toda la línea si <code>Referer</code> no está
    establecido.</td>
    </tr>

    <tr>
    <td><code>%4{Referer}i</code></td>
    <td>Registra <code>Referer</code> solo si la severidad del mensaje
    de registro es 4 (warn) o más severa (es decir, niveles 1 a 4:
    alert, crit, error, warn).</td>
    </tr>

    </table>

    <p>Algunos especificadores de formato aceptan parámetros
    adicionales entre llaves.</p>

    <table border="1" style="zebra">
    <columnspec><column width=".2"/><column width=".8"/></columnspec>

    <tr><th>Cadena de&nbsp;Formato</th> <th>Descripción</th></tr>

    <tr><td><code>%%</code></td>
        <td>El signo de porcentaje</td></tr>

    <tr><td><code>%a</code></td>
        <td>Dirección IP y puerto del cliente de la petición</td></tr>

    <tr><td><code>%{c}a</code></td>
        <td>Dirección IP y puerto del peer subyacente de la conexión
            (consulte el módulo <module>mod_remoteip</module>)</td></tr>

    <tr><td><code>%A</code></td>
        <td>Dirección IP y puerto locales</td></tr>

    <tr><td><code>%{<em>nombre</em>}e</code></td>
        <td>Variable de entorno <em>nombre</em> de la petición</td></tr>

    <tr><td><code>%E</code></td>
        <td>Código de estado de error de APR/OS y su cadena</td></tr>

    <tr><td><code>%F</code></td>
        <td>Nombre del fichero fuente y número de línea de la llamada
            de registro</td></tr>

    <tr><td><code>%{<em>nombre</em>}i</code></td>
        <td>Cabecera de petición <em>nombre</em></td></tr>

    <tr><td><code>%k</code></td>
        <td>Número de peticiones keep-alive en esta conexión</td></tr>

    <tr><td><code>%l</code></td>
        <td>Nivel de registro del mensaje</td></tr>

    <tr><td><code>%L</code></td>
        <td>ID de registro de la petición</td></tr>

    <tr><td><code>%{c}L</code></td>
        <td>ID de registro de la conexión</td></tr>

    <tr><td><code>%{C}L</code></td>
        <td>ID de registro de la conexión si se usa en el ámbito de
            conexión; vacío en caso contrario</td></tr>

    <tr><td><code>%m</code></td>
        <td>Nombre del módulo que registra el mensaje</td></tr>

    <tr><td><code>%M</code></td>
        <td>El mensaje de registro en sí</td></tr>

    <tr><td><code>%{<em>nombre</em>}n</code></td>
        <td>Nota de petición <em>nombre</em></td></tr>

    <tr><td><code>%P</code></td>
        <td>ID del proceso actual</td></tr>

    <tr><td><code>%T</code></td>
        <td>ID del hilo actual</td></tr>

    <tr><td><code>%{g}T</code></td>
        <td>ID de hilo único del sistema para el hilo actual (el mismo
            ID que muestra, por ejemplo, <code>top</code>; actualmente
            solo en Linux)</td></tr>

    <tr><td><code>%t</code></td>
        <td>La hora actual</td></tr>

    <tr><td><code>%{u}t</code></td>
        <td>La hora actual incluyendo microsegundos</td></tr>

    <tr><td><code>%{m}t</code></td>
        <td>La hora actual incluyendo milisegundos</td></tr>

    <tr><td><code>%{cu}t</code></td>
        <td>La hora actual en formato ISO 8601 extendido (compacto),
            incluyendo microsegundos</td></tr>

    <tr><td><code>%{cuz}t</code></td>
        <td>La hora actual en formato ISO 8601 extendido (compacto),
            incluyendo microsegundos y la zona horaria en el formato
            estándar ISO 8601:2000. Disponible solo desde la versión
            2.4.58</td></tr>

    <tr><td><code>%{%-format}t</code></td>
	<td>La hora actual con el formato de la función
	    <code>strftime(3)</code>. Disponible solo desde la versión
	    2.4.58</td></tr>

    <tr><td><code>%v</code></td>
        <td>El <directive module="core">ServerName</directive> canónico
            del servidor actual.</td></tr>

    <tr><td><code>%V</code></td>
        <td>El nombre del servidor que atiende la petición según el
            ajuste de <directive module="core" >UseCanonicalName</directive>.</td></tr>

    <tr><td><code>\&nbsp;</code> (barra invertida espacio)</td>
        <td>Espacio que no delimita campo</td></tr>

    <tr><td><code>%&nbsp;</code> (porcentaje espacio)</td>
        <td>Delimitador de campo (sin salida)</td></tr>
    </table>

    <p>El formato de ID de registro <code>%L</code> produce un
    identificador único para una conexión o petición. Esto se puede
    usar para correlacionar qué líneas de registro pertenecen a la
    misma conexión o petición, y en qué conexión ocurre cada petición.
    También hay disponible una cadena de formato <code>%L</code> en
    <module>mod_log_config</module> para permitir correlacionar las
    entradas del log de accesos con las líneas del log de errores. Si
    <module>mod_unique_id</module> está cargado, se usará su
    identificador único como ID de registro de las peticiones.</p>

    <highlight language="config">
#Ejemplo (formato por defecto para los MPM basados en hilos)
ErrorLogFormat "[%{u}t] [%-m:%l] [pid %P:tid %T] %7F: %E: [client\ %a] %M%&nbsp;,\&nbsp;referer\&nbsp;%{Referer}i"
    </highlight>

    <p>Esto daría como resultado mensajes de error como:</p>

    <example>
    [Thu May 12 08:28:57.652118 2011] [core:error] [pid 8777:tid 4326490112] [client ::1:58619] AH00124: Request exceeded the limit of 10 internal redirects due to probable configuration error
    </example>

    <p>Observe que, como se comentó anteriormente, algunos campos se
    omiten por completo porque no están definidos.</p>

    <highlight language="config">
#Ejemplo (similar al formato de la serie 2.2.x)
ErrorLogFormat "[%t] [%l] %7F: %E: [client\ %a] %M%&nbsp;,\&nbsp;referer\&nbsp;%{Referer}i"
    </highlight>

    <highlight language="config">
#Ejemplo avanzado con ID de registro de petición/conexión
ErrorLogFormat "[%{uc}t] [%-m:%-l] [R:%L] [C:%{C}L] %7F: %E: %M"
ErrorLogFormat request "[%{uc}t] [R:%L] Request %k on C:%{c}L pid:%P tid:%T"
ErrorLogFormat request "[%{uc}t] [R:%L] UA:'%+{User-Agent}i'"
ErrorLogFormat request "[%{uc}t] [R:%L] Referer:'%+{Referer}i'"
ErrorLogFormat connection "[%{uc}t] [C:%{c}L] remote\ %a local\ %A"
    </highlight>

</usage>
<seealso><directive module="core">ErrorLog</directive></seealso>
<seealso><directive module="core">LogLevel</directive></seealso>
<seealso><a href="../logs.html">Ficheros de Log de Apache HTTP Server</a></seealso>
</directivesynopsis>

<directivesynopsis>
<name>ExtendedStatus</name>
<description>Mantiene información de estado extendido para cada
petición</description>
<syntax>ExtendedStatus On|Off</syntax>
<default>ExtendedStatus Off[*]</default>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>Esta opción registra datos adicionales por proceso de trabajo
    sobre la petición que se está ejecutando en cada momento y crea un
    resumen de utilización. Puede ver estas variables en tiempo de
    ejecución configurando <module>mod_status</module>. Tenga en
    cuenta que otros módulos pueden depender de este marcador de
    estado (scoreboard).</p>

    <p>Este ajuste se aplica a todo el servidor y no se puede
    habilitar o deshabilitar host virtual por host virtual. La
    recopilación de información de estado extendido puede ralentizar
    el servidor. Tenga en cuenta también que este ajuste no se puede
    cambiar durante un reinicio ordenado (graceful restart).</p>

    <note>
    <p>Tenga en cuenta que cargar <module>mod_status</module>
    cambiará el comportamiento por defecto a ExtendedStatus On,
    y otros módulos de terceros pueden hacer lo mismo. Estos módulos
    dependen de recopilar información detallada sobre el estado de
    todos los procesos de trabajo. El valor por defecto es cambiado
    por <module>mod_status</module> desde la versión 2.3.6. El valor
    por defecto anterior siempre era Off.</p>
    </note>

</usage>

</directivesynopsis>

<directivesynopsis>
<name>FileETag</name>
<description>Atributos de fichero usados para crear la cabecera de
respuesta HTTP ETag en ficheros estáticos</description>
<syntax>FileETag <var>component</var> ...</syntax>
<default>FileETag MTime Size</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>FileInfo</override>
<compatibility>El valor por defecto era "INode&nbsp;MTime&nbsp;Size" en la
versión 2.3.14 y anteriores.</compatibility>

<usage>
    <p>
    La directiva <directive>FileETag</directive> configura los
    atributos de fichero que se usan para crear el campo de cabecera
    de respuesta <code>ETag</code> (entity tag) cuando el documento
    se basa en un fichero estático. (El valor de <code>ETag</code> se
    usa en la gestión de la caché para ahorrar ancho de banda de red.)
    La directiva <directive>FileETag</directive> le permite elegir
    cuáles de ellos -- si alguno -- se deben usar. Las palabras clave
    reconocidas son:
    </p>

    <dl>
     <dt><strong>INode</strong></dt>
     <dd>El número de i-node del fichero se incluirá en el cálculo</dd>
     <dt><strong>MTime</strong></dt>
     <dd>Se incluirá la fecha y hora de la última modificación del fichero</dd>
     <dt><strong>Size</strong></dt>
     <dd>Se incluirá el número de bytes del fichero</dd>
     <dt><strong>All</strong></dt>
     <dd>Se usarán todos los campos disponibles. Esto es equivalente a:
         <highlight language="config">
FileETag INode MTime Size
         </highlight></dd>
     <dt><strong>Digest</strong></dt>
     <dd>Si un documento se basa en un fichero, el campo
       <code>ETag</code> se calculará obteniendo el resumen (digest)
       del fichero.</dd>
     <dt><strong>None</strong></dt>
     <dd>Si un documento se basa en un fichero, no se incluirá ningún
       campo <code>ETag</code> en la respuesta</dd>
    </dl>

    <p>Las palabras clave <code>INode</code>, <code>MTime</code>,
    <code>Size</code> y <code>Digest</code> se pueden prefijar con
    <code>+</code> o <code>-</code>, lo que permite modificar el
    ajuste por defecto heredado de un ámbito más amplio. Cualquier
    palabra clave que aparezca sin ese prefijo cancela de inmediato y
    por completo el ajuste heredado.</p>

    <p>Si la configuración de un directorio incluye
    <code>FileETag&nbsp;INode&nbsp;MTime&nbsp;Size</code>, y la de un
    subdirectorio incluye <code>FileETag&nbsp;-INode</code>, el ajuste
    de ese subdirectorio (que heredarán los subdirectorios que no lo
    anulen) será equivalente a
    <code>FileETag&nbsp;MTime&nbsp;Size</code>.</p>
    <note><title>Server Side Includes</title>
    No se genera un ETag para las respuestas procesadas por
    <module>mod_include</module>, ya que la entidad de la respuesta
    puede cambiar sin que cambien el INode, MTime, Size o Digest del
    fichero estático con directivas SSI incrustadas.
    </note>

</usage>
</directivesynopsis>

<directivesynopsis type="section">
<name>Files</name>
<description>Contains directives that apply to matched
filenames</description>
<syntax>&lt;Files <var>filename</var>&gt; ... &lt;/Files&gt;</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>All</override>

<usage>
    <p>La directiva <directive type="section">Files</directive>
    limita el ámbito de las directivas que contiene por nombre de
    fichero. Es comparable a las directivas
    <directive module="core" type="section">Directory</directive> y
    <directive module="core" type="section">Location</directive>.
    Debe cerrarse con una directiva <code>&lt;/Files&gt;</code>. Las
    directivas que se den dentro de esta sección se aplicarán a
    cualquier objeto cuyo nombre base (el último componente del
    nombre de fichero) coincida con el nombre de fichero
    especificado. Las secciones <directive type="section">Files</directive>
    se procesan en el orden en que aparecen en el fichero de
    configuración, después de que se lean las secciones
    <directive module="core" type="section">Directory</directive> y
    los ficheros <code>.htaccess</code>, pero antes de las secciones
    <directive type="section" module="core">Location</directive>.
    Tenga en cuenta que <directive type="section">Files</directive>
    se puede anidar dentro de secciones <directive type="section"
    module="core">Directory</directive> para restringir la parte del
    sistema de ficheros a la que se aplica.</p>

    <p>El argumento <var>filename</var> debe incluir un nombre de
    fichero, o una cadena con comodines, donde <code>?</code>
    coincide con cualquier carácter individual, y <code>*</code>
    coincide con cualquier secuencia de caracteres.</p>
    <highlight language="config">
&lt;Files "cat.html"&gt;
    # Inserte aquí lo que se aplique a cat.html
&lt;/Files&gt;

&lt;Files "?at.*"&gt;
    # Esto se aplicaría a cat.html, bat.html, hat.php, etc.
&lt;/Files&gt;
    </highlight>
    <p>También se pueden usar <glossary ref="regex">expresiones
    regulares</glossary>, añadiendo el carácter <code>~</code>. Por
    ejemplo:</p>

    <highlight language="config">
&lt;Files ~ "\.(gif|jpe?g|png)$"&gt;
    #...
&lt;/Files&gt;
    </highlight>

    <p>coincidiría con la mayoría de los formatos gráficos habituales
    en Internet. No obstante, se prefiere usar
    <directive module="core" type="section">FilesMatch</directive>.</p>

    <p>Tenga en cuenta que, a diferencia de las secciones
    <directive type="section" module="core">Directory</directive> y
    <directive type="section" module="core">Location</directive>, las
    secciones <directive type="section">Files</directive> se pueden
    usar dentro de ficheros <code>.htaccess</code>. Esto permite a los
    usuarios controlar el acceso a sus propios ficheros, a nivel de
    fichero individual.</p>

</usage>
<seealso><a href="../sections.html">How &lt;Directory&gt;, &lt;Location&gt;
    and &lt;Files&gt; sections work</a> for an explanation of how these
    different sections are combined when a request is received</seealso>
</directivesynopsis>

<directivesynopsis type="section">
<name>FilesMatch</name>
<description>Contains directives that apply to regular-expression matched
filenames</description>
<syntax>&lt;FilesMatch <var>regex</var>&gt; ... &lt;/FilesMatch&gt;</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>All</override>

<usage>
    <p>La directiva <directive type="section">FilesMatch</directive>
    limita el ámbito de las directivas que contiene por nombre de
    fichero, igual que hace la directiva <directive module="core" type="section">Files</directive>.
    Sin embargo, acepta una <glossary ref="regex">expresión
    regular</glossary>. Por ejemplo:</p>

    <highlight language="config">
&lt;FilesMatch ".+\.(gif|jpe?g|png)$"&gt;
    # ...
&lt;/FilesMatch&gt;
    </highlight>

    <p>coincidiría con la mayoría de los formatos gráficos habituales
    en Internet.</p>

    <note>El <code>.+</code> al principio de la expresión regular
    garantiza que no coincidan ficheros llamados, por ejemplo,
    <code>.png</code> o <code>.gif</code>.</note>

    <p>A partir de la versión 2.4.8, los grupos con nombre y las
    referencias hacia atrás se capturan y se escriben en el entorno
    con el nombre correspondiente prefijado con "MATCH_" y en
    mayúsculas. Esto permite hacer referencia a elementos de los
    ficheros desde <a href="../expr.html">expresiones</a> y módulos
    como <module>mod_rewrite</module>. Para evitar confusiones, las
    referencias hacia atrás numeradas (sin nombre) se ignoran. Use
    grupos con nombre en su lugar.</p>

    <highlight language="config">
&lt;FilesMatch "^(?&lt;sitename&gt;[^/]+)"&gt;
    Require ldap-group cn=%{env:MATCH_SITENAME},ou=combined,o=Example
&lt;/FilesMatch&gt;
    </highlight>
</usage>

<seealso><a href="../sections.html">How &lt;Directory&gt;, &lt;Location&gt;
    and &lt;Files&gt; sections work</a> for an explanation of how these
    different sections are combined when a request is received</seealso>
</directivesynopsis>

<directivesynopsis>
<name>FlushMaxPipelined</name>
<description>Número máximo de respuestas en pipeline por encima del
cual se vuelcan a la red</description>
<syntax>FlushMaxPipelined <var>número</var></syntax>
<default>FlushMaxPipelined 5</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>
<compatibility>2.5 y posteriores</compatibility>

<usage>
    <p>Esta directiva permite configurar el número máximo de respuestas
    en pipeline que permanecen pendientes mientras se sigan recibiendo
    peticiones en pipeline. Cuando se alcanza el límite, las respuestas
    se vuelcan a la red de forma forzosa en modo bloqueante, hasta volver
    a estar por debajo del límite.</p>

    <p><directive>FlushMaxPipelined</directive> ayuda a limitar el uso de
    memoria. Cuando se establece a <code>0</code> el pipelining se
    desactiva; cuando se establece a <code>-1</code> no hay límite
    (<directive module="core">FlushMaxThreshold</directive> sigue
    aplicándose).</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>FlushMaxThreshold</name>
<description>Umbral por encima del cual los datos pendientes se vuelcan
a la red</description>
<syntax>FlushMaxThreshold <var>número-de-bytes</var></syntax>
<default>FlushMaxThreshold 65535</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>
<compatibility>2.5 y posteriores</compatibility>

<usage>
    <p>Esta directiva permite configurar el umbral de datos de salida
    pendientes (en bytes). Cuando se alcanza el límite, los datos se
    vuelcan a la red de forma forzosa en modo bloqueante, hasta volver a
    estar por debajo del límite.</p>

    <p><directive>FlushMaxThreshold</directive> ayuda a limitar el uso de
    memoria. Cuando se establece a <code>0</code> o a un valor demasiado
    pequeño, en realidad no hay datos pendientes, pero en los MPM basados
    en hilos puede haber más hilos ocupados esperando a la red y, por
    tanto, menos disponibles para atender las demás conexiones
    simultáneas.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ForceType</name>
<description>Fuerza a que todos los ficheros coincidentes se sirvan
con el tipo de medio especificado en el campo de cabecera HTTP
Content-Type</description>
<syntax>ForceType <var>tipo-de-medio</var>|None</syntax>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>FileInfo</override>

<usage>
    <p>Cuando se coloca en un fichero <code>.htaccess</code> o en una
    sección <directive type="section" module="core">Directory</directive>,
    <directive type="section" module="core">Location</directive> o
    <directive type="section" module="core">Files</directive>, esta
    directiva fuerza a que todos los ficheros coincidentes se sirvan
    con la identificación de tipo de contenido dada por
    <var>tipo-de-medio</var>. Por ejemplo, si tuviera un directorio
    lleno de ficheros GIF, pero no quisiera etiquetarlos todos con
    <code>.gif</code>, podría usar:</p>

    <highlight language="config">
ForceType image/gif
    </highlight>

    <p>Tenga en cuenta que esta directiva sobrescribe otras
    asociaciones de tipo de medio indirectas definidas en mime.types
    o mediante <directive module="mod_mime">AddType</directive>.</p>

    <p>También puede sobrescribir ajustes más generales de
    <directive>ForceType</directive> usando el valor
    <code>None</code>:</p>

    <highlight language="config">
# forzar a que todos los ficheros sean image/gif:
&lt;Location "/images"&gt;
  ForceType image/gif
&lt;/Location&gt;

# pero las asociaciones mime-type normales aquí:
&lt;Location "/images/mixed"&gt;
  ForceType None
&lt;/Location&gt;
    </highlight>

    <p>Esta directiva sobrescribe principalmente los tipos de
    contenido generados para los ficheros estáticos servidos desde el
    sistema de ficheros. Para recursos distintos de los ficheros
    estáticos, donde el generador de la respuesta normalmente
    especifica un Content-Type, esta directiva no tiene ningún
    efecto.</p>


    <note><title>Nota</title>
    <p>Si no se establece explícitamente ningún manejador para una
    petición, el tipo de contenido especificado también se usará como
    nombre del manejador.</p>

    <p>Cuando directivas explícitas como
    <directive module="core" >SetHandler</directive> o
    <directive module="mod_mime">AddHandler</directive> no se aplican
    a la petición actual, el nombre interno del manejador que
    normalmente establecen esas directivas se establece en su lugar
    al tipo de contenido especificado por esta directiva.
    </p>
    <p>
    Este es un comportamiento histórico que algunos módulos de
    terceros (como mod_php) pueden usar: un tipo de contenido
    "sintético" empleado únicamente para indicar al módulo que se
    haga responsable de la petición coincidente.
    </p>

    <p>Deben evitarse las configuraciones que dependan de este tipo
    de tipos "sintéticos". Además, las configuraciones que restringen
    el acceso a <directive module="core" >SetHandler</directive> o a
    <directive module="mod_mime">AddHandler</directive> deberían
    restringir también el acceso a esta directiva.</p>
    </note>

</usage>
</directivesynopsis>
<directivesynopsis>
<name>GprofDir</name>
<description>Directorio en el que escribir los datos de perfilado
gmon.out.  </description>
<syntax>GprofDir <var>/tmp/gprof/</var>|<var>/tmp/gprof/</var>%</syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>Cuando el servidor se ha compilado con soporte de perfilado
    gprof, <directive>GprofDir</directive> hace que se escriban
    ficheros <code>gmon.out</code> en el directorio especificado
    cuando el proceso termina. Si el argumento acaba en un símbolo de
    porcentaje ('%'), se crean subdirectorios para cada identificador
    de proceso.</p>

    <p>Esta directiva, por el momento, solo funciona con el MPM
    <module>prefork</module>.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>HostnameLookups</name>
<description>Habilita las resoluciones DNS de las direcciones IP de
los clientes</description>
<syntax>HostnameLookups On|Off|Double</syntax>
<default>HostnameLookups Off</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>

<usage>
    <p>Esta directiva habilita las resoluciones DNS de forma que se
    puedan registrar los nombres de host (y pasarlos a los CGIs/SSIs
    en <code>REMOTE_HOST</code>). El valor <code>Double</code> hace
    referencia a realizar una resolución DNS inversa doble. Es decir,
    después de realizar una resolución inversa, se realiza una
    resolución directa sobre ese resultado. Al menos una de las
    direcciones IP de la resolución directa debe coincidir con la
    dirección original. (En la terminología de "tcpwrappers" esto se
    llama <code>PARANOID</code>.)</p>

    <p>Independientemente del ajuste, cuando <module>mod_authz_host</module>
    se usa para controlar el acceso por nombre de host, se realizará
    una resolución inversa doble. Esto es necesario por seguridad.
    Tenga en cuenta que el resultado de esta doble resolución inversa
    no está disponible en general a menos que establezca
    <code>HostnameLookups Double</code>. Por ejemplo, si solo tiene
    <code>HostnameLookups On</code> y se hace una petición a un objeto
    protegido por restricciones de nombre de host, independientemente
    de que la resolución inversa doble falle o no, a los CGIs se les
    seguirá pasando el resultado de la resolución inversa simple en
    <code>REMOTE_HOST</code>.</p>

    <p>El valor por defecto es <code>Off</code> para ahorrar tráfico
    de red en aquellos sitios que realmente no necesitan hacer las
    resoluciones inversas. También es mejor para los usuarios finales,
    porque no tienen que sufrir la latencia adicional que implica una
    resolución. Los sitios con mucha carga deberían dejar esta
    directiva en <code>Off</code>, ya que las resoluciones DNS pueden
    llevar bastante tiempo. La utilidad <program>logresolve</program>,
    compilada por defecto en el subdirectorio <code>bin</code> de su
    directorio de instalación, se puede usar para resolver los
    nombres de host a partir de las direcciones IP registradas, de
    forma asíncrona (offline).</p>

    <p>Por último, si tiene <a
    href="mod_authz_host.html#reqhost">directivas Require basadas en
    nombre de host</a>, se realizará una resolución de nombre de
    host independientemente del ajuste de
    <directive>HostnameLookups</directive>.</p>
</usage>
</directivesynopsis>

<directivesynopsis type="section">
<name>If</name>
<description>Contiene directivas que se aplican solo si se cumple una
condición en una petición en tiempo de ejecución</description>
<syntax>&lt;If <var>expresión</var>&gt; ... &lt;/If&gt;</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>All</override>
<compatibility>Las condiciones anidadas se evalúan a partir de la
versión 2.4.26</compatibility>

<usage>
    <p>La directiva de sección <directive type="section">If</directive>
    evalúa una expresión en tiempo de ejecución, y aplica las
    directivas que contiene si y solo si la expresión se evalúa como
    verdadera. Por ejemplo:</p>

    <highlight language="config">
&lt;If "-z req('Host')"&gt;
    </highlight>

    <p>coincidiría con las peticiones HTTP/1.0 sin cabecera
    <var>Host:</var>. Las expresiones pueden contener varios
    operadores de tipo shell para comparación de cadenas
    (<code>==</code>, <code>!=</code>, <code>&lt;</code>, ...),
    comparación de enteros (<code>-eq</code>, <code>-ne</code>, ...),
    y otros (<code>-n</code>, <code>-z</code>, <code>-f</code>, ...).
    También es posible usar expresiones regulares,</p>

    <highlight language="config">
&lt;If "%{QUERY_STRING} =~ /(delete|commit)=.*?elem/"&gt;
    </highlight>

    <p>coincidencias de patrones de tipo shell y muchas otras
    operaciones. Estas operaciones se pueden realizar sobre cabeceras
    de petición (<code>req</code>), variables de entorno
    (<code>env</code>), y un gran número de otras propiedades. La
    documentación completa está disponible en
    <a href="../expr.html">Expresiones en Apache HTTP Server</a>.</p>

    <p>Solo se pueden usar en esta sección de configuración las
    directivas que soportan el
    <a href="directive-dict.html#Context">contexto de directorio</a>.</p>

    <note type="warning">
    Ciertas variables, como <code>CONTENT_TYPE</code> y otras
    cabeceras de respuesta, se establecen después de que las
    condiciones de &lt;If&gt; ya se hayan evaluado, por lo que no
    estarán disponibles para usarse en esta directiva.
    </note>

    <note type="warning">
    Las directivas que tienen efecto durante el análisis de la
    configuración, como <directive>Define</directive>,
    <directive>Include</directive>, y <directive>Error</directive>,
    no se pueden hacer condicionales encerrándolas en una sección de
    configuración <directive type="section">If</directive>. Estas
    secciones siempre forman parte de la configuración,
    independientemente de cómo se evalúen en tiempo de ejecución.
    </note>


</usage>

<seealso><a href="../expr.html">Expressions in Apache HTTP Server</a>,
for a complete reference and more examples.</seealso>
<seealso><directive type="section" module="core">ElseIf</directive></seealso>
<seealso><directive type="section" module="core">Else</directive></seealso>
<seealso><a href="../sections.html">How &lt;Directory&gt;, &lt;Location&gt;,
    &lt;Files&gt; sections work</a> for an explanation of how these
    different sections are combined when a request is received.
    <directive type="section">If</directive>,
    <directive type="section">ElseIf</directive>, and
    <directive type="section">Else</directive> are applied last.</seealso>
</directivesynopsis>

<directivesynopsis type="section">
<name>IfDefine</name>
<description>Encierra directivas que solo se procesarán si una
condición es verdadera en el arranque</description>
<syntax>&lt;IfDefine [!]<var>parameter-name</var>&gt; ...
    &lt;/IfDefine&gt;</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>All</override>

<usage>
    <p>La sección <code>&lt;IfDefine <var>test</var>&gt;...&lt;/IfDefine&gt;
    </code> se usa para marcar directivas condicionales. Las
    directivas dentro de una sección <directive
    type="section">IfDefine</directive> solo se procesan si
    <var>test</var> es verdadero. Si <var>test</var> es falso, todo
    lo que hay entre las marcas de inicio y fin se ignora.</p>

    <p><var>test</var> en la directiva de sección <directive
    type="section">IfDefine</directive> puede tener una de estas dos
    formas:</p>

    <ul>
      <li><var>parameter-name</var></li>

      <li><code>!</code><var>parameter-name</var></li>
    </ul>

    <p>En el primer caso, las directivas entre las marcas de inicio y
    fin solo se procesan si el parámetro llamado
    <var>parameter-name</var> está definido. El segundo formato
    invierte la condición, y solo procesa las directivas si
    <var>parameter-name</var> <strong>no</strong> está definido.</p>

    <p>El argumento <var>parameter-name</var> es una definición dada
    en la línea de comandos de <program>httpd</program> mediante
    <code>-D<var>parameter</var></code> en el momento en que se
    arrancó el servidor, o mediante la directiva <directive
    module="core">Define</directive>.</p>

    <p>Las secciones <directive type="section">IfDefine</directive>
    se pueden anidar, lo que se puede usar para implementar pruebas
    sencillas con varios parámetros. Ejemplo:</p>

    <example>httpd -DReverseProxy -DUseCache -DMemCache ...</example>
    <highlight language="config">
&lt;IfDefine ReverseProxy&gt;
  LoadModule proxy_module   modules/mod_proxy.so
  LoadModule proxy_http_module   modules/mod_proxy_http.so
  &lt;IfDefine UseCache&gt;
    LoadModule cache_module   modules/mod_cache.so
    &lt;IfDefine MemCache&gt;
      LoadModule mem_cache_module   modules/mod_mem_cache.so
    &lt;/IfDefine&gt;
    &lt;IfDefine !MemCache&gt;
      LoadModule cache_disk_module   modules/mod_cache_disk.so
    &lt;/IfDefine&gt;
  &lt;/IfDefine&gt;
&lt;/IfDefine&gt;
    </highlight>
</usage>
</directivesynopsis>

<directivesynopsis type="section">
<name>IfFile</name>
<description>Encierra directivas que solo se procesarán si el fichero
existe en el arranque</description>
<syntax>&lt;IfFile [!]<var>nombre-de-parámetro</var>&gt; ...
    &lt;/IfFile&gt;</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>All</override>
<compatibility>Disponible a partir de la versión 2.4.34</compatibility>

<usage>
    <p>La sección <code>&lt;IfFile <var>nombre-de-fichero</var>&gt;...&lt;/IfFile&gt;
    </code> se usa para marcar directivas que son condicionales a la
    existencia de un fichero en disco. Las directivas dentro de una
    sección <directive type="section">IfFile</directive> solo se
    procesan si <var>nombre-de-fichero</var> existe. Si
    <var>nombre-de-fichero</var> no existe, todo lo que hay entre las
    marcas de inicio y fin se ignora. <var>nombre-de-fichero</var> puede
    ser una ruta absoluta o una ruta relativa a la raíz del servidor.</p>

    <p><var>nombre-de-fichero</var> en la directiva de sección
    <directive type="section">IfFile</directive> puede adoptar las
    mismas formas que la variable <var>test</var> en la sección
    <directive type="section" module="core">IfDefine</directive>, es
    decir, la comprobación se puede negar colocando el carácter
    <code>!</code> justo antes de <var>nombre-de-fichero</var>.
    </p>

    <p>Si se proporciona un <var>nombre-de-fichero</var> relativo, la
    comprobación es relativa a <directive module="core">ServerRoot</directive>.
    En el caso de que esta directiva aparezca antes de
    <directive module="core">ServerRoot</directive>, la ruta se
    comprobará en relación con la raíz del servidor compilada o con la
    raíz del servidor pasada en la línea de comandos mediante el
    parámetro <code>-d</code>.</p>

    <note type="warning"><title>Aviso</title>
    En la versión 2.4.34, no es posible especificar un
    <var>nombre-de-fichero</var> entre comillas. Esto generaría un error
    de análisis al arrancar. El principal impacto es que no se pueden
    usar nombres de fichero con espacios. Este comportamiento se corrige
    en la versión 2.4.35.</note>

</usage>
</directivesynopsis>

<directivesynopsis type="section">
<name>IfModule</name>
<description>Encierra directivas que se procesan condicionadas a la
presencia o ausencia de un módulo concreto</description>
<syntax>&lt;IfModule [!]<var>module-file</var>|<var>module-identifier</var>&gt; ...
    &lt;/IfModule&gt;</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>All</override>

<usage>
    <p>La sección <code>&lt;IfModule <var>test</var>&gt;...&lt;/IfModule&gt;</code>
    se usa para marcar directivas que son condicionales a la presencia
    de un módulo concreto. Las directivas dentro de una sección
    <directive type="section">IfModule</directive> solo se procesan
    si <var>test</var> es verdadero. Si <var>test</var> es falso, todo
    lo que hay entre las marcas de inicio y fin se ignora.</p>

    <p><var>test</var> en la directiva de sección <directive
    type="section">IfModule</directive> puede tener una de estas dos
    formas:</p>

    <ul>
      <li><var>module</var></li>

      <li>!<var>module</var></li>
    </ul>

    <p>En el primer caso, las directivas entre las marcas de inicio y
    fin solo se procesan si el módulo llamado <var>module</var> está
    incluido en Apache httpd -- ya sea compilado o cargado
    dinámicamente mediante <directive module="mod_so"
    >LoadModule</directive>. El segundo formato invierte la
    condición, y solo procesa las directivas si <var>module</var>
    <strong>no</strong> está incluido.</p>

    <p>El argumento <var>module</var> puede ser el identificador del
    módulo o el nombre de fichero del módulo, en el momento en que
    se compiló. Por ejemplo, <code>rewrite_module</code> es el
    identificador y <code>mod_rewrite.c</code> es el nombre de
    fichero. Si un módulo consta de varios ficheros fuente, use el
    nombre del fichero que contiene la cadena
    <code>STANDARD20_MODULE_STUFF</code>.</p>

    <p>Las secciones <directive type="section">IfModule</directive>
    se pueden anidar, lo que se puede usar para implementar pruebas
    sencillas con varios módulos.</p>

    <note>Esta sección solo debería usarse si necesita tener un
    fichero de configuración que funcione tanto si un módulo
    concreto está disponible como si no. En el funcionamiento normal,
    no es necesario colocar las directivas en secciones <directive
    type="section">IfModule</directive>.</note>
</usage>
</directivesynopsis>

<directivesynopsis type="section">
<name>IfDirective</name>
<description>Encierra directivas que se procesan condicionadas a la
presencia o ausencia de una directiva concreta</description>
<syntax>&lt;IfDirective [!]<var>nombre-de-directiva</var>&gt; ...
    &lt;/IfDirective&gt;</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>All</override>
<compatibility>Disponible a partir de la versión 2.4.34</compatibility>

<usage>
    <p>La sección <code>&lt;IfDirective <var>test</var>&gt;...&lt;/IfDirective&gt;</code>
    se usa para marcar directivas que son condicionales a la presencia de
    una directiva concreta. Las directivas dentro de una sección
    <directive type="section">IfDirective</directive> solo se procesan
    si <var>test</var> es verdadero. Si <var>test</var> es falso, todo
    lo que hay entre las marcas de inicio y fin se ignora.</p>

    <p><var>test</var> en la sección <directive type="section"
    >IfDirective</directive> puede adoptar una de estas dos formas:</p>

    <ul>
      <li><var>nombre-de-directiva</var></li>

      <li>!<var>nombre-de-directiva</var></li>
    </ul>

    <p>En el primer caso, las directivas entre las marcas de inicio y
    fin solo se procesan si una directiva con ese nombre está disponible
    en el momento del procesamiento. El segundo formato invierte la
    comprobación, y solo procesa las directivas si
    <var>nombre-de-directiva</var> <strong>no</strong> está
    disponible.</p>

    <note>Esta sección solo debería usarse si necesita tener un único
    fichero de configuración que funcione en varias versiones de
    <program>httpd</program>, independientemente de si una directiva
    concreta está disponible. En el funcionamiento normal, las
    directivas no necesitan colocarse en secciones <directive
    type="section">IfDirective</directive>.</note>
</usage>
<seealso><directive module="core" type="section">IfSection</directive></seealso>
</directivesynopsis>

<directivesynopsis type="section">
<name>IfSection</name>
<description>Encierra directivas que se procesan condicionadas a la
presencia o ausencia de una directiva de sección concreta</description>
<syntax>&lt;IfSection [!]<var>nombre-de-sección</var>&gt; ...
    &lt;/IfSection&gt;</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>All</override>
<compatibility>Disponible a partir de la versión 2.4.34</compatibility>

<usage>
    <p>La sección <code>&lt;IfSection
    <var>test</var>&gt;...&lt;/IfSection&gt;</code> se usa para marcar
    directivas que son condicionales a la presencia de una directiva de
    sección concreta. Una directiva de sección es cualquier directiva,
    como <directive type="section">VirtualHost</directive>, que encierra
    otras directivas, y cuyo nombre empieza por "&lt;".</p>

    <p>Las directivas dentro de una sección <directive type="section"
    >IfSection</directive> solo se procesan si <var>test</var> es
    verdadero. Si <var>test</var> es falso, todo lo que hay entre las
    marcas de inicio y fin se ignora.</p>

    <p><var>nombre-de-sección</var> debe especificarse sin el "&lt;"
    inicial ni el "&gt;" final. <var>test</var> en la sección <directive
    type="section">IfSection</directive> puede adoptar una de estas dos
    formas:</p>

    <ul>
      <li><var>nombre-de-sección</var></li>
      <li>!<var>nombre-de-sección</var></li>
    </ul>

    <p>En el primer caso, las directivas entre las marcas de inicio y
    fin solo se procesan si una directiva de sección con ese nombre está
    disponible en el momento del procesamiento. El segundo formato
    invierte la comprobación, y solo procesa las directivas si
    <var>nombre-de-sección</var> <strong>no</strong> es una directiva de
    sección disponible.</p>

    <p>Por ejemplo:</p>

    <highlight language="config">
&lt;IfSection VirtualHost&gt;
   ...
&lt;/IfSection&gt;
    </highlight>

    <note>Esta sección solo debería usarse si necesita tener un único
    fichero de configuración que funcione en varias versiones de
    <program>httpd</program>, independientemente de si una directiva de
    sección concreta está disponible. En el funcionamiento normal, las
    directivas no necesitan colocarse en secciones <directive
    type="section">IfSection</directive>.</note>
</usage>
<seealso><directive module="core" type="section">IfDirective</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>Include</name>
<description>Incluye otros ficheros de configuración desde los
ficheros de configuración del servidor</description>
<syntax>Include <var>ruta-a-fichero</var>|<var>ruta-a-directorio</var>|<var>comodín</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context>
</contextlist>
<compatibility>La coincidencia de comodines de directorio está
disponible a partir de la versión 2.3.6</compatibility>

<usage>
    <p>Esta directiva permite la inclusión de otros ficheros de
    configuración desde los ficheros de configuración del servidor.</p>

    <p>Se pueden usar caracteres comodín de estilo shell
    (<code>fnmatch()</code>) en las partes de nombre de fichero o de
    directorio de la ruta para incluir varios ficheros a la vez, en
    orden alfabético. Además, si <directive>Include</directive> apunta
    a un directorio en lugar de a un fichero, Apache httpd leerá todos
    los ficheros de ese directorio y de cualquier subdirectorio. Sin
    embargo, no se recomienda incluir directorios enteros, porque es
    fácil dejar accidentalmente ficheros temporales en un directorio
    que pueden hacer que <program>httpd</program> falle. En su lugar,
    le animamos a usar la sintaxis de comodines que se muestra a
    continuación, para incluir ficheros que coincidan con un patrón
    concreto, como *.conf, por ejemplo.</p>

    <p>La directiva <directive module="core">Include</directive>
    <strong>fallará con un error</strong> si una expresión con
    comodín no coincide con ningún fichero. La directiva
    <directive module="core">IncludeOptional</directive> se puede usar
    si los comodines sin coincidencias deben ignorarse.</p>

    <p>La ruta de fichero especificada puede ser una ruta absoluta, o
    puede ser relativa al directorio
    <directive module="core">ServerRoot</directive>.</p>

    <p>Ejemplos:</p>

    <highlight language="config">
Include /usr/local/apache2/conf/ssl.conf
Include /usr/local/apache2/conf/vhosts/*.conf
    </highlight>

    <p>O bien, proporcionando rutas relativas a su directorio
    <directive module="core">ServerRoot</directive>:</p>

    <highlight language="config">
Include conf/ssl.conf
Include conf/vhosts/*.conf
    </highlight>

    <p>Se pueden incluir comodines en la parte de directorio o de
    fichero de la ruta. Este ejemplo fallará si no hay ningún
    subdirectorio en conf/vhosts que contenga al menos un fichero
    *.conf:</p>

    <highlight language="config">
Include conf/vhosts/*/*.conf
    </highlight>

    <p>Alternativamente, el siguiente comando simplemente se ignorará
    en caso de que falten ficheros o directorios:</p>

    <highlight language="config">
IncludeOptional conf/vhosts/*/*.conf
    </highlight>

</usage>

<seealso><directive module="core">IncludeOptional</directive></seealso>
<seealso><program>apachectl</program></seealso>
</directivesynopsis>

<directivesynopsis>
<name>IncludeOptional</name>
<description>Incluye otros ficheros de configuración desde los
ficheros de configuración del servidor</description>
<syntax>IncludeOptional <var>ruta-a-fichero</var>|<var>ruta-a-directorio</var>|<var>comodín</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context>
</contextlist>
<compatibility>Disponible a partir de la versión 2.3.6. Las rutas a
               ficheros inexistentes sin comodines no provocan un
               SyntaxError a partir de la versión 2.4.30</compatibility>

<usage>
    <p>Esta directiva permite la inclusión de otros ficheros de
    configuración desde los ficheros de configuración del servidor.
    Funciona de forma idéntica a la directiva
    <directive module="core">Include</directive>, pero se ignorará de
    forma silenciosa (en lugar de provocar un error) si se usan
    comodines y estos no coinciden con ningún fichero o directorio, o
    si una ruta de fichero no existe en el sistema de ficheros.</p>
</usage>

<seealso><directive module="core">Include</directive></seealso>
<seealso><program>apachectl</program></seealso>
</directivesynopsis>

<directivesynopsis>
<name>KeepAlive</name>
<description>Habilita las conexiones persistentes HTTP</description>
<syntax>KeepAlive On|Off</syntax>
<default>KeepAlive On</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La extensión Keep-Alive de HTTP/1.0 y la característica de
    conexión persistente de HTTP/1.1 proporcionan sesiones HTTP de
    larga duración que permiten enviar varias peticiones a través de
    la misma conexión TCP. En algunos casos se ha demostrado que esto
    da como resultado una mejora de casi el 50% en los tiempos de
    latencia para documentos HTML con muchas imágenes. Para habilitar
    las conexiones Keep-Alive, establezca <code>KeepAlive On</code>.</p>

    <p>Para los clientes HTTP/1.0, las conexiones Keep-Alive solo se
    usarán si el cliente las solicita específicamente. Además, una
    conexión Keep-Alive con un cliente HTTP/1.0 solo se puede usar
    cuando se conoce de antemano la longitud del contenido. Esto
    implica que el contenido dinámico, como la salida de CGI, las
    páginas SSI y los listados de directorios generados por el
    servidor, por lo general no usarán conexiones Keep-Alive con
    clientes HTTP/1.0. Para los clientes HTTP/1.1, las conexiones
    persistentes son el comportamiento por defecto a menos que se
    indique lo contrario. Si el cliente lo solicita, se usará
    codificación por trozos (chunked) para enviar contenido de
    longitud desconocida a través de conexiones persistentes.</p>

    <p>Cuando un cliente usa una conexión Keep-Alive, se contará como
    una única "petición" a efectos de la directiva <directive
    module="mpm_common">MaxConnectionsPerChild</directive>,
    independientemente de cuántas peticiones se envíen usando esa
    conexión.</p>
</usage>

<seealso><directive module="core">MaxKeepAliveRequests</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>KeepAliveTimeout</name>
<description>Tiempo que esperará el servidor peticiones subsiguientes
en una conexión persistente</description>
<syntax>KeepAliveTimeout <var>num-seconds</var>|<var>num-milliseconds</var>ms</syntax>
<default>KeepAliveTimeout 5</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>El número de segundos que Apache httpd esperará una petición
    subsiguiente antes de cerrar la conexión. Añadiendo el sufijo
    'ms' el tiempo de espera también se puede establecer en
    milisegundos. Una vez que se ha recibido una petición, se aplica
    el valor de tiempo de espera especificado por la directiva
    <directive module="core">Timeout</directive>.</p>

    <p>Establecer <directive>KeepAliveTimeout</directive> con un
    valor alto puede causar problemas de rendimiento en servidores con
    mucha carga. Cuanto mayor sea el tiempo de espera, más procesos
    del servidor permanecerán ocupados esperando en conexiones con
    clientes inactivos.</p>

    <p>Si <directive>KeepAliveTimeout</directive> <strong>no</strong>
    se establece para un host virtual basado en nombre, se usará el
    valor del primer host virtual definido que mejor coincida con la
    IP y el puerto locales.</p>
</usage>
</directivesynopsis>

<directivesynopsis type="section">
<name>Limit</name>
<description>Restringe los controles de acceso que contiene a solo
ciertos métodos HTTP</description>
<syntax>&lt;Limit <var>method</var> [<var>method</var>] ... &gt; ...
    &lt;/Limit&gt;</syntax>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig, Limit</override>

<usage>
    <p>Los controles de acceso normalmente son efectivos para
    <strong>todos</strong> los métodos de acceso, y este es el
    comportamiento habitual deseado. <strong>En el caso general, las
    directivas de control de acceso no deberían colocarse dentro de
    una sección <directive type="section">Limit</directive>.</strong></p>

    <p>El propósito de la directiva <directive
    type="section">Limit</directive> es restringir el efecto de los
    controles de acceso a los métodos HTTP indicados. Para todos los
    demás métodos, las restricciones de acceso que están dentro de la
    sección <directive type="section">Limit</directive>
    <strong>no tendrán efecto</strong>. El siguiente ejemplo aplica el
    control de acceso solo a los métodos <code>POST</code>,
    <code>PUT</code> y <code>DELETE</code>, dejando todos los demás
    métodos sin proteger:</p>

    <highlight language="config">
&lt;Limit POST PUT DELETE&gt;
  Require valid-user
&lt;/Limit&gt;
    </highlight>

    <p>Los nombres de método listados pueden ser uno o más de:
    <code>GET</code>, <code>POST</code>, <code>PUT</code>,
    <code>DELETE</code>, <code>CONNECT</code>, <code>OPTIONS</code>,
    <code>PATCH</code>, <code>PROPFIND</code>, <code>PROPPATCH</code>,
    <code>MKCOL</code>, <code>COPY</code>, <code>MOVE</code>,
    <code>LOCK</code>, y <code>UNLOCK</code>. <strong>El nombre del
    método distingue mayúsculas de minúsculas.</strong> Si se usa
    <code>GET</code>, también restringirá las peticiones
    <code>HEAD</code>. El método <code>TRACE</code> no se puede
    limitar (vea <directive module="core">TraceEnable</directive>).</p>

    <note type="warning">Siempre se debería usar una sección
    <directive type="section" module="core">LimitExcept</directive>
    en lugar de una sección <directive type="section">Limit</directive>
    para restringir el acceso, ya que una sección <directive
    type="section" module="core">LimitExcept</directive> protege
    frente a métodos arbitrarios. Consulte también la <a
    href="../sections.html#merging">documentación sobre la fusión de
    secciones de configuración</a> para una advertencia sobre cómo
    una <directive type="section">Limit</directive> dentro de una
    <directive type="section" module="core">Location</directive>
    puede anular silenciosamente las restricciones de <directive
    type="section" module="core">Directory</directive>.</note>

    <p>Las directivas <directive type="section">Limit</directive> y
    <directive type="section" module="core">LimitExcept</directive>
    se pueden anidar. En este caso, cada nivel sucesivo de directivas
    <directive type="section">Limit</directive> o <directive
    type="section" module="core">LimitExcept</directive> debe
    restringir aún más el conjunto de métodos a los que se aplican
    los controles de acceso.</p>

    <note type="warning">Cuando use directivas
    <directive type="section">Limit</directive> o
    <directive type="section">LimitExcept</directive> junto con la
    directiva <directive module="mod_authz_core">Require</directive>,
    tenga en cuenta que la primera <directive
    module="mod_authz_core">Require</directive> que tenga éxito
    autoriza la petición, independientemente de la presencia de
    otras directivas <directive module="mod_authz_core">Require</directive>.</note>

    <p>Por ejemplo, dada la siguiente configuración, todos los
    usuarios estarán autorizados para las peticiones <code>POST</code>,
    y la directiva <code>Require group editors</code> se ignorará en
    todos los casos:</p>

    <highlight language="config">
&lt;LimitExcept GET&gt;
  Require valid-user
&lt;/LimitExcept&gt;
&lt;Limit POST&gt;
  Require group editors
&lt;/Limit&gt;
    </highlight>
</usage>
</directivesynopsis>

<directivesynopsis type="section">
<name>LimitExcept</name>
<description>Restringe los controles de acceso a todos los métodos
HTTP excepto a los indicados</description>
<syntax>&lt;LimitExcept <var>method</var> [<var>method</var>] ... &gt; ...
    &lt;/LimitExcept&gt;</syntax>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig, Limit</override>

<usage>
    <p><directive type="section">LimitExcept</directive> y
    <code>&lt;/LimitExcept&gt;</code> se usan para delimitar un grupo
    de directivas de control de acceso que se aplicarán a cualquier
    método de acceso HTTP <strong>no</strong> listado en los
    argumentos; es decir, es lo contrario de una sección <directive
    type="section" module="core">Limit</directive> y se puede usar
    para controlar tanto métodos estándar como no estándar o no
    reconocidos. Consulte la documentación de <directive
    module="core" type="section">Limit</directive> para más detalles.</p>

    <p>Por ejemplo:</p>

    <highlight language="config">
&lt;LimitExcept POST GET&gt;
  Require valid-user
&lt;/LimitExcept&gt;
    </highlight>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>LimitInternalRecursion</name>
<description>Determina el número máximo de redirecciones internas y
subpeticiones anidadas</description>
<syntax>LimitInternalRecursion <var>number</var> [<var>number</var>]</syntax>
<default>LimitInternalRecursion 10</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>Una redirección interna ocurre, por ejemplo, al usar la
    directiva <directive module="mod_actions">Action</directive>, que
    redirige internamente la petición original a un script CGI. Una
    subpetición es el mecanismo de Apache httpd para averiguar qué
    ocurriría con una URI determinada si se solicitara. Por ejemplo,
    <module>mod_dir</module> usa subpeticiones para buscar los
    ficheros listados en la directiva <directive
    module="mod_dir">DirectoryIndex</directive>.</p>

    <p><directive>LimitInternalRecursion</directive> evita que el
    servidor falle al entrar en un bucle infinito de redirecciones
    internas o subpeticiones. Estos bucles normalmente se deben a
    errores de configuración.</p>

    <p>La directiva almacena dos límites distintos, que se evalúan
    por cada petición. El primer <var>number</var> es el número
    máximo de redirecciones internas que pueden seguirse una a otra.
    El segundo <var>number</var> determina hasta qué profundidad se
    pueden anidar las subpeticiones. Si especifica solo un
    <var>number</var>, se asignará a ambos límites.</p>

    <highlight language="config">
LimitInternalRecursion 5
    </highlight>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>LimitRequestBody</name>
<description>Restricts the total size of the HTTP request body sent
from the client</description>
<syntax>LimitRequestBody <var>bytes</var></syntax>
<default>LimitRequestBody 1073741824</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>All</override>
<compatibility>En Apache HTTP Server 2.4.53 y anteriores, el valor por
defecto era 0 (sin límite)</compatibility>

<usage>
    <p>Esta directiva especifica el número de <var>bytes</var>
    que se permiten en el cuerpo de una petición. Un valor de <var>0</var>
    significa que no hay límite.</p>

    <p>La directiva <directive>LimitRequestBody</directive> permite
    al usuario establecer un límite sobre el tamaño permitido del
    cuerpo de un mensaje de petición HTTP dentro del contexto en el
    que se da la directiva (servidor, por directorio, por fichero o
    por ubicación). Si la petición del cliente excede ese límite, el
    servidor devolverá una respuesta de error en lugar de atender la
    petición. El tamaño del cuerpo de una petición normal variará
    mucho dependiendo de la naturaleza del recurso y de los métodos
    permitidos sobre ese recurso. Los scripts CGI normalmente usan el
    cuerpo del mensaje para obtener la información de un formulario.
    Las implementaciones del método <code>PUT</code> requerirán un
    valor al menos tan grande como cualquier representación que el
    servidor desee aceptar para ese recurso.</p>

    <p>Esta directiva proporciona al administrador del servidor un
    mayor control sobre el comportamiento anómalo de las peticiones
    de los clientes, lo cual puede ser útil para evitar algunas formas
    de ataques de denegación de servicio.</p>

    <p>Si, por ejemplo, está permitiendo la subida de ficheros a una
    ubicación concreta y desea limitar el tamaño del fichero subido a
    100K, podría usar la siguiente directiva:</p>

    <highlight language="config">
LimitRequestBody 102400
    </highlight>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>LimitRequestFields</name>
<description>Limits the number of HTTP request header fields that
will be accepted from the client</description>
<syntax>LimitRequestFields <var>number</var></syntax>
<default>LimitRequestFields 100</default>
<contextlist><context>server config</context><context>virtual host</context></contextlist>

<usage>
    <p><var>Number</var> es un entero entre 0 (sin límite) y
    32767. El valor por defecto está definido por la constante de
    tiempo de compilación <code>DEFAULT_LIMIT_REQUEST_FIELDS</code>
    (100 tal y como se distribuye).</p>

    <p>La directiva <directive>LimitRequestFields</directive> permite
    al administrador del servidor modificar el límite en el número de
    campos de cabecera de petición permitidos en una petición HTTP. Un
    servidor necesita que este valor sea mayor que el número de campos
    que podría incluir una petición normal de un cliente. El número de
    campos de cabecera de petición usados por un cliente raramente
    excede de 20, pero esto puede variar entre diferentes
    implementaciones de cliente, a menudo dependiendo de hasta qué
    punto un usuario ha configurado su navegador para soportar
    negociación de contenidos detallada. Las extensiones HTTP
    opcionales a menudo se expresan usando campos de cabecera de
    petición.</p>

    <p>Esta directiva proporciona al administrador del servidor un
    mayor control sobre el comportamiento anómalo de las peticiones de
    los clientes, lo cual puede ser útil para evitar algunas formas de
    ataques de denegación de servicio. El valor debería incrementarse
    si los clientes normales ven una respuesta de error del servidor
    que indica que se enviaron demasiados campos en la petición.</p>

    <p>Por ejemplo:</p>

    <highlight language="config">
LimitRequestFields 50
    </highlight>

     <note type="warning"><title>Advertencia</title>
     <p>Cuando se usa alojamiento virtual basado en nombre, el valor
     de esta directiva se toma del host virtual por defecto (el
     primero listado) para la combinación de IP y puerto local.</p>
     </note>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>LimitRequestFieldSize</name>
<description>Limits the size of the HTTP request header allowed from the
client</description>
<syntax>LimitRequestFieldSize <var>bytes</var></syntax>
<default>LimitRequestFieldSize 8190</default>
<contextlist><context>server config</context><context>virtual host</context></contextlist>

<usage>
    <p>Esta directiva especifica el número de <var>bytes</var>
    que se permitirán en una cabecera de petición HTTP.</p>

    <p>La directiva <directive>LimitRequestFieldSize</directive>
    permite al administrador del servidor reducir o aumentar el
    límite sobre el tamaño permitido de un campo de cabecera de
    petición HTTP. Un servidor necesita que este valor sea
    suficientemente grande para contener cualquier campo de cabecera
    de una petición normal de un cliente. El tamaño de un campo de
    cabecera de petición normal variará mucho entre diferentes
    implementaciones de cliente, a menudo dependiendo de hasta qué
    punto un usuario ha configurado su navegador para soportar
    negociación de contenidos detallada. Las cabeceras de
    autenticación SPNEGO pueden llegar a tener 12392 bytes.</p>

    <p>Esta directiva proporciona al administrador del servidor un
    mayor control sobre el comportamiento anómalo de las peticiones de
    los clientes, lo cual puede ser útil para evitar algunas formas de
    ataques de denegación de servicio.</p>

    <p>Por ejemplo:</p>

    <highlight language="config">
LimitRequestFieldSize 4094
    </highlight>

    <note>En condiciones normales, el valor no debería cambiarse
    respecto al valor por defecto.</note>

    <note type="warning"><title>Advertencia</title>
    <p>Cuando se usa alojamiento virtual basado en nombre, el valor de
    esta directiva se toma del host virtual por defecto (el primero
    listado) que mejor se corresponda con la combinación de dirección
    IP y puerto actual.</p>
    </note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>LimitRequestLine</name>
<description>Limit the size of the HTTP request line that will be accepted
from the client</description>
<syntax>LimitRequestLine <var>bytes</var></syntax>
<default>LimitRequestLine 8190</default>
<contextlist><context>server config</context><context>virtual host</context></contextlist>

<usage>
    <p>Esta directiva establece el número de <var>bytes</var> que se
    permitirán en la línea de petición HTTP.</p>

    <p>La directiva <directive>LimitRequestLine</directive> permite
    al administrador del servidor reducir o aumentar el límite sobre
    el tamaño permitido de la línea de petición HTTP de un cliente.
    Dado que la línea de petición consiste en el método HTTP, el URI
    y la versión del protocolo, la directiva
    <directive>LimitRequestLine</directive> impone una restricción
    sobre la longitud del URI de petición permitido para una petición
    en el servidor. Un servidor necesita que este valor sea
    suficientemente grande para contener cualquiera de sus nombres de
    recurso, incluyendo cualquier información que pudiera pasarse en
    la parte de la consulta de una petición <code>GET</code>.</p>

    <p>Esta directiva proporciona al administrador del servidor un
    mayor control sobre el comportamiento anómalo de las peticiones de
    los clientes, lo cual puede ser útil para evitar algunas formas de
    ataques de denegación de servicio.</p>

    <p>Por ejemplo:</p>

    <highlight language="config">
LimitRequestLine 4094
    </highlight>

    <note>En condiciones normales, el valor no debería cambiarse
    respecto al valor por defecto.</note>

    <note type="warning"><title>Advertencia</title>
    <p>Cuando se usa alojamiento virtual basado en nombre, el valor de
    esta directiva se toma del host virtual por defecto (el primero
    listado) que mejor se corresponda con la combinación de dirección
    IP y puerto actual.</p>
    </note>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>LimitXMLRequestBody</name>
<description>Limits the size of an XML-based request body</description>
<syntax>LimitXMLRequestBody <var>bytes</var></syntax>
<default>LimitXMLRequestBody 1000000</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>All</override>

<usage>
    <p>Límite (en bytes) sobre el tamaño máximo del cuerpo de una
    petición basada en XML. Un valor de <code>0</code> aplicará un
    límite estricto (dependiendo de si el sistema es de 32 o 64 bits)
    que permite el escapado XML dentro de los límites de la memoria
    direccionable del sistema, pero existe solo por compatibilidad y
    no se recomienda, ya que no tiene en cuenta la memoria consumida
    en otros lugares o por peticiones concurrentes, lo que podría
    provocar un agotamiento de memoria a nivel de todo el sistema.
    </p>
    <p>Ejemplo:</p>

    <highlight language="config">
# Límite de 1 MiB
LimitXMLRequestBody 1048576
    </highlight>

</usage>
</directivesynopsis>

<directivesynopsis type="section">
<name>Location</name>
<description>Applies the enclosed directives only to matching
URLs</description>
<syntax>&lt;Location
    <var>URL-path</var>|<var>URL</var>&gt; ... &lt;/Location&gt;</syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive type="section">Location</directive>
    limita el ámbito de las directivas que contiene por URL. Es
    similar a la directiva <directive type="section" module="core">Directory</directive>,
    y comienza una subsección que se cierra con una directiva
    <code>&lt;/Location&gt;</code>. Las secciones
    <directive type="section">Location</directive> se procesan en el
    orden en que aparecen en el fichero de configuración, después de
    que se lean las secciones <directive type="section" module="core">Directory</directive>
    y los ficheros <code>.htaccess</code>, y después de las secciones
    <directive type="section" module="core">Files</directive>.</p>

    <p>Las secciones <directive type="section">Location</directive>
    operan completamente fuera del sistema de ficheros. Esto tiene
    varias consecuencias. La más importante es que las directivas
    <directive type="section">Location</directive> no deberían usarse
    para controlar el acceso a ubicaciones del sistema de ficheros.
    Dado que varias URLs distintas pueden mapear a la misma ubicación
    del sistema de ficheros, esos controles de acceso podrían
    eludirse.</p>

    <p>Las directivas que contiene se aplicarán a la petición si el
    componente de ruta de la URL cumple <em>cualquiera</em> de los
    siguientes criterios:
    </p>
    <ul>
      <li>La ubicación especificada coincide exactamente con el
      componente de ruta de la URL.
      </li>
      <li>La ubicación especificada, que termina en una barra, es un
      prefijo del componente de ruta de la URL (tratado como raíz de
      contexto).
      </li>
      <li>La ubicación especificada, con una barra final añadida, es
      un prefijo del componente de ruta de la URL (también tratado
      como raíz de contexto).
      </li>
    </ul>
    <p>
    En el ejemplo siguiente, donde no se usa barra final, las
    peticiones a /private1, /private1/ y /private1/file.txt tendrán
    aplicadas las directivas que contiene, pero /private1other no.
    </p>
    <highlight language="config">
&lt;Location "/private1"&gt;
    #  ...
&lt;/Location&gt;
    </highlight>
    <p>
    En el ejemplo siguiente, donde se usa una barra final, las
    peticiones a /private2/ y /private2/file.txt tendrán aplicadas las
    directivas que contiene, pero /private2 y /private2other no.
    </p>
    <highlight language="config">
&lt;Location "/private2<em>/</em>"&gt;
    # ...
&lt;/Location&gt;
    </highlight>

    <note><title>Cuándo usar <directive
    type="section">Location</directive></title>

    <p>Use <directive type="section">Location</directive> para
    aplicar directivas a contenido que vive fuera del sistema de
    ficheros. Para el contenido que vive en el sistema de ficheros,
    use <directive type="section" module="core">Directory</directive>
    y <directive type="section" module="core">Files</directive>. Una
    excepción es <code>&lt;Location "/"&gt;</code>, que es una forma
    sencilla de aplicar una configuración a todo el servidor.</p>
    </note>

    <p>Para todas las peticiones de origen (no de proxy), la URL que
    se compara es una ruta-URL de la forma <code>/ruta/</code>.
    <em>No se puede incluir ni el esquema, ni el nombre de host, ni
    el puerto, ni la cadena de consulta.</em> Para las peticiones de
    proxy, la URL que se compara depende del tipo de proxy. Con un
    proxy <strong>directo</strong> (<directive
    module="mod_proxy">ProxyRequests</directive>), la URL que se
    compara es de la forma <code>esquema://nombreservidor/ruta</code>,
    y debe incluir el prefijo. Con un proxy <strong>inverso</strong>
    (configurado mediante <directive module="mod_proxy">ProxyPass</directive>
    o <directive module="mod_proxy">RewriteRule ... [P]</directive>),
    la petición llega como una ruta-URL local, así que use
    <code>/ruta/</code> igual que haría con las peticiones de
    origen.</p>

    <p>La URL puede usar comodines. En una cadena con comodines,
    <code>?</code> coincide con cualquier carácter individual, y
    <code>*</code> coincide con cualquier secuencia de caracteres.
    Ninguno de los dos caracteres comodín coincide con una / en la
    ruta-URL.</p>

    <p>También se pueden usar <glossary ref="regex">expresiones
    regulares</glossary>, añadiendo el carácter <code>~</code>. Por
    ejemplo:</p>

    <highlight language="config">
&lt;Location ~ "/(extra|special)/data"&gt;
    #...
&lt;/Location&gt;
    </highlight>

    <p>coincidiría con las URLs que contuvieran la subcadena
    <code>/extra/data</code> o <code>/special/data</code>. La
    directiva <directive type="section" module="core">LocationMatch</directive>
    se comporta de forma idéntica a la versión con expresión regular
    de <directive type="section">Location</directive>, y se prefiere
    su uso, por la sencilla razón de que <code>~</code> es difícil de
    distinguir de <code>-</code> en muchas tipografías.</p>

    <p>La funcionalidad de <directive type="section">Location</directive>
    es especialmente útil cuando se combina con la directiva
    <directive module="core">SetHandler</directive>. Por ejemplo, para
    activar las peticiones de estado pero permitirlas solo desde
    navegadores en <code>example.com</code>, podría usar:</p>

    <highlight language="config">
&lt;Location "/status"&gt;
  SetHandler server-status
  Require host example.com
&lt;/Location&gt;
    </highlight>

    <note><title>Nota sobre / (barra)</title>
      <p>El carácter de barra tiene un significado especial que
      depende de dónde aparezca en una URL. Puede que esté
      acostumbrado a su comportamiento en el sistema de ficheros,
      donde varias barras adyacentes se colapsan habitualmente en una
      sola (<em>por ejemplo</em>, <code>/home///foo</code> es lo mismo
      que <code>/home/foo</code>). En el espacio de las URLs esto no
      es necesariamente así si la directiva
      <directive module="core">MergeSlashes</directive> se ha
      establecido a "OFF". La directiva <directive type="section" module="core">LocationMatch</directive>
      y la versión con expresión regular de <directive type="section"
      >Location</directive> requieren que especifique explícitamente
      varias barras si estas no se están fusionando.</p>

      <p>Por ejemplo, <code>&lt;LocationMatch "^/abc"&gt;</code>
      coincidiría con la URL de petición <code>/abc</code> pero no
      con la URL de petición <code>//abc</code>. La directiva (sin
      expresión regular) <directive type="section">Location</directive>
      se comporta de forma similar cuando se usa para peticiones de
      proxy. Pero cuando <directive type="section">Location</directive>
      (sin expresión regular) se usa para peticiones que no son de
      proxy, coincidirá implícitamente varias barras con una sola. Por
      ejemplo, si especifica <code>&lt;Location "/abc/def"&gt;</code>
      y la petición es a <code>/abc//def</code>, entonces
      coincidirá.</p>
    </note>
</usage>
<seealso><a href="../sections.html">How &lt;Directory&gt;, &lt;Location&gt;
    and &lt;Files&gt; sections work</a> for an explanation of how these
    different sections are combined when a request is received.</seealso>
<seealso><directive module="core">LocationMatch</directive></seealso>
</directivesynopsis>

<directivesynopsis type="section">
<name>LocationMatch</name>
<description>Aplica las directivas que contiene solo a las URLs que
coincidan con una expresión regular</description>
<syntax>&lt;LocationMatch
    <var>regex</var>&gt; ... &lt;/LocationMatch&gt;</syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive type="section">LocationMatch</directive>
    limita el ámbito de las directivas que contiene por URL, de forma
    idéntica a <directive module="core" type="section">Location</directive>.
    Sin embargo, toma una <glossary ref="regex">expresión
    regular</glossary> como argumento en lugar de una cadena simple.
    Por ejemplo:</p>

    <highlight language="config">
&lt;LocationMatch "/(extra|special)/data"&gt;
    # ...
&lt;/LocationMatch&gt;
    </highlight>

    <p>coincidiría con las URLs que contuvieran la subcadena
    <code>/extra/data</code> o <code>/special/data</code>.</p>

    <note><p>Si la intención es que una URL <strong>empiece
    con</strong> <code>/extra/data</code>, en vez de simplemente
    <strong>contener</strong> <code>/extra/data</code>, añada el
    prefijo <code>^</code> a la expresión regular para exigirlo.</p>

    <highlight language="config">
&lt;LocationMatch "^/(extra|special)/data"&gt;
    </highlight>
    </note>

    <p>A partir de la versión 2.4.8, los grupos con nombre y las
    referencias hacia atrás se capturan y se escriben en el entorno
    con el nombre correspondiente prefijado con "MATCH_" y en
    mayúsculas. Esto permite hacer referencia a elementos de las URLs
    desde <a href="../expr.html">expresiones</a> y módulos como
    <module>mod_rewrite</module>. Para evitar confusiones, las
    referencias hacia atrás numeradas (sin nombre) se ignoran. Use
    grupos con nombre en su lugar.</p>

    <highlight language="config">
&lt;LocationMatch "^/combined/(?&lt;sitename&gt;[^/]+)"&gt;
    Require ldap-group cn=%{env:MATCH_SITENAME},ou=combined,o=Example
&lt;/LocationMatch&gt;
    </highlight>

     <note><title>Nota sobre / (barra)</title>
      <p>El carácter de barra tiene un significado especial que
      depende de dónde aparezca en una URL. Puede que esté
      acostumbrado a su comportamiento en el sistema de ficheros,
      donde varias barras adyacentes se colapsan habitualmente en una
      sola (<em>por ejemplo</em>, <code>/home///foo</code> es lo mismo
      que <code>/home/foo</code>). En el espacio de las URLs esto no
      es necesariamente así si la directiva
      <directive module="core">MergeSlashes</directive> se ha
      establecido a "OFF". La directiva <directive type="section"
      module="core">LocationMatch</directive> y la versión con
      expresión regular de <directive type="section"
      >Location</directive> requieren que especifique explícitamente
      varias barras si estas no se están fusionando.</p>

      <p>Por ejemplo, <code>&lt;LocationMatch "^/abc"&gt;</code>
      coincidiría con la URL de petición <code>/abc</code> pero no con
      la URL de petición <code>//abc</code>. La directiva (sin
      expresión regular) <directive type="section">Location</directive>
      se comporta de forma similar cuando se usa para peticiones de
      proxy. Pero cuando <directive type="section">Location</directive>
      (sin expresión regular) se usa para peticiones que no son de
      proxy, coincidirá implícitamente varias barras con una sola. Por
      ejemplo, si especifica <code>&lt;Location "/abc/def"&gt;</code>
      y la petición es a <code>/abc//def</code>, entonces
      coincidirá.</p>
    </note>
</usage>

<seealso><a href="../sections.html">How &lt;Directory&gt;, &lt;Location&gt;
    and &lt;Files&gt; sections work</a> for an explanation of how these
    different sections are combined when a request is received</seealso>
</directivesynopsis>

<directivesynopsis>
<name>LogLevel</name>
<description>Controla el nivel de detalle del registro de errores
(ErrorLog)</description>
<syntax>LogLevel [<var>module</var>:]<var>level</var>
    [<var>module</var>:<var>level</var>] ...
</syntax>
<default>LogLevel warn</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context>
</contextlist>
<compatibility>La configuración por módulo y por directorio está
    disponible desde Apache HTTP Server 2.3.6</compatibility>

<usage>
    <p><directive>LogLevel</directive> ajusta el nivel de detalle de
    los mensajes que se registran en los registros de error (vea la
    directiva <directive module="core">ErrorLog</directive>). Los
    siguientes <var>level</var>s están disponibles, en orden
    decreciente de importancia:</p>

    <table border="1">
    <columnspec><column width=".2"/><column width=".3"/><column width=".5"/>
    </columnspec>
      <tr>
        <th><strong>Nivel</strong> </th>

        <th><strong>Descripción</strong> </th>

        <th><strong>Ejemplo</strong> </th>
      </tr>

      <tr>
        <td><code>emerg</code> </td>

        <td>Emergencias - el sistema no se puede usar.</td>

        <td>"Child cannot open lock file. Exiting"</td>
      </tr>

      <tr>
        <td><code>alert</code> </td>

        <td>Se debe actuar de inmediato.</td>

        <td>"getpwuid: couldn't determine user name from uid"</td>
      </tr>

      <tr>
        <td><code>crit</code> </td>

        <td>Condiciones críticas.</td>

        <td>"socket: Failed to get a socket, exiting child"</td>
      </tr>

      <tr>
        <td><code>error</code> </td>

        <td>Condiciones de error.</td>

        <td>"Premature end of script headers"</td>
      </tr>

      <tr>
        <td><code>warn</code> </td>

        <td>Condiciones de aviso.</td>

        <td>"child process 1234 did not exit, sending another
        SIGHUP"</td>
      </tr>

      <tr>
        <td><code>notice</code> </td>

        <td>Condición normal pero significativa.</td>

        <td>"httpd: caught SIGBUS, attempting to dump core in
        ..."</td>
      </tr>

      <tr>
        <td><code>info</code> </td>

        <td>Informativo.</td>

        <td>"Server seems busy, (you may need to increase
        StartServers, or Min/MaxSpareServers)..."</td>
      </tr>

      <tr>
        <td><code>debug</code> </td>

        <td>Mensajes de nivel de depuración</td>

        <td>"Opening config file ..."</td>
      </tr>
      <tr>
        <td><code>trace1</code> </td>

        <td>Mensajes de traza</td>

        <td>"proxy: FTP: control connection complete"</td>
      </tr>
      <tr>
        <td><code>trace2</code> </td>

        <td>Mensajes de traza</td>

        <td>"proxy: CONNECT: sending the CONNECT request to the remote proxy"</td>
      </tr>
      <tr>
        <td><code>trace3</code> </td>

        <td>Mensajes de traza</td>

        <td>"openssl: Handshake: start"</td>
      </tr>
      <tr>
        <td><code>trace4</code> </td>

        <td>Mensajes de traza</td>

        <td>"read from buffered SSL brigade, mode 0, 17 bytes"</td>
      </tr>
      <tr>
        <td><code>trace5</code> </td>

        <td>Mensajes de traza</td>

        <td>"map lookup FAILED: map=rewritemap key=keyname"</td>
      </tr>
      <tr>
        <td><code>trace6</code> </td>

        <td>Mensajes de traza</td>

        <td>"cache lookup FAILED, forcing new map lookup"</td>
      </tr>
      <tr>
        <td><code>trace7</code> </td>

        <td>Mensajes de traza, con grandes volúmenes de datos</td>

        <td>"| 0000: 02 23 44 30 13 40 ac 34 df 3d bf 9a 19 49 39 15 |"</td>
      </tr>
      <tr>
        <td><code>trace8</code> </td>

        <td>Mensajes de traza, con grandes volúmenes de datos</td>

        <td>"| 0000: 02 23 44 30 13 40 ac 34 df 3d bf 9a 19 49 39 15 |"</td>
      </tr>
    </table>

    <p>Cuando se especifica un nivel concreto, los mensajes de todos
    los demás niveles de mayor importancia también se registrarán.
    <em>P. ej.</em>, cuando se especifica <code>LogLevel info</code>,
    también se publicarán los mensajes con nivel <code>notice</code>
    y <code>warn</code>.</p>

    <p>Se recomienda usar un nivel de al menos <code>crit</code>.</p>

    <p>Por ejemplo:</p>

    <highlight language="config">
LogLevel notice
    </highlight>

    <note><title>Nota</title>
      <p>Cuando se registra en un fichero normal, los mensajes de
      nivel <code>notice</code> no se pueden suprimir y, por tanto,
      siempre se registran. Sin embargo, esto no se aplica cuando el
      registro se hace mediante <code>syslog</code>.</p>
    </note>

    <p>Especificar un nivel sin nombre de módulo restablecerá el
    nivel de todos los módulos a ese nivel. Especificar un nivel con
    un nombre de módulo establecerá el nivel solo para ese módulo.
    Se puede usar como especificación de módulo el nombre del fichero
    fuente del módulo, el identificador del módulo, o el identificador
    del módulo sin el sufijo <code>_module</code>. Esto significa que
    las siguientes tres especificaciones son equivalentes:</p>

    <highlight language="config">
LogLevel info ssl:warn
LogLevel info mod_ssl.c:warn
LogLevel info ssl_module:warn
    </highlight>

    <p>También es posible cambiar el nivel por directorio:</p>

    <highlight language="config">
LogLevel info
&lt;Directory "/usr/local/apache/htdocs/app"&gt;
  LogLevel debug
&lt;/Directory&gt;
    </highlight>

    <note>
        La configuración del nivel de registro por directorio solo
        afecta a los mensajes que se registran después de haberse
        procesado la petición y que están asociados a la petición.
        Los mensajes de registro asociados al servidor o a la
        conexión no se ven afectados. Sin embargo, estos últimos se
        pueden influir mediante la directiva
        <directive module="core">LogLevelOverride</directive>.
    </note>
</usage>
<seealso><directive module="core">ErrorLog</directive></seealso>
<seealso><directive module="core">ErrorLogFormat</directive></seealso>
<seealso><directive module="core">LogLevelOverride</directive></seealso>
<seealso><a href="../logs.html">Ficheros de registro de Apache HTTP
    Server</a></seealso>
</directivesynopsis>

<directivesynopsis>
<name>LogLevelOverride</name>
<description>Sobrescribe el nivel de detalle del ErrorLog para
determinados clientes</description>
<syntax>LogLevel <var>dirección-ip</var>[/<var>longitud-de-prefijo</var>]
    [<var>módulo</var>:]<var>nivel</var> [<var>módulo</var>:<var>nivel</var>] ...
</syntax>
<default>sin establecer</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>
<compatibility>Disponible en Apache HTTP Server 2.5.0 y posteriores</compatibility>

<usage>
    <p><directive>LogLevelOverride</directive> ajusta el
    <directive module="core">LogLevel</directive> para las peticiones
    procedentes de ciertas direcciones IP de cliente.
    Esto permite activar el registro detallado solo para determinados
    clientes de prueba. La dirección IP se comprueba en una fase muy
    temprana del procesamiento de la conexión. Por tanto,
    <directive>LogLevelOverride</directive> permite cambiar el nivel de
    registro para cosas como el handshake SSL, que ocurren antes de que
    se evalúe una directiva <directive module="core">LogLevel</directive>
    dentro de un contenedor <directive type="section" module="core">If</directive>.</p>

    <p><directive>LogLevelOverride</directive> acepta tanto una única
    dirección IP como una especificación de subred CIDR
    dirección-IP/longitud. Para la sintaxis de la especificación del
    nivel de registro, consulte la directiva
    <directive module="core">LogLevel</directive>.</p>

    <p>Para las peticiones que coinciden con una directiva
    <directive>LogLevelOverride</directive>, las especificaciones de
    <directive module="core">LogLevel</directive> por directorio se
    ignoran.</p>

    <p>Ejemplos:</p>

    <highlight language="config">
    LogLevelOverride 192.0.2.0/24 ssl:trace6
    LogLevelOverride 192.0.2.7 ssl:trace8
    </highlight>

    <note>
        <directive>LogLevelOverride</directive> solo afecta a los
        mensajes de registro asociados a la petición o a la conexión.
        Los mensajes de registro asociados al servidor no se ven
        afectados.
    </note>

</usage>
<seealso><directive module="core">LogLevel</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>MaxKeepAliveRequests</name>
<description>Número de peticiones permitidas en una conexión
persistente</description>
<syntax>MaxKeepAliveRequests <var>number</var></syntax>
<default>MaxKeepAliveRequests 100</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive>MaxKeepAliveRequests</directive>
    limita el número de peticiones permitidas por conexión cuando
    <directive module="core">KeepAlive</directive> está activado.
    Si se establece a <code>0</code>, se permitirán peticiones
    ilimitadas. Se recomienda mantener este ajuste con un valor alto
    para obtener el máximo rendimiento del servidor.</p>

    <p>Por ejemplo:</p>

    <highlight language="config">
MaxKeepAliveRequests 500
    </highlight>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>MaxRanges</name>
<description>Número de rangos permitidos antes de devolver el recurso
completo</description>
<syntax>MaxRanges default | unlimited | none | <var>número-de-rangos</var></syntax>
<default>MaxRanges 200</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context>
</contextlist>
<compatibility>Disponible en Apache HTTP Server 2.3.15 y posteriores</compatibility>

<usage>
    <p>La directiva <directive>MaxRanges</directive>
    limita el número de rangos HTTP que el servidor está dispuesto a
    devolver al cliente. Si se solicitan más rangos de los permitidos,
    se devuelve el recurso completo en su lugar.</p>

    <dl>
      <dt><strong>default</strong></dt>
      <dd>Limita el número de rangos a un valor por defecto de 200,
      fijado en tiempo de compilación.</dd>

      <dt><strong>none</strong></dt>
      <dd>Las cabeceras Range se ignoran.</dd>

      <dt><strong>unlimited</strong></dt>
      <dd>El servidor no limita el número de rangos que está dispuesto
          a satisfacer.</dd>

      <dt><var>número-de-rangos</var></dt>
      <dd>Un número positivo que representa el número máximo de rangos
      que el servidor está dispuesto a satisfacer.</dd>
    </dl>
</usage>
</directivesynopsis>

<directivesynopsis>
    <name>MaxRangeOverlaps</name>
    <description>Número de rangos superpuestos (p. ej.:
        <code>100-200,150-300</code>) permitidos antes de devolver el
        recurso completo</description>
    <syntax>MaxRangeOverlaps default | unlimited | none | <var>número-de-rangos</var></syntax>
    <default>MaxRangeOverlaps 20</default>
    <contextlist><context>server config</context><context>virtual host</context>
        <context>directory</context>
    </contextlist>
    <compatibility>Disponible en Apache HTTP Server 2.3.15 y posteriores</compatibility>

    <usage>
        <p>La directiva <directive>MaxRangeOverlaps</directive>
            limita el número de rangos HTTP superpuestos que el servidor
            está dispuesto a devolver al cliente. Si se solicitan más
            rangos superpuestos de los permitidos, se devuelve el
            recurso completo en su lugar.</p>

        <dl>
            <dt><strong>default</strong></dt>
            <dd>Limita el número de rangos superpuestos a un valor por
            defecto de 20, fijado en tiempo de compilación.</dd>

            <dt><strong>none</strong></dt>
            <dd>No se permite ninguna cabecera Range superpuesta.</dd>

            <dt><strong>unlimited</strong></dt>
            <dd>El servidor no limita el número de rangos superpuestos
                que está dispuesto a satisfacer.</dd>

            <dt><var>número-de-rangos</var></dt>
            <dd>Un número positivo que representa el número máximo de
                rangos superpuestos que el servidor está dispuesto a
                satisfacer.</dd>
        </dl>
    </usage>
</directivesynopsis>

<directivesynopsis>
    <name>MaxRangeReversals</name>
    <description>Número de inversiones de rango (p. ej.:
        <code>100-200,50-70</code>) permitidas antes de devolver el
        recurso completo</description>
    <syntax>MaxRangeReversals default | unlimited | none | <var>número-de-rangos</var></syntax>
    <default>MaxRangeReversals 20</default>
    <contextlist><context>server config</context><context>virtual host</context>
        <context>directory</context>
    </contextlist>
    <compatibility>Disponible en Apache HTTP Server 2.3.15 y posteriores</compatibility>

    <usage>
        <p>La directiva <directive>MaxRangeReversals</directive>
            limita el número de inversiones de rango HTTP que el
            servidor está dispuesto a devolver al cliente. Si se
            solicitan más inversiones de rango de las permitidas, se
            devuelve el recurso completo en su lugar.</p>

        <dl>
            <dt><strong>default</strong></dt>
            <dd>Limita el número de inversiones de rango a un valor por
            defecto de 20, fijado en tiempo de compilación.</dd>

            <dt><strong>none</strong></dt>
            <dd>No se permite ninguna cabecera de inversión de rango.</dd>

            <dt><strong>unlimited</strong></dt>
            <dd>El servidor no limita el número de inversiones de rango
                que está dispuesto a satisfacer.</dd>

            <dt><var>número-de-rangos</var></dt>
            <dd>Un número positivo que representa el número máximo de
                inversiones de rango que el servidor está dispuesto a
                satisfacer.</dd>
        </dl>
    </usage>
</directivesynopsis>

<directivesynopsis>
<name>Mutex</name>
<description>Configura el mecanismo de mutex y el directorio de
ficheros de bloqueo para todos los mutex, o para los indicados</description>
<syntax>Mutex <var>mechanism</var> [default|<var>mutex-name</var>] ... [OmitPID]</syntax>
<default>Mutex default</default>
<contextlist><context>server config</context></contextlist>
<compatibility>Disponible desde Apache HTTP Server 2.3.4</compatibility>

<usage>
    <p>La directiva <directive>Mutex</directive> establece el
    mecanismo, y opcionalmente la ubicación del fichero de bloqueo,
    que httpd y los módulos usan para serializar el acceso a los
    recursos. Especifique <code>default</code> como segundo argumento
    para cambiar los ajustes de todos los mutex; especifique un
    nombre de mutex (vea la tabla más abajo) como segundo argumento
    para anular los valores por defecto solo para ese mutex.</p>

    <p>La directiva <directive>Mutex</directive> se usa habitualmente
    en las siguientes situaciones excepcionales:</p>

    <ul>
        <li>cambiar el mecanismo de mutex cuando el mecanismo por
        defecto elegido por <glossary>APR</glossary> tiene un
        problema funcional o de rendimiento</li>

        <li>cambiar el directorio usado por los mutex basados en
        fichero cuando el directorio por defecto no admite
        bloqueos</li>
    </ul>

    <note><title>Módulos soportados</title>
    <p>Esta directiva solo configura los mutex que se hayan
    registrado con el servidor principal (core) mediante la API
    <code>ap_mutex_register()</code>. Todos los módulos incluidos con
    httpd soportan la directiva <directive>Mutex</directive>, pero
    los módulos de terceros pueden no hacerlo. Consulte la
    documentación del módulo de terceros, que debe indicar el nombre
    o nombres de mutex que se pueden configurar si esta directiva
    está soportada.</p>
    </note>

    <p>Los siguientes <em>mecanismos</em> de mutex están disponibles:</p>
    <ul>
        <li><code>default | yes</code>
        <p>Esto selecciona la implementación de bloqueo por defecto,
        determinada por <glossary>APR</glossary>. La implementación
        de bloqueo por defecto se puede mostrar ejecutando
        <program>httpd</program> con la opción <code>-V</code>.</p></li>

        <li><code>none | no</code>
        <p>Esto deshabilita en la práctica el mutex, y solo se
        permite para un mutex si el módulo indica que es una opción
        válida. Consulte la documentación del módulo para más
        información.</p></li>

        <li><code>posixsem</code>
        <p>Esta es una variante de mutex basada en un semáforo
        POSIX.</p>

        <note type="warning"><title>Aviso</title>
        <p>La propiedad del semáforo no se recupera si un hilo del
        proceso que posee el mutex falla con un error de
        segmentación, lo que provoca que el servidor web se quede
        colgado.</p>
        </note>
        </li>

        <li><code>sysvsem</code>
        <p>Esta es una variante de mutex basada en un semáforo IPC de
        SystemV.</p>

        <note type="warning"><title>Aviso</title>
        <p>Es posible que se "pierdan" semáforos SysV si los procesos
        fallan antes de que se elimine el semáforo.</p>
	</note>

        <note type="warning"><title>Seguridad</title>
        <p>La API de semáforos permite un ataque de denegación de
        servicio por parte de cualquier CGI que se ejecute con el
        mismo uid que el servidor web (<em>es decir</em>, todos los
        CGIs, a menos que use algo como <program>suexec</program> o
        <code>cgiwrapper</code>).</p>
	</note>
        </li>

        <li><code>sem</code>
        <p>Esto selecciona la "mejor" implementación de semáforo
        disponible, eligiendo entre semáforos POSIX e IPC de SystemV,
        en ese orden.</p></li>

        <li><code>pthread</code>
        <p>Esta es una variante de mutex basada en mutex de hilos
        POSIX entre procesos.</p>

        <note type="warning"><title>Aviso</title>
        <p>En la mayoría de los sistemas, si un proceso hijo termina
        de forma anómala mientras tiene un mutex que usa esta
        implementación, el servidor se bloqueará (deadlock) y dejará
        de responder a las peticiones. Cuando esto ocurre, el
        servidor necesitará un reinicio manual para recuperarse.</p>
        <p>Solaris y Linux son excepciones notables, ya que
        proporcionan un mecanismo que normalmente permite recuperar
        el mutex después de que un proceso hijo termine de forma
        anómala mientras lo tiene.</p>
        <p>Si su sistema cumple POSIX o implementa la función
        <code>pthread_mutexattr_setrobust_np()</code>, puede que
        pueda usar la opción <code>pthread</code> con seguridad.</p>
        </note>
        </li>

        <li><code>fcntl:/path/to/mutex</code>
        <p>Esta es una variante de mutex en la que se usa un fichero
        físico (de bloqueo) y la función <code>fcntl()</code> como
        mutex.</p>

        <note type="warning"><title>Aviso</title>
        <p>Cuando se usan varios mutex basados en este mecanismo en
        entornos multi-hilo y multi-proceso, se pueden notificar
        errores de bloqueo mutuo (EDEADLK) para operaciones de mutex
        válidas si <code>fcntl()</code> no es consciente de los
        hilos (thread-aware), como ocurre en Solaris.</p>
	</note>
        </li>

        <li><code>flock:/path/to/mutex</code>
        <p>Esto es similar al método <code>fcntl:/path/to/mutex</code>,
        con la excepción de que se usa la función <code>flock()</code>
        para proporcionar el bloqueo de ficheros.</p></li>

        <li><code>file:/path/to/mutex</code>
        <p>Esto selecciona la "mejor" implementación de bloqueo de
        ficheros disponible, eligiendo entre <code>fcntl</code> y
        <code>flock</code>, en ese orden.</p></li>
    </ul>

    <p>La mayoría de los mecanismos solo están disponibles en
    determinadas plataformas, cuando la plataforma subyacente y
    <glossary>APR</glossary> los soportan. Los mecanismos que no
    están disponibles en todas las plataformas son <em>posixsem</em>,
    <em>sysvsem</em>, <em>sem</em>, <em>pthread</em>, <em>fcntl</em>,
    <em>flock</em>, y <em>file</em>.</p>

    <p>Con los mecanismos basados en fichero <em>fcntl</em> y
    <em>flock</em>, la ruta, si se proporciona, es un directorio en
    el que se creará el fichero de bloqueo. El directorio por
    defecto es el directorio de ficheros en tiempo de ejecución de
    httpd, <directive module="core">DefaultRuntimeDir</directive>.
    Si se proporciona una ruta relativa, es relativa a
    <directive module="core">DefaultRuntimeDir</directive>. Use
    siempre un sistema de ficheros de disco local para
    <code>/path/to/mutex</code> y nunca un directorio que resida en
    un sistema de ficheros NFS o AFS. El nombre base del fichero será
    el tipo de mutex, una cadena de instancia opcional proporcionada
    por el módulo, y, a menos que se especifique la palabra clave
    <code>OmitPID</code>, se añadirá el identificador de proceso del
    proceso padre de httpd para hacer único el nombre del fichero,
    evitando conflictos cuando varias instancias de httpd comparten
    un directorio de ficheros de bloqueo. Por ejemplo, si el nombre
    del mutex es <code>mpm-accept</code> y el directorio de ficheros
    de bloqueo es <code>/var/httpd/locks</code>, el nombre del
    fichero de bloqueo para la instancia de httpd con identificador
    de proceso padre 12345 sería
    <code>/var/httpd/locks/mpm-accept.12345</code>.</p>

    <note type="warning"><title>Seguridad</title>
    <p>Es mejor <em>evitar</em> colocar los ficheros de mutex en un
    directorio con permiso de escritura para todos, como
    <code>/var/tmp</code>, porque alguien podría provocar un ataque
    de denegación de servicio e impedir que el servidor arranque
    creando un fichero de bloqueo con el mismo nombre que el que el
    servidor intentará crear.</p>
    </note>

    <p>La siguiente tabla documenta los nombres de los mutex usados
    por httpd y los módulos incluidos.</p>

    <table border="1" style="zebra">
        <tr>
            <th>Nombre del mutex</th>
            <th>Módulo(s)</th>
            <th>Recurso protegido</th>
	</tr>
        <tr>
            <td><code>mpm-accept</code></td>
            <td>MPMs <module>prefork</module> y <module>worker</module></td>
            <td>conexiones entrantes, para evitar el problema de la
            estampida (thundering herd); para más información,
            consulte la documentación de <a
            href="../misc/perf-tuning.html">ajuste de rendimiento</a></td>
	</tr>
        <tr>
            <td><code>authdigest-client</code></td>
            <td><module>mod_auth_digest</module></td>
            <td>lista de clientes en memoria compartida</td>
	</tr>
        <tr>
            <td><code>authdigest-opaque</code></td>
            <td><module>mod_auth_digest</module></td>
            <td>contador en memoria compartida</td>
	</tr>
        <tr>
            <td><code>ldap-cache</code></td>
            <td><module>mod_ldap</module></td>
            <td>caché de resultados LDAP</td>
	</tr>
        <tr>
            <td><code>rewrite-map</code></td>
            <td><module>mod_rewrite</module></td>
            <td>comunicación con programas de mapeo externos, para
            evitar que se entremezcle la E/S de varias peticiones</td>
	</tr>
        <tr>
            <td><code>ssl-cache</code></td>
            <td><module>mod_ssl</module></td>
            <td>caché de sesiones SSL</td>
	</tr>
        <tr>
            <td><code>ssl-stapling</code></td>
            <td><module>mod_ssl</module></td>
            <td>caché de respuestas de OCSP stapling</td>
	</tr>
        <tr>
            <td><code>watchdog-callback</code></td>
            <td><module>mod_watchdog</module></td>
            <td>función de retrollamada (callback) de un módulo
            cliente concreto</td>
	</tr>
    </table>

    <p>La palabra clave <code>OmitPID</code> suprime la adición del
    identificador del proceso padre de httpd al nombre del fichero de
    bloqueo.</p>

    <p>En el siguiente ejemplo, el mecanismo de mutex para el mutex
    de aceptación del MPM se cambiará del valor por defecto
    compilado a <code>fcntl</code>, con el fichero de bloqueo
    asociado creado en el directorio <code>/var/httpd/locks</code>.
    El mecanismo de mutex para todos los demás mutex se cambiará del
    valor por defecto compilado a <code>sysvsem</code>.</p>

    <highlight language="config">
Mutex sysvsem default
Mutex fcntl:/var/httpd/locks mpm-accept
    </highlight>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>NameVirtualHost</name>
<description>OBSOLETA: Designa una dirección IP para alojamiento
virtual basado en nombre</description>
<syntax>NameVirtualHost <var>addr</var>[:<var>port</var>]</syntax>
<contextlist><context>server config</context></contextlist>

<usage>

<p>Antes de la versión 2.3.11, era necesario usar
<directive>NameVirtualHost</directive> para indicar al servidor que
una combinación concreta de dirección IP y puerto podía usarse como
host virtual basado en nombre. En la versión 2.3.11 y posteriores, el
alojamiento virtual basado en nombre se activa automáticamente para
una dirección en cuanto esa combinación de dirección IP y puerto se
usa en varios hosts virtuales.</p>

<p>Esta directiva actualmente no tiene ningún efecto.</p>
</usage>

<seealso><a href="../vhosts/">Documentación de los Hosts
Virtuales</a></seealso>

</directivesynopsis>

<directivesynopsis>
<name>Options</name>
<description>Configura qué características están disponibles en un
directorio concreto</description>
<syntax>Options
    [+|-]<var>option</var> [[+|-]<var>option</var>] ...</syntax>
<default>Options FollowSymlinks</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>Options</override>
<compatibility>El valor por defecto cambió de All a FollowSymlinks en la
versión 2.3.11</compatibility>

<usage>
    <p>La directiva <directive>Options</directive> controla qué
    características del servidor están disponibles en un directorio
    concreto.</p>

    <p><var>option</var> se puede establecer a <code>None</code>, en
    cuyo caso no se habilita ninguna de las características
    adicionales, o a una o más de las siguientes:</p>

    <dl>
      <dt><code>All</code></dt>

      <dd>Todas las opciones excepto <code>MultiViews</code>.</dd>

      <dt><code>ExecCGI</code></dt>

      <dd>
      Se permite la ejecución de scripts CGI mediante
      <module>mod_cgi</module>.</dd>

      <dt><code>FollowSymLinks</code></dt>

      <dd>
      El servidor seguirá los enlaces simbólicos en este directorio.
      Este es el ajuste por defecto.
      <note>
      <p>Cuando el servidor sigue el enlace simbólico, <em>no</em>
      cambia el nombre de ruta usado para comparar con las secciones
      <directive type="section" module="core">Directory</directive>.</p>

      <p>Deshabilitar esta opción también impide que
      <module>mod_rewrite</module> funcione en el contexto por
      directorio (ficheros <code>.htaccess</code> y secciones
      <directive type="section" module="core">Directory</directive>).</p>

      <p>Las opciones <code>FollowSymLinks</code> y
      <code>SymLinksIfOwnerMatch</code> de <directive
      module="core">Options</directive> solo funcionan en secciones
      <directive type="section" module="core">Directory</directive> o
      en ficheros <code>.htaccess</code>.</p>

      <p>Omitir esta opción no debería considerarse una restricción
      de seguridad, ya que la comprobación de enlaces simbólicos está
      sujeta a condiciones de carrera que hacen que se pueda eludir.</p>
      </note></dd>

      <dt><code>Includes</code></dt>

      <dd>
      Se permiten los contenidos del lado del servidor (server-side
      includes) proporcionados por <module>mod_include</module>.</dd>

      <dt><code>IncludesNOEXEC</code></dt>

      <dd>

      Se permiten los contenidos del lado del servidor, pero
      <code>#exec cmd</code> y <code>#exec cgi</code> están
      deshabilitados. Aun así es posible hacer <code>#include
      virtual</code> de scripts CGI desde directorios con
      <directive module="mod_alias">ScriptAlias</directive>.</dd>

      <dt><code>Indexes</code></dt>

      <dd>
      Si se solicita una URL que se mapea a un directorio y no hay
      ningún <directive module="mod_dir">DirectoryIndex</directive>
      (<em>p. ej.</em>, <code>index.html</code>) en ese directorio,
      entonces <module>mod_autoindex</module> devolverá un listado
      con formato del directorio.</dd>

      <dt><code>MultiViews</code></dt>

      <dd>
      Se permiten los "MultiViews" con <a
      href="../content-negotiation.html">negociación de
      contenido</a> usando <module>mod_negotiation</module>.
      <note><title>Nota</title> <p>Esta opción se ignora si se
      establece en un lugar distinto de una sección <directive
      module="core" type="section">Directory</directive>, ya que
      <module>mod_negotiation</module> necesita recursos reales con
      los que comparar y a partir de los cuales evaluar.</p></note>
      </dd>

      <dt><code>SymLinksIfOwnerMatch</code></dt>

      <dd>El servidor solo seguirá los enlaces simbólicos para los
      que el fichero o directorio de destino tenga el mismo id de
      usuario que el enlace.

      <note><title>Nota</title>
      <p>Las opciones <code>FollowSymLinks</code> y
      <code>SymLinksIfOwnerMatch</code> de <directive
      module="core">Options</directive> solo funcionan en secciones
      <directive type="section" module="core">Directory</directive> o
      en ficheros <code>.htaccess</code>.</p>

      <p>Esta opción no debería considerarse una restricción de
      seguridad, ya que la comprobación de enlaces simbólicos está
      sujeta a condiciones de carrera que hacen que se pueda eludir.</p>
      </note> </dd>
    </dl>

    <p>Normalmente, si varias <directive>Options</directive> pudieran
    aplicarse a un directorio, se usa la más específica y las demás
    se ignoran; las opciones no se fusionan. (Vea <a
    href="../sections.html#merging">cómo se fusionan las
    secciones</a>.) Sin embargo, si <em>todas</em> las opciones de la
    directiva <directive>Options</directive> van precedidas de un
    símbolo <code>+</code> o <code>-</code>, las opciones se
    fusionan. Cualquier opción precedida de <code>+</code> se añade a
    las opciones actualmente en vigor, y cualquier opción precedida
    de <code>-</code> se elimina de las opciones actualmente en
    vigor.</p>

    <note><title>Nota</title>
    <p>Mezclar <directive>Options</directive> con <code>+</code> o
    <code>-</code> con otras que no los lleven no es una sintaxis
    válida, y la comprobación de sintaxis lo rechazará al arrancar el
    servidor, abortando el arranque.</p>
    </note>

    <p>Por ejemplo, sin ningún símbolo <code>+</code> ni <code>-</code>:</p>

    <highlight language="config">
&lt;Directory "/web/docs"&gt;
  Options Indexes FollowSymLinks
&lt;/Directory&gt;

&lt;Directory "/web/docs/spec"&gt;
  Options Includes
&lt;/Directory&gt;
    </highlight>

    <p>entonces solo se establecerá <code>Includes</code> para el
    directorio <code>/web/docs/spec</code>. Sin embargo, si la segunda
    directiva <directive>Options</directive> usa los símbolos
    <code>+</code> y <code>-</code>:</p>

    <highlight language="config">
&lt;Directory "/web/docs"&gt;
  Options Indexes FollowSymLinks
&lt;/Directory&gt;

&lt;Directory "/web/docs/spec"&gt;
  Options +Includes -Indexes
&lt;/Directory&gt;
    </highlight>

    <p>entonces las opciones <code>FollowSymLinks</code> e
    <code>Includes</code> se establecen para el directorio
    <code>/web/docs/spec</code>.</p>

    <note><title>Nota</title>
      <p>Usar <code>-IncludesNOEXEC</code> o <code>-Includes</code>
      deshabilita completamente los contenidos del lado del servidor,
      independientemente del ajuste anterior.</p>
    </note>

    <p>El valor por defecto en ausencia de cualquier otro ajuste es
    <code>FollowSymlinks</code>.</p>

    <p>Cuando se usan <code>All</code> y <code>None</code>, deben ser
    la primera opción listada. Los modificadores + y - no se pueden
    usar con las opciones <code>All</code> y <code>None</code>.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>Protocol</name>
<description>Protocolo para un socket a la escucha</description>
<syntax>Protocol <var>protocol</var></syntax>
<contextlist><context>server config</context><context>virtual host</context></contextlist>
<compatibility>En Windows, solo disponible desde Apache 2.3.3.</compatibility>

<usage>
    <p>Esta directiva especifica el protocolo usado para un socket a
       la escucha concreto. El protocolo se usa para determinar qué
       módulo debe gestionar una petición y para aplicar
       optimizaciones específicas del protocolo con la directiva
       <directive>AcceptFilter</directive>.</p>

    <p>Esta directiva no es necesaria para la mayoría de las
       configuraciones. Si no se especifica, <code>https</code> es el
       valor por defecto para el puerto 443 y <code>http</code> el
       valor por defecto para todos los demás puertos. El protocolo
       se usa para determinar qué módulo debe gestionar una petición,
       y para aplicar optimizaciones específicas del protocolo con la
       directiva <directive module="core">AcceptFilter</directive>.</p>

    <p>Por ejemplo, si está ejecutando <code>https</code> en un
       puerto no estándar, especifique el protocolo explícitamente:</p>

    <highlight language="config">
Protocol https
    </highlight>

    <p>También puede especificar el protocolo usando la directiva
       <directive module="mpm_common">Listen</directive>.</p>
</usage>
<seealso><directive module="core">AcceptFilter</directive></seealso>
<seealso><directive module="mpm_common">Listen</directive></seealso>
</directivesynopsis>


<directivesynopsis>
    <name>Protocols</name>
    <description>Protocolos disponibles para un servidor/host virtual</description>
    <syntax>Protocols <var>protocolo</var> ...</syntax>
    <default>Protocols http/1.1</default>
    <contextlist><context>server config</context><context>virtual host</context></contextlist>
    <compatibility>Disponible solo a partir de Apache 2.4.17.</compatibility>

    <usage>
        <p>Esta directiva especifica la lista de protocolos soportados
            para un servidor/host virtual. La lista determina los
            protocolos permitidos que un cliente puede negociar para
            este servidor/host.</p>

        <p>Necesita establecer los protocolos si quiere ampliar los
            protocolos disponibles para un servidor/host. Por defecto,
            solo se permite el protocolo http/1.1 (que incluye la
            compatibilidad con clientes 1.0 y 0.9).</p>

        <p>Por ejemplo, si quiere soportar HTTP/2 para un servidor con
            TLS, especifique:</p>

        <highlight language="config">
Protocols h2 http/1.1
        </highlight>

        <p>Los protocolos válidos son <code>http/1.1</code> para
            conexiones http y https, <code>h2</code> en conexiones
            https y <code>h2c</code> para conexiones http. Los módulos
            pueden habilitar más protocolos.</p>

        <p>Es seguro especificar protocolos que no estén
        disponibles/habilitados. Esos nombres de protocolo simplemente
        se ignorarán.</p>

        <note><title>Nota</title>
        <p>El protocolo <code>http/1.1</code> siempre está disponible y
            no se puede excluir omitiéndolo de esta directiva. Esta
            directiva controla qué protocolos adicionales están
            disponibles para la negociación y, cuando se usa junto con
            <directive>ProtocolsHonorOrder</directive>, su orden de
            preferencia.</p></note>

        <p>Los protocolos especificados en los servidores base se
            heredan en los hosts virtuales solo si el host virtual no
            tiene su propia directiva Protocols. O, dicho de otro modo,
            las directivas Protocols en los hosts virtuales sustituyen a
            cualquier directiva de este tipo en el servidor base.
        </p>

    </usage>
    <seealso><directive module="core">ProtocolsHonorOrder</directive></seealso>
</directivesynopsis>


<directivesynopsis>
    <name>ProtocolsHonorOrder</name>
    <description>Determina si el orden de Protocols determina la
    precedencia durante la negociación</description>
    <syntax>ProtocolsHonorOrder On|Off</syntax>
    <default>ProtocolsHonorOrder On</default>
    <contextlist><context>server config</context><context>virtual host</context></contextlist>
    <compatibility>Disponible solo a partir de Apache 2.4.17.</compatibility>

    <usage>
        <p>Esta directiva especifica si el servidor debe respetar el
        orden en el que la directiva <directive>Protocols</directive>
        lista los protocolos.</p>

        <p>Si se configura a Off, el orden de la lista de protocolos
            proporcionada por el cliente tiene precedencia sobre el
            orden de la configuración del servidor.</p>

        <p>Con <directive>ProtocolsHonorOrder</directive> establecido a
            <code>on</code> (valor por defecto), el orden del cliente no
            importa y solo el orden de los ajustes del servidor influye
            en el resultado de la negociación del protocolo.</p>

    </usage>
    <seealso><directive module="core">Protocols</directive></seealso>
</directivesynopsis>


<directivesynopsis>
<name>ReadBufferSize</name>
<description>Tamaño de los búferes usados para leer datos</description>
<syntax>ReadBufferSize <var>bytes</var></syntax>
<default>ReadBufferSize 8192</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>
<compatibility>2.5 y posteriores</compatibility>

<usage>
    <p>Esta directiva permite configurar el tamaño (en bytes) del búfer
    de memoria usado para leer datos de la red o de ficheros.</p>

    <p>Un búfer más grande puede mejorar el rendimiento con datos de
    mayor tamaño, pero consume más memoria por conexión. El tamaño
    mínimo configurable es <var>1024</var>.</p>
</usage>
</directivesynopsis>


<directivesynopsis>
    <name>RegexDefaultOptions</name>
    <description>Permite configurar opciones globales/por defecto para
    las expresiones regulares</description>
    <syntax>RegexDefaultOptions [none] [+|-]<var>opción</var> [[+|-]<var>opción</var>] ...</syntax>
    <default>RegexDefaultOptions DOTALL DOLLAR_ENDONLY</default>
    <contextlist><context>server config</context></contextlist>
    <compatibility>Disponible solo a partir de Apache 2.4.30.</compatibility>

    <usage>
        <p>Esta directiva añade cierto comportamiento por defecto a
        CUALQUIER expresión regular usada a partir de ese momento.</p>

        <p>Cualquier opción precedida de un '+' se añade a las opciones
        ya establecidas.<br />
        Cualquier opción precedida de un '-' se elimina de las opciones
        ya establecidas.<br />
        Cualquier opción sin '+' ni '-' se establecerá, eliminando
        cualquier otra opción ya establecida.<br />
        La palabra clave <code>none</code> restablece cualquier opción
        ya establecida.</p>

        <p><var>opción</var> puede ser:</p>
        <dl>
            <dt><code>ICASE</code></dt>
            <dd>Usa una coincidencia que no distingue mayúsculas y
            minúsculas.</dd>

            <dt><code>EXTENDED</code></dt>
            <dd>El indicador /x de Perl: ignora los espacios (sin
            escapar) y los comentarios en el patrón.</dd>

            <dt><code>DOTALL</code></dt>
            <dd>El indicador /s de Perl: '.' coincide con los
            caracteres de salto de línea.</dd>

            <dt><code>DOLLAR_ENDONLY</code></dt>
            <dd>'$' coincide solo al final de la cadena.</dd>
        </dl>
        <highlight language="config">
# Restablecer todas las opciones por defecto/definidas
RegexDefaultOptions none
# Añadir la opción ICASE para todas las expresiones regulares por defecto
RegexDefaultOptions +ICASE
...
# Añadir la opción ICASE a las ya aplicables
RegexDefaultOptions +ICASE
# Eliminar la opción DOLLAR_ENDONLY por defecto, pero mantener cualquier otra
RegexDefaultOptions -DOLLAR_ENDONLY
...
# Establecer solo la opción DOTALL, restableciendo cualquier otra
RegexDefaultOptions DOTALL
...
# Establecer solo las opciones DOTALL e ICASE
# Las opciones se aplican en orden y de forma ciega, así que:
#   RegexDefaultOptions DOTALL ICASE
# no funcionaría como podría esperarse (ICASE anula DOTALL)
RegexDefaultOptions none +DOTALL +ICASE
# o "simplemente"
RegexDefaultOptions DOTALL +ICASE
...
        </highlight>
    </usage>
</directivesynopsis>


<directivesynopsis>
<name>RLimitCPU</name>
<description>Limita el consumo de CPU de los procesos lanzados por
los procesos hijos de Apache httpd</description>
<syntax>RLimitCPU <var>seconds</var>|max [<var>seconds</var>|max]</syntax>
<default>Sin establecer; usa los valores por defecto del sistema
operativo</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>All</override>

<usage>
    <p>Toma 1 o 2 parámetros. El primer parámetro establece el límite
    de recursos "soft" para todos los procesos y el segundo parámetro
    establece el límite de recursos máximo. Cualquiera de los
    parámetros puede ser un número, o <code>max</code> para indicar
    al servidor que el límite debe establecerse al máximo permitido
    por la configuración del sistema operativo. Aumentar el límite
    de recursos máximo requiere que el servidor se esté ejecutando
    como <code>root</code>, o que esté en la fase inicial de
    arranque.</p>

    <p>Esto se aplica a los procesos lanzados (forked) desde los
    procesos hijos de Apache httpd que atienden peticiones, no a los
    propios procesos hijos de Apache httpd. Esto incluye los scripts
    CGI y los comandos exec de SSI, pero no los procesos lanzados
    desde el proceso padre de Apache httpd, como los registros con
    tubería (piped logs).</p>

    <p>Los límites de recursos de CPU se expresan en segundos por
    proceso.</p>
</usage>
<seealso><directive module="core">RLimitMEM</directive></seealso>
<seealso><directive module="core">RLimitNPROC</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>RLimitMEM</name>
<description>Limita el consumo de memoria de los procesos lanzados
por los procesos hijos de Apache httpd</description>
<syntax>RLimitMEM <var>bytes</var>|max [<var>bytes</var>|max]</syntax>
<default>Sin establecer; usa los valores por defecto del sistema
operativo</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>All</override>

<usage>
    <p>Toma 1 o 2 parámetros. El primer parámetro establece el límite
    de recursos "soft" para todos los procesos y el segundo parámetro
    establece el límite de recursos máximo. Cualquiera de los
    parámetros puede ser un número, o <code>max</code> para indicar
    al servidor que el límite debe establecerse al máximo permitido
    por la configuración del sistema operativo. Aumentar el límite
    de recursos máximo requiere que el servidor se esté ejecutando
    como <code>root</code>, o que esté en la fase inicial de
    arranque.</p>

    <p>Esto se aplica a los procesos lanzados (forked) desde los
    procesos hijos de Apache httpd que atienden peticiones, no a los
    propios procesos hijos de Apache httpd. Esto incluye los scripts
    CGI y los comandos exec de SSI, pero no los procesos lanzados
    desde el proceso padre de Apache httpd, como los registros con
    tubería (piped logs).</p>

    <p>Los límites de recursos de memoria se expresan en bytes por
    proceso.</p>
</usage>
<seealso><directive module="core">RLimitCPU</directive></seealso>
<seealso><directive module="core">RLimitNPROC</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>RLimitNPROC</name>
<description>Limita el número de procesos que pueden ser lanzados por
los procesos lanzados por los procesos hijos de Apache httpd</description>
<syntax>RLimitNPROC <var>number</var>|max [<var>number</var>|max]</syntax>
<default>Sin establecer; usa los valores por defecto del sistema
operativo</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>All</override>

<usage>
    <p>Toma 1 o 2 parámetros. El primer parámetro establece el límite
    de recursos "soft" para todos los procesos, y el segundo
    parámetro establece el límite de recursos máximo. Cualquiera de
    los parámetros puede ser un número, o <code>max</code> para
    indicar al servidor que el límite debe establecerse al máximo
    permitido por la configuración del sistema operativo. Aumentar el
    límite de recursos máximo requiere que el servidor se esté
    ejecutando como <code>root</code>, o que esté en la fase inicial
    de arranque.</p>

    <p>Esto se aplica a los procesos lanzados (forked) desde los
    procesos hijos de Apache httpd que atienden peticiones, no a los
    propios procesos hijos de Apache httpd. Esto incluye los scripts
    CGI y los comandos exec de SSI, pero no los procesos lanzados
    desde el proceso padre de Apache httpd, como los registros con
    tubería (piped logs).</p>

    <p>Los límites de procesos controlan el número de procesos por
    usuario.</p>

    <note><title>Nota</title>
      <p>Si los procesos CGI <strong>no</strong> se ejecutan con
      identificadores de usuario distintos del identificador de
      usuario del servidor web, esta directiva limitará el número de
      procesos que el propio servidor puede crear. Un indicio de esta
      situación serán los mensajes <strong><code>cannot
      fork</code></strong> en el <code>error_log</code>.</p>
    </note>
</usage>
<seealso><directive module="core">RLimitMEM</directive></seealso>
<seealso><directive module="core">RLimitCPU</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>ScriptInterpreterSource</name>
<description>Técnica para localizar el interpretador para los
scripts CGI</description>
<syntax>ScriptInterpreterSource Registry|Registry-Strict|Script</syntax>
<default>ScriptInterpreterSource Script</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>FileInfo</override>
<compatibility>Solo Win32.</compatibility>

<usage>
    <p>Esta directiva se usa para controlar cómo encuentra Apache
    httpd el interpretador usado para ejecutar los scripts CGI. El
    ajuste por defecto es <code>Script</code>. Esto hace que Apache
    httpd use el interpretador al que apunta la línea shebang
    (primera línea, que empieza por <code>#!</code>) del script. En
    sistemas Win32 esta línea normalmente tiene este aspecto:</p>

    <highlight language="perl">
#!C:/Perl/bin/perl.exe
    </highlight>

    <p>o, si <code>perl</code> está en el <code>PATH</code>,
    simplemente:</p>

    <highlight language="perl">
#!perl
    </highlight>

    <p>Establecer <code>ScriptInterpreterSource Registry</code> hará
    que se busque en el árbol del registro de Windows
    <code>HKEY_CLASSES_ROOT</code> usando la extensión del fichero
    del script (p. ej., <code>.pl</code>) como clave de búsqueda. El
    comando definido por la subclave del registro
    <code>Shell\ExecCGI\Command</code> o, si no existe, por la
    subclave <code>Shell\Open\Command</code> se usa para abrir el
    fichero del script. Si no se pueden encontrar las claves del
    registro, Apache httpd recurre al comportamiento de la opción
    <code>Script</code>.</p>

    <note type="warning"><title>Seguridad</title>
    <p>Tenga cuidado al usar <code>ScriptInterpreterSource
    Registry</code> con directorios con <directive
    module="mod_alias">ScriptAlias</directive>, porque Apache httpd
    intentará ejecutar <strong>todos</strong> los ficheros dentro de
    ese directorio. El ajuste <code>Registry</code> puede provocar
    llamadas a programas no deseadas en ficheros que normalmente no
    se ejecutan. Por ejemplo, el comando de apertura por defecto para
    los ficheros <code>.htm</code> en la mayoría de los sistemas
    Windows ejecuta Microsoft Internet Explorer, de forma que
    cualquier petición HTTP de un fichero <code>.htm</code> existente
    dentro del directorio del script arrancaría el navegador en
    segundo plano en el servidor. Esta es una buena forma de colapsar
    su sistema en menos de un minuto.</p>
    </note>

    <p>La opción <code>Registry-Strict</code> hace lo mismo que
    <code>Registry</code>, pero usa solo la subclave
    <code>Shell\ExecCGI\Command</code>. La clave <code>ExecCGI</code>
    no es habitual. Debe configurarse manualmente en el registro de
    Windows, lo que evita llamadas a programas accidentales en su
    sistema.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SeeRequestTail</name>
<description>Determina si mod_status muestra los primeros 63
caracteres de una petición o los últimos 63, suponiendo que la
propia petición tenga más de 63 caracteres.</description>
<syntax>SeeRequestTail On|Off</syntax>
<default>SeeRequestTail Off</default>
<contextlist><context>server config</context></contextlist>

<usage>
    <p><module>mod_status</module> con <code>ExtendedStatus On</code>
    muestra la petición que se está gestionando en ese momento. Por
    motivos históricos, de la petición solo se almacenan 63
    caracteres a efectos de visualización. Esta directiva controla
    si se almacenan los primeros 63 caracteres (el comportamiento
    anterior y el valor por defecto) o los últimos 63. Esto, por
    supuesto, solo es aplicable si la longitud de la petición es de
    64 caracteres o más.</p>

    <p>Si Apache httpd está gestionando <code
    >GET&nbsp;/disk1/storage/apache/htdocs/images/imagestore1/food/apples.jpg&nbsp;HTTP/1.1</code
    >, <module>mod_status</module> lo muestra así:
    </p>

    <table border="1">
      <tr>
        <th>Off (por defecto)</th>
        <td>GET&nbsp;/disk1/storage/apache/htdocs/images/imagestore1/food/apples</td>
      </tr>
      <tr>
        <th>On</th>
        <td>orage/apache/htdocs/images/imagestore1/food/apples.jpg&nbsp;HTTP/1.1</td>
      </tr>
    </table>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>ServerAdmin</name>
<description>Dirección de correo que el servidor incluye en los
mensajes de error enviados al cliente</description>
<syntax>ServerAdmin <var>email-address</var>|<var>URL</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p><directive>ServerAdmin</directive> establece la dirección de
    contacto que el servidor incluye en cualquier mensaje de error
    que devuelva al cliente. Si <code>httpd</code> no reconoce el
    argumento proporcionado como una URL, asume que es una
    <var>email-address</var> y le añade el prefijo
    <code>mailto:</code> en los destinos de los hiperenlaces. Sin
    embargo, se recomienda usar realmente una dirección de correo, ya
    que hay muchos scripts CGI que asumen eso. Si quiere usar una
    URL, debería apuntar a otro servidor bajo su control. En caso
    contrario, los usuarios podrían no poder contactar con usted en
    caso de error.</p>

    <p>Puede merecer la pena configurar una dirección dedicada para
    esto, p. ej.</p>

    <highlight language="config">
ServerAdmin www-admin@foo.example.com
    </highlight>
    <p>ya que los usuarios no siempre mencionan que están hablando
    sobre el servidor.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ServerAlias</name>
<description>Alternate names for a host used when matching requests
to name-virtual hosts</description>
<syntax>ServerAlias <var>hostname</var> [<var>hostname</var>] ...</syntax>
<contextlist><context>virtual host</context></contextlist>

<usage>
    <p>La directiva <directive>ServerAlias</directive> establece los
    nombres alternativos de un host, para usar con
    <a href="../vhosts/name-based.html">hosts virtuales basados en
    nombre</a>. <directive>ServerAlias</directive> puede incluir
    comodines, si procede.</p>

    <highlight language="config">
&lt;VirtualHost *:80&gt;
  ServerName server.example.com
  ServerAlias server server2.example.com server2
  ServerAlias *.example.com
  UseCanonicalName Off
  # ...
&lt;/VirtualHost&gt;
    </highlight>

    <p>Los hosts virtuales basados en nombre del conjunto de
    <directive type="section" module="core">virtualhost</directive>s
    que mejor coincide se procesan en el orden en que aparecen en la
    configuración. Se usa el primer <directive module="core">ServerName</directive>
    o <directive module="core">ServerAlias</directive> que coincida,
    sin que haya una precedencia distinta para los comodines (ni para
    ServerName frente a ServerAlias).</p>

    <p>La lista completa de nombres en la directiva
    <directive type="section" module="core">VirtualHost</directive>
    se trata igual que un <directive>ServerAlias</directive> (sin
    comodines).</p>

</usage>
<seealso><directive module="core">UseCanonicalName</directive></seealso>
<seealso><a href="../vhosts/">Apache HTTP Server Virtual Host documentation</a></seealso>
</directivesynopsis>

<directivesynopsis>
<name>ServerName</name>
<description>Nombre de host y puerto que el servidor usa para
identificarse a sí mismo</description>
<syntax>ServerName [<var>scheme</var>://]<var>domain-name</var>|<var>ip-address</var>[:<var>port</var>]</syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive>ServerName</directive> establece el
    esquema de la petición, el nombre de host y el puerto que el
    servidor usa para identificarse a sí mismo.
    </p>

    <p><directive>ServerName</directive> se usa (posiblemente junto
    con <directive module="core">ServerAlias</directive>) para
    identificar de forma unívoca un host virtual, cuando se usan
    <a href="../vhosts/name-based.html">hosts virtuales basados en
    nombre</a>.</p>

    <p>Además, se usa al crear URLs de redirección autorreferenciales
    cuando <directive module="core">UseCanonicalName</directive> se
    establece a <code>On</code>. Cuando <code>UseCanonicalName</code>
    se establece a <code>DNS</code>, se usa en su lugar una resolución
    DNS inversa.</p>

    <p>Por ejemplo, si el nombre de la
    máquina que alberga el servidor web es <code>simple.example.com</code>,
    pero la máquina también tiene el alias DNS <code>www.example.com</code>
    y desea que el servidor web se identifique así, debe usarse la
    siguiente directiva:</p>

    <highlight language="config">
ServerName www.example.com
    </highlight>

    <p>La directiva <directive>ServerName</directive> puede aparecer
    en cualquier lugar dentro de la definición de un servidor. No
    obstante, cada aparición sobrescribe la anterior (dentro de ese
    servidor).</p>

    <p>Si no se especifica ningún <directive>ServerName</directive>,
    el servidor intenta deducir el nombre de host visible para el
    cliente preguntando primero al sistema operativo por el nombre de
    host del sistema y, si eso falla, realizando una resolución
    inversa sobre una dirección IP presente en el sistema.</p>

    <p>Si no se especifica ningún puerto en
    <directive>ServerName</directive>, el servidor usará el puerto de
    la petición entrante. Para una fiabilidad y previsibilidad
    óptimas, debería especificar un nombre de host y un puerto
    explícitos mediante la directiva <directive>ServerName</directive>.</p>

    <p>Si está usando <a
    href="../vhosts/name-based.html">hosts virtuales basados en
    nombre</a>, el <directive>ServerName</directive> dentro de una
    sección <directive type="section" module="core">VirtualHost</directive>
    especifica qué nombre de host debe aparecer en la cabecera
    <code>Host:</code> de la petición para que coincida con este host
    virtual.</p>

    <p>En ocasiones, el servidor se ejecuta detrás de un dispositivo
    que procesa SSL, como un proxy inverso, un balanceador de carga o
    un dispositivo de descarga SSL. Cuando este sea el caso,
    especifique el esquema <code>https://</code> y el número de
    puerto al que se conectan los clientes en la directiva
    <directive>ServerName</directive> para asegurarse de que el
    servidor genera las URLs autorreferenciales correctas.
    </p>

    <p>Consulte la descripción de las directivas
    <directive module="core">UseCanonicalName</directive> y
    <directive module="core">UseCanonicalPhysicalPort</directive> para
    conocer los ajustes que determinan si las URLs autorreferenciales
    (por ejemplo, las del módulo <module>mod_dir</module>) harán
    referencia al puerto especificado, o al número de puerto dado en
    la petición del cliente.
    </p>

    <note type="warning">
    <p>Si no se establece <directive>ServerName</directive> a un
    nombre que su servidor pueda resolver a una dirección IP, se
    producirá un aviso al arrancar. <code>httpd</code> usará entonces
    cualquier nombre de host que pueda determinar, usando el comando
    <code>hostname</code> del sistema. Este casi nunca será el nombre
    de host que realmente desea.</p>
    <example>
    httpd: Could not reliably determine the server's fully qualified domain name, using rocinante.local for ServerName
    </example>
    </note>

    <note type="warning">
    <p>Las direcciones IPv6 en <directive>ServerName</directive> no
        se soportan actualmente y producirán un error al arrancar,
        incluso encerradas entre corchetes. Este es un
        <a href="https://bz.apache.org/bugzilla/show_bug.cgi?id=52178"
        >problema conocido</a>.</p></note>

</usage>

<seealso><a href="../dns-caveats.html">Issues Regarding DNS and
    Apache HTTP Server</a></seealso>
<seealso><a href="../vhosts/">Apache HTTP Server virtual host
    documentation</a></seealso>
<seealso><directive module="core">UseCanonicalName</directive></seealso>
<seealso><directive module="core">UseCanonicalPhysicalPort</directive></seealso>
<seealso><directive module="core">ServerAlias</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>ServerPath</name>
<description>Ruta URL heredada de un host virtual basado en nombre
al que accede un navegador incompatible</description>
<syntax>ServerPath <var>URL-path</var></syntax>
<contextlist><context>virtual host</context></contextlist>

<usage>
    <p>La directiva <directive>ServerPath</directive> establece la
    ruta URL heredada de un host, para usarla con <a
    href="../vhosts/name-based.html">hosts virtuales basados en
    nombre</a>.</p>

    <note><p>Esta es una característica heredada que proporciona
    compatibilidad con clientes HTTP/1.0 que no envían una cabecera
    <code>Host:</code>. Cuando un cliente de ese tipo solicita una
    URL que coincide con el <directive>ServerPath</directive> de un
    host virtual, la petición se sirve desde ese host virtual. En la
    práctica, todos los clientes HTTP modernos envían la cabecera
    <code>Host:</code>, lo que hace innecesaria esta directiva.</p></note>
</usage>
<seealso><a href="../vhosts/name-based.html">Soporte de hosts
    virtuales basados en nombre</a></seealso>
<seealso><a href="../vhosts/examples.html#serverpath">Ejemplo de
    ServerPath</a></seealso>
</directivesynopsis>

<directivesynopsis>
<name>ServerRoot</name>
<description>Directorio base para la instalación del servidor</description>
<syntax>ServerRoot <var>directory-path</var></syntax>
<default>ServerRoot /usr/local/apache</default>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>La directiva <directive>ServerRoot</directive> establece el
    directorio en el que vive el servidor. Normalmente contendrá los
    subdirectorios <code>conf/</code> y <code>logs/</code>. Las rutas
    relativas en otras directivas de configuración (como <directive
    module="core">Include</directive> o <directive
    module="mod_so">LoadModule</directive>, por ejemplo) se toman
    como relativas a este directorio.</p>

    <highlight language="config">
ServerRoot "/home/httpd"
    </highlight>

    <p>La ubicación por defecto de <directive>ServerRoot</directive>
    se puede modificar usando el argumento <code>--prefix</code> de
    <a href="../programs/configure.html"><code>configure</code></a>,
    y la mayoría de las distribuciones de terceros del servidor
    tienen una ubicación por defecto distinta de la indicada más
    arriba.</p>

</usage>
<seealso><a href="../invoking.html">la opción <code>-d</code>
    de <code>httpd</code></a></seealso>
<seealso><a href="../misc/security_tips.html#serverroot">los
    consejos de seguridad</a> para obtener información sobre cómo
    establecer correctamente los permisos de
    <directive>ServerRoot</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>ServerSignature</name>
<description>Configura el pie de página de los documentos generados
por el servidor</description>
<syntax>ServerSignature On|Off|EMail</syntax>
<default>ServerSignature Off</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>All</override>

<usage>
    <p>La directiva <directive>ServerSignature</directive> permite
    configurar una línea de pie de página al final de los documentos
    generados por el servidor (mensajes de error, listados de
    directorios ftp de <module>mod_proxy</module>, salida de
    <module>mod_info</module>, ...). La razón por la que podría
    querer habilitar esa línea de pie de página es que, en una cadena
    de proxies, el usuario a menudo no tiene forma de saber cuál de
    los servidores encadenados produjo realmente un mensaje de error
    devuelto.</p>

    <p>El ajuste <code>Off</code>, que es el valor por defecto,
    suprime la línea de pie de página. El ajuste <code>On</code>
    simplemente añade una línea con el número de versión del
    servidor y el <directive module="core">ServerName</directive>
    del host virtual que atiende la petición, y el ajuste
    <code>EMail</code> además crea una referencia "mailto:" al
    <directive module="core">ServerAdmin</directive> del documento
    referenciado.</p>

    <p>Los detalles del número de versión del servidor que se
    muestran se controlan mediante la directiva
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
    <p>Esta directiva controla si el campo de cabecera de respuesta
    <code>Server</code> que se devuelve a los clientes incluye una
    descripción del tipo genérico de sistema operativo del servidor,
    así como información sobre los módulos compilados.</p>

    <dl>
      <dt><code>ServerTokens Full</code> (o sin especificar)</dt>

      <dd>El servidor envía (<em>p. ej.</em>): <code>Server: Apache/2.4.2
      (Unix) PHP/4.2.2 MyMod/1.2</code></dd>

      <dt><code>ServerTokens Prod[uctOnly]</code></dt>

      <dd>El servidor envía (<em>p. ej.</em>): <code>Server:
      Apache</code></dd>

      <dt><code>ServerTokens Major</code></dt>

      <dd>El servidor envía (<em>p. ej.</em>): <code>Server:
      Apache/2</code></dd>

      <dt><code>ServerTokens Minor</code></dt>

      <dd>El servidor envía (<em>p. ej.</em>): <code>Server:
      Apache/2.4</code></dd>

      <dt><code>ServerTokens Min[imal]</code></dt>

      <dd>El servidor envía (<em>p. ej.</em>): <code>Server:
      Apache/2.4.2</code></dd>

      <dt><code>ServerTokens OS</code></dt>

      <dd>El servidor envía (<em>p. ej.</em>): <code>Server: Apache/2.4.2
      (Unix)</code></dd>

    </dl>

    <p>Este ajuste se aplica a todo el servidor, y no se puede
    habilitar o deshabilitar host virtual por host virtual.</p>

    <p>Esta directiva también controla la información que presenta
    la directiva <directive module="core">ServerSignature</directive>.</p>

    <note>No se recomienda establecer <directive>ServerTokens</directive>
    por debajo de <code>minimal</code>, porque dificulta la
    depuración de problemas de interoperabilidad. Tenga en cuenta
    también que deshabilitar la cabecera Server: no hace absolutamente
    nada para que su servidor sea más seguro. La idea de la
    "seguridad mediante la ofuscación" es un mito y lleva a una
    falsa sensación de seguridad.</note>
</usage>
<seealso><directive module="core">ServerSignature</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>SetHandler</name>
<description>Fuerza a que todos los ficheros coincidentes sean
procesados por un manejador</description>
<syntax>SetHandler <var>nombre-de-manejador</var>|none|<var>expresión</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>FileInfo</override>
<compatibility>2.5 y posteriores</compatibility>

<usage>
    <p>Cuando se coloca en un fichero <code>.htaccess</code> o en una
    sección <directive type="section" module="core">Directory</directive>
    o <directive type="section" module="core">Location</directive>,
    esta directiva fuerza a que todos los ficheros coincidentes se
    analicen mediante el <a href="../handler.html">manejador</a>
    indicado por <var>nombre-de-manejador</var>. Por ejemplo, si
    tuviera un directorio que quisiera que se analizara por completo
    como ficheros de reglas de imagemap, independientemente de la
    extensión, podría poner lo siguiente en un fichero
    <code>.htaccess</code> de ese directorio:</p>

    <highlight language="config">
SetHandler imap-file
    </highlight>

    <p>Otro ejemplo: si quisiera que el servidor mostrara un informe
    de estado cada vez que se llamara a una URL
    <code>http://nombreservidor/status</code>, podría poner lo
    siguiente en <code>httpd.conf</code>:</p>

    <highlight language="config">
&lt;Location "/status"&gt;
  SetHandler server-status
&lt;/Location&gt;
    </highlight>

    <p>También podría usar esta directiva para configurar un manejador
    concreto para los ficheros con una extensión de fichero concreta.
    Por ejemplo:</p>

    <highlight language="config">
&lt;FilesMatch "\.php$"&gt;
    SetHandler application/x-httpd-php
&lt;/FilesMatch&gt;
    </highlight>

    <p>Se pueden usar expresiones con valor de cadena para hacer
    referencia a variables por petición, incluyendo referencias hacia
    atrás a expresiones regulares con nombre:</p>

    <highlight language="config">
&lt;LocationMatch ^/app/(?&lt;sub&gt;[^/]+)/&gt;
     SetHandler "proxy:unix:/var/run/app_%{env:MATCH_sub}.sock|fcgi://localhost:8080"
&lt;/LocationMatch&gt;
    </highlight>

    <p>Puede sobrescribir una directiva <directive>SetHandler</directive>
    definida anteriormente usando el valor <code>None</code>.</p>

    <note><title>Nota</title>
    <p>Dado que <directive>SetHandler</directive> sobrescribe los
    manejadores por defecto, se suprime el comportamiento normal, como
    el tratamiento de las URLs que terminan en una barra (/) como
    directorios o ficheros de índice. También sobrescribe
    <directive module="mod_dir">FallbackResource</directive>, ya que la
    petición ya tiene asignado explícitamente un manejador.</p></note>

    <note><title>Orden de fusión con Files/FilesMatch</title>
    <p>Un <directive>SetHandler</directive> establecido dentro de una
    sección <directive type="section" module="core">Files</directive>
    o <directive type="section" module="core">FilesMatch</directive>
    se fusiona <em>después</em> de uno establecido en una sección
    <directive type="section" module="core">Directory</directive> o en
    un fichero <code>.htaccess</code> para la misma petición, y por
    tanto lo sobrescribe, incluso cuando el <code>.htaccess</code>
    parezca más específico. Consulte <a
    href="../sections.html#merging">Cómo se fusionan las
    secciones</a> para conocer el orden de fusión completo.</p></note>
</usage>

<seealso><directive module="mod_mime">AddHandler</directive></seealso>
<seealso><directive module="mod_dir">FallbackResource</directive></seealso>

</directivesynopsis>

<directivesynopsis>
<name>SetInputFilter</name>
<description>Establece los filtros que procesarán las peticiones del
cliente y los datos POST</description>
<syntax>SetInputFilter <var>filter</var>[;<var>filter</var>...]</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>FileInfo</override>

<usage>
    <p>La directiva <directive>SetInputFilter</directive> establece
    el filtro o filtros que procesarán las peticiones del cliente y
    los datos POST cuando el servidor los reciba. Esto se añade a
    cualquier filtro definido en otro lugar, incluida la directiva
    <directive module="mod_mime">AddInputFilter</directive>.</p>

    <p>Si se especifica más de un filtro, deben separarse con punto
    y coma, en el orden en el que deben procesar el contenido.</p>
</usage>
<seealso>documentación de <a href="../filter.html">Filtros</a></seealso>
</directivesynopsis>

<directivesynopsis>
<name>SetOutputFilter</name>
<description>Establece los filtros que procesarán las respuestas del
servidor</description>
<syntax>SetOutputFilter <var>filter</var>[;<var>filter</var>...]</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>FileInfo</override>

<usage>
    <p>La directiva <directive>SetOutputFilter</directive> establece
    los filtros que procesarán las respuestas del servidor antes de
    enviarlas al cliente. Esto se añade a cualquier filtro definido
    en otro lugar, incluida la directiva
    <directive module="mod_mime">AddOutputFilter</directive>.</p>

    <p>Por ejemplo, la siguiente configuración procesará todos los
    ficheros del directorio <code>/www/data/</code> como contenidos
    del lado del servidor (server-side includes).</p>

    <highlight language="config">
&lt;Directory "/www/data/"&gt;
  SetOutputFilter INCLUDES
&lt;/Directory&gt;
    </highlight>

    <p>Si se especifica más de un filtro, deben separarse con punto
    y coma, en el orden en el que deben procesar el contenido.</p>
</usage>
<seealso>documentación de <a href="../filter.html">Filtros</a></seealso>
</directivesynopsis>

<directivesynopsis>
<name>TimeOut</name>
<description>Tiempo que esperará el servidor para ciertos eventos
antes de hacer fallar una petición</description>
<syntax>TimeOut <var>time-interval</var>[s]</syntax>
<default>TimeOut 60</default>
<contextlist><context>server config</context><context>virtual host</context></contextlist>

<usage>
    <p>La directiva <directive>TimeOut</directive> define el tiempo
    que esperará Apache httpd para la E/S en varias circunstancias:</p>

    <ul>
      <li><p>Al leer datos del cliente, el tiempo que se espera a que
      llegue un paquete TCP si el búfer de lectura está vacío.</p>
      <p>Para los datos iniciales de una conexión nueva, esta
      directiva no tiene efecto hasta que cualquier <directive
      module="core">AcceptFilter</directive> configurado haya pasado
      la nueva conexión al servidor.</p>
      </li>

      <li>Al escribir datos al cliente, el tiempo que se espera la
      confirmación de un paquete si el búfer de envío está lleno.</li>

      <li>En <module>mod_cgi</module> y <module>mod_cgid</module>, el
      tiempo que se espera cualquier bloque individual de salida de
      un script CGI.</li>

      <li>En <module>mod_ext_filter</module>, el tiempo que se espera
      la salida de un proceso de filtrado.</li>

      <li>En <module>mod_proxy</module>, el valor de tiempo de espera
      por defecto si no se configura <directive
      module="mod_proxy">ProxyTimeout</directive>.</li>
    </ul>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>TraceEnable</name>
<description>Determina el comportamiento ante las peticiones
<code>TRACE</code></description>
<syntax>TraceEnable <var>[on|off|extended]</var></syntax>
<default>TraceEnable on</default>
<contextlist><context>server config</context><context>virtual host</context></contextlist>

<usage>
    <p>Esta directiva sobrescribe el comportamiento de <code>TRACE</code>
    tanto para el núcleo del servidor como para <module>mod_proxy</module>.
    El valor por defecto <code>TraceEnable on</code> permite las
    peticiones <code>TRACE</code> según la RFC 2616, que no permite que
    la petición vaya acompañada de ningún cuerpo. <code>TraceEnable off</code>
    hace que el núcleo del servidor y <module>mod_proxy</module>
    devuelvan al cliente un error <code>405</code> (Método no
    permitido).</p>

    <p>Por último, solo con fines de prueba y diagnóstico, se pueden
    permitir cuerpos de petición usando la directiva no conforme
    <code>TraceEnable extended</code>. El núcleo (como servidor de
    origen) restringirá el cuerpo de la petición a 64Kb (más 8Kb para
    las cabeceras de los fragmentos si se usa
    <code>Transfer-Encoding: chunked</code>). El núcleo reflejará las
    cabeceras completas y todas las cabeceras de fragmento en el
    cuerpo de la respuesta. Como servidor proxy, el cuerpo de la
    petición no está restringido a 64Kb.</p>

    <p>El método <code>TRACE</code> no se puede restringir usando
    <directive type="section" module="core">Limit</directive> ni
    <directive type="section" module="core">LimitExcept</directive>.
    Use <directive>TraceEnable</directive> en su lugar.</p>

    <note><title>Nota</title>

    <p>A pesar de lo que se afirma en sentido contrario, activar el
    método <code>TRACE</code> no expone ninguna vulnerabilidad de
    seguridad en Apache httpd. El método <code>TRACE</code> está
    definido por la especificación HTTP/1.1 y se espera que las
    implementaciones lo soporten.</p>

    </note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>UnDefine</name>
<description>Elimina la definición de una variable</description>
<syntax>UnDefine <var>nombre-de-parámetro</var></syntax>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>

<usage>
    <p>Anula el efecto de un <directive module="core">Define</directive>
    o de pasar un argumento <code>-D</code> a <program>httpd</program>.</p>
    <p>Esta directiva se puede usar para activar o desactivar el uso de
    secciones <directive module="core"
    type="section">IfDefine</directive> sin necesidad de modificar los
    argumentos <code>-D</code> en ningún script de arranque.</p>

    <p>Los nombres de variable no pueden contener el carácter de dos
    puntos ":", para evitar conflictos con la sintaxis de
    <directive module="mod_rewrite">RewriteMap</directive>.</p>

    <note><title>Ámbito en Host Virtual y riesgos</title>
      <p>Aunque esta directiva se soporta en el contexto de host
         virtual, los cambios que realiza son visibles para cualquier
         directiva de configuración posterior, más allá de cualquier
         host virtual que la contenga.</p>
    </note>
</usage>
<seealso><directive module="core">Define</directive></seealso>
<seealso><directive module="core">IfDefine</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>UseCanonicalName</name>
<description>Configura cómo determina el servidor su propio nombre y
puerto</description>
<syntax>UseCanonicalName On|Off|DNS</syntax>
<default>UseCanonicalName Off</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>

<usage>
    <p>En muchas situaciones Apache httpd debe construir una URL
    <em>autorreferencial</em> -- es decir, una URL que haga referencia
    al propio servidor. Con <code>UseCanonicalName On</code> Apache
    httpd usará el nombre de host y el puerto especificados en la
    directiva <directive module="core">ServerName</directive> para
    construir el nombre canónico del servidor. Este nombre se usa en
    todas las URLs autorreferenciales, y para los valores de
    <code>SERVER_NAME</code> y <code>SERVER_PORT</code> en los CGIs.</p>

    <p>Con <code>UseCanonicalName Off</code> Apache httpd formará las
    URLs autorreferenciales usando el nombre de host y el puerto
    proporcionados por el cliente, si se proporcionan (en caso
    contrario usará el nombre canónico, tal como se definió
    anteriormente). Estos valores son los mismos que se usan para
    implementar <a href="../vhosts/name-based.html">hosts virtuales
    basados en nombre</a>, y están disponibles con los mismos
    clientes. Las variables CGI <code>SERVER_NAME</code> y
    <code>SERVER_PORT</code> también se construirán a partir de los
    valores proporcionados por el cliente.</p>

    <p>Un ejemplo en el que esto puede ser útil es en un servidor de
    intranet en el que los usuarios se conectan a la máquina usando
    nombres cortos como <code>www</code>. Notará que si los usuarios
    escriben un nombre corto y una URL que es un directorio, como
    <code>http://www/splat</code>, <em>sin la barra final</em>,
    entonces Apache httpd los redirigirá a
    <code>http://www.example.com/splat/</code>. Si tiene habilitada
    la autenticación, esto hará que el usuario tenga que autenticarse
    dos veces (una para <code>www</code> y otra para
    <code>www.example.com</code> -- vea <a
    href="https://cwiki.apache.org/confluence/display/httpd/FAQ#Why_does_Apache_ask_for_my_password_twice_before_serving_a_file.3F">
    las preguntas frecuentes sobre este asunto para más información</a>).
    Pero si <directive>UseCanonicalName</directive> se establece a
    <code>Off</code>, entonces Apache httpd redirigirá a
    <code>http://www/splat/</code>.</p>

    <p>Existe una tercera opción, <code>UseCanonicalName DNS</code>,
    pensada para usarse con alojamiento virtual masivo basado en IP,
    para dar soporte a clientes antiguos que no proporcionan una
    cabecera <code>Host:</code>. Con esta opción, Apache httpd hace
    una resolución DNS inversa sobre la dirección IP del servidor a
    la que se conectó el cliente, para poder calcular las URLs
    autorreferenciales.</p>

    <note type="warning"><title>Aviso</title>
    <p>Si los CGIs hacen suposiciones sobre los valores de
    <code>SERVER_NAME</code>, esta opción podría romperlos. El
    cliente es, en esencia, libre de dar el valor que quiera como
    nombre de host. Pero si el CGI solo usa <code>SERVER_NAME</code>
    para construir URLs autorreferenciales, entonces no debería haber
    problema.</p>
    </note>
</usage>
<seealso><directive module="core">UseCanonicalPhysicalPort</directive></seealso>
<seealso><directive module="core">ServerName</directive></seealso>
<seealso><directive module="mpm_common">Listen</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>UseCanonicalPhysicalPort</name>
<description>Configura cómo determina el servidor su propio puerto</description>
<syntax>UseCanonicalPhysicalPort On|Off</syntax>
<default>UseCanonicalPhysicalPort Off</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>

<usage>
    <p>En muchas situaciones Apache httpd debe construir una URL
    <em>autorreferencial</em> -- es decir, una URL que haga
    referencia al propio servidor. Con <code>UseCanonicalPhysicalPort
    On</code>, Apache httpd, al construir el puerto canónico del
    servidor para cumplir con la directiva <directive
    module="core">UseCanonicalName</directive>, ofrecerá el número de
    puerto físico real usado por esta petición como puerto
    potencial. Con <code>UseCanonicalPhysicalPort Off</code>, Apache
    httpd nunca usará el número de puerto físico real, y en su lugar
    se basará en toda la información configurada para construir un
    número de puerto válido.</p>

    <note><title>Nota</title>
    <p>El orden de búsqueda cuando se usa el puerto físico es el
    siguiente:</p>
     <dl>
     <dt><code>UseCanonicalName Off | DNS</code></dt>
     <dd>
     <ol>
      <li>Puerto extraído de la cabecera <code>Host:</code></li>
      <li>Puerto físico (solo con <directive>UseCanonicalPhysicalPort</directive> en ON)</li>
      <li>Puerto proporcionado en <directive module="core">Servername</directive></li>
      <li>Puerto por defecto para el esquema/protocolo (como 80 o 443)</li>
     </ol>
     </dd>
     <dt><code>UseCanonicalName On</code></dt>
     <dd>
     <ol>
      <li>Puerto proporcionado en <directive module="core">Servername</directive></li>
      <li>Puerto físico (solo con <directive>UseCanonicalPhysicalPort</directive> en ON)</li>
      <li>Puerto por defecto para el esquema/protocolo (como 80 o 443)</li>
     </ol>
     </dd>
    </dl>

    <p>Los puertos físicos solo se incluyen en la búsqueda con
    <code>UseCanonicalPhysicalPort On</code>.</p>
    </note>

</usage>
<seealso><directive module="core">UseCanonicalName</directive></seealso>
<seealso><directive module="core">ServerName</directive></seealso>
<seealso><directive module="mpm_common">Listen</directive></seealso>
</directivesynopsis>

<directivesynopsis type="section">
<name>VirtualHost</name>
<description>Contiene directivas que se aplican solo a un nombre de
host o dirección IP concretos</description>
<syntax>&lt;VirtualHost
    <var>addr</var>[:<var>port</var>] [<var>addr</var>[:<var>port</var>]]
    ...&gt; ... &lt;/VirtualHost&gt;</syntax>
<contextlist><context>server config</context></contextlist>

<usage>
    <p><directive type="section">VirtualHost</directive> y
    <code>&lt;/VirtualHost&gt;</code> se usan para delimitar un grupo
    de directivas que solo se aplicarán a un host virtual concreto.
    Se puede usar cualquier directiva permitida en un contexto de
    host virtual. Cuando el servidor recibe una petición de un
    documento en un host virtual concreto, usa las directivas de
    configuración delimitadas en la sección <directive
    type="section">VirtualHost</directive>. <var>Addr</var> puede ser
    cualquiera de los siguientes, opcionalmente seguido de dos puntos
    y un número de puerto (o *):</p>

    <ul>
      <li>La dirección IP del host virtual;</li>

      <li>Un nombre de dominio totalmente cualificado para la
      dirección IP del host virtual (no recomendado);</li>

      <li>El carácter <code>*</code>, que actúa como comodín y
      coincide con cualquier dirección IP.</li>

      <li>La cadena <code>_default_</code>, que es un alias de
      <code>*</code></li>

    </ul>

    <highlight language="config">
&lt;VirtualHost 10.1.2.3:80&gt;
  ServerAdmin webmaster@host.example.com
  DocumentRoot "/www/docs/host.example.com"
  ServerName host.example.com
  ErrorLog "logs/host.example.com-error_log"
  TransferLog "logs/host.example.com-access_log"
&lt;/VirtualHost&gt;
    </highlight>


    <p>Las direcciones IPv6 deben especificarse entre corchetes
    porque, de otro modo, no se podría determinar el número de
    puerto opcional. A continuación se muestra un ejemplo con IPv6:</p>

    <highlight language="config">
&lt;VirtualHost [2001:db8::a00:20ff:fea7:ccea]:80&gt;
  ServerAdmin webmaster@host.example.com
  DocumentRoot "/www/docs/host.example.com"
  ServerName host.example.com
  ErrorLog "logs/host.example.com-error_log"
  TransferLog "logs/host.example.com-access_log"
&lt;/VirtualHost&gt;
    </highlight>

    <p>Cada host virtual debe corresponder a una dirección IP, un
    número de puerto o un nombre de host distintos para el servidor;
    en el primer caso, la máquina del servidor debe estar configurada
    para aceptar paquetes IP para varias direcciones. (Si la máquina
    no tiene varias interfaces de red, esto se puede conseguir con el
    comando <code>ifconfig alias</code> -- si su sistema operativo lo
    soporta).</p>

    <note><title>Nota</title>
    <p>El uso de <directive type="section">VirtualHost</directive>
    <strong>no</strong> afecta a las direcciones en las que escucha
    Apache httpd. Puede que necesite asegurarse de que Apache httpd
    escucha en las direcciones correctas usando <directive
    module="mpm_common">Listen</directive>.</p>
    </note>

    <p>Se debería especificar un <directive
    module="core">ServerName</directive> dentro de cada bloque
    <directive type="section">VirtualHost</directive>. Si no está
    presente, se heredará el <directive
    module="core">ServerName</directive> de la configuración del
    servidor "principal".</p>

    <p>Cuando se recibe una petición, el servidor primero la asigna
    al <directive type="section">VirtualHost</directive> que mejor
    coincida, basándose únicamente en la combinación de la dirección
    IP y el puerto locales. Las entradas que no son comodín tienen
    mayor precedencia. Si no se produce ninguna coincidencia basada
    en IP y puerto, se usa la configuración del servidor
    "principal".</p>

    <p>Si varios hosts virtuales contienen la dirección IP y puerto
    que mejor coinciden, el servidor selecciona entre esos hosts
    virtuales el que mejor coincida según el nombre de host
    solicitado. Si no se encuentra ningún host virtual basado en
    nombre que coincida, se usará el primer host virtual listado que
    coincidiera con la dirección IP. Como consecuencia, el primer
    host virtual listado para una combinación dada de dirección IP y
    puerto es el host virtual por defecto para esa combinación de IP
    y puerto.</p>

    <note type="warning"><title>Seguridad</title>
    <p>Consulte el documento <a
    href="../misc/security_tips.html">consejos de seguridad</a> para
    obtener detalles sobre por qué su seguridad podría verse
    comprometida si el directorio donde se almacenan los ficheros de
    registro puede ser escrito por alguien distinto del usuario que
    arranca el servidor.</p>
    </note>
</usage>
<seealso><a href="../vhosts/">documentación de hosts virtuales de
    Apache HTTP Server</a></seealso>
<seealso><a href="../dns-caveats.html">Cuestiones relativas a DNS y
    Apache HTTP Server</a></seealso>
<seealso><a href="../bind.html">Establecer qué direcciones y puertos
    usa Apache HTTP Server</a></seealso>
<seealso><a href="../sections.html">Cómo funcionan las secciones
    &lt;Directory&gt;, &lt;Location&gt; y &lt;Files&gt;</a> para una
    explicación de cómo se combinan estas distintas secciones cuando
    se recibe una petición</seealso>
</directivesynopsis>

<directivesynopsis>
<name>RegisterHttpMethod</name>
<description>Registra métodos HTTP no estándar</description>
<syntax>RegisterHttpMethod <var>método</var> [<var>método</var> [...]]</syntax>
<contextlist><context>server config</context></contextlist>
<compatibility>Disponible en Apache HTTP Server 2.4.24 y posteriores</compatibility>

<usage>
<p>Esta directiva puede usarse para registrar métodos HTTP adicionales.
Esto es necesario si se necesitan usar métodos no estándar con
directivas que aceptan nombres de métodos como parámetros, o para
permitir que ciertos métodos no estándar se usen a través de un proxy o
de un script CGI cuando el servidor se ha configurado para pasar a los
módulos solo los métodos reconocidos.</p>
</usage>
<seealso><directive module="core">HTTPProtocolOptions</directive></seealso>
<seealso><directive module="mod_allowmethods">AllowMethods</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>Warning</name>
<description>Avisa durante el análisis de la configuración con un
mensaje personalizado</description>
<syntax>Warning <var>mensaje</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>All</override>
<compatibility>2.5 y posteriores</compatibility>

<usage>
    <p>Si se puede detectar un problema desde dentro de la
    configuración, esta directiva puede usarse para generar un mensaje
    de aviso personalizado. El análisis de la configuración no se
    detiene. El uso típico es comprobar si ciertas opciones definidas
    por el usuario están establecidas, y avisar si no lo están.</p>

    <highlight language="config">
# Ejemplo
# avisar cuando ReverseProxy no está establecido
&lt;IfDefine !ReverseProxy&gt;
  Warning "reverse proxy is not started, hope this is okay!"
&lt;/IfDefine&gt;

&lt;IfDefine ReverseProxy&gt;
  # definir configuración de proxy personalizada
&lt;/IfDefine&gt;
    </highlight>

    <note type="warning"><title>Nota</title>
        <p> Esta directiva se evalúa en el momento del procesamiento de
        la configuración, no en tiempo de ejecución. Como resultado,
        esta directiva no se puede evaluar condicionalmente
        encerrándola en una sección <directive type="section" module="core"
        >If</directive>.</p>
    </note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>UNCList</name>
<description>Controla a qué nombres de host UNC puede acceder el
servidor
</description>
<syntax>UNCList <var>nombre-de-host</var> [<var>nombre-de-host</var>...]</syntax>
<default>sin establecer</default>
<contextlist><context>server config</context>
</contextlist>
<compatibility>Añadida en 2.4.60, solo en Windows.</compatibility>

<usage>
    <p> Durante el procesamiento de la petición, las peticiones para
    acceder a una ruta del sistema de ficheros que se resuelve a una
    ruta UNC fallarán a menos que el nombre de host de la ruta UNC se
    haya especificado mediante esta directiva. El objetivo es limitar
    el acceso a rutas derivadas de entradas no fiables.</p>

    <highlight language="config">
    UNCList example.com other.example.com
    </highlight>

    <note type="warning"><title>Seguridad</title>
        <p>Los valores especificados por esta directiva solo son
        comprobados por algunos componentes del servidor, antes de
        acceder a rutas del sistema de ficheros que puedan derivarse
        inadvertidamente de entradas no fiables. </p>
        <p> Como medida más completa y preventiva, los sistemas Windows
        deberían aislarse a nivel de red para que no puedan realizar
        llamadas SMB/NTLM salientes a destinos inesperados.</p>
    </note>

    <note type="warning"><title>Orden de la directiva</title>
    <p>Esta directiva debe colocarse antes de las rutas UNC usadas en
    httpd.conf. Varias apariciones de la directiva restablecen la
    lista.</p>
    </note>

</usage>
</directivesynopsis>


<directivesynopsis>
<name>MergeTrailers</name>
<description>Determina si los trailers se fusionan con las
cabeceras</description>
<syntax>MergeTrailers [on|off]</syntax>
<default>MergeTrailers off</default>
<contextlist><context>server config</context><context>virtual host</context></contextlist>
<compatibility>2.4.11 y posteriores</compatibility>

<usage>
    <p>Esta directiva controla si las cabeceras finales ("trailers")
    HTTP se copian en la representación interna de las cabeceras HTTP.
    Esta fusión ocurre cuando el cuerpo de la petición se ha consumido
    completamente, mucho después de que la mayor parte del
    procesamiento de cabeceras haya tenido ocasión de examinarlas o
    modificarlas.</p>
    <p>Esta opción se ofrece por compatibilidad con versiones
    anteriores a la 2.4.11, en las que los trailers siempre se
    fusionaban.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>QualifyRedirectURL</name>
<description>Controla si la variable de entorno REDIRECT_URL se
             cualifica completamente</description>
<syntax>QualifyRedirectURL On|Off</syntax>
<default>QualifyRedirectURL Off</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context>
</contextlist>
<override>FileInfo</override>
<compatibility>Directiva soportada a partir de la 2.4.18. La versión
2.4.17 se comportaba como si estuviese configurado
'QualifyRedirectURL On'.</compatibility>

<usage>
    <p>Esta directiva controla si el servidor se asegurará de que la
    variable de entorno REDIRECT_URL esté completamente cualificada.
    Por defecto, la variable contiene la URL exacta solicitada por el
    cliente, como "/index.html". Con <directive
    >QualifyRedirectURL On</directive>, la misma petición daría como
    resultado un valor como "http://www.example.com/index.html".</p>
    <p>Incluso sin esta directiva establecida, cuando se realiza una
    petición contra una URL completamente cualificada, REDIRECT_URL
    seguirá estando completamente cualificada.
    </p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>StrictHostCheck</name>
<description>Controla si el servidor exige que el nombre de host
             solicitado esté enumerado en el host virtual que gestiona
             la petición
             </description>
<syntax>StrictHostCheck ON|OFF</syntax>
<default>StrictHostCheck OFF</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>
<compatibility>Añadida en 2.5.1</compatibility>

<usage>
    <p>Por defecto, el servidor responderá a peticiones para cualquier
    nombre de host, incluidas las peticiones dirigidas a nombres de
    host inesperados o no configurados. Aunque esto es cómodo, a veces
    es deseable limitar qué nombres de host gestiona una aplicación de
    backend, ya que a menudo generará respuestas autorreferenciales.</p>

    <p>Estableciendo <directive>StrictHostCheck</directive> a <em>ON</em>,
    el servidor devolverá un error HTTP 400 si el nombre de host
    solicitado no se ha listado explícitamente mediante
    <directive module="core">ServerName</directive> o
    <directive module="core">ServerAlias</directive> en el host virtual
    que mejor coincide con los detalles de la conexión entrante.</p>

   <p>Esta directiva también permite hacer coincidir el nombre de host
   solicitado con los nombres de host especificados dentro de la
   etiqueta de apertura <directive module="core">VirtualHost</directive>,
   que es un mecanismo de configuración relativamente poco conocido que
   actúa como entradas adicionales de
   <directive module="core">ServerAlias</directive>.</p>

   <p>Esta directiva no tiene efecto en hosts virtuales no
   predeterminados. El valor heredado de la configuración global del
   servidor, o del host virtual por defecto para la ip:puerto de la
   conexión subyacente, determina el valor efectivo.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>MergeSlashes</name>
<description>Controla si el servidor fusiona barras consecutivas en las
URLs.
</description>
<syntax>MergeSlashes ON|OFF</syntax>
<default>MergeSlashes ON</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>
<compatibility>Añadida en 2.5.1</compatibility>

<usage>
    <p>Por defecto, el servidor fusiona (o colapsa) varios caracteres
    de barra ('/') consecutivos en el componente de ruta de la URL de
    la petición.</p>

    <p>Al mapear URLs al sistema de ficheros, estas barras múltiples no
    son significativas. Sin embargo, las URLs gestionadas de otras
    formas, como por CGI o por proxy, pueden preferir conservar el
    significado de las barras consecutivas múltiples. En estos casos,
    <directive>MergeSlashes</directive> se puede establecer a
    <em>OFF</em> para conservar las barras consecutivas múltiples, que
    es el comportamiento heredado.</p>
    <p>
    Cuando se establece a "OFF", las expresiones regulares usadas en el
    fichero de configuración que coinciden con el componente de ruta de
    la URL (<directive>LocationMatch</directive>,
    <directive>RewriteRule</directive>, ...) necesitan tener en cuenta
    las barras consecutivas múltiples. Las directivas
    <directive>Location</directive> que no se basan en expresiones
    regulares siempre operan contra una URL con las barras ya
    fusionadas y no pueden diferenciar entre barras múltiples.</p>
</usage>
</directivesynopsis>

</modulesynopsis>
