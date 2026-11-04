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
    <p>Mientras que procesa una petición el servidor busca
    el primer fichero de configuración existente dentro de un listado de nombres en
    cada directorio de la ruta del documento, si los ficheros distribuidos
    de configuración están <a href="#allowoverride">habilitados para ese
    directorio</a>. Por ejemplo:</p>

     <highlight language="config">
AccessFileName .acl
    </highlight>

    <p>Antes de servir el documento
    <code>/usr/local/web/index.html</code>, el servidor leerá
    <code>/.acl</code>, <code>/usr/.acl</code>,
    <code>/usr/local/.acl</code> y <code>/usr/local/web/.acl</code>
    para las directivas, salvo que estén deshabilitadas con:</p>

     <highlight language="config">
&lt;Directory "/"&gt;
    AllowOverride None
&lt;/Directory&gt;
    </highlight>

    
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
<description>Determina si Determines whether encoded path separators in URLs are allowed to
be passed through</description>
<syntax>AllowEncodedSlashes On|Off</syntax>
<default>AllowEncodedSlashes Off</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>
<compatibility>Available in Apache httpd 2.0.46 and later</compatibility>

<usage>
    <p>The <directive>AllowEncodedSlashes</directive> directive allows URLs
    which contain encoded path separators (<code>%2F</code> for <code>/</code>
    and additionally <code>%5C</code> for <code>\</code> on according systems)
    to be used. Normally such URLs are refused with a 404 (Not found) error.</p>

    <p>Turning <directive>AllowEncodedSlashes</directive> <code>On</code> is
    mostly useful when used in conjunction with <code>PATH_INFO</code>.</p>

    <note><title>Note</title>
      <p>Allowing encoded slashes does <em>not</em> imply <em>decoding</em>.
      Occurrences of <code>%2F</code> or <code>%5C</code> (<em>only</em> on
      according systems) will be left as such in the otherwise decoded URL
      string.</p>
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
<description>This directive has no effect other than to emit warnings
if the value is not <code>none</code>. In prior versions, DefaultType
would specify a default media type to assign to response content for
which no other media type configuration could be found.
</description>
<syntax>DefaultType <var>media-type|none</var></syntax>
<default>DefaultType none</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>FileInfo</override>
<compatibility>The argument <code>none</code> is available in Apache httpd 2.2.7 and later.  All other choices are DISABLED for 2.3.x and later.</compatibility>

<usage>
    <p>This directive has been disabled.  For backwards compatibility
    of configuration files, it may be specified with the value
    <code>none</code>, meaning no default media type. For example:</p>

    <example>
      DefaultType None
    </example>

    <p><code>DefaultType None</code> is only available in
    httpd-2.2.7 and later.</p>

    <p>Use the mime.types configuration file and the
    <directive module="mod_mime">AddType</directive> to configure media
    type assignments via file extensions, or the
    <directive module="core">ForceType</directive> directive to configure
    the media type for specific resources. Otherwise, the server will
    send the response without a Content-Type header field and the
    recipient may attempt to guess the media type.</p>
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
<description>Enclose a group of directives that apply only to the
named file-system directory, sub-directories, and their contents.</description>
<syntax>&lt;Directory <var>directory-path</var>&gt;
... &lt;/Directory&gt;</syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p><directive type="section">Directory</directive> and
    <code>&lt;/Directory&gt;</code> are used to enclose a group of
    directives that will apply only to the named directory,
    sub-directories of that directory, and the files within the respective 
    directories.  Any directive that is allowed
    in a directory context may be used. <var>Directory-path</var> is
    either the full path to a directory, or a wild-card string using
    Unix shell-style matching. In a wild-card string, <code>?</code> matches
    any single character, and <code>*</code> matches any sequences of
    characters. You may also use <code>[]</code> character ranges. None
    of the wildcards match a `/' character, so <code>&lt;Directory
    /*/public_html&gt;</code> will not match
    <code>/home/user/public_html</code>, but <code>&lt;Directory
    /home/*/public_html&gt;</code> will match. Example:</p>

    <example>
      &lt;Directory /usr/local/httpd/htdocs&gt;<br />
      <indent>
        Options Indexes FollowSymLinks<br />
      </indent>
      &lt;/Directory&gt;
    </example>

    <note>
      <p>Be careful with the <var>directory-path</var> arguments:
      They have to literally match the filesystem path which Apache httpd uses
      to access the files. Directives applied to a particular
      <code>&lt;Directory&gt;</code> will not apply to files accessed from
      that same directory via a different path, such as via different symbolic
      links.</p>
    </note>

    <p><glossary ref="regex">Regular
    expressions</glossary> can also be used, with the addition of the
    <code>~</code> character. For example:</p>

    <example>
      &lt;Directory ~ "^/www/.*/[0-9]{3}"&gt;
    </example>

    <p>would match directories in <code>/www/</code> that consisted of
    three numbers.</p>

    <p>If multiple (non-regular expression) <directive
    type="section">Directory</directive> sections
    match the directory (or one of its parents) containing a document,
    then the directives are applied in the order of shortest match
    first, interspersed with the directives from the <a
    href="#accessfilename">.htaccess</a> files. For example,
    with</p>

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

    <p>for access to the document <code>/home/web/dir/doc.html</code>
    the steps are:</p>

    <ul>
      <li>Apply directive <code>AllowOverride None</code>
      (disabling <code>.htaccess</code> files).</li>

      <li>Apply directive <code>AllowOverride FileInfo</code> (for
      directory <code>/home</code>).</li>

      <li>Apply any <code>FileInfo</code> directives in
      <code>/home/.htaccess</code>, <code>/home/web/.htaccess</code> and
      <code>/home/web/dir/.htaccess</code> in that order.</li>
    </ul>

    <p>Regular expressions are not considered until after all of the
    normal sections have been applied. Then all of the regular
    expressions are tested in the order they appeared in the
    configuration file. For example, with</p>

    <example>
      &lt;Directory ~ abc$&gt;<br />
      <indent>
        # ... directives here ...<br />
      </indent>
      &lt;/Directory&gt;
    </example>

    <p>the regular expression section won't be considered until after
    all normal <directive type="section">Directory</directive>s and
    <code>.htaccess</code> files have been applied. Then the regular
    expression will match on <code>/home/abc/public_html/abc</code> and
    the corresponding <directive type="section">Directory</directive> will
    be applied.</p>

   <p><strong>Note that the default access for
    <code>&lt;Directory /&gt;</code> is <code>Allow from All</code>.
    This means that Apache httpd will serve any file mapped from an URL. It is
    recommended that you change this with a block such
    as</strong></p>

    <example>
      &lt;Directory /&gt;<br />
      <indent>
        Order Deny,Allow<br />
        Deny from All<br />
      </indent>
      &lt;/Directory&gt;
    </example>

    <p><strong>and then override this for directories you
    <em>want</em> accessible. See the <a
    href="../misc/security_tips.html">Security Tips</a> page for more
    details.</strong></p>

    <p>The directory sections occur in the <code>httpd.conf</code> file.
    <directive type="section">Directory</directive> directives
    cannot nest, and cannot appear in a <directive module="core"
    type="section">Limit</directive> or <directive module="core"
    type="section">LimitExcept</directive> section.</p>
</usage>
<seealso><a href="../sections.html">How &lt;Directory&gt;,
    &lt;Location&gt; and &lt;Files&gt; sections work</a> for an
    explanation of how these different sections are combined when a
    request is received</seealso>
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
<description>Directory that forms the main document tree visible
from the web</description>
<syntax>DocumentRoot <var>directory-path</var></syntax>
<default>DocumentRoot /usr/local/apache/htdocs</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>This directive sets the directory from which <program>httpd</program>
    will serve files. Unless matched by a directive like <directive
    module="mod_alias">Alias</directive>, the server appends the
    path from the requested URL to the document root to make the
    path to the document. Example:</p>

    <example>
      DocumentRoot /usr/web
    </example>

    <p>then an access to
    <code>http://www.my.host.com/index.html</code> refers to
    <code>/usr/web/index.html</code>. If the <var>directory-path</var> is 
    not absolute then it is assumed to be relative to the <directive 
    module="core">ServerRoot</directive>.</p>

    <p>The <directive>DocumentRoot</directive> should be specified without
    a trailing slash.</p>
</usage>
<seealso><a href="../urlmapping.html#documentroot">Mapping URLs to Filesystem
Locations</a></seealso>
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
<description>Use memory-mapping to read files during delivery</description>
<syntax>EnableMMAP On|Off</syntax>
<default>EnableMMAP On</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>FileInfo</override>

<usage>
    <p>This directive controls whether the <program>httpd</program> may use
    memory-mapping if it needs to read the contents of a file during
    delivery.  By default, when the handling of a request requires
    access to the data within a file -- for example, when delivering a
    server-parsed file using <module>mod_include</module> -- Apache httpd
    memory-maps the file if the OS supports it.</p>

    <p>This memory-mapping sometimes yields a performance improvement.
    But in some environments, it is better to disable the memory-mapping
    to prevent operational problems:</p>

    <ul>
    <li>On some multiprocessor systems, memory-mapping can reduce the
    performance of the <program>httpd</program>.</li>
    <li>Deleting or truncating a file while <program>httpd</program>
      has it memory-mapped can cause <program>httpd</program> to
      crash with a segmentation fault.
    </li>
    </ul>

    <p>For server configurations that are vulnerable to these problems,
    you should disable memory-mapping of delivered files by specifying:</p>

    <example>
      EnableMMAP Off
    </example>

    <p>For NFS mounted files, this feature may be disabled explicitly for
    the offending files by specifying:</p>

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
<description>Use the kernel sendfile support to deliver files to the client</description>
<syntax>EnableSendfile On|Off</syntax>
<default>EnableSendfile Off</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>FileInfo</override>
<compatibility>Available in version 2.0.44 and later. Default changed to Off in
version 2.3.9.</compatibility>

<usage>
    <p>This directive controls whether <program>httpd</program> may use the
    sendfile support from the kernel to transmit file contents to the client.
    By default, when the handling of a request requires no access
    to the data within a file -- for example, when delivering a
    static file -- Apache httpd uses sendfile to deliver the file contents
    without ever reading the file if the OS supports it.</p>

    <p>This sendfile mechanism avoids separate read and send operations,
    and buffer allocations. But on some platforms or within some
    filesystems, it is better to disable this feature to avoid
    operational problems:</p>

    <ul>
    <li>Some platforms may have broken sendfile support that the build
    system did not detect, especially if the binaries were built on
    another box and moved to such a machine with broken sendfile
    support.</li>
    <li>On Linux the use of sendfile triggers TCP-checksum
    offloading bugs on certain networking cards when using IPv6.</li>
    <li>On Linux on Itanium, sendfile may be unable to handle files
    over 2GB in size.</li>
    <li>With a network-mounted <directive
    module="core">DocumentRoot</directive> (e.g., NFS, SMB, CIFS, FUSE),
    the kernel may be unable to serve the network file through
    its own cache.</li>
    </ul>

    <p>For server configurations that are not vulnerable to these problems,
    you may enable this feature by specifying:</p>

    <example>
      EnableSendfile On
    </example>

    <p>For network mounted files, this feature may be disabled explicitly
    for the offending files by specifying:</p>

    <example>
      &lt;Directory "/path-to-nfs-files"&gt;
      <indent>
        EnableSendfile Off
      </indent>
      &lt;/Directory&gt;
    </example>
    <p>Please note that the per-directory and .htaccess configuration
       of <directive>EnableSendfile</directive> is not supported by
       <module>mod_cache_disk</module>.
       Only global definition of <directive>EnableSendfile</directive>
       is taken into account by the module.
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
<description>Abort configuration parsing with a custom error message</description>
<syntax>Error <var>message</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<compatibility>2.3.9 and later</compatibility>

<usage>
    <p>If an error can be detected within the configuration, this
    directive can be used to generate a custom error message, and halt
    configuration parsing.  The typical use is for reporting required
    modules which are missing from the configuration.</p>

    <example><title>Example</title>
      # ensure that mod_include is loaded<br />
      &lt;IfModule !include_module&gt;<br />
      Error mod_include is required by mod_foo.  Load it with LoadModule.<br />
      &lt;/IfModule&gt;<br />
      <br />
      # ensure that exactly one of SSL,NOSSL is defined<br />
      &lt;IfDefine SSL&gt;<br />
      &lt;IfDefine NOSSL&gt;<br />
      Error Both SSL and NOSSL are defined.  Define only one of them.<br />
      &lt;/IfDefine&gt;<br />
      &lt;/IfDefine&gt;<br />
      &lt;IfDefine !SSL&gt;<br />
      &lt;IfDefine !NOSSL&gt;<br />
      Error Either SSL or NOSSL must be defined.<br />
      &lt;/IfDefine&gt;<br />
      &lt;/IfDefine&gt;<br />
    </example>

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
<description>Location where the server will log errors</description>
<syntax> ErrorLog <var>file-path</var>|syslog[:<var>facility</var>]</syntax>
<default>ErrorLog logs/error_log (Unix) ErrorLog logs/error.log (Windows and OS/2)</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>The <directive>ErrorLog</directive> directive sets the name of
    the file to which the server will log any errors it encounters. If
    the <var>file-path</var> is not absolute then it is assumed to be 
    relative to the <directive module="core">ServerRoot</directive>.</p>

    <example><title>Example</title>
    ErrorLog /var/log/httpd/error_log
    </example>

    <p>If the <var>file-path</var>
    begins with a pipe character "<code>|</code>" then it is assumed to be a
    command to spawn to handle the error log.</p>

    <example><title>Example</title>
    ErrorLog "|/usr/local/bin/httpd_errors"
    </example>

    <p>See the notes on <a href="../logs.html#piped">piped logs</a> for
    more information.</p>

    <p>Using <code>syslog</code> instead of a filename enables logging
    via syslogd(8) if the system supports it. The default is to use
    syslog facility <code>local7</code>, but you can override this by
    using the <code>syslog:<var>facility</var></code> syntax where
    <var>facility</var> can be one of the names usually documented in
    syslog(1).  The facility is effectively global, and if it is changed
    in individual virtual hosts, the final facility specified affects the
    entire server.</p>

    <example><title>Example</title>
    ErrorLog syslog:user
    </example>

    <p>SECURITY: See the <a
    href="../misc/security_tips.html#serverroot">security tips</a>
    document for details on why your security could be compromised
    if the directory where log files are stored is writable by
    anyone other than the user that starts the server.</p>
    <note type="warning"><title>Note</title>
      <p>When entering a file path on non-Unix platforms, care should be taken
      to make sure that only forward slashed are used even though the platform
      may allow the use of back slashes. In general it is a good idea to always 
      use forward slashes throughout the configuration files.</p>
    </note>
</usage>
<seealso><directive module="core">LogLevel</directive></seealso>
<seealso><a href="../logs.html">Apache HTTP Server Log Files</a></seealso>
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
<description>Keep track of extended status information for each 
request</description>
<syntax>ExtendedStatus On|Off</syntax>
<default>ExtendedStatus Off[*]</default>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>This option tracks additional data per worker about the
    currently executing request, and a utilization summary; you 
    can see these variables during runtime by configuring 
    <module>mod_status</module>.  Note that other modules may
    rely on this scoreboard.</p>

    <p>This setting applies to the entire server, and cannot be
    enabled or disabled on a virtualhost-by-virtualhost basis.
    The collection of extended status information can slow down
    the server.  Also note that this setting cannot be changed
    during a graceful restart.</p>

    <note>
    <p>Note that loading <module>mod_status</module> will change 
    the default behavior to ExtendedStatus On, while other
    third party modules may do the same.  Such modules rely on
    collecting detailed information about the state of all workers.
    The default is changed by <module>mod_status</module> beginning
    with version 2.3.6; the previous default was always Off.</p>
    </note>

</usage>

</directivesynopsis>

<directivesynopsis>
<name>FileETag</name>
<description>File attributes used to create the ETag
HTTP response header for static files</description>
<syntax>FileETag <var>component</var> ...</syntax>
<default>FileETag INode MTime Size</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>FileInfo</override>

<usage>
    <p>
    The <directive>FileETag</directive> directive configures the file
    attributes that are used to create the <code>ETag</code> (entity
    tag) response header field when the document is based on a static file.
    (The <code>ETag</code> value is used in cache management to save
    network bandwidth.) The
    <directive>FileETag</directive> directive allows you to choose
    which of these -- if any -- should be used. The recognized keywords are:
    </p>

    <dl>
     <dt><strong>INode</strong></dt>
     <dd>The file's i-node number will be included in the calculation</dd>
     <dt><strong>MTime</strong></dt>
     <dd>The date and time the file was last modified will be included</dd>
     <dt><strong>Size</strong></dt>
     <dd>The number of bytes in the file will be included</dd>
     <dt><strong>All</strong></dt>
     <dd>All available fields will be used. This is equivalent to:
         <example>FileETag INode MTime Size</example></dd>
     <dt><strong>None</strong></dt>
     <dd>If a document is file-based, no <code>ETag</code> field will be
       included in the response</dd>
    </dl>

    <p>The <code>INode</code>, <code>MTime</code>, and <code>Size</code>
    keywords may be prefixed with either <code>+</code> or <code>-</code>,
    which allow changes to be made to the default setting inherited
    from a broader scope. Any keyword appearing without such a prefix
    immediately and completely cancels the inherited setting.</p>

    <p>If a directory's configuration includes
    <code>FileETag&nbsp;INode&nbsp;MTime&nbsp;Size</code>, and a
    subdirectory's includes <code>FileETag&nbsp;-INode</code>,
    the setting for that subdirectory (which will be inherited by
    any sub-subdirectories that don't override it) will be equivalent to
    <code>FileETag&nbsp;MTime&nbsp;Size</code>.</p>
    <note type="warning"><title>Warning</title>
    Do not change the default for directories or locations that have WebDAV
    enabled and use <module>mod_dav_fs</module> as a storage provider.
    <module>mod_dav_fs</module> uses <code>INode&nbsp;MTime&nbsp;Size</code>
    as a fixed format for <code>ETag</code> comparisons on conditional requests.
    These conditional requests will break if the <code>ETag</code> format is
    changed via <directive>FileETag</directive>.
    </note>
    <note><title>Server Side Includes</title>
    An ETag is not generated for responses parsed by <module>mod_include</module>, 
    since the response entity can change without a change of the INode, MTime, or Size 
    of the static file with embedded SSI directives.
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
<description>Directory to write gmon.out profiling data to.  </description>
<syntax>GprofDir <var>/tmp/gprof/</var>|<var>/tmp/gprof/</var>%</syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>When the server has been compiled with gprof profiling support,
    <directive>GprofDir</directive> causes <code>gmon.out</code> files to
    be written to the specified directory when the process exits.  If the
    argument ends with a percent symbol ('%'), subdirectories are created
    for each process id.</p>

    <p>This directive currently only works with the <module>prefork</module> 
    MPM.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>HostnameLookups</name>
<description>Enables DNS lookups on client IP addresses</description>
<syntax>HostnameLookups On|Off|Double</syntax>
<default>HostnameLookups Off</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>

<usage>
    <p>This directive enables DNS lookups so that host names can be
    logged (and passed to CGIs/SSIs in <code>REMOTE_HOST</code>).
    The value <code>Double</code> refers to doing double-reverse
    DNS lookup. That is, after a reverse lookup is performed, a forward
    lookup is then performed on that result. At least one of the IP
    addresses in the forward lookup must match the original
    address. (In "tcpwrappers" terminology this is called
    <code>PARANOID</code>.)</p>

    <p>Regardless of the setting, when <module>mod_authz_host</module> is
    used for controlling access by hostname, a double reverse lookup
    will be performed.  This is necessary for security. Note that the
    result of this double-reverse isn't generally available unless you
    set <code>HostnameLookups Double</code>. For example, if only
    <code>HostnameLookups On</code> and a request is made to an object
    that is protected by hostname restrictions, regardless of whether
    the double-reverse fails or not, CGIs will still be passed the
    single-reverse result in <code>REMOTE_HOST</code>.</p>

    <p>The default is <code>Off</code> in order to save the network
    traffic for those sites that don't truly need the reverse
    lookups done. It is also better for the end users because they
    don't have to suffer the extra latency that a lookup entails.
    Heavily loaded sites should leave this directive
    <code>Off</code>, since DNS lookups can take considerable
    amounts of time. The utility <program>logresolve</program>, compiled by
    default to the <code>bin</code> subdirectory of your installation
    directory, can be used to look up host names from logged IP addresses
    offline.</p>
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
<description>Encloses directives that will be processed only
if a test is true at startup</description>
<syntax>&lt;IfDefine [!]<var>parameter-name</var>&gt; ...
    &lt;/IfDefine&gt;</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>All</override>

<usage>
    <p>The <code>&lt;IfDefine <var>test</var>&gt;...&lt;/IfDefine&gt;
    </code> section is used to mark directives that are conditional. The
    directives within an <directive type="section">IfDefine</directive>
    section are only processed if the <var>test</var> is true. If <var>
    test</var> is false, everything between the start and end markers is
    ignored.</p>

    <p>The <var>test</var> in the <directive type="section"
    >IfDefine</directive> section directive can be one of two forms:</p>

    <ul>
      <li><var>parameter-name</var></li>

      <li><code>!</code><var>parameter-name</var></li>
    </ul>

    <p>In the former case, the directives between the start and end
    markers are only processed if the parameter named
    <var>parameter-name</var> is defined. The second format reverses
    the test, and only processes the directives if
    <var>parameter-name</var> is <strong>not</strong> defined.</p>

    <p>The <var>parameter-name</var> argument is a define as given on the
    <program>httpd</program> command line via <code>-D<var>parameter</var>
    </code> at the time the server was started or by the <directive
    module="core">Define</directive> directive.</p>

    <p><directive type="section">IfDefine</directive> sections are
    nest-able, which can be used to implement simple
    multiple-parameter tests. Example:</p>

    <example>
      httpd -DReverseProxy -DUseCache -DMemCache ...<br />
      <br />
      # httpd.conf<br />
      &lt;IfDefine ReverseProxy&gt;<br />
      <indent>
        LoadModule proxy_module   modules/mod_proxy.so<br />
        LoadModule proxy_http_module   modules/mod_proxy_http.so<br />
        &lt;IfDefine UseCache&gt;<br />
        <indent>
          LoadModule cache_module   modules/mod_cache.so<br />
          &lt;IfDefine MemCache&gt;<br />
          <indent>
            LoadModule mem_cache_module   modules/mod_mem_cache.so<br />
          </indent>
          &lt;/IfDefine&gt;<br />
          &lt;IfDefine !MemCache&gt;<br />
          <indent>
            LoadModule cache_disk_module   modules/mod_cache_disk.so<br />
          </indent>
          &lt;/IfDefine&gt;
        </indent>
        &lt;/IfDefine&gt;
      </indent>
      &lt;/IfDefine&gt;
    </example>
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
<description>Encloses directives that are processed conditional on the
presence or absence of a specific module</description>
<syntax>&lt;IfModule [!]<var>module-file</var>|<var>module-identifier</var>&gt; ...
    &lt;/IfModule&gt;</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>All</override>
<compatibility>Module identifiers are available in version 2.1 and
later.</compatibility>

<usage>
    <p>The <code>&lt;IfModule <var>test</var>&gt;...&lt;/IfModule&gt;</code>
    section is used to mark directives that are conditional on the presence of
    a specific module. The directives within an <directive type="section"
    >IfModule</directive> section are only processed if the <var>test</var>
    is true. If <var>test</var> is false, everything between the start and
    end markers is ignored.</p>

    <p>The <var>test</var> in the <directive type="section"
    >IfModule</directive> section directive can be one of two forms:</p>

    <ul>
      <li><var>module</var></li>

      <li>!<var>module</var></li>
    </ul>

    <p>In the former case, the directives between the start and end
    markers are only processed if the module named <var>module</var>
    is included in Apache httpd -- either compiled in or
    dynamically loaded using <directive module="mod_so"
    >LoadModule</directive>. The second format reverses the test,
    and only processes the directives if <var>module</var> is
    <strong>not</strong> included.</p>

    <p>The <var>module</var> argument can be either the module identifier or
    the file name of the module, at the time it was compiled.  For example,
    <code>rewrite_module</code> is the identifier and
    <code>mod_rewrite.c</code> is the file name. If a module consists of
    several source files, use the name of the file containing the string
    <code>STANDARD20_MODULE_STUFF</code>.</p>

    <p><directive type="section">IfModule</directive> sections are
    nest-able, which can be used to implement simple multiple-module
    tests.</p>

    <note>This section should only be used if you need to have one
    configuration file that works whether or not a specific module
    is available. In normal operation, directives need not be
    placed in <directive type="section">IfModule</directive>
    sections.</note>
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
<description>Enables HTTP persistent connections</description>
<syntax>KeepAlive On|Off</syntax>
<default>KeepAlive On</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>The Keep-Alive extension to HTTP/1.0 and the persistent
    connection feature of HTTP/1.1 provide long-lived HTTP sessions
    which allow multiple requests to be sent over the same TCP
    connection. In some cases this has been shown to result in an
    almost 50% speedup in latency times for HTML documents with
    many images. To enable Keep-Alive connections, set
    <code>KeepAlive On</code>.</p>

    <p>For HTTP/1.0 clients, Keep-Alive connections will only be
    used if they are specifically requested by a client. In
    addition, a Keep-Alive connection with an HTTP/1.0 client can
    only be used when the length of the content is known in
    advance. This implies that dynamic content such as CGI output,
    SSI pages, and server-generated directory listings will
    generally not use Keep-Alive connections to HTTP/1.0 clients.
    For HTTP/1.1 clients, persistent connections are the default
    unless otherwise specified. If the client requests it, chunked
    encoding will be used in order to send content of unknown
    length over persistent connections.</p>

    <p>When a client uses a Keep-Alive connection it will be counted
    as a single "request" for the <directive module="mpm_common"
    >MaxConnectionsPerChild</directive> directive, regardless
    of how many requests are sent using the connection.</p>
</usage>

<seealso><directive module="core">MaxKeepAliveRequests</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>KeepAliveTimeout</name>
<description>Amount of time the server will wait for subsequent
requests on a persistent connection</description>
<syntax>KeepAliveTimeout <var>num</var>[ms]</syntax>
<default>KeepAliveTimeout 5</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>
<compatibility>Specifying a value in milliseconds is available in 
Apache httpd 2.3.2 and later</compatibility>

<usage>
    <p>The number of seconds Apache httpd will wait for a subsequent
    request before closing the connection. By adding a postfix of ms the
    timeout can be also set in milliseconds. Once a request has been
    received, the timeout value specified by the
    <directive module="core">Timeout</directive> directive applies.</p>

    <p>Setting <directive>KeepAliveTimeout</directive> to a high value
    may cause performance problems in heavily loaded servers. The
    higher the timeout, the more server processes will be kept
    occupied waiting on connections with idle clients.</p>
    
    <p>In a name-based virtual host context, the value of the first
    defined virtual host (the default host) in a set of <directive
    module="core">NameVirtualHost</directive> will be used.
    The other values will be ignored.</p>
</usage>
</directivesynopsis>

<directivesynopsis type="section">
<name>Limit</name>
<description>Restrict enclosed access controls to only certain HTTP
methods</description>
<syntax>&lt;Limit <var>method</var> [<var>method</var>] ... &gt; ...
    &lt;/Limit&gt;</syntax>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig, Limit</override>

<usage>
    <p>Access controls are normally effective for
    <strong>all</strong> access methods, and this is the usual
    desired behavior. <strong>In the general case, access control
    directives should not be placed within a
    <directive type="section">Limit</directive> section.</strong></p>

    <p>The purpose of the <directive type="section">Limit</directive>
    directive is to restrict the effect of the access controls to the
    nominated HTTP methods. For all other methods, the access
    restrictions that are enclosed in the <directive
    type="section">Limit</directive> bracket <strong>will have no
    effect</strong>. The following example applies the access control
    only to the methods <code>POST</code>, <code>PUT</code>, and
    <code>DELETE</code>, leaving all other methods unprotected:</p>

    <example>
      &lt;Limit POST PUT DELETE&gt;<br />
      <indent>
        Require valid-user<br />
      </indent>
      &lt;/Limit&gt;
    </example>

    <p>The method names listed can be one or more of: <code>GET</code>,
    <code>POST</code>, <code>PUT</code>, <code>DELETE</code>,
    <code>CONNECT</code>, <code>OPTIONS</code>,
    <code>PATCH</code>, <code>PROPFIND</code>, <code>PROPPATCH</code>,
    <code>MKCOL</code>, <code>COPY</code>, <code>MOVE</code>,
    <code>LOCK</code>, and <code>UNLOCK</code>. <strong>The method name is
    case-sensitive.</strong> If <code>GET</code> is used it will also
    restrict <code>HEAD</code> requests. The <code>TRACE</code> method
    cannot be limited (see <directive module="core"
    >TraceEnable</directive>).</p>

    <note type="warning">A <directive type="section"
    module="core">LimitExcept</directive> section should always be
    used in preference to a <directive type="section">Limit</directive>
    section when restricting access, since a <directive type="section"
    module="core">LimitExcept</directive> section provides protection
    against arbitrary methods.</note>

    <p>The <directive type="section">Limit</directive> and
    <directive type="section" module="core">LimitExcept</directive>
    directives may be nested.  In this case, each successive level of
    <directive type="section">Limit</directive> or <directive
    type="section" module="core">LimitExcept</directive> directives must
    further restrict the set of methods to which access controls apply.</p>

    <note type="warning">When using
    <directive type="section">Limit</directive> or
    <directive type="section">LimitExcept</directive> directives with
    the <directive module="mod_authz_core">Require</directive> directive,
    note that the first <directive module="mod_authz_core">Require</directive>
    to succeed authorizes the request, regardless of the presence of other
    <directive module="mod_authz_core">Require</directive> directives.</note>

    <p>For example, given the following configuration, all users will
    be authorized for <code>POST</code> requests, and the
    <code>Require group editors</code> directive will be ignored
    in all cases:</p>

    <example>
      &lt;LimitExcept GET&gt;
      <indent>
        Require valid-user
      </indent> 
      &lt;/LimitExcept&gt;<br />
      &lt;Limit POST&gt;
      <indent>
        Require group editors
      </indent> 
      &lt;/Limit&gt;
    </example>
</usage>
</directivesynopsis>

<directivesynopsis type="section">
<name>LimitExcept</name>
<description>Restrict access controls to all HTTP methods
except the named ones</description>
<syntax>&lt;LimitExcept <var>method</var> [<var>method</var>] ... &gt; ...
    &lt;/LimitExcept&gt;</syntax>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig, Limit</override>

<usage>
    <p><directive type="section">LimitExcept</directive> and
    <code>&lt;/LimitExcept&gt;</code> are used to enclose
    a group of access control directives which will then apply to any
    HTTP access method <strong>not</strong> listed in the arguments;
    i.e., it is the opposite of a <directive type="section"
    module="core">Limit</directive> section and can be used to control
    both standard and nonstandard/unrecognized methods. See the
    documentation for <directive module="core"
    type="section">Limit</directive> for more details.</p>

    <p>For example:</p>

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
<description>Determine maximum number of internal redirects and nested
subrequests</description>
<syntax>LimitInternalRecursion <var>number</var> [<var>number</var>]</syntax>
<default>LimitInternalRecursion 10</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>
<compatibility>Available in Apache httpd 2.0.47 and later</compatibility>

<usage>
    <p>An internal redirect happens, for example, when using the <directive
    module="mod_actions">Action</directive> directive, which internally
    redirects the original request to a CGI script. A subrequest is Apache httpd's
    mechanism to find out what would happen for some URI if it were requested.
    For example, <module>mod_dir</module> uses subrequests to look for the
    files listed in the <directive module="mod_dir">DirectoryIndex</directive>
    directive.</p>

    <p><directive>LimitInternalRecursion</directive> prevents the server
    from crashing when entering an infinite loop of internal redirects or
    subrequests. Such loops are usually caused by misconfigurations.</p>

    <p>The directive stores two different limits, which are evaluated on
    per-request basis. The first <var>number</var> is the maximum number of
    internal redirects, that may follow each other. The second <var>number</var>
    determines, how deep subrequests may be nested. If you specify only one
    <var>number</var>, it will be assigned to both limits.</p>

    <example><title>Example</title>
      LimitInternalRecursion 5
    </example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>LimitRequestBody</name>
<description>Restricts the total size of the HTTP request body sent
from the client</description>
<syntax>LimitRequestBody <var>bytes</var></syntax>
<default>LimitRequestBody 0</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>All</override>

<usage>
    <p>This directive specifies the number of <var>bytes</var> from 0
    (meaning unlimited) to 2147483647 (2GB) that are allowed in a
    request body. See the note below for the limited applicability
    to proxy requests.</p>

    <p>The <directive>LimitRequestBody</directive> directive allows
    the user to set a limit on the allowed size of an HTTP request
    message body within the context in which the directive is given
    (server, per-directory, per-file or per-location). If the client
    request exceeds that limit, the server will return an error
    response instead of servicing the request. The size of a normal
    request message body will vary greatly depending on the nature of
    the resource and the methods allowed on that resource. CGI scripts
    typically use the message body for retrieving form information.
    Implementations of the <code>PUT</code> method will require
    a value at least as large as any representation that the server
    wishes to accept for that resource.</p>

    <p>This directive gives the server administrator greater
    control over abnormal client request behavior, which may be
    useful for avoiding some forms of denial-of-service
    attacks.</p>

    <p>If, for example, you are permitting file upload to a particular
    location, and wish to limit the size of the uploaded file to 100K,
    you might use the following directive:</p>

    <example>
      LimitRequestBody 102400
    </example>
    
    <note><p>For a full description of how this directive is interpreted by 
    proxy requests, see the <module>mod_proxy</module> documentation.</p>
    </note>

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
    <p><var>Number</var> is an integer from 0 (meaning unlimited) to
    32767. The default value is defined by the compile-time
    constant <code>DEFAULT_LIMIT_REQUEST_FIELDS</code> (100 as
    distributed).</p>

    <p>The <directive>LimitRequestFields</directive> directive allows
    the server administrator to modify the limit on the number of
    request header fields allowed in an HTTP request. A server needs
    this value to be larger than the number of fields that a normal
    client request might include. The number of request header fields
    used by a client rarely exceeds 20, but this may vary among
    different client implementations, often depending upon the extent
    to which a user has configured their browser to support detailed
    content negotiation. Optional HTTP extensions are often expressed
    using request header fields.</p>

    <p>This directive gives the server administrator greater
    control over abnormal client request behavior, which may be
    useful for avoiding some forms of denial-of-service attacks.
    The value should be increased if normal clients see an error
    response from the server that indicates too many fields were
    sent in the request.</p>

    <p>For example:</p>

    <example>
      LimitRequestFields 50
    </example>

     <note type="warning"><title>Warning</title>
     <p> When name-based virtual hosting is used, the value for this 
     directive is taken from the default (first-listed) virtual host for the
     <directive>NameVirtualHost</directive> the connection was mapped to.</p>
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
    <p>This directive specifies the number of <var>bytes</var>
    that will be allowed in an HTTP request header.</p>

    <p>The <directive>LimitRequestFieldSize</directive> directive
    allows the server administrator to reduce or increase the limit 
    on the allowed size of an HTTP request header field. A server
    needs this value to be large enough to hold any one header field 
    from a normal client request. The size of a normal request header 
    field will vary greatly among different client implementations, 
    often depending upon the extent to which a user has configured
    their browser to support detailed content negotiation. SPNEGO
    authentication headers can be up to 12392 bytes.</p>

    <p>This directive gives the server administrator greater
    control over abnormal client request behavior, which may be
    useful for avoiding some forms of denial-of-service attacks.</p>

    <p>For example:</p>

    <example>
      LimitRequestFieldSize 4094
    </example>

    <note>Under normal conditions, the value should not be changed from
    the default.</note>

    <note type="warning"><title>Warning</title>
    <p> When name-based virtual hosting is used, the value for this 
    directive is taken from the default (first-listed) virtual host for the
    <directive>NameVirtualHost</directive> the connection was mapped to.</p>
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
    <p>This directive sets the number of <var>bytes</var> that will be 
    allowed on the HTTP request-line.</p>

    <p>The <directive>LimitRequestLine</directive> directive allows
    the server administrator to reduce or increase the limit on the allowed size
    of a client's HTTP request-line. Since the request-line consists of the
    HTTP method, URI, and protocol version, the
    <directive>LimitRequestLine</directive> directive places a
    restriction on the length of a request-URI allowed for a request
    on the server. A server needs this value to be large enough to
    hold any of its resource names, including any information that
    might be passed in the query part of a <code>GET</code> request.</p>

    <p>This directive gives the server administrator greater
    control over abnormal client request behavior, which may be
    useful for avoiding some forms of denial-of-service attacks.</p>

    <p>For example:</p>

    <example>
      LimitRequestLine 4094
    </example>

    <note>Under normal conditions, the value should not be changed from
    the default.</note>

    <note type="warning"><title>Warning</title>
    <p> When name-based virtual hosting is used, the value for this 
    directive is taken from the default (first-listed) virtual host for the
    <directive>NameVirtualHost</directive> the connection was mapped to.</p>
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
    <p>Limit (in bytes) on maximum size of an XML-based request
    body. A value of <code>0</code> will disable any checking.</p>

    <p>Example:</p>

    <example>
      LimitXMLRequestBody 0
    </example>

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
<description>Controls the verbosity of the ErrorLog</description>
<syntax>LogLevel [<var>module</var>:]<var>level</var>
    [<var>module</var>:<var>level</var>] ...
</syntax>
<default>LogLevel warn</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context>
</contextlist>
<compatibility>Per-module and per-directory configuration is available in
    Apache HTTP Server 2.3.6 and later</compatibility>

<usage>
    <p><directive>LogLevel</directive> adjusts the verbosity of the
    messages recorded in the error logs (see <directive
    module="core">ErrorLog</directive> directive). The following
    <var>level</var>s are available, in order of decreasing
    significance:</p>

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

        <td>Emergencies - system is unusable.</td>

        <td>"Child cannot open lock file. Exiting"</td>
      </tr>

      <tr>
        <td><code>alert</code> </td>

        <td>Action must be taken immediately.</td>

        <td>"getpwuid: couldn't determine user name from uid"</td>
      </tr>

      <tr>
        <td><code>crit</code> </td>

        <td>Critical Conditions.</td>

        <td>"socket: Failed to get a socket, exiting child"</td>
      </tr>

      <tr>
        <td><code>error</code> </td>

        <td>Error conditions.</td>

        <td>"Premature end of script headers"</td>
      </tr>

      <tr>
        <td><code>warn</code> </td>

        <td>Warning conditions.</td>

        <td>"child process 1234 did not exit, sending another
        SIGHUP"</td>
      </tr>

      <tr>
        <td><code>notice</code> </td>

        <td>Normal but significant condition.</td>

        <td>"httpd: caught SIGBUS, attempting to dump core in
        ..."</td>
      </tr>

      <tr>
        <td><code>info</code> </td>

        <td>Informational.</td>

        <td>"Server seems busy, (you may need to increase
        StartServers, or Min/MaxSpareServers)..."</td>
      </tr>

      <tr>
        <td><code>debug</code> </td>

        <td>Debug-level messages</td>

        <td>"Opening config file ..."</td>
      </tr>
      <tr>
        <td><code>trace1</code> </td>

        <td>Trace messages</td>

        <td>"proxy: FTP: control connection complete"</td>
      </tr>
      <tr>
        <td><code>trace2</code> </td>

        <td>Trace messages</td>

        <td>"proxy: CONNECT: sending the CONNECT request to the remote proxy"</td>
      </tr>
      <tr>
        <td><code>trace3</code> </td>

        <td>Trace messages</td>

        <td>"openssl: Handshake: start"</td>
      </tr>
      <tr>
        <td><code>trace4</code> </td>

        <td>Trace messages</td>

        <td>"read from buffered SSL brigade, mode 0, 17 bytes"</td>
      </tr>
      <tr>
        <td><code>trace5</code> </td>

        <td>Trace messages</td>

        <td>"map lookup FAILED: map=rewritemap key=keyname"</td>
      </tr>
      <tr>
        <td><code>trace6</code> </td>

        <td>Trace messages</td>

        <td>"cache lookup FAILED, forcing new map lookup"</td>
      </tr>
      <tr>
        <td><code>trace7</code> </td>

        <td>Trace messages, dumping large amounts of data</td>

        <td>"| 0000: 02 23 44 30 13 40 ac 34 df 3d bf 9a 19 49 39 15 |"</td>
      </tr>
      <tr>
        <td><code>trace8</code> </td>

        <td>Trace messages, dumping large amounts of data</td>

        <td>"| 0000: 02 23 44 30 13 40 ac 34 df 3d bf 9a 19 49 39 15 |"</td>
      </tr>
    </table>

    <p>When a particular level is specified, messages from all
    other levels of higher significance will be reported as well.
    <em>E.g.</em>, when <code>LogLevel info</code> is specified,
    then messages with log levels of <code>notice</code> and
    <code>warn</code> will also be posted.</p>

    <p>Using a level of at least <code>crit</code> is
    recommended.</p>

    <p>For example:</p>

    <example>
      LogLevel notice
    </example>

    <note><title>Note</title>
      <p>When logging to a regular file messages of the level
      <code>notice</code> cannot be suppressed and thus are always
      logged. However, this doesn't apply when logging is done
      using <code>syslog</code>.</p>
    </note>

    <p>Specifying a level without a module name will reset the level
    for all modules to that level.  Specifying a level with a module
    name will set the level for that module only. It is possible to
    use the module source file name, the module identifier, or the
    module identifier with the trailing <code>_module</code> omitted
    as module specification. This means the following three specifications
    are equivalent:</p>

    <example>
      LogLevel info ssl:warn<br />
      LogLevel info mod_ssl.c:warn<br />
      LogLevel info ssl_module:warn<br />
    </example>

    <p>It is also possible to change the level per directory:</p>

    <example>
        LogLevel info<br />
        &lt;Directory /usr/local/apache/htdocs/app&gt;<br />
        &nbsp; LogLevel debug<br />
        &lt;/Files&gt;
    </example>

    <note>
        Per directory loglevel configuration only affects messages that are
	logged after the request has been parsed and that are associated with
	the request. Log messages which are associated with the connection or
	the server are not affected.
    </note>
</usage>
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
<description>Number of requests allowed on a persistent
connection</description>
<syntax>MaxKeepAliveRequests <var>number</var></syntax>
<default>MaxKeepAliveRequests 100</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>The <directive>MaxKeepAliveRequests</directive> directive
    limits the number of requests allowed per connection when
    <directive module="core" >KeepAlive</directive> is on. If it is
    set to <code>0</code>, unlimited requests will be allowed. We
    recommend that this setting be kept to a high value for maximum
    server performance.</p>

    <p>For example:</p>

    <example>
      MaxKeepAliveRequests 500
    </example>
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
<description>Configures mutex mechanism and lock file directory for all
or specified mutexes</description>
<syntax>Mutex <var>mechanism</var> [default|<var>mutex-name</var>] ... [OmitPID]</syntax>
<default>Mutex default</default>
<contextlist><context>server config</context></contextlist>
<compatibility>Available in Apache HTTP Server 2.3.4 and later</compatibility>

<usage>
    <p>The <directive>Mutex</directive> directive sets the mechanism,
    and optionally the lock file location, that httpd and modules use
    to serialize access to resources.  Specify <code>default</code> as
    the first argument to change the settings for all mutexes; specify
    a mutex name (see table below) as the first argument to override
    defaults only for that mutex.</p>

    <p>The <directive>Mutex</directive> directive is typically used in
    the following exceptional situations:</p>

    <ul>
        <li>change the mutex mechanism when the default mechanism selected
        by <glossary>APR</glossary> has a functional or performance
        problem</li>

        <li>change the directory used by file-based mutexes when the
        default directory does not support locking</li>
    </ul>

    <note><title>Supported modules</title>
    <p>This directive only configures mutexes which have been registered
    with the core server using the <code>ap_mutex_register()</code> API.
    All modules bundled with httpd support the <directive>Mutex</directive>
    directive, but third-party modules may not.  Consult the documentation
    of the third-party module, which must indicate the mutex name(s) which
    can be configured if this directive is supported.</p>
    </note>

    <p>The following mutex <em>mechanisms</em> are available:</p>
    <ul>
        <li><code>default | yes</code>
        <p>This selects the default locking implementation, as determined by
        <glossary>APR</glossary>.  The default locking implementation can
        be displayed by running <program>httpd</program> with the 
        <code>-V</code> option.</p></li>

        <li><code>none | no</code>
        <p>This effectively disables the mutex, and is only allowed for a
        mutex if the module indicates that it is a valid choice.  Consult the
        module documentation for more information.</p></li>

        <li><code>posixsem</code>
        <p>This is a mutex variant based on a Posix semaphore.</p>

        <note type="warning"><title>Warning</title>
        <p>The semaphore ownership is not recovered if a thread in the process
        holding the mutex segfaults, resulting in a hang of the web server.</p>
        </note>
        </li>

        <li><code>sysvsem</code>
        <p>This is a mutex variant based on a SystemV IPC semaphore.</p>

        <note type="warning"><title>Warning</title>
        <p>It is possible to "leak" SysV semaphores if processes crash 
        before the semaphore is removed.</p>
	</note>

        <note type="warning"><title>Security</title>
        <p>The semaphore API allows for a denial of service attack by any
        CGIs running under the same uid as the webserver (<em>i.e.</em>,
        all CGIs, unless you use something like <program>suexec</program>
        or <code>cgiwrapper</code>).</p>
	</note>
        </li>

        <li><code>sem</code>
        <p>This selects the "best" available semaphore implementation, choosing
        between Posix and SystemV IPC semaphores, in that order.</p></li>

        <li><code>pthread</code>
        <p>This is a mutex variant based on cross-process Posix thread
        mutexes.</p>

        <note type="warning"><title>Warning</title>
        <p>On most systems, if a child process terminates abnormally while
        holding a mutex that uses this implementation, the server will deadlock
        and stop responding to requests.  When this occurs, the server will
        require a manual restart to recover.</p>
        <p>Solaris is a notable exception as it provides a mechanism which
        usually allows the mutex to be recovered after a child process
        terminates abnormally while holding a mutex.</p>
        <p>If your system implements the
        <code>pthread_mutexattr_setrobust_np()</code> function, you may be able
        to use the <code>pthread</code> option safely.</p>
        </note>
        </li>

        <li><code>fcntl:/path/to/mutex</code>
        <p>This is a mutex variant where a physical (lock-)file and the 
        <code>fcntl()</code> function are used as the mutex.</p>

        <note type="warning"><title>Warning</title>
        <p>When multiple mutexes based on this mechanism are used within
        multi-threaded, multi-process environments, deadlock errors (EDEADLK)
        can be reported for valid mutex operations if <code>fcntl()</code>
        is not thread-aware, such as on Solaris.</p>
	</note>
        </li>

        <li><code>flock:/path/to/mutex</code>
        <p>This is similar to the <code>fcntl:/path/to/mutex</code> method
        with the exception that the <code>flock()</code> function is used to
        provide file locking.</p></li>

        <li><code>file:/path/to/mutex</code>
        <p>This selects the "best" available file locking implementation,
        choosing between <code>fcntl</code> and <code>flock</code>, in that
        order.</p></li>
    </ul>

    <p>Most mechanisms are only available on selected platforms, where the 
    underlying platform and <glossary>APR</glossary> support it.  Mechanisms
    which aren't available on all platforms are <em>posixsem</em>,
    <em>sysvsem</em>, <em>sem</em>, <em>pthread</em>, <em>fcntl</em>, 
    <em>flock</em>, and <em>file</em>.</p>

    <p>With the file-based mechanisms <em>fcntl</em> and <em>flock</em>,
    the path, if provided, is a directory where the lock file will be created.
    The default directory is httpd's run-time file directory relative to
    <directive module="core">ServerRoot</directive>.  Always use a local disk
    filesystem for <code>/path/to/mutex</code> and never a directory residing
    on a NFS- or AFS-filesystem.  The basename of the file will be the mutex
    type, an optional instance string provided by the module, and unless the
    <code>OmitPID</code> keyword is specified, the process id of the httpd 
    parent process will be appended to to make the file name unique, avoiding
    conflicts when multiple httpd instances share a lock file directory.  For
    example, if the mutex name is <code>mpm-accept</code> and the lock file
    directory is <code>/var/httpd/locks</code>, the lock file name for the
    httpd instance with parent process id 12345 would be 
    <code>/var/httpd/locks/mpm-accept.12345</code>.</p>

    <note type="warning"><title>Security</title>
    <p>It is best to <em>avoid</em> putting mutex files in a world-writable
    directory such as <code>/var/tmp</code> because someone could create
    a denial of service attack and prevent the server from starting by
    creating a lockfile with the same name as the one the server will try
    to create.</p>
    </note>

    <p>The following table documents the names of mutexes used by httpd
    and bundled modules.</p>

    <table border="1" style="zebra">
        <tr>
            <th>Mutex name</th>
            <th>Module(s)</th>
            <th>Protected resource</th>
	</tr>
        <tr>
            <td><code>mpm-accept</code></td>
            <td><module>prefork</module> and <module>worker</module> MPMs</td>
            <td>incoming connections, to avoid the thundering herd problem;
            for more information, refer to the
            <a href="../misc/perf-tuning.html">performance tuning</a>
            documentation</td>
	</tr>
        <tr>
            <td><code>authdigest-client</code></td>
            <td><module>mod_auth_digest</module></td>
            <td>client list in shared memory</td>
	</tr>
        <tr>
            <td><code>authdigest-opaque</code></td>
            <td><module>mod_auth_digest</module></td>
            <td>counter in shared memory</td>
	</tr>
        <tr>
            <td><code>ldap-cache</code></td>
            <td><module>mod_ldap</module></td>
            <td>LDAP result cache</td>
	</tr>
        <tr>
            <td><code>rewrite-map</code></td>
            <td><module>mod_rewrite</module></td>
            <td>communication with external mapping programs, to avoid
            intermixed I/O from multiple requests</td>
	</tr>
        <tr>
            <td><code>ssl-cache</code></td>
            <td><module>mod_ssl</module></td>
            <td>SSL session cache</td>
	</tr>
        <tr>
            <td><code>ssl-stapling</code></td>
            <td><module>mod_ssl</module></td>
            <td>OCSP stapling response cache</td>
	</tr>
        <tr>
            <td><code>watchdog-callback</code></td>
            <td><module>mod_watchdog</module></td>
            <td>callback function of a particular client module</td>
	</tr>
    </table>

    <p>The <code>OmitPID</code> keyword suppresses the addition of the httpd
    parent process id from the lock file name.</p>

    <p>In the following example, the mutex mechanism for the MPM accept
    mutex will be changed from the compiled-in default to <code>fcntl</code>,
    with the associated lock file created in directory
    <code>/var/httpd/locks</code>.  The mutex mechanism for all other mutexes
    will be changed from the compiled-in default to <code>sysvsem</code>.</p>

    <example>
    Mutex default sysvsem<br />
    Mutex mpm-accept fcntl:/var/httpd/locks
    </example>
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
<description>Configures what features are available in a particular
directory</description>
<syntax>Options
    [+|-]<var>option</var> [[+|-]<var>option</var>] ...</syntax>
<default>Options All</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>Options</override>

<usage>
    <p>The <directive>Options</directive> directive controls which
    server features are available in a particular directory.</p>

    <p><var>option</var> can be set to <code>None</code>, in which
    case none of the extra features are enabled, or one or more of
    the following:</p>

    <dl>
      <dt><code>All</code></dt>

      <dd>All options except for <code>MultiViews</code>. This is the default
      setting.</dd>

      <dt><code>ExecCGI</code></dt>

      <dd>
      Execution of CGI scripts using <module>mod_cgi</module>
      is permitted.</dd>

      <dt><code>FollowSymLinks</code></dt>

      <dd>

      The server will follow symbolic links in this directory.
      <note>
      <p>Even though the server follows the symlink it does <em>not</em>
      change the pathname used to match against <directive type="section"
      module="core">Directory</directive> sections.</p>
      <p>Note also, that this option <strong>gets ignored</strong> if set
      inside a <directive type="section" module="core">Location</directive>
      section.</p>
      <p>Omitting this option should not be considered a security restriction,
      since symlink testing is subject to race conditions that make it
      circumventable.</p>
      </note></dd>

      <dt><code>Includes</code></dt>

      <dd>
      Server-side includes provided by <module>mod_include</module>
      are permitted.</dd>

      <dt><code>IncludesNOEXEC</code></dt>

      <dd>

      Server-side includes are permitted, but the <code>#exec
      cmd</code> and <code>#exec cgi</code> are disabled. It is still
      possible to <code>#include virtual</code> CGI scripts from
      <directive module="mod_alias">ScriptAlias</directive>ed
      directories.</dd>

      <dt><code>Indexes</code></dt>

      <dd>
      If a URL which maps to a directory is requested, and there
      is no <directive module="mod_dir">DirectoryIndex</directive>
      (<em>e.g.</em>, <code>index.html</code>) in that directory, then
      <module>mod_autoindex</module> will return a formatted listing
      of the directory.</dd>

      <dt><code>MultiViews</code></dt>

      <dd>
      <a href="../content-negotiation.html">Content negotiated</a>
      "MultiViews" are allowed using
      <module>mod_negotiation</module>.
      <note><title>Note</title> <p>This option gets ignored if set
      anywhere other than <directive module="core" type="section"
      >Directory</directive>, as <module>mod_negotiation</module>
      needs real resources to compare against and evaluate from.</p></note>
      </dd>

      <dt><code>SymLinksIfOwnerMatch</code></dt>

      <dd>The server will only follow symbolic links for which the
      target file or directory is owned by the same user id as the
      link.

      <note><title>Note</title> <p>This option gets ignored if
      set inside a <directive module="core"
      type="section">Location</directive> section.</p>
      <p>This option should not be considered a security restriction,
      since symlink testing is subject to race conditions that make it
      circumventable.</p></note>
      </dd>
    </dl>

    <p>Normally, if multiple <directive>Options</directive> could
    apply to a directory, then the most specific one is used and
    others are ignored; the options are not merged. (See <a
    href="../sections.html#mergin">how sections are merged</a>.)
    However if <em>all</em> the options on the
    <directive>Options</directive> directive are preceded by a
    <code>+</code> or <code>-</code> symbol, the options are
    merged. Any options preceded by a <code>+</code> are added to the
    options currently in force, and any options preceded by a
    <code>-</code> are removed from the options currently in
    force. </p>

    <note type="warning"><title>Warning</title>
    <p>Mixing <directive>Options</directive> with a <code>+</code> or
    <code>-</code> with those without is not valid syntax, and is likely
    to cause unexpected results.</p>
    </note>

    <p>For example, without any <code>+</code> and <code>-</code> symbols:</p>

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

    <p>then only <code>Includes</code> will be set for the
    <code>/web/docs/spec</code> directory. However if the second
    <directive>Options</directive> directive uses the <code>+</code> and
    <code>-</code> symbols:</p>

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

    <p>then the options <code>FollowSymLinks</code> and
    <code>Includes</code> are set for the <code>/web/docs/spec</code>
    directory.</p>

    <note><title>Note</title>
      <p>Using <code>-IncludesNOEXEC</code> or
      <code>-Includes</code> disables server-side includes completely
      regardless of the previous setting.</p>
    </note>

    <p>The default in the absence of any other settings is
    <code>All</code>.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>Protocol</name>
<description>Protocol for a listening socket</description>
<syntax>Protocol <var>protocol</var></syntax>
<contextlist><context>server config</context><context>virtual host</context></contextlist>
<compatibility>Available in Apache 2.1.5 and later.
On Windows from Apache 2.3.3 and later.</compatibility>

<usage>
    <p>This directive specifies the protocol used for a specific listening socket.
       The protocol is used to determine which module should handle a request, and
       to apply protocol specific optimizations with the <directive>AcceptFilter</directive>
       directive.</p>

    <p>You only need to set the protocol if you are running on non-standard ports, otherwise <code>http</code> is assumed for port 80 and <code>https</code> for port 443.</p>

    <p>For example, if you are running <code>https</code> on a non-standard port, specify the protocol explicitly:</p>

    <example>
      Protocol https
    </example>

    <p>You can also specify the protocol using the <directive module="mpm_common">Listen</directive> directive.</p>
</usage>
<seealso><directive>AcceptFilter</directive></seealso>
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
<description>Limits the CPU consumption of processes launched
by Apache httpd children</description>
<syntax>RLimitCPU <var>seconds</var>|max [<var>seconds</var>|max]</syntax>
<default>Unset; uses operating system defaults</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>All</override>

<usage>
    <p>Takes 1 or 2 parameters. The first parameter sets the soft
    resource limit for all processes and the second parameter sets
    the maximum resource limit. Either parameter can be a number,
    or <code>max</code> to indicate to the server that the limit should
    be set to the maximum allowed by the operating system
    configuration. Raising the maximum resource limit requires that
    the server is running as <code>root</code>, or in the initial startup
    phase.</p>

    <p>This applies to processes forked off from Apache httpd children
    servicing requests, not the Apache httpd children themselves. This
    includes CGI scripts and SSI exec commands, but not any
    processes forked off from the Apache httpd parent such as piped
    logs.</p>

    <p>CPU resource limits are expressed in seconds per
    process.</p>
</usage>
<seealso><directive module="core">RLimitMEM</directive></seealso>
<seealso><directive module="core">RLimitNPROC</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>RLimitMEM</name>
<description>Limits the memory consumption of processes launched
by Apache httpd children</description>
<syntax>RLimitMEM <var>bytes</var>|max [<var>bytes</var>|max]</syntax>
<default>Unset; uses operating system defaults</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>All</override>

<usage>
    <p>Takes 1 or 2 parameters. The first parameter sets the soft
    resource limit for all processes and the second parameter sets
    the maximum resource limit. Either parameter can be a number,
    or <code>max</code> to indicate to the server that the limit should
    be set to the maximum allowed by the operating system
    configuration. Raising the maximum resource limit requires that
    the server is running as <code>root</code>, or in the initial startup
    phase.</p>

    <p>This applies to processes forked off from Apache httpd children
    servicing requests, not the Apache httpd children themselves. This
    includes CGI scripts and SSI exec commands, but not any
    processes forked off from the Apache httpd parent such as piped
    logs.</p>

    <p>Memory resource limits are expressed in bytes per
    process.</p>
</usage>
<seealso><directive module="core">RLimitCPU</directive></seealso>
<seealso><directive module="core">RLimitNPROC</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>RLimitNPROC</name>
<description>Limits the number of processes that can be launched by
processes launched by Apache httpd children</description>
<syntax>RLimitNPROC <var>number</var>|max [<var>number</var>|max]</syntax>
<default>Unset; uses operating system defaults</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>All</override>

<usage>
    <p>Takes 1 or 2 parameters. The first parameter sets the soft
    resource limit for all processes and the second parameter sets
    the maximum resource limit. Either parameter can be a number,
    or <code>max</code> to indicate to the server that the limit
    should be set to the maximum allowed by the operating system
    configuration. Raising the maximum resource limit requires that
    the server is running as <code>root</code>, or in the initial startup
    phase.</p>

    <p>This applies to processes forked off from Apache httpd children
    servicing requests, not the Apache httpd children themselves. This
    includes CGI scripts and SSI exec commands, but not any
    processes forked off from the Apache httpd parent such as piped
    logs.</p>

    <p>Process limits control the number of processes per user.</p>

    <note><title>Note</title>
      <p>If CGI processes are <strong>not</strong> running
      under user ids other than the web server user id, this directive
      will limit the number of processes that the server itself can
      create. Evidence of this situation will be indicated by
      <strong><code>cannot fork</code></strong> messages in the
      <code>error_log</code>.</p>
    </note>
</usage>
<seealso><directive module="core">RLimitMEM</directive></seealso>
<seealso><directive module="core">RLimitCPU</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>ScriptInterpreterSource</name>
<description>Technique for locating the interpreter for CGI
scripts</description>
<syntax>ScriptInterpreterSource Registry|Registry-Strict|Script</syntax>
<default>ScriptInterpreterSource Script</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>FileInfo</override>
<compatibility>Win32 only;
option <code>Registry-Strict</code> is available in Apache HTTP Server 2.0 and
later</compatibility>

<usage>
    <p>This directive is used to control how Apache httpd finds the
    interpreter used to run CGI scripts. The default setting is
    <code>Script</code>. This causes Apache httpd to use the interpreter pointed to
    by the shebang line (first line, starting with <code>#!</code>) in the
    script. On Win32 systems this line usually looks like:</p>

    <example>
      #!C:/Perl/bin/perl.exe
    </example>

    <p>or, if <code>perl</code> is in the <code>PATH</code>, simply:</p>

    <example>
      #!perl
    </example>

    <p>Setting <code>ScriptInterpreterSource Registry</code> will
    cause the Windows Registry tree <code>HKEY_CLASSES_ROOT</code> to be
    searched using the script file extension (e.g., <code>.pl</code>) as a
    search key. The command defined by the registry subkey
    <code>Shell\ExecCGI\Command</code> or, if it does not exist, by the subkey
    <code>Shell\Open\Command</code> is used to open the script file. If the
    registry keys cannot be found, Apache httpd falls back to the behavior of the
    <code>Script</code> option.</p>

    <note type="warning"><title>Security</title>
    <p>Be careful when using <code>ScriptInterpreterSource
    Registry</code> with <directive
    module="mod_alias">ScriptAlias</directive>'ed directories, because
    Apache httpd will try to execute <strong>every</strong> file within this
    directory. The <code>Registry</code> setting may cause undesired
    program calls on files which are typically not executed. For
    example, the default open command on <code>.htm</code> files on
    most Windows systems will execute Microsoft Internet Explorer, so
    any HTTP request for an <code>.htm</code> file existing within the
    script directory would start the browser in the background on the
    server. This is a good way to crash your system within a minute or
    so.</p>
    </note>

    <p>The option <code>Registry-Strict</code> which is new in Apache HTTP Server
    2.0 does the same thing as <code>Registry</code> but uses only the
    subkey <code>Shell\ExecCGI\Command</code>. The
    <code>ExecCGI</code> key is not a common one. It must be
    configured manually in the windows registry and hence prevents
    accidental program calls on your system.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SeeRequestTail</name>
<description>Determine if mod_status displays the first 63 characters
of a request or the last 63, assuming the request itself is greater than
63 chars.</description>
<syntax>SeeRequestTail On|Off</syntax>
<default>SeeRequestTail Off</default>
<contextlist><context>server config</context></contextlist>
<compatibility>Available in Apache httpd 2.2.7 and later.</compatibility>

<usage>
    <p>mod_status with <code>ExtendedStatus On</code>
    displays the actual request being handled. 
    For historical purposes, only 63 characters of the request
    are actually stored for display purposes. This directive
    controls whether the 1st 63 characters are stored (the previous
    behavior and the default) or if the last 63 characters are. This
    is only applicable, of course, if the length of the request is
    64 characters or greater.</p>

    <p>If Apache httpd is handling <code
    >GET&nbsp;/disk1/storage/apache/htdocs/images/imagestore1/food/apples.jpg&nbsp;HTTP/1.1</code
    > mod_status displays as follows:
    </p>

    <table border="1">
      <tr>
        <th>Off (default)</th>
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
<description>Email address that the server includes in error
messages sent to the client</description>
<syntax>ServerAdmin <var>email-address</var>|<var>URL</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>The <directive>ServerAdmin</directive> sets the contact address
    that the server includes in any error messages it returns to the
    client. If the <code>httpd</code> doesn't recognize the supplied argument
    as an URL, it
    assumes, that it's an <var>email-address</var> and prepends it with
    <code>mailto:</code> in hyperlink targets. However, it's recommended to
    actually use an email address, since there are a lot of CGI scripts that
    make that assumption. If you want to use an URL, it should point to another
    server under your control. Otherwise users may not be able to contact you in
    case of errors.</p>

    <p>It may be worth setting up a dedicated address for this, e.g.</p>

    <example>
      ServerAdmin www-admin@foo.example.com
    </example>
    <p>as users do not always mention that they are talking about the
    server!</p>
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
<description>Legacy URL pathname for a name-based virtual host that
is accessed by an incompatible browser</description>
<syntax>ServerPath <var>URL-path</var></syntax>
<contextlist><context>virtual host</context></contextlist>

<usage>
    <p>The <directive>ServerPath</directive> directive sets the legacy
    URL pathname for a host, for use with <a
    href="../vhosts/">name-based virtual hosts</a>.</p>
</usage>
<seealso><a href="../vhosts/">Apache HTTP Server Virtual Host documentation</a></seealso>
</directivesynopsis>

<directivesynopsis>
<name>ServerRoot</name>
<description>Base directory for the server installation</description>
<syntax>ServerRoot <var>directory-path</var></syntax>
<default>ServerRoot /usr/local/apache</default>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>The <directive>ServerRoot</directive> directive sets the
    directory in which the server lives. Typically it will contain the
    subdirectories <code>conf/</code> and <code>logs/</code>. Relative
    paths in other configuration directives (such as <directive
    module="core">Include</directive> or <directive
    module="mod_so">LoadModule</directive>, for example) are taken as 
    relative to this directory.</p>

    <example><title>Example</title>
      ServerRoot /home/httpd
    </example>

</usage>
<seealso><a href="../invoking.html">the <code>-d</code>
    option to <code>httpd</code></a></seealso>
<seealso><a href="../misc/security_tips.html#serverroot">the
    security tips</a> for information on how to properly set
    permissions on the <directive>ServerRoot</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>ServerSignature</name>
<description>Configures the footer on server-generated documents</description>
<syntax>ServerSignature On|Off|EMail</syntax>
<default>ServerSignature Off</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>All</override>

<usage>
    <p>The <directive>ServerSignature</directive> directive allows the
    configuration of a trailing footer line under server-generated
    documents (error messages, <module>mod_proxy</module> ftp directory
    listings, <module>mod_info</module> output, ...). The reason why you
    would want to enable such a footer line is that in a chain of proxies,
    the user often has no possibility to tell which of the chained servers
    actually produced a returned error message.</p>

    <p>The <code>Off</code>
    setting, which is the default, suppresses the footer line (and is
    therefore compatible with the behavior of Apache-1.2 and
    below). The <code>On</code> setting simply adds a line with the
    server version number and <directive
    module="core">ServerName</directive> of the serving virtual host,
    and the <code>EMail</code> setting additionally creates a
    "mailto:" reference to the <directive
    module="core">ServerAdmin</directive> of the referenced
    document.</p>

    <p>After version 2.0.44, the details of the server version number
    presented are controlled by the <directive
    module="core">ServerTokens</directive> directive.</p>
</usage>
<seealso><directive module="core">ServerTokens</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>ServerTokens</name>
<description>Configures the <code>Server</code> HTTP response
header</description>
<syntax>ServerTokens Major|Minor|Min[imal]|Prod[uctOnly]|OS|Full</syntax>
<default>ServerTokens Full</default>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>This directive controls whether <code>Server</code> response
    header field which is sent back to clients includes a
    description of the generic OS-type of the server as well as
    information about compiled-in modules.</p>

    <dl>
      <dt><code>ServerTokens Full</code> (or not specified)</dt>

      <dd>Server sends (<em>e.g.</em>): <code>Server: Apache/2.4.1
      (Unix) PHP/4.2.2 MyMod/1.2</code></dd>

      <dt><code>ServerTokens Prod[uctOnly]</code></dt>

      <dd>Server sends (<em>e.g.</em>): <code>Server:
      Apache</code></dd>

      <dt><code>ServerTokens Major</code></dt>

      <dd>Server sends (<em>e.g.</em>): <code>Server:
      Apache/2</code></dd>

      <dt><code>ServerTokens Minor</code></dt>

      <dd>Server sends (<em>e.g.</em>): <code>Server:
      Apache/2.4</code></dd>

      <dt><code>ServerTokens Min[imal]</code></dt>

      <dd>Server sends (<em>e.g.</em>): <code>Server:
      Apache/2.4.1</code></dd>

      <dt><code>ServerTokens OS</code></dt>

      <dd>Server sends (<em>e.g.</em>): <code>Server: Apache/2.4.1
      (Unix)</code></dd>

    </dl>

    <p>This setting applies to the entire server, and cannot be
    enabled or disabled on a virtualhost-by-virtualhost basis.</p>

    <p>After version 2.0.44, this directive also controls the
    information presented by the <directive
    module="core">ServerSignature</directive> directive.</p>
    
    <note>Setting <directive>ServerTokens</directive> to less than
    <code>minimal</code> is not recommended because it makes it more
    difficult to debug interoperational problems. Also note that
    disabling the Server: header does nothing at all to make your
    server more secure; the idea of "security through obscurity"
    is a myth and leads to a false sense of safety.</note>

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
<description>Sets the filters that will process client requests and POST
input</description>
<syntax>SetInputFilter <var>filter</var>[;<var>filter</var>...]</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>FileInfo</override>

<usage>
    <p>The <directive>SetInputFilter</directive> directive sets the
    filter or filters which will process client requests and POST
    input when they are received by the server. This is in addition to
    any filters defined elsewhere, including the
    <directive module="mod_mime">AddInputFilter</directive>
    directive.</p>

    <p>If more than one filter is specified, they must be separated
    by semicolons in the order in which they should process the
    content.</p>
</usage>
<seealso><a href="../filter.html">Filters</a> documentation</seealso>
</directivesynopsis>

<directivesynopsis>
<name>SetOutputFilter</name>
<description>Sets the filters that will process responses from the
server</description>
<syntax>SetOutputFilter <var>filter</var>[;<var>filter</var>...]</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>FileInfo</override>

<usage>
    <p>The <directive>SetOutputFilter</directive> directive sets the filters
    which will process responses from the server before they are
    sent to the client. This is in addition to any filters defined
    elsewhere, including the
    <directive module="mod_mime">AddOutputFilter</directive>
    directive.</p>

    <p>For example, the following configuration will process all files
    in the <code>/www/data/</code> directory for server-side
    includes.</p>

    <example>
      &lt;Directory /www/data/&gt;<br />
      <indent>
        SetOutputFilter INCLUDES<br />
      </indent>
      &lt;/Directory&gt;
    </example>

    <p>If more than one filter is specified, they must be separated
    by semicolons in the order in which they should process the
    content.</p>
</usage>
<seealso><a href="../filter.html">Filters</a> documentation</seealso>
</directivesynopsis>

<directivesynopsis>
<name>TimeOut</name>
<description>Amount of time the server will wait for
certain events before failing a request</description>
<syntax>TimeOut <var>seconds</var></syntax>
<default>TimeOut 60</default>
<contextlist><context>server config</context><context>virtual host</context></contextlist>

<usage>
    <p>The <directive>TimeOut</directive> directive defines the length
    of time Apache httpd will wait for I/O in various circumstances:</p>

    <ol>
      <li>When reading data from the client, the length of time to
      wait for a TCP packet to arrive if the read buffer is
      empty.</li>

      <li>When writing data to the client, the length of time to wait
      for an acknowledgement of a packet if the send buffer is
      full.</li>

      <li>In <module>mod_cgi</module>, the length of time to wait for
      output from a CGI script.</li>

      <li>In <module>mod_ext_filter</module>, the length of time to
      wait for output from a filtering process.</li>

      <li>In <module>mod_proxy</module>, the default timeout value if
      <directive module="mod_proxy">ProxyTimeout</directive> is not
      configured.</li>
    </ol>

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
<description>Configures how the server determines its own name and
port</description>
<syntax>UseCanonicalName On|Off|DNS</syntax>
<default>UseCanonicalName Off</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>

<usage>
    <p>In many situations Apache httpd must construct a <em>self-referential</em>
    URL -- that is, a URL that refers back to the same server. With
    <code>UseCanonicalName On</code> Apache httpd will use the hostname and port
    specified in the <directive module="core">ServerName</directive>
    directive to construct the canonical name for the server. This name
    is used in all self-referential URLs, and for the values of
    <code>SERVER_NAME</code> and <code>SERVER_PORT</code> in CGIs.</p>

    <p>With <code>UseCanonicalName Off</code> Apache httpd will form
    self-referential URLs using the hostname and port supplied by
    the client if any are supplied (otherwise it will use the
    canonical name, as defined above). These values are the same
    that are used to implement <a
    href="../vhosts/name-based.html">name-based virtual hosts</a>,
    and are available with the same clients. The CGI variables
    <code>SERVER_NAME</code> and <code>SERVER_PORT</code> will be
    constructed from the client supplied values as well.</p>

    <p>An example where this may be useful is on an intranet server
    where you have users connecting to the machine using short
    names such as <code>www</code>. You'll notice that if the users
    type a shortname, and a URL which is a directory, such as
    <code>http://www/splat</code>, <em>without the trailing
    slash</em> then Apache httpd will redirect them to
    <code>http://www.domain.com/splat/</code>. If you have
    authentication enabled, this will cause the user to have to
    authenticate twice (once for <code>www</code> and once again
    for <code>www.domain.com</code> -- see <a
    href="http://httpd.apache.org/docs/misc/FAQ.html#prompted-twice">the
    FAQ on this subject for more information</a>). But if
    <directive>UseCanonicalName</directive> is set <code>Off</code>, then
    Apache httpd will redirect to <code>http://www/splat/</code>.</p>

    <p>There is a third option, <code>UseCanonicalName DNS</code>,
    which is intended for use with mass IP-based virtual hosting to
    support ancient clients that do not provide a
    <code>Host:</code> header. With this option Apache httpd does a
    reverse DNS lookup on the server IP address that the client
    connected to in order to work out self-referential URLs.</p>

    <note type="warning"><title>Warning</title>
    <p>If CGIs make assumptions about the values of <code>SERVER_NAME</code>
    they may be broken by this option. The client is essentially free
    to give whatever value they want as a hostname. But if the CGI is
    only using <code>SERVER_NAME</code> to construct self-referential URLs
    then it should be just fine.</p>
    </note>
</usage>
<seealso><directive module="core">UseCanonicalPhysicalPort</directive></seealso>
<seealso><directive module="core">ServerName</directive></seealso>
<seealso><directive module="mpm_common">Listen</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>UseCanonicalPhysicalPort</name>
<description>Configures how the server determines its own name and
port</description>
<syntax>UseCanonicalPhysicalPort On|Off</syntax>
<default>UseCanonicalPhysicalPort Off</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>

<usage>
    <p>In many situations Apache httpd must construct a <em>self-referential</em>
    URL -- that is, a URL that refers back to the same server. With
    <code>UseCanonicalPhysicalPort On</code> Apache httpd will, when
    constructing the canonical port for the server to honor
    the <directive module="core">UseCanonicalName</directive> directive,
    provide the actual physical port number being used by this request
    as a potential port. With <code>UseCanonicalPhysicalPort Off</code>
    Apache httpd will not ever use the actual physical port number, instead
    relying on all configured information to construct a valid port number.</p>

    <note><title>Note</title>
    <p>The ordering of when the physical port is used is as follows:<br /><br />
     <code>UseCanonicalName On</code></p>
     <ul>
      <li>Port provided in <code>Servername</code></li>
      <li>Physical port</li>
      <li>Default port</li>
     </ul>
     <code>UseCanonicalName Off | DNS</code>
     <ul>
      <li>Parsed port from <code>Host:</code> header</li>
      <li>Physical port</li>
      <li>Port provided in <code>Servername</code></li>
      <li>Default port</li>
     </ul>
    
    <p>With <code>UseCanonicalPhysicalPort Off</code>, the
    physical ports are removed from the ordering.</p>
    </note>

</usage>
<seealso><directive module="core">UseCanonicalName</directive></seealso>
<seealso><directive module="core">ServerName</directive></seealso>
<seealso><directive module="mpm_common">Listen</directive></seealso>
</directivesynopsis>

<directivesynopsis type="section">
<name>VirtualHost</name>
<description>Contains directives that apply only to a specific
hostname or IP address</description>
<syntax>&lt;VirtualHost
    <var>addr</var>[:<var>port</var>] [<var>addr</var>[:<var>port</var>]]
    ...&gt; ... &lt;/VirtualHost&gt;</syntax>
<contextlist><context>server config</context></contextlist>

<usage>
    <p><directive type="section">VirtualHost</directive> and
    <code>&lt;/VirtualHost&gt;</code> are used to enclose a group of
    directives that will apply only to a particular virtual host. Any
    directive that is allowed in a virtual host context may be
    used. When the server receives a request for a document on a
    particular virtual host, it uses the configuration directives
    enclosed in the <directive type="section">VirtualHost</directive>
    section. <var>Addr</var> can be:</p>

    <ul>
      <li>The IP address of the virtual host;</li>

      <li>A fully qualified domain name for the IP address of the
      virtual host (not recommended);</li>

      <li>The character <code>*</code>, which is used only in combination with
      <code>NameVirtualHost *</code> to match all IP addresses; or</li>

      <li>The string <code>_default_</code>, which is used only
      with IP virtual hosting to catch unmatched IP addresses.</li>
    </ul>

    <example><title>Example</title>
      &lt;VirtualHost 10.1.2.3&gt;<br />
      <indent>
        ServerAdmin webmaster@host.example.com<br />
        DocumentRoot /www/docs/host.example.com<br />
        ServerName host.example.com<br />
        ErrorLog logs/host.example.com-error_log<br />
        TransferLog logs/host.example.com-access_log<br />
      </indent>
      &lt;/VirtualHost&gt;
    </example>


    <p>IPv6 addresses must be specified in square brackets because
    the optional port number could not be determined otherwise.  An
    IPv6 example is shown below:</p>

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

    <p>Each Virtual Host must correspond to a different IP address,
    different port number or a different host name for the server,
    in the former case the server machine must be configured to
    accept IP packets for multiple addresses. (If the machine does
    not have multiple network interfaces, then this can be
    accomplished with the <code>ifconfig alias</code> command -- if
    your OS supports it).</p>

    <note><title>Note</title>
    <p>The use of <directive type="section">VirtualHost</directive> does
    <strong>not</strong> affect what addresses Apache httpd listens on. You
    may need to ensure that Apache httpd is listening on the correct addresses
    using <directive module="mpm_common">Listen</directive>.</p>
    </note>

    <p>When using IP-based virtual hosting, the special name
    <code>_default_</code> can be specified in
    which case this virtual host will match any IP address that is
    not explicitly listed in another virtual host. In the absence
    of any <code>_default_</code> virtual host the "main" server config,
    consisting of all those definitions outside any VirtualHost
    section, is used when no IP-match occurs.</p>

    <p>You can specify a <code>:port</code> to change the port that is
    matched. If unspecified then it defaults to the same port as the
    most recent <directive module="mpm_common">Listen</directive>
    statement of the main server. You may also specify <code>:*</code>
    to match all ports on that address. (This is recommended when used
    with <code>_default_</code>.)</p>

    <p>A <directive module="core">ServerName</directive> should be
    specified inside each <directive
    type="section">VirtualHost</directive> block. If it is absent, the
    <directive module="core">ServerName</directive> from the "main"
    server configuration will be inherited.</p>

    <p>If no matching virtual host is found, then the first listed
    virtual host that matches the IP address will be used.  As a
    consequence, the first listed virtual host is the default virtual
    host.</p>

    <note type="warning"><title>Security</title>
    <p>See the <a href="../misc/security_tips.html">security tips</a>
    document for details on why your security could be compromised if the
    directory where log files are stored is writable by anyone other
    than the user that starts the server.</p>
    </note>
</usage>
<seealso><a href="../vhosts/">Apache HTTP Server Virtual Host documentation</a></seealso>
<seealso><a href="../dns-caveats.html">Issues Regarding DNS and
    Apache HTTP Server</a></seealso>
<seealso><a href="../bind.html">Setting
    which addresses and ports Apache HTTP Server uses</a></seealso>
<seealso><a href="../sections.html">How &lt;Directory&gt;, &lt;Location&gt;
    and &lt;Files&gt; sections work</a> for an explanation of how these
    different sections are combined when a request is received</seealso>
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
