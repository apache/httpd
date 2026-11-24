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

<modulesynopsis metafile="mod_cache.xml.meta">

<name>mod_cache</name>
<description>Filtro de caché HTTP compatible con RFC 2616.</description>
<status>Extension</status>
<sourcefile>mod_cache.c</sourcefile>
<identifier>cache_module</identifier>

<summary>
    <note type="warning">Este módulo debe usarse con cuidado, ya que cuando la
    directiva <directive module="mod_cache">CacheQuickHandler</directive> está
    en su valor por defecto de <strong>on</strong>, las directivas <directive
    module="mod_access_compat">Allow</directive> y <directive
    module="mod_access_compat">Deny</directive> se eluden.
    No debería activar el caché por quick handler para ningún contenido al que
    desee limitar el acceso por nombre de host del cliente, dirección o variable
    de entorno.</note>

    <p><module>mod_cache</module> implementa un <strong>filtro de caché de
    contenido HTTP</strong> compatible con <rfc>2616</rfc>, con soporte para el
    almacenamiento en caché de respuestas de negociación de contenido que
    contienen la cabecera Vary.</p>

    <p>El almacenamiento en caché compatible con RFC 2616 proporciona un
    mecanismo para verificar si un contenido obsoleto o caducado sigue siendo
    válido, y puede suponer una mejora de rendimiento significativa cuando el
    servidor de origen admite <strong>peticiones condicionales</strong>
    respetando la cabecera de petición HTTP
    If-None-Match (<rfc section="14.26">2616</rfc>).
    El contenido solo se regenera desde cero cuando el contenido
    ha cambiado, y no cuando caduca la entrada de la caché.</p>

    <p>Como filtro, <module>mod_cache</module> puede colocarse delante del
    contenido procedente de cualquier handler, incluyendo <strong>archivos
    planos</strong> (servidos desde un disco lento y cacheados en un disco
    rápido), la salida de un <strong>script CGI</strong> o de un
    <strong>generador de contenido dinámico</strong>, o contenido
    <strong>proxyado desde otro servidor</strong>.</p>

    <p>En la configuración por defecto, <module>mod_cache</module> inserta el
    filtro de caché lo más adelante posible dentro de la pila de filtros,
    utilizando el <strong>quick handler</strong> para omitir todo el
    procesamiento por petición al devolver contenido al cliente. En este modo
    de funcionamiento, <module>mod_cache</module> puede entenderse como un
    servidor proxy de caché acoplado delante del servidor web, pero
    ejecutándose dentro del propio servidor web.</p>

    <p>Cuando el quick handler se desactiva mediante la directiva
    <directive module="mod_cache">CacheQuickHandler</directive>,
    es posible insertar el filtro <strong>CACHE</strong> en un
    punto de la pila de filtros elegido por el administrador. Esto ofrece la
    posibilidad de almacenar en caché el contenido antes de que ese contenido se
    personalice mediante el filtro de <module>mod_include</module>, o se
    comprima opcionalmente mediante el filtro de <module>mod_deflate</module>.</p>

    <p>En condiciones normales, <module>mod_cache</module> responderá a las
    cabeceras
    Cache-Control (<rfc section="14.9">2616</rfc>)
    y
    Pragma (<rfc section="14.32">2616</rfc>)
    enviadas por un cliente en una petición, o por un
    servidor en una respuesta, y puede controlarse mediante ellas. En circunstancias
    excepcionales, <module>mod_cache</module> puede configurarse para anular estas
    cabeceras y forzar un comportamiento específico del sitio; sin embargo, dicho
    comportamiento se limitará a esta caché únicamente, y no afectará al
    funcionamiento de otras cachés que puedan existir entre el cliente y el
    servidor, por lo que no se recomienda salvo que sea estrictamente
    necesario.</p>

    <p>RFC 2616 permite que la caché devuelva datos obsoletos mientras la
    entrada obsoleta existente se actualiza desde el servidor de origen, y esto
    está soportado por <module>mod_cache</module> cuando la directiva
    <directive module="mod_cache">CacheLock</directive> está configurada
    adecuadamente. Dichas respuestas contendrán una cabecera HTTP
    Warning (<rfc section="14.46">2616</rfc>)
    con un código de respuesta 110. RFC 2616 también permite que una caché devuelva
    datos obsoletos cuando el intento de actualizar esos datos obsoletos devuelve un
    error 500 o superior, y este comportamiento está soportado por defecto por
    <module>mod_cache</module>. Dichas respuestas contendrán una cabecera HTTP
    Warning (<rfc section="14.46">2616</rfc>)
    con un código de respuesta 111.</p>

    <p><module>mod_cache</module> requiere los servicios de uno o más
    módulos de gestión de almacenamiento. La distribución base de Apache incluye los
    siguientes módulos de gestión de almacenamiento:</p>
    <dl>
    <dt><module>mod_cache_disk</module></dt>
    <dd>Implementa un gestor de almacenamiento basado en disco. Las cabeceras y los
    cuerpos se almacenan por separado en disco, en una estructura de directorios derivada
    del hash md5 de la URL cacheada. Se pueden almacenar simultáneamente varias
    respuestas de negociación de contenido, aunque este módulo no admite
    el almacenamiento en caché de contenido parcial. Se proporciona la herramienta
    <program>htcacheclean</program> para listar las URL cacheadas, eliminar URL
    cacheadas, o mantener el tamaño de la caché de disco dentro de los límites de
    tamaño e inodos.</dd>
    <dt><module>mod_cache_socache</module></dt>
    <dd>Implementa un gestor de almacenamiento basado en una caché de objetos
    compartida. Las cabeceras y los cuerpos se almacenan juntos bajo una única
    clave basada en la URL de la respuesta que se está cacheando. Se pueden almacenar
    simultáneamente varias respuestas de negociación de contenido, aunque este
    módulo no admite el almacenamiento en caché de contenido parcial.</dd>
    </dl>

    <p>Encontrará más detalles, discusión y ejemplos en la
    <a href="../caching.html">Guía de caché</a>.</p>
</summary>
<seealso><a href="../caching.html">Guía de caché</a></seealso>

<section id="related"><title>Módulos y directivas relacionados</title>
    <related>
      <modulelist>
        <module>mod_cache_disk</module>
        <module>mod_cache_socache</module>
      </modulelist>
      <directivelist>
        <directive module="mod_cache_disk">CacheRoot</directive>
        <directive module="mod_cache_disk">CacheDirLevels</directive>
        <directive module="mod_cache_disk">CacheDirLength</directive>
        <directive module="mod_cache_disk">CacheMinFileSize</directive>
        <directive module="mod_cache_disk">CacheMaxFileSize</directive>
        <directive module="mod_cache_socache">CacheSocache</directive>
        <directive module="mod_cache_socache">CacheSocacheMaxTime</directive>
        <directive module="mod_cache_socache">CacheSocacheMinTime</directive>
        <directive module="mod_cache_socache">CacheSocacheMaxSize</directive>
        <directive module="mod_cache_socache">CacheSocacheReadSize</directive>
        <directive module="mod_cache_socache">CacheSocacheReadTime</directive>
      </directivelist>
    </related>
</section>

<section id="sampleconf"><title>Ejemplo de configuración</title>
    <example><title>Ejemplo de httpd.conf</title>
    <highlight language="config">
#
# Sample Cache Configuration
#
LoadModule cache_module modules/mod_cache.so
&lt;IfModule mod_cache.c&gt;
    LoadModule cache_disk_module modules/mod_cache_disk.so
    &lt;IfModule mod_cache_disk.c&gt;
        CacheRoot c:/cacheroot
        CacheEnable disk  /
        CacheDirLevels 5
        CacheDirLength 3
    &lt;/IfModule&gt;

    # When acting as a proxy, don't cache the list of security updates
    CacheDisable http://security.update.server/update-list/
&lt;/IfModule&gt;
      </highlight>
    </example>
</section>

<section id="thunderingherd"><title>Evitar el "thundering herd"</title>
  <p>Cuando una entrada cacheada se vuelve obsoleta, <module>mod_cache</module> enviará
  una petición condicional al backend, que debe confirmar si la
  entrada cacheada sigue siendo válida, y enviar una entidad actualizada si no lo es.</p>
  <p>Transcurre una cantidad de tiempo pequeña pero finita entre el momento en que la entidad cacheada
  se vuelve obsoleta y el momento en que esa entidad obsoleta se actualiza por completo. En un
  servidor con mucho tráfico, puede llegar un número significativo de peticiones durante ese tiempo, y
  provocar una avalancha repentina e impredecible de peticiones al backend
  (<strong>thundering herd</strong>).</p>
  <p>Para contener esa avalancha, la directiva <directive module="mod_cache">CacheLock</directive>
  puede usarse para definir un directorio en el que se crean bloqueos para
  las URL <strong>en curso</strong>. El bloqueo se usa como <strong>indicio</strong>
  por otras peticiones para suprimir un intento de almacenamiento en caché (otra petición ya ha
  ido a buscar la entidad), o para indicar que una entrada obsoleta se está
  actualizando (mientras tanto se devolverá contenido obsoleto).
  </p>
  <section>
    <title>Almacenamiento inicial en caché de una entrada</title>
    <p>Cuando una entidad se cachea por primera vez, se crea un bloqueo para la
    entidad hasta que la respuesta se ha cacheado por completo. Durante la vida del
    bloqueo, la caché suprimirá el segundo y los siguientes intentos de cachear la
    misma entidad. Aunque esto no detiene la avalancha, sí evita que la
    caché intente cachear la misma entidad varias veces simultáneamente.
    </p>
  </section>
  <section>
    <title>Actualización de una entrada obsoleta</title>
    <p>Cuando una entidad alcanza su vida útil de frescura y se vuelve obsoleta, se
    crea un bloqueo para la entidad hasta que la respuesta se haya confirmado como
    válida, o la haya sustituido el backend. Durante la vida del bloqueo, la
    segunda petición entrante y las siguientes harán que se devuelvan datos obsoletos,
    conteniendo así la avalancha.</p>
  </section>
  <section>
    <title>Bloqueos y Cache-Control: no-cache</title>
    <p>Los bloqueos se usan solo como un <strong>indicio</strong> para permitir que la caché sea
    más considerada con los servidores backend; sin embargo, el bloqueo puede saltarse si es necesario.
    Si el cliente envía una petición con una cabecera Cache-Control que fuerza una recarga, cualquier
    bloqueo que pueda existir se ignorará, y la petición del cliente se
    atenderá de inmediato, actualizándose la entrada cacheada.</p>
    <p>Como mecanismo de seguridad adicional, los bloqueos tienen una antigüedad máxima configurable.
    Una vez alcanzada esa antigüedad, el bloqueo se elimina, y una nueva petición tiene
    la oportunidad de crear un nuevo bloqueo. Esta antigüedad máxima puede establecerse con
    la directiva <directive module="mod_cache">CacheLockMaxAge</directive>, y por defecto
    es de 5 segundos.
    </p>
  </section>
  <section>
    <title>Ejemplo de configuración</title>
    <example><title>Activar el bloqueo de caché</title>
    <highlight language="config">
#
# Enable the cache lock
#
&lt;IfModule mod_cache.c&gt;
    CacheLock on
    CacheLockPath /tmp/mod_cache-lock
    CacheLockMaxAge 5
&lt;/IfModule&gt;
      </highlight>
    </example>
  </section>
</section>

<section id="finecontrol"><title>Control fino con el filtro CACHE</title>
  <p>En el modo de funcionamiento de caché por defecto, la caché se ejecuta como quick handler,
  cortando el camino a la mayor parte del procesamiento del servidor y ofreciendo el mejor
  rendimiento de caché disponible.</p>

  <p>En este modo, la caché se <strong>acopla</strong> delante del servidor,
  actuando como si se hubiera colocado delante del servidor un proxy de caché
  compatible con RFC 2616 independiente.</p>

  <p>Aunque este modo ofrece el mejor rendimiento, el administrador puede necesitar,
  en determinadas circunstancias, realizar más procesamiento sobre la
  petición después de que se cachee, como para inyectar personalización en la
  página cacheada, o para aplicar restricciones de autorización al contenido. En estas
  circunstancias, a menudo el administrador se ve obligado a colocar servidores proxy inverso
  independientes detrás o delante del servidor de caché para lograrlo.</p>

  <p>Para resolver este problema, la directiva <directive module="mod_cache">CacheQuickHandler</directive>
  puede establecerse a <strong>off</strong>, y el servidor
  procesará todas las fases que normalmente se gestionan en una petición sin caché, incluyendo las
  fases de <strong>autenticación y autorización</strong>.</p>

  <p>Además, el administrador puede especificar opcionalmente el <strong>punto exacto
  dentro de la cadena de filtros</strong> en el que se realizará el almacenamiento en caché, añadiendo el
  filtro <strong>CACHE</strong> a la cadena de filtros de salida.</p>

  <p>Por ejemplo, para cachear el contenido antes de aplicar compresión a la respuesta,
  coloque el filtro <strong>CACHE</strong> antes del filtro <strong>DEFLATE</strong>
  como en el siguiente ejemplo:</p>

  <highlight language="config">
# Cache content before optional compression
CacheQuickHandler off
AddOutputFilterByType CACHE;DEFLATE text/plain
  </highlight>

  <p>Otra opción es cachear el contenido antes de que
  <module>mod_include</module> (u otro filtro de procesamiento de contenido) aplique la
  personalización. En este ejemplo, las plantillas que contienen etiquetas que entiende
  <module>mod_include</module> se cachean antes de analizarse:</p>

  <highlight language="config">
# Cache content before mod_include and mod_deflate
CacheQuickHandler off
AddOutputFilterByType CACHE;INCLUDES;DEFLATE text/html
  </highlight>

  <p>Puede colocar el filtro <strong>CACHE</strong> en cualquier punto que desee dentro de la
  cadena de filtros. En este ejemplo, el contenido se cachea después de que lo analice
  <module>mod_include</module>, pero antes de que lo procese
  <module>mod_deflate</module>:</p>

  <highlight language="config">
# Cache content between mod_include and mod_deflate
CacheQuickHandler off
AddOutputFilterByType INCLUDES;CACHE;DEFLATE text/html
  </highlight>

  <note type="warning"><title>Aviso:</title>Si la posición del filtro
  <strong>CACHE</strong> en la cadena de filtros cambia por cualquier motivo,
  puede que necesite <strong>vaciar su caché</strong> para garantizar que los datos
  servidos sigan siendo coherentes. <module>mod_cache</module> no está en
  posición de garantizar esto por usted.</note>

</section>

<section id="status"><title>Estado y registro de la caché</title>
  <p>Una vez que <module>mod_cache</module> ha decidido si una entidad debe
  servirse o no desde la caché, el motivo detallado de esa decisión se
  escribe en el entorno del subproceso de la petición bajo la
  clave <strong>cache-status</strong>. Este motivo puede registrarse con la
  directiva <directive module="mod_log_config">LogFormat</directive> de la
  siguiente forma:</p>

  <highlight language="config">
    LogFormat "%{cache-status}e ..."
  </highlight>

  <p>Según la decisión de caché tomada, el motivo también se escribe en el
  entorno del subproceso bajo una de las siguientes cuatro claves, según corresponda:</p>

  <dl>
    <dt>cache-hit</dt><dd>La respuesta se sirvió desde la caché.</dd>
    <dt>cache-revalidate</dt><dd>La respuesta estaba obsoleta y se
      revalidó correctamente, sirviéndose después desde la caché.</dd>
    <dt>cache-miss</dt><dd>La respuesta se sirvió desde el servidor remoto.</dd>
    <dt>cache-invalidate</dt><dd>La entidad cacheada se invalidó por una petición
      con un método distinto de GET o HEAD.</dd>
  </dl>

  <p>Esto permite registrar de forma condicional las peticiones cacheadas,
  como en el siguiente ejemplo:</p>

  <highlight language="config">
CustomLog "cached-requests.log" common env=cache-hit
CustomLog "uncached-requests.log" common env=cache-miss
CustomLog "revalidated-requests.log" common env=cache-revalidate
CustomLog "invalidated-requests.log" common env=cache-invalidate
  </highlight>

  <p>Para los autores de módulos, hay disponible un hook llamado <var>cache_status</var>,
  que permite a los módulos responder a los resultados de caché anteriores de forma
  personalizada.</p>
</section>

<directivesynopsis>
<name>CacheEnable</name>
<description>Activa el almacenamiento en caché de las URL indicadas usando un gestor
de almacenamiento concreto</description>
<syntax>CacheEnable <var>cache_type</var> [<var>url-string</var>]</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context>
</contextlist>
<compatibility>Un url-string de '/' aplicado al contenido de proxy directo en 2.2 y
 anteriores.</compatibility>

<usage>
    <p>La directiva <directive>CacheEnable</directive> indica a
    <module>mod_cache</module> que cachee las URL en o por debajo de
    <var>url-string</var>. El gestor de almacenamiento de caché se especifica con el
    argumento <var>cache_type</var>. La directiva <directive>CacheEnable</directive>
    puede colocarse alternativamente dentro de secciones
    <directive type="section" module="core">Location</directive> o
    <directive type="section" module="core">LocationMatch</directive> para indicar
    que el contenido es cacheable.
    El <var>cache_type</var> <code>disk</code> indica a
    <module>mod_cache</module> que use el gestor de almacenamiento basado en disco
    implementado por <module>mod_cache_disk</module>. El <var>cache_type</var>
    <code>socache</code> indica a <module>mod_cache</module> que use el
    gestor de almacenamiento basado en caché de objetos compartida implementado por
    <module>mod_cache_socache</module>.</p>
    <p>En caso de que el espacio de URL se solape entre distintas directivas
    <directive>CacheEnable</directive> (como en el siguiente ejemplo),
    se ejecutará cada gestor de almacenamiento posible hasta encontrar el primero que
    realmente procese la petición. El orden en que se ejecutan los gestores de almacenamiento
    lo determina el orden de las directivas <directive>CacheEnable</directive>
    en el archivo de configuración. Las directivas <directive>CacheEnable</directive>
    dentro de secciones <directive type="section" module="core">Location</directive> o
    <directive type="section" module="core">LocationMatch</directive> se procesan
    antes que las directivas <directive>CacheEnable</directive> definidas globalmente.</p>

    <p>Cuando actúa como proxy directo, <var>url-string</var> debe
    como mínimo empezar por un protocolo para el que deba activarse el almacenamiento en caché.</p>

    <highlight language="config">
# Cache content (normal handler only)
CacheQuickHandler off
&lt;Location "/foo"&gt;
    CacheEnable disk
&lt;/Location&gt;

# Cache regex (normal handler only)
CacheQuickHandler off
&lt;LocationMatch "foo$"&gt;
    CacheEnable disk
&lt;/LocationMatch&gt;

# Cache all but forward proxy url's (normal or quick handler)
CacheEnable  disk  /

# Cache FTP-proxied url's (normal or quick handler)
CacheEnable  disk  ftp://

# Cache forward proxy content from www.example.org (normal or quick handler)
CacheEnable  disk  http://www.example.org/
    </highlight>

    <p>Un nombre de host que empieza por <strong>"*"</strong> coincide con todos los nombres de host que
    tengan ese sufijo. Un nombre de host que empieza por <strong>"."</strong> coincide con todos los
    nombres de host que contengan los componentes de dominio que le siguen.</p>

    <highlight language="config">
# Match www.example.org, and fooexample.org
CacheEnable  disk  http://*example.org/
# Match www.example.org, but not fooexample.org
CacheEnable  disk  http://.example.org/
    </highlight>

    <p> La variable de entorno <code>no-cache</code> puede establecerse para
    desactivar el almacenamiento en caché en un conjunto más preciso de recursos en las versiones
    2.2.12 y posteriores.</p>

</usage>
<seealso><a href="../env.html">Variables de entorno en Apache</a></seealso>
</directivesynopsis>

<directivesynopsis>
<name>CacheDisable</name>
<description>Desactiva el almacenamiento en caché de las URL indicadas</description>
<syntax>CacheDisable <var>url-string</var> | <var>on</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>

<usage>
    <note><p>Esta directiva solo es válida en secciones
    <directive module="core" type="section">Location</directive> y
    <directive module="mod_proxy" type="section">Proxy</directive>
    entre los contextos por directorio. No se admite en secciones
    <directive module="core" type="section">Directory</directive>,
    <directive module="core" type="section">Files</directive> ni
    <directive module="core" type="section">If</directive>.</p></note>

    <p>La directiva <directive>CacheDisable</directive> indica a
    <module>mod_cache</module> que <em>no</em> cachee las URL en o por debajo de
    <var>url-string</var>.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
      CacheDisable /local_files
      </highlight>
    </example>

    <p>Si se usa en una directiva <directive type="section" module="core">Location</directive>,
    la ruta debe especificarse por debajo de la Location, o si se usa la palabra "on",
    se desactivará el almacenamiento en caché para toda la location.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
&lt;Location "/foo"&gt;
    CacheDisable on
&lt;/Location&gt;
      </highlight>
    </example>

    <p>La variable de entorno <code>no-cache</code> puede establecerse para
    desactivar el almacenamiento en caché en un conjunto más preciso de recursos en las versiones
    2.2.12 y posteriores.</p>

</usage>
<seealso><a href="../env.html">Variables de entorno en Apache</a></seealso>
</directivesynopsis>
<directivesynopsis>
<name>CacheMaxExpire</name>
<description>El tiempo máximo en segundos durante el que se cachea un documento</description>
<syntax>CacheMaxExpire <var>seconds</var></syntax>
<default>CacheMaxExpire 86400 (un día)</default>
<contextlist><context>server config</context>
    <context>virtual host</context>
    <context>directory</context>
    <context>.htaccess</context>
</contextlist>

<usage>
    <p>La directiva <directive>CacheMaxExpire</directive> especifica el número máximo de
    segundos durante los que se conservarán los documentos HTTP cacheables sin comprobar el servidor
    de origen. Por tanto, los documentos estarán desactualizados como máximo este número de segundos. Este valor
    máximo se aplica incluso si el documento proporcionaba una fecha de caducidad.</p>

    <highlight language="config">
      CacheMaxExpire 604800
    </highlight>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>CacheMinExpire</name>
<description>El tiempo mínimo en segundos durante el que se cachea un documento</description>
<syntax>CacheMinExpire <var>seconds</var></syntax>
<default>CacheMinExpire 0</default>
<contextlist><context>server config</context>
  <context>virtual host</context>
  <context>directory</context>
  <context>.htaccess</context>
</contextlist>

<usage>
    <p>La directiva <directive>CacheMinExpire</directive> especifica el número mínimo de
    segundos durante los que se conservarán los documentos HTTP cacheables sin comprobar el servidor
    de origen. Solo se usa si el documento no proporcionaba un tiempo de caducidad válido.</p>


    <highlight language="config">
      CacheMinExpire 3600
    </highlight>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>CacheDefaultExpire</name>
<description>La duración por defecto durante la que se cachea un documento cuando no se especifica una fecha de caducidad.</description>
<syntax>CacheDefaultExpire <var>seconds</var></syntax>
<default>CacheDefaultExpire 3600 (una hora)</default>
<contextlist><context>server config</context>
  <context>virtual host</context>
  <context>directory</context>
  <context>.htaccess</context>
</contextlist>

<usage>
    <p>La directiva <directive>CacheDefaultExpire</directive> especifica un tiempo por defecto,
    en segundos, durante el que se cachea un documento si no se proporciona ni fecha de caducidad ni fecha de
    última modificación. El valor especificado con la directiva <directive module="mod_cache">CacheMaxExpire</directive>
    <em>no</em> anula este ajuste.</p>

    <highlight language="config">
      CacheDefaultExpire 86400
    </highlight>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>CacheIgnoreNoLastMod</name>
<description>Ignora el hecho de que una respuesta no tenga cabecera Last
Modified.</description>
<syntax>CacheIgnoreNoLastMod On|Off</syntax>
<default>CacheIgnoreNoLastMod Off</default>
<contextlist><context>server config</context>
  <context>virtual host</context>
  <context>directory</context>
  <context>.htaccess</context>
</contextlist>

<usage>
    <p>Normalmente, los documentos sin fecha de última modificación no se cachean.
    En algunas circunstancias, la fecha de última modificación se elimina (durante el
    procesamiento de <module>mod_include</module>, por ejemplo) o no se proporciona
    en absoluto. La directiva <directive>CacheIgnoreNoLastMod</directive>
    permite especificar que los documentos sin fecha de última modificación
    se consideren para almacenamiento en caché, aunque no tengan fecha de última modificación.
    Si no se proporciona con el documento ni una fecha de última modificación ni una fecha de
    caducidad, se usará el valor especificado por la directiva
    <directive module="mod_cache">CacheDefaultExpire</directive> para
    generar una fecha de caducidad.</p>

    <note>Más concretamente, una respuesta 200 OK solo se cachea si incluye
    al menos una de las cabeceras <code>Last-Modified</code>, <code>ETag</code>
    o <code>Expires</code>, o una directiva <code>Cache-Control: max-age</code>
    o <code>s-maxage</code>. Esta directiva omite ese requisito por completo. Cuando ya está presente
    alguna de esas cabeceras, esta directiva no tiene efecto.</note>

    <highlight language="config">
      CacheIgnoreNoLastMod On
    </highlight>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>CacheIgnoreCacheControl</name>
<description>Ignora la petición de no servir contenido cacheado al cliente</description>
<syntax>CacheIgnoreCacheControl On|Off</syntax>
<default>CacheIgnoreCacheControl Off</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>Normalmente, las peticiones que contienen un valor de cabecera <code>Cache-Control: no-cache</code> o
    Pragma: no-cache no se sirven desde la caché. La directiva
    <directive>CacheIgnoreCacheControl</directive> permite anular este
    comportamiento. <directive>CacheIgnoreCacheControl On</directive>
    indica al servidor que intente servir el recurso desde la caché incluso
    si la petición contiene valores de cabecera no-cache.</p>

    <highlight language="config">
      CacheIgnoreCacheControl On
    </highlight>

    <note type="warning"><title>Aviso:</title>
       Esta directiva permitirá servir desde la caché incluso si el cliente ha
       solicitado que el documento no se sirva desde la caché. Esto podría
       dar lugar a que se sirva contenido obsoleto.
    </note>
</usage>
<seealso><directive module="mod_cache">CacheStorePrivate</directive></seealso>
<seealso><directive module="mod_cache">CacheStoreNoStore</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>CacheIgnoreQueryString</name>
<description>Ignora la cadena de consulta al almacenar en caché</description>
<syntax>CacheIgnoreQueryString On|Off</syntax>
<default>CacheIgnoreQueryString Off</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>Normalmente, las peticiones con parámetros en la cadena de consulta se cachean por separado
    para cada cadena de consulta única. Según RFC 2616/13.9, esto solo se hace
    si se especifica un tiempo de caducidad. La directiva
    <directive>CacheIgnoreQueryString</directive> indica a la caché que
    cachee las peticiones aunque no se especifique un tiempo de caducidad, y que responda con
    una respuesta cacheada incluso si la cadena de consulta difiere. Desde el punto de vista
    del almacenamiento en caché, la petición se trata como si no tuviera cadena de consulta cuando esta
    directiva está activada.</p>

    <highlight language="config">
      CacheIgnoreQueryString On
    </highlight>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>CacheLastModifiedFactor</name>
<description>El factor usado para calcular una fecha de caducidad basada en la
fecha LastModified.</description>
<syntax>CacheLastModifiedFactor <var>float</var></syntax>
<default>CacheLastModifiedFactor 0.1</default>
<contextlist><context>server config</context>
  <context>virtual host</context>
  <context>directory</context>
  <context>.htaccess</context>
</contextlist>

<usage>
    <p>En caso de que un documento no proporcione una fecha de caducidad pero sí
    proporcione una fecha de última modificación, se puede calcular una fecha de caducidad en función
    del tiempo transcurrido desde la última modificación del documento. La directiva
    <directive>CacheLastModifiedFactor</directive> especifica un
    <var>factor</var> que se usará para generar esta fecha de caducidad
    según la siguiente fórmula:

    <code>expiry-period = time-since-last-modified-date * <var>factor</var>
    expiry-date = current-date + expiry-period</code>

    Por ejemplo, si el documento se modificó por última vez hace 10 horas, y el
    <var>factor</var> es 0.1, el periodo de caducidad se establecerá en
    10*0.1 = 1 hora. Si la hora actual fuera las 15:00, la fecha de
    caducidad calculada sería 15:00 + 1 hora = 16:00.

    Si el periodo de caducidad fuera mayor que el establecido por
    <directive module="mod_cache">CacheMaxExpire</directive>, este último tiene
    prioridad.</p>

    <highlight language="config">
      CacheLastModifiedFactor 0.5
    </highlight>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>CacheIgnoreHeaders</name>
<description>No almacena en caché las cabeceras HTTP indicadas.
</description>
<syntax>CacheIgnoreHeaders <var>header-string</var> [<var>header-string</var>] ...</syntax>
<default>CacheIgnoreHeaders None</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>Según RFC 2616, las cabeceras HTTP "hop-by-hop" no se almacenan en
    la caché. Las siguientes cabeceras HTTP son cabeceras "hop-by-hop" y, por tanto,
    no se almacenan en la caché en <em>ningún</em> caso, independientemente del
    valor de <directive>CacheIgnoreHeaders</directive>:</p>

    <ul>
      <li><code>Connection</code></li>
      <li><code>Keep-Alive</code></li>
      <li><code>Proxy-Authenticate</code></li>
      <li><code>Proxy-Authorization</code></li>
      <li><code>TE</code></li>
      <li><code>Trailers</code></li>
      <li><code>Transfer-Encoding</code></li>
      <li><code>Upgrade</code></li>
    </ul>

    <p><directive>CacheIgnoreHeaders</directive> especifica cabeceras HTTP
    adicionales que no deben almacenarse en la caché. Por ejemplo, en algunos casos
    tiene sentido evitar que las cookies se almacenen en la caché.</p>

    <p><directive>CacheIgnoreHeaders</directive> toma una lista separada por espacios
    de cabeceras HTTP que no deben almacenarse en la caché. Si solo no deben almacenarse en la
    caché las cabeceras "hop-by-hop" (el comportamiento compatible con RFC 2616),
    <directive>CacheIgnoreHeaders</directive> puede establecerse a
    <code>None</code>.</p>

    <example><title>Ejemplo 1</title>
    <highlight language="config">
      CacheIgnoreHeaders Set-Cookie
      </highlight>
    </example>

    <example><title>Ejemplo 2</title>
    <highlight language="config">
      CacheIgnoreHeaders None
      </highlight>
    </example>

    <note type="warning"><title>Aviso:</title>
      Si no se almacenan cabeceras como <code>Expires</code>, necesarias para una
      correcta gestión de la caché, debido a un ajuste de
      <directive>CacheIgnoreHeaders</directive>, el comportamiento de
      mod_cache queda sin definir.
    </note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>CacheIgnoreURLSessionIdentifiers</name>
<description>Ignora los identificadores de sesión definidos codificados en la URL al almacenar en caché
</description>
<syntax>CacheIgnoreURLSessionIdentifiers <var>identifier</var> [<var>identifier</var>] ...</syntax>
<default>CacheIgnoreURLSessionIdentifiers None</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>A veces, las aplicaciones codifican el identificador de sesión en la URL, como en los siguientes
    ejemplos:
    </p>
    <ul>
      <li><code>/someapplication/image.gif;jsessionid=123456789</code></li>
      <li><code>/someapplication/image.gif?PHPSESSIONID=12345678</code></li>
    </ul>
    <p>Esto provoca que los recursos cacheables se almacenen por separado para cada sesión, lo que
    a menudo no es deseable. <directive>CacheIgnoreURLSessionIdentifiers</directive> permite
    definir una lista de identificadores que se eliminan de la clave usada para identificar
    una entidad en la caché, de forma que los recursos cacheables no se almacenen por separado para
    cada sesión.
    </p>
    <p><code>CacheIgnoreURLSessionIdentifiers None</code> limpia la lista de identificadores
    ignorados. En cualquier otro caso, cada identificador se añade a la lista.</p>

    <example><title>Ejemplo 1</title>
    <highlight language="config">
      CacheIgnoreURLSessionIdentifiers jsessionid
      </highlight>
    </example>

    <example><title>Ejemplo 2</title>
    <highlight language="config">
      CacheIgnoreURLSessionIdentifiers None
      </highlight>
    </example>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>CacheStoreExpired</name>
<description>Intenta cachear respuestas que el servidor reporta como caducadas</description>
<syntax>CacheStoreExpired On|Off</syntax>
<default>CacheStoreExpired Off</default>
<contextlist><context>server config</context>
  <context>virtual host</context>
  <context>directory</context>
  <context>.htaccess</context>
</contextlist>

<usage>
    <p>Desde httpd 2.2.4, las respuestas que ya han caducado no se
       almacenan en la caché. La directiva <directive>CacheStoreExpired</directive>
       permite anular este comportamiento.
       <directive>CacheStoreExpired</directive> On
       indica al servidor que intente cachear el recurso aunque esté obsoleto.
       Las peticiones posteriores provocarían una petición If-Modified-Since
       al servidor de origen, y la respuesta podría satisfacerse desde la caché
       si el recurso del backend no ha cambiado.</p>

    <highlight language="config">
      CacheStoreExpired On
    </highlight>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>CacheStorePrivate</name>
<description>Intenta cachear respuestas que el servidor ha marcado como privadas</description>
<syntax>CacheStorePrivate On|Off</syntax>
<default>CacheStorePrivate Off</default>
<contextlist><context>server config</context>
  <context>virtual host</context>
  <context>directory</context>
  <context>.htaccess</context>
</contextlist>

<usage>
    <p>Normalmente, las respuestas con valores de cabecera <code>Cache-Control: private</code> no se
       almacenan en la caché. La directiva <directive>CacheStorePrivate</directive>
       permite anular este comportamiento.
       <directive>CacheStorePrivate</directive> On
       indica al servidor que intente cachear el recurso aunque contenga
       valores de cabecera private.</p>

    <highlight language="config">
      CacheStorePrivate On
    </highlight>

    <note type="warning"><title>Aviso:</title>
       Esta directiva permitirá cachear incluso si el servidor remoto ha
       solicitado que el recurso no se cachee. Esta directiva solo es
       recomendable para una caché 'privada'.
    </note>
</usage>
<seealso><directive module="mod_cache">CacheIgnoreCacheControl</directive></seealso>
<seealso><directive module="mod_cache">CacheStoreNoStore</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>CacheStoreNoStore</name>
<description>Intenta cachear peticiones o respuestas que se han marcado como no-store.</description>
<syntax>CacheStoreNoStore On|Off</syntax>
<default>CacheStoreNoStore Off</default>
<contextlist><context>server config</context>
  <context>virtual host</context>
  <context>directory</context>
  <context>.htaccess</context>
</contextlist>

<usage>
    <p>Normalmente, las peticiones o respuestas con valores de cabecera <code>Cache-Control: no-store</code>
       no se almacenan en la caché. La
       directiva <directive>CacheStoreNoStore</directive> permite anular este
       comportamiento. <directive>CacheStoreNoStore</directive> On
       indica al servidor que intente cachear el recurso aunque contenga
       valores de cabecera no-store.</p>

    <highlight language="config">
      CacheStoreNoStore On
    </highlight>

    <note type="warning"><title>Aviso:</title>
       Como se describe en RFC 2616, la directiva no-store está pensada para
       "evitar la publicación o retención involuntaria de información sensible
       (por ejemplo, en cintas de copia de seguridad)." Activar esta opción podría almacenar
       información sensible en la caché. Queda advertido.
    </note>
</usage>
<seealso><directive module="mod_cache">CacheIgnoreCacheControl</directive></seealso>
<seealso><directive module="mod_cache">CacheStorePrivate</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>CacheLock</name>
<description>Activa el bloqueo de "thundering herd".</description>
<syntax>CacheLock <var>on|off</var></syntax>
<default>CacheLock off</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
  <p>La directiva <directive>CacheLock</directive> activa el bloqueo de thundering herd
  para el espacio de URL indicado.</p>

  <p>En una configuración mínima, la siguiente directiva es todo lo que se necesita
  para activar el bloqueo de thundering herd en el directorio de archivos de tiempo de ejecución por defecto.</p>

  <highlight language="config">
# Enable cache lock
CacheLock on
  </highlight>

  <p>Los bloqueos consisten en archivos vacíos que solo existen para las URL obsoletas en curso, por lo que
  consumen significativamente menos recursos que la caché de disco tradicional.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>CacheLockPath</name>
<description>Establece el directorio de ruta de bloqueo.</description>
<syntax>CacheLockPath <var>directory</var></syntax>
<default>CacheLockPath mod_cache-lock</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
  <p>La directiva <directive>CacheLockPath</directive> permite especificar el
  directorio en el que se crean los bloqueos. Si <var>directory</var> no es una ruta
  absoluta, la ubicación especificada será relativa al valor de
  <directive module="core">DefaultRuntimeDir</directive>.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>CacheLockMaxAge</name>
<description>Establece la antigüedad máxima posible de un bloqueo de caché.</description>
<syntax>CacheLockMaxAge <var>integer</var></syntax>
<default>CacheLockMaxAge 5</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
  <p>La directiva <directive>CacheLockMaxAge</directive> especifica la antigüedad
  máxima de cualquier bloqueo de caché.</p>

  <p>Un bloqueo más antiguo que este valor, en segundos, se ignorará, y la siguiente
  petición entrante tendrá la oportunidad de volver a establecer el bloqueo.
  Este mecanismo evita que un cliente lento tarde un tiempo excesivamente largo en actualizar
  una entidad.</p>

</usage>
</directivesynopsis>

<directivesynopsis>
  <name>CacheQuickHandler</name>
  <description>Ejecuta la caché desde el quick handler.</description>
  <syntax>CacheQuickHandler <var>on|off</var></syntax>
  <default>CacheQuickHandler on</default>
  <contextlist><context>server config</context><context>virtual host</context>
  </contextlist>
  <compatibility>Apache HTTP Server 2.3.3 y posteriores</compatibility>

  <usage>
    <p>La directiva <directive>CacheQuickHandler</directive>
    controla la fase en la que se gestiona la caché.</p>

    <p>En la configuración activada por defecto, la caché opera dentro de la fase de quick
    handler. Esta fase corta el camino a la mayor parte del procesamiento del servidor,
    y representa el modo de funcionamiento más eficiente para un servidor típico.
    La caché se <strong>acopla</strong> delante del servidor, y se evita la
    mayor parte del procesamiento del servidor.</p>

    <p>Cuando está desactivada, la caché opera como un handler normal, y está sujeta
    al conjunto completo de fases al gestionar una petición del servidor. Aunque este modo es
    más lento que el predeterminado, permite usar la caché en los casos en los que se
    requiere un procesamiento completo, como cuando el contenido está sujeto a autorización.</p>

    <highlight language="config">
# Run cache as a normal handler
CacheQuickHandler off
    </highlight>

    <p>También es posible, cuando el quick handler está desactivado, que el
    administrador elija la ubicación exacta dentro de la cadena de filtros en la que
    se realiza el almacenamiento en caché, añadiendo el filtro <strong>CACHE</strong> a
    la cadena.</p>

    <highlight language="config">
# Cache content before mod_include and mod_deflate
CacheQuickHandler off
AddOutputFilterByType CACHE;INCLUDES;DEFLATE text/html
    </highlight>

    <p>Si el filtro CACHE se especifica más de una vez, se aplicará la última instancia.</p>

  </usage>
</directivesynopsis>

<directivesynopsis>
<name>CacheHeader</name>
<description>Añade una cabecera X-Cache a la respuesta.</description>
<syntax>CacheHeader <var>on|off</var></syntax>
<default>CacheHeader off</default>
<contextlist><context>server config</context>
    <context>virtual host</context>
    <context>directory</context>
    <context>.htaccess</context>
</contextlist>
<compatibility>Disponible en Apache 2.3.9 y posteriores</compatibility>

<usage>
  <p>Cuando la directiva <directive>CacheHeader</directive>
  está activada, se añadirá a la respuesta una cabecera <strong>X-Cache</strong>
  con el estado de caché de esa respuesta. Si se usa el handler normal, esta
  directiva puede aparecer dentro de una directiva <directive type="section" module="core">Directory</directive>
  o <directive type="section" module="core">Location</directive>. Si se usa el quick
  handler, esta directiva debe aparecer en un contexto de servidor o de virtual host,
  en caso contrario el ajuste se ignorará.</p>

  <dl>
    <dt><strong>HIT</strong></dt><dd>La entidad estaba válida, y se sirvió desde la
    caché.</dd>
    <dt><strong>REVALIDATE</strong></dt><dd>La entidad estaba obsoleta, se
    revalidó correctamente y se sirvió desde la caché.</dd>
    <dt><strong>MISS</strong></dt><dd>La entidad se obtuvo del servidor
      remoto y no se sirvió desde la caché.</dd>
  </dl>

  <highlight language="config">
# Enable the X-Cache header
CacheHeader on
  </highlight>

  <highlight language="config">
    X-Cache: HIT from localhost
  </highlight>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>CacheDetailHeader</name>
<description>Añade una cabecera X-Cache-Detail a la respuesta.</description>
<syntax>CacheDetailHeader <var>on|off</var></syntax>
<default>CacheDetailHeader off</default>
<contextlist><context>server config</context>
      <context>virtual host</context>
      <context>directory</context>
      <context>.htaccess</context>
</contextlist>
<compatibility>Disponible en Apache 2.3.9 y posteriores</compatibility>

<usage>
  <p>Cuando la directiva <directive>CacheDetailHeader</directive>
  está activada, se añadirá a la respuesta una cabecera <strong>X-Cache-Detail</strong>
  que contiene el motivo detallado de una decisión de caché concreta.</p>

  <p>Puede ser útil, durante el desarrollo de servicios RESTful cacheados, disponer de
  información adicional sobre la decisión de caché escrita en las cabeceras de respuesta, para
  confirmar si el cliente y el servicio han usado correctamente
  <code>Cache-Control</code> y otras cabeceras.</p>

  <p>Si se usa el handler normal, esta directiva puede aparecer dentro de una directiva
  <directive type="section" module="core">Directory</directive> o
  <directive type="section" module="core">Location</directive>. Si se usa el quick handler,
  esta directiva debe aparecer en un contexto de servidor o de virtual host, en caso contrario
  el ajuste se ignorará.</p>

  <highlight language="config">
# Enable the X-Cache-Detail header
CacheDetailHeader on
  </highlight>

  <example>
    X-Cache-Detail: "conditional cache hit: entity refreshed" from localhost<br />
  </example>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>CacheKeyBaseURL</name>
<description>Anula la URL base de las claves de caché del proxy inverso.</description>
<syntax>CacheKeyBaseURL <var>URL</var></syntax>
<contextlist><context>server config</context>
<context>virtual host</context>
</contextlist>
<compatibility>Disponible en Apache 2.3.9 y posteriores</compatibility>

<usage>
  <p>Cuando se especifica la directiva <directive>CacheKeyBaseURL</directive>,
  la URL proporcionada se usará como URL base para calcular
  la URL de las claves de caché en la configuración de proxy inverso. Si no se especifica,
  se usa el esquema, el nombre de host y el puerto del virtual host actual para construir
  la clave de caché. Cuando hay presente un clúster de máquinas, y todas las entradas cacheadas
  deben almacenarse bajo la misma clave de caché, se puede especificar una nueva URL base
  con esta directiva.</p>

  <highlight language="config">
# Override the base URL of the cache key.
CacheKeyBaseURL http://www.example.com/
  </highlight>

  <note type="warning">Tenga cuidado al establecer esta directiva. Si dos virtual hosts
  distintos reciben accidentalmente la misma URL base, las entradas de un virtual host
  se servirán al otro.</note>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>CacheStaleOnError</name>
<description>Sirve contenido obsoleto en lugar de respuestas 5xx.</description>
<syntax>CacheStaleOnError <var>on|off</var></syntax>
<default>CacheStaleOnError on</default>
<contextlist><context>server config</context>
    <context>virtual host</context>
    <context>directory</context>
    <context>.htaccess</context>
</contextlist>
<compatibility>Disponible en Apache 2.3.9 y posteriores</compatibility>

<usage>
  <p>Cuando la directiva <directive>CacheStaleOnError</directive>
  está activada, y hay disponibles datos obsoletos en la caché, la caché responderá a las
  respuestas 5xx del backend devolviendo los datos obsoletos en lugar de
  la respuesta 5xx. Aunque se respetarán las cabeceras Cache-Control enviadas por los clientes,
  y las respuestas 5xx originales se devolverán al cliente si las solicita, la respuesta 5xx así
  devuelta al cliente no invalidará el contenido de la caché.</p>

  <highlight language="config">
# Serve stale data on error.
CacheStaleOnError on
  </highlight>

</usage>
</directivesynopsis>

</modulesynopsis>
