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

<modulesynopsis metafile="mod_rewrite.xml.meta">

<name>mod_rewrite</name>

<description>Proporciona un motor de reescritura basado en reglas para
reescribir las URLs solicitadas al vuelo</description>

<status>Extension</status>
<sourcefile>mod_rewrite.c</sourcefile>
<identifier>rewrite_module</identifier>

<summary>
	<p>El módulo <module>mod_rewrite</module> usa un motor de reescritura
      basado en reglas, apoyado en un analizador de expresiones regulares PCRE, para reescribir
      las URLs solicitadas al vuelo. Por defecto, <module>mod_rewrite</module> mapea
      una URL a una ruta del sistema de archivos. Sin embargo, también puede usarse para
      redirigir una URL a otra URL, o para invocar una solicitud de proxy interna.</p>

      <p>Proporciona una forma flexible y potente de manipular URLs usando un
      número ilimitado de reglas. Cada regla puede tener un
      número ilimitado de condiciones de regla asociadas, que le permiten reescribir URLs
      basándose en <a href="#rewritecond">variables del servidor</a> (incluyendo cabeceras
      HTTP, detalles de la conexión y marcas de tiempo), variables de entorno,
      u otras propiedades de la solicitud. Las reglas pueden operar sobre la
      <a href="directive-dict.html#Syntax">ruta de la URL</a> (incluyendo cualquier
      <a href="core.html#acceptpathinfo">información final de nombre de ruta</a>)
      y también pueden alterar la
      <a href="../expr.html#vars">cadena de consulta</a>.</p>

      <p>Una regla de reescritura
      puede invocarse en los archivos de configuración del servidor, o en contexto
      <glossary ref="perdirectory">per-directorio</glossary>. La cadena de sustitución
      de una regla de reescritura puede incluir una cadena de consulta, y una regla puede dar lugar a
      un subprocesamiento interno, una redirección externa de la solicitud, o
      un tráfico de proxy interno.</p>

      <p>Encontrará más detalles, discusión y ejemplos en la
      <a href="../rewrite/">Guía de mod_rewrite</a>.</p>
</summary>
<seealso><a href="rewrite/index.html">Guía de mod_rewrite</a></seealso>

<section id="logging"><title>Registro</title>

    <p><module>mod_rewrite</module> ofrece un registro detallado de sus acciones
    en los niveles de registro de <code>trace1</code> a <code>trace8</code>. El
    nivel de registro puede establecerse específicamente para <module>mod_rewrite</module>
    usando la directiva <directive module="core">LogLevel</directive>: hasta el
    nivel <code>debug</code>, no se registra ninguna acción, mientras que <code>trace8</code>
    significa que prácticamente todas las acciones se registran.</p>

    <note>
      ¡Usar un nivel de registro de traza alto para <module>mod_rewrite</module>
      ralentizará su Apache HTTP Server drásticamente! ¡Use un nivel de registro
      superior a <code>trace2</code> solo para depuración!
    </note>

        <example><title>Ejemplo</title>
            <highlight language="config">
LogLevel alert rewrite:trace3
            </highlight>
        </example>

    <note><title>RewriteLog</title>
      <p>Quienes estén familiarizados con versiones anteriores de
      <module>mod_rewrite</module> sin duda buscarán las directivas
      <code>RewriteLog</code> y <code>RewriteLogLevel</code>. Desde el
      lanzamiento de httpd 2.4, estas directivas se han sustituido por la
      configuración de registro por módulo que proporciona
      <directive module="core">LogLevel</directive>.
      </p>

      <p>Para obtener solo los mensajes de registro específicos de
      <module>mod_rewrite</module>, canalice el archivo de registro a través de grep:</p>

        <example>
            <highlight language="sh">
tail -f error_log|fgrep '[rewrite:'
            </highlight>
        </example>
    </note>

</section>

<directivesynopsis>
<name>RewriteEngine</name>
<description>Activa o desactiva el motor de reescritura en tiempo de ejecución</description>
<syntax>RewriteEngine on|off</syntax>
<default>RewriteEngine off</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>

      <p>La directiva <directive>RewriteEngine</directive> activa o
      desactiva el motor de reescritura en tiempo de ejecución. Si se establece en
      <code>off</code>, este módulo no hace ningún procesamiento en tiempo de
      ejecución. Ni siquiera actualiza las variables de entorno
      <code>SCRIPT_URx</code>.</p>

      <p>Use esta directiva para desactivar las reglas en un contexto concreto,
      en lugar de comentar todas las directivas
      <directive module="mod_rewrite">RewriteRule</directive>.</p>

      <p>Tenga en cuenta que las configuraciones de reescritura no se
      heredan en los hosts virtuales. Esto significa que necesita una
      directiva <code>RewriteEngine on</code> en cada host virtual
      en el que quiera usar reglas de reescritura.</p>

      <p>Las directivas <directive module="mod_rewrite">RewriteMap</directive>
      de tipo <code>prg</code>
      no se inician durante la inicialización del servidor si se definen en un
      contexto que no tenga <directive>RewriteEngine</directive> establecida en
      <code>on</code></p>
</usage>

</directivesynopsis>

<directivesynopsis>
<name>RewriteOptions</name>
<description>Establece algunas opciones especiales para el motor de reescritura</description>
<syntax>RewriteOptions <var>Options</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>FileInfo</override>
<usage>

      <p>La directiva <directive>RewriteOptions</directive> establece algunas
      opciones especiales para la configuración actual por servidor o por
      directorio. La cadena <em>Option</em> actualmente solo puede ser
      una de las siguientes:</p>

      <dl>
      <dt><code>Inherit</code></dt>
      <dd>

      <p>Esto fuerza a la configuración actual a heredar la
      configuración del padre. En contexto per-virtual-server,
      esto significa que se heredan los mapas, condiciones y reglas del
      servidor principal. En contexto per-directorio esto significa
      que se heredan las condiciones y reglas de la configuración
      <code>.htaccess</code> del directorio padre o de las secciones
      <directive type="section" module="core">Directory</directive>.
      Las reglas heredadas se copian virtualmente
      en la sección donde se usa esta directiva. Si se usa
      combinada con reglas locales, las reglas heredadas se copian detrás
      de las reglas locales. La posición de esta directiva -por debajo o por encima
      de las reglas locales- no influye en este comportamiento. Si las
      reglas locales forzaron la detención de la reescritura, las reglas heredadas
      no se procesarán.</p>

      <note type="warning">
      Las reglas heredadas del ámbito padre se aplican
      <strong>después</strong> de las reglas especificadas en el ámbito hijo.
      </note>
      </dd>

      <dt><code>InheritBefore</code></dt>
      <dd>
      <p>Como <code>Inherit</code> arriba, pero las reglas del ámbito padre
      se aplican <strong>antes</strong> de las reglas especificadas en el ámbito hijo.<br />
      Disponible en Apache HTTP Server 2.3.10 y posteriores.</p>
      </dd>

      <dt><code>InheritDown</code></dt>
      <dd>

      <p>Si esta opción está activada, todas las configuraciones hijas heredarán
      la configuración de la configuración actual. Es equivalente a
      especificar <code>RewriteOptions Inherit</code> en todas las configuraciones
      hijas. Vea la opción <code>Inherit</code> para más detalles
      sobre cómo se gestionan las relaciones padre-hijo.<br />
      Disponible en Apache HTTP Server 2.4.8 y posteriores.</p>
      </dd>

      <dt><code>InheritDownBefore</code></dt>
      <dd>

      <p>Como <code>InheritDown</code> arriba, pero las reglas del ámbito
      actual se aplican <strong>antes</strong> de las reglas especificadas en el
      ámbito de cualquier hijo.<br />
      Disponible en Apache HTTP Server 2.4.8 y posteriores.</p>
      </dd>

      <dt><code>IgnoreInherit</code></dt>
      <dd>

      <p>Esta opción fuerza a las configuraciones actual e hijas a ignorar
      todas las reglas que se heredarían de un padre que especifique
      <code>InheritDown</code> o <code>InheritDownBefore</code>.<br />
      Disponible en Apache HTTP Server 2.4.8 y posteriores.</p>
      </dd>

      <dt><code>AllowNoSlash</code></dt>
      <dd>
      <p>Por defecto, <module>mod_rewrite</module> ignorará las URLs que mapeen a un
      directorio en disco pero carezcan de barra final, en la expectativa de que
      el módulo <module>mod_dir</module> hará que el cliente reciba una redirección a
      la URL canónica con barra final.</p>

      <p>Cuando la directiva <directive module="mod_dir">DirectorySlash</directive>
      se establece en off, se puede activar la opción <code>AllowNoSlash</code> para garantizar
      que las reglas de reescritura ya no se ignoren. Esta opción hace posible
      aplicar reglas de reescritura dentro de archivos .htaccess que coincidan con el directorio sin
      barra final, si así se desea.<br />
      Disponible en Apache HTTP Server 2.4.0 y posteriores.</p>
      </dd>

      <dt><code>AllowAnyURI</code></dt>
      <dd>

      <p>Cuando <directive module="mod_rewrite">RewriteRule</directive>
      se usa en contexto <code>VirtualHost</code> o de servidor con
      la versión 2.2.22 o posterior de httpd, <module>mod_rewrite</module>
      solo procesará las reglas de reescritura si la URI de la solicitud es una
      <a href="directive-dict.html#Syntax">ruta de la URL</a>. Esto evita
      algunos problemas de seguridad en los que ciertas reglas podrían permitir
      expansiones de patrón "sorprendentes" (vea
      <a href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3368">CVE-2011-3368</a>
      y
      <a href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-4317">CVE-2011-4317</a>).
      Para eliminar la restricción de comparar con una ruta de URL, se
      puede activar la opción <code>AllowAnyURI</code>, y
      <module>mod_rewrite</module> aplicará el conjunto de reglas a cualquier
      cadena de URI de solicitud, independientemente de si esa cadena coincide con
      la gramática de ruta de URL que exige la especificación HTTP.<br />
      Disponible en Apache HTTP Server 2.4.3 y posteriores.</p>

      <note type="warning">
      <title>Advertencia de seguridad</title>

      <p>Activar esta opción hará que el servidor sea vulnerable a
      problemas de seguridad si se usa con reglas de reescritura escritas sin
      el cuidado necesario. Se recomienda <strong>encarecidamente</strong>
      no usar esta opción. En particular, tenga cuidado con las
      cadenas de entrada que contengan el carácter '<code>@</code>', que podría
      cambiar la interpretación de la URI transformada, según
      los nombres CVE anteriores.</p>
      </note>
      </dd>

      <dt><code>MergeBase</code></dt>
      <dd>

      <p>Con esta opción, el valor de <directive module="mod_rewrite"
      >RewriteBase</directive> se copia desde donde se define explícitamente
      a cualquier subdirectorio o sub-location que no defina su propia
      <directive module="mod_rewrite">RewriteBase</directive>. Este era el
      comportamiento por defecto entre la 2.4.0 y la 2.4.3, y la bandera para restaurarlo está
      disponible en Apache HTTP Server 2.4.4 y posteriores.</p>
      </dd>

      <dt><code>IgnoreContextInfo</code></dt>
      <dd>

      <p>Cuando se hace una sustitución relativa
         en contexto de directorio (htaccess) y no se ha establecido <directive module="mod_rewrite"
         >RewriteBase</directive>, este módulo usa información de contexto extendida
         de la URL y del sistema de archivos para volver a convertir la sustitución
         relativa en una URL. Módulos como
         <module>mod_userdir</module> y <module>mod_alias</module>
         proporcionan esta información de contexto extendida. Disponible en 2.4.16 y posteriores.</p>
      </dd>


      <dt><code>LegacyPrefixDocRoot</code></dt>
      <dd>

      <p>Antes de la 2.4.26, si una sustitución era una URL absoluta que coincidía
         con el host virtual actual, la URL podía reducirse primero a una ruta de URL
         y luego reducirse a una ruta local. Dado que la URL puede reducirse
         a una ruta local, la ruta debería llevar como prefijo la raíz de documentos.
         Esto evita que se acceda a un archivo como /tmp/myfile cuando se hace una
         solicitud a http://host/file/myfile con la siguiente
         <directive module="mod_rewrite">RewriteRule</directive>.</p>
      <highlight language="config">
          RewriteRule /file/(.*) http://localhost/tmp/$1
      </highlight>
      <p>Esta opción permite usar el comportamiento antiguo, en el que la raíz de
         documentos no se añade como prefijo a una ruta local que se redujo a partir de una
         URL. Disponible en 2.4.26 y posteriores.</p>
      </dd>

      </dl>
</usage>

</directivesynopsis>

<directivesynopsis>
<name>RewriteMap</name>
<description>Define una función de mapeo para la búsqueda de claves</description>
<syntax>RewriteMap <em>MapName</em> <em>MapType</em>:<em>MapSource</em>
    [<em>MapTypeOptions</em>]
</syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>
<compatibility>El tercer parámetro, MapTypeOptions, solo está disponible en Apache httpd
2.4.29 y posteriores.</compatibility>

<usage>
      <p>La directiva <directive>RewriteMap</directive> define un
      <em>mapa de reescritura</em> que las funciones de mapeo pueden usar dentro de
      las cadenas de sustitución de una regla para
      insertar/sustituir campos mediante una búsqueda por clave. El origen de
      esta búsqueda puede ser de varios tipos.</p>

      <p>El <a id="mapfunc" name="mapfunc"><em>MapName</em></a> es
      el nombre del mapa y se usará para especificar una
      función de mapeo para las cadenas de sustitución de una regla de
      reescritura mediante una de las siguientes construcciones:</p>

      <p class="indent">
        <strong><code>${</code> <em>MapName</em> <code>:</code>
        <em>LookupKey</em> <code>}</code><br />
         <code>${</code> <em>MapName</em> <code>:</code>
        <em>LookupKey</em> <code>|</code> <em>DefaultValue</em>
        <code>}</code></strong>
      </p>

      <p>Cuando aparece una construcción de este tipo, se consulta el mapa
      <em>MapName</em> y se busca la clave <em>LookupKey</em>. Si se
      encuentra la clave, la construcción de la función de mapeo se sustituye por
      <em>SubstValue</em>. Si la clave no se encuentra, se sustituye por
      <em>DefaultValue</em> o por la cadena vacía si no se especificó
      ningún <em>DefaultValue</em>. Los valores vacíos se comportan como si la clave
      estuviera ausente, por lo que no es posible distinguir entre claves con
      valor vacío y claves ausentes.</p>

      <p>Por ejemplo, podría definir una
      <directive>RewriteMap</directive> así:</p>

      <highlight language="config">
RewriteMap examplemap "txt:/path/to/file/map.txt"
      </highlight>

      <p>Entonces podría usar este mapa en una
      <directive module="mod_rewrite">RewriteRule</directive> así:</p>

      <highlight language="config">
RewriteRule "^/ex/(.*)" "${examplemap:$1}"
      </highlight>

      <p>El significado del argumento <em>MapTypeOptions</em> depende del
      <em>MapType</em> concreto. Vea
      <a href="../rewrite/rewritemap.html">Uso de RewriteMap</a> para
      más información.</p>

      <p>Pueden usarse las siguientes combinaciones de <em>MapType</em> y
      <em>MapSource</em>:</p>

    <dl>

    <dt>txt</dt>
        <dd>Un archivo de texto plano que contiene pares clave-valor separados por
        espacios, uno por línea. (<a href="../rewrite/rewritemap.html#txt">Detalles ...</a>)</dd>

    <dt>rnd</dt>
        <dd>Selecciona aleatoriamente una entrada de un archivo de texto plano (<a href="../rewrite/rewritemap.html#rnd">Detalles ...</a>)</dd>

    <dt>dbm</dt>
        <dd>Busca una entrada en un archivo dbm que contiene pares de nombre y
        valor. El hash se construye a partir de un archivo de texto plano usando
        la utilidad <code><a href="../programs/httxt2dbm.html">httxt2dbm</a></code>.
        (<a href="../rewrite/rewritemap.html#dbm">Detalles ...</a>)</dd>

    <dt>int</dt>
        <dd>Una de las cuatro funciones internas disponibles que proporciona
        <code>RewriteMap</code>: toupper, tolower, escape o
        unescape. (<a href="../rewrite/rewritemap.html#int">Detalles ...</a>)</dd>

    <dt>prg</dt>
        <dd>Llama a un programa o script externo para procesar la
        reescritura. (<a href="../rewrite/rewritemap.html#prg">Detalles ...</a>)</dd>

    <dt>dbd o fastdbd</dt>
        <dd>Una instrucción SQL SELECT que se ejecuta para buscar el
        destino de la reescritura. (<a href="../rewrite/rewritemap.html#dbd">Detalles ...</a>)</dd>
    </dl>

    <p>Encontrará más detalles, y numerosos ejemplos, en la <a
    href="../rewrite/rewritemap.html">guía de RewriteMap</a></p>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>RewriteBase</name>
<description>Establece la URL base para las reescrituras por directorio</description>
<syntax>RewriteBase <em>URL-path</em></syntax>
<default>None</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>FileInfo</override>

<usage>
      <p>La directiva <directive>RewriteBase</directive> especifica el
      prefijo de URL que se usará con las directivas
      <directive module="mod_rewrite">RewriteRule</directive>
      <glossary ref="perdirectory">per-directorio</glossary> que sustituyen
      una ruta relativa.</p>
      <p>Esta directiva es <em>obligatoria</em> cuando se usa una ruta relativa
      en una sustitución en contexto <glossary ref="perdirectory">per-directorio</glossary>, a menos que se cumpla
      alguna de las siguientes condiciones:</p>
      <ul>
          <li>La solicitud original, y la sustitución, están por debajo de la
               <directive module="core">DocumentRoot</directive>
               (y no son alcanzables por otros medios, como
               <directive module="mod_alias">Alias</directive>).</li>
          <li>La ruta de directorio a la que se aplica la RewriteRule,
               con la sustitución relativa añadida como sufijo, también es válida
               como ruta de URL en el servidor (esto es poco frecuente).</li>
          <li>En Apache HTTP Server 2.4.16 y posteriores, esta directiva puede
                omitirse cuando la solicitud se mapea mediante
                <directive module="mod_alias">Alias</directive>
                o <module>mod_userdir</module>.</li>
      </ul>

</usage>

</directivesynopsis>

<directivesynopsis>
<name>RewriteCond</name>
<description>Define una condición bajo la cual se realizará la reescritura
</description>
<syntax> RewriteCond
      <em>TestString</em> [!]<em>CondPattern</em> [<em>flags</em>]</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>
      <p>La directiva <directive>RewriteCond</directive> define una
      condición de regla. Una o más <directive>RewriteCond</directive>
      pueden preceder a una directiva <directive module="mod_rewrite">RewriteRule</directive>.
      La siguiente regla solo se usa entonces si el
      estado actual de la URI coincide con su patrón, <strong
      >y</strong> si se cumplen estas condiciones.</p>

      <p>Si el <em>CondPattern</em> va precedido de un <code>!</code>, la
      condición se considera verdadera solo si el
      <em>CondPattern</em> no coincide.</p>

      <!-- ============================================================ -->
      <!-- TestString                                                    -->
      <!-- ============================================================ -->

      <p><a id="rewritecond-teststring" name="rewritecond-teststring"
      ></a><strong>TestString</strong></p>

      <p><em>TestString</em> es una cadena que puede contener las
      siguientes construcciones expandidas además de texto plano:</p>

      <!-- Backreferences -->

      <p><a id="rewritecond-backreferences" name="rewritecond-backreferences"
      ></a><strong>Referencias inversas</strong></p>

      <dl>
        <dt><strong><code>$N</code></strong> &mdash; referencias inversas de RewriteRule</dt>
        <dd>Referencias inversas de la forma <code>$N</code>
          (0 &lt;= N &lt;= 9). $1 a $9 dan acceso a las partes agrupadas
          (entre paréntesis) del patrón, procedentes de la
          <code>RewriteRule</code> sujeta al conjunto actual de
          condiciones <code>RewriteCond</code>. $0 da
          acceso a la cadena completa que coincide con ese patrón.</dd>

        <dt><strong><code>%N</code></strong> &mdash; referencias inversas de RewriteCond</dt>
        <dd>Referencias inversas de la forma <code>%N</code>
          (0 &lt;= N &lt;= 9). %1 a %9 dan acceso a las partes agrupadas
          (de nuevo, entre paréntesis) del patrón, procedentes de la última
          <code>RewriteCond</code> que coincidió en el conjunto actual
          de condiciones. %0 da acceso a la cadena completa que coincide con
          ese patrón.</dd>
      </dl>

      <note>Las referencias inversas solo se definen si el patrón
      coincide. Por tanto, si el patrón va precedido de
      <code>!</code>, nunca se define ninguna referencia inversa.
      Vea <a href="../rewrite/tech.html#InternalRuleset">cómo se
      aplica el conjunto de reglas</a> para más detalles sobre el orden en el que
      se comparan los patrones y se rellenan las referencias inversas.</note>

      <!-- RewriteMap Expansions -->

      <p><a id="rewritecond-mapexpansions" name="rewritecond-mapexpansions"
      ></a><strong>Expansiones de RewriteMap</strong></p>

      <p>Son expansiones de la forma <strong><code
      >${mapname:key|default}</code></strong>.
      Vea <a href="#mapfunc">la documentación de
      RewriteMap</a> para más detalles.</p>

      <!-- Server and CGI Variables -->

      <p><a id="rewritecond-servervars" name="rewritecond-servervars"
      ></a><strong>Variables del servidor y de CGI</strong></p>

      <p>Son variables de la forma
        <strong><code>%{</code> <em>NAME_OF_VARIABLE</em>
        <code>}</code></strong>
      donde <em>NAME_OF_VARIABLE</em> puede ser una cadena tomada
      de la siguiente lista:</p>

          <table>
          <columnspec><column width=".3"/><column width=".3"/>
           <column width=".3"/></columnspec>
            <tr>
              <th>Cabeceras HTTP:</th> <th>conexión y solicitud:</th> <th></th>
            </tr>

            <tr>
              <td>
                 HTTP_ACCEPT<br />
                 HTTP_COOKIE<br />
                 HTTP_FORWARDED<br />
                 HTTP_HOST<br />
                 HTTP_PROXY_CONNECTION<br />
                 HTTP_REFERER<br />
                 HTTP_USER_AGENT<br />
              </td>

              <td>
                 AUTH_TYPE<br />
                 CONN_REMOTE_ADDR<br />
                 CONTEXT_PREFIX<br />
                 CONTEXT_DOCUMENT_ROOT<br />
                 IPV6<br />
                 <glossary ref="pathinfo">PATH_INFO</glossary><br />
                 QUERY_STRING<br />
                 REMOTE_ADDR<br />
                 REMOTE_HOST<br />
                 REMOTE_IDENT<br />
                 REMOTE_PORT<br />
                 REMOTE_USER<br />
                 REQUEST_METHOD<br />
                 SCRIPT_FILENAME<br />
              </td>

              <td></td>
            </tr>

            <tr>
              <th>internos del servidor:</th> <th>fecha y hora:</th> <th>especiales:</th>
            </tr>

            <tr>
              <td>
                 DOCUMENT_ROOT<br />
                 SCRIPT_GROUP<br />
                 SCRIPT_USER<br />
                 SERVER_ADDR<br />
                 SERVER_ADMIN<br />
                 SERVER_NAME<br />
                 SERVER_PORT<br />
                 SERVER_PROTOCOL<br />
                 SERVER_SOFTWARE<br />
              </td>

              <td>
                 TIME_YEAR<br />
                 TIME_MON<br />
                 TIME_DAY<br />
                 TIME_HOUR<br />
                 TIME_MIN<br />
                 TIME_SEC<br />
                 TIME_WDAY<br />
                 TIME<br />
              </td>

              <td>
                 API_VERSION<br />
                 CONN_REMOTE_ADDR<br />
                 HTTPS<br />
                 IS_SUBREQ<br />
                 REMOTE_ADDR<br />
                 REQUEST_FILENAME<br />
                 REQUEST_SCHEME<br />
                 REQUEST_URI<br />
                 THE_REQUEST<br />
              </td>
            </tr>
          </table>

                <p>Todas estas variables
                corresponden a las cabeceras MIME HTTP del mismo nombre, a
                variables C del Apache HTTP Server o a
                campos <code>struct tm</code> del sistema Unix.
                La mayoría están documentadas en el
                <a href="../expr.html#vars">documento de expresiones</a>, en el
                <a href="../env.html">documento de variables de entorno</a>,
                o en la especificación CGI (<rfc>3875</rfc>).</p>

                <p>SERVER_NAME y SERVER_PORT dependen, respectivamente, de los valores de
                <directive module="core">UseCanonicalName</directive> y
                <directive module="core">UseCanonicalPhysicalPort</directive>.</p>

                <p>Las variables SCRIPT_FILENAME y REQUEST_FILENAME
                contienen el mismo valor: el valor del
                campo <code>filename</code> de la estructura interna
                <code>request_rec</code> del Apache HTTP Server.
                El primer nombre es el nombre de variable CGI comúnmente conocido,
                mientras que el segundo es la contrapartida apropiada de
                REQUEST_URI (que contiene el valor del
                campo <code>uri</code> de <code>request_rec</code>).</p>

                <p>Si se produjo una sustitución y la reescritura continúa,
                el valor de ambas variables se actualizará en consecuencia.</p>

                <p>Si se usa en contexto per-servidor (<em>es decir</em>, antes de que
                la solicitud se mapee al sistema de archivos), SCRIPT_FILENAME y
                REQUEST_FILENAME no pueden contener la ruta completa del sistema de
                archivos local, ya que la ruta es desconocida en esta etapa del
                procesamiento. En ese caso, ambas variables contendrán inicialmente el valor de
                REQUEST_URI. Para obtener la ruta completa del sistema de archivos
                local de la solicitud en contexto per-servidor, use una búsqueda anticipada
                basada en URL, <code>%{LA-U:REQUEST_FILENAME}</code>, para determinar
                el valor final de REQUEST_FILENAME.</p>

                <p>A continuación se incluyen las que son especiales para
                <module>mod_rewrite</module>.</p>
                <dl>
                  <dt><code>API_VERSION</code></dt>

                  <dd>Esta es la versión de la API de módulos de Apache httpd
                  (la interfaz interna entre el servidor y el
                  módulo) en la compilación actual de httpd, tal como se define en
                  include/ap_mmn.h. La versión de la API de módulos
                  corresponde a la versión de Apache httpd en uso (en
                  la versión de publicación de Apache httpd 1.3.14, por
                  ejemplo, es 19990320:10), pero interesa principalmente
                  a los autores de módulos.</dd>

                  <dt><code>CONN_REMOTE_ADDR</code></dt>

                  <dd>Desde la 2.4.8: la dirección IP del extremo remoto de la conexión (vea el
                  módulo <module>mod_remoteip</module>).</dd>

                  <dt><code>HTTPS</code></dt>

                  <dd>Contendrá el texto "on" si la conexión usa
                  SSL/TLS, u "off" en caso contrario. (Esta variable
                  puede usarse de forma segura independientemente de si
                  <module>mod_ssl</module> está cargado o no).</dd>

                  <dt><code>IS_SUBREQ</code></dt>

                  <dd>Contendrá el texto "true" si la solicitud
                  que se está procesando en ese momento es una subsolicitud,
                  o "false" en caso contrario. Las subsolicitudes pueden generarlas
                  módulos que necesitan resolver archivos o URIs
                  adicionales para completar sus tareas.</dd>

                  <dt><code>REMOTE_ADDR</code></dt>

                  <dd>La dirección IP del host remoto (vea el
                  módulo <module>mod_remoteip</module>).</dd>

                  <dt><code>REQUEST_FILENAME</code></dt>

                  <dd>La ruta completa del sistema de archivos local al archivo o
                  script que coincide con la solicitud, si el servidor ya la ha
                  determinado en el momento en que se referencia
                  <code>REQUEST_FILENAME</code>. En caso contrario, como
                  sucede en contexto de host virtual, es el mismo
                  valor que <code>REQUEST_URI</code>. Según el valor de
                  <directive module="core">AcceptPathInfo</directive>, el
                  servidor puede haber usado solo algunos componentes iniciales de
                  <code>REQUEST_URI</code> para mapear la solicitud a un archivo.
                  </dd>

                  <dt><code>REQUEST_SCHEME</code></dt>

                  <dd>Contendrá el esquema de la solicitud (normalmente
                  "http" o "https"). Este valor puede verse influido por
                  <directive module="core">ServerName</directive>.</dd>

                  <dt><code>REQUEST_URI</code></dt>

                  <dd>El componente de ruta de la URI solicitada,
                  como "/index.html". Esto excluye notablemente la
                  cadena de consulta, disponible como su propia variable
                  llamada <code>QUERY_STRING</code>. El valor devuelto para
                  <code>REQUEST_URI</code>
                  ya está decodificado (%-decoded); para volver a codificarlo, páselo por
                  la <a href="#mapfunc">función de mapeo</a> "escape".
                  Tenga en cuenta que esta variable de servidor difiere de la variable
                  de entorno CGI del mismo nombre: en un contexto CGI,
                  <code>REQUEST_URI</code> contiene la URI original completa
                  de la línea de solicitud, incluida la cadena de consulta. Vea
                  la directiva <directive module="core">CGIVar</directive>
                  para más detalles.
                  </dd>

                  <dt><code>THE_REQUEST</code></dt>

                  <dd>La línea de solicitud HTTP completa enviada por el
                  navegador al servidor (por ejemplo, "<code>GET
                  /index.html HTTP/1.1</code>"). Esto no
                  incluye ninguna cabecera adicional enviada por el
                  navegador. Este valor no se ha desescapado
                  (decodificado), a diferencia de la mayoría de las demás variables anteriores.</dd>

                </dl>

      <!-- Prefixed Variable Lookups -->

      <p><a id="rewritecond-prefixed" name="rewritecond-prefixed"
      ></a><strong>Búsquedas de variables con prefijo</strong></p>

      <p>Además de las variables del servidor anteriores, la sintaxis
      <code>%{<em>PREFIX</em>:<em>name</em>}</code> da
      acceso a fuentes adicionales:</p>

      <dl>
        <dt><strong><code>%{ENV:variable}</code></strong></dt>
        <dd>Donde <em>variable</em> puede ser
        cualquier variable de entorno. Se busca mediante las estructuras internas
        de Apache httpd y, si no se encuentra ahí, mediante
        <code>getenv()</code> desde el proceso del servidor Apache httpd.</dd>

        <dt><strong><code>%{SSL:variable}</code></strong></dt>
        <dd>Donde <em>variable</em> es el
        nombre de una <a href="mod_ssl.html#envvars">variable de entorno
        SSL</a>. Esto puede usarse tanto si <module>mod_ssl</module>
        está cargado como si no, pero si no lo está siempre se expandirá a
        la cadena vacía. Ejemplo:
        <code>%{SSL:SSL_CIPHER_USEKEYSIZE}</code> puede expandirse a
        <code>128</code>. Estas variables están disponibles incluso sin
        establecer la opción <code>StdEnvVars</code> de la
        directiva <directive module="mod_ssl">SSLOptions</directive>.</dd>

        <dt><strong><code>%{HTTP:header}</code></strong></dt>
        <dd>Donde <em>header</em> puede ser
        cualquier nombre de cabecera MIME HTTP. Esto siempre puede usarse para obtener el
        valor de una cabecera enviada en la solicitud HTTP.
        Ejemplo: <code>%{HTTP:Proxy-Connection}</code> es
        el valor de la cabecera HTTP
        ``<code>Proxy-Connection:</code>''.
        <p>Si se usa una cabecera HTTP en una condición, esa cabecera se añade a
        la cabecera Vary de la respuesta en caso de que la condición se evalúe
        como verdadera para la solicitud. <strong>No</strong> se añade si la
        condición se evalúa como falsa para la solicitud. Añadir la cabecera HTTP
        a la cabecera Vary de la respuesta es necesario para un almacenamiento en caché correcto.</p>
        <p>Debe tenerse en cuenta que las condiciones siguen una lógica de cortocircuito
        cuando se usa la bandera '<strong><code>ornext|OR</code></strong>', de
        modo que es posible que determinadas condiciones no lleguen a evaluarse.</p></dd>
      </dl>

      <!-- Look-ahead Sub-requests -->

      <p><a id="rewritecond-lookahead" name="rewritecond-lookahead"
      ></a><strong>Subsolicitudes de búsqueda anticipada</strong></p>

      <p>Estas formas realizan una subsolicitud interna para determinar el
      valor final de una variable que todavía no está disponible en la etapa actual
      del procesamiento:</p>

      <dl>
        <dt><a id="LA-U" name="LA-U"><strong><code>%{LA-U:variable}</code></strong></a></dt>
        <dd>Realiza una subsolicitud interna (basada en URL) para determinar el valor
        final de <em>variable</em>. Esto puede usarse para acceder a
        una variable para la reescritura que no está disponible en la etapa actual,
        pero que se establecerá en una fase posterior.
        <p>Por ejemplo, para reescribir según la
        variable <code>REMOTE_USER</code> desde el contexto
        per-servidor (archivo <code>httpd.conf</code>) debe
        usar <code>%{LA-U:REMOTE_USER}</code>: esta
        variable la establecen las fases de autorización, que llegan
        <em>después</em> de la fase de traducción de URL (durante la cual
        opera <module>mod_rewrite</module>).</p>
        <p>Por otro lado, dado que <module>mod_rewrite</module> implementa
        su contexto <glossary ref="perdirectory">per-directorio</glossary> mediante
        la fase Fixup de la API, y dado que las fases de autorización
        llegan <em>antes</em> de esta fase, en ese contexto simplemente puede
        usar <code>%{REMOTE_USER}</code>.</p></dd>

        <dt><strong><code>%{LA-F:variable}</code></strong></dt>
        <dd>Realiza una subsolicitud interna (basada en el nombre de archivo) para determinar
        el valor final de <em>variable</em>. La mayoría de las veces, esto es
        lo mismo que LA-U arriba.</dd>
      </dl>

      <!-- Expression Syntax -->

      <p><a id="rewritecond-expr" name="rewritecond-expr"
      ></a><strong>Sintaxis de expresión</strong></p>

      <p>Si <em>TestString</em> tiene el valor especial <code>expr</code>,
      <em>CondPattern</em> se tratará como una
      <a href="../expr.html">ap_expr</a>. Las cabeceras HTTP referenciadas en la
      expresión se añadirán a la cabecera Vary si no se indica la bandera
      <code>novary</code>.</p>

      <!-- ============================================================ -->
      <!-- CondPattern                                                   -->
      <!-- ============================================================ -->

      <p><a id="rewritecond-condpattern" name="rewritecond-condpattern"
      ></a><strong>CondPattern</strong></p>

      <p><em>CondPattern</em> es el patrón de la condición,
       una expresión regular que se aplica a la
      instancia actual de <em>TestString</em>.
      <em>TestString</em> se evalúa primero, antes de compararse con
      <em>CondPattern</em>.</p>

      <p><em>CondPattern</em> suele ser una
      <glossary ref="regex">expresión regular</glossary>, pero hay
      sintaxis adicional disponible para realizar otras pruebas útiles sobre
      <em>Teststring</em>:</p>

      <!-- Negation -->

      <p>Puede prefijar la cadena del patrón con un
        carácter '<code>!</code>' (signo de exclamación) para negar el resultado
        de la condición, sin importar el tipo de <em>CondPattern</em> que se use.
      </p>

      <!-- String Comparisons -->

      <p><a id="rewritecond-stringcomp" name="rewritecond-stringcomp"
      ></a><strong>Comparaciones de cadenas</strong></p>

      <dl>
            <dt><strong>&lt;CondPattern</strong></dt>
            <dd>Precede lexicográficamente<br />
            Trata <em>CondPattern</em> como una cadena plana y la
            compara lexicográficamente con <em>TestString</em>. Verdadero si
            <em>TestString</em> precede lexicográficamente a
            <em>CondPattern</em>.</dd>

            <dt><strong>&gt;CondPattern</strong></dt>
            <dd>Sigue lexicográficamente<br />
            Trata <em>CondPattern</em> como una cadena plana y la
            compara lexicográficamente con <em>TestString</em>. Verdadero si
            <em>TestString</em> sigue lexicográficamente a
            <em>CondPattern</em>.</dd>

            <dt><strong>=CondPattern</strong></dt>
            <dd>Lexicográficamente igual<br />
            Trata <em>CondPattern</em> como una cadena plana y la
            compara lexicográficamente con <em>TestString</em>. Verdadero si
            <em>TestString</em> es lexicográficamente igual a
            <em>CondPattern</em> (las dos cadenas son exactamente
            iguales, carácter por carácter). Si <em>CondPattern</em>
            es <code>""</code> (dos comillas), esto
            compara <em>TestString</em> con la cadena vacía.</dd>

            <dt><strong>&lt;=CondPattern</strong></dt>
            <dd>Lexicográficamente menor o igual que<br />
            Trata <em>CondPattern</em> como una cadena plana y la
            compara lexicográficamente con <em>TestString</em>. Verdadero
            si <em>TestString</em> precede lexicográficamente a
            <em>CondPattern</em>, o es igual a <em>CondPattern</em>
            (las dos cadenas son iguales, carácter por carácter).</dd>

            <dt><strong>&gt;=CondPattern</strong></dt>
            <dd>Lexicográficamente mayor o igual que<br />
            Trata <em>CondPattern</em> como una cadena plana y la
            compara lexicográficamente con <em>TestString</em>. Verdadero
            si <em>TestString</em> sigue lexicográficamente a
            <em>CondPattern</em>, o es igual a <em>CondPattern</em>
            (las dos cadenas son iguales, carácter por carácter).</dd>
      </dl>

        <note><title>Nota</title>
        El operador de comparación de cadenas es parte del argumento
        <em>CondPattern</em> y debe incluirse dentro de las comillas si se usan. Por ejemplo:

        <highlight language="config">
RewriteCond %{HTTP_USER_AGENT} "=This Robot/1.0"
        </highlight>
        </note>

      <!-- Integer Comparisons -->

      <p><a id="rewritecond-intcomp" name="rewritecond-intcomp"
      ></a><strong>Comparaciones de enteros</strong></p>

      <dl>
            <dt><strong>-eq</strong></dt>
            <dd>Es numéricamente igual a.<br />
            <em>TestString</em> se trata como un entero, y se
            compara numéricamente con <em>CondPattern</em>. Verdadero si
            ambos son numéricamente iguales.</dd>

            <dt><strong>-ge</strong></dt>
            <dd>Es numéricamente mayor o igual que.<br />
            <em>TestString</em> se trata como un entero, y se
            compara numéricamente con <em>CondPattern</em>. Verdadero si
            <em>TestString</em> es numéricamente mayor o igual
            que <em>CondPattern</em>.</dd>

            <dt><strong>-gt</strong></dt>
            <dd>Es numéricamente mayor que.<br />
            <em>TestString</em> se trata como un entero, y se
            compara numéricamente con <em>CondPattern</em>. Verdadero si
            <em>TestString</em> es numéricamente mayor que
            <em>CondPattern</em>.</dd>

            <dt><strong>-le</strong></dt>
            <dd>Es numéricamente menor o igual que.<br />
            <em>TestString</em> se trata como un entero, y se
            compara numéricamente con <em>CondPattern</em>. Verdadero si
            <em>TestString</em> es numéricamente menor o igual
            que <em>CondPattern</em>. Para evitar confusión con
            <strong>-l</strong>, use la variante <strong>-L</strong> o
            <strong>-h</strong>.</dd>

            <dt><strong>-lt</strong></dt>
            <dd>Es numéricamente menor que.<br />
            <em>TestString</em> se trata como un entero, y se
            compara numéricamente con <em>CondPattern</em>. Verdadero si
            <em>TestString</em> es numéricamente menor que
            <em>CondPattern</em>. Para evitar confusión con
            <strong>-l</strong>, use la variante <strong>-L</strong> o
            <strong>-h</strong>.</dd>

            <dt><strong>-ne</strong></dt>
            <dd>Es numéricamente distinto de.<br />
            <em>TestString</em> se trata como un entero, y se
            compara numéricamente con <em>CondPattern</em>. Verdadero si
            ambos son numéricamente distintos. Esto es equivalente a
            <code>!-eq</code>.</dd>
      </dl>

      <!-- File Attribute Tests -->

      <p><a id="rewritecond-fileattr" name="rewritecond-fileattr"
      ></a><strong>Pruebas de atributos de archivo</strong></p>

      <dl>
          <dt><strong>-d</strong></dt>
          <dd>Es un <strong>d</strong>irectorio.<br />
             Trata <em>TestString</em> como un nombre de ruta y comprueba
            si existe, y si es un directorio.
          </dd>

          <dt><strong>-f</strong></dt>
          <dd>Es un <strong>f</strong>ichero regular.<br />
             Trata <em>TestString</em> como un nombre de ruta y comprueba
            si existe, y si es un archivo regular.
          </dd>

           <dt><strong>-F</strong></dt>
           <dd>Es un archivo existente, mediante subsolicitud.<br />
            Comprueba si <em>TestString</em> es un archivo válido,
            accesible a través de todos los controles de acceso actualmente
            configurados en el servidor para esa ruta. Esto usa una
            subsolicitud interna para hacer la comprobación, así que úselo con cuidado:
            ¡puede afectar al rendimiento de su servidor!
           </dd>

            <dt><strong>-h</strong></dt>
            <dd>Es un enlace simbólico, convención bash.<br />
            Vea <strong>-l</strong>.
            </dd>

            <dt><strong>-l</strong></dt>
            <dd>Es un en<strong>l</strong>ace simbólico.<br />
            Trata <em>TestString</em> como un nombre de ruta y comprueba
            si existe, y si es un enlace simbólico. También puede
            usarse la convención bash <strong>-L</strong> o
            <strong>-h</strong> si hay posibilidad de confusión,
            como al usar las pruebas <strong>-lt</strong> o
            <strong>-le</strong>.
            </dd>

            <dt><strong>-L</strong></dt>
            <dd>Es un enlace simbólico, convención bash.<br />
            Vea <strong>-l</strong>.</dd>

            <dt><strong>-s</strong></dt>
            <dd>Es un archivo regular con tamaño.<br />
            Trata <em>TestString</em> como un nombre de ruta y comprueba
            si existe, y si es un archivo regular con un tamaño mayor
            que cero.</dd>

            <dt><strong>-U</strong></dt>
            <dd><p>Es una URL existente, mediante subsolicitud.<br />
            Comprueba si <em>TestString</em> es una URL válida,
            accesible a través de todos los controles de acceso actualmente
            configurados en el servidor para esa ruta. Esto usa una
            subsolicitud interna para hacer la comprobación, así que úselo con cuidado:
            ¡puede afectar al rendimiento de su servidor!</p>
            <p>Esta bandera <em>solo</em> devuelve información sobre aspectos
            como el control de acceso, la autenticación y la autorización. Esta bandera
            <em>no</em> devuelve información sobre el código de estado que
            habría devuelto el handler configurado (archivo estático, CGI, proxy, etc.).</p> </dd>

            <dt><strong>-x</strong></dt>
            <dd>Tiene permisos de ejecución.<br />
            Trata <em>TestString</em> como un nombre de ruta y comprueba
            si existe, y si tiene permisos de ejecución.
            Estos permisos se determinan según
            el sistema operativo subyacente.</dd>
      </dl>

          <p>Por ejemplo:</p>

        <highlight language="config">
RewriteCond /var/www/%{REQUEST_URI} !-f
RewriteRule ^(.+) /other/archive/$1 [R]
        </highlight>

      <!-- Expression Evaluation in CondPattern -->

      <p><a id="rewritecond-expr-pattern" name="rewritecond-expr-pattern"
      ></a><strong>Evaluación de expresiones</strong></p>

           <p>Si <em>TestString</em> tiene el valor especial <code>expr</code>,
           <em>CondPattern</em> se tratará como una
           <a href="../expr.html">ap_expr</a>.</p>

           <p>
            En el siguiente ejemplo, se usa <code>-strmatch</code> para
            comparar <code>REFERER</code> con el nombre de host del sitio,
            con el fin de bloquear el hotlinking no deseado.
           </p>

           <highlight language="config">
RewriteCond expr "! %{HTTP_REFERER} -strmatch '*://%{HTTP_HOST}/*'"
RewriteRule "^/images" "-" [F]
           </highlight>

      <!-- ============================================================ -->
      <!-- Flags                                                         -->
      <!-- ============================================================ -->

      <p><a id="rewritecond-flags" name="rewritecond-flags"
      ></a><strong>Banderas</strong></p>

     <p>Puede establecer banderas especiales para <em>CondPattern</em> añadiendo
        <strong><code>[</code><em>flags</em><code>]</code></strong>
      como tercer argumento a la directiva <directive>RewriteCond</directive>,
      donde <em>flags</em> es una lista separada por comas de cualquiera de las
      siguientes banderas:</p>

      <dl>
        <dt>'<strong><code>nocase|NC</code></strong>'</dt>
        <dd>Hace que la comprobación no distinga entre mayúsculas y
        minúsculas: se ignoran las diferencias entre 'A-Z' y 'a-z',
        tanto en el <em>TestString</em> expandido como en el
        <em>CondPattern</em>. Esta bandera solo es efectiva para las
        comparaciones entre <em>TestString</em> y <em>CondPattern</em>.
        No tiene efecto en las comprobaciones de sistema de archivos ni de
        subsolicitud.</dd>

        <dt>'<strong><code>ornext|OR</code></strong>'</dt>
        <dd>Use esto para combinar condiciones de regla con un OR local
          en lugar del AND implícito. Ejemplo típico:

<highlight language="config">
RewriteCond "%{REMOTE_HOST}"  "^host1"  [OR]
RewriteCond "%{REMOTE_HOST}"  "^host2"  [OR]
RewriteCond "%{REMOTE_HOST}"  "^host3"
RewriteRule ...some special stuff for any of these hosts...
</highlight>

          Sin esta bandera tendría que escribir el par condición/regla
          tres veces.
        </dd>

        <dt>'<strong><code>novary|NV</code></strong>'</dt>
        <dd>Si se usa una cabecera HTTP en la condición, esta bandera evita que
        esa cabecera se añada a la cabecera Vary de la respuesta. <br />
        Usar esta bandera podría romper el almacenamiento en caché correcto de la respuesta
        si la representación de esa respuesta varía según el valor de esta cabecera.
        Por eso esta bandera solo debería usarse si se comprende bien el significado
        de la cabecera Vary.
        </dd>
      </dl>

      <!-- ============================================================ -->
      <!-- Example                                                       -->
      <!-- ============================================================ -->

      <p><a id="rewritecond-examples" name="rewritecond-examples"
      ></a><strong>Ejemplo</strong></p>

       <p>Para reescribir la página de inicio de un sitio según la
        cabecera ``<code>User-Agent:</code>'' de la solicitud, puede
        usar lo siguiente: </p>

<highlight language="config">
RewriteCond  "%{HTTP_USER_AGENT}"  "(iPhone|Blackberry|Android)"
RewriteRule  "^/$"                 "/homepage.mobile.html"  [L]

RewriteRule  "^/$"                 "/homepage.std.html"     [L]
</highlight>

        <p>Explicación: si usa un navegador que se identifica a sí mismo
        como navegador móvil (tenga en cuenta que el ejemplo es incompleto, ya que
        hay muchas otras plataformas móviles), se sirve la versión móvil
        de la página de inicio. En caso contrario, se sirve la página estándar.
        </p>

        <p>Por defecto, varias <directive>RewriteCond</directive>
        se evalúan en secuencia con un <strong>AND</strong> lógico implícito.
        Si una condición falla, en ausencia de una bandera
        <strong><code>OR</code></strong>, se abandona todo el conjunto de reglas,
        y no se evalúan más condiciones.
        </p>

</usage>

</directivesynopsis>


<directivesynopsis>
<name>RewriteRule</name>
<description>Define reglas para el motor de reescritura</description>
<syntax>RewriteRule
      [!]<em>Pattern</em> <em>Substitution</em> [<em>flags</em>]</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>
      <p>La directiva <directive>RewriteRule</directive> es el verdadero
      caballo de batalla de la reescritura. La directiva puede aparecer más de una vez,
      y cada instancia define una única regla de reescritura. El
      orden en que se definen estas reglas es importante: es el orden
      en el que se aplicarán en tiempo de ejecución.</p>

      <p><a id="patterns" name="patterns"><em>Pattern</em></a> es
      una <a id="regexp" name="regexp"><glossary ref="regex">expresión
      regular</glossary></a>. Con qué se compara este patrón varía según
      dónde se defina la directiva <directive>RewriteRule</directive>. </p>

      <p>Si el patrón va precedido de un <code>!</code>, la
      sustitución solo se realizará si el
      <em>patrón</em> no coincide.</p>

<note><title><a id="what_is_matched" name="what_is_matched">¿Qué se compara?</a></title>

<ul>
      <li><p>En contexto <directive module="core">VirtualHost</directive>,
      el <em>Pattern</em> se comparará inicialmente con la parte de la
      URL que va después del nombre de host y el puerto, y antes de la cadena de consulta (por ejemplo, "/app1/index.html").
      Esta es la <a href="directive-dict.html#Syntax">ruta de la URL</a> (decodificada con %).</p></li>

      <li><p>En contexto <glossary ref="perdirectory">per-directorio</glossary>
      (<directive module="core">Directory</directive> y .htaccess),
      el <em>Pattern</em> se compara solo con una ruta parcial; por ejemplo, una solicitud
      de "/app1/index.html" puede dar lugar a la comparación con "app1/index.html"
      o con "index.html", dependiendo de la ruta de directorio a la que se aplique
      la <directive>RewriteRule</directive>.</p>

      <p>La ruta de directorio a la que se aplica la regla se elimina de la ruta del sistema de
      archivos actualmente mapeada antes de la comparación (hasta e incluyendo una barra final).
      El resultado neto de esta eliminación del prefijo <glossary ref="perdirectory">per-directorio</glossary>
      es que las reglas en este contexto solo coinciden con la parte de la ruta del sistema de archivos
      actualmente mapeada que está "por debajo" de la ruta de directorio a la que se aplica la regla.</p>

      <p>Directivas como <directive module="core"
      >DocumentRoot</directive> y <directive module="mod_alias">Alias</directive>, o incluso el
      resultado de sustituciones previas de <directive>RewriteRule</directive>, determinan
      la ruta del sistema de archivos actualmente mapeada.
      </p>
      </li>

      <li><p>Si desea comparar con el nombre de host, el puerto, o la cadena de consulta, use una
      <directive module="mod_rewrite">RewriteCond</directive> con las variables
      <code>%{HTTP_HOST}</code>, <code>%{SERVER_PORT}</code>, o
      <code>%{QUERY_STRING}</code> respectivamente.</p></li>
</ul>
</note>

<note><title>Reescrituras <glossary ref="perdirectory">per-directorio</glossary></title>
<ul>
<li>El motor de reescritura puede usarse en archivos <a
href="../howto/htaccess.html">.htaccess</a> y en secciones <directive type="section"
module="core">Directory</directive>, con algo de complejidad
adicional.</li>

<li>Para activar el motor de reescritura en este contexto, necesita establecer
<code>RewriteEngine On</code> <strong>y</strong>
tener activada al menos una de las opciones <code>FollowSymLinks</code> o
<code>SymLinksIfOwnerMatch</code> de
<directive module="core">Options</directive>. Tenga en cuenta
que estas opciones no pueden establecerse en un archivo de configuración distribuido
(<code>.htaccess</code>) a menos que
<directive module="core">AllowOverride</directive> lo permita
en la configuración del servidor.</li>

<li>Vea la directiva <directive module="mod_rewrite">RewriteBase</directive>
para más información sobre qué prefijo se volverá a añadir a las
sustituciones relativas.</li>

<li>Si desea comparar con la ruta de URL completa en una
<directive>RewriteRule</directive> en contexto <glossary ref="perdirectory">per-directorio</glossary>,
use la variable <code>%{REQUEST_URI}</code> en
una <directive module="mod_rewrite">RewriteCond</directive>.</li>

<li>El prefijo eliminado siempre termina en barra, lo que significa que la comparación se hace contra una cadena que
<em>nunca</em> tiene una barra inicial. Por tanto, un <em>Pattern</em> con <code>^/</code> nunca
coincide en contexto <glossary ref="perdirectory">per-directorio</glossary>.</li>

<li>Aunque las reglas de reescritura se permiten sintácticamente en secciones <directive
type="section" module="core">Location</directive> y <directive
type="section" module="core">Files</directive>
(incluyendo sus contrapartidas con expresión regular), esto
nunca debería ser necesario y no está soportado. Una característica que probablemente
falle en estos contextos son las sustituciones relativas.</li>

<li>Los bloques <directive module="core">If</directive>
siguen las reglas del contexto <em>directory</em>.</li>

<li>Por defecto, mod_rewrite sobrescribe las reglas al <a href="../sections.html#merging">
fusionar secciones</a> que pertenecen al mismo contexto. La directiva
<directive module="mod_rewrite">RewriteOptions</directive> puede cambiar este
comportamiento, por ejemplo con el ajuste <em>Inherit</em>.</li>

<li>La directiva <directive module="mod_rewrite">RewriteOptions</directive> también regula el
comportamiento de las secciones que se indican en el mismo nivel de anidamiento de la configuración. En el
siguiente ejemplo, por defecto solo se tienen en cuenta las RewriteRule indicadas en el segundo
bloque <directive module="core">If</directive>, ya que las primeras se
sobrescriben. Usar <directive
module="mod_rewrite">RewriteOptions</directive> Inherit fuerza a mod_rewrite a fusionar las dos
secciones y tener en cuenta ambos conjuntos de instrucciones, en lugar de solo el último.</li>
</ul>
<example>
<highlight language="config">
&lt;If "true"&gt;
  # Without RewriteOptions Inherit, this rule is overridden by the next
  # section and no redirect will happen for URIs containing 'foo'
  RewriteRule foo http://example.com/foo [R]
&lt;/If&gt;
&lt;If "true"&gt;
  RewriteRule bar http://example.com/bar [R]
&lt;/If&gt;
</highlight>
</example>
</note>

      <p>Para información sobre <glossary ref="regex">expresiones
      regulares</glossary>, incluido el uso del prefijo
      <code>!</code> para negar un patrón, vea la sección
      <a href="../rewrite/intro.html#regex">Expresiones regulares</a>
      de la introducción a mod_rewrite.</p>

      <p>La <a id="rhs" name="rhs"><em>Substitution</em></a> de una
      regla de reescritura es la cadena que sustituye a la ruta de URL (vea
      <a href="#what_is_matched">"¿Qué se compara?"</a> arriba)
      cuando se cumplen las condiciones de la regla. La <em>Substitution</em> puede
      ser:</p>

      <dl>

        <dt>ruta del sistema de archivos</dt>

        <dd>Indica la ubicación en el sistema de archivos del recurso
        que se entregará al cliente. Una sustitución que comienza con
        <code>/</code> se trata como una ruta del sistema de archivos solo en
        contexto de servidor o de host virtual, y solo cuando el primer
        componente de la ruta existe en el sistema de archivos. En
        contexto <glossary ref="perdirectory">per-directorio</glossary>,
        no se hace esta suposición.</dd>

        <dt>ruta de URL</dt>

        <dd>Una ruta relativa a <directive
        module="core">DocumentRoot</directive> hacia el recurso que se
        servirá. En contexto de servidor o de host virtual,
        si el primer segmento de la ruta existe en la raíz del
        sistema de archivos, la sustitución se trata como una ruta
        del sistema de archivos en su lugar. Por ejemplo, <code>/www/file.html</code>
        es una ruta de URL a menos que exista un directorio llamado
        <code>www</code> en la raíz del sistema de archivos. Si quiere que se
        apliquen otras directivas de mapeo de URL (como
        <directive module="mod_alias">Alias</directive>) a la
        ruta de URL resultante, use la bandera <code>[PT]</code> como
        se describe más abajo.</dd>

        <dt>URL absoluta</dt>

        <dd><p>Si se especifica una URL absoluta,
        <module>mod_rewrite</module> comprueba si el
        nombre de host coincide con el host actual. Si es así, el esquema y el
        nombre de host se eliminan y la ruta resultante se trata como
        una ruta de URL. En caso contrario, se realiza una redirección externa a
        la URL indicada. Para forzar una redirección externa de vuelta al
        host actual, vea la bandera <code>[R]</code> más abajo.</p>
        <p>Tenga en cuenta que una redirección (implícita o no) que use una URI absoluta
        incluirá la cadena de consulta solicitada; para evitarlo vea
        la bandera <code>[QSD]</code> más abajo.</p></dd>

        <dt><code>-</code> (guion)</dt>

        <dd>Un guion indica que no debe realizarse ninguna sustitución
        (la ruta existente se pasa sin modificar). Esto se usa
        cuando hay que aplicar una bandera (vea más abajo) sin cambiar
        la ruta.</dd>

      </dl>

      <note><title>Cómo se interpretan las sustituciones de ruta</title>
      <p>Que una sustitución de ruta se trate como una ruta del sistema de archivos
      o como una ruta de URL depende del contexto y de si comienza con
      barra:</p>
      <ul>
        <li><strong>Comienza con <code>/</code>, contexto de servidor/vhost:</strong>
        Se trata como una ruta del sistema de archivos si el primer componente de la ruta existe
        en disco; en caso contrario, se trata como una ruta de URL.</li>
        <li><strong>Comienza con <code>/</code>, contexto <glossary ref="perdirectory">per-directorio</glossary>:</strong>
        Siempre se trata como una ruta de URL. No se hace ninguna suposición sobre el sistema de archivos.</li>
        <li><strong>No comienza con <code>/</code> (relativa),
        contexto de servidor/vhost:</strong> Se trata como una ruta de URL relativa
        a la URI de la solicitud actual.</li>
        <li><strong>No comienza con <code>/</code> (relativa),
        contexto <glossary ref="perdirectory">per-directorio</glossary>:</strong> Se trata como una ruta de URL relativa
        a la ruta de directorio a la que se aplica la <directive
        module="core">Directory</directive> o el <code>.htaccess</code>.
        Vea <directive>RewriteBase</directive> para controlar
        el prefijo que se añade a las sustituciones relativas.</li>
      </ul>
      </note>

      <p>Además de texto plano, la cadena <em>Substitution</em> puede incluir</p>

      <ol>
        <li>referencias inversas (<code>$N</code>) al patrón de la
        RewriteRule</li>

        <li>referencias inversas (<code>%N</code>) al último patrón de
        RewriteCond que coincidió</li>

        <li>variables del servidor como en las cadenas de prueba de las condiciones de regla
        (<code>%{VARNAME}</code>)</li>

        <li>llamadas a <a href="#mapfunc">función de mapeo</a>
        (<code>${mapname:key|default}</code>)</li>
      </ol>

      <p>Las referencias inversas son identificadores de la forma
      <code>$</code><strong>N</strong>
      (<strong>N</strong>=0..9). <code>$0</code> se refiere a la
      cadena completa que coincide con el <em>Pattern</em>, mientras que
      <code>$1</code>..<code>$9</code> se refieren a los grupos
      capturados correspondientes del <em>Pattern</em> que ha coincidido.
      De forma similar, las referencias inversas
      <code>%0</code>..<code>%9</code> se refieren al <em>CondPattern</em>
      de <directive module="mod_rewrite">RewriteCond</directive>
      que ha coincidido más recientemente: <code>%0</code> es la coincidencia
      completa y <code>%1</code>..<code>%9</code> son los grupos
      capturados. Las variables del servidor son las mismas
      que para el <em>TestString</em> de una directiva
      <directive module="mod_rewrite">RewriteCond</directive>.
      Las funciones de mapeo proceden de la
      directiva <directive module="mod_rewrite">RewriteMap</directive>
      y se explican en ese apartado.
      Estos tres tipos de variables se expanden en el orden anterior.</p>

      <p>Las reglas de reescritura se aplican a los resultados de reglas de
      reescritura previas, en el orden en el que se definen
      en el archivo de configuración. La ruta de URL o la ruta del sistema de archivos (vea
      <a href="#what_is_matched">"¿Qué se compara?"</a>, arriba) se <strong>sustituye
      completamente</strong> por la <em>Substitution</em>, y el
      proceso de reescritura continúa hasta que se han aplicado todas las reglas,
      o hasta que se termina explícitamente mediante una
      bandera <a href="../rewrite/flags.html#flag_l"><code><strong>L</strong></code></a>,
      u otra bandera que implique una terminación inmediata, como
      <code><strong>END</strong></code> o
      <code><strong>F</strong></code>.</p>

     <note><title>Modificar la cadena de consulta</title>
      <p>Por defecto, la cadena de consulta se pasa sin cambios. Sin embargo, puede
      crear URLs en la cadena de sustitución que contengan
      una parte de cadena de consulta. Simplemente use un signo de interrogación dentro de la
      cadena de sustitución para indicar que el texto siguiente debe
      reinyectarse en la cadena de consulta. Cuando quiera borrar una
      cadena de consulta existente, termine la cadena de sustitución con solo un
      signo de interrogación. Para combinar la cadena de consulta nueva con la antigua, use
      la bandera <code>[QSA]</code>.</p>
     </note>

      <p>Además, puede establecer <a name="rewriteflags"
      id="rewriteflags">acciones</a> especiales que se realicen
      añadiendo <strong><code>[</code><em>flags</em><code>]</code></strong>
      como tercer argumento de la directiva <directive>RewriteRule</directive>.
      <em>Flags</em> es una lista separada por comas, rodeada de corchetes, con
      cualquiera de las banderas de la siguiente tabla. Puede encontrar más
      detalles, y ejemplos, de cada bandera en el <a
      href="../rewrite/flags.html">documento de banderas de reescritura</a>.</p>

    <table border="1" style="zebra">
    <tr><th>Bandera y sintaxis</th>
        <th>Función</th>
    </tr>
    <tr>
        <td>B</td>
        <td>Escapa los caracteres no alfanuméricos en las referencias inversas <em>antes</em>
        de aplicar la transformación. Para un escape similar de las variables del servidor, vea
        la <a href="#mapfunc">función de mapeo</a> "escape".<em><a
        href="../rewrite/flags.html#flag_b">detalles ...</a></em></td>
    </tr>
    <tr>
        <td>BCTLS</td>
        <td>Como [B], pero solo escapa los caracteres de control y los espacios.
        <em><a href="../rewrite/flags.html#flag_bctls">detalles ...</a></em></td>
    </tr>
    <tr>
        <td>BNE</td>
        <td>Caracteres de [B] o [BCTLS] que <strong>no</strong> deben escaparse.
        <em><a href="../rewrite/flags.html#flag_bne">detalles ...</a></em></td>
    </tr>
    <tr>
        <td>backrefnoplus|BNP</td>
        <td>Si se están escapando las referencias inversas, los espacios deben escaparse a
        %20 en lugar de +. Útil cuando la referencia inversa se usará en el
        componente de ruta en lugar de en la cadena de consulta.<em><a
        href="../rewrite/flags.html#flag_bnp">detalles ...</a></em></td>
    </tr>

    <tr>
        <td>chain|C</td>
        <td>La regla se encadena a la siguiente regla. Si la regla falla,
        la(s) regla(s) encadenadas a ella se omitirán. <em><a
        href="../rewrite/flags.html#flag_c">detalles ...</a></em></td>
    </tr>
    <tr>
        <td>cookie|CO=<em>NAME</em>:<em>VAL</em></td>
        <td>Establece una cookie en el navegador del cliente. La sintaxis completa es:
        CO=<em>NAME</em>:<em>VAL</em>:<em>domain</em>[:<em>lifetime</em>[:<em>path</em>[:<em>secure</em>[:<em>httponly</em>[<em>samesite</em>]]]]] <em><a href="../rewrite/flags.html#flag_co">detalles ...</a></em>
        </td>
    </tr>
    <tr>
        <td>discardpath|DPI</td>
        <td>Hace que se descarte la parte PATH_INFO de la URI reescrita.
        <em><a href="../rewrite/flags.html#flag_dpi">detalles
        ...</a></em></td>
    </tr>
    <tr>
        <td>END</td>
        <td>Detiene el proceso de reescritura inmediatamente y no aplica
        más reglas. También evita que se sigan ejecutando reglas de reescritura
        en contexto <glossary ref="perdirectory">per-directorio</glossary>. (Disponible en 2.3.9 y posteriores)
        <em><a href="../rewrite/flags.html#flag_end">detalles ...</a></em></td>
    </tr>
    <tr>
        <td>env|E=[!]<em>VAR</em>[:<em>VAL</em>]</td>
        <td>Hace que se establezca una variable de entorno <em>VAR</em> (con el
        valor <em>VAL</em> si se proporciona). La forma !<em>VAR</em> hace que
        se elimine la variable de entorno <em>VAR</em>.
        <em><a href="../rewrite/flags.html#flag_e">detalles ...</a></em></td>
    </tr>
    <tr>
        <td>forbidden|F</td>
        <td>Devuelve una respuesta 403 FORBIDDEN al navegador del cliente.
        <em><a href="../rewrite/flags.html#flag_f">detalles ...</a></em></td>
    </tr>
    <tr>
        <td>gone|G</td>
        <td>Devuelve una respuesta 410 GONE al navegador del cliente. <em><a
        href="../rewrite/flags.html#flag_g">detalles ...</a></em></td>
    </tr>
    <tr>
        <td>Handler|H=<em>Content-handler</em></td>
        <td>Hace que la URI resultante se envíe al <em>Content-handler</em>
        especificado para su procesamiento. <em><a
        href="../rewrite/flags.html#flag_h">detalles ...</a></em></td>
    </tr>
    <tr>
        <td>last|L</td>
        <td>Detiene el proceso de reescritura inmediatamente y no aplica
        más reglas. Tenga especialmente en cuenta las advertencias para el contexto <glossary ref="perdirectory">per-directorio</glossary> (vea también la bandera END). <em><a
        href="../rewrite/flags.html#flag_l">detalles ...</a></em></td>
    </tr>
    <tr>
        <td>next|N</td>
        <td>Vuelve a ejecutar el proceso de reescritura, comenzando de nuevo con la
        primera regla, usando como punto de partida el resultado del conjunto de reglas hasta
        ese momento. <em><a href="../rewrite/flags.html#flag_n">detalles
        ...</a></em></td>
    </tr>
    <tr>
        <td>nocase|NC</td>
        <td>Hace que la comparación del patrón no distinga mayúsculas y minúsculas.
        <em><a href="../rewrite/flags.html#flag_nc">detalles ...</a></em></td>
    </tr>
    <tr>
        <td>noescape|NE</td>
        <td>Evita que mod_rewrite aplique el escape en código hexadecimal de
            caracteres especiales en el resultado de reescrituras que dan lugar a
            una redirección. <em>
            <a href="../rewrite/flags.html#flag_ne">detalles ...</a></em></td>
    </tr>
    <tr>
        <td>nosubreq|NS</td>
        <td>Hace que se omita una regla si la solicitud actual es una
        subsolicitud interna. <em><a
        href="../rewrite/flags.html#flag_ns">detalles ...</a></em></td>
    </tr>
    <tr>
        <td>proxy|P</td>
        <td>Fuerza a que la URL de sustitución se envíe internamente como una
        solicitud de proxy. <em><a href="../rewrite/flags.html#flag_p">detalles
        ...</a></em></td>
    </tr>
    <tr>
        <td>passthrough|PT</td>
        <td>Hace que la URI resultante se devuelva al motor de mapeo de URL
        para que la procesen otros traductores de URI a nombre de archivo,
        como <code>Alias</code> o
        <code>Redirect</code>. <em><a
        href="../rewrite/flags.html#flag_pt">detalles ...</a></em></td>
    </tr>
    <tr>
        <td>qsappend|QSA</td>
        <td>Añade cualquier cadena de consulta de la URL de solicitud original a
        cualquier cadena de consulta creada en el destino de la reescritura.<em><a
        href="../rewrite/flags.html#flag_qsa">detalles ...</a></em></td>
    </tr>
    <tr>
        <td>qsdiscard|QSD</td>
        <td>Descarta cualquier cadena de consulta adjunta a la URI entrante.
        <em><a href="../rewrite/flags.html#flag_qsd">detalles
        ...</a></em></td>
    </tr>
    <tr>
        <td>qslast|QSL</td>
        <td>Interpreta el último signo de interrogación (el más a la derecha) como
            delimitador de la cadena de consulta, en lugar del primero (el más a la izquierda), como se usa normalmente.
            Disponible en 2.4.19 y posteriores.
        <em><a href="../rewrite/flags.html#flag_qsl">detalles
        ...</a></em></td>
    </tr>

    <tr>
        <td>redirect|R[=<em>code</em>]</td>
        <td>Fuerza una redirección externa, opcionalmente con el código de
        estado HTTP especificado. <em><a
        href="../rewrite/flags.html#flag_r">detalles ...</a></em>
        </td>
    </tr>
    <tr>
        <td>skip|S=<em>num</em></td>
        <td>Indica al motor de reescritura que omita las siguientes <em>num</em>
        reglas si la regla actual coincide. <em><a
        href="../rewrite/flags.html#flag_s">detalles ...</a></em></td>
    </tr>
    <tr>
        <td>type|T=<em>MIME-type</em></td>
        <td>Fuerza a que el <glossary>MIME-type</glossary> del archivo destino
        sea el tipo especificado. <em><a
        href="../rewrite/flags.html#flag_t">detalles ...</a></em></td>
    </tr>
    <tr>
        <td>UnsafeAllow3F</td>
        <td>Permite sustituciones a partir de URLs que puedan ser inseguras.
        <em><a href="../rewrite/flags.html#flag_unsafe_allow_3f">detalles ...</a></em>
        </td>
    </tr>
    <tr>
        <td>UnsafePrefixStat</td>
        <td>Permite sustituciones potencialmente inseguras a partir de una variable o referencia inversa inicial hacia una ruta del sistema de archivos.
        <em><a href="../rewrite/flags.html#flag_unsafe_prefix_stat">detalles ...</a></em><br />
        <since>2.4.60</since>
        </td>
    </tr>
    <tr>
        <td>UNC</td>
        <td>Evita la fusión de varias barras iniciales, como las que usan las rutas UNC de Windows.
        <em><a href="../rewrite/flags.html#flag_unc">detalles ...</a></em><br />
        <since>2.4.62</since>
        </td>
    </tr>

    </table>

<note><title>Expansión del directorio personal</title>
<p>Cuando la cadena de sustitución comienza con una cadena
parecida a "/~user" (mediante texto explícito o referencias inversas), <module>mod_rewrite</module> realiza
la expansión del directorio personal independientemente de la presencia o configuración
de <module>mod_userdir</module>.</p>

<p>Esta expansión no se produce cuando se usa la bandera <em>PT</em>
en la directiva <directive module="mod_rewrite">RewriteRule</directive>.</p>
</note>


     <p>Aquí se muestran las posibles combinaciones de la forma de la
      cadena de sustitución, el contexto, y las banderas [R] y [P], junto con sus
      significados:</p>

      <p><strong>Fuera de la configuración <glossary ref="perdirectory">per-directorio</glossary><br />
       para la solicitud ``<code>GET
      /somepath/pathinfo</code>'':</strong><br />
      </p>

<table border="1" style="zebra">
<tr>
<th>Regla dada</th>
<th>Sustitución resultante</th>
</tr>

<tr>
<td>^/somepath(.*) otherpath$1</td>
<td>no válida, no soportada</td>
</tr>

<tr>
<td>^/somepath(.*) otherpath$1  [R]</td>
<td>no válida, no soportada</td>
</tr>

<tr>
<td>^/somepath(.*) otherpath$1  [P]</td>
<td>no válida, no soportada</td>
</tr>

<tr>
<td>^/somepath(.*) /otherpath$1</td>
<td>/otherpath/pathinfo</td>
</tr>

<tr>
<td>^/somepath(.*) /otherpath$1 [R]</td>
<td>http://thishost/otherpath/pathinfo mediante redirección externa</td>
</tr>

<tr>
<td>^/somepath(.*) /otherpath$1 [P]</td>
<td>no tiene sentido, no soportada</td>
</tr>

<tr>
<td>^/somepath(.*) http://thishost/otherpath$1</td>
<td>/otherpath/pathinfo</td>
</tr>

<tr>
<td>^/somepath(.*) http://thishost/otherpath$1 [R]</td>
<td>http://thishost/otherpath/pathinfo mediante redirección externa</td>
</tr>

<tr>
<td>^/somepath(.*) http://thishost/otherpath$1 [P]</td>
<td>no tiene sentido, no soportada</td>
</tr>

<tr>
<td>^/somepath(.*) http://otherhost/otherpath$1</td>
<td>http://otherhost/otherpath/pathinfo mediante redirección externa</td>
</tr>

<tr>
<td>^/somepath(.*) http://otherhost/otherpath$1 [R]</td>
<td>http://otherhost/otherpath/pathinfo mediante redirección externa (la bandera [R] es redundante)</td>
</tr>

<tr>
<td>^/somepath(.*) http://otherhost/otherpath$1 [P]</td>
<td>http://otherhost/otherpath/pathinfo mediante proxy interno</td>
</tr>
</table>

      <p><strong>Dentro de la configuración <glossary ref="perdirectory">per-directorio</glossary> para
      <code>/somepath</code><br />
       (por ejemplo, <code>.htaccess</code> o <code>&lt;Directory&gt;</code>, con
      <code>RewriteBase "/somepath"</code>)<br />
       para la solicitud ``<code>GET
      /somepath/localpath/pathinfo</code>'':</strong><br />
     </p>

<table border="1" style="zebra">

<tr>
<th>Regla dada</th>
<th>Sustitución resultante</th>
</tr>

<tr>
<td>^localpath(.*) otherpath$1</td>
<td>/somepath/otherpath/pathinfo</td>
</tr>

<tr>
<td>^localpath(.*) otherpath$1  [R]</td>
<td>http://thishost/somepath/otherpath/pathinfo mediante redirección
externa</td>
</tr>

<tr>
<td>^localpath(.*) otherpath$1  [P]</td>
<td>no tiene sentido, no soportada</td>
</tr>

<tr>
<td>^localpath(.*) /otherpath$1</td>
<td>/otherpath/pathinfo</td>
</tr>

<tr>
<td>^localpath(.*) /otherpath$1 [R]</td>
<td>http://thishost/otherpath/pathinfo mediante redirección externa</td>
</tr>

<tr>
<td>^localpath(.*) /otherpath$1 [P]</td>
<td>no tiene sentido, no soportada</td>
</tr>

<tr>
<td>^localpath(.*) http://thishost/otherpath$1</td>
<td>/otherpath/pathinfo</td>
</tr>

<tr>
<td>^localpath(.*) http://thishost/otherpath$1 [R]</td>
<td>http://thishost/otherpath/pathinfo mediante redirección externa</td>
</tr>

<tr>
<td>^localpath(.*) http://thishost/otherpath$1 [P]</td>
<td>no tiene sentido, no soportada</td>
</tr>

<tr>
<td>^localpath(.*) http://otherhost/otherpath$1</td>
<td>http://otherhost/otherpath/pathinfo mediante redirección externa</td>
</tr>

<tr>
<td>^localpath(.*) http://otherhost/otherpath$1 [R]</td>
<td>http://otherhost/otherpath/pathinfo mediante redirección externa (la bandera [R] es redundante)</td>
</tr>

<tr>
<td>^localpath(.*) http://otherhost/otherpath$1 [P]</td>
<td>http://otherhost/otherpath/pathinfo mediante proxy interno</td>
</tr>

</table>

  </usage>
 </directivesynopsis>
</modulesynopsis>
