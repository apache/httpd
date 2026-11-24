<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933179 -->
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

<modulesynopsis metafile="mod_policy.xml.meta">

<name>mod_policy</name>
<description>Aplicación del cumplimiento del protocolo HTTP.</description>
<status>Extension</status>
<sourcefile>mod_policy.c</sourcefile>
<identifier>policy_module</identifier>

<summary>
    <p>El protocolo HTTP recomienda que los clientes sean "liberales en
    lo que aceptan" y los servidores "estrictos en lo que envían". En algunos
    casos puede ser difícil detectar cuándo un servidor o una aplicación
    está mal configurado, está sirviendo contenido no cacheable o se comporta
    de forma subóptima, ya que un cliente HTTP podría estar compensando el
    comportamiento del servidor. Estos problemas pueden llegar a provocar un
    consumo excesivo de ancho de banda, o la caída del servidor bajo carga.</p>

    <p>El módulo <module>mod_policy</module> consiste en un conjunto de
    filtros que comprueban el cumplimiento del protocolo HTTP por parte de los
    servidores. Estas pruebas permiten al administrador del servidor registrar
    las infracciones, o directamente rechazar las respuestas en las que se
    dan determinadas condiciones.</p>

    <p>Esto puede usarse como una forma de establecer criterios mínimos de
    cumplimiento del protocolo HTTP para una aplicación restful. Alternativamente,
    un proxy inverso o una caché podrían configurarse para protegerse de
    servidores de origen mal configurados o de contenido inesperadamente no
    cacheable, o como mecanismo para detectar errores de configuración dentro
    del propio servidor.</p>

</summary>
<seealso><a href="../filter.html">Filtros</a></seealso>
<seealso><a href="../compliance.html">Cumplimiento del protocolo HTTP</a></seealso>

<section id="actions">
    <title>Acciones</title>

    <p>Si se infringe una política, se puede llevar a cabo una de las
    siguientes acciones:</p>

    <dl>
    <dt><strong>ignore</strong></dt>
    <dd>La comprobación de la política se ignorará para el espacio de URL dado,
    incluso si el filtro está presente.</dd>

    <dt><strong>log</strong></dt>
    <dd>La comprobación de la política se ejecutará, y si se detecta una
    infracción se registrará una advertencia en el error_log del servidor, y
    se añadirá una cabecera <code>Warning</code> a la respuesta en beneficio
    del cliente.</dd>

    <dt><strong>enforce</strong></dt>
    <dd>La comprobación de la política se ejecutará, y si se detecta una
    infracción se registrará un error en el error_log del servidor, se
    añadirá una cabecera <code>Warning</code> a la respuesta, y se devolverá
    un <code>502 Bad Gateway</code> al cliente. Se pueden añadir enlaces
    opcionales a documentación explicativa en cada mensaje de error, detallando
    el origen de cada política.</dd>

    </dl>

    <p>También es posible desactivar selectivamente todas las políticas para
    un espacio de URL dado, si fuera necesario, usando la directiva
    <directive module="mod_policy">PolicyFilter</directive>.</p>

    <p>Alternativamente, la directiva
    <directive module="mod_policy">PolicyEnvironment</directive>
    puede usarse para especificar una variable de entorno que, de estar
    presente, hará que las políticas se degraden o se omitan selectivamente.</p>

</section>

<section id="tests">
    <title>Pruebas de política</title>

    <p>Están disponibles los siguientes filtros de política:</p>

    <dl>
    <dt><strong><a href="../compliance.html#policytype">POLICY_TYPE</a>
    </strong>: Exige tipos de contenido válidos</dt>
    <dd>Se pueden detectar los tipos de contenido que sean sintácticamente
	inválidos o estén en blanco, y rechazar la petición. Los tipos se pueden
	restringir a una lista específica que contenga los comodines opcionales
	? y *.</dd>

    <dt><strong><a href="../compliance.html#policylength">POLICY_LENGTH</a>
    </strong>: Exige la presencia de un Content-Length</dt>
    <dd>La longitud de las respuestas se puede especificar de una de estas tres
    formas: indicando una longitud explícita de antemano, usando codificación
    chunked para fijar la longitud, o sin fijar ninguna longitud y terminando
    la petición al completarse. La ausencia de una longitud de contenido
    específica puede afectar a la cacheabilidad de la respuesta, e impide el
    uso de keepalive durante las peticiones HTTP/1.0. Esta política exige la
    presencia de una longitud de contenido explícita en la respuesta.</dd>

    <dt><strong><a href="../compliance.html#policykeepalive">POLICY_KEEPALIVE
    </a></strong>: Exige la posibilidad de mantener la conexión activa (keepalive)</dt>
    <dd>Menos restrictiva que la prueba POLICY_LENGTH, esta política exige que
    sea posible mantener activa la respuesta. Si la respuesta no tiene una
    longitud cero definida por el protocolo, y la respuesta no es ya un error,
    y la respuesta no tiene ni Content-Length ni está declarada como HTTP/1.1
    y carece de Content-Encoding: chunked, entonces esta respuesta será
    rechazada.</dd>

    <dt><strong><a href="../compliance.html#policyvary">POLICY_VARY</a>
    </strong>: Exige la ausencia de ciertas cabeceras dentro de las cabeceras Vary</dt>
    <dd>Si la cabecera Vary contiene alguna de las cabeceras especificadas,
    esta política rechazará la petición. El caso típico es la presencia de
    User-Agent dentro de Vary, lo cual es probable que provoque una condición
    de denegación de servicio a una caché.</dd>

    <dt><strong><a href="../compliance.html#policyvalidation">
    POLICY_VALIDATION</a></strong>: Exige la presencia de Etag y/o
    Last-Modified</dt>
    <dd>La capacidad de una caché para determinar si una entidad cacheada
    puede refrescarse depende de que esté presente una cabecera Etag y/o
    Last-Modified válida frente a la que revalidar. La ausencia de ambas
    cabeceras, o la sintaxis inválida de una de ellas, hará que esta política
    se rechace.</dd>

    <dt><strong><a href="../compliance.html#policyconditional">
    POLICY_CONDITIONAL</a></strong>: Exige el funcionamiento correcto de las
    peticiones condicionales</dt>
    <dd>Cuando hay cabeceras condicionales presentes en la petición, un
    servidor debería responder con un <code>304 Not Modified</code> o
    <code>412 Precondition Failed</code> cuando corresponda. Un servidor puede
    ignorar las cabeceras condicionales, y esto afecta a la eficiencia del
    mecanismo de caché HTTP. Esta política rechaza las peticiones en las que
    está presente una cabecera condicional, se esperaba un código de respuesta
    304 o 412, pero se obtuvo en su lugar una respuesta 2xx.</dd>

    <dt><strong><a href="../compliance.html#policynocache">POLICY_NOCACHE</a>
    </strong>: Exige respuestas cacheables</dt>
    <dd>Cuando se encuentra una respuesta que se declara explícitamente no
    cacheable, se rechaza la petición. Una respuesta se considera no cacheable
    si especifica cualquiera de los siguientes elementos:
    <ul><li><code>Cache-Control: no-cache</code></li>
    <li><code>Pragma: no-cache</code></li>
    <li><code>Cache-Control: no-store</code></li>
    <li><code>Cache-Control: private</code></li>
    </ul></dd>

    <dt><strong><a href="../compliance.html#policymaxage">POLICY_MAXAGE</a>
    </strong>: Exige una maxage mínima</dt>
    <dd>Cuando se encuentra una respuesta en la que el tiempo de vida de
    frescura es menor que el valor dado, o el tiempo de vida de frescura es
    heurístico, se rechaza la petición. Una respuesta se comprueba en el
    siguiente orden:
    <ul><li>Si <code>s-maxage</code> está presente pero es demasiado pequeño; o</li>
    <li>Si <code>max-age</code> está presente pero es demasiado pequeño; o</li>
    <li>Si <code>Expires</code> está presente y no es válido; o</li>
    <li><code>Date</code> está presente y no es válido; o</li>
    <li><code>Expires</code> menos Date es demasiado pequeño; o</li>
    <li>No se ha declarado <code>s-maxage</code>, <code>maxage</code>, ni
    <code>Expires</code>/<code>Date</code> en absoluto</li>
    </ul></dd>

    <dt><strong><a href="../compliance.html#policyversion">POLICY_VERSION</a>
    </strong>: Exige una versión mínima de HTTP dentro de una petición</dt>
    <dd>Cuando se encuentra una petición con un número de versión HTTP menor
    que la versión mínima requerida, se rechaza la petición. Se reconocen los
    siguientes números de versión:
    <ul><li><code>HTTP/1.1</code></li>
    <li><code>HTTP/1.0</code></li>
    <li><code>HTTP/0.9</code></li>
    </ul></dd>

    </dl>

</section>

<section id="example">
    <title>Ejemplo de configuración</title>

    <p>Una configuración típica que protege un servidor que sirve contenido
    estático podría ser la siguiente:</p>

    <highlight language="config">
&lt;Location "/"&gt;
  SetOutputFilter POLICY_TYPE;POLICY_LENGTH;POLICY_KEEPALIVE;POLICY_VARY;POLICY_VALIDATION; \
    POLICY_CONDITIONAL;POLICY_NOCACHE;POLICY_MAXAGE;POLICY_VERSION

  # el tipo de contenido debe estar presente y ser válido, pero puede ser cualquiera
  PolicyType enforce */*

  # rechazar si no se declara explícitamente una longitud de contenido
  PolicyLength enforce

  # cubierto por el filtro de longitud de la política
  PolicyKeepalive ignore

  # rechazar si User-Agent aparece dentro de las cabeceras Vary
  PolicyVary enforce User-Agent

  # queremos exigir la validación
  PolicyValidation enforce

  # las respuestas condicionales no funcionales deben rechazarse
  PolicyConditional enforce

  # las respuestas no-cache deben rechazarse
  PolicyNocache enforce

  # maxage debe ser de al menos un día
  PolicyMaxage enforce 86400

  # la versión de la petición puede ser cualquiera
  PolicyVersion ignore HTTP/1.1
&lt;/Location&gt;

# suprimir la protección de política para server-status
&lt;Location "/server-status"&gt;
  PolicyFilter off
&lt;/Location&gt;
    </highlight>

</section>

<directivesynopsis>

<name>PolicyFilter</name>
<description>Activa o desactiva las políticas para el espacio de URL dado.</description>
<syntax>PolicyFilter <var>on|off</var></syntax>
<default>on</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>
<compatibility>PolicyFilter solo está disponible en Apache 2.5.0 y
posteriores.</compatibility>

<usage>
    <p>Interruptor maestro para activar o desactivar las políticas para un
    espacio de URL dado.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
# activado por defecto
&lt;Location "/"&gt;
  PolicyFilter on
&lt;/Location&gt;

# suprimir la protección de política para server-status
&lt;Location "/server-status"&gt;
  PolicyFilter off
&lt;/Location&gt;
</highlight>
    </example>
</usage>

</directivesynopsis>

<directivesynopsis>

<name>PolicyEnvironment</name>
<description>Modifica las políticas en función de una variable de entorno.</description>
<syntax>PolicyEnvironment <var>variable</var> <var>log-value</var> <var>ignore-value</var></syntax>
<default>none</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>
<compatibility>PolicyEnvironment solo está disponible en Apache 2.5.0 y
posteriores.</compatibility>

<usage>
    <p>Degrada las políticas a solo registro o a ser ignoradas en función de
    la presencia de una variable de entorno. Si la variable dada está presente
    y es igual al valor de log-value, las políticas exigidas se registrarán en
    su lugar. Si la variable dada está presente y es igual al valor de
    ignore-value, todas las políticas se ignorarán.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
# degradar si POLICY_CONTROL estaba presente
PolicyEnvironment POLICY_CONTROL log ignore
    </highlight>
    </example>
</usage>

</directivesynopsis>

<directivesynopsis>

<name>PolicyConditional</name>
<description>Activa la política de peticiones condicionales.</description>
<syntax>PolicyConditional <var>ignore|log|enforce</var></syntax>
<default>ignore</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>
<compatibility>PolicyConditional solo está disponible en Apache 2.5.0 y
posteriores.</compatibility>

<usage>
    <p>Cuando se registra o se exige, se rechazará una respuesta que debería
    haber sido condicional pero no lo fue.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
# las respuestas condicionales no funcionales deben rechazarse
PolicyConditional enforce
    </highlight>
    </example>
</usage>

</directivesynopsis>

<directivesynopsis>

<name>PolicyConditionalURL</name>
<description>URL que describe la política de peticiones condicionales.</description>
<syntax>PolicyConditionalURL <var>url</var></syntax>
<default>none</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>
<compatibility>PolicyConditionalURL solo está disponible en Apache 2.5.0 y
posteriores.</compatibility>

<usage>
    <p>Especifica la URL de la documentación que describe la política de
    peticiones condicionales, para que aparezca dentro de los mensajes de
    error.</p>
</usage>

</directivesynopsis>

<directivesynopsis>

<name>PolicyLength</name>
<description>Activa la política de longitud de contenido.</description>
<syntax>PolicyLength <var>ignore|log|enforce</var></syntax>
<default>ignore</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>
<compatibility>PolicyLength solo está disponible en Apache 2.5.0 y
posteriores.</compatibility>

<usage>
    <p>Cuando se registra o se exige, se rechazará una respuesta que carezca
    de una cabecera <code>Content-Length</code> explícita.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
# la ausencia de cabecera Content-Length debe rechazarse
PolicyLength enforce
    </highlight>
    </example>
</usage>

</directivesynopsis>

<directivesynopsis>

<name>PolicyLengthURL</name>
<description>URL que describe la política de longitud de contenido.</description>
<syntax>PolicyLengthURL <var>url</var></syntax>
<default>none</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>
<compatibility>PolicyLengthURL solo está disponible en Apache 2.5.0 y
posteriores.</compatibility>

<usage>
    <p>Especifica la URL de la documentación que describe la política de
    longitud de contenido, para que aparezca dentro de los mensajes de
    error.</p>
</usage>

</directivesynopsis>

<directivesynopsis>

<name>PolicyKeepalive</name>
<description>Activa la política de keepalive.</description>
<syntax>PolicyKeepalive <var>ignore|log|enforce</var></syntax>
<default>ignore</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>
<compatibility>PolicyKeepalive solo está disponible en Apache 2.5.0 y
posteriores.</compatibility>

<usage>
    <p>Cuando se registra o se exige, se rechazará una respuesta que carezca
    tanto de una cabecera <code>Content-Length</code> explícita como de un
    <code>Transfer-Encoding</code> igual a <code>chunked</code>.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
# la ausencia de Content-Length o Transfer-Encoding debe rechazarse
PolicyKeepalive enforce
</highlight>
    </example>
</usage>

</directivesynopsis>

<directivesynopsis>

<name>PolicyKeepaliveURL</name>
<description>URL que describe la política de keepalive.</description>
<syntax>PolicyKeepaliveURL <var>url</var></syntax>
<default>none</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>
<compatibility>PolicyKeepaliveURL solo está disponible en Apache 2.5.0 y
posteriores.</compatibility>

<usage>
    <p>Especifica la URL de la documentación que describe la política de
    keepalive, para que aparezca dentro de los mensajes de error.</p>
</usage>

</directivesynopsis>

<directivesynopsis>

<name>PolicyType</name>
<description>Activa la política de tipo de contenido.</description>
<syntax>PolicyType <var>ignore|log|enforce</var> <var>type</var> [ <var>type</var> [ ... ]]</syntax>
<default>ignore</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>
<compatibility>PolicyType solo está disponible en Apache 2.5.0 y
posteriores.</compatibility>

<usage>
    <p>Cuando se registra o se exige, se rechazará una respuesta que carezca
    de una cabecera <code>Content-Type</code>, en la que la cabecera
    <code>Content-Type</code> esté mal formada, o en la que la cabecera no
    coincida con el patrón o patrones dados.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
# exigir json o XML
PolicyType enforce application/json text/xml
    </highlight>
    </example>

    <example><title>Ejemplo</title>
    <highlight language="config">
# un tipo de contenido mal formado debe rechazarse
PolicyType enforce */*
    </highlight>
    </example>

</usage>

</directivesynopsis>

<directivesynopsis>

<name>PolicyTypeURL</name>
<description>URL que describe la política de tipo de contenido.</description>
<syntax>PolicyTypeURL <var>url</var></syntax>
<default>none</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>
<compatibility>PolicyTypeURL solo está disponible en Apache 2.5.0 y
posteriores.</compatibility>

<usage>
    <p>Especifica la URL de la documentación que describe la política de tipo
    de contenido, para que aparezca dentro de los mensajes de error.</p>
</usage>

</directivesynopsis>

<directivesynopsis>

<name>PolicyVary</name>
<description>Activa la política de Vary.</description>
<syntax>PolicyVary <var>ignore|log|enforce</var> <var>header</var> [ <var>header</var> [ ... ]]</syntax>
<default>ignore</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>
<compatibility>PolicyVary solo está disponible en Apache 2.5.0 y
posteriores.</compatibility>

<usage>
    <p>Cuando se registra o se exige, se rechazará una respuesta que contenga
    una cabecera <code>Vary</code> que a su vez contenga alguna de las
    cabeceras indicadas.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
# rechazar respuestas con "User-Agent" en la cabecera Vary
PolicyVary enforce User-Agent
    </highlight>
    </example>

</usage>

</directivesynopsis>

<directivesynopsis>

<name>PolicyVaryURL</name>
<description>URL que describe la política de tipo de contenido.</description>
<syntax>PolicyVaryURL <var>url</var></syntax>
<default>none</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>
<compatibility>PolicyVaryURL solo está disponible en Apache 2.5.0 y
posteriores.</compatibility>

<usage>
    <p>Especifica la URL de la documentación que describe la política de
    vary, para que aparezca dentro de los mensajes de error.</p>
</usage>

</directivesynopsis>

<directivesynopsis>

<name>PolicyValidation</name>
<description>Activa la política de validación.</description>
<syntax>PolicyValidation <var>ignore|log|enforce</var></syntax>
<default>ignore</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>
<compatibility>PolicyValidation solo está disponible en Apache 2.5.0 y
posteriores.</compatibility>

<usage>
    <p>Cuando se registra o se exige, se rechazará una respuesta que carezca
    de una cabecera <code>ETag</code> válida o de una cabecera
    <code>Last-Modified</code>, o en la que cualquiera de ellas sea
    sintácticamente incorrecta.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
# la ausencia de ETag o Last-Modified se rechazará
PolicyValidation enforce
    </highlight>
    </example>

</usage>

</directivesynopsis>

<directivesynopsis>

<name>PolicyValidationURL</name>
<description>URL que describe la política de tipo de contenido.</description>
<syntax>PolicyValidationURL <var>url</var></syntax>
<default>none</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>
<compatibility>PolicyValidationURL solo está disponible en Apache 2.5.0 y
posteriores.</compatibility>

<usage>
    <p>Especifica la URL de la documentación que describe la política de
    validación, para que aparezca dentro de los mensajes de error.</p>
</usage>

</directivesynopsis>

<directivesynopsis>

<name>PolicyNocache</name>
<description>Activa la política de no-cache en el cacheo.</description>
<syntax>PolicyNocache <var>ignore|log|enforce</var></syntax>
<default>ignore</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>
<compatibility>PolicyNocache solo está disponible en Apache 2.5.0 y
posteriores.</compatibility>

<usage>
    <p>Cuando se registra o se exige, se rechazará una respuesta que se
    declare a sí misma no cacheable mediante las cabeceras
    <code>Cache-Control</code> o <code>Pragma</code>.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
# Cache-Control: no-cache se rechazará
PolicyNocache enforce
    </highlight>
    </example>

</usage>

</directivesynopsis>

<directivesynopsis>

<name>PolicyNocacheURL</name>
<description>URL que describe la política de no-cache en el cacheo.</description>
<syntax>PolicyNocacheURL <var>url</var></syntax>
<default>none</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>
<compatibility>PolicyNocacheURL solo está disponible en Apache 2.5.0 y
posteriores.</compatibility>

<usage>
    <p>Especifica la URL de la documentación que describe la política de
    no-cache en el cacheo, para que aparezca dentro de los mensajes de
    error.</p>
</usage>

</directivesynopsis>

<directivesynopsis>

<name>PolicyMaxage</name>
<description>Activa la política de max-age mínima en el cacheo.</description>
<syntax>PolicyMaxage <var>ignore|log|enforce</var> <var>age</var></syntax>
<default>ignore</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>
<compatibility>PolicyMaxage solo está disponible en Apache 2.5.0 y
posteriores.</compatibility>

<usage>
    <p>Cuando se registra o se exige, se rechazará una respuesta que carezca
    de un tiempo de vida de frescura explícito definido con
    <code>max-age</code>, <code>s-maxage</code> o una cabecera
    <code>Expires</code>, o en la que el tiempo de vida de frescura explícito
    sea menor que el valor dado.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
# rechazar respuestas con un tiempo de vida de frescura menor a un día
PolicyMaxage enforce 86400
    </highlight>
    </example>

</usage>

</directivesynopsis>

<directivesynopsis>

<name>PolicyMaxageURL</name>
<description>URL que describe la política de tiempo mínimo de frescura en el cacheo.</description>
<syntax>PolicyMaxageURL <var>url</var></syntax>
<default>none</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>
<compatibility>PolicyMaxageURL solo está disponible en Apache 2.5.0 y
posteriores.</compatibility>

<usage>
    <p>Especifica la URL de la documentación que describe la política de
    tiempo mínimo de frescura en el cacheo, para que aparezca dentro de los
    mensajes de error.</p>
</usage>

</directivesynopsis>

<directivesynopsis>

<name>PolicyVersion</name>
<description>Activa la política de versión.</description>
<syntax>PolicyVersion <var>ignore|log|enforce</var> <var>HTTP/0.9|HTTP/1.0|HTTP/1.1</var></syntax>
<default>ignore</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>
<compatibility>PolicyVersion solo está disponible en Apache 2.5.0 y
posteriores.</compatibility>

<usage>
    <p>Cuando se registra o se exige, se rechazará una petición con una
    versión inferior a la especificada.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
# rechazar peticiones con una versión de HTTP anterior a HTTP/1.1
PolicyVersion enforce HTTP/1.1
    </highlight>
    </example>

</usage>

</directivesynopsis>

<directivesynopsis>

<name>PolicyVersionURL</name>
<description>URL que describe la política de versión mínima de HTTP en las peticiones.</description>
<syntax>PolicyVersionURL <var>url</var></syntax>
<default>none</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>
<compatibility>PolicyVersionURL solo está disponible en Apache 2.5.0 y
posteriores.</compatibility>

<usage>
    <p>Especifica la URL de la documentación que describe la política de
    versión mínima de HTTP en las peticiones, para que aparezca dentro de los
    mensajes de error.</p>
</usage>

</directivesynopsis>

</modulesynopsis>
