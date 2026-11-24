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

<modulesynopsis metafile="mod_firehose.xml.meta">

<name>mod_firehose</name>
<description>Multiplexa toda la E/S hacia un archivo o tubería dados.</description>
<status>Extension</status>
<sourcefile>mod_firehose.c</sourcefile>
<identifier>firehose_module</identifier>

<summary>
    <p><code>mod_firehose</code> proporciona un mecanismo para registrar los datos
    que se intercambian entre el servidor httpd y el cliente, a nivel de conexión
    en bruto, hacia un archivo o una tubería, de forma que los
    datos se puedan analizar o reproducir de nuevo contra el servidor en el futuro.
    Se puede pensar en él como un "tcpdump para httpd".</p>

    <p>Las conexiones se registran después de haberse eliminado el SSL, y se pueden
    usar para depuración forense.</p>

    <p>La herramienta <program>firehose</program> se puede usar para demultiplexar
    el flujo registrado de vuelta a archivos individuales para su análisis, o para
    reproducirlo usando una herramienta como <code>netcat</code>.</p>

    <note><title>AVISO</title>Este módulo IGNORA todos los mecanismos a nivel de
    petición para mantener los datos privados. Es responsabilidad del
    administrador asegurarse de que no se exponen datos privados de forma
    involuntaria al usar este módulo.
    </note>

</summary>
<seealso><program>firehose</program></seealso>

<section id="enable">
    <title>Activar un Firehose</title>

    <p>Para activar el módulo, debe compilarse y cargarse
    en su configuración de Apache en ejecución, y usar las directivas de abajo
    para registrar los datos que le interesen.</p>

    <p>Es posible registrar tanto los datos entrantes como los salientes en
    el mismo nombre de archivo si se desea, ya que la dirección del flujo se registra
    dentro de cada fragmento.</p>

    <p>Es posible escribir tanto en archivos normales como en fifos (tuberías).
    En el caso de las fifos, mod_firehose se asegura de que el tamaño del paquete
    no sea mayor que PIPE_BUF, para garantizar que las escrituras sean atómicas.</p>

    <p>Si se usa una tubería, algo debe estar leyendo de ella antes de que
    se inicie httpd para que la tubería se pueda abrir correctamente para
    escritura. Si la petición para abrir la tubería falla, mod_firehose se
    desactivará silenciosamente y no registrará nada, y el servidor seguirá
    funcionando con normalidad.</p>

    <p>Por defecto, todos los intentos de escritura bloquearán el servidor. Si el
    servidor web se ha compilado contra APR v2.0 o posterior, y se especifica el
    parámetro opcional "nonblock", todas las escrituras en archivo serán no
    bloqueantes, y los desbordamientos del búfer harán que se pierdan datos de
    depuración. En ese caso es posible priorizar el funcionamiento del servidor
    por encima del registro de los datos de firehose.</p>

</section>

<section id="format">
    <title>Formato del flujo</title>

    <p>Normalmente el servidor atiende varias conexiones simultáneamente,
    por lo que las peticiones y respuestas deben multiplexarse antes de
    escribirse en el firehose.</p>

    <p>El formato del fragmento está diseñado como texto claro, de modo que un firehose
    se pueda abrir e inspeccionar con un editor de texto normal.
    Alternativamente, se puede usar la herramienta <program>firehose</program> para
    demultiplexar el firehose de vuelta a peticiones o
    conexiones individuales.</p>

    <p>El tamaño de los fragmentos multiplexados está regido por PIPE_BUF,
    el tamaño máximo de escritura que el sistema está dispuesto a realizar
    de forma atómica. Al mantener los fragmentos multiplexados por debajo de PIPE_BUF en
    tamaño, el módulo garantiza que los datos de fragmentos distintos no se
    entrelacen. El tamaño de PIPE_BUF varía según el sistema
    operativo.</p>

    <p>La BNF del formato del fragmento es la siguiente:</p>

    <pre>
 stream = 0*(fragment)

 fragment = header CRLF body CRLF

 header = length SPC timestamp SPC ( request | response ) SPC uuid SPC count

 length = &lt;up to 16 byte hex fragment length>
 timestamp = &lt;up to 16 byte hex timestamp microseconds since 1970>
 request = "&lt;"
 response = ">"
 uuid = &lt;formatted uuid of the connection>
 count = &lt;hex fragment number in the connection>

 body = &lt;the binary content of the fragment>

 SPC = &lt;a single space>
 CRLF = &lt;a carriage return, followed by a line feed>
    </pre>

    <p>Todos los fragmentos de una conexión o de una petición compartirán el mismo
    UUID, dependiendo de si se registran conexiones o peticiones.
    Si se registran conexiones, pueden aparecer varias peticiones dentro de
    una misma conexión. Un fragmento de longitud cero indica el final de la
    conexión.</p>

    <p>Los fragmentos pueden perderse o descartarse si el proceso que los lee
    es demasiado lento. Si esto ocurre, aparecerán huecos en la numeración
    del contador de la conexión. Se registrará un aviso en el log de errores
    indicando el UUID y el contador del fragmento descartado, de forma que se
    pueda confirmar que el fragmento se descartó.</p>

    <p>Es posible que el fragmento vacío final no llegue a aparecer,
    por ejemplo si el proceso httpd falla, o se termina de forma abrupta.
    El fragmento final puede descartarse si el proceso que lee los
    fragmentos no es suficientemente rápido.</p>

</section>

<directivesynopsis>

<name>FirehoseConnectionInput</name>
<description>Captura el tráfico que entra al servidor en cada conexión</description>
<syntax>FirehoseConnectionInput <var>[ block | nonblock ]</var> <var>filename</var></syntax>
<default>none</default>
<contextlist><context>server config</context></contextlist>
<compatibility>FirehoseConnectionInput solo está disponible en Apache 2.5.0 y
posteriores.</compatibility>

<usage>
    <p>Captura el tráfico que entra al servidor en cada conexión. Se capturarán
    varias peticiones dentro de la misma conexión si hay keepalive
    presente.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
      FirehoseConnectionInput connection-input.firehose
      </highlight>
    </example>
</usage>

</directivesynopsis>

<directivesynopsis>

<name>FirehoseConnectionOutput</name>
<description>Captura el tráfico que sale del servidor en cada conexión</description>
<syntax>FirehoseConnectionOutput <var>[ block | nonblock ]</var> <var>filename</var></syntax>
<default>none</default>
<contextlist><context>server config</context></contextlist>
<compatibility>FirehoseConnectionOutput solo está disponible en Apache 2.5.0 y
posteriores.</compatibility>

<usage>
    <p>Captura el tráfico que sale del servidor en cada conexión.
    Se capturarán varias peticiones dentro de la misma conexión si hay
    keepalive presente.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
      FirehoseConnectionOutput connection-output.firehose
      </highlight>
    </example>
</usage>

</directivesynopsis>

<directivesynopsis>

<name>FirehoseRequestInput</name>
<description>Captura el tráfico que entra al servidor en cada petición</description>
<syntax>FirehoseRequestInput <var>[ block | nonblock ]</var> <var>filename</var></syntax>
<default>none</default>
<contextlist><context>server config</context></contextlist>
<compatibility>FirehoseRequestInput solo está disponible en Apache 2.5.0 y
posteriores.</compatibility>

<usage>
    <p>Captura el tráfico que entra al servidor en cada petición. Las peticiones
    se capturarán por separado, independientemente de la presencia de keepalive.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
      FirehoseRequestInput request-input.firehose
      </highlight>
    </example>
</usage>

</directivesynopsis>

<directivesynopsis>

<name>FirehoseRequestOutput</name>
<description>Captura el tráfico que sale del servidor en cada petición</description>
<syntax>FirehoseRequestOutput <var>[ block | nonblock ]</var> <var>filename</var></syntax>
<default>none</default>
<contextlist><context>server config</context></contextlist>
<compatibility>FirehoseRequestOutput solo está disponible en Apache 2.5.0 y
posteriores.</compatibility>

<usage>
    <p>Captura el tráfico que sale del servidor en cada petición. Las peticiones
    se capturarán por separado, independientemente de la presencia de keepalive.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
      FirehoseRequestOutput request-output.firehose
      </highlight>
    </example>
</usage>

</directivesynopsis>

<directivesynopsis>

<name>FirehoseProxyConnectionInput</name>
<description>Captura el tráfico que entra por la parte trasera de mod_proxy</description>
<syntax>FirehoseProxyConnectionInput <var>[ block | nonblock ]</var> <var>filename</var></syntax>
<default>none</default>
<contextlist><context>server config</context></contextlist>
<compatibility>FirehoseProxyConnectionInput solo está disponible en Apache 2.5.0 y
posteriores.</compatibility>

<usage>
    <p>Captura el tráfico que recibe mod_proxy.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
      FirehoseProxyConnectionInput proxy-input.firehose
      </highlight>
    </example>
</usage>

</directivesynopsis>

<directivesynopsis>

<name>FirehoseProxyConnectionOutput</name>
<description>Captura el tráfico que se envía desde la parte trasera de mod_proxy</description>
<syntax>FirehoseProxyConnectionOutput <var>[ block | nonblock ]</var> <var>filename</var></syntax>
<default>none</default>
<contextlist><context>server config</context></contextlist>
<compatibility>FirehoseProxyConnectionOutput solo está disponible en Apache 2.5.0 y
posteriores.</compatibility>

<usage>
    <p>Captura el tráfico que envía mod_proxy.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
      FirehoseProxyConnectionOutput proxy-output.firehose
      </highlight>
    </example>
</usage>

</directivesynopsis>

</modulesynopsis>
