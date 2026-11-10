<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1939346 -->
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

<modulesynopsis metafile="mod_logio.xml.meta">

<name>mod_logio</name>
<description>Registro de los bytes de entrada y salida por petición</description>
<status>Extension</status>
<sourcefile>mod_logio.c</sourcefile>
<identifier>logio_module</identifier>

<summary>

    <p>Este módulo proporciona el registro del número de bytes de entrada y
    salida recibidos/enviados por petición. Las cifras reflejan los bytes reales
    tal como se recibieron en la red, lo que tiene en cuenta las
    cabeceras y los cuerpos de las peticiones y respuestas. El conteo se realiza
    antes de SSL/TLS en la entrada y después de SSL/TLS en la salida, de modo que las cifras
    reflejarán correctamente cualquier cambio introducido por el cifrado.</p>

    <p>Este módulo requiere <module>mod_log_config</module>.</p>

    <note>Cuando se usan conexiones KeepAlive con SSL, la sobrecarga del
    handshake SSL se refleja en el conteo de bytes de la primera petición de la
    conexión. Cuando se produce una renegociación SSL por directorio, los bytes se asocian
    con la petición que provocó la renegociación.</note>

</summary>

<seealso><module>mod_log_config</module></seealso>
<seealso><a href="../logs.html">Archivos de log de Apache</a></seealso>

<section id="formats">
<title>Formatos de log personalizados</title>

    <p>Este módulo añade tres nuevas directivas de registro. Las características de la
    propia petición se registran colocando directivas "<code>%</code>" en
    la cadena de formato, que se sustituyen en el archivo de log por los valores
    siguientes:</p>

    <table border="1" style="zebra">
    <tr><th>Cadena&nbsp;de&nbsp;formato</th>
        <th>Descripción</th></tr>

    <tr><td><code>%I</code></td>
        <td>Bytes recibidos, incluidas la petición y las cabeceras; no puede
        ser cero.</td></tr>

    <tr><td><code>%O</code></td>
        <td>Bytes enviados, incluidas las cabeceras. Puede ser cero en casos raros,
        como cuando una petición se interrumpe antes de enviar una respuesta.</td></tr>

    <tr><td><code>%S</code></td>
        <td>Bytes transferidos (recibidos y enviados), incluidas la petición y las cabeceras,
        no puede ser cero. Es la combinación de %I y %O.<br />
        Disponible en Apache 2.4.7 y posteriores</td></tr>

    <tr><td><code>%^FU</code></td>
        <td>Retardo en microsegundos entre la llegada de la petición y la lectura del
        último byte del cuerpo de la petición (fin de la subida).
        Solo disponible si <directive>LogIOTrackTTFU</directive> está establecida en
        ON. Si el seguimiento no está activado, o nunca se llegó a leer el último byte
        del cuerpo de la petición (por ejemplo, la petición se interrumpió antes de que
        terminara la subida), el valor registrado es <code>-</code>.<br />
        Disponible en Apache 2.5.1 y posteriores</td></tr>

    <tr><td><code>%^FB</code></td>
        <td>Retardo en microsegundos entre la llegada de la petición y la escritura del
        primer byte de las cabeceras de la respuesta. Solo disponible si
        <directive>LogIOTrackTTFB</directive> está establecida en ON. Si el seguimiento
        no está activado, o nunca se llegó a escribir el primer byte de las cabeceras
        de la respuesta (por ejemplo, la petición se interrumpió antes de escribir
        ninguna cabecera de respuesta), el valor registrado es <code>-</code>.<br />
        Disponible en Apache 2.4.13 y posteriores</td></tr>
    </table>

    <p>Normalmente, esta funcionalidad se usa así:</p>

    <dl>
      <dt>Formato de log combinado de E/S:</dt>
      <dd><code>"%h %l %u %t \"%r\" %&gt;s %b \"%{Referer}i\"
      \"%{User-agent}i\" %I %O"</code></dd>
    </dl>
</section>

<directivesynopsis>
<name>LogIOTrackTTFU</name>
<description>Activa el seguimiento del tiempo hasta el último byte de la petición (TTFU = time to
finish upload)</description>
<syntax>LogIOTrackTTFU ON|OFF</syntax>
<default>LogIOTrackTTFU OFF</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>All</override>
<compatibility>Apache HTTP Server 2.5.1 y posteriores</compatibility>

<usage>
    <p>Esta directiva configura si este módulo registra el retardo
    entre la lectura de la petición y la lectura del último byte del cuerpo
    de la petición (fin de la subida). El valor resultante puede registrarse
    con el formato <code>%^FU</code>.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>LogIOTrackTTFB</name>
<description>Activa el seguimiento del tiempo hasta el primer byte (TTFB = time to first byte)
</description>
<syntax>LogIOTrackTTFB ON|OFF</syntax>
<default>LogIOTrackTTFB OFF</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>All</override>
<compatibility>Apache HTTP Server 2.4.13 y posteriores</compatibility>

<usage>
    <p>Esta directiva configura si este módulo registra el retardo
    entre la lectura de la petición y la escritura del primer byte de las cabeceras
    de la respuesta. El valor resultante puede registrarse con el
    formato <code>%^FB</code>.</p>
</usage>
</directivesynopsis>

</modulesynopsis>
