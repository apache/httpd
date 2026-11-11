<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1855413 -->
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

<modulesynopsis metafile="mod_reqtimeout.xml.meta">

<name>mod_reqtimeout</name>
<description>Establece el tiempo de espera y la tasa mínima de datos para recibir peticiones
</description>
<status>Extension</status>
<sourcefile>mod_reqtimeout.c</sourcefile>
<identifier>reqtimeout_module</identifier>
<compatibility>Disponible en Apache HTTPD 2.2.15 y posteriores</compatibility>

<summary>
    <p>Este módulo proporciona una forma sencilla de establecer tiempos de espera y tasas
    mínimas de datos para recibir peticiones. Si se produce un tiempo de espera o una tasa
    de datos es demasiado baja, el servidor cerrará la conexión correspondiente.</p>

    <p>Esto se registra con <directive module="core">LogLevel</directive>
    <code>info</code>.</p>

    <p>Si es necesario, la directiva <directive module="core">LogLevel</directive>
    puede ajustarse para registrarlo explícitamente:</p>
    <highlight language="config">
      LogLevel reqtimeout:info
    </highlight>
</summary>

<section id="examples"><title>Ejemplos</title>

    <ol>
      <li>
        Permitir 5 segundos para completar el handshake TLS, 10 segundos para
        recibir las cabeceras de la petición y 30 segundos para recibir el
        cuerpo de la petición:

        <highlight language="config">
          RequestReadTimeout handshake=5 header=10 body=30
        </highlight>
      </li>

      <li>
        Permitir al menos 10 segundos para recibir el cuerpo de la petición.
        Si el cliente envía datos, aumentar el tiempo de espera 1 segundo por cada
        1000 bytes recibidos, sin límite superior para el tiempo de espera (salvo
        el límite dado indirectamente por
        <directive module="core">LimitRequestBody</directive>):

        <highlight language="config">
          RequestReadTimeout body=10,MinRate=1000
        </highlight>
      </li>

      <li>
        Permitir al menos 10 segundos para recibir las cabeceras de la petición.
        Si el cliente envía datos, aumentar el tiempo de espera 1 segundo por cada
        500 bytes recibidos. Pero no permitir más de 30 segundos para las
        cabeceras de la petición:

        <highlight language="config">
          RequestReadTimeout header=10-30,MinRate=500
        </highlight>
      </li>

      <li>
        Normalmente, un servidor debería tener configurados tanto el tiempo de espera de
        cabeceras como el de cuerpo. Si se usa una configuración común para los virtual
        hosts http y https, los tiempos de espera no deberían establecerse demasiado bajos:

        <highlight language="config">
          RequestReadTimeout header=20-40,MinRate=500 body=20,MinRate=500
        </highlight>
      </li>

    </ol>
</section>

<directivesynopsis>
<name>RequestReadTimeout</name>
<description>Establece los valores de tiempo de espera para completar el handshake TLS, recibir
las cabeceras y/o el cuerpo de la petición del cliente.
</description>
<syntax>RequestReadTimeout
[handshake=<var>timeout</var>[-<var>maxtimeout</var>][,MinRate=<var>rate</var>]
[header=<var>timeout</var>[-<var>maxtimeout</var>][,MinRate=<var>rate</var>]
[body=<var>timeout</var>[-<var>maxtimeout</var>][,MinRate=<var>rate</var>]
</syntax>
<default>RequestReadTimeout handshake=0 header=20-40,MinRate=500 body=20,MinRate=500</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>
<compatibility>Disponible en la versión 2.2.15 y posteriores; deshabilitado por
defecto en la versión 2.3.14 y anteriores. La etapa <code>handshake</code>
está disponible desde la versión 2.4.39.
</compatibility>

<usage>
    <p>Esta directiva puede establecer varios tiempos de espera para completar el handshake TLS,
    recibir las cabeceras de la petición y/o el cuerpo de la petición del cliente.
    Si el cliente no completa cada una de estas etapas dentro del tiempo
    configurado, se envía un error <code>408 REQUEST TIME OUT</code>.</p>

    <p>Para los virtual hosts SSL, el valor del tiempo de espera de <code>handshake</code> es el tiempo
    necesario para realizar el handshake SSL inicial. Si el navegador del usuario está configurado para
    consultar listas de revocación de certificados y el servidor CRL no está accesible, el
    handshake SSL inicial puede tardar un tiempo considerable hasta que el navegador deje de
    esperar la CRL. Por lo tanto, el tiempo de espera de <code>handshake</code> debería tener en cuenta
    esta posible sobrecarga para los virtual hosts SSL (si es necesario).
    Los valores del tiempo de espera del cuerpo incluyen el tiempo necesario para la renegociación SSL
    (si es necesario).</p>

    <p>Cuando se usa un <directive module="core">AcceptFilter</directive>
    (normalmente el caso en Linux y FreeBSD), el socket no se envía al
    proceso del servidor hasta que se recibe al menos un byte (o toda la petición para
    <code>httpready</code>). Los tiempos de espera de handshake y de cabeceras
    configurados con <directive>RequestReadTimeout</directive> solo son efectivos
    después de que el proceso del servidor haya recibido el socket.</p>

    <p>Para cada una de las tres etapas de tiempo de espera (handshake, cabecera o cuerpo), hay
    tres formas de especificar el tiempo de espera:
    </p>

    <ul>

    <li><strong>Valor de tiempo de espera fijo</strong>:<br />

    <example><var>stage</var>=<var>timeout</var></example>

    <p>El tiempo en segundos permitido para completar toda la etapa (handshake,
    lectura de todas las cabeceras o el cuerpo de la petición). Un valor de 0 significa sin límite.</p>
    </li>

    <li><strong>Deshabilitar el módulo para un vhost</strong>:<br />

    <example>handshake=0 header=0 body=0</example>

    <p>Esto deshabilita completamente <module>mod_reqtimeout</module> (tenga en cuenta que
    <code>handshake=0</code> ya es el valor por defecto y podría omitirse).</p>
    </li>

    <li><strong>Valor de tiempo de espera que aumenta cuando se reciben
    datos</strong>:<br />
    <example>
    <var>stage</var>=<var>timeout</var>,MinRate=<var>data_rate</var>
    </example>

    <p>Igual que lo anterior, pero cada vez que se reciben datos, el valor del tiempo de espera se
    incrementa de acuerdo con la tasa mínima de datos especificada (en bytes por
    segundo).</p>
    </li>

    <li><strong>Valor de tiempo de espera que aumenta cuando se reciben datos, con un
    límite superior</strong>:<br />
    <example>
    <var>stage</var>=<var>timeout</var>-<var>maxtimeout</var>,MinRate=<var>data_rate</var>
    </example>

    <p>Igual que lo anterior, pero el tiempo de espera no se incrementará por encima del segundo
    valor del rango de tiempo de espera especificado.</p>
    </li>

    </ul>

</usage>

</directivesynopsis>

</modulesynopsis>
