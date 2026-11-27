<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933180 -->
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

<modulesynopsis metafile="mod_proxy_http.xml.meta">

<name>mod_proxy_http</name>
<description>Módulo de soporte HTTP para
<module>mod_proxy</module></description>
<status>Extension</status>
<sourcefile>mod_proxy_http.c</sourcefile>
<identifier>proxy_http_module</identifier>

<summary>
    <p>Este módulo <em>requiere</em> el servicio de <module
    >mod_proxy</module>. Proporciona las funcionalidades usadas para
    hacer de proxy de peticiones HTTP y HTTPS. <module>mod_proxy_http</module>
    admite HTTP/0.9, HTTP/1.0 y HTTP/1.1. <em>No</em>
    proporciona ninguna capacidad de caché. Si desea configurar un proxy
    con caché, puede que le interese usar el servicio adicional del
    módulo <module>mod_cache</module>.</p>

    <p>Por lo tanto, para tener la capacidad de gestionar peticiones de proxy HTTP,
    <module>mod_proxy</module> y <module>mod_proxy_http</module>
    deben estar presentes en el servidor.</p>

    <note type="warning"><title>Aviso</title>
      <p>No active el proxy hasta que haya <a
      href="mod_proxy.html#access">asegurado su servidor</a>. Los servidores proxy
      abiertos son peligrosos tanto para su red como para Internet en
      general.</p>
    </note>
</summary>
<seealso><module>mod_proxy</module></seealso>
<seealso><module>mod_proxy_connect</module></seealso>

<section id="env"><title>Variables de entorno</title>
    <p>Además de las directivas de configuración que controlan el
    comportamiento de <module>mod_proxy</module>, hay una serie de
    <dfn>variables de entorno</dfn> que controlan el proveedor del protocolo HTTP.
    Las variables de entorno siguientes que no especifican valores concretos
    se activan al establecerse con cualquier valor.</p>
    <dl>
        <dt>proxy-sendextracrlf</dt>
        <dd>Hace que el proxy envíe un salto de línea CR-LF adicional al final de una
        petición. Esto es una solución alternativa para un error de algunos navegadores.</dd>
        <dt>force-proxy-request-1.0</dt>
        <dd>Fuerza al proxy a enviar las peticiones al backend como HTTP/1.0
        y desactiva las funcionalidades de HTTP/1.1.</dd>
        <dt>proxy-nokeepalive</dt>
        <dd>Fuerza al proxy a cerrar la conexión con el backend después de
        cada petición.</dd>
        <dt>proxy-chain-auth</dt>
        <dd>Si el proxy requiere autenticación, leerá y
        consumirá las credenciales de autenticación de proxy enviadas por el cliente.
        Con <var>proxy-chain-auth</var> <em>también</em> reenviará
        las credenciales al siguiente proxy de la cadena. Esto puede
        ser necesario si tiene una cadena de proxies que comparten
        información de autenticación. <strong>Aviso de seguridad:</strong>
        No establezca esto a menos que sepa que lo necesita, ya que reenvía
        información sensible.</dd>
        <dt>proxy-sendcl</dt>
        <dd>HTTP/1.0 requería que todas las peticiones HTTP que incluyen un cuerpo
        (por ejemplo, peticiones POST) incluyeran una cabecera <var>Content-Length</var>.
        Esta variable de entorno fuerza al proxy de Apache a
        enviar esta cabecera al servidor de backend, independientemente de lo que
        haya enviado el cliente al proxy. Garantiza la compatibilidad al
        hacer de proxy para un backend HTTP/1.0 o desconocido. Sin embargo,
        puede requerir que toda la petición se almacene en el búfer del proxy,
        por lo que resulta muy ineficiente para peticiones grandes.</dd>
        <dt>proxy-sendchunks o proxy-sendchunked</dt>
        <dd>Esto es lo contrario de <var>proxy-sendcl</var>. Permite que
        los cuerpos de las peticiones se envíen al backend usando codificación de
        transferencia fragmentada (chunked). Esto permite transmitir la petición de forma eficiente,
        pero requiere que el servidor de backend admita HTTP/1.1.</dd>
        <dt>proxy-interim-response</dt>
        <dd>Esta variable admite los valores <code>RFC</code> (el valor por defecto) o
        <code>Suppress</code>. Las versiones anteriores de httpd suprimían
        las respuestas provisionales HTTP (1xx) enviadas desde el backend. Esto es
        técnicamente una violación del protocolo HTTP. En la práctica,
        si un backend envía una respuesta provisional, puede que esté
        extendiendo el protocolo de una manera que no conocemos,
        o que simplemente esté funcionando mal. Por eso ahora es configurable: establezca
        <code>proxy-interim-response RFC</code> para cumplir totalmente con el
        protocolo, o <code>proxy-interim-response Suppress</code>
        para suprimir las respuestas provisionales.</dd>
        <dt>proxy-initial-not-pooled</dt>
        <dd>Si se establece esta variable, no se reutilizará ninguna conexión agrupada
        si la petición del cliente es la petición inicial en la conexión del frontend. Esto evita
        el mensaje de error "proxy: error reading status line from remote server"
        provocado por la condición de carrera en la que el servidor de backend cierra la
        conexión agrupada después de la comprobación de conexión por parte del proxy y
        antes de que los datos enviados por el proxy lleguen al backend. Hay que tener
        en cuenta que establecer esta variable reduce el rendimiento,
        especialmente con clientes HTTP/1.0.
        </dd>
    </dl>
</section>

<section id="notes"><title>Notas de la petición</title>
    <p><module>mod_proxy_http</module> crea las siguientes notas de petición para
        el registro, usando el formato <code>%{VARNAME}n</code> en
        <directive module="mod_log_config">LogFormat</directive> o
        <directive module="core">ErrorLogFormat</directive>:
    </p>
    <dl>
        <dt>proxy-source-port</dt>
        <dd>El puerto local usado para la conexión con el servidor de backend.</dd>
        <dt>proxy-status</dt>
        <dd>El estado HTTP recibido del servidor de backend.</dd>
    </dl>
</section>

</modulesynopsis>
