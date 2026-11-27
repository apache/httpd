<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1850547 -->
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

<modulesynopsis metafile="mod_proxy_http2.xml.meta">

<name>mod_proxy_http2</name>
<description>Módulo de soporte HTTP/2 para
<module>mod_proxy</module></description>
<status>Extension</status>
<sourcefile>mod_proxy_http2.c</sourcefile>
<identifier>proxy_http2_module</identifier>
<compatibility>Disponible en httpd 2.4.19 y posteriores</compatibility>

<summary>
    <p><module>mod_proxy_http2</module>
    solo admite HTTP/2; <em>no</em>
    ofrece ninguna reducción a HTTP/1.1. Esto significa que el backend
    necesita admitir HTTP/2, porque en su lugar no se usará HTTP/1.1.</p>

    <p>Este módulo <em>requiere</em> el servicio de <module
    >mod_proxy</module>, por lo que, para tener la capacidad de
    gestionar peticiones de proxy HTTP/2,
    el servidor debe cargar tanto <module>mod_proxy</module> como
    <module>mod_proxy_http2</module>.</p>

    <p><module>mod_proxy_http2</module> funciona con peticiones entrantes
    que usan HTTP/1.1 o HTTP/2. En ambos casos, las peticiones que se
    envían al mismo backend se transmiten por una única conexión TCP
    siempre que sea posible (es decir, cuando la conexión se pueda reutilizar).</p>

    <p>Advertencia: no se intentará consolidar varias peticiones de frontend
    HTTP/1.1 (configuradas para enviarse como proxy al mismo backend)
    en flujos (streams) HTTP/2 pertenecientes a la misma petición HTTP/2.
    Cada petición de frontend HTTP/1.1 se enviará al backend como proxy mediante
    una petición HTTP/2 independiente (intentando reutilizar la misma conexión TCP
    si es posible).</p>

    <p>Este módulo se basa en <a href="http://nghttp2.org/">libnghttp2</a>
    para proporcionar el motor principal de http/2.</p>

    <note type="warning"><title>Aviso</title>
        <p>Este módulo es experimental. Su comportamiento, sus directivas y sus
        valores por defecto están sujetos a más cambios de una versión a
        otra que en otros módulos estándar. Se recomienda a los usuarios
        consultar el archivo "CHANGES" para posibles actualizaciones.</p>
    </note>

    <note type="warning"><title>Aviso</title>
      <p>No active el proxy hasta que haya <a
      href="mod_proxy.html#access">asegurado su servidor</a>. Los servidores proxy
      abiertos son peligrosos tanto para su red como para Internet en
      general.</p>
    </note>
</summary>
<seealso><module>mod_http2</module></seealso>
<seealso><module>mod_proxy</module></seealso>
<seealso><module>mod_proxy_connect</module></seealso>

    <section id="examples"><title>Ejemplos básicos</title>

    <p>Los siguientes ejemplos muestran cómo configurar HTTP/2 para
    las conexiones de backend de un proxy inverso.</p>

    <example><title>HTTP/2 (TLS)</title>
    <highlight language="config">
ProxyPass "/app" "h2://app.example.com"
ProxyPassReverse "/app" "https://app.example.com"
    </highlight>
    </example>

    <example><title>HTTP/2 (texto en claro)</title>
    <highlight language="config">
ProxyPass "/app" "h2c://app.example.com"
ProxyPassReverse "/app" "http://app.example.com"
    </highlight>
    </example>

    <note>
      <p>Los esquemas que se deben configurar arriba en
      <directive>ProxyPassReverse</directive> para el proxy inverso de los
      protocolos <code>h2</code> (o <code>h2c</code>) son los habituales
      <code>https</code> (resp. <code>http</code>), tal como espera o usa
      el user-agent.</p>
    </note>
    </section> <!-- /examples -->

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
        <dd>El estado HTTP/2 recibido del servidor de backend.</dd>
    </dl>
</section>

</modulesynopsis>
