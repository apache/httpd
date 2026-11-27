<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1936574 -->
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

<modulesynopsis metafile="mod_proxy_wstunnel.xml.meta">

<name>mod_proxy_wstunnel</name>
<description>Módulo de soporte de Websockets para
<module>mod_proxy</module></description>
<status>Deprecated</status>
<sourcefile>mod_proxy_wstunnel.c</sourcefile>
<identifier>proxy_wstunnel_module</identifier>
<compatibility>Disponible en httpd 2.4.5 y posteriores</compatibility>

<summary>
  <note type="warning"><title><a id="deprecation" name="deprecation">Obsolescencia</a></title>
    <p>Desde Apache HTTP Server 2.4.47, el protocolo Upgrade (tunneling) puede manejarse mejor con
    <module>mod_proxy_http</module>.</p>
    <p>Vea <a href="mod_proxy.html#protoupgrade">Protocol Upgrade</a>.</p>
  </note>

    <p>Este módulo <em>requiere</em> el servicio de <module >mod_proxy</module>.
    Proporciona soporte para encapsular (tunneling) conexiones web
    socket hacia un servidor websockets de backend. La conexión
    se actualiza automáticamente a una conexión websocket:</p>

    <example><title>Respuesta HTTP</title>
        <highlight language="config">
Upgrade: WebSocket
Connection: Upgrade
        </highlight>
    </example>

<p>El redireccionamiento de peticiones a un servidor websockets como <code>echo.websocket.org</code> puede hacerse usando la
directiva <directive type="ProxyPass" module="mod_proxy">ProxyPass</directive>:</p>
    <highlight language="config">
ProxyPass "/ws2/"  "ws://echo.websocket.org/"
ProxyPass "/wss2/" "wss://echo.websocket.org/"
    </highlight>

<p>El redireccionamiento simultáneo de HTTP y websockets, con un conjunto
específico de URLs que sean exclusivamente de websocket, puede hacerse
indicando la directiva <directive type="ProxyPass" module="mod_proxy"
>ProxyPass</directive> de websockets antes de la directiva HTTP:</p>
<highlight language="config">
ProxyPassMatch ^/(myApp/ws)$  ws://backend.example.com:9080/$1
ProxyPass / http://backend.example.com:9080/
</highlight>

<p>El redireccionamiento simultáneo de HTTP y websockets, donde las URLs de
los websockets no son exclusivamente de websocket o no se conocen de
antemano, puede hacerse usando la directiva <directive type="RewriteRule"
module="mod_rewrite">RewriteRule</directive> para configurar el
redireccionamiento de websockets:</p>
<highlight language="config">
ProxyPass / http://example.com:9080/
RewriteEngine on
RewriteCond %{HTTP:Upgrade} websocket [NC]
RewriteCond %{HTTP:Connection} upgrade [NC]
RewriteRule ^/?(.*) "ws://example.com:9080/$1" [P,L]
</highlight>

<p>El balanceo de carga entre varios backends puede lograrse usando <module>mod_proxy_balancer</module>.</p>

<p>
El módulo también puede usarse para actualizar a protocolos distintos de WebSocket, estableciendo
el parámetro <var><a href="mod_proxy.html#upgrade">upgrade</a></var> en la directiva
<directive type="ProxyPass" module="mod_proxy">ProxyPass</directive>
con el nombre de un protocolo personalizado.
Los valores especiales <code>upgrade=NONE</code> y <code>upgrade=ANY</code> pueden usarse para
pruebas o para forzar la actualización, pero <strong>no se recomiendan</strong> en producción por
motivos de seguridad.
<code>NONE</code> significa que se omite la comprobación de la cabecera pero la actualización/tunneling a
WebSocket siempre ocurre igualmente.
<code>ANY</code> significa que la actualización/tunneling ocurrirá usando cualquier protocolo solicitado por el cliente.
</p>
</summary>

<seealso><module>mod_proxy</module></seealso>

<directivesynopsis>
<name>ProxyWebsocketFallbackToProxyHttp</name>
<description>Indica a este módulo que deje que <module>mod_proxy_http</module> gestione la petición</description>
<syntax>ProxyWebsocketFallbackToProxyHttp On|Off</syntax>
<default>ProxyWebsocketFallbackToProxyHttp On</default>
<contextlist><context>server config</context>
<context>virtual host</context>
</contextlist>
<compatibility>Disponible en httpd 2.4.48 y posteriores</compatibility>

<usage>
    <p>Desde httpd 2.4.47, <module>mod_proxy_http</module> puede gestionar la actualización
    y el tunneling de WebSocket conforme a RFC 7230; esta directiva controla
    si <module>mod_proxy_wstunnel</module> debe delegar esto en
    <module>mod_proxy_http</module>, que es el comportamiento por defecto.</p>
    <p>Establecerla a <em>Off</em> hace que <module>mod_proxy_wstunnel</module> gestione
    las peticiones WebSocket como en httpd 2.4.46 y anteriores.</p>
</usage>
</directivesynopsis>

</modulesynopsis>
