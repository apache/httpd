<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1937537 -->
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

<modulesynopsis metafile="mod_proxy_connect.xml.meta">

<name>mod_proxy_connect</name>
<description>Extensión de <module>mod_proxy</module> para
la gestión de peticiones <code>CONNECT</code></description>
<status>Extension</status>
<sourcefile>mod_proxy_connect.c</sourcefile>
<identifier>proxy_connect_module</identifier>

<summary>
    <p>Este módulo <em>requiere</em> el servicio de <module
    >mod_proxy</module>. Proporciona soporte para el método HTTP
    <code>CONNECT</code>. Este método se usa principalmente para encapsular peticiones SSL
    a través de servidores proxy.</p>

    <p>Por lo tanto, para poder gestionar peticiones <code>CONNECT</code>,
    <module>mod_proxy</module> y
    <module>mod_proxy_connect</module> deben estar presentes en el servidor.</p>

    <p>CONNECT también se usa cuando el servidor necesita enviar una petición HTTPS
    a través de un proxy directo. En este caso el servidor actúa como cliente CONNECT.
    Esta funcionalidad es parte de <module>mod_proxy</module> y
    <module>mod_proxy_connect</module> no es necesario en este caso.</p>

    <note type="warning"><title>Advertencia</title>
      <p>No active el proxy hasta que haya <a
      href="mod_proxy.html#access">asegurado su servidor</a>. Los servidores proxy
      abiertos son peligrosos tanto para su red como para Internet en
      general.</p>
    </note>
</summary>
<seealso><module>mod_proxy</module></seealso>

<section id="notes"><title>Notas de la petición</title>
    <p><module>mod_proxy_connect</module> crea las siguientes notas de petición para
        el registro, usando el formato <code>%{VARNAME}n</code> en
        <directive module="mod_log_config">LogFormat</directive> o
        <directive module="core">ErrorLogFormat</directive>:
    </p>
    <dl>
        <dt>proxy-source-port</dt>
        <dd>El puerto local usado para la conexión con el servidor de backend.</dd>
    </dl>

   <p>Las peticiones con el método CONNECT se controlan mediante el
   bloque <directive module="mod_proxy">Proxy</directive>
   como cualquier otra petición HTTP que pase por el proxy.
   Las conexiones SSL a través de un proxy pueden filtrarse explícitamente
   especificando el host y el puerto de destino, por ejemplo:
   </p>

   <highlight language="config">
&lt;Proxy www.example.com:443&gt;
  Require ip 192.168.0.0/16
&lt;/Proxy&gt;
   </highlight>
</section>

<directivesynopsis>
<name>AllowCONNECT</name>
<description>Puertos a los que se permite <code>CONNECT</code> a través del
proxy</description>
<syntax>AllowCONNECT <var>port</var>[-<var>port</var>]
[<var>port</var>[-<var>port</var>]] ... | None</syntax>
<default>AllowCONNECT 443 563</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>
<compatibility>Movida desde <module>mod_proxy</module> en Apache 2.3.5.
Los rangos de puertos están disponibles desde Apache 2.3.7.</compatibility>

<usage>
    <p>La directiva <directive>AllowCONNECT</directive> especifica una lista
    de números de puerto o rangos a los que el método <code>CONNECT</code> del
    proxy puede conectarse. Los navegadores actuales usan este método cuando se
    solicita una conexión <code>https</code> y está en efecto el encapsulamiento del
    proxy sobre HTTP.</p>

    <p>Por defecto, solo están activados el puerto https por defecto (<code>443</code>) y el
    puerto snews por defecto (<code>563</code>). Use la
    directiva <directive>AllowCONNECT</directive> para anular este valor por defecto y
    permitir conexiones únicamente a los puertos indicados.</p>

    <p>Establezca el valor a <code>None</code> para no permitir peticiones
    <code>CONNECT</code> a ningún puerto, incluidos los predeterminados. <code>None</code> no se
    puede combinar con números de puerto en el mismo contexto.</p>

    <p>Cuando <directive>AllowCONNECT</directive> se establece tanto en el
    servidor principal como en un host virtual, las listas de puertos se fusionan, de modo que un host
    virtual puede permitir puertos adicionales. Un valor de <code>None</code> tiene
    precedencia y no permite ningún puerto donde se establezca; pero un <code>None</code>
    heredado se ve a su vez sobrescrito por una lista explícita de puertos en un
    host virtual.</p>
</usage>
</directivesynopsis>

</modulesynopsis>
