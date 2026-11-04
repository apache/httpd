<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1934245 -->
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

<modulesynopsis metafile="mod_proxy_scgi.xml.meta">

<name>mod_proxy_scgi</name>
<description>Módulo de pasarela SCGI para <module>mod_proxy</module></description>
<status>Extension</status>
<sourcefile>mod_proxy_scgi.c</sourcefile>
<identifier>proxy_scgi_module</identifier>

<summary>
    <p>Este módulo <em>requiere</em> el servicio de <module
    >mod_proxy</module>. Proporciona soporte para el
    <a href="http://python.ca/scgi/protocol.txt">protocolo SCGI, versión
    1</a>.</p>

    <p>Por tanto, para poder gestionar el protocolo SCGI,
    <module>mod_proxy</module> y <module>mod_proxy_scgi</module> deben
    estar presentes en el servidor.</p>

    <note type="warning"><title>Advertencia</title>
      <p>No active el proxy hasta que haya <a
      href="mod_proxy.html#access">asegurado su servidor</a>. Los servidores proxy
      abiertos son peligrosos tanto para su red como para Internet en
      general.</p>
    </note>
</summary>

<seealso><module>mod_proxy</module></seealso>
<seealso><module>mod_proxy_balancer</module></seealso>

<section id="examples"><title>Ejemplos</title>
    <p>Recuerde que, para que los siguientes ejemplos funcionen, tiene que
    activar <module>mod_proxy</module> y <module>mod_proxy_scgi</module>.</p>

    <example><title>Pasarela simple</title>
    <highlight language="config">
ProxyPass "/scgi-bin/" "scgi://localhost:4000/"
      </highlight>
    </example>

    <p>La pasarela balanceada necesita <module>mod_proxy_balancer</module> y
    al menos un módulo de algoritmo de balanceo de carga, como
    <module>mod_lbmethod_byrequests</module>, además de los módulos de proxy
    mencionados anteriormente. <module>mod_lbmethod_byrequests</module> es el
    valor por defecto, y se usará para esta configuración de ejemplo.</p>

    <example><title>Pasarela balanceada</title>
    <highlight language="config">
ProxyPass "/scgi-bin/" "balancer://somecluster/"
&lt;Proxy balancer://somecluster&gt;
    BalancerMember scgi://localhost:4000
    BalancerMember scgi://localhost:4001
&lt;/Proxy&gt;
    </highlight>
    </example>
</section>

<section id="env"><title>Variables de entorno</title>
    <p>Además de las directivas de configuración que controlan el
    comportamiento de <module>mod_proxy</module>, una <dfn>variable
    de entorno</dfn> también puede controlar el proveedor del protocolo
    SCGI:</p>
    <dl>
        <dt>proxy-scgi-pathinfo</dt>
        <dd>Por defecto, <module>mod_proxy_scgi</module> no creará
        ni exportará la variable de entorno <var><glossary ref="pathinfo">PATH_INFO</glossary></var>. Esto permite
        que el servidor SCGI de backend determine correctamente <var>SCRIPT_NAME</var>
        y <var>Script-URI</var> y cumpla con la sección 3.3 de RFC 3875.
        Si en cambio necesita que <module>mod_proxy_scgi</module> genere
        una "mejor suposición" para <var>PATH_INFO</var>, establezca esta variable de entorno. La
        variable debe establecerse antes de que <directive module="mod_env">SetEnv</directive>
        tenga efecto. Se puede usar <directive module="mod_setenvif">SetEnvIf</directive>
        en su lugar: <code>SetEnvIf Request_URI . proxy-scgi-pathinfo</code>
        </dd>
    </dl>
</section>

<directivesynopsis>
<name>ProxySCGISendfile</name>
<description>Activa la evaluación de la cabecera de respuesta pseudo
<var>X-Sendfile</var></description>
<syntax>ProxySCGISendfile On|Off|<var>Headername</var></syntax>
<default>ProxySCGISendfile Off</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>

<usage>
    <p>La directiva <directive>ProxySCGISendfile</directive> permite que el
    backend SCGI deje que los archivos sean servidos directamente por la pasarela. Esto es útil
    por motivos de rendimiento &mdash; httpd puede usar <code>sendfile</code> u otras
    optimizaciones, que no son posibles si el archivo llega a través del socket
    de backend. Además, el contenido del archivo no se transmite dos veces.</p>
    <p>El argumento de la directiva <directive>ProxySCGISendfile</directive> determina el
    comportamiento de la pasarela:</p>
    <dl>
    <dt><code>Off</code></dt>
    <dd>No se realiza ningún tratamiento especial.</dd>

    <dt><code>On</code></dt>
    <dd>La pasarela busca una cabecera de respuesta del backend llamada
    <code>X-Sendfile</code> e interpreta el valor como el nombre de archivo que servir.
    La cabecera se elimina de las cabeceras de respuesta final. Esto es equivalente a
    <code>ProxySCGISendfile X-Sendfile</code>.</dd>

    <dt>cualquier otro valor</dt>
    <dd>Similar a <code>On</code>, pero en lugar del nombre de cabecera
    predefinido <code>X-Sendfile</code>, el argumento se usa como el nombre de la cabecera.</dd>
    </dl>

    <example><title>Ejemplo</title>
    <highlight language="config">
# Usar la cabecera por defecto (X-Sendfile)
ProxySCGISendfile On

# Usar una cabecera diferente
ProxySCGISendfile X-Send-Static
    </highlight>
    </example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxySCGIInternalRedirect</name>
<description>Activa o desactiva las respuestas de redirección interna del
backend</description>
<syntax>ProxySCGIInternalRedirect On|Off|<var>Headername</var></syntax>
<default>ProxySCGIInternalRedirect On</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>
<compatibility>La función <var>Headername</var> está disponible en Apache
httpd 2.4.13 y posteriores.</compatibility>

<usage>
    <p><directive>ProxySCGIInternalRedirect</directive> permite que el backend
    redirija internamente la pasarela a una URL diferente. Esta función
    se origina en <module>mod_cgi</module>, que redirige internamente la
    respuesta si el estado de la respuesta es <code>OK</code> (<code>200</code>) y
    la respuesta contiene una cabecera <code>Location</code> (o una cabecera
    alternativa configurada) cuyo valor comienza con una barra (<code>/</code>). Este valor se
    interpreta como una nueva URL local a la que Apache httpd redirige internamente.</p>

    <p><module>mod_proxy_scgi</module> hace lo mismo que
    <module>mod_cgi</module> en este aspecto, salvo que puede desactivar la
    función o especificar el uso de una cabecera distinta de <code>Location</code>.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
    ProxySCGIInternalRedirect Off

# Django y otros frameworks completarán totalmente las "URLs locales"
# establecidas por la aplicación, por lo que debe usarse una cabecera alternativa.
&lt;Location /django-app/&gt;
    ProxySCGIInternalRedirect X-Location
&lt;/Location&gt;
    </highlight>
    </example>
</usage>
</directivesynopsis>

</modulesynopsis>
