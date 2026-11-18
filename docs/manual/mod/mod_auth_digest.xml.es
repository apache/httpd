<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933503 -->
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

<modulesynopsis metafile="mod_auth_digest.xml.meta">

<name>mod_auth_digest</name>
<description>Autenticación de usuarios usando MD5
    Digest Authentication</description>
<status>Extension</status>
<sourcefile>mod_auth_digest.c</sourcefile>
<identifier>auth_digest_module</identifier>

<summary>
    <p>Este módulo implementa la Autenticación Digest de HTTP
    (<rfc>2617</rfc>), y ofrece una alternativa a <module>mod_auth_basic</module>
    en la que la contraseña no se transmite en texto plano. Sin embargo,
    esto no supone una ventaja de seguridad significativa frente a la
    autenticación básica. Por otro lado, el almacenamiento de contraseñas en
    el servidor es mucho menos seguro con la autenticación Digest que con
    la autenticación básica. Por lo tanto, usar autenticación básica y
    cifrar toda la conexión mediante <module>mod_ssl</module> es una
    alternativa mucho mejor.</p>
</summary>

<seealso><directive module="mod_authn_core">AuthName</directive></seealso>
<seealso><directive module="mod_authn_core">AuthType</directive></seealso>
<seealso><directive module="mod_authz_core">Require</directive></seealso>
<seealso><a href="../howto/auth.html">Cómo hacer la autenticación</a></seealso>

<section id="using"><title>Uso de la autenticación Digest</title>

    <p>Para usar la autenticación MD5 Digest, configure la ubicación que se
    va a proteger como se muestra en el siguiente ejemplo:</p>

    <example><title>Ejemplo:</title>
    <highlight language="config">
&lt;Location "/private/"&gt;
    AuthType Digest
    AuthName "private area"
    AuthDigestDomain "/private/" "http://mirror.my.dom/private2/"

    AuthDigestProvider file
    AuthUserFile "/web/auth/.digest_pw"
    Require valid-user
&lt;/Location&gt;
      </highlight>
    </example>

    <p><directive module="mod_auth_digest">AuthDigestDomain</directive>
    debería listar las ubicaciones que estarán protegidas por esta
    configuración.</p>

    <p>El archivo de contraseñas referenciado en la directiva <directive
    module="mod_auth_digest">AuthUserFile</directive> puede
    crearse y gestionarse con la herramienta <program>htdigest</program>.</p>


    <note><title>Nota</title>
    <p>La autenticación Digest pretendía ser más segura que la autenticación
    básica, pero ya no cumple ese objetivo de diseño. Un atacante de tipo
    man-in-the-middle puede forzar trivialmente al navegador a degradarse a
    autenticación básica. E incluso un espía pasivo puede obtener la
    contraseña por fuerza bruta usando el hardware gráfico actual, porque el
    algoritmo de hash usado por la autenticación Digest es demasiado rápido.
    Otro problema es que el almacenamiento de las contraseñas en el
    servidor es inseguro. El contenido de un archivo htdigest robado puede
    usarse directamente para la autenticación Digest. Por lo tanto, se
    recomienda encarecidamente usar <module>mod_ssl</module> para cifrar
    toda la conexión.</p>
    <p><module>mod_auth_digest</module> solo funciona correctamente en
    plataformas donde APR admite memoria compartida.</p>
    </note>
</section>


<directivesynopsis>
<name>AuthDigestProvider</name>
<description>Establece el proveedor(es) de autenticación para esta ubicación</description>
<syntax>AuthDigestProvider <var>provider-name</var>
[<var>provider-name</var>] ...</syntax>
<default>AuthDigestProvider file</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>La directiva <directive>AuthDigestProvider</directive> establece
    qué proveedor se usa para autenticar a los usuarios de esta ubicación.
    El proveedor <code>file</code> por defecto está implementado
    por el módulo <module>mod_authn_file</module>. Asegúrese de
    que el módulo proveedor elegido está presente en el servidor.</p>

    <p>Vea <module>mod_authn_dbm</module>, <module>mod_authn_file</module>,
    <module>mod_authn_dbd</module> y <module>mod_authn_socache</module>
    para conocer los proveedores disponibles.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthDigestQop</name>
<description>Determina la calidad de protección a usar en la autenticación
digest</description>
<syntax>AuthDigestQop none|auth|auth-int [auth|auth-int]</syntax>
<default>AuthDigestQop auth</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>La directiva <directive>AuthDigestQop</directive> determina la
    <dfn>calidad de protección</dfn> a usar. <code>auth</code> solo
    realizará la autenticación (usuario/contraseña); <code>auth-int</code>
    es autenticación más comprobación de integridad (también se calcula y
    comprueba un hash MD5 de la entidad); <code>none</code> hará que el
    módulo use el antiguo algoritmo digest de RFC-2069 (que no incluye
    comprobación de integridad). Pueden especificarse tanto <code>auth</code>
    como <code>auth-int</code>, en cuyo caso el navegador elegirá cuál de
    ellos usar. <code>none</code> solo debería usarse si, por alguna razón,
    al navegador no le gusta el desafío que recibe de otro modo.</p>

    <note>
      <code>auth-int</code> todavía no está implementado.
    </note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthDigestNonceLifetime</name>
<description>Cuánto tiempo es válido el nonce del servidor</description>
<syntax>AuthDigestNonceLifetime <var>seconds</var></syntax>
<default>AuthDigestNonceLifetime 300</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>La directiva <directive>AuthDigestNonceLifetime</directive>
    controla cuánto tiempo es válido el nonce del servidor. Cuando el
    cliente contacta con el servidor usando un nonce caducado, el servidor
    devolverá un 401 con <code>stale=true</code>. Si <var>seconds</var> es
    mayor que 0, especifica el tiempo durante el cual el nonce es válido;
    esto probablemente nunca debería establecerse por debajo de 10
    segundos. Si <var>seconds</var> es menor que 0, el nonce nunca caduca.
    <!-- Not implemented yet: If <var>seconds</var> is 0 then
    the nonce may be used exactly once by the client. Note that while
    one-time-nonces provide higher security against replay attacks,
    they also have significant performance implications, as the
    browser cannot pipeline or multiple connections for the
    requests. Because browsers cannot easily detect that
    one-time-nonces are being used, this may lead to browsers trying
    to pipeline requests and receiving 401 responses for all but the
    first request, requiring the browser to resend the requests. Note
    also that the protection against replay attacks only makes sense
    for dynamically generated content and things like POST requests;
    for static content the attacker may already have the complete
    response, so one-time-nonces do not make sense here.  -->
    </p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthDigestAlgorithm</name>
<description>Selecciona el algoritmo usado para calcular los hashes de
desafío y respuesta en la autenticación digest</description>
<syntax>AuthDigestAlgorithm MD5|MD5-sess</syntax>
<default>AuthDigestAlgorithm MD5</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>La directiva <directive>AuthDigestAlgorithm</directive>
    selecciona el algoritmo usado para calcular los hashes de desafío y
    respuesta.</p>

    <note>
      <code>MD5-sess</code> todavía no está correctamente implementado.
    </note>
    <!--
    <p>To use <code>MD5-sess</code> you must first code up the
    <code>get_userpw_hash()</code> function in
    <code>mod_auth_digest.c</code>.</p>
    -->
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthDigestDomain</name>
<description>URIs que están en el mismo espacio de protección para la
autenticación Digest</description>
<syntax>AuthDigestDomain <var>URI</var> [<var>URI</var>] ...</syntax>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>La directiva <directive>AuthDigestDomain</directive> le permite
    especificar una o más URIs que están en el mismo espacio de protección
    (<em>es decir</em>, que usan el mismo realm e información de
    usuario/contraseña). Las URIs especificadas son prefijos; el cliente
    asumirá que todas las URIs "por debajo" de estas también están
    protegidas por el mismo usuario/contraseña. Las URIs pueden ser URIs
    absolutas (<em>es decir</em>, incluyendo un esquema, host, puerto, etc.)
    o URIs relativas.</p>

    <p>Esta directiva <em>debería</em> especificarse siempre y
    contener al menos el (conjunto de) URI(s) raíz para este espacio.
    Omitirlo hará que el cliente envíe la cabecera
    Authorization en <em>cada petición</em> enviada a este
    servidor.</p>

    <p>Las URIs especificadas también pueden apuntar a servidores distintos,
    en cuyo caso los clientes (que entiendan esto) compartirán entonces la
    información de usuario/contraseña entre varios servidores sin
    preguntar al usuario cada vez. </p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthDigestShmemSize</name>
<description>La cantidad de memoria compartida a reservar para el
seguimiento de clientes</description>
<syntax>AuthDigestShmemSize <var>size</var></syntax>
<default>AuthDigestShmemSize 1000</default>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>La directiva <directive>AuthDigestShmemSize</directive> define
    la cantidad de memoria compartida que se reservará al arrancar el
    servidor para el seguimiento de clientes. Tenga en cuenta que el
    segmento de memoria compartida no puede establecerse por debajo del
    espacio necesario para hacer seguimiento de al menos <em>un</em> cliente.
    Este valor depende de su sistema. Si quiere averiguar el valor exacto,
    puede simplemente establecer <directive>AuthDigestShmemSize</directive>
    al valor <code>0</code> y leer el mensaje de error tras intentar arrancar
    el servidor.</p>

    <p>El <var>size</var> normalmente se expresa en bytes, pero puede
    seguir el número con una <code>K</code> o una <code>M</code> para
    expresar su valor en KBytes o MBytes. Por ejemplo, las siguientes
    directivas son todas equivalentes:</p>

<highlight language="config">
AuthDigestShmemSize 1048576
AuthDigestShmemSize 1024K
AuthDigestShmemSize 1M
    </highlight>
</usage>
</directivesynopsis>

</modulesynopsis>
