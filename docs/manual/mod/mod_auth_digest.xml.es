<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1937887 -->
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
    <p>Este módulo implementa la autenticación HTTP Digest
    (<rfc>2617</rfc>), una alternativa a la autenticación Basic proporcionada
    por <module>mod_auth_basic</module> en la que la contraseña no se envía
    por la red en texto claro.</p>

    <p>Basic y Digest son ambos únicamente esquemas de autenticación: establecen
    quién es el cliente, y no hacen nada por la confidencialidad o la
    integridad de la propia petición y respuesta. Sobre una conexión sin
    cifrar, el contenido de cada petición y respuesta queda expuesto con
    cualquiera de los dos esquemas; la única ventaja de Digest es que la
    contraseña no está entre ellos. Por tanto, Digest no sustituye a una
    conexión asegurada con <module>mod_ssl</module>, que protege tanto las
    credenciales como los datos, y esa única ventaja tiene sus propios
    límites (vea la nota más abajo).</p>
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
    <p>La única ventaja de Digest sobre Basic, mantener la contraseña fuera
    de la red, es condicional. Si el cliente revierte silenciosamente a Basic
    cuando se le desafía, un atacante activo puede eliminar el desafío
    Digest y ofrecer Basic en su lugar, y el navegador entonces envía la
    contraseña en texto claro; un espía pasivo puede montar un ataque de
    fuerza bruta sin conexión sobre una respuesta capturada, lo cual el
    rápido hash MD5 apenas ralentiza; y si se roba el archivo de
    <program>htdigest</program>, sus hashes almacenados pueden reproducirse
    para autenticarse directamente en ese realm, sin que se recupere la
    contraseña en sí. Cifre toda la conexión con <module>mod_ssl</module> en
    su lugar.</p>
    <p><module>mod_auth_digest</module> requiere una APR construida con
    soporte de memoria compartida, y no se compila sin ella.</p>
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
Digest</description>
<syntax>AuthDigestQop auth</syntax>
<default>AuthDigestQop auth</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>La directiva <directive>AuthDigestQop</directive> determina la
    <dfn>calidad de protección</dfn> a usar. Solo se admite <code>auth</code>
    (autenticación), y es el valor por defecto, por lo que esta
    directiva ya no tiene ningún efecto y se mantiene solo por
    compatibilidad.</p>

    <note>Versiones anteriores también admitían <code>none</code> (el esquema
    Digest de RFC 2069, sin calidad de protección). Se ha eliminado:
    una petición cuyo <code>qop</code> falte o no sea <code>auth</code>
    se rechaza ahora.</note>
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
    controla cuánto tiempo es válido el nonce del servidor. Cuando el cliente
    contacta con el servidor usando un nonce caducado, el servidor devuelve un
    401 con <code>stale=true</code>, y un cliente conforme con la RFC
    reintenta con un nonce nuevo sin preguntar al usuario.</p>

    <ul>
      <li>Si <var>seconds</var> es mayor que 0, especifica el
      tiempo durante el cual el nonce es válido; esto probablemente nunca
      debería establecerse por debajo de 10 segundos.</li>

      <li>Si <var>seconds</var> es 0, el nonce puede usarse exactamente
      una vez. El servidor suministra el siguiente nonce en la
      cabecera <code>Authentication-Info</code> de cada respuesta para que
      el cliente pueda continuar; a un cliente que reutiliza un nonce se le
      responde con <code>stale=true</code> y reintenta. Los nonces de un
      solo uso ofrecen una protección más fuerte frente a la reproducción de
      una petición capturada, pero el cliente no puede encadenar peticiones
      (pipelining), y uno que lo haga recibe un 401 para todas menos la
      primera y tiene que reenviarlas. Este coste merece la pena
      principalmente para peticiones que cambian el estado del servidor o
      devuelven contenido que varía con el tiempo; reproducir una petición de
      contenido inalterado que el espía ya capturó por completo no aporta
      nada.</li>

      <li>Si <var>seconds</var> es menor que 0, el nonce nunca
      caduca.</li>
    </ul>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthDigestNcCheck</name>
<description>Activa o desactiva la comprobación del nonce-count enviado por
el cliente</description>
<syntax>AuthDigestNcCheck On|Off</syntax>
<default>AuthDigestNcCheck Off</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>AuthConfig</override>

<usage>
    <p>La directiva <directive>AuthDigestNcCheck</directive> activa o
    desactiva la verificación del valor de nonce-count enviado por el cliente.
    El nonce-count es un contador secuencial que el cliente incrementa en
    cada petición que usa el mismo nonce. Comprobarlo ayuda a detectar
    ataques de repetición.</p>

    <p>Esta función requiere soporte de memoria compartida en la plataforma.
    Si la memoria compartida no está disponible y esta directiva se establece
    a <code>On</code>, el servidor devolverá un error en el arranque.</p>

    <p>Aunque se recomienda desde el punto de vista de la seguridad, activar
    esta directiva tiene una implicación de rendimiento: todas las peticiones
    que porten una cabecera <code>Authorization</code> deben serializarse a
    través de una sección crítica para poder comparar de forma segura los
    valores de nonce-count. En servidores de alto tráfico esto puede ser
    apreciable.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthDigestAlgorithm</name>
<description>Selecciona el algoritmo usado para calcular los hashes de
desafío y respuesta en la autenticación Digest</description>
<syntax>AuthDigestAlgorithm MD5</syntax>
<default>AuthDigestAlgorithm MD5</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>La directiva <directive>AuthDigestAlgorithm</directive>
    selecciona el algoritmo usado para calcular los hashes de desafío y
    respuesta. Solo se admite <code>MD5</code>.</p>
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
    servidor. Además de aumentar el tamaño de la petición, también puede
    tener un efecto perjudicial en el rendimiento si la <directive
    module="mod_auth_digest">AuthDigestNcCheck</directive> está activada.</p>

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
<default>AuthDigestShmemSize 8192</default>
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

    <p>El valor por defecto da cabida a unos 140 clientes. A un cliente que se
    descarta para hacer sitio a otro no se le deniega el acceso: se le emite
    un nuevo nonce con <code>stale=true</code>, lo que le cuesta una petición
    extra. Tenga en cuenta que una petición que no se autentica también ocupa
    una entrada, ya que el desafío que se le devuelve porta el identificador
    por el que se hace seguimiento del cliente.</p>

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
