<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933739 -->
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

<modulesynopsis metafile="mod_autht_jwt.xml.meta">

<name>mod_autht_jwt</name>
<description>Autenticación mediante tokens usando tokens JWT</description>
<status>Base</status>
<sourcefile>mod_autht_jwt.c</sourcefile>
<identifier>autht_jwt_module</identifier>

<summary>
    <p>Este módulo proporciona a los front-ends de análisis de tokens, como
    <module>mod_auth_bearer</module>, la capacidad de autenticar usuarios
    verificando un token JWT según se describe en
    <rfc>7519</rfc>.</p>

    <p>Un token JWT se lee de la cabecera <var>Authorization</var>
    con un <var>auth-scheme</var> de <var>Bearer</var>.</p>

    <p>Cuando se usa <module>mod_auth_bearer</module>, este módulo se invoca
    mediante
    <directive module="mod_auth_bearer">AuthBearerProvider</directive>
    con el valor <code>jwt</code>.</p>

    <p>Este módulo también se puede usar de forma independiente para generar tokens JWT
    que se pasan a un servidor o servicio de backend. Las claims se incrustan dentro
    de un token, que opcionalmente se firma y se pasa usando
    la cabecera <var>Authorization</var> como un token <var>Bearer</var>.</p>
</summary>
<seealso>
  <directive module="mod_auth_bearer">AuthBearerProvider</directive>
</seealso>

<directivesynopsis>
<name>AuthtJwtDriver</name>
<description>Establece el nombre del controlador de cifrado subyacente que se va a
usar</description>
<syntax>AuthtJwtDriver <var>name</var> <var>[param[=value]]</var></syntax>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>

<usage>
    <p>La directiva <directive>AuthtJwtDriver</directive> especifica el nombre
    del controlador de cifrado que se usará para firmar y verificar. Si no se especifica,
    el controlador usado por defecto es el recomendado que viene compilado en APR-util.</p>

    <p>Siga las instrucciones de
    <directive module="mod_session_crypto">SessionCryptoDriver</directive> para
    configurar el controlador.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthtJwtVerify</name>
<description>El algoritmo de firma JWS y la frase de paso/clave para verificar un
token JWT entrante</description>
<syntax>AuthtJwtVerify <var>algorithm</var> [<var>type</var> <var>param</var>]</syntax>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>La directiva <directive>AuthtJwtVerify</directive> especifica el algoritmo
    y el secreto usados para verificar los tokens bearer entrantes.</p>

    <p>Si se selecciona el tipo de algoritmo <var>none</var>, el token no se
    protege y se aceptará tal cual. Úselo solo cuando el cliente sea de confianza y
    el canal esté protegido por otros medios, como TLS con autenticación mutua, o
    sockets de dominio unix.</p>

    <p>Si está presente, la claim <var>sub</var> se asigna a REMOTE_USER.</p>

    <example><title>Ejemplo sin verificación</title>
    <highlight language="config">
&lt;Location "/mutual-tls-secured"&gt;
  AuthType bearer
  AuthName example-name
  AuthBearerProvider jwt
  AuthtJwtVerify none
  Require valid-user
&lt;/Location&gt;
    </highlight>
    </example>

    <p>Si se usa el tipo de algoritmo <var>HS256</var>, el algoritmo se establece en
    <var>HMAC-SHA256</var>, y el secreto se establece dentro del <var>file</var> especificado
    como tercer parámetro. El contenido del token bearer sigue siendo visible, por lo que
    el canal debe seguir protegido frente a escuchas mediante TLS.</p>

    <p>Si la firma se verifica, y si está presente, la claim <var>sub</var> se
    asigna a REMOTE_USER.</p>

    <example><title>Ejemplo de verificación</title>
    <highlight language="config">
&lt;Location "/secure"&gt;
  AuthType bearer
  AuthName example-name
  AuthBearerProvider jwt
  AuthtJwtVerify hs256 file "/www/conf/jwt.secret"
  Require valid-user
&lt;/Location&gt;
    </highlight>
    </example>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthtJwtSign</name>
<description>El algoritmo de firma JWS y la frase de paso/clave para firmar un
token JWT saliente</description>
<syntax>AuthtJwtSign <var>algorithm</var> [<var>type</var> <var>param</var>]</syntax>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>La directiva <directive>AuthtJwtSign</directive> especifica el algoritmo
    y el secreto usados para firmar los tokens bearer salientes que se pasan a un servidor o servicio.</p>

    <p>Si se selecciona el tipo de algoritmo <var>none</var>, el token no se
    protege. Úselo solo cuando el cliente sea de confianza y el canal esté protegido
    por otros medios, como TLS con autenticación mutua, o sockets de dominio unix.</p>

    <p>Establezca las claims que se enviarán en el token mediante la directiva
    <directive module="mod_autht_jwt">AuthtJwtClaim</directive>. La
    claim <var>sub</var> se usa para transmitir el usuario remoto.</p>

    <example><title>Ejemplo sin verificación</title>
    <highlight language="config">
&lt;Location "/mutual-tls-secured"&gt;
  AuthtJwtClaim set sub %{REMOTE_USER}
  AuthtJwtSign none
&lt;/Location&gt;
    </highlight>
    </example>

    <p>Si se usa el tipo de algoritmo <var>HS256</var>, el algoritmo se establece en
    <var>HMAC-SHA256</var>, y el secreto se establece dentro del <var>file</var> especificado
    como tercer parámetro. El contenido del token bearer sigue siendo visible, por lo que
    el canal debe seguir protegido frente a escuchas mediante TLS.</p>

    <example><title>Ejemplo de verificación</title>
    <highlight language="config">
&lt;Location "/secure"&gt;
  AuthtJwtClaim set sub %{REMOTE_USER}
  AuthtJwtSign hs256 file "/www/conf/jwt.secret"
&lt;/Location&gt;
    </highlight>
    </example>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthtJwtClaim</name>
<description>Establece una claim con el nombre y la expresión dados, o elimina la claim con el nombre dado</description>
<syntax>AuthtJwtVerify <var>[set|unset]</var> <var>name</var> [<var>value</var>]</syntax>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>La directiva <directive>AuthtJwtClaim</directive> añade y/o elimina
    claims del token que se pasa al servidor o servicio de backend.</p>

    <p>Cuando se establece una claim, el valor de la claim es el resultado de una expresión. La
    expresión puede incluir parámetros de un certificado digital, o el nombre del
    usuario que se ha autenticado ante Apache httpd.</p>

    <example><title>Ejemplo de transmisión del usuario remoto</title>
    <highlight language="config">
&lt;Location "/secure"&gt;
  AuthtJwtClaim set sub %{REMOTE_USER}
  AuthtJwtSign hs256 file "/www/conf/jwt.secret"
&lt;/Location&gt;
    </highlight>
    </example>

    <p>Cuando se elimina una claim, la claim establecida previamente se elimina del token.</p>

    <example><title>Ejemplo de eliminación de una claim</title>
    <highlight language="config">
AuthtJwtClaim set my-claim present
&lt;Location "/secure"&gt;
  AuthtJwtClaim set sub %{REMOTE_USER}
  AuthtJwtClaim unset my-claim
  AuthtJwtSign hs256 file "/www/conf/jwt.secret"
&lt;/Location&gt;
    </highlight>
    </example>

</usage>
</directivesynopsis>

</modulesynopsis>
