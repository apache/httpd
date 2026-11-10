<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933179 -->
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

<modulesynopsis metafile="mod_auth_bearer.xml.meta">

<name>mod_auth_bearer</name>
<description>Autenticación HTTP Bearer</description>
<status>Base</status>
<sourcefile>mod_auth_bearer.c</sourcefile>
<identifier>auth_bearer_module</identifier>

<summary>
    <p>Este módulo permite usar la autenticación HTTP Bearer para
    restringir el acceso pasando el token bearer a los proveedores indicados.
    Este módulo debe combinarse con al menos un módulo de
    tokens, como <module>mod_autht_jwt</module>, y un módulo de
    autorización, como <module>mod_authz_user</module>.</p>
</summary>
<seealso><directive module="mod_authn_core">AuthName</directive></seealso>
<seealso><directive module="mod_authn_core">AuthType</directive></seealso>
<seealso><directive module="mod_authz_core">Require</directive></seealso>
<seealso><a href="../howto/auth.html">Cómo hacer la autenticación</a></seealso>

<directivesynopsis>
<name>AuthBearerProvider</name>
<description>Establece el proveedor o proveedores de autenticación para esta ubicación</description>
<syntax>AuthBearerProvider <var>provider-name</var>
[<var>provider-name</var>] ...</syntax>
<default>AuthBearerProvider file</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>La directiva <directive>AuthBearerProvider</directive> establece
    qué proveedor se usa para verificar los tokens en esta ubicación.
    El proveedor por defecto <code>jwt</code> está implementado
    por el módulo <module>mod_autht_jwt</module>. Asegúrese de
    que el módulo proveedor elegido esté presente en el servidor.</p>
    <example><title>Ejemplo</title>
    <highlight language="config">
&lt;Location "/secure"&gt;
    AuthType bearer
    AuthName "private area"
    AuthBearerProvider jwt
    AuthtJwtVerify hs256 file "/www/etc/jwt.secret"
    Require            valid-user
&lt;/Location&gt;
    </highlight>
    </example>
    <p>Los proveedores se consultan en orden hasta que uno de ellos encuentra una coincidencia
    para el token solicitado. Esto normalmente significa que el token se ha
    firmado correctamente, o que el token no ha caducado.</p>

    <p>El primer proveedor implementado es <module>mod_autht_jwt</module>.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthBearerAuthoritative</name>
<description>Establece si la verificación del token se pasa a módulos de
nivel inferior</description>
<syntax>AuthBearerAuthoritative On|Off</syntax>
<default>AuthBearerAuthoritative On</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>Normalmente, cada módulo de verificación de tokens listado en <directive
    module="mod_auth_bearer">AuthBearerProvider</directive> intentará
    verificar el token, y si no se encuentra que el token sea válido,
    se denegará el acceso. Establecer explícitamente la directiva
    <directive>AuthBearerAuthoritative</directive> a
    <code>Off</code> permite que la verificación del token se pase a
    otros módulos que no se basan en proveedores si el token no se reconoce.
    Esto solo debería ser necesario al combinar
    <module>mod_auth_bearer</module> con módulos de terceros que no
    estén configurados con la directiva
    <directive module="mod_auth_bearer">AuthBearerProvider</directive>.
    Al usar dichos módulos, el orden de procesamiento
    lo determina el código fuente de los módulos y no es configurable.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthBearerProxy</name>
<description>Pasa un token de autenticación bearer a través de una conexión proxy
generado usando la expresión indicada</description>
<syntax>AuthBearerProxy off|<var>expression</var></syntax>
<default>none</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>
<compatibility>Apache HTTP Server 2.5.1 y posteriores</compatibility>
<usage>
    <p>La expresión indicada se pasa como token bearer en la
    cabecera Authorization, que se pasa al servidor o servicio
    detrás del servidor web. La expresión se interpreta usando el
    <a href="../expr.html">analizador de expresiones</a>, que permite
    establecer el token en función de los parámetros de la petición.</p>

    <note>
    La cabecera Authorization añadida por esta directiva <em>no</em>
    se usa como entrada para ninguna autenticación o autorización dentro del
    servidor local. Está diseñada para pasarse a los servidores de origen.
    </note>

    <p>En este ejemplo, pasamos un token fijo a un servidor de backend.</p>

    <example><title>Ejemplo fijo</title>
    <highlight language="config">
&lt;Location "/demo"&gt;
    AuthBearerProxy my-fixed-token
&lt;/Location&gt;
    </highlight>
    </example>

    <p>En este ejemplo, pasamos la cadena de consulta como token al
    servidor de backend.</p>

    <example><title>Ejemplo con cadena de consulta</title>
    <highlight language="config">
&lt;Location "/secure"&gt;
    AuthBearerProxy "%{QUERY_STRING}"
&lt;/Location&gt;
    </highlight>
    </example>

    <example><title>Ejemplo de exclusión</title>
    <highlight language="config">
&lt;Location "/public"&gt;
    AuthBearerProxy off
&lt;/Location&gt;
    </highlight>
    </example>

</usage>
</directivesynopsis>

</modulesynopsis>
