<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1673582 -->
<!-- Spanish Translation: Daniel Ferradal <dferradal@apache.org> -->

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

<modulesynopsis metafile="mod_auth_basic.xml.meta">

<name>mod_auth_basic</name>
<description>Autenticación HTTP Básica</description>
<status>Base</status>
<sourcefile>mod_auth_basic.c</sourcefile>
<identifier>auth_basic_module</identifier>

<summary>
    <p>Este módulo permite el uso de Autenticación HTTP Básica para restringir acceso buscando usuarios en los proveedores configurados.
    La autenticación HTTP Digest la facilita el módulo
    <module>mod_auth_digest</module>.  Este módulo debería combinarse generalmente con al menos un módulo de autenticación como <module>mod_authn_file</module> y uno de autorización como <module>mod_authz_user</module>.</p>
</summary>
<seealso><directive module="mod_authn_core">AuthName</directive></seealso>
<seealso><directive module="mod_authn_core">AuthType</directive></seealso>
<seealso><directive module="mod_authz_core">Require</directive></seealso>
<seealso><a href="../howto/auth.html">Authentication howto</a></seealso>

<directivesynopsis>
<name>AuthBasicProvider</name>
<description>Configura el/los proveedor/es de autenticación para esta 
ubicación</description>
<syntax>AuthBasicProvider <var>provider-name</var>
[<var>provider-name</var>] ...</syntax>
<default>AuthBasicProvider file</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>La directiva <directive>AuthBasicProvider</directive> configura qué proveedor se usa para autenticar los usuarios en esta ubicación. El 
    <code>fichero</code> proveedor por defecto se implementa con el módulo <module>mod_authn_file</module>.  Asegúrese de que el proveedor elegido está presente en el servidor.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
&lt;Location "/secure"&gt;
    AuthType basic
    AuthName "private area"
    AuthBasicProvider  dbm
    AuthDBMType        SDBM
    AuthDBMUserFile    "/www/etc/dbmpasswd"
    Require            valid-user
&lt;/Location&gt;
    </highlight>
    </example>

    <p>Se consulta a los proveedores en orden hasta que un proveedor encuentra una coincidencia para el nombre de usuario solicitado, y en este punto solo este proveedor intentará comprobar la contraseña.  Un fallo al verificar la contraseña no provoca que el control se pase a los proveedores 
    subsiguientes.</p>

    <p>Los proveedores son implementados por <module>mod_authn_dbm</module>,
    <module>mod_authn_file</module>, <module>mod_authn_dbd</module>,
    <module>mod_authnz_ldap</module> y <module>mod_authn_socache</module>.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthBasicAuthoritative</name>
<description>Configura si se pasan autorización o autenticación a los módulos de más bajo nivel</description>
<syntax>AuthBasicAuthoritative On|Off</syntax>
<default>AuthBasicAuthoritative On</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>Normalmente, cada módulo de autorización listado en 
    <directive module="mod_auth_basic">AuthBasicProvider</directive>
    intentará vefificar el usuario y si el usuario no se encuentra en ningún proveedor, el acceso será denegado. Configurando la directiva
    <directive>AuthBasicAuthoritative</directive> de forma explícita a
    <code>Off</code> permite que ambos autenticación y autorización sean pasados a otros módulos no-proveedores si <strong>no hay ID de usuario</strong> o 
    <strong>regla</strong> coincidente para el ID de usario facilitado.  Esto solo sería necesario cuando se combina <module>mod_auth_basic</module> con módulos de terceros que no están configurados con la directiva 
    <directive module="mod_auth_basic">AuthBasicProvider</directive>. Cuando se usan tales módulos, el orden de procesamiento se determina en el código fuente de los módulos y no es configurable.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthBasicFake</name>
<description>Autenticación básica falsa usando las expresiones facilitadas para usario y contraseña</description>
<syntax>AuthBasicFake off|username [password]</syntax>
<default>none</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>
<compatibility>Apache HTTP Server 2.4.5 y posteriores</compatibility>
<usage>
    <p>El usuario y contraseña especificados se combinan en una cabecera de Autorización, que se pasa al servidor o servicio detrás del servidor web. Ambos cambios usuario y contraseña son interpretrados usando el <a href="../expr.html">intérprete de expresión</a>, que permite que tanto el usuario como la contraseña se basen en los parámetros solicitados.</p>

    <p>Si la contraseña no se especifica, se utilizará el valor por defecto  "password".  Para desahabilitar la autenticación básica falsa para una URL, especifique "AuthBasicFake off".</p>

    <p>En este ejemplo, enviamos un usuario y contraseña fijos a un servidor backend.</p>

    <example><title>Fixed Example</title>
    <highlight language="config">
&lt;Location "/demo"&gt;
    AuthBasicFake demo demopass
&lt;/Location&gt;
    </highlight>
    </example>

    <p>En este ejemplo, pasamos la dirección de email extraida de un certificado cliente, extendiendo la opción de funcionalidad de FakeBasicAuth dentro de la directiva <directive module="mod_ssl">SSLOptions</directive>.  Como con la opción FakeBasicAuth, la contraseña se configura a la cadena de caracteres específica "password".</p>

    <example><title>Ejemplo de Certificado</title>
    <highlight language="config">
&lt;Location "/secure"&gt;
    AuthBasicFake "%{SSL_CLIENT_S_DN_Email}"
&lt;/Location&gt;
    </highlight>
    </example>

    <p>Extendiendo el ejemplo de arriba, generamos una contraseña encriptando la dirección email con una contraseña fija, y pasando el resultado encriptado al servidor de backend.  Este método se puede usar como puerta de acceso a sistemas antiguos que no dan soporte a certificados cliente.</p>

    <example><title>Ejemplo de Contraseña</title>
    <highlight language="config">
&lt;Location "/secure"&gt;
    AuthBasicFake "%{SSL_CLIENT_S_DN_Email}" "%{sha1:passphrase-%{SSL_CLIENT_S_DN_Email}}"
&lt;/Location&gt;
    </highlight>
    </example>

    <example><title>Ejemplo de Exclusión</title>
    <highlight language="config">
&lt;Location "/public"&gt;
    AuthBasicFake off
&lt;/Location&gt;
    </highlight>
    </example>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthBasicUseDigestAlgorithm</name>
<description>Comprueba contraseñas en proveedores de autenticación como si la Autenticación Digest estuviera en uso en lugar de la Autenticación Básica.
</description>
<syntax>AuthBasicUseDigestAlgorithm MD5|Off</syntax>
<default>AuthBasicUseDigestAlgorithm Off</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>
<compatibility>Apache HTTP Server 2.4.7 y posteriores</compatibility>

<usage>
    <p>Normalmente, cuando se usa Autenticación Básica, los proveedores listados en
    <directive module="mod_auth_basic">AuthBasicProvider</directive> intentan verificar un usuario comprobando sus almacenes de datos para encontrar una coincidencia de nombre de usuario y contraseña asociados.  Las contraseñas almacenadas generalmente están encriptadas, pero no necesariamente; cada proveedor puede usar su propio esquema de almacenamiento para contraseñas.</p>

    <p>Cuando se usa 
    <directive module="mod_auth_digest">AuthDigestProvider</directive> y Autenticación Digest, los proveedores realizan una comprobación similar para encontrar un nombre de usuario en sus almacenes de datos.  Sin embargo, al contrario que en el caso de la Autenticación Básica, el valor asociado con cada nombre de usuario almacenado debe ser una cadena de caracteres encriptada compuesta del nombre de usuario, nombre real y contraseña.  (Vea el
    <a href="http://tools.ietf.org/html/rfc2617#section-3.2.2.2">
    RFC 2617, Sección 3.2.2.2</a> para más detalles en el formato usado para la cadena de caracteres encriptada.)</p>

    <p>Como consecuencia de la diferencia entre los valores almacenados entre la Autenticación Básica y la Digest, convertir desde Autenticación Digest a Autenticación Básica generalmente requiere que a todos los usuarios se les asigne nuevas contraseñas, puesto que sus contraseñas actuales no pueden ser recuperadas desde el esquema de almacenamiento de contraseñas impuesto en esos proveedores que soportan la Autenticación Digest.</p>

    <p>Configurando la directiva 
    <directive module="mod_auth_basic">AuthBasicUseDigestAlgorithm</directive> a
    <code>MD5</code> hará que se compruebe la contraseña del usuario de Autenticación Básica usando el mismo formato encriptado que para Autenticación Digest.  Primero una cadena de caracteres que se compone del nombre de usuario, nombre real y contraseña es encriptada con MD5; entonces el usuario y esta cadena de caracteres encriptada se pasan a los proveedores listados en 
    <directive module="mod_auth_basic">AuthBasicProvider</directive> como si
    <directive module="mod_authn_core">AuthType</directive> fuera configurado como
    <code>Digest</code> y como si se estuviera usando la Autenticación Digest.
    </p>

    <p>A través del uso de 
    <directive module="mod_auth_basic">AuthBasicUseDigestAlgorithm</directive> un sitio puede pasar de Autenticación Digest a Básica sin requerir que a los usuarios se les asignen contraseñas nuevas.</p>

    <note>
      El método inverso de cambiar de Autenticación Básica a Digest sin asignar nuevas contraseñas generalmente no es posible.  Solo si las contraseñas de la Autenticación Básica se han almacenado en texto plano o con un esquema de encriptación reversible sería posible recuperarlas y generar un nuevo almacén de datos siguiendo el esquema de almacenamiento de contraseñas de Autenticación Digest.
    </note>

    <note>
      Solo proveedores que dan soporte a Autenticación Digest podrán autenticar usuarios cuando 
      <directive module="mod_auth_basic">AuthBasicUseDigestAlgorithm</directive>
      está configurada a <code>MD5</code>.  El uso de otros proveedores dará como resultado una respuesta de error y se denegará el acceso al cliente.
    </note>
</usage>
</directivesynopsis>

</modulesynopsis>
